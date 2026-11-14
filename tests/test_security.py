"""安全攻击测试。

每个用例对应一个已确认的漏洞，当前（未修复）代码下必须失败。
约束：不改公开接口（路由/字段名）、不改运行配置（环境变量名与默认值）、
不引入新依赖。
"""

import hmac
import json
import os
import tempfile
import threading

_TMP = tempfile.mkdtemp(prefix="pay-sec-test-")
os.environ["PAY_DB"] = os.path.join(_TMP, "pay.db")
os.environ["PAY_LOG_CARD"] = "1"  # 即便开启日志开关，也不允许打印完整卡号

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import service, store  # noqa: E402
from app.main import app  # noqa: E402

client = TestClient(app)


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    """每个用例使用独立 SQLite 文件，互不污染。"""
    db = tmp_path / "sec.db"
    monkeypatch.setattr(store.config, "DB_PATH", str(db))
    monkeypatch.setattr(service.config, "DB_PATH", str(db))
    store.init_db()
    yield


def _signed_webhook(payload: dict, sig: str | None = None):
    raw = json.dumps(payload, separators=(",", ":")).encode()
    if sig is None:
        sig = service.sign(raw)
    return client.post(
        "/webhook/payment",
        content=raw,
        headers={"x-signature": sig, "content-type": "application/json"},
    )


def _seed_order(order_id: str, amount: int = 1000) -> None:
    resp = _signed_webhook(
        {"order_id": order_id, "amount_cents": amount, "card_no": "4242424242424242"}
    )
    assert resp.status_code == 200


# --- 1. 回调验签：非恒定时间比较（时序攻击） -------------------------------

def test_signature_verification_uses_constant_time_compare(monkeypatch):
    """验签必须走 hmac.compare_digest；直接 == 比较可被时序侧信道逐字节猜签名。"""
    calls = []
    real_compare = hmac.compare_digest

    def spy(a, b):
        calls.append((a, b))
        return real_compare(a, b)

    monkeypatch.setattr(hmac, "compare_digest", spy)
    _signed_webhook({"order_id": "sig-1", "amount_cents": 100})
    assert calls, "verify() 未使用 hmac.compare_digest，疑似使用 == 直接比较签名"


# --- 2. 回调日志：完整卡号落日志（PCI-DSS 敏感信息泄露） --------------------

def test_webhook_must_not_log_full_card_number(caplog):
    payload = {"order_id": "log-1", "amount_cents": 100, "card_no": "4242424242424242"}
    with caplog.at_level("INFO", logger="pay"):
        resp = _signed_webhook(payload)
    assert resp.status_code == 200
    full_pan = "4242424242424242"
    assert all(full_pan not in record.getMessage() for record in caplog.records), (
        "完整卡号出现在应用日志中"
    )


# --- 3. 查询链路：响应回显完整卡号 -----------------------------------------

def test_order_response_masks_card_number():
    _seed_order("mask-1")
    resp = client.get("/orders/mask-1")
    assert resp.status_code == 200
    body = resp.json()
    assert "card_no" in body  # 字段名保持不变
    assert "4242424242424242" not in body["card_no"]
    assert body["card_no"].endswith("4242")  # 仅保留后四位


# --- 4. 回调入账：负金额 / 零金额 / 非正整数 -------------------------------

def test_webhook_rejects_negative_amount():
    resp = _signed_webhook({"order_id": "neg-1", "amount_cents": -100})
    assert resp.status_code == 400


def test_webhook_rejects_zero_amount():
    resp = _signed_webhook({"order_id": "zero-1", "amount_cents": 0})
    assert resp.status_code == 400


def test_webhook_rejects_non_integer_amount():
    # 1.5 元被 int() 截断为 1 元入账；布尔值也会被 int() 接受
    resp = _signed_webhook({"order_id": "frac-1", "amount_cents": 1.5})
    assert resp.status_code == 400
    resp = _signed_webhook({"order_id": "bool-1", "amount_cents": True})
    assert resp.status_code == 400


def test_webhook_rejects_missing_order_id():
    resp = _signed_webhook({"amount_cents": 100})
    assert resp.status_code == 400


def test_webhook_rejects_malformed_json():
    resp = client.post(
        "/webhook/payment",
        content=b"{not-json",
        headers={"x-signature": "x", "content-type": "application/json"},
    )
    assert resp.status_code == 400


# --- 5. 退款：负数退款（反向加钱 / 绕过可退额度） ---------------------------

def test_refund_rejects_negative_amount():
    _seed_order("rneg-1")
    resp = client.post("/refund", json={"order_id": "rneg-1", "amount_cents": -500})
    assert resp.status_code == 400
    row = store.get_order("rneg-1")
    assert row["refunded_cents"] == 0


def test_refund_rejects_zero_amount():
    _seed_order("rzero-1")
    resp = client.post("/refund", json={"order_id": "rzero-1", "amount_cents": 0})
    assert resp.status_code == 400


def test_refund_rejects_fractional_amount():
    _seed_order("rfrac-1")
    resp = client.post("/refund", json={"order_id": "rfrac-1", "amount_cents": 1.99})
    assert resp.status_code == 400


def test_refund_rejects_missing_fields():
    resp = client.post("/refund", json={"order_id": "rmiss-1"})
    assert resp.status_code == 400
    resp = client.post("/refund", json={"amount_cents": 100})
    assert resp.status_code == 400


# --- 6. 退款：TOCTOU 并发超额退款 ------------------------------------------

def test_concurrent_refunds_cannot_exceed_order_amount():
    order_id = "race-1"
    amount = 1000
    _seed_order(order_id, amount)

    # 让所有线程都先完成“读订单 + 额度判断”阶段，再并发写入，
    # 稳定放大 service 层 check-then-act 的时间窗。
    start = threading.Event()
    real_get_order = store.get_order

    def gated_get_order(oid):
        row = real_get_order(oid)
        start.wait(5)
        return row

    store.get_order = gated_get_order
    try:
        results = []

        def worker():
            r = client.post("/refund", json={"order_id": order_id, "amount_cents": 600})
            results.append(r.status_code)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        start.set()
        for t in threads:
            t.join()
    finally:
        store.get_order = real_get_order

    row = store.get_order(order_id)
    assert row["refunded_cents"] <= amount, (
        f"并发退款超额：累计退款 {row['refunded_cents']} > 订单金额 {amount}"
    )
    assert sum(1 for code in results if code == 200) <= amount // 600


# --- 7. 幂等：进程内集合在多进程/重启下失效 ---------------------------------

def test_duplicate_webhook_is_idempotent_without_in_memory_state():
    payload = {"order_id": "idem-1", "amount_cents": 100, "card_no": "4242"}
    raw = json.dumps(payload, separators=(",", ":")).encode()
    sig = service.sign(raw)
    headers = {"x-signature": sig, "content-type": "application/json"}

    first = client.post("/webhook/payment", content=raw, headers=headers)
    assert first.status_code == 200

    # 模拟服务重启 / 多副本：内存幂等状态被清空（修复后服务不再持有该状态）
    processed = getattr(service, "_processed", set())
    processed.clear()

    second = client.post("/webhook/payment", content=raw, headers=headers)
    assert second.status_code == 200
    assert second.json() == {"status": "duplicate"}

    rows = store.connect().execute(
        "SELECT COUNT(*) AS c FROM orders WHERE order_id = ?", ("idem-1",)
    ).fetchone()
    assert rows["c"] == 1
