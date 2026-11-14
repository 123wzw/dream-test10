"""功能测试。"""

import os
import tempfile

_TMP = tempfile.mkdtemp(prefix="pay-test-")
os.environ["PAY_DB"] = os.path.join(_TMP, "pay.db")
os.environ["PAY_LOG_CARD"] = "0"

from fastapi.testclient import TestClient  # noqa: E402

from app import service  # noqa: E402
from app.main import app  # noqa: E402

client = TestClient(app)


def _post_webhook(order_id="o-1", amount=1000, card="4242"):
    payload = {"order_id": order_id, "amount_cents": amount, "card_no": card}
    import json

    raw = json.dumps(payload, separators=(",", ":")).encode()
    sig = service.sign(raw)
    return client.post("/webhook/payment", content=raw,
                       headers={"x-signature": sig, "content-type": "application/json"})


def test_health():
    assert client.get("/health").status_code == 200


def test_webhook_accepts_valid_signature():
    assert _post_webhook("o-100").status_code == 200


def test_webhook_rejects_bad_signature():
    import json

    raw = json.dumps({"order_id": "o-101", "amount_cents": 100}, separators=(",", ":")).encode()
    resp = client.post("/webhook/payment", content=raw,
                       headers={"x-signature": "deadbeef", "content-type": "application/json"})
    assert resp.status_code == 401


def test_refund_within_amount():
    _post_webhook("o-102", 1000)
    resp = client.post("/refund", json={"order_id": "o-102", "amount_cents": 300})
    assert resp.status_code == 200


def test_refund_exceeds_amount():
    _post_webhook("o-103", 500)
    resp = client.post("/refund", json={"order_id": "o-103", "amount_cents": 900})
    assert resp.status_code == 400


def test_order_lookup():
    _post_webhook("o-104", 2000)
    resp = client.get("/orders/o-104")
    assert resp.status_code == 200
    assert resp.json()["amount_cents"] == 2000
