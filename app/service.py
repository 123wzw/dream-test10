"""业务逻辑。"""

import hmac
import hashlib
import logging
import time

from app import config, store

logger = logging.getLogger("pay")


class SignatureError(Exception):
    pass


class RefundError(Exception):
    pass


class WebhookError(Exception):
    pass


def sign(body: bytes) -> str:
    return hmac.new(config.WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()


def verify(body: bytes, signature: str) -> None:
    expected = sign(body)
    # 恒定时间比较，防止通过响应耗时逐字节推断签名（时序攻击）
    if not isinstance(signature, str) or not hmac.compare_digest(expected, signature):
        raise SignatureError("bad signature")


def mask_card(card_no: str) -> str:
    """卡号脱敏：仅保留后四位，其余以 * 替换。"""
    if not card_no:
        return ""
    if len(card_no) <= 4:
        return "*" * len(card_no)
    return "*" * (len(card_no) - 4) + card_no[-4:]


def _require_positive_int(value, field: str) -> int:
    # bool 是 int 的子类，必须先排除；float 不允许隐式截断
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise WebhookError(f"invalid {field}")
    return value


def handle_webhook(payload: dict, signature: str, raw_body: bytes) -> dict:
    verify(raw_body, signature)

    if not isinstance(payload, dict):
        raise WebhookError("invalid payload")

    order_id = payload.get("order_id")
    if not isinstance(order_id, str) or not order_id.strip():
        raise WebhookError("invalid order_id")
    amount_cents = _require_positive_int(payload.get("amount_cents"), "amount_cents")

    card_raw = payload.get("card_no", "")
    if not isinstance(card_raw, str):
        raise WebhookError("invalid card_no")
    card_masked = mask_card(card_raw)

    if config.LOG_CARD:
        logger.info("webhook order=%s card=%s", order_id, card_masked)

    # 以数据库主键冲突作为幂等判据，服务重启 / 多副本下依然成立
    created = store.create_order(order_id, amount_cents, card_masked)
    if not created:
        return {"status": "duplicate"}
    return {"status": "ok"}


def refund(order_id: str, amount_cents: int) -> dict:
    if not isinstance(order_id, str) or not order_id.strip():
        raise RefundError("invalid order_id")
    # 拒绝负数 / 零 / 浮点 / 布尔：负数会让 refunded_cents 反向减少，等于放大可退额度
    if isinstance(amount_cents, bool) or not isinstance(amount_cents, int) or amount_cents <= 0:
        raise RefundError("invalid amount_cents")

    row = store.get_order(order_id)
    if row is None:
        raise RefundError("order not found")
    if amount_cents > row["amount_cents"] - row["refunded_cents"]:
        raise RefundError("refund exceeds order amount")

    # 单条条件 UPDATE 原子落账，兜底并发场景下的超额退款
    if not store.apply_refund(order_id, amount_cents):
        raise RefundError("refund exceeds order amount")

    return {"order_id": order_id, "refunded": amount_cents, "at": int(time.time())}
