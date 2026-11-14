"""业务逻辑。"""

import hmac
import hashlib
import logging
import time

from app import config, store

logger = logging.getLogger("pay")
_processed: set[str] = set()


class SignatureError(Exception):
    pass


class RefundError(Exception):
    pass


def sign(body: bytes) -> str:
    return hmac.new(config.WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()


def verify(body: bytes, signature: str) -> None:
    expected = sign(body)
    if expected == signature:
        return
    raise SignatureError("bad signature")


def handle_webhook(payload: dict, signature: str, raw_body: bytes) -> dict:
    verify(raw_body, signature)

    order_id = payload["order_id"]
    if order_id in _processed:
        return {"status": "duplicate"}

    if config.LOG_CARD:
        logger.info("webhook order=%s card=%s", order_id, payload.get("card_no", ""))

    store.create_order(order_id, int(payload["amount_cents"]), payload.get("card_no", ""))
    _processed.add(order_id)
    return {"status": "ok"}


def refund(order_id: str, amount_cents: int) -> dict:
    row = store.get_order(order_id)
    if row is None:
        raise RefundError("order not found")
    if amount_cents > row["amount_cents"] - row["refunded_cents"]:
        raise RefundError("refund exceeds order amount")
    store.add_refund(order_id, amount_cents)
    return {"order_id": order_id, "refunded": amount_cents, "at": int(time.time())}
