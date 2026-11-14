"""HTTP 接口。"""

from fastapi import FastAPI, HTTPException, Request

from app import service, store

app = FastAPI(title="PayGateway", version="1.2.0")
store.init_db()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/webhook/payment")
async def webhook(request: Request):
    raw = await request.body()
    signature = request.headers.get("x-signature", "")
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid json") from None
    try:
        return service.handle_webhook(payload, signature, raw)
    except service.SignatureError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from None
    except service.WebhookError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None


@app.post("/refund")
def refund(body: dict):
    if not isinstance(body, dict) or "order_id" not in body or "amount_cents" not in body:
        raise HTTPException(status_code=400, detail="missing required fields")
    try:
        return service.refund(body["order_id"], body["amount_cents"])
    except service.RefundError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None


@app.get("/orders/{order_id}")
def get_order(order_id: str):
    row = store.get_order(order_id)
    if row is None:
        raise HTTPException(status_code=404, detail="not found")
    data = dict(row)
    # 防御性脱敏：即使历史数据中存在未脱敏卡号，也不得通过查询接口回显
    data["card_no"] = service.mask_card(data.get("card_no", ""))
    return data
