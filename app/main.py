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
    payload = await request.json()
    try:
        return service.handle_webhook(payload, signature, raw)
    except service.SignatureError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from None


@app.post("/refund")
def refund(body: dict):
    try:
        return service.refund(body["order_id"], int(body["amount_cents"]))
    except service.RefundError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None


@app.get("/orders/{order_id}")
def get_order(order_id: str):
    row = store.get_order(order_id)
    if row is None:
        raise HTTPException(status_code=404, detail="not found")
    return dict(row)
