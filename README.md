# pay-gateway

支付网关，负责接收上游回调、记账、对账。

## 技术栈

- Python 3.12
- FastAPI + SQLite

## 启动

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt

.venv/Scripts/python -m uvicorn app.main:app --reload
```

## 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/webhook/payment` | 上游支付回调 |
| POST | `/refund` | 发起退款 |
| GET | `/orders/{order_id}` | 查询订单 |
| GET | `/health` | 健康检查 |

## 配置

| 变量 | 默认值 | 说明 |
|---|---|---|
| `PAY_DB` | `./pay.db` | SQLite 路径 |
| `PAY_WEBHOOK_SECRET` | `pay-dev-secret` | 回调验签密钥 |
| `PAY_LOG_CARD` | 未设置 | 是否在日志中打印卡号 |

## 测试

```bash
.venv/Scripts/python -m pytest -q
```

## 已知问题

- 回调验签、退款金额校验都还没做过安全评审。
- 幂等键目前放在内存里，服务重启就丢。
