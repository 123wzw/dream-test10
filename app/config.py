"""配置。"""

import logging
import os

DB_PATH = os.environ.get("PAY_DB", "./pay.db")
WEBHOOK_SECRET = os.environ.get("PAY_WEBHOOK_SECRET", "pay-dev-secret")
LOG_CARD = os.environ.get("PAY_LOG_CARD", "1") == "1"

# 默认值是开发兜底密钥，生产环境若未通过 PAY_WEBHOOK_SECRET 覆盖必须显式告警；
# 不改变环境变量名与默认值本身（受评审约束），只做可观测性提示。
if WEBHOOK_SECRET == "pay-dev-secret":
    logging.getLogger("pay").warning(
        "PAY_WEBHOOK_SECRET is using the built-in development default; "
        "set a strong secret via environment before deploying"
    )
