"""配置。"""

import os

DB_PATH = os.environ.get("PAY_DB", "./pay.db")
WEBHOOK_SECRET = os.environ.get("PAY_WEBHOOK_SECRET", "pay-dev-secret")
LOG_CARD = os.environ.get("PAY_LOG_CARD", "1") == "1"
