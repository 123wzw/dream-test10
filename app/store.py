"""存储层。"""

import sqlite3

from app import config


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    # 并发写入时等待锁而不是立刻抛 database is locked
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def init_db() -> None:
    conn = connect()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS orders (
                order_id TEXT PRIMARY KEY,
                amount_cents INTEGER NOT NULL,
                refunded_cents INTEGER NOT NULL DEFAULT 0,
                card_no TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'paid'
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


def get_order(order_id: str):
    conn = connect()
    try:
        return conn.execute("SELECT * FROM orders WHERE order_id = ?", (order_id,)).fetchone()
    finally:
        conn.close()


def create_order(order_id: str, amount_cents: int, card_no: str) -> bool:
    """插入订单。返回 True 表示新插入，False 表示订单已存在（幂等重复回调）。"""
    conn = connect()
    try:
        cur = conn.execute(
            "INSERT OR IGNORE INTO orders (order_id, amount_cents, card_no) VALUES (?, ?, ?)",
            (order_id, amount_cents, card_no),
        )
        conn.commit()
        return cur.rowcount == 1
    finally:
        conn.close()


def apply_refund(order_id: str, amount_cents: int) -> bool:
    """原子退款：仅当累计退款不超过订单金额时才落账。

    用单条条件 UPDATE 把“检查额度 + 加退款”合并为一次写操作，
    依靠 SQLite 写锁串行化，消除 check-then-act 的并发超额退款窗口。
    返回 True 表示退款成功，False 表示额度不足。
    """
    conn = connect()
    try:
        cur = conn.execute(
            """
            UPDATE orders
               SET refunded_cents = refunded_cents + ?
             WHERE order_id = ?
               AND refunded_cents + ? <= amount_cents
            """,
            (amount_cents, order_id, amount_cents),
        )
        conn.commit()
        return cur.rowcount == 1
    finally:
        conn.close()
