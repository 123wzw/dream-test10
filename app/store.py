"""存储层。"""

import sqlite3

from app import config


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(config.DB_PATH)
    conn.row_factory = sqlite3.Row
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


def create_order(order_id: str, amount_cents: int, card_no: str) -> None:
    conn = connect()
    try:
        conn.execute(
            "INSERT OR IGNORE INTO orders (order_id, amount_cents, card_no) VALUES (?, ?, ?)",
            (order_id, amount_cents, card_no),
        )
        conn.commit()
    finally:
        conn.close()


def add_refund(order_id: str, amount_cents: int) -> None:
    conn = connect()
    try:
        conn.execute(
            "UPDATE orders SET refunded_cents = refunded_cents + ? WHERE order_id = ?",
            (amount_cents, order_id),
        )
        conn.commit()
    finally:
        conn.close()
