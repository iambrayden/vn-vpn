"""SQLite storage. One connection per request; the schema is created on startup."""
import os
import sqlite3
from contextlib import contextmanager

DB_PATH = os.environ.get("DATABASE_PATH", "/data/vnvpn.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    is_admin      INTEGER NOT NULL DEFAULT 0,
    status        TEXT NOT NULL DEFAULT 'active',   -- active | suspended
    private_key   TEXT NOT NULL,
    public_key    TEXT NOT NULL UNIQUE,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS nodes (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    location      TEXT NOT NULL DEFAULT '',
    endpoint_host TEXT NOT NULL,
    listen_port   INTEGER NOT NULL DEFAULT 51820,
    public_key    TEXT NOT NULL,
    secret_hash   TEXT NOT NULL UNIQUE,
    enabled       INTEGER NOT NULL DEFAULT 1,
    agent_version TEXT NOT NULL DEFAULT '',
    hostname      TEXT NOT NULL DEFAULT '',
    last_seen     TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS peer_stats (
    user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    node_id        INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    rx_bytes       INTEGER NOT NULL DEFAULT 0,
    tx_bytes       INTEGER NOT NULL DEFAULT 0,
    last_handshake INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, node_id)
);

CREATE TABLE IF NOT EXISTS enroll_tokens (
    token      TEXT PRIMARY KEY,
    label      TEXT NOT NULL DEFAULT '',
    uses       INTEGER NOT NULL DEFAULT 0,
    max_uses   INTEGER,                 -- NULL = unlimited
    revoked    INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


@contextmanager
def session():
    conn = connect()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    with session() as conn:
        conn.executescript(SCHEMA)
