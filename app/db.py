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
    country       TEXT NOT NULL DEFAULT '',     -- ISO 3166-1 alpha-2
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

-- Each device a customer adds gets its own WireGuard key and tunnel address.
CREATE TABLE IF NOT EXISTS devices (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name           TEXT NOT NULL,
    private_key    TEXT NOT NULL,
    public_key     TEXT NOT NULL UNIQUE,
    address        TEXT NOT NULL UNIQUE,
    last_handshake INTEGER NOT NULL DEFAULT 0,   -- newest handshake on any server
    active_since   INTEGER NOT NULL DEFAULT 0,   -- start of the current session (decides who keeps a slot)
    kicked_until   INTEGER NOT NULL DEFAULT 0,   -- "Disconnect" from the portal blocks the device until then
    created_at     TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS device_stats (
    device_id      INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    node_id        INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    rx_bytes       INTEGER NOT NULL DEFAULT 0,
    tx_bytes       INTEGER NOT NULL DEFAULT 0,
    last_handshake INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (device_id, node_id)
);

CREATE TABLE IF NOT EXISTS stripe_events (
    id         TEXT PRIMARY KEY,
    type       TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
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


# Columns added after the first release: (table, column, definition)
MIGRATIONS = [
    ("nodes", "country", "TEXT NOT NULL DEFAULT ''"),
    ("users", "plan", "TEXT NOT NULL DEFAULT ''"),                  # basic | pro | ''
    ("users", "plan_source", "TEXT NOT NULL DEFAULT ''"),           # stripe | manual
    ("users", "sub_status", "TEXT NOT NULL DEFAULT ''"),            # Stripe subscription status
    ("users", "stripe_customer_id", "TEXT NOT NULL DEFAULT ''"),
    ("users", "stripe_subscription_id", "TEXT NOT NULL DEFAULT ''"),
    ("users", "period_end", "INTEGER NOT NULL DEFAULT 0"),
    ("users", "cancel_at_period_end", "INTEGER NOT NULL DEFAULT 0"),
]


def init():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    with session() as conn:
        conn.executescript(SCHEMA)
        for table, column, definition in MIGRATIONS:
            cols = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
            if column not in cols:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        _migrate_user_keys_to_devices(conn)


def _migrate_user_keys_to_devices(conn):
    """Before devices existed every user had one key with address = client_ip(user id).
    Turn those into each user's first device so configs already handed out keep working."""
    if conn.execute("SELECT 1 FROM meta WHERE key = 'devices_v1'").fetchone():
        return
    from .crypto import client_ip
    has_stats = conn.execute("SELECT 1 FROM sqlite_master WHERE name = 'peer_stats'").fetchone()
    for u in conn.execute("SELECT id, private_key, public_key FROM users").fetchall():
        if has_stats and not conn.execute(
                "SELECT 1 FROM peer_stats WHERE user_id = ? AND last_handshake > 0", (u["id"],)).fetchone():
            continue  # never connected: nothing to preserve, they'll add devices themselves
        cur = conn.execute("INSERT INTO devices (user_id, name, private_key, public_key, address) VALUES (?,?,?,?,?)",
                           (u["id"], "My device", u["private_key"], u["public_key"], client_ip(u["id"])))
        conn.execute("""INSERT INTO device_stats (device_id, node_id, rx_bytes, tx_bytes, last_handshake)
                        SELECT ?, p.node_id, p.rx_bytes, p.tx_bytes, p.last_handshake
                        FROM peer_stats p JOIN nodes n ON n.id = p.node_id WHERE p.user_id = ?""",
                     (cur.lastrowid, u["id"]))
    conn.execute("INSERT INTO meta (key, value) VALUES ('devices_v1', datetime('now'))")
