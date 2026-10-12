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

-- Which locations a device has downloaded (to warn before handing the same config to a second machine).
CREATE TABLE IF NOT EXISTS device_downloads (
    device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    node_id    INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    first_at   INTEGER NOT NULL,
    PRIMARY KEY (device_id, node_id)
);

CREATE TABLE IF NOT EXISTS device_stats (
    device_id      INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    node_id        INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    rx_bytes       INTEGER NOT NULL DEFAULT 0,
    tx_bytes       INTEGER NOT NULL DEFAULT 0,
    last_handshake INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (device_id, node_id)
);

-- Data used per customer, per server, per UTC day. Built from the growth of WireGuard's per-peer counters
-- (which reset when a tunnel restarts), so totals survive restarts. Kept indefinitely; it's tiny.
CREATE TABLE IF NOT EXISTS usage_daily (
    day       TEXT NOT NULL,                 -- YYYY-MM-DD (UTC)
    user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    node_id   INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    down      INTEGER NOT NULL DEFAULT 0,    -- bytes to the customer
    up        INTEGER NOT NULL DEFAULT 0,    -- bytes from the customer
    PRIMARY KEY (day, user_id, node_id)
);
CREATE INDEX IF NOT EXISTS usage_daily_user ON usage_daily (user_id, day);

-- One row per agent check-in (~15s); pruned after METRICS_DAYS.
CREATE TABLE IF NOT EXISTS node_metrics (
    node_id      INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    ts           INTEGER NOT NULL,
    cpu          REAL NOT NULL,
    mem_used     INTEGER NOT NULL,
    mem_total    INTEGER NOT NULL,
    disk_used    INTEGER NOT NULL,
    disk_total   INTEGER NOT NULL,
    load1        REAL NOT NULL,
    rx_bps       INTEGER NOT NULL,
    tx_bps       INTEGER NOT NULL,
    active_peers INTEGER NOT NULL,
    uptime       INTEGER NOT NULL,
    cores        INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS node_metrics_node_ts ON node_metrics (node_id, ts);

-- Where customers connect from: one row per device session on a server.
CREATE TABLE IF NOT EXISTS sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   INTEGER REFERENCES devices(id) ON DELETE SET NULL,
    node_id     INTEGER REFERENCES nodes(id) ON DELETE SET NULL,
    user_email  TEXT NOT NULL,
    device_name TEXT NOT NULL,
    node_name   TEXT NOT NULL,
    client_ip   TEXT NOT NULL,
    started     INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    rx_base     INTEGER NOT NULL DEFAULT 0,
    tx_base     INTEGER NOT NULL DEFAULT 0,
    rx_bytes    INTEGER NOT NULL DEFAULT 0,   -- client upload
    tx_bytes    INTEGER NOT NULL DEFAULT 0    -- client download
);
CREATE INDEX IF NOT EXISTS sessions_device ON sessions (device_id, node_id, id);
CREATE INDEX IF NOT EXISTS sessions_seen ON sessions (last_seen);

-- Where traffic goes: connections from the tunnel, aggregated per check-in by destination.
CREATE TABLE IF NOT EXISTS flow_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    first_seen  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    node_id     INTEGER REFERENCES nodes(id) ON DELETE SET NULL,
    device_id   INTEGER REFERENCES devices(id) ON DELETE SET NULL,
    user_email  TEXT NOT NULL,
    device_name TEXT NOT NULL,
    node_name   TEXT NOT NULL,
    src         TEXT NOT NULL,
    dst         TEXT NOT NULL,
    dport       INTEGER NOT NULL,
    proto       TEXT NOT NULL,
    conns       INTEGER NOT NULL,
    bytes_out   INTEGER NOT NULL,
    bytes_in    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS flow_log_seen ON flow_log (last_seen);
CREATE INDEX IF NOT EXISTS flow_log_dst ON flow_log (dst);

-- DNS names customers looked up through the tunnel (counts per check-in).
CREATE TABLE IF NOT EXISTS dns_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          INTEGER NOT NULL,
    node_id     INTEGER REFERENCES nodes(id) ON DELETE SET NULL,
    device_id   INTEGER REFERENCES devices(id) ON DELETE SET NULL,
    user_email  TEXT NOT NULL,
    device_name TEXT NOT NULL,
    name        TEXT NOT NULL,
    app         TEXT NOT NULL DEFAULT '',
    category    TEXT NOT NULL DEFAULT '',
    count       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS dns_log_ts ON dns_log (ts);

-- Hourly totals of flow_log / dns_log, kept much longer (INSIGHTS_DAYS) for the 30-day and all-time views.
CREATE TABLE IF NOT EXISTS flow_rollup (
    last_seen   INTEGER NOT NULL,             -- start of the hour
    node_id     INTEGER, device_id INTEGER,
    user_email  TEXT NOT NULL, device_name TEXT NOT NULL, node_name TEXT NOT NULL,
    src TEXT NOT NULL, dst TEXT NOT NULL, host TEXT NOT NULL, dport INTEGER NOT NULL, proto TEXT NOT NULL,
    app TEXT NOT NULL, category TEXT NOT NULL, country TEXT NOT NULL, org TEXT NOT NULL,
    conns INTEGER NOT NULL, bytes_in INTEGER NOT NULL, bytes_out INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS flow_rollup_ts ON flow_rollup (last_seen);
CREATE TABLE IF NOT EXISTS dns_rollup (
    ts INTEGER NOT NULL, node_id INTEGER, device_id INTEGER, user_email TEXT NOT NULL, device_name TEXT NOT NULL,
    name TEXT NOT NULL, app TEXT NOT NULL, category TEXT NOT NULL, count INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS dns_rollup_ts ON dns_rollup (ts);

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
    ("nodes", "agent_error", "TEXT NOT NULL DEFAULT ''"),          # last problem the agent reported
    ("enroll_tokens", "node_id", "INTEGER"),                        # set = one-time re-enroll for that server
    ("enroll_tokens", "expires_at", "INTEGER"),                     # unix time; NULL = never
    ("nodes", "slot", "INTEGER"),                                   # which /16 of VPN_POOL the server uses
    # one config used on two machines at once: the server sees the peer's address flip back and forth
    ("devices", "last_ip", "TEXT NOT NULL DEFAULT ''"),
    ("devices", "ip_changed_at", "INTEGER NOT NULL DEFAULT 0"),
    ("devices", "ip_flips", "INTEGER NOT NULL DEFAULT 0"),
    ("devices", "shared_at", "INTEGER NOT NULL DEFAULT 0"),
    # handshake churn: two machines on one key keep re-handshaking every few seconds (normal: ~2 minutes)
    ("devices", "hs_churn", "INTEGER NOT NULL DEFAULT 0"),
    ("devices", "hs_churn_at", "INTEGER NOT NULL DEFAULT 0"),
    ("device_stats", "endpoint", "TEXT NOT NULL DEFAULT ''"),       # last client ip:port seen by that server
    # traffic insights: what each destination is
    ("flow_log", "host", "TEXT NOT NULL DEFAULT ''"),               # DNS name the client looked it up as
    ("flow_log", "app", "TEXT NOT NULL DEFAULT ''"),
    ("flow_log", "category", "TEXT NOT NULL DEFAULT ''"),
    ("flow_log", "country", "TEXT NOT NULL DEFAULT ''"),            # of the destination
    ("flow_log", "org", "TEXT NOT NULL DEFAULT ''"),                # network owner of the destination
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
        # give every server its own address range (servers registered before per-server ranges existed)
        for i, n in enumerate(conn.execute("SELECT id FROM nodes WHERE slot IS NULL ORDER BY id").fetchall()):
            used = {r[0] for r in conn.execute("SELECT slot FROM nodes WHERE slot IS NOT NULL")}
            conn.execute("UPDATE nodes SET slot = ? WHERE id = ?",
                         (next(s for s in range(1 << 16) if s not in used), n["id"]))
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS nodes_slot ON nodes (slot)")
        # the first "shared config" detector (public-IP changes) misfired on mobile carriers that rotate IPs
        # ... and so did the second (handshake churn alone) for one machine with tunnels to several servers
        if not conn.execute("SELECT 1 FROM meta WHERE key = 'shared_v3'").fetchone():
            conn.execute("UPDATE devices SET shared_at = 0, hs_churn = 0")
            conn.execute("INSERT INTO meta (key, value) VALUES ('shared_v3', datetime('now'))")
        if not conn.execute("SELECT 1 FROM meta WHERE key = 'shared_v2'").fetchone():
            conn.execute("UPDATE devices SET shared_at = 0")
            conn.execute("INSERT INTO meta (key, value) VALUES ('shared_v2', datetime('now'))")


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
