"""Server metrics, connection sessions, destination logs, retention and alerts."""
import asyncio
import json
import logging
import os
import threading
import time
import urllib.request

from . import apps, db, geo, insights

METRICS_DAYS = int(os.environ.get("METRICS_DAYS", "30"))
INSIGHTS_DAYS = int(os.environ.get("INSIGHTS_DAYS", "365"))  # hourly traffic totals (30-day / all-time views)
SESSION_LOG_DAYS = int(os.environ.get("SESSION_LOG_DAYS", "30"))
FLOW_LOG_DAYS = int(os.environ.get("FLOW_LOG_DAYS", "7"))
LOG_SESSIONS = os.environ.get("LOG_SESSIONS", "true").lower() in ("1", "true", "yes")
LOG_DESTINATIONS = os.environ.get("LOG_DESTINATIONS", "true").lower() in ("1", "true", "yes")
ALERT_WEBHOOK_URL = os.environ.get("ALERT_WEBHOOK_URL", "")
ALERT_CPU = float(os.environ.get("ALERT_CPU_PERCENT", "90"))
ALERT_DISK = float(os.environ.get("ALERT_DISK_PERCENT", "90"))
SESSION_GAP = 240  # seconds without a handshake that end a session

log = logging.getLogger("vnvpn.monitoring")

RANGES = {"1h": (3600, 60), "24h": (86400, 900), "7d": (7 * 86400, 3600)}  # span, bucket seconds


# --------------------------------------------------------------------------- ingest (called from agent sync)

def record_metrics(conn, node_id: int, m: dict):
    try:
        conn.execute("""INSERT INTO node_metrics (node_id, ts, cpu, mem_used, mem_total, disk_used, disk_total,
                        load1, rx_bps, tx_bps, active_peers, uptime, cores) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                     (node_id, int(time.time()), float(m["cpu"]), int(m["mem_used"]), int(m["mem_total"]),
                      int(m["disk_used"]), int(m["disk_total"]), float(m["load1"]), int(m["rx_bps"]),
                      int(m["tx_bps"]), int(m["active_peers"]), int(m["uptime"]), int(m.get("cores", 1))))
    except (KeyError, TypeError, ValueError):
        log.warning("node %s sent malformed metrics", node_id)


def record_session(conn, node, device, user_email: str, endpoint: str, rx: int, tx: int):
    """Track where a device connects from. One row per continuous session per server."""
    if not LOG_SESSIONS or not endpoint:
        return
    client_ip = endpoint.rsplit(":", 1)[0].strip("[]")
    now = int(time.time())
    s = conn.execute("SELECT * FROM sessions WHERE device_id = ? AND node_id = ? ORDER BY id DESC LIMIT 1",
                     (device["id"], node["id"])).fetchone()
    if s and s["client_ip"] == client_ip and now - s["last_seen"] < SESSION_GAP and rx >= s["rx_base"]:
        conn.execute("UPDATE sessions SET last_seen = ?, rx_bytes = ?, tx_bytes = ? WHERE id = ?",
                     (now, rx - s["rx_base"], tx - s["tx_base"], s["id"]))
    else:
        conn.execute("""INSERT INTO sessions (device_id, node_id, user_email, device_name, node_name, client_ip,
                        started, last_seen, rx_base, tx_base) VALUES (?,?,?,?,?,?,?,?,?,?)""",
                     (device["id"], node["id"], user_email, device["name"], node["name"], client_ip, now, now,
                      rx, tx))


def record_flows(conn, node, flows: list, devices_by_ip: dict):
    if not LOG_DESTINATIONS:
        return
    rows = []
    for f in flows[:20000]:
        d = devices_by_ip.get(f.get("src"))
        try:
            dst, dport = str(f["dst"])[:45], int(f.get("dport", 0))
            host = str(f.get("host") or "")[:253].lower()
            country, org = geo.lookup(dst)
            app, category = apps.classify(host, org, dport)
            rows.append((int(f["first"]), int(f["last"]), node["id"], d["id"] if d else None,
                         d["email"] if d else "", d["name"] if d else "", node["name"], str(f["src"])[:45],
                         dst, dport, str(f.get("proto", ""))[:10],
                         int(f.get("conns", 0)), int(f.get("out", 0)), int(f.get("in", 0)),
                         host, app, category, country, org[:120]))
        except (KeyError, TypeError, ValueError):
            continue
    conn.executemany("""INSERT INTO flow_log (first_seen, last_seen, node_id, device_id, user_email, device_name,
                        node_name, src, dst, dport, proto, conns, bytes_out, bytes_in, host, app, category,
                        country, org) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", rows)


def record_dns(conn, node, lookups: list, devices_by_ip: dict):
    """DNS names looked up through the tunnel, as counted by the agent since its last check-in."""
    if not LOG_DESTINATIONS:
        return
    now, rows = int(time.time()), []
    for q in lookups[:5000]:
        try:
            name = str(q["name"]).lower().rstrip(".")[:253]
            count = int(q.get("count", 1))
        except (KeyError, TypeError, ValueError):
            continue
        if not name or name.endswith((".arpa", ".local")):
            continue
        d = devices_by_ip.get(q.get("src"))
        app, category = apps.classify(name)
        rows.append((now, node["id"], d["id"] if d else None, d["email"] if d else "", d["name"] if d else "",
                     name, app, category, count))
    conn.executemany("""INSERT INTO dns_log (ts, node_id, device_id, user_email, device_name, name, app, category,
                        count) VALUES (?,?,?,?,?,?,?,?,?)""", rows)


# --------------------------------------------------------------------------- queries

def latest_metrics(conn) -> dict[int, dict]:
    rows = conn.execute("""SELECT m.* FROM node_metrics m JOIN (
                             SELECT node_id, MAX(ts) ts FROM node_metrics GROUP BY node_id) l
                           ON l.node_id = m.node_id AND l.ts = m.ts""").fetchall()
    return {r["node_id"]: summarize(r) for r in rows}


def summarize(r) -> dict:
    return {
        "ts": r["ts"], "cpu": r["cpu"], "load1": r["load1"], "cores": r["cores"],
        "mem_pct": round(100 * r["mem_used"] / r["mem_total"], 1) if r["mem_total"] else 0,
        "mem_used": r["mem_used"], "mem_total": r["mem_total"],
        "disk_pct": round(100 * r["disk_used"] / r["disk_total"], 1) if r["disk_total"] else 0,
        "disk_used": r["disk_used"], "disk_total": r["disk_total"],
        "rx_bps": r["rx_bps"], "tx_bps": r["tx_bps"], "active_peers": r["active_peers"], "uptime": r["uptime"],
    }


def series(conn, node_id: int, range_key: str) -> dict:
    """Bucketed averages for the server charts."""
    span, bucket = RANGES.get(range_key, RANGES["24h"])
    since = int(time.time()) - span
    rows = conn.execute(f"""
        SELECT (ts / {bucket}) * {bucket} t, AVG(cpu) cpu,
               AVG(CAST(mem_used AS REAL) / NULLIF(mem_total, 0)) * 100 mem,
               AVG(rx_bps) rx, AVG(tx_bps) tx, MAX(rx_bps) rx_max, MAX(tx_bps) tx_max, AVG(active_peers) peers
        FROM node_metrics WHERE node_id = ? AND ts >= ? GROUP BY t ORDER BY t""", (node_id, since)).fetchall()
    return {"range": range_key, "bucket": bucket, "since": since, "until": int(time.time()),
            "points": [{"t": r["t"], "cpu": round(r["cpu"], 1), "mem": round(r["mem"] or 0, 1),
                        "rx": round(r["rx"]), "tx": round(r["tx"]), "peers": round(r["peers"], 1)} for r in rows]}


# --------------------------------------------------------------------------- retention & alerts

def purge(conn):
    now = int(time.time())
    conn.execute("DELETE FROM node_metrics WHERE ts < ?", (now - METRICS_DAYS * 86400,))
    conn.execute("DELETE FROM sessions WHERE last_seen < ?", (now - SESSION_LOG_DAYS * 86400,))
    conn.execute("DELETE FROM flow_log WHERE last_seen < ?", (now - FLOW_LOG_DAYS * 86400,))
    conn.execute("DELETE FROM dns_log WHERE ts < ?", (now - FLOW_LOG_DAYS * 86400,))
    conn.execute("DELETE FROM flow_rollup WHERE last_seen < ?", (now - INSIGHTS_DAYS * 86400,))
    conn.execute("DELETE FROM dns_rollup WHERE ts < ?", (now - INSIGHTS_DAYS * 86400,))


def send_alert(text: str):
    if not ALERT_WEBHOOK_URL:
        return
    # "content" is what Discord reads, "text" is what Slack reads
    body = json.dumps({"content": text, "text": text}).encode()
    req = urllib.request.Request(ALERT_WEBHOOK_URL, data=body, headers={"Content-Type": "application/json",
                                                                         "User-Agent": "vnvpn-panel"})
    try:
        urllib.request.urlopen(req, timeout=10).close()
    except OSError as e:
        log.warning("alert webhook failed: %s", e)


_alert_state: dict[tuple[int, str], bool] = {}


def check_alerts(conn, node_online) -> list[str]:
    """Return alert messages for state changes since the last check (offline, high CPU, disk full)."""
    messages = []
    metrics = latest_metrics(conn)
    cpu_5m = {r["node_id"]: r["cpu"] for r in conn.execute(
        "SELECT node_id, AVG(cpu) cpu FROM node_metrics WHERE ts > ? GROUP BY node_id", (int(time.time()) - 300,))}
    for n in conn.execute("SELECT * FROM nodes WHERE enabled = 1").fetchall():
        m = metrics.get(n["id"], {})
        cpu = cpu_5m.get(n["id"], 0)
        conditions = {
            "offline": (not node_online(n) and n["last_seen"] is not None,
                        f"🔴 {n['name']} is offline (no check-in for 90s)", f"🟢 {n['name']} is back online"),
            "cpu": (cpu >= ALERT_CPU, f"🟠 {n['name']} CPU averaging {cpu:.0f}% over 5 minutes",
                    f"✅ {n['name']} CPU back to normal"),
            "disk": (m.get("disk_pct", 0) >= ALERT_DISK, f"🟠 {n['name']} disk {m.get('disk_pct', 0):.0f}% full",
                     f"✅ {n['name']} disk usage back under {ALERT_DISK:.0f}%"),
        }
        for key, (bad, on_msg, off_msg) in conditions.items():
            prev = _alert_state.get((n["id"], key))
            if prev is None:
                _alert_state[(n["id"], key)] = bad  # first look after start: don't alert on old news
            elif bad != prev:
                _alert_state[(n["id"], key)] = bad
                messages.append(on_msg if bad else off_msg)
    return messages


def _tick(node_online, do_purge: bool):
    with db.session() as conn:
        messages = check_alerts(conn, node_online)
        insights.rollup(conn)
        if do_purge:
            purge(conn)
    for msg in messages:
        send_alert(msg)
    if do_purge and LOG_DESTINATIONS:  # destination country/owner database, weekly, without holding up alerts
        threading.Thread(target=geo.refresh_if_stale, daemon=True).start()


async def background_loop(node_online):
    """Alerts every 30s, retention cleanup hourly - in a worker thread so the web server never waits on it."""
    last_purge = 0.0
    while True:
        try:
            do_purge = time.time() - last_purge > 3600
            await asyncio.to_thread(_tick, node_online, do_purge)
            if do_purge:
                last_purge = time.time()
        except Exception:
            log.exception("monitoring loop failed")
        await asyncio.sleep(30)
