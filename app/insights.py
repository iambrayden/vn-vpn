"""Traffic insights: aggregates over the destination log for the admin dashboard (UniFi-style)."""
import time

from . import apps

RANGES = {"1h": (3600, 120), "24h": (86400, 1800), "7d": (7 * 86400, 4 * 3600), "30d": (30 * 86400, 12 * 3600),
          "all": (None, None)}  # span, bucket seconds (all: from the oldest hourly total)
HOUR = 3600
FLOW_COLS = ("last_seen, node_id, device_id, user_email, device_name, node_name, src, dst, host, dport, proto, app, "
             "category, country, org, conns, bytes_in, bytes_out")
DNS_COLS = "ts, node_id, device_id, user_email, device_name, name, app, category, count"


def rollup(conn):
    """Fold finished hours of flow_log / dns_log into the hourly tables (cheap: runs every 30s, works once an hour)."""
    done = conn.execute("SELECT value FROM meta WHERE key = 'rollup_until'").fetchone()
    until = (int(time.time()) - 120) // HOUR * HOUR  # 2 min grace for check-ins straddling the hour
    start = int(done[0]) if done else (conn.execute("SELECT MIN(last_seen) FROM flow_log").fetchone()[0] or until)
    start = start // HOUR * HOUR
    if start >= until:
        return
    conn.execute(f"""INSERT INTO flow_rollup ({FLOW_COLS})
        SELECT (last_seen / {HOUR}) * {HOUR}, node_id, device_id, MAX(user_email), MAX(device_name), MAX(node_name),
               src, dst, host, dport, proto, MAX(app), MAX(category), MAX(country), MAX(org),
               SUM(conns), SUM(bytes_in), SUM(bytes_out)
        FROM flow_log WHERE last_seen >= ? AND last_seen < ?
        GROUP BY 1, node_id, device_id, src, dst, host, dport, proto""", (start, until))
    conn.execute(f"""INSERT INTO dns_rollup ({DNS_COLS})
        SELECT (ts / {HOUR}) * {HOUR}, node_id, device_id, MAX(user_email), MAX(device_name), name, MAX(app),
               MAX(category), SUM(count)
        FROM dns_log WHERE ts >= ? AND ts < ? GROUP BY 1, node_id, device_id, name""", (start, until))
    conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('rollup_until', ?)", (str(until),))


def _sources(conn, since: int):
    """Tables to read: detailed logs for short ranges; hourly totals + the unfinished hours for long ones."""
    if since >= time.time() - 2 * 86400:
        return "flow_log", "dns_log"
    done = conn.execute("SELECT value FROM meta WHERE key = 'rollup_until'").fetchone()
    cut = int(done[0]) if done else 0
    return (f"(SELECT {FLOW_COLS} FROM flow_rollup WHERE last_seen < {cut} "
            f"UNION ALL SELECT {FLOW_COLS} FROM flow_log WHERE last_seen >= {cut})",
            f"(SELECT {DNS_COLS} FROM dns_rollup WHERE ts < {cut} "
            f"UNION ALL SELECT {DNS_COLS} FROM dns_log WHERE ts >= {cut})")


def _all_time(conn, now: int) -> tuple[int, int]:
    first = min([v for v in (conn.execute("SELECT MIN(last_seen) FROM flow_rollup").fetchone()[0],
                             conn.execute("SELECT MIN(last_seen) FROM flow_log").fetchone()[0]) if v] or [now - 86400])
    span = max(86400, now - first)
    bucket = next(b for b in (HOUR, 4 * HOUR, 12 * HOUR, 86400, 7 * 86400, 30 * 86400) if span / b <= 120)
    return span, bucket

# How a flow is labelled when grouping: its app, else the network owner, else Unknown.
APP = "COALESCE(NULLIF(app, ''), NULLIF(org, ''), 'Unknown')"
CATEGORY = "COALESCE(NULLIF(category, ''), 'Other')"
DEST = "COALESCE(NULLIF(host, ''), dst)"
BYTES = "SUM(bytes_in + bytes_out)"


def _where(f: dict, since: int, dns=False):
    """SQL filter for the dashboard's filter chips. dns=True: the same filters on dns_log."""
    clauses, params = [("ts" if dns else "last_seen") + " >= ?"], [since]
    if f.get("node"):
        clauses.append("node_id = ?"); params.append(int(f["node"]))
    if f.get("device"):
        clauses.append("device_id = ?"); params.append(int(f["device"]))
    if f.get("user"):
        clauses.append("user_email = ?"); params.append(f["user"])
    if f.get("category"):
        clauses.append(CATEGORY + " = ?"); params.append(f["category"])
    if f.get("app"):
        clauses.append(("COALESCE(NULLIF(app, ''), 'Unknown')" if dns else APP) + " = ?"); params.append(f["app"])
    if not dns:
        if f.get("country"):
            clauses.append("country = ?"); params.append(f["country"])
        if f.get("dest"):
            clauses.append(DEST + " = ?"); params.append(f["dest"])
        if f.get("port"):
            clauses.append("dport = ?"); params.append(int(f["port"]))
    elif f.get("country") or f.get("port"):
        clauses.append("0")  # DNS lookups have no destination country/port
    elif f.get("dest"):
        clauses.append("name = ?"); params.append(f["dest"])
    if f.get("q"):
        like = f"%{f['q']}%"
        cols = ["user_email", "device_name", "name"] if dns else ["user_email", "device_name", "host", "dst", "org",
                                                                  "app", "src"]
        clauses.append("(" + " OR ".join(f"{c} LIKE ?" for c in cols) + ")"); params += [like] * len(cols)
    return " AND ".join(clauses), params


def dashboard(conn, range_key: str, f: dict) -> dict:
    now = int(time.time())
    span, bucket = RANGES.get(range_key) or RANGES["24h"]
    if range_key == "all":
        span, bucket = _all_time(conn, now)
    since = now - span
    flows, dnslog = _sources(conn, since)
    where, p = _where(f, since)

    k = conn.execute(f"""SELECT COALESCE(SUM(bytes_in), 0) down, COALESCE(SUM(bytes_out), 0) up,
                         COALESCE(SUM(conns), 0) conns, COUNT(DISTINCT COALESCE(device_id, src)) clients,
                         COUNT(DISTINCT {DEST}) dests, COUNT(DISTINCT NULLIF(country, '')) countries
                         FROM {flows} WHERE {where}""", p).fetchone()
    dwhere, dp = _where(f, since, dns=True)
    dns_total = conn.execute(f"SELECT COALESCE(SUM(count), 0) FROM {dnslog} WHERE {dwhere}", dp).fetchone()[0]

    def top(group, label_cols, order=BYTES, limit=10, extra=""):
        rows = conn.execute(f"""SELECT {label_cols}, SUM(bytes_in) down, SUM(bytes_out) up, SUM(conns) conns,
                                COUNT(DISTINCT COALESCE(device_id, src)) clients {extra}
                                FROM {flows} WHERE {where} GROUP BY {group} ORDER BY {order} DESC LIMIT {limit}""",
                            p).fetchall()
        return [dict(r) for r in rows]

    categories = {r["name"]: dict(r) for r in conn.execute(
        f"""SELECT {CATEGORY} name, SUM(bytes_in) down, SUM(bytes_out) up, SUM(conns) conns
            FROM {flows} WHERE {where} GROUP BY name""", p)}
    timeline = {}
    for r in conn.execute(f"""SELECT (last_seen / {bucket}) * {bucket} t, {CATEGORY} c, {BYTES} b
                              FROM {flows} WHERE {where} GROUP BY t, c""", p):
        timeline.setdefault(r["t"], {})[r["c"]] = r["b"]

    # interface throughput from server metrics (accurate even for connections still open)
    mp = [since] + ([int(f["node"])] if f.get("node") else [])
    per_node = conn.execute(f"""SELECT (ts / {bucket}) * {bucket} t, node_id, AVG(rx_bps) rx, AVG(tx_bps) tx,
                                MAX(active_peers) peers FROM node_metrics WHERE ts >= ?
                                {'AND node_id = ?' if f.get('node') else ''} GROUP BY t, node_id""", mp).fetchall()
    tp = {}
    for r in per_node:
        a = tp.setdefault(r["t"], {"t": r["t"], "rx": 0, "tx": 0, "peers": 0})
        a["rx"] += r["rx"]; a["tx"] += r["tx"]; a["peers"] += r["peers"]

    app_rows = top(APP, f"{APP} name, MAX({CATEGORY}) category", limit=12)
    clients = top("COALESCE(device_id, src)", "device_id, MAX(user_email) user, MAX(device_name) device, "
                  "MAX(src) ip", limit=10)
    for c in clients:  # what each client mostly uses
        r = conn.execute(f"""SELECT {APP} a FROM {flows} WHERE {where} AND COALESCE(device_id, src) = ?
                             GROUP BY a ORDER BY {BYTES} DESC LIMIT 1""",
                         p + [c["device_id"] if c["device_id"] is not None else c["ip"]]).fetchone()
        c["top_app"] = r["a"] if r else ""
    dns_rows = conn.execute(f"""SELECT name, MAX(COALESCE(NULLIF(app, ''), '')) app, MAX(category) category,
                                SUM(count) lookups, COUNT(DISTINCT COALESCE(device_id, user_email)) clients
                                FROM {dnslog} WHERE {dwhere} GROUP BY name ORDER BY lookups DESC LIMIT 12""",
                            dp).fetchall()
    servers = conn.execute(f"""SELECT node_id id, MAX(node_name) name, SUM(bytes_in) down, SUM(bytes_out) up,
                               SUM(conns) conns FROM {flows} WHERE {where} GROUP BY node_id
                               ORDER BY {BYTES} DESC LIMIT 10""", p).fetchall()
    return {
        "range": range_key, "bucket": bucket, "since": since, "until": now,
        "kpi": {"down": k["down"], "up": k["up"], "conns": k["conns"], "clients": k["clients"],
                "dests": k["dests"], "countries": k["countries"], "dns": dns_total,
                "top_app": app_rows[0]["name"] if app_rows else ""},
        "categories": [dict(categories.get(c, {"name": c, "down": 0, "up": 0, "conns": 0})) for c in apps.CATEGORIES],
        "timeline": [{"t": t, **v} for t, v in sorted(timeline.items())],
        "throughput": sorted(tp.values(), key=lambda a: a["t"]),
        "apps": app_rows,
        "clients": clients,
        "destinations": top(DEST, f"{DEST} name, MAX(dst) ip, MAX(org) org, MAX(country) country, "
                                  f"MAX({APP}) app, MAX({CATEGORY}) category", limit=12),
        "countries": top("country", "country code", limit=10, extra=", COUNT(DISTINCT dst) dests"),
        "ports": top("dport, proto", "dport port, proto", order="SUM(conns)", limit=8),
        "dns": [dict(r) for r in dns_rows],
        "servers": [dict(r) for r in servers],
    }


def live(conn, f: dict, after: int = 0, limit: int = 60) -> list[dict]:
    """Newest flows (for the live feed), optionally only those newer than id `after`."""
    where, p = _where(f, int(time.time()) - 7 * 86400)
    rows = conn.execute(f"""SELECT id, first_seen, last_seen, user_email, device_name, device_id, node_name, src,
                            dst, host, dport, proto, conns, bytes_in, bytes_out, {APP} app, {CATEGORY} category,
                            country, org FROM flow_log WHERE {where} AND id > ? ORDER BY id DESC LIMIT {limit}""",
                        p + [after]).fetchall()
    return [dict(r) for r in rows]
