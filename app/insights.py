"""Traffic insights: aggregates over the destination log for the admin dashboard (UniFi-style)."""
import time

from . import apps

RANGES = {"1h": (3600, 120), "24h": (86400, 1800), "7d": (7 * 86400, 4 * 3600)}  # span, bucket seconds

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
    span, bucket = RANGES.get(range_key, RANGES["24h"])
    now = int(time.time())
    since = now - span
    where, p = _where(f, since)

    k = conn.execute(f"""SELECT COALESCE(SUM(bytes_in), 0) down, COALESCE(SUM(bytes_out), 0) up,
                         COALESCE(SUM(conns), 0) conns, COUNT(DISTINCT COALESCE(device_id, src)) clients,
                         COUNT(DISTINCT {DEST}) dests, COUNT(DISTINCT NULLIF(country, '')) countries
                         FROM flow_log WHERE {where}""", p).fetchone()
    dwhere, dp = _where(f, since, dns=True)
    dns_total = conn.execute(f"SELECT COALESCE(SUM(count), 0) FROM dns_log WHERE {dwhere}", dp).fetchone()[0]

    def top(group, label_cols, order=BYTES, limit=10, extra=""):
        rows = conn.execute(f"""SELECT {label_cols}, SUM(bytes_in) down, SUM(bytes_out) up, SUM(conns) conns,
                                COUNT(DISTINCT COALESCE(device_id, src)) clients {extra}
                                FROM flow_log WHERE {where} GROUP BY {group} ORDER BY {order} DESC LIMIT {limit}""",
                            p).fetchall()
        return [dict(r) for r in rows]

    categories = {r["name"]: dict(r) for r in conn.execute(
        f"""SELECT {CATEGORY} name, SUM(bytes_in) down, SUM(bytes_out) up, SUM(conns) conns
            FROM flow_log WHERE {where} GROUP BY name""", p)}
    timeline = {}
    for r in conn.execute(f"""SELECT (last_seen / {bucket}) * {bucket} t, {CATEGORY} c, {BYTES} b
                              FROM flow_log WHERE {where} GROUP BY t, c""", p):
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
        r = conn.execute(f"""SELECT {APP} a FROM flow_log WHERE {where} AND COALESCE(device_id, src) = ?
                             GROUP BY a ORDER BY {BYTES} DESC LIMIT 1""",
                         p + [c["device_id"] if c["device_id"] is not None else c["ip"]]).fetchone()
        c["top_app"] = r["a"] if r else ""
    dns_rows = conn.execute(f"""SELECT name, MAX(COALESCE(NULLIF(app, ''), '')) app, MAX(category) category,
                                SUM(count) lookups, COUNT(DISTINCT COALESCE(device_id, user_email)) clients
                                FROM dns_log WHERE {dwhere} GROUP BY name ORDER BY lookups DESC LIMIT 12""",
                            dp).fetchall()
    servers = conn.execute(f"""SELECT node_id id, MAX(node_name) name, SUM(bytes_in) down, SUM(bytes_out) up,
                               SUM(conns) conns FROM flow_log WHERE {where} GROUP BY node_id
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
