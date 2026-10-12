"""VN-VPN management panel: client portal, admin console, provisioning API and agent API."""
import asyncio
import csv
import hashlib
import io
import logging
import ipaddress
import os
import re
import secrets
import threading
import time
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import qrcode
import qrcode.image.svg
from fastapi import Depends, FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

from . import apps, billing, countries, crypto, db, geo, insights, monitoring

log = logging.getLogger("vnvpn")

BASE = Path(__file__).parent
AGENT_DIR = BASE.parent / "agent"
AGENT_VERSION = re.search(r'^VERSION = "([^"]+)"', (AGENT_DIR / "agent.py").read_text(), re.M).group(1)



def _secret_key() -> str:
    """Use SECRET_KEY, else a key persisted next to the database so sessions survive restarts."""
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    path = Path(db.DB_PATH).parent / "secret.key"
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(secrets.token_hex(32))
        path.chmod(0o600)
    return path.read_text().strip()


SECRET_KEY = _secret_key()
PUBLIC_URL = os.environ.get("PUBLIC_URL", "").strip().rstrip("/")
# Coolify's SERVICE_FQDN_* is a bare domain ("vpn.example.com"); assume HTTPS when no scheme is given.
if PUBLIC_URL and "://" not in PUBLIC_URL:
    PUBLIC_URL = "https://" + PUBLIC_URL
BRAND = os.environ.get("BRAND_NAME", "VN-VPN")
OPEN_SIGNUP = os.environ.get("OPEN_SIGNUP", "true").lower() in ("1", "true", "yes")
PROVISION_API_KEY = os.environ.get("PROVISION_API_KEY", "")
NODE_OFFLINE_AFTER = timedelta(seconds=int(os.environ.get("NODE_OFFLINE_AFTER", "90")))
NODE_CAPACITY = int(os.environ.get("NODE_CAPACITY", "250"))  # active users before a node shows as "busy"
ACTIVE_WINDOW = 180  # seconds since last handshake that still counts as connected
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

app = FastAPI(title=BRAND, docs_url="/api/docs", redoc_url=None)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, same_site="lax",
                   https_only=PUBLIC_URL.startswith("https://"), max_age=14 * 24 * 3600)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
templates = Jinja2Templates(directory=BASE / "templates")
templates.env.globals["brand"] = BRAND
templates.env.globals["open_signup"] = OPEN_SIGNUP


def human_bytes(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def ago(value):
    """'3 min ago' from an ISO timestamp (UTC) or a unix timestamp."""
    if not value:
        return "never"
    if isinstance(value, (int, float)):
        ts = float(value)
    else:
        ts = datetime.fromisoformat(value).replace(tzinfo=timezone.utc).timestamp()
    secs = max(0, int(now_utc().timestamp() - ts))
    for unit, size in (("d", 86400), ("h", 3600), ("min", 60)):
        if secs >= size:
            return f"{secs // size} {unit} ago"
    return "just now"


def human_bps(bps):
    bps = float(bps or 0)
    for unit in ("bps", "Kbps", "Mbps", "Gbps"):
        if bps < 1000 or unit == "Gbps":
            return f"{bps:.0f} {unit}" if unit == "bps" else f"{bps:.1f} {unit}"
        bps /= 1000


def duration(secs):
    secs = int(secs or 0)
    d, h, m = secs // 86400, secs % 86400 // 3600, secs % 3600 // 60
    return f"{d}d {h}h" if d else f"{h}h {m}m" if h else f"{m}m" if m else f"{secs}s"


def fmt_ts(ts):
    return datetime.fromtimestamp(int(ts), timezone.utc).strftime("%b %-d %H:%M") if ts else "—"


PORT_NAMES = {80: "HTTP", 443: "HTTPS", 53: "DNS", 853: "DNS-TLS", 22: "SSH", 25: "SMTP", 465: "SMTPS",
              587: "SMTP", 993: "IMAPS", 995: "POP3S", 123: "NTP", 3478: "STUN", 5228: "Google Play",
              5223: "Apple Push", 1194: "OpenVPN", 51820: "WireGuard", 3389: "RDP", 8080: "HTTP-alt"}


def port_name(port, proto=""):
    if proto == "icmp":
        return "ping"
    name = PORT_NAMES.get(int(port or 0))
    return f"{port} · {name}" if name else str(port)


templates.env.filters["bps"] = human_bps
templates.env.filters["duration"] = duration
templates.env.filters["ts"] = fmt_ts
templates.env.filters["port"] = port_name
templates.env.filters["bytes"] = human_bytes
templates.env.filters["ago"] = ago
templates.env.filters["flag"] = countries.flag
templates.env.globals["countries"] = countries.COUNTRIES
templates.env.globals["plans"] = billing.PLANS            # public plans (pricing pages)
templates.env.globals["all_plans"] = billing.ALL_PLANS    # incl. admin-only plans
templates.env.globals["limit_label"] = billing.limit_label


def _asset_version(name: str) -> str:
    """Content hash for cache-busting, so a deploy never leaves browsers on a stale app.js / style.css."""
    return hashlib.sha256((BASE / "static" / name).read_bytes()).hexdigest()[:10]


templates.env.globals["asset_v"] = {n: _asset_version(n) for n in ("app.js", "style.css", "insights.js")}


# --------------------------------------------------------------------------- helpers

def now_utc():
    return datetime.now(timezone.utc)


def node_online(node) -> bool:
    if not node["last_seen"]:
        return False
    seen = datetime.fromisoformat(node["last_seen"]).replace(tzinfo=timezone.utc)
    return now_utc() - seen < NODE_OFFLINE_AFTER


def panel_url(request: Request) -> str:
    if PUBLIC_URL:
        return PUBLIC_URL
    proto = request.headers.get("x-forwarded-proto", request.url.scheme)
    host = request.headers.get("x-forwarded-host", request.headers.get("host", request.url.netloc))
    return f"{proto}://{host}"


def client_ip_of(request: Request) -> str:
    # Behind Cloudflare, X-Forwarded-For / X-Real-IP set by the reverse proxy hold Cloudflare's address;
    # CF-Connecting-IP holds the real client.
    for header in ("cf-connecting-ip", "true-client-ip"):
        if request.headers.get(header):
            return request.headers[header].strip()
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.headers.get("x-real-ip") or (request.client.host if request.client else "")


def create_user(conn, email: str, password: str, is_admin=False, plan=""):
    email = email.strip().lower()
    if not EMAIL_RE.match(email):
        raise ValueError("Please enter a valid email address.")
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters.")
    if conn.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
        raise ValueError("An account with that email already exists.")
    if plan and plan not in billing.ALL_PLANS:
        raise ValueError(f"Unknown plan '{plan}'. Use one of: {', '.join(billing.ALL_PLANS)}.")
    # users.private_key/public_key predate per-device keys; still filled because the columns are NOT NULL
    priv, pub = crypto.wg_keypair()
    cur = conn.execute(
        "INSERT INTO users (email, password_hash, is_admin, private_key, public_key, plan, plan_source) "
        "VALUES (?,?,?,?,?,?,?)",
        (email, crypto.hash_password(password), int(is_admin), priv, pub, plan, "manual" if plan else ""),
    )
    return cur.lastrowid


def current_user(request: Request):
    uid = request.session.get("uid")
    if not uid:
        return None
    with db.session() as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()


def require_user(request: Request):
    user = current_user(request)
    if not user:
        raise HTTPException(status_code=303, headers={"Location": "/login"})
    return user


def require_admin(request: Request):
    user = require_user(request)
    if not user["is_admin"]:
        raise HTTPException(status_code=403, detail="Admins only")
    return user


async def json_body(request: Request) -> dict:
    """Read a JSON object body. Handlers that need it can then be plain `def` and run in the thread pool,
    so slow work (SQLite, Stripe calls) never blocks the event loop - or the container health check."""
    try:
        body = await request.json()
    except ValueError:
        raise HTTPException(400, "Invalid JSON")
    if not isinstance(body, dict):
        raise HTTPException(400, "Invalid body")
    return body


async def raw_body(request: Request) -> bytes:
    return await request.body()


def flash(request: Request, message: str, kind="ok"):
    request.session.setdefault("flash", []).append([kind, message])


def render(request: Request, name: str, **ctx):
    if "user" not in ctx:
        ctx["user"] = current_user(request)
    ctx["flashes"] = request.session.pop("flash", [])
    return templates.TemplateResponse(request, name, ctx)


def visible_nodes(conn):
    rows = conn.execute("SELECT * FROM nodes WHERE enabled = 1 ORDER BY location, name").fetchall()
    return [dict(r, online=node_online(r)) for r in rows]


@app.on_event("startup")
async def startup():
    db.init()
    asyncio.get_running_loop().create_task(monitoring.background_loop(node_online))
    admin_email = os.environ.get("ADMIN_EMAIL")
    admin_password = os.environ.get("ADMIN_PASSWORD")
    if admin_email and admin_password:
        with db.session() as conn:
            row = conn.execute("SELECT id FROM users WHERE email = ?", (admin_email.lower(),)).fetchone()
            if row:
                conn.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (row["id"],))
            elif not conn.execute("SELECT 1 FROM users WHERE is_admin = 1").fetchone():
                # bootstrap only: once an admin exists (possibly renamed), don't recreate ADMIN_EMAIL
                create_user(conn, admin_email, admin_password, is_admin=True)


@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, exc: StarletteHTTPException):
    if exc.status_code == 303:
        return RedirectResponse(exc.headers["Location"], status_code=303)
    if request.url.path.startswith(("/api/", "/agent/", "/billing/webhook")):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
    resp = render(request, "error.html", code=exc.status_code, detail=exc.detail)
    resp.status_code = exc.status_code
    return resp


# --------------------------------------------------------------------------- auth pages

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    """Public homepage: what the service is, locations (no server status), pricing."""
    with db.session() as conn:
        rows = conn.execute("SELECT name, location, country FROM nodes WHERE enabled = 1").fetchall()
    locations = {}
    for r in rows:  # one entry per city, however many servers it has
        city = r["location"] or r["name"]
        locations[(r["country"], city.lower())] = {"city": city, "country": r["country"],
                                                   "country_name": countries.COUNTRIES.get(r["country"], "")}
    locations = sorted(locations.values(), key=lambda l: (l["country_name"] or l["city"], l["city"]))
    country_count = len({l["country"] or l["city"] for l in locations})
    return render(request, "landing.html", locations=locations, country_count=country_count,
                  **plan_context_public())


def plan_context_public():
    return {"billing_enabled": billing.enabled(),
            "price_labels": {k: billing.price_label(k) for k in billing.PLANS} if billing.enabled()
            else {k: p["price_label"] for k, p in billing.PLANS.items()}}


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return render(request, "login.html")


@app.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...)):
    with db.session() as conn:
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email.strip().lower(),)).fetchone()
    if not user or not crypto.verify_password(password, user["password_hash"]):
        flash(request, "Invalid email or password.", "error")
        return RedirectResponse("/login", status_code=303)
    request.session["uid"] = user["id"]
    return RedirectResponse("/admin" if user["is_admin"] else "/portal", status_code=303)


@app.get("/signup", response_class=HTMLResponse)
def signup_page(request: Request):
    if not OPEN_SIGNUP:
        raise HTTPException(404, "Sign-up is closed.")
    plan = request.query_params.get("plan", "")
    return render(request, "signup.html", plan=plan if plan in billing.PLANS else "")


@app.post("/signup")
def signup(request: Request, email: str = Form(...), password: str = Form(...)):
    if not OPEN_SIGNUP:
        raise HTTPException(404, "Sign-up is closed.")
    try:
        with db.session() as conn:
            uid = create_user(conn, email, password)
    except ValueError as e:
        flash(request, str(e), "error")
        return RedirectResponse("/signup", status_code=303)
    request.session["uid"] = uid
    flash(request, "Welcome! Pick a plan to start using the VPN.")
    if request.query_params.get("plan") in billing.PLANS and billing.enabled():
        return billing_checkout(request, request.query_params["plan"])
    return RedirectResponse("/portal", status_code=303)


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# --------------------------------------------------------------------------- devices & connection limits

def clean_name(name: str) -> str:
    name = re.sub(r"[\x00-\x1f\x7f]", "", name or "").strip()
    return name[:40] or "My device"


def user_devices(conn, user):
    now = time.time()
    devices = [dict(d) for d in conn.execute("SELECT * FROM devices WHERE user_id = ? ORDER BY id", (user["id"],))]
    allowed = allowed_device_ids(conn, user_id=user["id"])
    nodes = {n["id"]: n["name"] for n in conn.execute("SELECT id, name FROM nodes")}
    for d in devices:
        # a device can have tunnels up to several servers at once (e.g. WireGuard on Windows)
        live = conn.execute("""SELECT node_id, rx_bytes, tx_bytes FROM device_stats
                               WHERE device_id = ? AND last_handshake > ? ORDER BY last_handshake DESC""",
                            (d["id"], now - ACTIVE_WINDOW)).fetchall()
        d["connected"] = d["id"] in allowed and bool(live)
        d["node_ids"] = [r["node_id"] for r in live] if d["connected"] else []
        d["node_id"] = d["node_ids"][0] if d["node_ids"] else None
        d["node_name"] = ", ".join(nodes.get(i, "") for i in d["node_ids"])
        d["down"] = sum(r["tx_bytes"] for r in live) if d["connected"] else 0
        d["up"] = sum(r["rx_bytes"] for r in live) if d["connected"] else 0
        d["kicked"] = d["kicked_until"] > now
        d["shared"] = now - d["shared_at"] < 3600
        d["downloaded"] = [r[0] for r in conn.execute(
            "SELECT node_id FROM device_downloads WHERE device_id = ?", (d["id"],))]
        d["downloaded_names"] = [nodes[i] for i in d["downloaded"] if i in nodes]
        d["blocked"] = not d["kicked"] and d["id"] not in allowed  # waiting for a free slot
    return devices


def allowed_device_ids(conn, user_id=None) -> set[int]:
    """Devices that servers should accept right now.

    Each plan allows N devices connected at the same time. While fewer than N are connected every device may
    connect; once N are, only those keep their slot (first connected wins) until one goes idle for
    ACTIVE_WINDOW seconds or is disconnected from the portal."""
    now = time.time()
    sql = """SELECT d.id, d.user_id, d.last_handshake, d.active_since, d.kicked_until,
                    u.status, u.is_admin, u.plan, u.plan_source, u.sub_status
             FROM devices d JOIN users u ON u.id = d.user_id"""
    rows = conn.execute(sql + (" WHERE d.user_id = ?" if user_id else ""), (user_id,) if user_id else ()).fetchall()
    by_user: dict[int, list] = {}
    for r in rows:
        by_user.setdefault(r["user_id"], []).append(r)
    allowed = set()
    for devs in by_user.values():
        limit = billing.device_limit(devs[0])
        if limit <= 0:
            continue
        candidates = [d for d in devs if d["kicked_until"] <= now]
        live = sorted((d for d in candidates if now - d["last_handshake"] < ACTIVE_WINDOW),
                      key=lambda d: (d["active_since"] or d["last_handshake"], d["id"]))
        chosen = live[:limit] if len(live) >= limit else candidates
        allowed.update(d["id"] for d in chosen)
    return allowed


# --------------------------------------------------------------------------- client portal

def portal_nodes(conn, devices):
    """Servers visible to a client, with load and which of their devices is on it."""
    nodes = visible_nodes(conn)
    now = time.time()
    active = {r["node_id"]: r["n"] for r in conn.execute(
        "SELECT node_id, COUNT(*) n FROM device_stats WHERE last_handshake > ? GROUP BY node_id",
        (now - ACTIVE_WINDOW,))}
    for n in nodes:
        n["here"] = [{"id": d["id"], "name": d["name"]} for d in devices if d["connected"] and n["id"] in d["node_ids"]]
        n["devices_here"] = [d["name"] for d in n["here"]]
        n["connected"] = bool(n["devices_here"])
        n["load"] = min(100, round(100 * active.get(n["id"], 0) / NODE_CAPACITY))
        n["country_name"] = countries.COUNTRIES.get(n["country"], "")
        n["recommended"] = False
    names = tunnel_names(nodes)
    for n in nodes:
        n["tunnel"] = names[n["id"]]
    online = [n for n in nodes if n["online"]]
    if len(online) > 1:
        min(online, key=lambda n: n["load"])["recommended"] = True
    nodes.sort(key=lambda n: (not n["online"], n["country_name"] or n["location"], n["name"]))
    return nodes


def plan_context(user):
    plan = billing.ALL_PLANS.get(user["plan"])
    limit = billing.device_limit(user)
    return {
        "plan": plan, "plan_key": user["plan"], "limit": limit, "limit_text": billing.limit_label(limit),
        "renews": datetime.fromtimestamp(user["period_end"], timezone.utc).strftime("%b %-d, %Y")
        if user["period_end"] else "",
        "billing_enabled": billing.enabled(),
        "price_labels": {k: billing.price_label(k) for k in billing.PLANS} if billing.enabled()
        else {k: p["price_label"] for k, p in billing.PLANS.items()},
    }


USAGE_PERIODS = {"month": "This month", "30d": "Last 30 days", "all": "All time"}


def user_usage(conn, user_id: int, period: str) -> dict:
    """Data used per location for a customer over a period (UTC days)."""
    today = now_utc().date()
    since = {"month": today.replace(day=1).isoformat(), "30d": (today - timedelta(days=29)).isoformat(),
             "all": "0000-00-00"}[period]
    rows = [dict(r) for r in conn.execute("""
        SELECT n.id, n.name, n.location, n.country, SUM(u.down) down, SUM(u.up) up
        FROM usage_daily u JOIN nodes n ON n.id = u.node_id
        WHERE u.user_id = ? AND u.day >= ? GROUP BY n.id ORDER BY SUM(u.down + u.up) DESC""", (user_id, since))]
    peak = max((r["down"] + r["up"] for r in rows), default=0)
    for r in rows:
        r["total"] = r["down"] + r["up"]
        r["pct"] = round(100 * r["total"] / peak) if peak else 0
        r["country_name"] = countries.COUNTRIES.get(r["country"], "")
    return {"rows": rows, "down": sum(r["down"] for r in rows), "up": sum(r["up"] for r in rows),
            "period": period, "label": USAGE_PERIODS[period]}


@app.get("/portal", response_class=HTMLResponse)
def portal(request: Request):
    user = require_user(request)
    if not billing.has_access(user):
        return render(request, "pricing.html", **plan_context(user))
    with db.session() as conn:
        if not conn.execute("SELECT 1 FROM devices WHERE user_id = ?", (user["id"],)).fetchone():
            # first visit after subscribing: one ready-to-use device, named after the phone it's opened on
            add_device(conn, user, MOBILE_DEVICE_NAMES.get(mobile_os(request), "My device"))
        devices = user_devices(conn, user)
        nodes = portal_nodes(conn, devices)
        period = request.query_params.get("usage", "month")
        usage = user_usage(conn, user["id"], period if period in USAGE_PERIODS else "month")
    connected = [d for d in devices if d["connected"]]
    return render(request, "portal.html", nodes=nodes, devices=devices, connected=connected, usage=usage,
                  downloaded_map={str(d["id"]): d["downloaded"] for d in devices},
                  device_nodes={str(d["id"]): {"name": d["name"], "nodes": d["node_ids"]} for d in devices},
                  usage_periods=USAGE_PERIODS,
                  ever_connected=any(d["last_handshake"] for d in devices), max_devices=billing.MAX_DEVICES,
                  mobile_os=mobile_os(request),
                  **plan_context(user))


@app.get("/pricing", response_class=HTMLResponse)
def pricing(request: Request):
    user = require_user(request)
    return render(request, "pricing.html", **plan_context(user))


@app.get("/portal/status.json")
def portal_status(request: Request):
    user = require_user(request)
    with db.session() as conn:
        devices = user_devices(conn, user)
        nodes = portal_nodes(conn, devices)
    return {
        "limit": billing.device_limit(user),
        "devices": [{k: d[k] for k in ("id", "name", "connected", "blocked", "kicked", "node_name", "down", "up")}
                    for d in devices],
        "nodes": [{k: n[k] for k in ("id", "name", "online", "connected", "devices_here", "load")} for n in nodes],
    }


def change_email(conn, user, new_email: str) -> str:
    """Change a user's login email (also in Stripe and in the logs). Returns the normalized email."""
    new_email = new_email.strip().lower()
    if not EMAIL_RE.match(new_email):
        raise ValueError("Please enter a valid email address.")
    if new_email == user["email"]:
        return new_email
    if conn.execute("SELECT 1 FROM users WHERE email = ? AND id != ?", (new_email, user["id"])).fetchone():
        raise ValueError("Another account already uses that email.")
    conn.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, user["id"]))
    for table in ("sessions", "flow_log"):  # keep the traffic log searchable under the new address
        conn.execute(f"UPDATE {table} SET user_email = ? WHERE user_email = ?", (new_email, user["email"]))
    billing.update_customer_email(user, new_email)
    return new_email


@app.post("/account/email")
def account_email(request: Request, email: str = Form(...), password: str = Form(...)):
    user = require_user(request)
    if not crypto.verify_password(password, user["password_hash"]):
        flash(request, "Your password is incorrect.", "error")
        return RedirectResponse("/portal#account", status_code=303)
    try:
        with db.session() as conn:
            new = change_email(conn, user, email)
        flash(request, f"Your login email is now {new}.")
    except ValueError as e:
        flash(request, str(e), "error")
    return RedirectResponse("/portal#account", status_code=303)


@app.post("/account/password")
def change_password(request: Request, current: str = Form(...), new: str = Form(...)):
    user = require_user(request)
    if not crypto.verify_password(current, user["password_hash"]):
        flash(request, "Your current password is incorrect.", "error")
    elif len(new) < 8:
        flash(request, "New password must be at least 8 characters.", "error")
    else:
        with db.session() as conn:
            conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (crypto.hash_password(new), user["id"]))
        flash(request, "Password updated.")
    return RedirectResponse("/portal#account", status_code=303)


def add_device(conn, user, name: str) -> int:
    priv, pub = crypto.wg_keypair()
    cur = conn.execute("INSERT INTO devices (user_id, name, private_key, public_key, address) VALUES (?,?,?,?,?)",
                       (user["id"], clean_name(name), priv, pub, crypto.allocate_address(conn)))
    return cur.lastrowid


def require_access(request: Request):
    user = require_user(request)
    if not billing.has_access(user):
        raise HTTPException(303, headers={"Location": "/portal"})
    return user


def _own_device(conn, user, device_id: int):
    d = conn.execute("SELECT * FROM devices WHERE id = ? AND user_id = ?", (device_id, user["id"])).fetchone()
    if not d:
        raise HTTPException(404, "Device not found.")
    return d


@app.post("/portal/devices")
def portal_add_device(request: Request, name: str = Form("")):
    user = require_access(request)
    with db.session() as conn:
        count = conn.execute("SELECT COUNT(*) FROM devices WHERE user_id = ?", (user["id"],)).fetchone()[0]
        if billing.MAX_DEVICES and count >= billing.MAX_DEVICES:
            flash(request, f"You can have up to {billing.MAX_DEVICES} devices. Remove one you no longer use.", "error")
            return RedirectResponse("/portal#devices", status_code=303)
        device_id = add_device(conn, user, name)
    flash(request, f"Added {clean_name(name)}. Now download a location for it below.")
    return RedirectResponse(f"/portal?device={device_id}#locations", status_code=303)


@app.post("/portal/devices/{device_id}/rename")
def portal_rename_device(request: Request, device_id: int, name: str = Form(...)):
    user = require_access(request)
    with db.session() as conn:
        _own_device(conn, user, device_id)
        conn.execute("UPDATE devices SET name = ? WHERE id = ?", (clean_name(name), device_id))
    return RedirectResponse("/portal#devices", status_code=303)


@app.post("/portal/devices/{device_id}/disconnect")
def portal_disconnect_device(request: Request, device_id: int):
    """Free a connection slot right away (e.g. to switch from laptop to phone)."""
    user = require_access(request)
    with db.session() as conn:
        d = _own_device(conn, user, device_id)
        # Block long enough for its last handshake to go stale, so it can't reclaim the slot it just gave up.
        conn.execute("UPDATE devices SET kicked_until = ?, active_since = 0 WHERE id = ?",
                     (int(time.time()) + ACTIVE_WINDOW + 30, device_id))
    flash(request, f"{d['name']} disconnected. Your other device can connect now (within ~15 seconds).")
    return RedirectResponse("/portal#devices", status_code=303)


@app.post("/portal/devices/{device_id}/delete")
def portal_delete_device(request: Request, device_id: int):
    user = require_user(request)
    with db.session() as conn:
        d = _own_device(conn, user, device_id)
        conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))
    flash(request, f"Removed {d['name']}. Its configs stop working within ~15 seconds.")
    return RedirectResponse("/portal#devices", status_code=303)


def _device_node(request: Request, node_id: int, device_id: int):
    user = require_access(request)
    with db.session() as conn:
        device = _own_device(conn, user, device_id)
        node = conn.execute("SELECT * FROM nodes WHERE id = ? AND enabled = 1", (node_id,)).fetchone()
    if not node:
        raise HTTPException(404, "Server not found.")
    return user, device, node


def _conf_name(node) -> str:
    label = node["location"] or node["name"]
    if node["country"]:
        label = f"{node['country']}-{label}"
    slug = re.sub(r"[^A-Za-z0-9_=+.-]+", "-", label).strip("-")
    return slug[:15] or f"vpn-{node['id']}"  # WireGuard tunnel names: max 15 chars, no spaces


def tunnel_names(nodes) -> dict[int, str]:
    """The name each location gets in the WireGuard app (the config's file name), unique per customer."""
    names, used = {}, set()
    for n in sorted(nodes, key=lambda n: n["id"]):
        name = _conf_name(n)
        if name in used:
            name = f"{name[:15 - len(str(n['id'])) - 1]}-{n['id']}"
        used.add(name)
        names[n["id"]] = name
    return names


def tunnel_name(conn, node) -> str:
    return tunnel_names(conn.execute("SELECT id, name, location, country FROM nodes WHERE enabled = 1").fetchall()
                        ).get(node["id"]) or _conf_name(node)


MOBILE_DEVICE_NAMES = {"ios": "iPhone", "android": "Android phone"}


def mobile_os(request: Request) -> str:
    ua = request.headers.get("user-agent", "")
    return "ios" if re.search(r"iPhone|iPad|iPod", ua) else "android" if "Android" in ua else ""


def _mark_downloaded(device_id: int, node_ids):
    with db.session() as conn:
        conn.executemany("INSERT OR IGNORE INTO device_downloads (device_id, node_id, first_at) VALUES (?,?,?)",
                         [(device_id, n, int(time.time())) for n in node_ids])


@app.get("/portal/config/{node_id}.conf")
def download_config(request: Request, node_id: int, device: int):
    user, dev, node = _device_node(request, node_id, device)
    _mark_downloaded(dev["id"], [node["id"]])
    with db.session() as conn:
        name = tunnel_name(conn, node)
    # the file name becomes the tunnel's name in WireGuard; octet-stream so phones keep the .conf extension
    return Response(crypto.client_config(dev, node, user["email"]), media_type="application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="{name}.conf"'})


@app.get("/portal/qr/{node_id}.svg")
def config_qr(request: Request, node_id: int, device: int):
    user, dev, node = _device_node(request, node_id, device)
    _mark_downloaded(dev["id"], [node["id"]])
    img = qrcode.make(crypto.client_config(dev, node, user["email"]), image_factory=qrcode.image.svg.SvgPathImage,
                      box_size=8, border=2)
    buf = io.BytesIO()
    img.save(buf)
    return Response(buf.getvalue(), media_type="image/svg+xml", headers={"Cache-Control": "no-store"})


@app.get("/portal/configs.zip")
def download_all(request: Request, device: int):
    user = require_access(request)
    with db.session() as conn:
        dev = _own_device(conn, user, device)
        nodes = conn.execute("SELECT * FROM nodes WHERE enabled = 1").fetchall()
    buf = io.BytesIO()
    names = tunnel_names(nodes)
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for n in nodes:
            zf.writestr(f"{names[n['id']]}.conf", crypto.client_config(dev, n, user["email"]))
    _mark_downloaded(dev["id"], [n["id"] for n in nodes])
    fname = re.sub(r"[^A-Za-z0-9_.-]+", "-", f"{BRAND}-{dev['name']}")
    return Response(buf.getvalue(), media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{fname}.zip"'})


# --------------------------------------------------------------------------- billing

@app.post("/billing/checkout")
def billing_checkout(request: Request, plan: str = Form(...)):
    user = require_user(request)
    if plan not in billing.PLANS or not billing.enabled() or not billing.PLANS[plan]["price_id"]:
        raise HTTPException(400, "That plan isn't available.")
    if user["plan_source"] == "stripe" and user["sub_status"] in billing.LIVE_STATUSES:
        return billing_change(request, plan)  # already subscribed: switch plans instead of a 2nd subscription
    try:
        url = billing.checkout_url(user, plan, panel_url(request))
    except billing.stripe.StripeError as e:
        flash(request, f"Couldn't start checkout: {e.user_message or 'payment provider error'}", "error")
        return RedirectResponse("/portal", status_code=303)
    return RedirectResponse(url, status_code=303)


@app.get("/billing/success")
def billing_success(request: Request, session_id: str = ""):
    require_user(request)
    try:
        with db.session() as conn:
            billing.complete_checkout(conn, session_id)
        flash(request, "Payment received — you're all set! Download a location below to connect.")
    except Exception:  # the webhook will still activate the account
        flash(request, "Payment received. Your plan activates in a few seconds — refresh if it doesn't.", "info")
    return RedirectResponse("/portal", status_code=303)


@app.post("/billing/change")
def billing_change(request: Request, plan: str = Form(...)):
    user = require_user(request)
    if plan not in billing.PLANS or not user["stripe_subscription_id"] or not billing.enabled():
        raise HTTPException(400, "Can't change plan.")
    try:
        with db.session() as conn:
            billing.change_plan(conn, user, plan)
        p = billing.PLANS[plan]
        flash(request, f"You're now on {p['name']} — {p['devices']} device{'s' if p['devices'] > 1 else ''} at a time.")
    except billing.stripe.StripeError as e:
        flash(request, f"Couldn't change plan: {e.user_message or 'payment provider error'}", "error")
    return RedirectResponse("/portal#account", status_code=303)


@app.post("/billing/portal")
def billing_portal(request: Request):
    user = require_user(request)
    if not user["stripe_customer_id"] or not billing.enabled():
        raise HTTPException(400, "No billing account yet.")
    return RedirectResponse(billing.portal_url(user, f"{panel_url(request)}/portal#account"), status_code=303)


@app.post("/billing/webhook")
def billing_webhook(payload: bytes = Depends(raw_body), stripe_signature: str | None = Header(None)):
    try:
        with db.session() as conn:
            kind = billing.handle_webhook(conn, payload, stripe_signature)
    except ValueError:
        raise HTTPException(400, "Bad signature")
    return {"received": kind}


# --------------------------------------------------------------------------- admin console

def admin_nodes(conn):
    return [dict(r, online=node_online(r)) for r in conn.execute(f"""
        SELECT n.*, COALESCE(SUM(s.rx_bytes),0) rx, COALESCE(SUM(s.tx_bytes),0) tx,
               COUNT(CASE WHEN s.last_handshake > strftime('%s','now') - {ACTIVE_WINDOW} THEN 1 END) active_peers
        FROM nodes n LEFT JOIN device_stats s ON s.node_id = n.id
        GROUP BY n.id ORDER BY n.id""")]


def live_sessions(conn):
    """Devices with a recent handshake, newest first, with the server they're on."""
    rows = conn.execute("""
        SELECT d.id, d.name device, d.active_since, u.email, n.name node, s.rx_bytes, s.tx_bytes, s.last_handshake
        FROM devices d JOIN users u ON u.id = d.user_id
        JOIN device_stats s ON s.device_id = d.id
        JOIN nodes n ON n.id = s.node_id
        WHERE s.last_handshake > ? ORDER BY d.active_since DESC, n.name""", (time.time() - ACTIVE_WINDOW,)).fetchall()
    return [{"id": r["id"], "email": r["email"], "device": r["device"], "node": r["node"],
             "down": human_bytes(r["tx_bytes"]), "up": human_bytes(r["rx_bytes"]),
             "since": ago(r["active_since"] or r["last_handshake"]).replace(" ago", "")} for r in rows]


@app.get("/admin/status.json")
def admin_status(request: Request):
    require_admin(request)
    with db.session() as conn:
        nodes = admin_nodes(conn)
        sessions = live_sessions(conn)
        metrics = monitoring.latest_metrics(conn)
    return {"sessions": sessions, "metrics": {str(k): v for k, v in metrics.items()},"nodes": [{"id": n["id"], "name": n["name"], "online": n["online"], "active": n["active_peers"],
                       "traffic": human_bytes(n["rx"] + n["tx"]), "last_seen": ago(n["last_seen"])}
                      for n in nodes],
            "online": sum(n["online"] for n in nodes), "active": sum(n["active_peers"] for n in nodes)}


@app.get("/admin", response_class=HTMLResponse)
def admin(request: Request):
    require_admin(request)
    with db.session() as conn:
        nodes = admin_nodes(conn)
        users = [dict(u, access=billing.has_access(u)) for u in conn.execute("""
            SELECT u.*, COALESCE(SUM(s.rx_bytes + s.tx_bytes),0) traffic, MAX(d.last_handshake) last_hs,
                   COUNT(DISTINCT d.id) device_count
            FROM users u LEFT JOIN devices d ON d.user_id = u.id LEFT JOIN device_stats s ON s.device_id = d.id
            GROUP BY u.id ORDER BY u.id DESC""")]
        tokens = conn.execute("""SELECT * FROM enroll_tokens WHERE revoked = 0 AND node_id IS NULL
                                 ORDER BY created_at DESC""").fetchall()
        sessions = live_sessions(conn)
        metrics = monitoring.latest_metrics(conn)
        insights_ctx = insights_context(conn)
    for n in nodes:
        n["m"] = metrics.get(n["id"])
        try:
            n["endpoint_problem"] = crypto.endpoint_problem(n["endpoint_host"])
        except ValueError:
            n["endpoint_problem"] = ""
    return render(request, "admin.html", nodes=nodes, users=users, tokens=tokens, sessions=sessions,
                  panel=panel_url(request), now_ts=now_utc().timestamp(),
                  provision_enabled=bool(PROVISION_API_KEY), billing_enabled=billing.enabled(),
                  webhook_configured=bool(billing.STRIPE_WEBHOOK_SECRET),
                  price_problems={k: billing.price_errors.get(k) for k in billing.PLANS
                                  if billing.enabled() and not billing.price_label(k)}
                                 if billing.enabled() else {},
                  **insights_ctx)


@app.get("/admin/servers/{node_id}", response_class=HTMLResponse)
def admin_server(request: Request, node_id: int):
    require_admin(request)
    with db.session() as conn:
        node = next((n for n in admin_nodes(conn) if n["id"] == node_id), None)
        if not node:
            raise HTTPException(404, "Server not found.")
        m = monitoring.latest_metrics(conn).get(node_id)
        recent = conn.execute("""SELECT * FROM sessions WHERE node_id = ? ORDER BY last_seen DESC LIMIT 15""",
                              (node_id,)).fetchall()
    with db.session() as conn:
        reenroll = reenroll_command(conn, request, node_id)
    return render(request, "server.html", n=node, m=m, recent=recent, now_ts=time.time(), reenroll=reenroll,
                  agent_version=AGENT_VERSION, has_stats=version_tuple(node["agent_version"]) >= (0, 3, 0),
                  self_updates=version_tuple(node["agent_version"]) >= (0, 2, 0))


def version_tuple(v: str | None) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v or ""))


@app.get("/admin/servers/{node_id}/metrics.json")
def admin_server_metrics(request: Request, node_id: int, range: str = "1h"):
    require_admin(request)
    with db.session() as conn:
        node = conn.execute("SELECT * FROM nodes WHERE id = ?", (node_id,)).fetchone()
        if not node:
            raise HTTPException(404)
        data = monitoring.series(conn, node_id, range)
        data["latest"] = monitoring.latest_metrics(conn).get(node_id)
        data["online"] = node_online(node)
        last_tok = conn.execute("""SELECT uses, max_uses, expires_at, revoked FROM enroll_tokens WHERE node_id = ?
                                   ORDER BY created_at DESC LIMIT 1""", (node_id,)).fetchone()
        data["reenroll"] = ("" if not last_tok else "used" if last_tok["uses"] >= last_tok["max_uses"]
                            else "expired" if last_tok["revoked"] or last_tok["expires_at"] < time.time() else "pending")
        data["last_seen"] = ago(node["last_seen"])
    return data


TRAFFIC_PAGE = 200


def _traffic_query(view: str, q: str, node: int, hours: int, group: bool):
    since = int(time.time()) - max(1, min(hours, 24 * 90)) * 3600
    like = f"%{q.strip()}%"
    params: list = [since]
    if view == "sessions":
        where = "last_seen >= ?"
        if q.strip():
            where += " AND (user_email LIKE ? OR client_ip LIKE ? OR device_name LIKE ?)"
            params += [like] * 3
        if node:
            where += " AND node_id = ?"
            params.append(node)
        return f"SELECT * FROM sessions WHERE {where} ORDER BY last_seen DESC", params
    where = "last_seen >= ?"
    if q.strip():
        where += (" AND (user_email LIKE ? OR dst LIKE ? OR src LIKE ? OR device_name LIKE ? OR host LIKE ?"
                  " OR CAST(dport AS TEXT) = ?)")
        params += [like] * 5 + [q.strip()]
    if node:
        where += " AND node_id = ?"
        params.append(node)
    if group:
        return (f"""SELECT dst, dport, proto, COUNT(DISTINCT user_email) users, SUM(conns) conns,
                    SUM(bytes_out) bytes_out, SUM(bytes_in) bytes_in, MAX(last_seen) last_seen
                    FROM flow_log WHERE {where} GROUP BY dst, dport, proto
                    ORDER BY SUM(bytes_in + bytes_out) DESC, SUM(conns) DESC""", params)
    return f"SELECT * FROM flow_log WHERE {where} ORDER BY last_seen DESC, id DESC", params


@app.get("/admin/traffic", response_class=HTMLResponse)
def admin_traffic(request: Request, view: str = "sessions", q: str = "", node: int = 0, hours: int = 24,
                  group: int = 0, page: int = 1):
    require_admin(request)
    view = view if view in ("sessions", "destinations") else "sessions"
    sql, params = _traffic_query(view, q, node, hours, bool(group))
    page = max(1, page)
    with db.session() as conn:
        rows = conn.execute(f"{sql} LIMIT {TRAFFIC_PAGE + 1} OFFSET {(page - 1) * TRAFFIC_PAGE}", params).fetchall()
        nodes = conn.execute("SELECT id, name FROM nodes ORDER BY name").fetchall()
    return render(request, "traffic.html", rows=rows[:TRAFFIC_PAGE], has_more=len(rows) > TRAFFIC_PAGE, view=view,
                  q=q, node=node, hours=hours, group=group, page=page, nodes=nodes, now_ts=time.time(),
                  log_sessions=monitoring.LOG_SESSIONS, log_destinations=monitoring.LOG_DESTINATIONS,
                  flow_days=monitoring.FLOW_LOG_DAYS, session_days=monitoring.SESSION_LOG_DAYS)


INSIGHT_FILTERS = ("node", "device", "user", "category", "app", "country", "dest", "port", "q")


def _insight_filters(request: Request) -> dict:
    f = {k: request.query_params.get(k, "").strip()[:255] for k in INSIGHT_FILTERS}
    for k in ("node", "device", "port"):
        if f[k] and not f[k].isdigit():
            f[k] = ""
    return {k: v for k, v in f.items() if v}


def insights_context(conn) -> dict:
    """Template variables for the Insights tab."""
    old_agents = [n["name"] for n in conn.execute("SELECT name, agent_version FROM nodes WHERE enabled = 1")
                  if version_tuple(n["agent_version"]) < (0, 5, 0)]
    return {"log_destinations": monitoring.LOG_DESTINATIONS, "flow_days": monitoring.FLOW_LOG_DAYS,
            "rollup_days": monitoring.INSIGHTS_DAYS, "categories": apps.CATEGORIES, "old_agents": old_agents,
            "geo": geo.status(), "flag_codes": sorted(countries.COUNTRIES)}


@app.get("/admin/insights")
def admin_insights(request: Request):
    require_admin(request)  # the dashboard is a tab of /admin now; keep old links (and their filters) working
    q = request.url.query
    return RedirectResponse(f"/admin{'?' + q if q else ''}#insights", status_code=303)


@app.post("/admin/insights/geo")
def admin_insights_geo(request: Request):
    """Download the IP owner/country database now (in the background - it takes a minute)."""
    require_admin(request)
    threading.Thread(target=geo.refresh_if_stale, kwargs={"force": True}, daemon=True).start()
    flash(request, "Downloading the IP owner database — reload this page in a minute.", "info")
    return RedirectResponse("/admin#insights", status_code=303)


@app.get("/admin/insights/data.json")
def admin_insights_data(request: Request, range: str = "24h"):
    require_admin(request)
    with db.session() as conn:
        return insights.dashboard(conn, range if range in insights.RANGES else "24h", _insight_filters(request))


@app.get("/admin/insights/live.json")
def admin_insights_live(request: Request, after: int = 0):
    require_admin(request)
    with db.session() as conn:
        return {"flows": insights.live(conn, _insight_filters(request), after)}


@app.get("/admin/traffic.csv")
def admin_traffic_csv(request: Request, view: str = "sessions", q: str = "", node: int = 0, hours: int = 24,
                      group: int = 0):
    require_admin(request)
    sql, params = _traffic_query(view if view in ("sessions", "destinations") else "sessions", q, node, hours,
                                 bool(group))
    with db.session() as conn:
        rows = conn.execute(f"{sql} LIMIT 100000", params).fetchall()
    buf = io.StringIO()
    w = csv.writer(buf)
    if rows:
        cols = [c for c in rows[0].keys() if c not in ("rx_base", "tx_base")]
        w.writerow(cols)
        for r in rows:
            w.writerow([datetime.fromtimestamp(r[c], timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                        if c in ("started", "last_seen", "first_seen") else r[c] for c in cols])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{view}-{int(time.time())}.csv"'})


@app.post("/admin/tokens")
def admin_new_token(request: Request, label: str = Form(""), max_uses: str = Form("")):
    require_admin(request)
    with db.session() as conn:
        conn.execute("INSERT INTO enroll_tokens (token, label, max_uses) VALUES (?,?,?)",
                     (secrets.token_urlsafe(24), label.strip(), int(max_uses) if max_uses.strip() else None))
    flash(request, "Enrollment token created.")
    return RedirectResponse("/admin#servers/add", status_code=303)


@app.post("/admin/tokens/{token}/revoke")
def admin_revoke_token(request: Request, token: str):
    require_admin(request)
    with db.session() as conn:
        conn.execute("UPDATE enroll_tokens SET revoked = 1 WHERE token = ?", (token,))
    flash(request, "Token revoked.")
    return RedirectResponse("/admin#servers/add", status_code=303)


@app.post("/admin/nodes/{node_id}")
def admin_update_node(request: Request, node_id: int, name: str = Form(...), location: str = Form(""),
                      country: str = Form(""), endpoint_host: str = Form(...), enabled: str = Form(None)):
    require_admin(request)
    if not crypto.valid_endpoint(endpoint_host):
        flash(request, f"'{endpoint_host}' isn't an IPv4 address or hostname — servers are IPv4-only.", "error")
        return RedirectResponse("/admin#servers", status_code=303)
    if crypto.endpoint_problem(endpoint_host):
        flash(request, f"{endpoint_host} is a {crypto.endpoint_problem(endpoint_host)} — clients can't reach the "
                       "server there. Use the server's own public IPv4.", "error")
        return RedirectResponse("/admin#servers", status_code=303)
    with db.session() as conn:
        conn.execute("UPDATE nodes SET name=?, location=?, country=?, endpoint_host=?, enabled=? WHERE id=?",
                     (name.strip(), location.strip(), countries.normalize(country), endpoint_host.strip(),
                      int(bool(enabled)), node_id))
    flash(request, f"Saved {name.strip()}.")
    return RedirectResponse("/admin#servers", status_code=303)


REENROLL_TTL = 3600


def reenroll_command(conn, request: Request, node_id: int) -> dict | None:
    """The newest still-usable re-enroll command for a server, if any."""
    tok = conn.execute("""SELECT * FROM enroll_tokens WHERE node_id = ? AND revoked = 0 AND uses < max_uses
                          AND expires_at > ? ORDER BY created_at DESC LIMIT 1""", (node_id, time.time())).fetchone()
    if not tok:
        return None
    return {"cmd": f"curl -fsSL {panel_url(request)}/agent/install.sh | sudo bash -s -- --token {tok['token']}",
            "expires_in": int(tok["expires_at"] - time.time())}


@app.post("/admin/nodes/{node_id}/reenroll")
def admin_reenroll_node(request: Request, node_id: int):
    """Create a one-time command that reconnects this server (or a rebuilt replacement) to the same entry."""
    require_admin(request)
    with db.session() as conn:
        node = conn.execute("SELECT name FROM nodes WHERE id = ?", (node_id,)).fetchone()
        if not node:
            raise HTTPException(404, "Server not found.")
        conn.execute("UPDATE enroll_tokens SET revoked = 1 WHERE node_id = ?", (node_id,))  # one live command
        conn.execute("""INSERT INTO enroll_tokens (token, label, max_uses, node_id, expires_at)
                        VALUES (?,?,1,?,?)""",
                     (secrets.token_urlsafe(24), f"Re-enroll {node['name']}", node_id, int(time.time()) + REENROLL_TTL))
    return RedirectResponse(f"/admin/servers/{node_id}#reenroll", status_code=303)


@app.post("/admin/nodes/{node_id}/toggle")
def admin_toggle_node(request: Request, node_id: int):
    require_admin(request)
    with db.session() as conn:
        conn.execute("UPDATE nodes SET enabled = 1 - enabled WHERE id = ?", (node_id,))
    return RedirectResponse("/admin#servers", status_code=303)


@app.post("/admin/nodes/{node_id}/delete")
def admin_delete_node(request: Request, node_id: int):
    require_admin(request)
    with db.session() as conn:
        conn.execute("DELETE FROM nodes WHERE id = ?", (node_id,))
    flash(request, f"Server #{node_id} removed. Its agent will stop syncing.")
    return RedirectResponse("/admin#servers", status_code=303)


@app.post("/admin/users")
def admin_create_user(request: Request, email: str = Form(...), password: str = Form(""),
                      is_admin: str = Form(None), plan: str = Form("")):
    require_admin(request)
    password = password or secrets.token_urlsafe(10)
    try:
        with db.session() as conn:
            create_user(conn, email, password, is_admin=bool(is_admin), plan=plan)
        flash(request, f"Created {email} — password: {password}", "info")
    except ValueError as e:
        flash(request, str(e), "error")
    return RedirectResponse("/admin#users", status_code=303)


@app.post("/admin/users/{user_id}/email")
def admin_user_email(request: Request, user_id: int, email: str = Form(...)):
    require_admin(request)
    try:
        with db.session() as conn:
            u = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            if not u:
                raise HTTPException(404, "User not found")
            new = change_email(conn, u, email)
        flash(request, f"Email changed to {new}.")
    except ValueError as e:
        flash(request, str(e), "error")
    return RedirectResponse("/admin#users", status_code=303)


@app.post("/admin/users/{user_id}/plan")
def admin_set_plan(request: Request, user_id: int, plan: str = Form("")):
    """Grant a plan without Stripe (friends, testing, invoices paid elsewhere) or remove a manual grant."""
    require_admin(request)
    if plan and plan not in billing.ALL_PLANS:
        raise HTTPException(400, "Unknown plan")
    with db.session() as conn:
        u = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if u and u["plan_source"] == "stripe" and u["sub_status"] in billing.LIVE_STATUSES:
            flash(request, "This user pays through Stripe — change or cancel their plan in your Stripe dashboard.",
                  "error")
            return RedirectResponse("/admin#users", status_code=303)
        conn.execute("UPDATE users SET plan = ?, plan_source = ? WHERE id = ?",
                     (plan, "manual" if plan else "", user_id))
    flash(request, f"Granted {billing.ALL_PLANS[plan]['name']} (free)." if plan else "Plan removed.")
    return RedirectResponse("/admin#users", status_code=303)


@app.post("/admin/users/{user_id}/{action}")
def admin_user_action(request: Request, user_id: int, action: str):
    me = require_admin(request)
    if user_id == me["id"] and action in ("suspend", "delete", "demote"):
        flash(request, "You can't do that to your own account.", "error")
        return RedirectResponse("/admin#users", status_code=303)
    sql = {
        "suspend": "UPDATE users SET status = 'suspended' WHERE id = ?",
        "activate": "UPDATE users SET status = 'active' WHERE id = ?",
        "promote": "UPDATE users SET is_admin = 1 WHERE id = ?",
        "demote": "UPDATE users SET is_admin = 0 WHERE id = ?",
        "delete": "DELETE FROM users WHERE id = ?",
    }.get(action)
    if not sql:
        raise HTTPException(404)
    with db.session() as conn:
        conn.execute(sql, (user_id,))
    flash(request, {"suspend": "User suspended — disconnected from all servers within ~15s.",
                    "activate": "User reactivated.", "promote": "Admin rights granted.",
                    "demote": "Admin rights removed.", "delete": "User deleted."}[action])
    return RedirectResponse("/admin#users", status_code=303)


# --------------------------------------------------------------------------- provisioning API
# For billing systems (WHMCS, Stripe webhooks, your website...) to create/suspend users.

def require_api_key(x_api_key: str | None):
    if not PROVISION_API_KEY or not x_api_key or not secrets.compare_digest(x_api_key, PROVISION_API_KEY):
        raise HTTPException(401, "Invalid or missing X-API-Key")


@app.post("/api/v1/users")
def api_create_user(request: Request, body: dict = Depends(json_body), x_api_key: str | None = Header(None)):
    require_api_key(x_api_key)
    password = body.get("password") or secrets.token_urlsafe(10)
    try:
        with db.session() as conn:
            uid = create_user(conn, body.get("email", ""), password, plan=body.get("plan", ""))
    except ValueError as e:
        raise HTTPException(409 if "exists" in str(e) else 400, str(e))
    return {"id": uid, "email": body["email"].strip().lower(), "password": password,
            "portal_url": f"{panel_url(request)}/login"}


def _api_user(conn, ident: str):
    col = "id" if ident.isdigit() else "email"
    row = conn.execute(f"SELECT * FROM users WHERE {col} = ?", (ident.lower(),)).fetchone()
    if not row:
        raise HTTPException(404, "User not found")
    return row


@app.get("/api/v1/users/{ident}")
def api_get_user(ident: str, x_api_key: str | None = Header(None)):
    require_api_key(x_api_key)
    with db.session() as conn:
        u = _api_user(conn, ident)
        devices = conn.execute("SELECT id, name, address, last_handshake FROM devices WHERE user_id = ?",
                               (u["id"],)).fetchall()
    return {"id": u["id"], "email": u["email"], "status": u["status"], "plan": u["plan"],
            "plan_source": u["plan_source"], "subscription_status": u["sub_status"],
            "has_access": billing.has_access(u), "devices": [dict(d) for d in devices],
            "created_at": u["created_at"]}


@app.put("/api/v1/users/{ident}/plan")
def api_set_plan(ident: str, body: dict = Depends(json_body), x_api_key: str | None = Header(None)):
    """Grant/remove a plan without Stripe: {"plan": "basic" | "pro" | ""}."""
    require_api_key(x_api_key)
    plan = body.get("plan", "")
    if plan and plan not in billing.ALL_PLANS:
        raise HTTPException(400, f"Unknown plan; use one of {list(billing.ALL_PLANS)} or \"\"")
    with db.session() as conn:
        u = _api_user(conn, ident)
        conn.execute("UPDATE users SET plan = ?, plan_source = ? WHERE id = ?",
                     (plan, "manual" if plan else "", u["id"]))
    return {"id": u["id"], "plan": plan}


@app.post("/api/v1/users/{ident}/{action}")
def api_user_action(ident: str, action: str, x_api_key: str | None = Header(None)):
    require_api_key(x_api_key)
    status = {"suspend": "suspended", "unsuspend": "active"}.get(action)
    if not status:
        raise HTTPException(404, "Unknown action")
    with db.session() as conn:
        u = _api_user(conn, ident)
        conn.execute("UPDATE users SET status = ? WHERE id = ?", (status, u["id"]))
    return {"id": u["id"], "status": status}


@app.delete("/api/v1/users/{ident}")
def api_delete_user(ident: str, x_api_key: str | None = Header(None)):
    require_api_key(x_api_key)
    with db.session() as conn:
        u = _api_user(conn, ident)
        conn.execute("DELETE FROM users WHERE id = ?", (u["id"],))
    return {"deleted": u["id"]}


@app.get("/api/v1/servers")
def api_servers():
    """Public server list (e.g. for a status page or a client app)."""
    with db.session() as conn:
        return [{"id": n["id"], "name": n["name"], "location": n["location"], "country": n["country"],
                 "online": n["online"]}
                for n in visible_nodes(conn)]


# --------------------------------------------------------------------------- agent API

@app.get("/agent/install.sh", response_class=PlainTextResponse)
def agent_install_script(request: Request):
    script = (AGENT_DIR / "install.sh").read_text()
    return PlainTextResponse(script.replace("__PANEL_URL__", panel_url(request)),
                             media_type="text/x-shellscript")


@app.get("/agent/agent.py", response_class=PlainTextResponse)
def agent_source():
    return PlainTextResponse((AGENT_DIR / "agent.py").read_text(), media_type="text/x-python")


@app.get("/api/agent/whoami")
def agent_whoami(request: Request):
    return {"ip": client_ip_of(request)}


CHURN_GAP = 60       # a re-handshake sooner than this after the previous one (healthy tunnels: ~120 s) ...
CHURN_COUNT = 3      # ... this many times ...
CHURN_WINDOW = 300   # ... each within this long of the last = two machines fighting over one key


def _track_churn(conn, d, prev_hs: int, hs: int, prev_endpoint: str, endpoint: str, now: int):
    """Two machines using the same config keep invalidating each other's session: the server sees a new
    handshake every few seconds AND the peer's source (ip:port) flipping between the machines.
    Requiring both avoids false alarms: carrier NAT rotating a phone's IP doesn't add handshakes, and one
    machine with tunnels to several servers (which can re-handshake often) keeps one source per server."""
    if not (prev_hs and hs > prev_hs and hs - prev_hs < CHURN_GAP):
        return
    if not (prev_endpoint and endpoint and endpoint != prev_endpoint):
        return
    churn = d["hs_churn"] + 1 if now - d["hs_churn_at"] < CHURN_WINDOW else 1
    d["hs_churn"], d["hs_churn_at"] = churn, now
    conn.execute("""UPDATE devices SET hs_churn = ?, hs_churn_at = ?,
                    shared_at = CASE WHEN ? >= ? THEN ? ELSE shared_at END WHERE id = ?""",
                 (churn, now, churn, CHURN_COUNT, now, d["id"]))


def _new_slot(conn) -> int:
    try:
        return crypto.allocate_slot(conn)
    except ValueError as e:
        raise HTTPException(409, str(e))


@app.post("/api/agent/register")
def agent_register(request: Request, body: dict = Depends(json_body)):
    token = body.get("token", "")
    public_key = body.get("public_key", "")
    if not re.fullmatch(r"[A-Za-z0-9+/]{42,43}=?", public_key):
        raise HTTPException(400, "Invalid WireGuard public key")
    with db.session() as conn:
        tok = conn.execute("SELECT * FROM enroll_tokens WHERE token = ? AND revoked = 0", (token,)).fetchone()
        if not tok or (tok["max_uses"] is not None and tok["uses"] >= tok["max_uses"]):
            raise HTTPException(401, "Invalid, revoked or used-up enrollment token")
        if tok["expires_at"] and tok["expires_at"] < time.time():
            raise HTTPException(401, "This enrollment command has expired; create a new one in the admin panel")
        endpoint = (body.get("endpoint") or client_ip_of(request)).strip()
        if not crypto.valid_endpoint(endpoint):
            raise HTTPException(400, f"'{endpoint}' isn't a public IPv4 address or hostname. "
                                     "Servers are IPv4-only; re-run the installer with --endpoint <IPv4>.")
        if crypto.endpoint_problem(endpoint) == "Cloudflare IP":
            raise HTTPException(400, f"{endpoint} is a Cloudflare address, not this server. "
                                     "Re-run the installer with --endpoint <this server's public IPv4>.")
        hostname = str(body.get("hostname", ""))[:100]
        secret = secrets.token_urlsafe(32)
        target = None
        if tok["node_id"]:
            # one-time re-enroll command for a specific server: keep its name, location, stats and logs,
            # take the (possibly new) key, IP and port of whatever box ran the command
            target = conn.execute("SELECT id FROM nodes WHERE id = ?", (tok["node_id"],)).fetchone()
            if not target:
                raise HTTPException(404, "The server this command was created for has been removed")
            clash = conn.execute("SELECT name FROM nodes WHERE public_key = ? AND id != ?",
                                 (public_key, target["id"])).fetchone()
            if clash:
                raise HTTPException(409, f"This machine is already enrolled as '{clash['name']}'. "
                                         "Remove that server first, or re-enroll it instead.")
        # Re-enrolling the same box (same public key) replaces the old record instead of duplicating it.
        existing = target or conn.execute("SELECT id FROM nodes WHERE public_key = ?", (public_key,)).fetchone()
        if target:
            conn.execute("""UPDATE nodes SET public_key=?, secret_hash=?, endpoint_host=?, listen_port=?, hostname=?,
                            agent_error='' WHERE id=?""",
                         (public_key, crypto.sha256(secret), endpoint, int(body.get("listen_port", 51820)),
                          hostname, target["id"]))
            node_id = target["id"]
        elif existing:
            conn.execute("UPDATE nodes SET secret_hash=?, endpoint_host=?, listen_port=?, hostname=? WHERE id=?",
                         (crypto.sha256(secret), endpoint, int(body.get("listen_port", 51820)), hostname,
                          existing["id"]))
            node_id = existing["id"]
        else:
            cur = conn.execute(
                "INSERT INTO nodes (name, location, country, endpoint_host, listen_port, public_key, secret_hash, "
                "hostname, slot) VALUES (?,?,?,?,?,?,?,?,?)",
                (str(body.get("name") or hostname or endpoint)[:100], str(body.get("location", ""))[:100],
                 countries.normalize(body.get("country")) or countries.normalize(body.get("location")),
                 endpoint, int(body.get("listen_port", 51820)), public_key, crypto.sha256(secret), hostname,
                 _new_slot(conn)))
            node_id = cur.lastrowid
        conn.execute("UPDATE enroll_tokens SET uses = uses + 1 WHERE token = ?", (token,))
        slot = conn.execute("SELECT slot FROM nodes WHERE id = ?", (node_id,)).fetchone()[0]
    return {"node_id": node_id, "secret": secret, "address": crypto.server_address(slot)}


@app.post("/api/agent/sync")
def agent_sync(request: Request, body: dict = Depends(json_body), authorization: str | None = Header(None)):
    """Agent heartbeat: reports per-peer traffic, receives the desired peer list.

    Kept in separate transactions so optional extras (stats, logs) can never stop a server from
    checking in: 1) mark the node seen, 2) device state, 3) monitoring/logging (best effort)."""
    secret = (authorization or "").removeprefix("Bearer ").strip()
    with db.session() as conn:
        node = conn.execute("SELECT * FROM nodes WHERE secret_hash = ?", (crypto.sha256(secret),)).fetchone()
        if not node:
            raise HTTPException(401, "Unknown node; re-enroll this server")
        conn.execute("UPDATE nodes SET last_seen = ?, agent_version = ?, agent_error = ? WHERE id = ?",
                     (now_utc().strftime("%Y-%m-%dT%H:%M:%S"), str(body.get("agent_version", ""))[:20],
                      str(body.get("last_error") or "")[:500], node["id"]))
        # The agent reports the public IPv4 it sees on its own interface. If the stored endpoint is clearly
        # wrong (a Cloudflare or private address), correct it so client configs point at the real server.
        reported = str(body.get("public_ip") or "").strip()
        if (reported and crypto.endpoint_problem(node["endpoint_host"]) and crypto.valid_endpoint(reported)
                and not crypto.endpoint_problem(reported)):
            conn.execute("UPDATE nodes SET endpoint_host = ? WHERE id = ?", (reported, node["id"]))
            log.warning("node %s: endpoint %s -> %s (reported by agent)", node["id"], node["endpoint_host"], reported)
            node = conn.execute("SELECT * FROM nodes WHERE id = ?", (node["id"],)).fetchone()

    peers_in = [p for p in body.get("peers") or [] if isinstance(p, dict)]
    now = int(time.time())
    with db.session() as conn:
        devices = {d["public_key"]: d for d in conn.execute(
            """SELECT d.id, d.user_id, d.name, d.public_key, d.address, d.last_handshake, d.active_since, u.email,
                      d.hs_churn, d.hs_churn_at
               FROM devices d JOIN users u ON u.id = d.user_id""")}
        devices = {k: dict(v) for k, v in devices.items()}
        prev = {r["device_id"]: r for r in conn.execute(
            "SELECT device_id, rx_bytes, tx_bytes, last_handshake, endpoint FROM device_stats WHERE node_id = ?",
            (node["id"],))}
        today = now_utc().strftime("%Y-%m-%d")
        for p in peers_in:
            d = devices.get(p.get("public_key"))
            if not d:
                continue
            try:
                hs, rx, tx = int(p.get("handshake") or 0), int(p.get("rx") or 0), int(p.get("tx") or 0)
            except (TypeError, ValueError):
                continue
            # usage = growth of the counters since the last check-in; a smaller value means the counter
            # was reset (tunnel restart / peer re-added), so everything it shows now is new traffic
            last = prev.get(d["id"])
            up = rx - last["rx_bytes"] if last and rx >= last["rx_bytes"] else rx
            down = tx - last["tx_bytes"] if last and tx >= last["tx_bytes"] else tx
            if up or down:
                conn.execute("""INSERT INTO usage_daily (day, user_id, node_id, down, up) VALUES (?,?,?,?,?)
                                ON CONFLICT(day, user_id, node_id) DO UPDATE SET
                                    down = down + excluded.down, up = up + excluded.up""",
                             (today, d["user_id"], node["id"], down, up))
            conn.execute("""
                INSERT INTO device_stats (device_id, node_id, rx_bytes, tx_bytes, last_handshake, endpoint)
                VALUES (?,?,?,?,?,?)
                ON CONFLICT(device_id, node_id) DO UPDATE SET
                    rx_bytes = excluded.rx_bytes, tx_bytes = excluded.tx_bytes,
                    last_handshake = excluded.last_handshake,
                    endpoint = CASE WHEN excluded.endpoint != '' THEN excluded.endpoint ELSE endpoint END""",
                (d["id"], node["id"], rx, tx, hs, str(p.get("endpoint") or "")))
            endpoint = str(p.get("endpoint") or "")
            _track_churn(conn, d, last["last_handshake"] if last else 0, hs,
                         last["endpoint"] if last else "", endpoint, now)
            if hs > d["last_handshake"]:
                # a handshake after an idle gap starts a new session
                new_session = now - d["last_handshake"] >= ACTIVE_WINDOW or not d["active_since"]
                conn.execute("UPDATE devices SET last_handshake = ?, active_since = ? WHERE id = ?",
                             (hs, hs if new_session else d["active_since"], d["id"]))

    try:
        with db.session() as conn:
            for p in peers_in:
                d = devices.get(p.get("public_key"))
                if d and now - int(p.get("handshake") or 0) < ACTIVE_WINDOW:
                    monitoring.record_session(conn, node, d, d["email"], str(p.get("endpoint") or ""),
                                              int(p.get("rx") or 0), int(p.get("tx") or 0))
            if isinstance(body.get("metrics"), dict):
                monitoring.record_metrics(conn, node["id"], body["metrics"])
            by_ip = {crypto.device_ip(d, node): d for d in devices.values()}
            if isinstance(body.get("flows"), list):
                monitoring.record_flows(conn, node, body["flows"], by_ip)
            if isinstance(body.get("dns"), list):
                monitoring.record_dns(conn, node, body["dns"], by_ip)
    except Exception:
        log.exception("node %s: recording stats/logs failed (check-in still accepted)", node["id"])

    with db.session() as conn:
        allowed = allowed_device_ids(conn) if node["enabled"] else set()
    peers = [{"public_key": d["public_key"], "allowed_ips": f"{crypto.device_ip(d, node)}/32"}
             for d in devices.values() if d["id"] in allowed]
    return {"node_id": node["id"], "address": crypto.server_address(node["slot"]),
            "subnet": str(crypto.node_subnet(node["slot"])),
            "mtu": crypto.WG_MTU, "endpoint": node["endpoint_host"], "listen_port": node["listen_port"],
            "peers": peers, "interval": 15, "agent_version": AGENT_VERSION,
            "flow_logging": monitoring.LOG_DESTINATIONS}


@app.get("/healthz")
def healthz():
    return {"ok": True}
