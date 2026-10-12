"""VN-VPN management panel: client portal, admin console, provisioning API and agent API."""
import io
import os
import re
import secrets
import time
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import qrcode
import qrcode.image.svg
from fastapi import FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

from . import billing, countries, crypto, db

BASE = Path(__file__).parent
AGENT_DIR = BASE.parent / "agent"



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


templates.env.filters["bytes"] = human_bytes
templates.env.filters["ago"] = ago
templates.env.filters["flag"] = countries.flag
templates.env.globals["countries"] = countries.COUNTRIES
templates.env.globals["plans"] = billing.PLANS


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
    if plan and plan not in billing.PLANS:
        raise ValueError(f"Unknown plan '{plan}'. Use one of: {', '.join(billing.PLANS)}.")
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
def startup():
    db.init()
    admin_email = os.environ.get("ADMIN_EMAIL")
    admin_password = os.environ.get("ADMIN_PASSWORD")
    if admin_email and admin_password:
        with db.session() as conn:
            row = conn.execute("SELECT id FROM users WHERE email = ?", (admin_email.lower(),)).fetchone()
            if row:
                conn.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (row["id"],))
            else:
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
    user = current_user(request)
    if user:
        return RedirectResponse("/admin" if user["is_admin"] else "/portal", status_code=303)
    return RedirectResponse("/login", status_code=303)


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
    return RedirectResponse("/", status_code=303)


@app.get("/signup", response_class=HTMLResponse)
def signup_page(request: Request):
    if not OPEN_SIGNUP:
        raise HTTPException(404, "Sign-up is closed.")
    return render(request, "signup.html")


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
        last = conn.execute("""SELECT node_id, rx_bytes, tx_bytes FROM device_stats WHERE device_id = ?
                               ORDER BY last_handshake DESC LIMIT 1""", (d["id"],)).fetchone()
        d["connected"] = d["id"] in allowed and now - d["last_handshake"] < ACTIVE_WINDOW
        d["node_id"] = last["node_id"] if last else None
        d["node_name"] = nodes.get(d["node_id"], "") if last else ""
        d["down"], d["up"] = (last["tx_bytes"], last["rx_bytes"]) if last else (0, 0)
        d["kicked"] = d["kicked_until"] > now
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
        n["devices_here"] = [d["name"] for d in devices if d["connected"] and d["node_id"] == n["id"]]
        n["connected"] = bool(n["devices_here"])
        n["load"] = min(100, round(100 * active.get(n["id"], 0) / NODE_CAPACITY))
        n["country_name"] = countries.COUNTRIES.get(n["country"], "")
        n["recommended"] = False
    online = [n for n in nodes if n["online"]]
    if len(online) > 1:
        min(online, key=lambda n: n["load"])["recommended"] = True
    nodes.sort(key=lambda n: (not n["online"], n["country_name"] or n["location"], n["name"]))
    return nodes


def plan_context(user):
    plan = billing.PLANS.get(user["plan"])
    return {
        "plan": plan, "plan_key": user["plan"], "limit": billing.device_limit(user),
        "renews": datetime.fromtimestamp(user["period_end"], timezone.utc).strftime("%b %-d, %Y")
        if user["period_end"] else "",
        "billing_enabled": billing.enabled(),
        "price_labels": {k: billing.price_label(k) for k in billing.PLANS} if billing.enabled()
        else {k: p["price_label"] for k, p in billing.PLANS.items()},
    }


@app.get("/portal", response_class=HTMLResponse)
def portal(request: Request):
    user = require_user(request)
    if not billing.has_access(user):
        return render(request, "pricing.html", **plan_context(user))
    with db.session() as conn:
        if not conn.execute("SELECT 1 FROM devices WHERE user_id = ?", (user["id"],)).fetchone():
            add_device(conn, user, "My device")  # first visit after subscribing: one ready-to-use device
        devices = user_devices(conn, user)
        nodes = portal_nodes(conn, devices)
    connected = [d for d in devices if d["connected"]]
    return render(request, "portal.html", nodes=nodes, devices=devices, connected=connected,
                  ever_connected=any(d["last_handshake"] for d in devices), max_devices=billing.MAX_DEVICES,
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
        if count >= billing.MAX_DEVICES:
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
    return slug[:15]  # WireGuard interface names are limited to 15 chars


@app.get("/portal/config/{node_id}.conf")
def download_config(request: Request, node_id: int, device: int):
    user, dev, node = _device_node(request, node_id, device)
    return PlainTextResponse(
        crypto.client_config(dev, node, user["email"]),
        headers={"Content-Disposition": f'attachment; filename="{_conf_name(node)}.conf"'},
    )


@app.get("/portal/qr/{node_id}.svg")
def config_qr(request: Request, node_id: int, device: int):
    user, dev, node = _device_node(request, node_id, device)
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
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        used = set()
        for n in nodes:
            name = _conf_name(n)
            if name in used:
                name = f"{name[:11]}-{n['id']}"[:15]
            used.add(name)
            zf.writestr(f"{name}.conf", crypto.client_config(dev, n, user["email"]))
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
async def billing_webhook(request: Request, stripe_signature: str | None = Header(None)):
    payload = await request.body()
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


@app.get("/admin/status.json")
def admin_status(request: Request):
    require_admin(request)
    with db.session() as conn:
        nodes = admin_nodes(conn)
    return {"nodes": [{"id": n["id"], "name": n["name"], "online": n["online"], "active": n["active_peers"],
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
        tokens = conn.execute("SELECT * FROM enroll_tokens WHERE revoked = 0 ORDER BY created_at DESC").fetchall()
    return render(request, "admin.html", nodes=nodes, users=users, tokens=tokens,
                  panel=panel_url(request), now_ts=now_utc().timestamp(),
                  provision_enabled=bool(PROVISION_API_KEY), billing_enabled=billing.enabled(),
                  webhook_configured=bool(billing.STRIPE_WEBHOOK_SECRET))


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
    with db.session() as conn:
        conn.execute("UPDATE nodes SET name=?, location=?, country=?, endpoint_host=?, enabled=? WHERE id=?",
                     (name.strip(), location.strip(), countries.normalize(country), endpoint_host.strip(),
                      int(bool(enabled)), node_id))
    flash(request, f"Saved {name.strip()}.")
    return RedirectResponse("/admin#servers", status_code=303)


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


@app.post("/admin/users/{user_id}/plan")
def admin_set_plan(request: Request, user_id: int, plan: str = Form("")):
    """Grant a plan without Stripe (friends, testing, invoices paid elsewhere) or remove a manual grant."""
    require_admin(request)
    if plan and plan not in billing.PLANS:
        raise HTTPException(400, "Unknown plan")
    with db.session() as conn:
        u = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if u and u["plan_source"] == "stripe" and u["sub_status"] in billing.LIVE_STATUSES:
            flash(request, "This user pays through Stripe — change or cancel their plan in your Stripe dashboard.",
                  "error")
            return RedirectResponse("/admin#users", status_code=303)
        conn.execute("UPDATE users SET plan = ?, plan_source = ? WHERE id = ?",
                     (plan, "manual" if plan else "", user_id))
    flash(request, f"Granted {billing.PLANS[plan]['name']} (free)." if plan else "Plan removed.")
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
async def api_create_user(request: Request, x_api_key: str | None = Header(None)):
    require_api_key(x_api_key)
    body = await request.json()
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
async def api_set_plan(ident: str, request: Request, x_api_key: str | None = Header(None)):
    """Grant/remove a plan without Stripe: {"plan": "basic" | "pro" | ""}."""
    require_api_key(x_api_key)
    plan = (await request.json()).get("plan", "")
    if plan and plan not in billing.PLANS:
        raise HTTPException(400, f"Unknown plan; use one of {list(billing.PLANS)} or \"\"")
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


@app.post("/api/agent/register")
async def agent_register(request: Request):
    body = await request.json()
    token = body.get("token", "")
    public_key = body.get("public_key", "")
    if not re.fullmatch(r"[A-Za-z0-9+/]{42,43}=?", public_key):
        raise HTTPException(400, "Invalid WireGuard public key")
    with db.session() as conn:
        tok = conn.execute("SELECT * FROM enroll_tokens WHERE token = ? AND revoked = 0", (token,)).fetchone()
        if not tok or (tok["max_uses"] is not None and tok["uses"] >= tok["max_uses"]):
            raise HTTPException(401, "Invalid, revoked or used-up enrollment token")
        endpoint = (body.get("endpoint") or client_ip_of(request)).strip()
        hostname = str(body.get("hostname", ""))[:100]
        secret = secrets.token_urlsafe(32)
        # Re-enrolling the same box (same public key) replaces the old record instead of duplicating it.
        existing = conn.execute("SELECT id FROM nodes WHERE public_key = ?", (public_key,)).fetchone()
        if existing:
            conn.execute("UPDATE nodes SET secret_hash=?, endpoint_host=?, listen_port=?, hostname=? WHERE id=?",
                         (crypto.sha256(secret), endpoint, int(body.get("listen_port", 51820)), hostname,
                          existing["id"]))
            node_id = existing["id"]
        else:
            cur = conn.execute(
                "INSERT INTO nodes (name, location, country, endpoint_host, listen_port, public_key, secret_hash, "
                "hostname) VALUES (?,?,?,?,?,?,?,?)",
                (str(body.get("name") or hostname or endpoint)[:100], str(body.get("location", ""))[:100],
                 countries.normalize(body.get("country")) or countries.normalize(body.get("location")),
                 endpoint, int(body.get("listen_port", 51820)), public_key, crypto.sha256(secret), hostname))
            node_id = cur.lastrowid
        conn.execute("UPDATE enroll_tokens SET uses = uses + 1 WHERE token = ?", (token,))
    return {"node_id": node_id, "secret": secret, "address": crypto.server_address()}


@app.post("/api/agent/sync")
async def agent_sync(request: Request, authorization: str | None = Header(None)):
    """Agent heartbeat: reports per-peer traffic, receives the desired peer list."""
    secret = (authorization or "").removeprefix("Bearer ").strip()
    body = await request.json()
    with db.session() as conn:
        node = conn.execute("SELECT * FROM nodes WHERE secret_hash = ?", (crypto.sha256(secret),)).fetchone()
        if not node:
            raise HTTPException(401, "Unknown node; re-enroll this server")
        conn.execute("UPDATE nodes SET last_seen = ?, agent_version = ? WHERE id = ?",
                     (now_utc().strftime("%Y-%m-%dT%H:%M:%S"), str(body.get("agent_version", ""))[:20], node["id"]))
        now = int(time.time())
        devices = {d["public_key"]: d for d in conn.execute(
            "SELECT id, public_key, address, last_handshake, active_since FROM devices")}
        for p in body.get("peers", []):
            d = devices.get(p.get("public_key"))
            if not d:
                continue
            hs = int(p.get("handshake", 0))
            conn.execute("""
                INSERT INTO device_stats (device_id, node_id, rx_bytes, tx_bytes, last_handshake)
                VALUES (?,?,?,?,?)
                ON CONFLICT(device_id, node_id) DO UPDATE SET
                    rx_bytes = excluded.rx_bytes, tx_bytes = excluded.tx_bytes,
                    last_handshake = excluded.last_handshake""",
                (d["id"], node["id"], int(p.get("rx", 0)), int(p.get("tx", 0)), hs))
            if hs > d["last_handshake"]:
                # a handshake after an idle gap starts a new session
                new_session = now - d["last_handshake"] >= ACTIVE_WINDOW or not d["active_since"]
                conn.execute("UPDATE devices SET last_handshake = ?, active_since = ? WHERE id = ?",
                             (hs, hs if new_session else d["active_since"], d["id"]))
        allowed = allowed_device_ids(conn) if node["enabled"] else set()
    peers = [{"public_key": d["public_key"], "allowed_ips": f"{d['address']}/32"}
             for d in devices.values() if d["id"] in allowed]
    return {"node_id": node["id"], "address": crypto.server_address(),
            "listen_port": node["listen_port"], "peers": peers, "interval": 15}


@app.get("/healthz")
def healthz():
    return {"ok": True}
