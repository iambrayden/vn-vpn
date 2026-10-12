"""VN-VPN management panel: client portal, admin console, provisioning API and agent API."""
import io
import os
import re
import secrets
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

from . import countries, crypto, db

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
PUBLIC_URL = os.environ.get("PUBLIC_URL", "").rstrip("/")
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


def create_user(conn, email: str, password: str, is_admin=False):
    email = email.strip().lower()
    if not EMAIL_RE.match(email):
        raise ValueError("Please enter a valid email address.")
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters.")
    if conn.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
        raise ValueError("An account with that email already exists.")
    priv, pub = crypto.wg_keypair()
    cur = conn.execute(
        "INSERT INTO users (email, password_hash, is_admin, private_key, public_key) VALUES (?,?,?,?,?)",
        (email, crypto.hash_password(password), int(is_admin), priv, pub),
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
    if request.url.path.startswith("/api/") or request.url.path.startswith("/agent/"):
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
    flash(request, "Welcome! Your VPN account is ready — pick a server below.")
    return RedirectResponse("/portal", status_code=303)


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# --------------------------------------------------------------------------- client portal

def portal_nodes(conn, user):
    """Servers visible to a client, with their own connection state and server load."""
    nodes = visible_nodes(conn)
    now = now_utc().timestamp()
    stats = {r["node_id"]: r for r in conn.execute("SELECT * FROM peer_stats WHERE user_id = ?", (user["id"],))}
    active = {r["node_id"]: r["n"] for r in conn.execute(
        "SELECT node_id, COUNT(*) n FROM peer_stats WHERE last_handshake > ? GROUP BY node_id",
        (now - ACTIVE_WINDOW,))}
    for n in nodes:
        s = stats.get(n["id"])
        n["connected"] = bool(s and now - s["last_handshake"] < ACTIVE_WINDOW)
        # rx/tx are from the server's point of view: server rx = client upload
        n["down"], n["up"] = (s["tx_bytes"], s["rx_bytes"]) if s else (0, 0)
        n["load"] = min(100, round(100 * active.get(n["id"], 0) / NODE_CAPACITY))
        n["country_name"] = countries.COUNTRIES.get(n["country"], "")
        n["recommended"] = False
    online = [n for n in nodes if n["online"]]
    if len(online) > 1:
        min(online, key=lambda n: n["load"])["recommended"] = True
    nodes.sort(key=lambda n: (not n["online"], n["country_name"] or n["location"], n["name"]))
    return nodes


@app.get("/portal", response_class=HTMLResponse)
def portal(request: Request):
    user = require_user(request)
    with db.session() as conn:
        nodes = portal_nodes(conn, user)
        ever_connected = conn.execute("SELECT 1 FROM peer_stats WHERE user_id = ? AND last_handshake > 0",
                                      (user["id"],)).fetchone() is not None
    return render(request, "portal.html", nodes=nodes, vpn_ip=crypto.client_ip(user["id"]),
                  connected=next((n for n in nodes if n["connected"]), None), ever_connected=ever_connected)


@app.get("/portal/status.json")
def portal_status(request: Request):
    user = require_user(request)
    with db.session() as conn:
        nodes = portal_nodes(conn, user)
    return {"nodes": [{k: n[k] for k in ("id", "name", "online", "connected", "down", "up", "load")}
                      for n in nodes]}


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
    return RedirectResponse(request.headers.get("referer") or "/portal", status_code=303)


def _user_node(request: Request, node_id: int):
    user = require_user(request)
    if user["status"] != "active":
        raise HTTPException(403, "Your account is suspended.")
    with db.session() as conn:
        node = conn.execute("SELECT * FROM nodes WHERE id = ? AND enabled = 1", (node_id,)).fetchone()
    if not node:
        raise HTTPException(404, "Server not found.")
    return user, node


def _conf_name(node) -> str:
    label = node["location"] or node["name"]
    if node["country"]:
        label = f"{node['country']}-{label}"
    slug = re.sub(r"[^A-Za-z0-9_=+.-]+", "-", label).strip("-")
    return slug[:15]  # WireGuard interface names are limited to 15 chars


@app.get("/portal/config/{node_id}.conf")
def download_config(request: Request, node_id: int):
    user, node = _user_node(request, node_id)
    return PlainTextResponse(
        crypto.client_config(user, node),
        headers={"Content-Disposition": f'attachment; filename="{_conf_name(node)}.conf"'},
    )


@app.get("/portal/qr/{node_id}.svg")
def config_qr(request: Request, node_id: int):
    user, node = _user_node(request, node_id)
    img = qrcode.make(crypto.client_config(user, node), image_factory=qrcode.image.svg.SvgPathImage,
                      box_size=8, border=2)
    buf = io.BytesIO()
    img.save(buf)
    return Response(buf.getvalue(), media_type="image/svg+xml")


@app.get("/portal/configs.zip")
def download_all(request: Request):
    user = require_user(request)
    if user["status"] != "active":
        raise HTTPException(403, "Your account is suspended.")
    with db.session() as conn:
        nodes = conn.execute("SELECT * FROM nodes WHERE enabled = 1").fetchall()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        used = set()
        for n in nodes:
            name = _conf_name(n)
            if name in used:
                name = f"{name[:11]}-{n['id']}"[:15]
            used.add(name)
            zf.writestr(f"{name}.conf", crypto.client_config(user, n))
    return Response(buf.getvalue(), media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{BRAND}-configs.zip"'})


@app.post("/portal/rotate-key")
def rotate_key(request: Request):
    user = require_user(request)
    priv, pub = crypto.wg_keypair()
    with db.session() as conn:
        conn.execute("UPDATE users SET private_key = ?, public_key = ? WHERE id = ?", (priv, pub, user["id"]))
    flash(request, "New keys issued. Download your locations again — old configs stop working within ~15 seconds.", "info")
    return RedirectResponse("/portal", status_code=303)


# --------------------------------------------------------------------------- admin console

def admin_nodes(conn):
    return [dict(r, online=node_online(r)) for r in conn.execute(f"""
        SELECT n.*, COALESCE(SUM(s.rx_bytes),0) rx, COALESCE(SUM(s.tx_bytes),0) tx,
               COUNT(CASE WHEN s.last_handshake > strftime('%s','now') - {ACTIVE_WINDOW} THEN 1 END) active_peers
        FROM nodes n LEFT JOIN peer_stats s ON s.node_id = n.id
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
        users = conn.execute("""
            SELECT u.*, COALESCE(SUM(s.rx_bytes + s.tx_bytes),0) traffic, MAX(s.last_handshake) last_hs
            FROM users u LEFT JOIN peer_stats s ON s.user_id = u.id
            GROUP BY u.id ORDER BY u.id DESC""").fetchall()
        tokens = conn.execute("SELECT * FROM enroll_tokens WHERE revoked = 0 ORDER BY created_at DESC").fetchall()
    return render(request, "admin.html", nodes=nodes, users=users, tokens=tokens,
                  panel=panel_url(request), now_ts=now_utc().timestamp(),
                  provision_enabled=bool(PROVISION_API_KEY))


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
                      is_admin: str = Form(None)):
    require_admin(request)
    password = password or secrets.token_urlsafe(10)
    try:
        with db.session() as conn:
            create_user(conn, email, password, is_admin=bool(is_admin))
        flash(request, f"Created {email} — password: {password}", "info")
    except ValueError as e:
        flash(request, str(e), "error")
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
            uid = create_user(conn, body.get("email", ""), password)
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
    return {"id": u["id"], "email": u["email"], "status": u["status"], "vpn_ip": crypto.client_ip(u["id"]),
            "created_at": u["created_at"]}


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
        users = conn.execute("SELECT id, public_key, status FROM users").fetchall()
        by_key = {u["public_key"]: u["id"] for u in users}
        for p in body.get("peers", []):
            uid = by_key.get(p.get("public_key"))
            if uid:
                conn.execute("""
                    INSERT INTO peer_stats (user_id, node_id, rx_bytes, tx_bytes, last_handshake)
                    VALUES (?,?,?,?,?)
                    ON CONFLICT(user_id, node_id) DO UPDATE SET
                        rx_bytes = excluded.rx_bytes, tx_bytes = excluded.tx_bytes,
                        last_handshake = excluded.last_handshake""",
                    (uid, node["id"], int(p.get("rx", 0)), int(p.get("tx", 0)), int(p.get("handshake", 0))))
    peers = [] if not node["enabled"] else [
        {"public_key": u["public_key"], "allowed_ips": f"{crypto.client_ip(u['id'])}/32"}
        for u in users if u["status"] == "active"
    ]
    return {"node_id": node["id"], "address": crypto.server_address(),
            "listen_port": node["listen_port"], "peers": peers, "interval": 15}


@app.get("/healthz")
def healthz():
    return {"ok": True}
