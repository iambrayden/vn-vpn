import importlib.util
import time
from pathlib import Path

from app import crypto, db, main
from tests.conftest import add_node, signup, sync
from tests.test_billing import devices_of, grant, handshake

spec = importlib.util.spec_from_file_location("agent", Path(__file__).parent.parent / "agent" / "agent.py")
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


def test_register_rejects_ipv6_endpoint(client):
    with db.session() as conn:
        conn.execute("INSERT INTO enroll_tokens (token) VALUES ('tok')")
    _, pub = crypto.wg_keypair()
    r = client.post("/api/agent/register", json={"token": "tok", "endpoint": "2a01:4f8::1", "public_key": pub})
    assert r.status_code == 400 and "IPv4" in r.json()["detail"]


def test_client_config_is_ipv4_with_safe_mtu(client):
    add_node(client)
    signup(client)
    grant("cust@example.com", "basic")
    client.get("/portal")
    dev = devices_of("cust@example.com")[0]
    conf = client.get(f"/portal/config/1.conf?device={dev['id']}").text
    assert "Endpoint = 1.2.3.4:51820" in conf
    assert f"MTU = {crypto.WG_MTU}" in conf and crypto.WG_MTU <= 1420
    assert "AllowedIPs = 0.0.0.0/0, ::/0" in conf  # IPv6 is captured (and dropped) so it can't leak


def test_sync_tells_agent_mtu_subnet_and_version(client):
    secret = add_node(client)
    r = client.post("/api/agent/sync", json={"peers": []}, headers={"Authorization": f"Bearer {secret}"}).json()
    assert r["mtu"] == crypto.WG_MTU and r["subnet"] == "10.64.0.0/16" and r["address"] == "10.64.0.1/16"
    assert r["agent_version"] == agent.VERSION and r["endpoint"] == "1.2.3.4"


def test_admin_sees_live_sessions(client):
    secret = add_node(client)
    signup(client)
    grant("cust@example.com", "basic")
    client.get("/portal")
    dev = devices_of("cust@example.com")[0]
    sync(client, secret, [handshake(dev)])
    client.post("/logout")
    with db.session() as conn:
        main.create_user(conn, "boss@example.com", "adminpass123", is_admin=True)
    client.post("/login", data={"email": "boss@example.com", "password": "adminpass123"})
    sessions = client.get("/admin/status.json").json()["sessions"]
    assert [(s["email"], s["device"], s["node"]) for s in sessions] == [("cust@example.com", "My device", "Node")]
    assert "cust@example.com" in client.get("/admin").text


def test_agent_server_config_forwards_and_clamps(monkeypatch):
    monkeypatch.setattr(agent, "DRY_RUN", True)
    conf = {"interface": "wg0", "wan_iface": "eth0"}
    out = agent.render_wg_conf(conf, {"address": "10.66.0.1/16", "subnet": "10.66.0.0/16", "listen_port": 51820,
                                      "mtu": 1380, "peers": [{"public_key": "K", "allowed_ips": "10.66.0.2/32"}]})
    assert "MTU = 1380" in out
    assert "iptables -t nat -I POSTROUTING -s 10.66.0.0/16 -o eth0 -j MASQUERADE" in out
    assert "iptables -I FORWARD -i wg0 -j ACCEPT" in out
    assert "--clamp-mss-to-pmtu" in out and "net.ipv4.ip_forward=1" in out
    assert "iptables -t nat -D POSTROUTING -s 10.66.0.0/16 -o eth0 -j MASQUERADE" in out  # PostDown mirrors PostUp


def test_qr_code_renders_for_device(client):
    add_node(client)
    signup(client)
    grant("cust@example.com", "pro")
    page = client.get("/portal").text
    dev = devices_of("cust@example.com")[0]
    assert f'src="/portal/qr/1.svg?device={dev["id"]}"' in page  # works without JavaScript
    r = client.get(f"/portal/qr/1.svg?device={dev['id']}")
    assert r.status_code == 200 and r.headers["content-type"] == "image/svg+xml" and b"<svg" in r.content


def test_devices_are_unlimited_by_default(client):
    signup(client)
    grant("cust@example.com", "basic")
    client.get("/portal")
    for i in range(15):
        client.post("/portal/devices", data={"name": f"D{i}"})
    assert len(devices_of("cust@example.com")) == 16


def test_static_assets_are_cache_busted_by_content(client):
    page = client.get("/login").text
    assert f"/static/app.js?v={main.templates.env.globals['asset_v']['app.js']}" in page


def _admin(client):
    with db.session() as conn:
        main.create_user(conn, "boss@example.com", "adminpass123", is_admin=True)
    client.post("/login", data={"email": "boss@example.com", "password": "adminpass123"})


def _reenroll_token(client, node_id=1):
    client.post(f"/admin/nodes/{node_id}/reenroll")
    with db.session() as conn:
        return conn.execute("SELECT token FROM enroll_tokens WHERE node_id = ? AND revoked = 0", (node_id,)).fetchone()[0]


def test_reenroll_keeps_server_entry_and_rotates_credentials(client):
    old_secret = add_node(client, "Chicago", "US")
    with db.session() as conn:
        conn.execute("UPDATE nodes SET location = 'Chicago, IL' WHERE id = 1")
    _admin(client)
    tok = _reenroll_token(client)
    page = client.get("/admin/servers/1").text
    assert f"--token {tok}" in page and "Re-enroll Chicago" in page
    assert client.get("/admin/servers/1/metrics.json").json()["reenroll"] == "pending"
    _, new_pub = crypto.wg_keypair()  # e.g. the server was rebuilt
    r = client.post("/api/agent/register", json={"token": tok, "name": "some-hostname", "endpoint": "5.6.7.8",
                                                  "public_key": new_pub, "hostname": "chi"})
    assert r.status_code == 200 and r.json()["node_id"] == 1
    with db.session() as conn:
        n = conn.execute("SELECT * FROM nodes").fetchall()
    assert len(n) == 1 and (n[0]["name"], n[0]["location"], n[0]["country"]) == ("Chicago", "Chicago, IL", "US")
    assert (n[0]["public_key"], n[0]["endpoint_host"]) == (new_pub, "5.6.7.8")
    assert client.post("/api/agent/sync", json={"peers": []}, headers={"Authorization": f"Bearer {old_secret}"}).status_code == 401
    assert sync(client, r.json()["secret"]) == set()
    assert client.get("/admin/servers/1/metrics.json").json()["reenroll"] == "used"
    # one-time
    _, other = crypto.wg_keypair()
    assert client.post("/api/agent/register", json={"token": tok, "endpoint": "5.6.7.9", "public_key": other}).status_code == 401


def test_reenroll_command_expires_and_is_hidden_from_wizard(client):
    add_node(client, "Chicago")
    _admin(client)
    tok = _reenroll_token(client)
    assert tok not in client.get("/admin").text  # not listed as a general enrollment token
    with db.session() as conn:
        conn.execute("UPDATE enroll_tokens SET expires_at = 1 WHERE token = ?", (tok,))
    _, pub = crypto.wg_keypair()
    r = client.post("/api/agent/register", json={"token": tok, "endpoint": "5.6.7.8", "public_key": pub})
    assert r.status_code == 401 and "expired" in r.json()["detail"]
    assert client.get("/admin/servers/1/metrics.json").json()["reenroll"] == "expired"


def test_reenroll_refuses_a_machine_enrolled_as_another_server(client):
    add_node(client, "A")
    with db.session() as conn:
        conn.execute("INSERT OR IGNORE INTO enroll_tokens (token) VALUES ('tok')")
    _, pub_b = crypto.wg_keypair()
    client.post("/api/agent/register", json={"token": "tok", "name": "B", "endpoint": "9.9.9.9", "public_key": pub_b})
    _admin(client)
    tok = _reenroll_token(client, 1)
    r = client.post("/api/agent/register", json={"token": tok, "endpoint": "9.9.9.9", "public_key": pub_b})
    assert r.status_code == 409 and "'B'" in r.json()["detail"]


def test_whoami_sees_through_cloudflare(client):
    r = client.get("/api/agent/whoami", headers={"CF-Connecting-IP": "203.0.113.50",
                                                  "X-Forwarded-For": "104.23.253.123", "X-Real-IP": "104.23.253.123"})
    assert r.json()["ip"] == "203.0.113.50"


def test_register_refuses_cloudflare_endpoint(client):
    with db.session() as conn:
        conn.execute("INSERT INTO enroll_tokens (token) VALUES ('tok')")
    _, pub = crypto.wg_keypair()
    r = client.post("/api/agent/register", json={"token": "tok", "endpoint": "104.23.253.123", "public_key": pub})
    assert r.status_code == 400 and "Cloudflare" in r.json()["detail"]


def test_agent_reported_ip_repairs_cloudflare_endpoint(client):
    """The production bug: servers registered at Cloudflare's address. The next check-in fixes them."""
    secret = add_node(client, "CHI1", "US")
    with db.session() as conn:
        conn.execute("UPDATE nodes SET endpoint_host = '104.23.253.123'")
    _admin(client)
    assert "Cloudflare IP" in client.get("/admin").text
    r = client.post("/api/agent/sync", json={"peers": [], "public_ip": "45.79.10.20"},
                    headers={"Authorization": f"Bearer {secret}"}).json()
    assert r["endpoint"] == "45.79.10.20"
    with db.session() as conn:
        assert conn.execute("SELECT endpoint_host FROM nodes").fetchone()[0] == "45.79.10.20"
    assert "Cloudflare IP" not in client.get("/admin").text


def test_reported_ip_never_overrides_a_good_endpoint(client):
    secret = add_node(client)  # 1.2.3.4, fine
    with db.session() as conn:
        conn.execute("UPDATE nodes SET endpoint_host = 'vpn-chi.example.com'")
    client.post("/api/agent/sync", json={"peers": [], "public_ip": "45.79.10.20"},
                headers={"Authorization": f"Bearer {secret}"})
    with db.session() as conn:
        assert conn.execute("SELECT endpoint_host FROM nodes").fetchone()[0] == "vpn-chi.example.com"


def test_admin_cannot_set_cloudflare_endpoint(client):
    add_node(client)
    _admin(client)
    client.post("/admin/nodes/1", data={"name": "N", "endpoint_host": "172.70.142.153"})
    with db.session() as conn:
        assert conn.execute("SELECT endpoint_host FROM nodes").fetchone()[0] == "1.2.3.4"


def test_agent_finds_its_public_ip_on_the_interface(monkeypatch):
    monkeypatch.setattr(agent, "sh", lambda *a, **k: "1.1.1.1 via 104.23.0.1 dev eth0 src 45.79.10.20 uid 0")
    assert agent.detect_public_ipv4() == "45.79.10.20"


def test_agent_skips_private_interface_ip_and_asks_outside(monkeypatch):
    monkeypatch.setattr(agent, "sh", lambda *a, **k: "1.1.1.1 via 10.0.0.1 dev eth0 src 10.0.0.5 uid 0")

    class Resp:
        def __init__(self, body): self.body = body
        def read(self): return self.body
        def __enter__(self): return self
        def __exit__(self, *a): pass
    monkeypatch.setattr(agent.urllib.request, "urlopen", lambda req, timeout=0: Resp(b"66.42.100.7\n"))
    assert agent.detect_public_ipv4() == "66.42.100.7"


def test_each_location_gives_a_device_a_different_tunnel_address(client):
    """WireGuard apps refuse tunnels with overlapping addresses ("Tunnel address overlaps with network ...")."""
    chi, stl = add_node(client, "CHI1", "US"), add_node(client, "STL1", "US")
    signup(client)
    grant("cust@example.com", "pro")
    client.get("/portal")
    client.post("/portal/devices", data={"name": "Laptop"})
    phone, laptop = devices_of("cust@example.com")
    addrs = {}
    for dev in (phone, laptop):
        for node in (1, 2):
            conf = client.get(f"/portal/config/{node}.conf?device={dev['id']}").text
            addrs[(dev["id"], node)] = conf.split("Address = ")[1].split("/")[0]
    assert len(set(addrs.values())) == 4                              # no overlaps anywhere
    assert addrs[(phone["id"], 1)].startswith("10.64.") and addrs[(phone["id"], 2)].startswith("10.65.")
    # each server accepts exactly the addresses its configs use
    r1 = client.post("/api/agent/sync", json={"peers": []}, headers={"Authorization": f"Bearer {chi}"}).json()
    r2 = client.post("/api/agent/sync", json={"peers": []}, headers={"Authorization": f"Bearer {stl}"}).json()
    assert (r1["address"], r2["address"]) == ("10.64.0.1/16", "10.65.0.1/16")
    assert {p["allowed_ips"] for p in r1["peers"]} == {f"{addrs[(d['id'], 1)]}/32" for d in (phone, laptop)}
    assert {p["allowed_ips"] for p in r2["peers"]} == {f"{addrs[(d['id'], 2)]}/32" for d in (phone, laptop)}


def test_existing_servers_get_their_own_range_on_upgrade(client):
    add_node(client, "A")
    add_node(client, "B")
    with db.session() as conn:
        conn.execute("DROP INDEX nodes_slot")
        conn.execute("UPDATE nodes SET slot = NULL")
    db.init()
    with db.session() as conn:
        assert sorted(r[0] for r in conn.execute("SELECT slot FROM nodes")) == [0, 1]
    # and a server added later takes the next free range
    add_node(client, "C")
    with db.session() as conn:
        assert conn.execute("SELECT slot FROM nodes WHERE name = 'C'").fetchone()[0] == 2


def test_server_ranges_are_reused_after_removal(client):
    add_node(client, "A")
    add_node(client, "B")
    with db.session() as conn:
        conn.execute("DELETE FROM nodes WHERE name = 'A'")
    add_node(client, "C")
    with db.session() as conn:
        assert conn.execute("SELECT slot FROM nodes WHERE name = 'C'").fetchone()[0] == 0
