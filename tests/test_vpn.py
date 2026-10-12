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
    assert r["mtu"] == crypto.WG_MTU and r["subnet"] == str(crypto.VPN_SUBNET)
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
