import time

from app import db, main, monitoring
from tests.conftest import add_node, signup, sync
from tests.test_billing import devices_of, grant
from tests.test_vpn import agent

METRICS = {"cpu": 12.4, "mem_used": 512 << 20, "mem_total": 1 << 30, "disk_used": 5 << 30, "disk_total": 20 << 30,
           "load1": 0.3, "rx_bps": 8_000_000, "tx_bps": 2_000_000, "uptime": 3600, "active_peers": 1, "cores": 2}


def login_admin(client):
    client.post("/logout")
    with db.session() as conn:
        main.create_user(conn, "boss@example.com", "adminpass123", is_admin=True)
    client.post("/login", data={"email": "boss@example.com", "password": "adminpass123"})


def customer_with_device(client):
    signup(client)
    grant("cust@example.com", "basic")
    client.get("/portal")
    return devices_of("cust@example.com")[0]


def post_sync(client, secret, **body):
    r = client.post("/api/agent/sync", json={"agent_version": "test", "peers": [], **body},
                    headers={"Authorization": f"Bearer {secret}"})
    assert r.status_code == 200, r.text
    return r.json()


def test_metrics_are_stored_and_charted(client):
    secret = add_node(client, "Chicago")
    post_sync(client, secret, metrics=METRICS)
    login_admin(client)
    data = client.get("/admin/servers/1/metrics.json?range=1h").json()
    assert data["latest"]["cpu"] == 12.4 and data["latest"]["mem_pct"] == 50.0
    assert data["points"][0]["rx"] == 8_000_000 and data["online"] is True
    page = client.get("/admin/servers/1").text
    assert "Chicago" in page and "12%" in page and "10.0 Mbps" in page
    assert "50%" in client.get("/admin").text  # memory column in the servers table


def test_malformed_metrics_do_not_break_sync(client):
    secret = add_node(client)
    post_sync(client, secret, metrics={"cpu": "lots"})
    with db.session() as conn:
        assert conn.execute("SELECT COUNT(*) FROM node_metrics").fetchone()[0] == 0


def test_sessions_record_where_customers_connect_from(client):
    secret = add_node(client, "Chicago")
    dev = customer_with_device(client)
    now = int(time.time())
    peer = {"public_key": dev["public_key"], "handshake": now - 5, "rx": 1000, "tx": 5000, "endpoint": "198.51.100.7:40001"}
    sync(client, secret, [peer])
    sync(client, secret, [{**peer, "rx": 3000, "tx": 9000}])                       # same session, more bytes
    sync(client, secret, [{**peer, "endpoint": "203.0.113.9:5555", "rx": 3500}])   # roamed to a new network
    with db.session() as conn:
        rows = conn.execute("SELECT client_ip, rx_bytes, tx_bytes, user_email, node_name FROM sessions ORDER BY id").fetchall()
    assert [tuple(r) for r in rows] == [("198.51.100.7", 2000, 4000, "cust@example.com", "Chicago"),
                                         ("203.0.113.9", 0, 0, "cust@example.com", "Chicago")]
    login_admin(client)
    page = client.get("/admin/traffic?view=sessions&q=198.51").text
    assert "198.51.100.7" in page and "203.0.113.9" not in page


def test_destination_flows_are_attributed_to_customers(client):
    secret = add_node(client)
    dev = customer_with_device(client)
    now = int(time.time())
    resp = post_sync(client, secret, flows=[
        {"src": "10.64" + dev["address"][5:], "dst": "93.184.216.34", "dport": 443, "proto": "tcp", "first": now, "last": now,
         "conns": 3, "out": 1200, "in": 48000},
        {"src": "10.66.9.9", "dst": "1.1.1.1", "dport": 53, "proto": "udp", "first": now, "last": now,
         "conns": 1, "out": 60, "in": 120}])
    assert resp["flow_logging"] is True
    login_admin(client)
    page = client.get("/admin/traffic?view=destinations").text
    assert "93.184.216.34" in page and "443 · HTTPS" in page and "cust@example.com" in page
    grouped = client.get("/admin/traffic?view=destinations&group=1").text
    assert "53 · DNS" in grouped
    csv = client.get("/admin/traffic.csv?view=destinations&q=93.184").text
    assert csv.splitlines()[0].startswith("id,first_seen") and "cust@example.com" in csv and "1.1.1.1" not in csv


def test_traffic_log_is_admin_only(client):
    signup(client)
    assert client.get("/admin/traffic").status_code == 403
    assert client.get("/admin/traffic.csv").status_code == 403


def test_retention_purges_old_rows(client, monkeypatch):
    secret = add_node(client)
    post_sync(client, secret, metrics=METRICS)
    with db.session() as conn:
        conn.execute("UPDATE node_metrics SET ts = ts - 30 * 86400")
        monitoring.purge(conn)
        assert conn.execute("SELECT COUNT(*) FROM node_metrics").fetchone()[0] == 0


def test_alerts_fire_on_state_changes_only(client, monkeypatch):
    secret = add_node(client, "Chicago")
    monitoring._alert_state.clear()
    post_sync(client, secret, metrics=METRICS)
    with db.session() as conn:
        assert monitoring.check_alerts(conn, main.node_online) == []  # first look: baseline, no alert
        conn.execute("UPDATE nodes SET last_seen = '2000-01-01T00:00:00'")
        assert monitoring.check_alerts(conn, main.node_online) == ["🔴 Chicago is offline (no check-in for 90s)"]
        assert monitoring.check_alerts(conn, main.node_online) == []  # no repeats
    post_sync(client, secret, metrics={**METRICS, "disk_used": 19 << 30})
    with db.session() as conn:
        msgs = monitoring.check_alerts(conn, main.node_online)
    assert "🟢 Chicago is back online" in msgs and any("disk 95% full" in m for m in msgs)


def test_homepage_is_public(client):
    add_node(client, "Chicago", "US")
    page = client.get("/").text
    assert "Server locations" in page and "Simple pricing" in page and "/signup?plan=pro" in page
    assert "Online" not in page and "Offline" not in page and "Maintenance" not in page and "servers online" not in page
    assert "/static/flags/us.svg" in page


# --------------------------------------------------------------------------- agent side

def test_conntrack_events_are_parsed():
    new = ("[NEW] tcp      6 120 SYN_SENT src=10.66.0.2 dst=93.184.216.34 sport=51234 dport=443 [UNREPLIED] "
           "src=93.184.216.34 dst=203.0.113.10 sport=443 dport=51234")
    end = ("[DESTROY] tcp      6 src=10.66.0.2 dst=93.184.216.34 sport=51234 dport=443 packets=10 bytes=1200 "
           "src=93.184.216.34 dst=203.0.113.10 sport=443 dport=51234 packets=40 bytes=48000 [ASSURED]")
    ping = "[NEW] icmp     1 30 src=10.66.0.2 dst=8.8.8.8 type=8 code=0 id=7 [UNREPLIED] src=8.8.8.8 dst=203.0.113.10 type=0 code=0 id=7"
    assert agent.parse_conntrack(new) == ("NEW", "tcp", "10.66.0.2", "93.184.216.34", 443, 0, 0)
    assert agent.parse_conntrack(end) == ("DESTROY", "tcp", "10.66.0.2", "93.184.216.34", 443, 1200, 48000)
    assert agent.parse_conntrack(ping)[1:5] == ("icmp", "10.66.0.2", "8.8.8.8", 0)
    assert agent.parse_conntrack("garbage") is None


def test_flow_collector_aggregates_by_destination():
    fc = agent.FlowCollector("10.66.0.0/16")
    fc.add(("NEW", "tcp", "10.66.0.2", "1.2.3.4", 443, 0, 0))
    fc.add(("NEW", "tcp", "10.66.0.2", "1.2.3.4", 443, 0, 0))
    fc.add(("DESTROY", "tcp", "10.66.0.2", "1.2.3.4", 443, 100, 900))
    flows = fc.drain()
    assert len(flows) == 1 and (flows[0]["conns"], flows[0]["out"], flows[0]["in"]) == (2, 100, 900)
    assert fc.drain() == []


def test_agent_metrics_sample_reads_proc():
    m = agent.Metrics("lo")
    s = m.sample(active_peers=2)
    assert 0 <= s["cpu"] <= 100 and s["mem_total"] > 0 and s["disk_total"] > 0 and s["active_peers"] == 2


def test_checkin_survives_broken_logging(client, monkeypatch):
    """Stats/log failures must never stop a server from checking in (it would show offline)."""
    secret = add_node(client)
    def boom(*a, **k):
        raise RuntimeError("logging broke")
    monkeypatch.setattr(monitoring, "record_metrics", boom)
    resp = post_sync(client, secret, metrics=METRICS, last_error="wg-quick up wg0 failed: RTNETLINK")
    assert resp["node_id"] == 1
    with db.session() as conn:
        n = conn.execute("SELECT * FROM nodes WHERE id = 1").fetchone()
    assert main.node_online(n) and "RTNETLINK" in n["agent_error"]
    login_admin(client)
    assert "Agent error" in client.get("/admin").text
    assert "RTNETLINK" in client.get("/admin/servers/1").text


def test_garbage_peers_do_not_break_checkin(client):
    secret = add_node(client)
    post_sync(client, secret, peers=[{"public_key": "x", "handshake": "soon"}, "nope", None])
    with db.session() as conn:
        assert main.node_online(conn.execute("SELECT * FROM nodes WHERE id = 1").fetchone())


def test_usage_per_location_survives_counter_resets(client):
    chi, cgk = add_node(client, "CHI1", "US"), add_node(client, "CGK1", "ID")
    dev = customer_with_device(client)
    now = int(time.time())
    peer = lambda rx, tx: {"public_key": dev["public_key"], "handshake": now - 5, "rx": rx, "tx": tx}
    sync(client, chi, [peer(1_000, 10_000)])        # server rx = customer upload, tx = download
    sync(client, chi, [peer(3_000, 50_000)])        # +2 KB up, +40 KB down
    sync(client, chi, [peer(500, 5_000)])           # tunnel restarted: counters reset -> +0.5 KB, +5 KB
    sync(client, cgk, [peer(2_000, 100_000)])
    with db.session() as conn:
        uid = conn.execute("SELECT id FROM users WHERE email = 'cust@example.com'").fetchone()[0]
        u = main.user_usage(conn, uid, "month")
    by = {r["name"]: (r["down"], r["up"]) for r in u["rows"]}
    assert by == {"CHI1": (55_000, 3_500), "CGK1": (100_000, 2_000)}
    assert [r["name"] for r in u["rows"]] == ["CGK1", "CHI1"]  # busiest first
    page = client.get("/portal").text
    assert "Usage by location" in page and "CHI1" in page and "97.7 KB" in page  # CGK1 down


def test_usage_periods(client):
    secret = add_node(client, "CHI1")
    dev = customer_with_device(client)
    with db.session() as conn:
        uid = conn.execute("SELECT id FROM users WHERE email = 'cust@example.com'").fetchone()[0]
        conn.execute("INSERT INTO usage_daily VALUES ('2020-01-01', ?, 1, 1000, 10)", (uid,))
        assert main.user_usage(conn, uid, "month")["rows"] == []
        assert main.user_usage(conn, uid, "all")["down"] == 1000
    assert "No data used in this period" in client.get("/portal?usage=30d").text
    assert "1000 B" in client.get("/portal?usage=all").text


def test_usage_is_private_to_each_customer(client):
    secret = add_node(client, "CHI1")
    dev = customer_with_device(client)
    sync(client, secret, [{"public_key": dev["public_key"], "handshake": int(time.time()), "rx": 9, "tx": 77_777}])
    client.post("/logout")
    signup(client, "other@example.com")
    grant("other@example.com", "basic")
    assert "No data used" in client.get("/portal").text
