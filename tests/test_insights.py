import struct
import time

import pytest

from app import apps, db, geo
from tests.conftest import add_node, signup
from tests.test_monitoring import customer_with_device, login_admin, post_sync
from tests.test_vpn import agent

TSV = ["1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n",
       "31.13.64.0\t31.13.127.255\t32934\tIE\tFACEBOOK\n",
       "93.184.216.0\t93.184.216.255\t15133\tUS\tEDGECAST\n",
       "100.0.0.0\t100.0.0.255\t0\tNone\tNot routed\n",
       "garbage line\n"]


@pytest.fixture
def use_geo(tmp_path, monkeypatch):
    monkeypatch.setattr(geo, "ENABLED", True)
    monkeypatch.setattr(geo, "_path", lambda: str(tmp_path / "geo.db"))
    geo.import_tsv(TSV)
    yield
    geo.lookup.cache_clear()  # don't leak lookups into tests without the database


def test_classify_by_hostname_owner_and_port():
    assert apps.classify("rr3---sn-abc.googlevideo.com") == ("YouTube", "Streaming")
    assert apps.classify("www.netflix.com.") == ("Netflix", "Streaming")
    assert apps.classify("tv.apple.com") == ("Apple TV+", "Streaming")      # more specific than apple.com
    assert apps.classify("cdn.apple.com")[1] == "Cloud & Software"
    assert apps.classify("", "FACEBOOK") == ("Facebook", "Social")
    assert apps.classify("", "SOME ISP", 53) == ("DNS", "Other")
    assert apps.classify("shop.example.org") == ("example.org", "Other")
    assert apps.classify("", "") == ("", "Other")
    assert apps.classify("notyoutube.com") != ("YouTube", "Streaming")      # suffix match is per label


def test_geo_import_and_lookup(use_geo):
    assert geo.lookup("1.0.0.1") == ("US", "CLOUDFLARENET")
    assert geo.lookup("31.13.70.5") == ("IE", "FACEBOOK")
    assert geo.lookup("1.0.1.1") == ("", "")        # gap between ranges
    assert geo.lookup("100.0.0.5") == ("", "")      # "not routed" rows are skipped
    assert geo.lookup("not-an-ip") == ("", "")


def test_geo_off_returns_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(geo, "_path", lambda: str(tmp_path / "geo.db"))
    geo.import_tsv(TSV)
    monkeypatch.setattr(geo, "ENABLED", False)
    assert geo.lookup("1.0.0.1") == ("", "")
    geo.lookup.cache_clear()


def dns_packet(client, name, answers):
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    dns = struct.pack("!HHHHHH", 1, 0x8180, 1, len(answers), 0, 0) + q + struct.pack("!HH", 1, 1)
    for ip, ttl in answers:
        dns += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, 4) + bytes(int(x) for x in ip.split("."))
    udp = struct.pack("!HHHH", 53, 40000, 8 + len(dns), 0) + dns
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0, bytes([1, 1, 1, 1]),
                     bytes(int(x) for x in client.split(".")))
    return ip + udp


def test_agent_learns_names_from_dns_answers():
    pkt = dns_packet("10.64.0.2", "www.YouTube.com", [("142.250.80.46", 120), ("142.250.80.47", 60)])
    assert agent.parse_dns_answer(pkt) == ("10.64.0.2", "www.youtube.com", [("142.250.80.46", 120), ("142.250.80.47", 60)])
    assert agent.parse_dns_answer(pkt[:30]) is None
    w = agent.DnsWatcher("wg0")
    w.add(agent.parse_dns_answer(pkt))
    w.add(agent.parse_dns_answer(pkt))
    assert w.lookup("10.64.0.2", "142.250.80.47") == "www.youtube.com"
    assert w.lookup("10.64.0.3", "142.250.80.47") == ""        # names are per client
    assert w.drain() == [{"src": "10.64.0.2", "name": "www.youtube.com", "count": 2}]
    assert w.drain() == []
    fc = agent.FlowCollector("10.64.0.0/16", w)
    fc.add(("NEW", "tcp", "10.64.0.2", "142.250.80.46", 443, 0, 0))
    assert fc.drain()[0]["host"] == "www.youtube.com"


def test_flows_are_enriched_and_dashboard_aggregates(client, use_geo):
    secret = add_node(client, "Chicago")
    dev = customer_with_device(client)
    src = "10.64" + dev["address"][5:]
    now = int(time.time())
    post_sync(client, secret, metrics={"cpu": 1, "mem_used": 1, "mem_total": 2, "disk_used": 1, "disk_total": 2,
                                       "load1": 0, "rx_bps": 5_000_000, "tx_bps": 1_000_000, "uptime": 1,
                                       "active_peers": 1},
              flows=[{"src": src, "dst": "93.184.216.34", "dport": 443, "proto": "tcp", "first": now, "last": now,
                      "conns": 2, "out": 1000, "in": 90000, "host": "rr1.googlevideo.com"},
                     {"src": src, "dst": "31.13.70.5", "dport": 443, "proto": "tcp", "first": now, "last": now,
                      "conns": 1, "out": 500, "in": 4000},
                     {"src": "10.64.9.9", "dst": "1.0.0.1", "dport": 53, "proto": "udp", "first": now, "last": now,
                      "conns": 1, "out": 60, "in": 120}],
              dns=[{"src": src, "name": "rr1.googlevideo.com", "count": 3}, {"src": src, "name": "x.in-addr.arpa"}])
    with db.session() as conn:
        rows = {r["dst"]: r for r in conn.execute("SELECT * FROM flow_log")}
        assert (rows["93.184.216.34"]["app"], rows["93.184.216.34"]["category"]) == ("YouTube", "Streaming")
        assert rows["93.184.216.34"]["country"] == "US" and rows["93.184.216.34"]["org"] == "EDGECAST"
        assert rows["31.13.70.5"]["app"] == "Facebook"           # no name: identified by network owner
        assert [r["name"] for r in conn.execute("SELECT name FROM dns_log")] == ["rr1.googlevideo.com"]

    login_admin(client)
    admin_page = client.get("/admin").text
    assert 'data-tab="insights"' in admin_page and 'id="insights-root"' in admin_page
    r = client.get("/admin/insights?app=Netflix", follow_redirects=False)   # old link -> the tab
    assert r.status_code == 303 and r.headers["location"] == "/admin?app=Netflix#insights"
    d = client.get("/admin/insights/data.json?range=1h").json()
    assert d["kpi"]["down"] == 94120 and d["kpi"]["clients"] == 2 and d["kpi"]["dns"] == 3
    assert d["kpi"]["top_app"] == "YouTube"
    cats = {c["name"]: c["down"] + c["up"] for c in d["categories"]}
    assert cats["Streaming"] == 91000 and cats["Social"] == 4500 and list(cats) == apps.CATEGORIES
    assert d["clients"][0]["device"] == dev["name"] and d["clients"][0]["top_app"] == "YouTube"
    assert d["destinations"][0]["name"] == "rr1.googlevideo.com"
    assert {c["code"] for c in d["countries"]} == {"US", "IE"}
    assert d["throughput"][0]["rx"] == 5_000_000 and d["timeline"][0]["Streaming"] == 91000
    assert d["dns"][0] == {"name": "rr1.googlevideo.com", "app": "YouTube", "category": "Streaming",
                           "lookups": 3, "clients": 1}

    # filters narrow everything
    f = client.get("/admin/insights/data.json?range=1h&category=Social").json()
    assert f["kpi"]["down"] == 4000 and f["apps"][0]["name"] == "Facebook" and f["dns"] == []
    f = client.get(f"/admin/insights/data.json?device={dev['id']}&country=US").json()
    assert f["kpi"]["conns"] == 2
    f = client.get("/admin/insights/data.json?dest=rr1.googlevideo.com").json()
    assert f["kpi"]["conns"] == 2 and f["kpi"]["dns"] == 3
    assert client.get("/admin/insights/data.json?q=cust@").json()["kpi"]["clients"] == 1
    assert client.get("/admin/insights/data.json?node=abc").status_code == 200   # bad ids are ignored

    live = client.get("/admin/insights/live.json").json()["flows"]
    assert len(live) == 3 and live[0]["id"] > live[-1]["id"]
    assert client.get(f"/admin/insights/live.json?after={live[0]['id']}").json()["flows"] == []
    assert client.get("/admin/insights/live.json?port=53").json()["flows"][0]["app"] == "Cloudflare"


def test_insights_are_admin_only(client):
    signup(client)
    for path in ("/admin/insights", "/admin/insights/data.json", "/admin/insights/live.json"):
        assert client.get(path).status_code == 403
    assert client.post("/admin/insights/geo").status_code == 403


IPHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile Safari/604.1"


def test_phone_gets_named_device_and_wireguard_import_flow(client):
    from tests.test_billing import devices_of, grant
    add_node(client, "Chicago")
    signup(client)
    grant("cust@example.com", "basic")
    page = client.get("/portal", headers={"User-Agent": IPHONE}).text
    assert devices_of("cust@example.com")[0]["name"] == "iPhone"
    assert "Set up this phone" in page and "Add to WireGuard" in page and 'id="import-help"' in page
    assert 'data-open="qr-' not in page                      # can't scan a QR code on its own screen
    desktop = client.get("/portal").text
    assert "Set up this phone" not in desktop and 'data-open="qr-' in desktop


def test_config_file_name_is_the_tunnel_name(client):
    from tests.test_billing import devices_of, grant
    from app import main
    add_node(client, "Chicago", country="US")
    with db.session() as conn:
        conn.execute("UPDATE nodes SET location = 'St. Louis'")
    signup(client)
    grant("cust@example.com", "basic")
    page = client.get("/portal").text
    dev = devices_of("cust@example.com")[0]
    r = client.get(f"/portal/config/1.conf?device={dev['id']}")
    assert r.headers["content-disposition"] == 'attachment; filename="US-St.-Louis.conf"'
    assert r.headers["content-type"] == "application/octet-stream" and r.text.startswith("[Interface]")
    assert "US-St.-Louis</code>" in page                      # name to type after scanning the QR code
    nodes = [{"id": 1, "name": "A", "location": "Chicago", "country": "US"},
             {"id": 12, "name": "B", "location": "Chicago", "country": "US"},
             {"id": 3, "name": "Frankfurt am Main Süd", "location": "", "country": "DE"}]
    assert main.tunnel_names(nodes) == {1: "US-Chicago", 12: "US-Chicago-12", 3: "DE-Frankfurt-am"}


def hello_packet(client, server, sni, pad_before=0):
    """IPv4/TCP packet with a TLS 1.3-style ClientHello carrying an SNI extension."""
    name = sni.encode()
    sni_ext = struct.pack("!HHHBH", 0, len(name) + 5, len(name) + 3, 0, len(name)) + name
    exts = struct.pack("!HH", 0x0a0a, pad_before) + b"\0" * pad_before + sni_ext   # GREASE ext first
    body = b"\x03\x03" + b"\x11" * 32 + b"\x00" + struct.pack("!H", 4) + b"\x13\x01\x13\x02" + b"\x01\x00"
    body += struct.pack("!H", len(exts)) + exts
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    tls = b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs
    tcp = struct.pack("!HHIIBBHHH", 50000, 443, 1, 0, 5 << 4, 0x18, 65535, 0, 0) + tls
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0,
                     bytes(int(x) for x in client.split(".")), bytes(int(x) for x in server.split(".")))
    return ip + tcp


def test_agent_learns_names_from_tls_handshakes():
    pkt = hello_packet("10.64.0.2", "142.250.80.46", "www.YouTube.com", pad_before=20)
    assert agent.parse_client_hello(pkt) == ("10.64.0.2", "142.250.80.46", "www.youtube.com")
    assert agent.parse_client_hello(pkt[:80]) is None                      # name in the part we didn't see
    assert agent.parse_client_hello(hello_packet("10.64.0.2", "1.1.1.1", "localhost")) is None
    w = agent.DnsWatcher("wg0")
    fc = agent.FlowCollector("10.64.0.0/16", w)
    fc.add(("NEW", "tcp", "10.64.0.2", "142.250.80.46", 443, 0, 0))       # connection starts before the hello
    w.add_sni(agent.parse_client_hello(pkt))
    assert fc.drain()[0]["host"] == "www.youtube.com"


def test_mirror_database_and_backfill_of_unknowns(client, tmp_path, monkeypatch):
    secret = add_node(client)
    now = int(time.time())
    post_sync(client, secret, flows=[{"src": "10.64.9.9", "dst": "31.13.70.5", "dport": 443, "proto": "tcp",
                                      "first": now, "last": now, "conns": 1, "out": 1, "in": 2}])
    with db.session() as conn:
        assert conn.execute("SELECT app, country FROM flow_log").fetchone()[:] == ("", "")   # no database yet
    monkeypatch.setattr(geo, "ENABLED", True)
    monkeypatch.setattr(geo, "_path", lambda: str(tmp_path / "geo.db"))
    assert geo.status()["ranges"] == 0
    asn = ['start_ip,end_ip,asn,org\n', '31.13.64.0,31.13.127.255,32934,"Facebook, Inc."\n']
    country = ["31.13.64.0,31.13.127.255,IE\n"]
    assert geo.import_csv(asn, country) == 1
    assert geo.lookup("31.13.70.5") == ("IE", "FACEBOOK, INC.")
    assert geo.backfill() == 1
    with db.session() as conn:
        assert conn.execute("SELECT app, country FROM flow_log").fetchone()[:] == ("Facebook", "IE")
    st = geo.status()
    assert st["ranges"] == 1 and st["source"] == "ip-location-db"
    geo.lookup.cache_clear()


def test_geo_download_failure_is_shown_with_retry(client, tmp_path, monkeypatch):
    monkeypatch.setattr(geo, "ENABLED", True)
    monkeypatch.setattr(geo, "_path", lambda: str(tmp_path / "geo.db"))
    monkeypatch.setattr(geo, "_get", lambda url: (_ for _ in ()).throw(OSError("blocked")))
    geo.refresh_if_stale(force=True)
    assert "iptoasn.com: blocked" in geo.state["error"] and "jsDelivr mirror: blocked" in geo.state["error"]
    login_admin(client)
    page = client.get("/admin").text
    assert "IP owner database isn" in page and "jsDelivr mirror: blocked" in page and "/admin/insights/geo" in page
    geo.state["error"] = ""


def test_hourly_totals_power_30_day_and_all_time(client):
    from app import insights
    secret = add_node(client)
    now = int(time.time())
    old = now - 20 * 86400
    post_sync(client, secret, flows=[
        {"src": "10.64.9.9", "dst": "1.0.0.1", "dport": 443, "proto": "tcp", "first": old, "last": old,
         "conns": 2, "out": 10, "in": 1000, "host": "www.netflix.com"},
        {"src": "10.64.9.9", "dst": "1.0.0.1", "dport": 443, "proto": "tcp", "first": old + 60, "last": old + 60,
         "conns": 1, "out": 5, "in": 500, "host": "www.netflix.com"},
        {"src": "10.64.9.9", "dst": "1.0.0.2", "dport": 443, "proto": "tcp", "first": now, "last": now,
         "conns": 1, "out": 1, "in": 7, "host": "www.google.com"}],
        dns=[{"src": "10.64.9.9", "name": "www.google.com", "count": 2}])
    with db.session() as conn:
        insights.rollup(conn)
        assert conn.execute("SELECT COUNT(*), SUM(bytes_in) FROM flow_rollup").fetchone()[:] == (1, 1500)
        insights.rollup(conn)                                                 # idempotent
        assert conn.execute("SELECT COUNT(*) FROM flow_rollup").fetchone()[0] == 1
        conn.execute("DELETE FROM flow_log WHERE last_seen < ?", (now - 7 * 86400,))   # raw log expired
    login_admin(client)
    for rng in ("30d", "all"):
        d = client.get(f"/admin/insights/data.json?range={rng}").json()
        assert d["kpi"]["down"] == 1507 and d["kpi"]["dns"] == 2, rng       # hourly totals + this hour
        assert d["apps"][0]["name"] == "Netflix"
    assert client.get("/admin/insights/data.json?range=7d").json()["kpi"]["down"] == 7
    assert client.get("/admin/insights/data.json?range=all").json()["bucket"] <= 86400
