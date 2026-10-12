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
    assert "Traffic insights" in client.get("/admin/insights").text
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
