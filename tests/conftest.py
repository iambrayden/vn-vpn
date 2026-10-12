import os
import tempfile

# Must be set before the app is imported: the DB path and session secret are read at import time.
_tmp = tempfile.mkdtemp(prefix="vnvpn-test-")
os.environ["DATABASE_PATH"] = os.path.join(_tmp, "boot.db")
os.environ["SECRET_KEY"] = "test-secret"
os.environ["PROVISION_API_KEY"] = "test-api-key"
os.environ.pop("STRIPE_SECRET_KEY", None)
os.environ["GEO_LOOKUP"] = "false"  # no ip2asn download in tests (tests that need it switch it on)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import billing, crypto, db, main  # noqa: E402


@pytest.fixture
def app_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "vnvpn.db"))
    db.init()
    return db


@pytest.fixture
def client(app_db):
    with TestClient(main.app) as c:
        yield c


def signup(client, email="cust@example.com", password="password123"):
    r = client.post("/signup", data={"email": email, "password": password}, follow_redirects=False)
    assert r.status_code == 303
    return client


def make_admin(email="admin@example.com"):
    with db.session() as conn:
        uid = main.create_user(conn, email, "adminpass123", is_admin=True)
    return uid


def add_node(client, name="Node", country="DE"):
    """Register a node through the real agent API; returns its bearer secret."""
    with db.session() as conn:
        conn.execute("INSERT OR IGNORE INTO enroll_tokens (token) VALUES ('tok')")
    _, pub = crypto.wg_keypair()
    r = client.post("/api/agent/register", json={"token": "tok", "name": name, "country": country,
                                                  "endpoint": "1.2.3.4", "public_key": pub})
    assert r.status_code == 200, r.text
    return r.json()["secret"]


def sync(client, secret, peers=()):
    r = client.post("/api/agent/sync", json={"agent_version": "test", "peers": list(peers)},
                    headers={"Authorization": f"Bearer {secret}"})
    assert r.status_code == 200, r.text
    return {p["public_key"] for p in r.json()["peers"]}
