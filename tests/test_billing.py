import hashlib
import hmac
import json
import time

import pytest

from app import billing, db, main
from tests.conftest import add_node, signup, sync


def user_row(email):
    with db.session() as conn:
        return conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()


def grant(email, plan):
    with db.session() as conn:
        conn.execute("UPDATE users SET plan = ?, plan_source = 'manual' WHERE email = ?", (plan, email))


def devices_of(email):
    with db.session() as conn:
        return conn.execute("SELECT d.* FROM devices d JOIN users u ON u.id = d.user_id WHERE u.email = ? "
                            "ORDER BY d.id", (email,)).fetchall()


def handshake(device, ago=5):
    return {"public_key": device["public_key"], "handshake": int(time.time()) - ago, "rx": 100, "tx": 200}


# --------------------------------------------------------------------------- paywall

def test_new_signup_sees_plans_not_servers(client):
    signup(client)
    page = client.get("/portal").text
    assert "Choose your plan" in page and "1</b> device at a time" in page and "5</b> devices at a time" in page
    assert client.get("/portal/configs.zip?device=1", follow_redirects=False).headers["location"] == "/portal"
    assert devices_of("cust@example.com") == []


def test_unpaid_users_are_not_given_to_servers(client):
    secret = add_node(client)
    signup(client)
    assert sync(client, secret) == set()


def test_granted_plan_unlocks_portal_and_creates_first_device(client):
    signup(client)
    grant("cust@example.com", "basic")
    page = client.get("/portal").text
    assert "Your devices" in page and "My device" in page
    dev = devices_of("cust@example.com")[0]
    secret = add_node(client)
    assert sync(client, secret) == {dev["public_key"]}
    conf = client.get(f"/portal/config/1.conf?device={dev['id']}").text
    assert "Address = 10.64.0.2/32" in conf and dev["private_key"] in conf  # first server's range


def test_cannot_download_someone_elses_device(client):
    signup(client, "a@example.com")
    grant("a@example.com", "pro")
    client.get("/portal")
    other = devices_of("a@example.com")[0]
    client.post("/logout")
    signup(client, "b@example.com")
    grant("b@example.com", "pro")
    add_node(client)
    assert client.get(f"/portal/config/1.conf?device={other['id']}").status_code == 404


# --------------------------------------------------------------------------- simultaneous connections

def test_basic_allows_one_device_at_a_time(client):
    secret = add_node(client)
    signup(client)
    grant("cust@example.com", "basic")
    client.get("/portal")
    client.post("/portal/devices", data={"name": "Laptop"})
    phone, laptop = devices_of("cust@example.com")
    # nobody connected: both may try
    assert sync(client, secret) == {phone["public_key"], laptop["public_key"]}
    # phone connects -> the laptop is refused while the phone holds the only slot
    assert sync(client, secret, [handshake(phone)]) == {phone["public_key"]}
    assert sync(client, secret, [handshake(phone)]) == {phone["public_key"]}
    status = client.get("/portal/status.json").json()
    assert [d["blocked"] for d in status["devices"]] == [False, True]
    assert "All your connections are in use" in client.get("/portal").text


def test_first_connected_device_keeps_the_slot(client):
    secret = add_node(client)
    signup(client)
    grant("cust@example.com", "basic")
    client.get("/portal")
    client.post("/portal/devices", data={"name": "Laptop"})
    phone, laptop = devices_of("cust@example.com")
    sync(client, secret, [handshake(phone, ago=30)])
    # both handshook in the same sync window: the earlier session wins
    assert sync(client, secret, [handshake(phone, ago=2), handshake(laptop, ago=1)]) == {phone["public_key"]}


def test_disconnect_frees_the_slot_for_another_device(client):
    secret = add_node(client)
    signup(client)
    grant("cust@example.com", "basic")
    client.get("/portal")
    client.post("/portal/devices", data={"name": "Laptop"})
    phone, laptop = devices_of("cust@example.com")
    sync(client, secret, [handshake(phone)])
    client.post(f"/portal/devices/{phone['id']}/disconnect")
    # phone is dropped, laptop allowed; the phone's last (still recent) handshake can't reclaim the slot
    assert sync(client, secret, [handshake(phone)]) == {laptop["public_key"]}
    assert sync(client, secret, [handshake(laptop)]) == {laptop["public_key"]}


def test_idle_device_releases_slot(client):
    secret = add_node(client)
    signup(client)
    grant("cust@example.com", "basic")
    client.get("/portal")
    client.post("/portal/devices", data={"name": "Laptop"})
    phone, laptop = devices_of("cust@example.com")
    sync(client, secret, [handshake(phone, ago=main.ACTIVE_WINDOW + 60)])
    assert sync(client, secret) == {phone["public_key"], laptop["public_key"]}


def test_pro_allows_five_at_once(client):
    secret = add_node(client)
    signup(client)
    grant("cust@example.com", "pro")
    client.get("/portal")
    for i in range(5):
        client.post("/portal/devices", data={"name": f"Device {i}"})
    devs = devices_of("cust@example.com")
    assert len(devs) == 6
    live = [handshake(d) for d in devs[:5]]
    assert sync(client, secret, live) == {d["public_key"] for d in devs[:5]}


def test_connections_count_across_servers(client):
    a, b = add_node(client, "A"), add_node(client, "B")
    signup(client)
    grant("cust@example.com", "basic")
    client.get("/portal")
    client.post("/portal/devices", data={"name": "Laptop"})
    phone, laptop = devices_of("cust@example.com")
    sync(client, a, [handshake(phone)])
    assert sync(client, b) == {phone["public_key"]}  # laptop can't use server B either


def test_device_cap(client, monkeypatch):
    monkeypatch.setattr(billing, "MAX_DEVICES", 2)
    signup(client)
    grant("cust@example.com", "pro")
    client.get("/portal")
    client.post("/portal/devices", data={"name": "Two"})
    client.post("/portal/devices", data={"name": "Three"})
    assert len(devices_of("cust@example.com")) == 2


# --------------------------------------------------------------------------- Stripe

class FakeStripeObject(dict):
    def to_dict(self):
        return dict(self)

    @property
    def url(self):
        return self["url"]


class FakeStripe:
    """Stands in for StripeClient.v1 so tests run without network or keys."""
    def __init__(self):
        self.subscriptions_by_id = {}
        self.created_sessions = []
        outer = self

        class Subs:
            def retrieve(self, sid, *a):
                return FakeStripeObject(outer.subscriptions_by_id[sid])

            def update(self, sid, params):
                sub = outer.subscriptions_by_id[sid]
                sub["items"]["data"][0]["price"]["id"] = params["items"][0]["price"]
                return FakeStripeObject(sub)

        class Sessions:
            def create(self, params):
                outer.created_sessions.append(params)
                return FakeStripeObject(url="https://checkout.stripe.test/s/1")

        class Prices:
            def retrieve(self, pid):
                return FakeStripeObject(unit_amount=499 if pid == "price_basic" else 999, currency="usd",
                                        recurring={"interval": "month", "interval_count": 1})

        self.v1 = type("V1", (), {"subscriptions": Subs(), "prices": Prices(),
                                  "checkout": type("C", (), {"sessions": Sessions()})(),
                                  "billing_portal": type("B", (), {"sessions": Sessions()})()})()

    def add_sub(self, sid, user_id, price, status="active", customer="cus_1"):
        self.subscriptions_by_id[sid] = {
            "id": sid, "customer": customer, "status": status, "metadata": {"user_id": str(user_id)},
            "cancel_at_period_end": False,
            "items": {"data": [{"id": "si_1", "price": {"id": price}, "current_period_end": 1900000000}]},
        }


@pytest.fixture
def stripe_on(monkeypatch):
    fake = FakeStripe()
    monkeypatch.setattr(billing, "_client", fake)
    monkeypatch.setattr(billing, "STRIPE_WEBHOOK_SECRET", "whsec_test")
    monkeypatch.setitem(billing.PLANS["basic"], "price_id", "price_basic")
    monkeypatch.setitem(billing.PLANS["pro"], "price_id", "price_pro")
    billing._price_cache.clear()
    return fake


def post_event(client, event, secret="whsec_test"):
    payload = json.dumps(event)
    ts = int(time.time())
    sig = hmac.new(secret.encode(), f"{ts}.{payload}".encode(), hashlib.sha256).hexdigest()
    return client.post("/billing/webhook", content=payload,
                       headers={"Stripe-Signature": f"t={ts},v1={sig}", "Content-Type": "application/json"})


def test_pricing_shows_stripe_prices(client, stripe_on):
    signup(client)
    page = client.get("/portal").text
    assert "$4.99/month" in page and "$9.99/month" in page and "Get Basic" in page


def test_checkout_redirects_to_stripe(client, stripe_on):
    signup(client)
    r = client.post("/billing/checkout", data={"plan": "pro"}, follow_redirects=False)
    assert r.headers["location"] == "https://checkout.stripe.test/s/1"
    params = stripe_on.created_sessions[0]
    assert params["line_items"][0]["price"] == "price_pro"
    assert params["customer_email"] == "cust@example.com" and params["mode"] == "subscription"


def test_webhook_activates_and_cancels_subscription(client, stripe_on):
    signup(client)
    uid = user_row("cust@example.com")["id"]
    stripe_on.add_sub("sub_1", uid, "price_basic")
    r = post_event(client, {"id": "evt_1", "type": "checkout.session.completed", "data": {"object": {
        "mode": "subscription", "client_reference_id": str(uid), "customer": "cus_1", "subscription": "sub_1"}}})
    assert r.status_code == 200
    u = user_row("cust@example.com")
    assert (u["plan"], u["sub_status"], u["stripe_customer_id"]) == ("basic", "active", "cus_1")
    assert billing.has_access(u) and billing.device_limit(u) == 1

    stripe_on.subscriptions_by_id["sub_1"]["items"]["data"][0]["price"]["id"] = "price_pro"
    post_event(client, {"id": "evt_2", "type": "customer.subscription.updated", "data": {"object": {"id": "sub_1"}}})
    assert billing.device_limit(user_row("cust@example.com")) == 5

    stripe_on.subscriptions_by_id["sub_1"]["status"] = "canceled"
    post_event(client, {"id": "evt_3", "type": "customer.subscription.deleted", "data": {"object": {"id": "sub_1"}}})
    u = user_row("cust@example.com")
    assert not billing.has_access(u) and u["plan"] == ""
    assert "Your subscription has ended" in client.get("/portal").text


def test_past_due_keeps_access_unpaid_does_not(client, stripe_on):
    signup(client)
    uid = user_row("cust@example.com")["id"]
    stripe_on.add_sub("sub_1", uid, "price_basic", status="past_due")
    post_event(client, {"id": "evt_1", "type": "customer.subscription.updated", "data": {"object": {"id": "sub_1"}}})
    assert billing.has_access(user_row("cust@example.com"))
    stripe_on.subscriptions_by_id["sub_1"]["status"] = "unpaid"
    post_event(client, {"id": "evt_2", "type": "customer.subscription.updated", "data": {"object": {"id": "sub_1"}}})
    assert not billing.has_access(user_row("cust@example.com"))


def test_webhook_rejects_bad_signature_and_ignores_duplicates(client, stripe_on):
    signup(client)
    uid = user_row("cust@example.com")["id"]
    stripe_on.add_sub("sub_1", uid, "price_pro")
    event = {"id": "evt_1", "type": "customer.subscription.created", "data": {"object": {"id": "sub_1"}}}
    assert post_event(client, event, secret="wrong").status_code == 400
    assert user_row("cust@example.com")["plan"] == ""
    assert post_event(client, event).json() == {"received": "customer.subscription.created"}
    assert post_event(client, event).json() == {"received": "duplicate"}


def test_success_redirect_activates_without_waiting_for_webhook(client, stripe_on, monkeypatch):
    signup(client)
    uid = user_row("cust@example.com")["id"]
    stripe_on.add_sub("sub_1", uid, "price_pro")
    monkeypatch.setattr(billing, "complete_checkout", lambda conn, sid: billing._apply_checkout(
        conn, {"client_reference_id": str(uid), "customer": "cus_1", "subscription": "sub_1"}))
    r = client.get("/billing/success?session_id=cs_1", follow_redirects=False)
    assert r.headers["location"] == "/portal"
    assert billing.device_limit(user_row("cust@example.com")) == 5


def test_change_plan_switches_existing_subscription(client, stripe_on):
    signup(client)
    uid = user_row("cust@example.com")["id"]
    stripe_on.add_sub("sub_1", uid, "price_basic")
    post_event(client, {"id": "evt_1", "type": "customer.subscription.created", "data": {"object": {"id": "sub_1"}}})
    # "Get Pro" while already subscribed must switch, not open a second checkout
    client.post("/billing/checkout", data={"plan": "pro"})
    assert stripe_on.created_sessions == []
    assert user_row("cust@example.com")["plan"] == "pro"


# --------------------------------------------------------------------------- admin & migration

def test_admin_can_grant_and_remove_free_plan(client):
    signup(client)
    uid = user_row("cust@example.com")["id"]
    client.post("/logout")
    main_admin = "boss@example.com"
    with db.session() as conn:
        main.create_user(conn, main_admin, "adminpass123", is_admin=True)
    client.post("/login", data={"email": main_admin, "password": "adminpass123"})
    client.post(f"/admin/users/{uid}/plan", data={"plan": "pro"})
    assert billing.device_limit(user_row("cust@example.com")) == 5
    client.post(f"/admin/users/{uid}/plan", data={"plan": ""})
    assert not billing.has_access(user_row("cust@example.com"))


def test_old_single_key_users_keep_their_config(tmp_path, monkeypatch):
    """Users from before devices existed keep their key and tunnel address as their first device."""
    import sqlite3
    path = tmp_path / "old.db"
    old = sqlite3.connect(path)
    old.executescript("""
        CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, password_hash TEXT,
            is_admin INTEGER DEFAULT 0, status TEXT DEFAULT 'active', private_key TEXT, public_key TEXT UNIQUE,
            created_at TEXT DEFAULT (datetime('now')));
        CREATE TABLE peer_stats (user_id INTEGER, node_id INTEGER, rx_bytes INTEGER, tx_bytes INTEGER,
            last_handshake INTEGER, PRIMARY KEY (user_id, node_id));
        INSERT INTO users (email, password_hash, private_key, public_key) VALUES
            ('used@x.com', 'h', 'PRIV1', 'PUB1'), ('never@x.com', 'h', 'PRIV2', 'PUB2');
        INSERT INTO peer_stats VALUES (1, 1, 10, 20, 1700000000);
    """)
    old.commit()
    old.close()
    monkeypatch.setattr(db, "DB_PATH", str(path))
    db.init()
    db.init()  # idempotent
    with db.session() as conn:
        devs = conn.execute("SELECT user_id, public_key, address FROM devices").fetchall()
    assert [tuple(d) for d in devs] == [(1, "PUB1", "10.66.0.2")]


def test_admin_told_why_a_price_is_missing(client, stripe_on, monkeypatch):
    def bad(pid):
        raise billing.stripe.InvalidRequestError(f"No such price: '{pid}'", "id")
    monkeypatch.setattr(stripe_on.v1.prices, "retrieve", bad)
    monkeypatch.setitem(billing.PLANS["basic"], "price_id", "prod_ABC")
    with db.session() as conn:
        main.create_user(conn, "boss@example.com", "adminpass123", is_admin=True)
    client.post("/login", data={"email": "boss@example.com", "password": "adminpass123"})
    page = client.get("/admin").text
    assert "No price shown for Basic" in page and "use the price ID" in page


def test_price_text_from_env_shows_on_homepage(client, monkeypatch):
    monkeypatch.setitem(billing.PLANS["basic"], "price_label", "$4.99/month")
    monkeypatch.setitem(billing.PLANS["pro"], "price_label", "$9.99/month")
    page = client.get("/").text
    assert "$4.99/month" in page and "$9.99/month" in page


# --------------------------------------------------------------------------- unlimited (admin-only) plan

def _login_admin(client):
    client.post("/logout")
    with db.session() as conn:
        if not conn.execute("SELECT 1 FROM users WHERE email = 'boss@example.com'").fetchone():
            main.create_user(conn, "boss@example.com", "adminpass123", is_admin=True)
    client.post("/login", data={"email": "boss@example.com", "password": "adminpass123"})


def test_unlimited_plan_has_no_device_limit(client):
    secret = add_node(client)
    signup(client)
    uid = user_row("cust@example.com")["id"]
    _login_admin(client)
    client.post(f"/admin/users/{uid}/plan", data={"plan": "unlimited"})
    u = user_row("cust@example.com")
    assert billing.has_access(u) and billing.device_limit(u) >= billing.UNLIMITED
    client.post("/logout")
    client.post("/login", data={"email": "cust@example.com", "password": "password123"})
    client.get("/portal")
    for i in range(7):
        client.post("/portal/devices", data={"name": f"D{i}"})
    devs = devices_of("cust@example.com")
    assert sync(client, secret, [handshake(d) for d in devs]) == {d["public_key"] for d in devs}
    page = client.get("/portal").text
    assert "Unlimited can be connected at a time" in page and "Unlimited" in page


def test_unlimited_plan_is_never_for_sale(client, stripe_on):
    assert "<h2>Unlimited</h2>" not in client.get("/").text
    signup(client)
    page = client.get("/portal").text                                  # pricing page
    assert "<h2>Basic</h2>" in page and "<h2>Unlimited</h2>" not in page
    assert client.post("/billing/checkout", data={"plan": "unlimited"}).status_code == 400
    assert stripe_on.created_sessions == []


def test_admins_themselves_are_unlimited(client):
    _login_admin(client)
    assert billing.device_limit(user_row("boss@example.com")) >= billing.UNLIMITED


# --------------------------------------------------------------------------- changing email

def test_customer_changes_their_email(client):
    signup(client)
    grant("cust@example.com", "basic")
    r = client.post("/account/email", data={"email": "new@example.com", "password": "wrong-password"})
    assert user_row("cust@example.com") is not None                      # wrong password: unchanged
    client.post("/account/email", data={"email": "New@Example.com", "password": "password123"})
    assert user_row("cust@example.com") is None and user_row("new@example.com") is not None
    client.post("/logout")
    r = client.post("/login", data={"email": "new@example.com", "password": "password123"}, follow_redirects=False)
    assert r.headers["location"] == "/portal"


def test_email_must_be_unique(client):
    signup(client, "a@example.com")
    client.post("/logout")
    signup(client, "b@example.com")
    client.post("/account/email", data={"email": "a@example.com", "password": "password123"})
    assert user_row("b@example.com") is not None


def test_admin_fixes_a_users_email_and_logs_follow(client):
    signup(client, "typo@exmaple.com")
    uid = user_row("typo@exmaple.com")["id"]
    with db.session() as conn:
        conn.execute("""INSERT INTO sessions (user_email, device_name, node_name, client_ip, started, last_seen)
                        VALUES ('typo@exmaple.com', 'Phone', 'CHI1', '45.1.1.1', 1, 2)""")
    _login_admin(client)
    client.post(f"/admin/users/{uid}/email", data={"email": "fixed@example.com"})
    assert user_row("fixed@example.com")["id"] == uid
    with db.session() as conn:
        assert conn.execute("SELECT user_email FROM sessions").fetchone()[0] == "fixed@example.com"


def test_renamed_admin_is_not_recreated_on_restart(client, monkeypatch):
    monkeypatch.setenv("ADMIN_EMAIL", "boss@example.com")
    monkeypatch.setenv("ADMIN_PASSWORD", "adminpass123")
    _login_admin(client)
    client.post("/account/email", data={"email": "me@valor.example", "password": "adminpass123"})
    import asyncio
    asyncio.run(main.startup())
    with db.session() as conn:
        admins = [r[0] for r in conn.execute("SELECT email FROM users WHERE is_admin = 1")]
    assert admins == ["me@valor.example"]
