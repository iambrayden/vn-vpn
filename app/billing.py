"""Plans, entitlements and Stripe (Checkout, Customer Portal, webhooks)."""
import json
import os
import time

import stripe

STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
MAX_DEVICES = int(os.environ.get("MAX_DEVICES", "10"))  # devices a user may register (not connect at once)

# Plan key -> settings. "devices" = how many devices may be connected at the same time.
PLANS = {
    "basic": {
        "name": os.environ.get("PLAN_BASIC_NAME", "Basic"),
        "devices": int(os.environ.get("PLAN_BASIC_DEVICES", "1")),
        "price_id": os.environ.get("STRIPE_PRICE_BASIC", ""),
        "price_label": os.environ.get("PLAN_BASIC_PRICE", ""),
    },
    "pro": {
        "name": os.environ.get("PLAN_PRO_NAME", "Pro"),
        "devices": int(os.environ.get("PLAN_PRO_DEVICES", "5")),
        "price_id": os.environ.get("STRIPE_PRICE_PRO", ""),
        "price_label": os.environ.get("PLAN_PRO_PRICE", ""),
    },
}
# Stripe subscription statuses that keep the VPN working. past_due = Stripe is still retrying the card.
LIVE_STATUSES = {"active", "trialing", "past_due"}

_client = stripe.StripeClient(STRIPE_SECRET_KEY) if STRIPE_SECRET_KEY else None
_price_cache: dict[str, tuple[float, str]] = {}


def enabled() -> bool:
    return bool(_client and any(p["price_id"] for p in PLANS.values()))


# --------------------------------------------------------------------------- entitlements

def has_access(user) -> bool:
    if user is None or user["status"] != "active":
        return False
    if user["is_admin"]:
        return True
    return user["plan"] in PLANS and (user["plan_source"] == "manual" or user["sub_status"] in LIVE_STATUSES)


def device_limit(user) -> int:
    """Simultaneous connections allowed for this user."""
    if user["plan"] in PLANS and has_access(user):
        return PLANS[user["plan"]]["devices"]
    if user["is_admin"]:
        return max(p["devices"] for p in PLANS.values())
    return 0


def plan_for_price(price_id: str) -> str:
    return next((k for k, p in PLANS.items() if p["price_id"] and p["price_id"] == price_id), "")


def price_label(plan: str) -> str:
    """'$4.99/month' from Stripe (cached for an hour), or the PLAN_*_PRICE override."""
    p = PLANS[plan]
    if p["price_label"] or not (_client and p["price_id"]):
        return p["price_label"]
    cached = _price_cache.get(plan)
    if cached and time.time() - cached[0] < 3600:
        return cached[1]
    try:
        price = _client.v1.prices.retrieve(p["price_id"]).to_dict()
        amount = (price.get("unit_amount") or 0) / 100
        symbol = {"usd": "$", "eur": "€", "gbp": "£", "cad": "CA$", "aud": "A$"}.get(price["currency"], "")
        text = f"{symbol}{amount:.2f}" if symbol else f"{amount:.2f} {price['currency'].upper()}"
        rec = price.get("recurring") or {}
        if rec:
            count = rec.get("interval_count", 1)
            text += f"/{rec['interval']}" if count == 1 else f" every {count} {rec['interval']}s"
        _price_cache[plan] = (time.time(), text)
        return text
    except stripe.StripeError:
        return ""


# --------------------------------------------------------------------------- Stripe calls

def checkout_url(user, plan: str, base_url: str) -> str:
    params = {
        "mode": "subscription",
        "line_items": [{"price": PLANS[plan]["price_id"], "quantity": 1}],
        "success_url": f"{base_url}/billing/success?session_id={{CHECKOUT_SESSION_ID}}",
        "cancel_url": f"{base_url}/portal",
        "client_reference_id": str(user["id"]),
        "metadata": {"user_id": str(user["id"])},
        "subscription_data": {"metadata": {"user_id": str(user["id"])}},
        "allow_promotion_codes": True,
    }
    if user["stripe_customer_id"]:
        params["customer"] = user["stripe_customer_id"]
    else:
        params["customer_email"] = user["email"]
    return _client.v1.checkout.sessions.create(params).url


def portal_url(user, return_url: str) -> str:
    return _client.v1.billing_portal.sessions.create(
        {"customer": user["stripe_customer_id"], "return_url": return_url}).url


def change_plan(conn, user, plan: str):
    """Switch an existing subscription to another plan, prorated."""
    sub = _client.v1.subscriptions.retrieve(user["stripe_subscription_id"]).to_dict()
    item = sub["items"]["data"][0]
    sub = _client.v1.subscriptions.update(sub["id"], {
        "items": [{"id": item["id"], "price": PLANS[plan]["price_id"]}],
        "proration_behavior": "create_prorations",
        "cancel_at_period_end": False,
    }).to_dict()
    sync_subscription(conn, sub)


def complete_checkout(conn, session_id: str):
    """Called on the success redirect so access is granted without waiting for the webhook."""
    session = _client.v1.checkout.sessions.retrieve(session_id, {"expand": ["subscription"]}).to_dict()
    _apply_checkout(conn, session)
    return session


# --------------------------------------------------------------------------- syncing state

def _apply_checkout(conn, session: dict):
    uid = session.get("client_reference_id") or (session.get("metadata") or {}).get("user_id")
    if uid and session.get("customer"):
        conn.execute("UPDATE users SET stripe_customer_id = ? WHERE id = ?", (session["customer"], int(uid)))
    sub = session.get("subscription")
    if isinstance(sub, str):
        sub = _client.v1.subscriptions.retrieve(sub).to_dict()
    if sub:
        sync_subscription(conn, sub, fallback_user_id=uid)


def sync_subscription(conn, sub: dict, fallback_user_id=None):
    uid = (sub.get("metadata") or {}).get("user_id") or fallback_user_id
    row = None
    if uid:
        row = conn.execute("SELECT id FROM users WHERE id = ?", (int(uid),)).fetchone()
    if not row and sub.get("customer"):
        row = conn.execute("SELECT id FROM users WHERE stripe_customer_id = ?", (sub["customer"],)).fetchone()
    if not row:
        return
    item = (sub.get("items") or {}).get("data", [{}])[0]
    plan = plan_for_price((item.get("price") or {}).get("id", ""))
    # current_period_end moved from the subscription to its items in newer Stripe API versions
    period_end = sub.get("current_period_end") or item.get("current_period_end") or 0
    status = sub.get("status", "")
    conn.execute("""UPDATE users SET plan = ?, plan_source = 'stripe', sub_status = ?, stripe_subscription_id = ?,
                    stripe_customer_id = COALESCE(NULLIF(?, ''), stripe_customer_id),
                    period_end = ?, cancel_at_period_end = ? WHERE id = ?""",
                 (plan if status != "canceled" else "", status, sub.get("id", ""), sub.get("customer") or "",
                  int(period_end), int(bool(sub.get("cancel_at_period_end"))), row["id"]))


def handle_webhook(conn, payload: bytes, signature: str | None):
    """Verify and apply a Stripe webhook. Raises ValueError on a bad signature."""
    try:
        stripe.WebhookSignature.verify_header(payload, signature, STRIPE_WEBHOOK_SECRET)
    except stripe.SignatureVerificationError as e:
        raise ValueError(str(e))
    event = json.loads(payload)
    if conn.execute("SELECT 1 FROM stripe_events WHERE id = ?", (event["id"],)).fetchone():
        return "duplicate"
    obj = event["data"]["object"]
    kind = event["type"]
    if kind == "checkout.session.completed" and obj.get("mode") == "subscription":
        _apply_checkout(conn, obj)
    elif kind in ("customer.subscription.created", "customer.subscription.updated",
                  "customer.subscription.deleted", "customer.subscription.paused",
                  "customer.subscription.resumed"):
        # Webhooks can arrive out of order; re-read the subscription so we always store its latest state.
        if _client:
            obj = _client.v1.subscriptions.retrieve(obj["id"]).to_dict()
        sync_subscription(conn, obj)
    conn.execute("INSERT INTO stripe_events (id, type) VALUES (?, ?)", (event["id"], kind))
    return kind
