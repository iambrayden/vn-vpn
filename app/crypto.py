"""Password hashing, WireGuard key generation, client addressing and config rendering."""
import base64
import hashlib
import hmac
import ipaddress
import os
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

# Every node runs the same tunnel subnet; a user gets the same address on every node,
# derived from their user id, so no per-node IP allocation is needed.
VPN_SUBNET = ipaddress.ip_network(os.environ.get("VPN_SUBNET", "10.66.0.0/16"))
CLIENT_DNS = os.environ.get("CLIENT_DNS", "1.1.1.1, 1.0.0.1")
PBKDF2_ROUNDS = 260_000


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ROUNDS)
    return f"pbkdf2${PBKDF2_ROUNDS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, rounds, salt, digest = stored.split("$")
    except ValueError:
        return False
    calc = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(rounds))
    return hmac.compare_digest(calc.hex(), digest)


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def wg_keypair() -> tuple[str, str]:
    key = X25519PrivateKey.generate()
    priv = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                             serialization.NoEncryption())
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(priv).decode(), base64.b64encode(pub).decode()


def server_address() -> str:
    """Address (with prefix) of the wg interface on every node."""
    return f"{VPN_SUBNET.network_address + 1}/{VPN_SUBNET.prefixlen}"


def client_ip(user_id: int) -> str:
    # .0 network, .1 is the node itself; users start at .2
    offset = user_id + 1
    if offset >= VPN_SUBNET.num_addresses - 1:
        raise ValueError("VPN subnet exhausted; widen VPN_SUBNET")
    return str(VPN_SUBNET.network_address + offset)


def client_config(user, node) -> str:
    return (
        "[Interface]\n"
        f"# {node['name']} ({node['location']}) - {user['email']}\n"
        f"PrivateKey = {user['private_key']}\n"
        f"Address = {client_ip(user['id'])}/32\n"
        f"DNS = {CLIENT_DNS}\n"
        "\n"
        "[Peer]\n"
        f"PublicKey = {node['public_key']}\n"
        f"Endpoint = {node['endpoint_host']}:{node['listen_port']}\n"
        "AllowedIPs = 0.0.0.0/0, ::/0\n"
        "PersistentKeepalive = 25\n"
    )
