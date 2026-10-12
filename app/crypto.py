"""Password hashing, WireGuard key generation, client addressing and config rendering."""
import base64
import hashlib
import hmac
import ipaddress
import os
import re
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

# Every node runs the same tunnel subnet; each device gets one address that is valid on every node,
# so no per-node IP allocation is needed.
VPN_SUBNET = ipaddress.ip_network(os.environ.get("VPN_SUBNET", "10.66.0.0/16"))
CLIENT_DNS = os.environ.get("CLIENT_DNS", "1.1.1.1, 1.0.0.1")
# 1380 instead of WireGuard's 1420 default: leaves headroom for PPPoE, mobile and other tunnels, which
# otherwise show up as "connected but pages hang". Used for both clients and servers.
WG_MTU = int(os.environ.get("WG_MTU", "1380"))
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


def client_ip(offset: int) -> str:
    """Tunnel address at a given offset (.0 is the network, .1 the node itself)."""
    offset = offset + 1
    if offset >= VPN_SUBNET.num_addresses - 1:
        raise ValueError("VPN subnet exhausted; widen VPN_SUBNET")
    return str(VPN_SUBNET.network_address + offset)


def allocate_address(conn) -> str:
    """Lowest tunnel address not yet used by any device."""
    used = {r[0] for r in conn.execute("SELECT address FROM devices")}
    offset = 1
    while client_ip(offset) in used:
        offset += 1
    return client_ip(offset)


def valid_endpoint(host: str) -> bool:
    """Servers are IPv4-only: a public IPv4 address or a hostname (which should resolve to one)."""
    host = host.strip()
    try:
        return ipaddress.ip_address(host).version == 4
    except ValueError:
        return bool(re.fullmatch(r"(?=.{1,253}$)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}", host))


def client_config(device, node, email: str) -> str:
    return (
        "[Interface]\n"
        f"# {node['name']} ({node['location']}) - {device['name']} - {email}\n"
        f"PrivateKey = {device['private_key']}\n"
        f"Address = {device['address']}/32\n"
        f"DNS = {CLIENT_DNS}\n"
        f"MTU = {WG_MTU}\n"
        "\n"
        "[Peer]\n"
        f"PublicKey = {node['public_key']}\n"
        f"Endpoint = {node['endpoint_host']}:{node['listen_port']}\n"
        # ::/0 routes IPv6 into the (IPv4-only) tunnel where it is dropped, so it can't leak around the VPN
        "AllowedIPs = 0.0.0.0/0, ::/0\n"
        "PersistentKeepalive = 25\n"
    )
