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

# Device "identity" addresses are allocated in VPN_SUBNET; only their host part (low 16 bits) matters.
VPN_SUBNET = ipaddress.ip_network(os.environ.get("VPN_SUBNET", "10.66.0.0/16"))
# Each server gets its own /16 out of this pool (slot 0 = 10.64.0.0/16, slot 1 = 10.65.0.0/16, ...), and a
# device's address on a server is that server's /16 + the device's host part. Tunnels for different
# locations therefore never overlap on the client - WireGuard apps refuse overlapping tunnel addresses.
VPN_POOL = ipaddress.ip_network(os.environ.get("VPN_POOL", "10.64.0.0/10"))
MAX_NODES = VPN_POOL.num_addresses // 65536
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


def node_subnet(slot: int) -> ipaddress.IPv4Network:
    if not 0 <= slot < MAX_NODES:
        raise ValueError(f"server slot {slot} outside VPN_POOL ({MAX_NODES} servers max)")
    return ipaddress.ip_network((int(VPN_POOL.network_address) + slot * 65536, 16))


def server_address(slot: int) -> str:
    """Address (with prefix) of a server's wg interface."""
    net = node_subnet(slot)
    return f"{net.network_address + 1}/{net.prefixlen}"


def device_ip(device, node) -> str:
    """A device's tunnel address on a given server: the server's /16 + the device's host part."""
    host = int(ipaddress.ip_address(device["address"])) & 0xFFFF
    return str(node_subnet(node["slot"]).network_address + host)


def allocate_slot(conn) -> int:
    used = {r[0] for r in conn.execute("SELECT slot FROM nodes WHERE slot IS NOT NULL")}
    slot = next((s for s in range(MAX_NODES) if s not in used), None)
    if slot is None:
        raise ValueError(f"all {MAX_NODES} server address ranges are in use; widen VPN_POOL")
    return slot


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


# Cloudflare's proxy ranges (https://www.cloudflare.com/ips-v4). A server "endpoint" in here means the panel
# saw Cloudflare instead of the server - WireGuard can't go through Cloudflare's proxy.
CLOUDFLARE_V4 = [ipaddress.ip_network(n) for n in (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
    "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22")]


def endpoint_problem(host: str) -> str:
    """'' if clients can reach this IPv4 endpoint, else a short reason ('Cloudflare IP', 'Private IP')."""
    try:
        ip = ipaddress.ip_address(host.strip())
    except ValueError:
        return ""  # hostname: can't judge here
    if any(ip in net for net in CLOUDFLARE_V4):
        return "Cloudflare IP"
    if not ip.is_global:
        return "Private IP"
    return ""


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
        f"Address = {device_ip(device, node)}/32\n"
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
