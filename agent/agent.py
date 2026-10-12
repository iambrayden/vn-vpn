#!/usr/bin/env python3
"""VN-VPN node agent (stdlib only).

  agent.py enroll --panel URL --token TOKEN [--name N] [--location L] [--country DE] [--endpoint HOST] [--port 51820]
  agent.py run            # sync loop (what the systemd service runs)
  agent.py run --once     # single sync, handy for debugging

Every few seconds the agent reports per-peer traffic to the panel and receives the list of
peers this node should accept, then applies it with `wg syncconf` (no tunnel interruption).
The node's private key never leaves the server.
"""
import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

VERSION = "0.1.0"
CONF_DIR = os.environ.get("VNVPN_DIR", "/etc/vnvpn")
CONF_FILE = os.path.join(CONF_DIR, "agent.json")
KEY_FILE = os.path.join(CONF_DIR, "private.key")
WG_DIR = os.environ.get("WG_DIR", "/etc/wireguard")
DRY_RUN = os.environ.get("VNVPN_DRY_RUN") == "1"  # print config instead of touching WireGuard


def log(*args):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), *args, flush=True)


def sh(*cmd, input=None):
    return subprocess.run(cmd, input=input, capture_output=True, text=True, check=True).stdout


def http(method, url, body=None, secret=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", f"vnvpn-agent/{VERSION}")
    if secret:
        req.add_header("Authorization", f"Bearer {secret}")
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read())


def load_conf():
    with open(CONF_FILE) as f:
        return json.load(f)


def public_key():
    if DRY_RUN and not os.path.exists(KEY_FILE):
        return "DRYRUNdryrunDRYRUNdryrunDRYRUNdryrunDRYRUN0="
    with open(KEY_FILE) as f:
        return sh("wg", "pubkey", input=f.read()).strip()


def default_iface():
    try:
        out = sh("ip", "-o", "route", "get", "1.1.1.1").split()
        return out[out.index("dev") + 1]
    except Exception:
        return "eth0"


# --------------------------------------------------------------------------- enroll

def enroll(args):
    panel = args.panel.rstrip("/")
    endpoint = args.endpoint
    if not endpoint:
        endpoint = http("GET", f"{panel}/api/agent/whoami")["ip"]
    res = http("POST", f"{panel}/api/agent/register", {
        "token": args.token,
        "name": args.name or socket.gethostname(),
        "location": args.location or "",
        "country": args.country or "",
        "endpoint": endpoint,
        "listen_port": args.port,
        "public_key": public_key(),
        "hostname": socket.gethostname(),
    })
    os.makedirs(CONF_DIR, exist_ok=True)
    conf = {"panel": panel, "node_id": res["node_id"], "secret": res["secret"],
            "interface": args.interface, "listen_port": args.port, "wan_iface": default_iface()}
    fd = os.open(CONF_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(conf, f, indent=2)
    log(f"enrolled as node #{res['node_id']} ({endpoint}:{args.port})")


# --------------------------------------------------------------------------- sync

def peer_stats(iface):
    """Parse `wg show <iface> dump` into the stats payload the panel expects."""
    if DRY_RUN:
        return []
    try:
        lines = sh("wg", "show", iface, "dump").strip().splitlines()
    except subprocess.CalledProcessError:
        return []
    stats = []
    for line in lines[1:]:  # first line is the interface itself
        pub, _psk, _endpoint, _allowed, handshake, rx, tx, _ka = line.split("\t")
        stats.append({"public_key": pub, "handshake": int(handshake), "rx": int(rx), "tx": int(tx)})
    return stats


def render_wg_conf(conf, desired):
    private_key = "<private key>"
    if not DRY_RUN:
        with open(KEY_FILE) as f:
            private_key = f.read().strip()
    wan = conf.get("wan_iface") or default_iface()
    iface = conf["interface"]
    lines = [
        "# Managed by vnvpn-agent - changes will be overwritten",
        "[Interface]",
        f"Address = {desired['address']}",
        f"ListenPort = {desired['listen_port']}",
        f"PrivateKey = {private_key}",
        f"PostUp = iptables -t nat -A POSTROUTING -o {wan} -j MASQUERADE; "
        f"iptables -A FORWARD -i {iface} -j ACCEPT; iptables -A FORWARD -o {iface} -j ACCEPT",
        f"PostDown = iptables -t nat -D POSTROUTING -o {wan} -j MASQUERADE; "
        f"iptables -D FORWARD -i {iface} -j ACCEPT; iptables -D FORWARD -o {iface} -j ACCEPT",
        "",
    ]
    for p in desired["peers"]:
        lines += ["[Peer]", f"PublicKey = {p['public_key']}", f"AllowedIPs = {p['allowed_ips']}", ""]
    return "\n".join(lines)


def iface_up(iface):
    return subprocess.run(["ip", "link", "show", iface], capture_output=True).returncode == 0


def apply(conf, desired, last_rendered):
    rendered = render_wg_conf(conf, desired)
    if rendered == last_rendered:
        return rendered
    iface = conf["interface"]
    if DRY_RUN:
        print(rendered)
        return rendered
    path = os.path.join(WG_DIR, f"{iface}.conf")
    fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(rendered)
    os.replace(path + ".tmp", path)
    if not iface_up(iface):
        sh("wg-quick", "up", iface)
        log(f"brought up {iface}")
    else:
        stripped = sh("wg-quick", "strip", iface)
        sh("wg", "syncconf", iface, "/dev/stdin", input=stripped)
    log(f"applied {len(desired['peers'])} peers")
    return rendered


def run(args):
    conf = load_conf()
    last, interval, failures = None, 15, 0
    log(f"vnvpn-agent {VERSION} node #{conf['node_id']} -> {conf['panel']}")
    # After a reboot, restore the last known config right away so users can connect
    # even if the panel is unreachable.
    if not DRY_RUN and not iface_up(conf["interface"]) and os.path.exists(
            os.path.join(WG_DIR, f"{conf['interface']}.conf")):
        try:
            sh("wg-quick", "up", conf["interface"])
            log(f"restored {conf['interface']} from last config")
        except subprocess.CalledProcessError as e:
            log(f"could not restore interface: {e.stderr}")
    while True:
        try:
            desired = http("POST", f"{conf['panel']}/api/agent/sync",
                           {"agent_version": VERSION, "peers": peer_stats(conf["interface"])},
                           secret=conf["secret"])
            last = apply(conf, desired, last)
            interval, failures = int(desired.get("interval", 15)), 0
        except urllib.error.HTTPError as e:
            failures += 1
            log(f"panel returned HTTP {e.code}: {e.read()[:200]!r}")
        except Exception as e:  # network blips etc. - keep the current tunnel config running
            failures += 1
            log(f"sync failed: {e}")
        if args.once:
            return 0 if failures == 0 else 1
        time.sleep(min(interval * (2 ** min(failures, 4)), 300) if failures else interval)


def main():
    ap = argparse.ArgumentParser(prog="vnvpn-agent")
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("enroll")
    e.add_argument("--panel", required=True)
    e.add_argument("--token", required=True)
    e.add_argument("--name")
    e.add_argument("--location")
    e.add_argument("--country", help="ISO country code for the flag, e.g. DE")
    e.add_argument("--endpoint", help="public IP/hostname clients connect to (auto-detected)")
    e.add_argument("--port", type=int, default=51820)
    e.add_argument("--interface", default="wg0")
    r = sub.add_parser("run")
    r.add_argument("--once", action="store_true")
    sub.add_parser("version")
    args = ap.parse_args()
    if args.cmd == "enroll":
        enroll(args)
    elif args.cmd == "run":
        sys.exit(run(args))
    else:
        print(VERSION)


if __name__ == "__main__":
    main()
