#!/usr/bin/env python3
"""VN-VPN node agent (stdlib only).

  agent.py enroll --panel URL --token TOKEN [--name N] [--location L] [--country DE] [--endpoint HOST] [--port 51820]
  agent.py run            # sync loop (what the systemd service runs)
  agent.py run --once     # single sync, handy for debugging
  agent.py doctor         # check forwarding, NAT, firewall, handshakes and the public endpoint

Every few seconds the agent reports per-peer traffic to the panel and receives the list of
peers this node should accept, then applies it with `wg syncconf` (no tunnel interruption).
The node's private key never leaves the server.
"""
import argparse
import json
import os
import socket
import subprocess
import shutil
import sys
import threading
import time
import urllib.error
import urllib.request

VERSION = "0.3.2"
CONF_DIR = os.environ.get("VNVPN_DIR", "/etc/vnvpn")
CONF_FILE = os.path.join(CONF_DIR, "agent.json")
KEY_FILE = os.path.join(CONF_DIR, "private.key")
WG_DIR = os.environ.get("WG_DIR", "/etc/wireguard")
DRY_RUN = os.environ.get("VNVPN_DRY_RUN") == "1"  # print config instead of touching WireGuard


def log(*args):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), *args, flush=True)


def sh(*cmd, input=None):
    return subprocess.run(cmd, input=input, capture_output=True, text=True, check=True).stdout


def http(method, url, body=None, secret=None, ipv4_only=False):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", f"vnvpn-agent/{VERSION}")
    if secret:
        req.add_header("Authorization", f"Bearer {secret}")
    if not ipv4_only:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read())
    # Force IPv4 so the panel sees this server's IPv4 address (clients' networks often lack IPv6)
    orig = socket.getaddrinfo
    socket.getaddrinfo = lambda host, port, family=0, *a, **kw: orig(host, port, socket.AF_INET, *a, **kw)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read())
    finally:
        socket.getaddrinfo = orig


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
    panel = args.panel.strip().rstrip("/")
    if "://" not in panel:
        panel = "https://" + panel
    endpoint = args.endpoint
    if not endpoint:
        # IPv4 only: many client networks have no IPv6, so servers are always reached over IPv4
        try:
            endpoint = http("GET", f"{panel}/api/agent/whoami", ipv4_only=True)["ip"]
        except OSError as e:
            sys.exit(f"Could not reach the panel over IPv4 ({e}). This server needs a public IPv4 address; "
                     "pass --endpoint <IPv4> if it has one.")
        if ":" in endpoint:
            sys.exit(f"The panel saw this server as {endpoint} (IPv6). Pass --endpoint <public IPv4>.")
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
        pub, _psk, endpoint, _allowed, handshake, rx, tx, _ka = line.split("\t")
        stats.append({"public_key": pub, "handshake": int(handshake), "rx": int(rx), "tx": int(tx),
                      "endpoint": "" if endpoint == "(none)" else endpoint})
    return stats


# --------------------------------------------------------------------------- server metrics

class Metrics:
    """CPU / memory / disk / bandwidth from /proc, as rates since the previous sample."""

    def __init__(self, wan):
        self.wan = wan
        self.prev_cpu = self._cpu()
        self.prev_net = (time.time(), *self._net())

    @staticmethod
    def _cpu():
        with open("/proc/stat") as f:
            vals = [int(v) for v in f.readline().split()[1:]]
        idle = vals[3] + (vals[4] if len(vals) > 4 else 0)
        return sum(vals), idle

    def _net(self):
        with open("/proc/net/dev") as f:
            for line in f:
                name, _, data = line.partition(":")
                if name.strip() == self.wan:
                    cols = data.split()
                    return int(cols[0]), int(cols[8])
        return 0, 0

    def sample(self, active_peers):
        total, idle = self._cpu()
        dt, di = total - self.prev_cpu[0], idle - self.prev_cpu[1]
        self.prev_cpu = (total, idle)
        now, rx, tx = time.time(), *self._net()
        secs = max(now - self.prev_net[0], 1e-6)
        rx_bps = max(0, rx - self.prev_net[1]) * 8 / secs
        tx_bps = max(0, tx - self.prev_net[2]) * 8 / secs
        self.prev_net = (now, rx, tx)
        mem = {}
        with open("/proc/meminfo") as f:
            for line in f:
                k, v = line.split(":")
                mem[k] = int(v.split()[0]) * 1024
        disk = os.statvfs("/")
        with open("/proc/uptime") as f:
            uptime = float(f.read().split()[0])
        return {
            "cpu": round(100 * (dt - di) / dt, 1) if dt else 0.0,
            "mem_total": mem.get("MemTotal", 0),
            "mem_used": mem.get("MemTotal", 0) - mem.get("MemAvailable", mem.get("MemFree", 0)),
            "disk_total": disk.f_blocks * disk.f_frsize,
            "disk_used": (disk.f_blocks - disk.f_bfree) * disk.f_frsize,
            "load1": round(os.getloadavg()[0], 2),
            "rx_bps": round(rx_bps), "tx_bps": round(tx_bps),
            "uptime": int(uptime), "active_peers": active_peers, "cores": os.cpu_count() or 1,
        }


# --------------------------------------------------------------------------- destination log

def parse_conntrack(line):
    """One `conntrack -E` event -> (event, proto, src, dst, dport, bytes_out, bytes_in) or None."""
    line = line.strip()
    if line.startswith("[NEW]"):
        event = "NEW"
    elif line.startswith("[DESTROY]"):
        event = "DESTROY"
    else:
        return None
    toks = line.split()
    proto = toks[1]
    orig, reply = {}, {}
    for t in toks[2:]:
        if "=" not in t:
            continue
        k, v = t.split("=", 1)
        (orig if k not in orig else reply)[k] = v
    if "src" not in orig or "dst" not in orig:
        return None
    return (event, proto, orig["src"], orig["dst"], int(orig.get("dport", 0)),
            int(orig.get("bytes", 0)), int(reply.get("bytes", 0)))


class FlowCollector:
    """Aggregates connections from VPN clients by (client, destination, port, protocol)."""
    MAX_KEYS = 20000
    install_attempted = False

    def __init__(self, subnet):
        self.subnet = subnet
        self.flows, self.dropped = {}, 0
        self.lock = threading.Lock()
        self.proc = None

    def start(self):
        if not shutil.which("conntrack") and not FlowCollector.install_attempted:
            FlowCollector.install_attempted = True
            # agents that self-updated predate the installer adding conntrack
            for pm, pkg in (("apt-get", "conntrack"), ("dnf", "conntrack-tools"), ("yum", "conntrack-tools"),
                            ("apk", "conntrack-tools")):
                if shutil.which(pm):
                    cmd = [pm, "add", pkg] if pm == "apk" else [pm, "install", "-y", pkg]
                    log(f"installing {pkg} for destination logging")
                    try:
                        subprocess.run(cmd, capture_output=True, timeout=120,
                                       env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"})
                    except subprocess.TimeoutExpired:
                        log(f"installing {pkg} timed out")
                    break
        if not shutil.which("conntrack"):
            log("destination logging is on but 'conntrack' couldn't be installed")
            return False
        subprocess.run(["sysctl", "-q", "-w", "net.netfilter.nf_conntrack_acct=1"], capture_output=True)
        self.proc = subprocess.Popen(["conntrack", "-E", "-e", "NEW,DESTROY", "-s", self.subnet],
                                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
        threading.Thread(target=self._read, daemon=True).start()
        log(f"logging destinations for {self.subnet}")
        return True

    def stop(self):
        if self.proc:
            self.proc.terminate()
            self.proc = None

    def _read(self):
        for line in self.proc.stdout:
            self.add(parse_conntrack(line))

    def add(self, ev):
        if not ev:
            return
        event, proto, src, dst, dport, b_out, b_in = ev
        key = (src, dst, dport, proto)
        now = int(time.time())
        with self.lock:
            f = self.flows.get(key)
            if f is None:
                if len(self.flows) >= self.MAX_KEYS:
                    self.dropped += 1
                    return
                f = self.flows[key] = {"src": src, "dst": dst, "dport": dport, "proto": proto,
                                       "first": now, "last": now, "conns": 0, "out": 0, "in": 0}
            f["last"] = now
            if event == "NEW":
                f["conns"] += 1
            else:
                f["out"] += b_out
                f["in"] += b_in

    def drain(self):
        with self.lock:
            flows, self.flows = list(self.flows.values()), {}
            if self.dropped:
                log(f"flow log: dropped {self.dropped} flows over the {self.MAX_KEYS} per-interval cap")
                self.dropped = 0
        return flows


def render_wg_conf(conf, desired):
    private_key = "<private key>"
    if not DRY_RUN:
        with open(KEY_FILE) as f:
            private_key = f.read().strip()
    wan = conf.get("wan_iface") or default_iface()
    iface = conf["interface"]
    subnet = desired.get("subnet") or desired["address"]
    # -I (insert) so the rules win over host firewalls (ufw, Docker) whose FORWARD policy is DROP.
    # MSS clamping keeps TCP working on paths with a smaller MTU (mobile, PPPoE).
    rules = [
        f"-t nat {{op}} POSTROUTING -s {subnet} -o {wan} -j MASQUERADE",
        f"{{op}} FORWARD -i {iface} -j ACCEPT",
        f"{{op}} FORWARD -o {iface} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
        f"-t mangle {{op}} FORWARD -o {iface} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
        f"-t mangle {{op}} FORWARD -i {iface} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
    ]
    # "|| true": wg-quick aborts the whole bring-up if any hook command fails (e.g. a kernel without the
    # TCPMSS module); a missing optional rule must never take the tunnel down. `doctor` reports gaps.
    up = "; ".join(f"iptables {r.format(op='-I')} || true" for r in rules)
    down = "; ".join(f"iptables {r.format(op='-D')} || true" for r in rules)
    lines = [
        "# Managed by vnvpn-agent - changes will be overwritten",
        "[Interface]",
        f"Address = {desired['address']}",
        f"ListenPort = {desired['listen_port']}",
        f"PrivateKey = {private_key}",
    ]
    if desired.get("mtu"):
        lines.append(f"MTU = {desired['mtu']}")
    lines += ["PostUp = sysctl -q -w net.ipv4.ip_forward=1 || true; " + up, f"PostDown = {down}", ""]
    for p in desired["peers"]:
        lines += ["[Peer]", f"PublicKey = {p['public_key']}", f"AllowedIPs = {p['allowed_ips']}", ""]
    return "\n".join(lines)


_APPLIED = os.path.join(CONF_DIR, "applied-interface.conf")


def _running_interface_section():
    try:
        with open(_APPLIED) as f:
            return f.read()
    except OSError:
        return None


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
    interface_section = rendered.split("[Peer]")[0]
    # Peers can be hot-swapped, but interface settings (MTU, NAT rules...) need the tunnel restarted.
    # Compare with what was last brought up, which also catches upgrades from older agents.
    if iface_up(iface) and _running_interface_section() != interface_section:
        log(f"interface settings changed; restarting {iface}")
        subprocess.run(["wg-quick", "down", iface], capture_output=True)  # uses the old file's PostDown
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
    with open(_APPLIED, "w") as f:
        f.write(interface_section)
    log(f"applied {len(desired['peers'])} peers")
    return rendered


_skip_update_until = 0.0


def self_update(conf, latest):
    """Download the panel's agent and exit; systemd restarts us on the new version."""
    try:
        req = urllib.request.Request(f"{conf['panel']}/agent/agent.py", headers={"User-Agent": f"vnvpn-agent/{VERSION}"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            code = resp.read()
        compile(code, "agent.py", "exec")  # never replace ourselves with something broken
        served = next((l.split('"')[1] for l in code.decode().splitlines() if l.startswith("VERSION = ")), "")
        if served != latest:  # e.g. a CDN cached an old agent.py: don't restart in a loop
            global _skip_update_until
            _skip_update_until = time.time() + 3600
            log(f"panel announced agent {latest} but served {served or '?'}; retrying in an hour")
            return
        path = os.path.abspath(__file__)
        with open(path + ".new", "wb") as f:
            f.write(code)
        os.chmod(path + ".new", 0o755)
        os.replace(path + ".new", path)
        log(f"updated agent {VERSION} -> {latest}; restarting")
        sys.exit(0)
    except (OSError, SyntaxError, ValueError) as e:
        log(f"self-update failed: {e}")


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
    try:
        metrics = Metrics(conf.get("wan_iface") or default_iface())
    except Exception as e:  # stats are optional; never let them stop check-ins
        log(f"server stats unavailable: {e}")
        metrics = None
    flows, unsent_flows, last_error, flow_failed = None, [], "", False
    while True:
        try:
            peers = peer_stats(conf["interface"])
            now = time.time()
            body = {"agent_version": VERSION, "peers": peers, "last_error": last_error}
            if metrics:
                try:
                    body["metrics"] = metrics.sample(sum(1 for p in peers if now - p["handshake"] < 180))
                except Exception as e:
                    log(f"server stats failed: {e}")
            if flows:
                unsent_flows = (unsent_flows + flows.drain())[-FlowCollector.MAX_KEYS:]
                body["flows"] = unsent_flows
            desired = http("POST", f"{conf['panel']}/api/agent/sync", body, secret=conf["secret"])
            unsent_flows = []
            interval, failures = int(desired.get("interval", 15)), 0
            try:
                last = apply(conf, desired, last)
                last_error = ""
            except subprocess.CalledProcessError as e:
                last_error = f"{' '.join(e.cmd)} failed: {(e.stderr or e.stdout or '').strip()[-400:]}"
                log(last_error)
            # destination logging is switched on/off from the panel
            if desired.get("flow_logging") and not flows and not flow_failed and not DRY_RUN:
                flows = FlowCollector(desired.get("subnet") or desired["address"])
                if not flows.start():
                    flows, flow_failed = None, True  # don't retry every check-in
            elif not desired.get("flow_logging") and flows:
                flows.stop()
                flows, unsent_flows = None, []
            latest = desired.get("agent_version")
            if latest and latest != VERSION and not args.once and not DRY_RUN and time.time() > _skip_update_until:
                if flows:
                    flows.stop()
                self_update(conf, latest)
        except urllib.error.HTTPError as e:
            failures += 1
            last_error = f"panel returned HTTP {e.code}: {e.read()[:200].decode(errors='replace')}"
            log(last_error)
            if e.code == 401:
                # re-running the installer re-enrolls and writes a new secret; pick it up without a restart
                try:
                    fresh = load_conf()
                    if fresh.get("secret") != conf.get("secret"):
                        conf = fresh
                        failures = 0
                        log("loaded new credentials from agent.json")
                except (OSError, ValueError):
                    pass
        except Exception as e:  # network blips etc. - keep the current tunnel config running
            failures += 1
            last_error = f"sync failed: {e}"
            log(last_error)
        if args.once:
            return 0 if failures == 0 else 1
        time.sleep(min(interval * (2 ** min(failures, 4)), 120) if failures else interval)


def doctor(_args):
    """Explain why clients might connect without traffic passing."""
    ok_all = True

    def check(ok, msg, fix=""):
        nonlocal ok_all
        ok_all &= bool(ok)
        print(("  \033[32m✓\033[0m " if ok else "  \033[31m✗\033[0m ") + msg + ("" if ok or not fix else f"\n      → {fix}"))

    def out(*cmd):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True)
        except FileNotFoundError:  # tool not installed (e.g. no ufw)
            return ""
        return r.stdout if r.returncode == 0 else ""

    conf = load_conf()
    iface = conf["interface"]
    print(f"vnvpn-agent {VERSION} doctor — node #{conf['node_id']}, panel {conf['panel']}\n")
    try:
        desired = http("POST", f"{conf['panel']}/api/agent/sync",
                       {"agent_version": VERSION, "peers": peer_stats(iface)}, secret=conf["secret"])
        check(True, f"panel reachable; {len(desired['peers'])} customer device(s) allowed on this server")
    except Exception as e:
        desired = {}
        check(False, f"panel not reachable: {e}", "check DNS/HTTPS to the panel, or re-run the installer")

    check(iface_up(iface), f"interface {iface} is up", f"journalctl -u vnvpn-agent -n 50; wg-quick up {iface}")
    show = out("wg", "show", iface)
    port = next((l.split(":")[1].strip() for l in show.splitlines() if "listening port" in l), "")
    check(port == str(conf["listen_port"]), f"WireGuard listening on UDP {port or '?'}")
    check(out("sysctl", "-n", "net.ipv4.ip_forward").strip() == "1", "IPv4 forwarding enabled",
          "sysctl -w net.ipv4.ip_forward=1")

    wan = conf.get("wan_iface") or default_iface()
    actual_wan = default_iface()
    check(wan == actual_wan, f"NAT goes out via {wan} (default route uses {actual_wan})",
          f"edit wan_iface in {CONF_FILE} to {actual_wan} and restart: systemctl restart vnvpn-agent")
    nat = out("iptables", "-t", "nat", "-S", "POSTROUTING")
    check("MASQUERADE" in nat and wan in nat, "NAT (MASQUERADE) rule present", "systemctl restart vnvpn-agent")
    fwd = out("iptables", "-S", "FORWARD")
    check(f"-i {iface} -j ACCEPT" in fwd, "forwarding from the tunnel allowed")
    policy = next((l for l in fwd.splitlines() if l.startswith("-P FORWARD")), "")
    if "DROP" in policy:
        print(f"    (FORWARD policy is DROP — fine as long as the rule above is present)")

    endpoint = desired.get("endpoint", "")
    try:
        my_ip = http("GET", f"{conf['panel']}/api/agent/whoami", ipv4_only=True)["ip"]
    except Exception:
        my_ip = ""
    if endpoint:
        check(":" not in endpoint, f"clients connect to {endpoint}:{conf['listen_port']}",
              f"IPv6 endpoints fail on most client networks; set the server's endpoint to {my_ip or 'its IPv4'} "
              "in Admin → Servers → Edit")
        if my_ip and endpoint != my_ip and not any(c.isalpha() for c in endpoint):
            check(False, f"registered endpoint {endpoint} differs from this server's public IPv4 {my_ip}",
                  "fix it in Admin → Servers → Edit")

    ufw = out("ufw", "status")
    if "Status: active" in ufw:
        check(str(conf["listen_port"]) in ufw, f"ufw allows UDP {conf['listen_port']}",
              f"ufw allow {conf['listen_port']}/udp")
    peers = peer_stats(iface)
    now = time.time()
    recent = [p for p in peers if p["handshake"] and now - p["handshake"] < 180]
    check(bool(recent) or not peers, f"{len(recent)} device(s) with a recent handshake",
          f"no client has completed a handshake: make sure UDP {conf['listen_port']} is open in your "
          "cloud provider's firewall / security group, and that the client's Endpoint is this server")
    print("\nAll checks passed." if ok_all else "\nSome checks failed — see the → hints above.")
    return 0 if ok_all else 1


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
    sub.add_parser("doctor")
    sub.add_parser("version")
    args = ap.parse_args()
    if args.cmd == "enroll":
        enroll(args)
    elif args.cmd == "run":
        sys.exit(run(args))
    elif args.cmd == "doctor":
        sys.exit(doctor(args))
    else:
        print(VERSION)


if __name__ == "__main__":
    main()
