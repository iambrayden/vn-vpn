#!/usr/bin/env bash
# VN-VPN node installer. Usage (from the admin panel):
#   curl -fsSL __PANEL_URL__/agent/install.sh | sudo bash -s -- --token TOKEN [--name "Frankfurt 1"] [--location "Frankfurt"] [--country DE]
# Options: --country DE (flag shown to clients), --endpoint HOST (public IP/DNS clients use; auto-detected), --port 51820, --uninstall
set -euo pipefail

PANEL="__PANEL_URL__"
TOKEN="" NAME="" LOCATION="" COUNTRY="" ENDPOINT="" PORT="51820" UNINSTALL=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --token) TOKEN="$2"; shift 2 ;;
    --name) NAME="$2"; shift 2 ;;
    --location) LOCATION="$2"; shift 2 ;;
    --country) COUNTRY="$2"; shift 2 ;;
    --endpoint) ENDPOINT="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --panel) PANEL="$2"; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
done

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root (pipe into 'sudo bash')"

if [[ $UNINSTALL -eq 1 ]]; then
  systemctl disable --now vnvpn-agent 2>/dev/null || true
  wg-quick down wg0 2>/dev/null || true
  rm -rf /etc/vnvpn /opt/vnvpn /etc/systemd/system/vnvpn-agent.service /etc/wireguard/wg0.conf
  systemctl daemon-reload
  say "VN-VPN agent removed"; exit 0
fi

[[ -n "$TOKEN" ]] || die "--token is required (create one in the admin panel)"

say "Installing packages"
if command -v apt-get >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq wireguard-tools iptables python3 curl iproute2 >/dev/null
elif command -v dnf >/dev/null; then
  dnf install -y -q epel-release 2>/dev/null || true
  dnf install -y -q wireguard-tools iptables python3 curl iproute
elif command -v yum >/dev/null; then
  yum install -y -q epel-release 2>/dev/null || true
  yum install -y -q wireguard-tools iptables python3 curl iproute
elif command -v apk >/dev/null; then
  apk add -q wireguard-tools iptables python3 curl iproute2
else
  die "unsupported distro: install wireguard-tools, iptables and python3 manually"
fi

say "Enabling IP forwarding"
cat > /etc/sysctl.d/99-vnvpn.conf <<EOF
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
sysctl -q -p /etc/sysctl.d/99-vnvpn.conf || true

say "Installing agent"
install -d -m 700 /etc/vnvpn /etc/wireguard
install -d -m 755 /opt/vnvpn
curl -fsSL "$PANEL/agent/agent.py" -o /opt/vnvpn/agent.py
chmod 755 /opt/vnvpn/agent.py
if [[ ! -s /etc/vnvpn/private.key ]]; then
  (umask 077; wg genkey > /etc/vnvpn/private.key)
fi

say "Registering with $PANEL"
args=(enroll --panel "$PANEL" --token "$TOKEN" --port "$PORT")
[[ -n "$NAME" ]] && args+=(--name "$NAME")
[[ -n "$LOCATION" ]] && args+=(--location "$LOCATION")
[[ -n "$COUNTRY" ]] && args+=(--country "$COUNTRY")
[[ -n "$ENDPOINT" ]] && args+=(--endpoint "$ENDPOINT")
python3 /opt/vnvpn/agent.py "${args[@]}"

if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  ufw allow "$PORT"/udp >/dev/null
  ufw route allow in on wg0 >/dev/null 2>&1 || true
fi
if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
  firewall-cmd -q --permanent --add-port="$PORT"/udp
  firewall-cmd -q --permanent --add-masquerade
  firewall-cmd -q --reload
fi

cat > /etc/systemd/system/vnvpn-agent.service <<EOF
[Unit]
Description=VN-VPN node agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/vnvpn/agent.py run
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now vnvpn-agent >/dev/null

sleep 3
if systemctl is-active -q vnvpn-agent; then
  say "Done! This server should now show as online in the panel."
  say "Logs: journalctl -u vnvpn-agent -f"
else
  die "agent failed to start; check: journalctl -u vnvpn-agent -n 50"
fi
