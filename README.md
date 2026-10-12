# VN-VPN

A self-hosted, resellable WireGuard VPN suite:

- **Management panel** (FastAPI + SQLite, one container) — deploy on Coolify.
- **Node agent** — turn any Linux VPS into a VPN server with one command. It installs WireGuard, registers with the panel and keeps its peer list in sync every 15s.
- **Client portal** — customers sign up, get access on every server instantly, and switch locations by importing configs / scanning QR codes in the WireGuard app.
- **Provisioning API** — let your billing system (WHMCS, Stripe webhook, your website) create, suspend and delete users.

![Admin](docs/admin.png)
![Portal](docs/portal.png)

## How it works

```
 customer ── signs up ──▶ panel (Coolify) ◀── POST /api/agent/sync every 15s ── agent on VPS #1, #2, ...
    │                       │  users, servers, keys                              wg syncconf (no downtime)
    └── WireGuard app ──────┼──────────────── tunnel ─────────────────────────▶ any VPS
```

- Every user gets one WireGuard keypair and a fixed tunnel IP (`10.66.x.y`), valid on **all** servers. Switching server = activating another tunnel in the WireGuard app.
- Agents pull the list of active users; suspended/deleted users are dropped from every server within ~15 seconds.
- Each server's private key is generated on the server and never leaves it. Agents authenticate with a per-node secret issued at enrollment.
- Servers keep running with their last config if the panel goes down, and restore it on reboot.

## Deploy the panel on Coolify

1. In Coolify: **+ New Resource → Public/Private Repository**, pick this repo, build pack **Docker Compose** (`docker-compose.yml`).
2. Set environment variables:
   | Variable | Required | Notes |
   |---|---|---|
   | `ADMIN_EMAIL`, `ADMIN_PASSWORD` | yes | Bootstrap admin account (created/promoted on start). |
   | `PROVISION_API_KEY` | no | Enables `/api/v1/users` for billing integrations. |
   | `OPEN_SIGNUP` | no | `true` (default) shows the public sign-up page. |
   | `BRAND_NAME` | no | Shown in the UI and config file names. |
   | `VPN_SUBNET`, `CLIENT_DNS` | no | Defaults `10.66.0.0/16`, `1.1.1.1, 1.0.0.1`. |
   `SECRET_KEY` and `PUBLIC_URL` are filled automatically by Coolify's `SERVICE_PASSWORD_64_SECRET` / `SERVICE_FQDN_PANEL` magic variables.
3. Set the domain for the `panel` service (e.g. `https://vpn.example.com`) and deploy. Data lives in the `vnvpn-data` volume.

Without Coolify: `docker build -t vnvpn . && docker run -p 8000:8000 -v vnvpn:/data -e ADMIN_EMAIL=... -e ADMIN_PASSWORD=... -e PUBLIC_URL=https://vpn.example.com vnvpn`

## Add a VPN server

1. Admin → **Add a server** → **New token** (unlimited or N uses — one token can enroll a whole fleet).
2. On a fresh VPS (Debian/Ubuntu/RHEL/Alma/Rocky/Alpine), as root:
   ```bash
   curl -fsSL https://vpn.example.com/agent/install.sh | sudo bash -s -- --token <TOKEN> --name "Frankfurt 1" --location "Germany"
   ```
   Optional: `--endpoint vpn-de1.example.com` (otherwise the public IP is auto-detected), `--port 51820`.
3. The server appears as **online** in the panel and in every customer's portal. Open **UDP 51820** in your cloud provider's firewall/security group.

Logs: `journalctl -u vnvpn-agent -f` · Uninstall: `curl -fsSL https://vpn.example.com/agent/install.sh | sudo bash -s -- --uninstall`

## Provisioning API

Interactive docs at `/api/docs`. All calls need `X-API-Key: $PROVISION_API_KEY`.

```bash
# create (password optional — generated and returned if omitted)
curl -X POST https://vpn.example.com/api/v1/users -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
     -d '{"email":"customer@example.com"}'
curl -X POST https://vpn.example.com/api/v1/users/customer@example.com/suspend   -H "X-API-Key: $KEY"
curl -X POST https://vpn.example.com/api/v1/users/customer@example.com/unsuspend -H "X-API-Key: $KEY"
curl -X DELETE https://vpn.example.com/api/v1/users/customer@example.com         -H "X-API-Key: $KEY"
curl https://vpn.example.com/api/v1/servers   # public server list + online status
```

## Try it locally

```bash
pip install -r requirements.txt
DATABASE_PATH=./data/vnvpn.db ADMIN_EMAIL=admin@example.com ADMIN_PASSWORD=adminpass123 \
  PROVISION_API_KEY=testkey uvicorn app.main:app --reload
```

Open http://localhost:8000, log in as admin, create a token. You can simulate a node without WireGuard installed:

```bash
mkdir -p /tmp/node1
VNVPN_DIR=/tmp/node1 VNVPN_DRY_RUN=1 python3 agent/agent.py enroll --panel http://localhost:8000 --token <TOKEN> --name Test --location Lab
VNVPN_DIR=/tmp/node1 VNVPN_DRY_RUN=1 python3 agent/agent.py run      # prints the wg0.conf it would apply
```

Then sign up as a customer at `/signup` and download configs.

## Preliminary — known gaps before selling

- User WireGuard private keys are stored in the panel DB (needed to serve configs); encrypt at rest or move to client-side key generation.
- One device per user; no per-plan device limits, bandwidth caps or expiry yet.
- No email verification / password reset; no CSRF tokens (SameSite=Lax cookies only).
- IPv4 egress only (IPv6 is routed into the tunnel and dropped, which prevents leaks).
- Traffic counters reset when a server's interface restarts.
- SQLite + single process — fine for hundreds of users/dozens of nodes; move to Postgres for more.
