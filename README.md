# Secure Ubuntu PaaS

Turn a fresh Ubuntu VPS into a **production-hardened self-hosting platform** in ~15 minutes.

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-24.04%20LTS-E95420?logo=ubuntu)](https://ubuntu.com/)
[![Coolify](https://img.shields.io/badge/Coolify-v4+-purple?logo=docker)](https://coolify.io/)
[![dFlow](https://img.shields.io/badge/dFlow-Dokku%200.35.x-1f8acb)](https://github.com/dflow-sh/dflow)
[![Shellcheck](https://img.shields.io/badge/ShellCheck-passed-brightgreen)](https://www.shellcheck.net/)

---

## What this is

You want to **self-host apps** on a server you control — a web app, a database, a file server, whatever. You rent a Linux VPS from any cloud provider for ~$5–$20/month and you own the machine.

The problem is doing this **safely**. A fresh server is wide open: root login over SSH, no firewall, no audit logging. And most self-hosting platforms expose their admin dashboard to the public internet by default.

This project gives you two things:

1. **A hardened server** — 15 security controls applied automatically (SSH locked down, firewall configured, audit logging, auto-updates, and more)
2. **A self-hosting PaaS installed and secured** — pick the platform you want with `--paas`:
   - **Coolify** *(default)* — a Heroku-like web UI; admin dashboard reachable only over Tailscale, apps published through Cloudflare
   - **dFlow** — a Dokku-based PaaS where the worker is owned by a remote dFlow controller; this project hardens the worker, locks the controller's access path, and verifies the dFlow contract (Dokku 0.35.x, Beszel agent, Restic backups)

**Before:** a fresh VPS with root SSH, no firewall, and no apps running

**After:**
- Coolify dashboard at `https://your-domain.com` — accessible only over Tailscale VPN
- Your deployed apps publicly accessible at `appname.your-domain.com` via Cloudflare
- SSH to the server only works via Tailscale (no public SSH attack surface)
- Hardened kernel, audit logging, fail2ban, and automatic security updates

---

## The tools this uses

You don't need to be an expert in these, but knowing what each one does helps:

| Tool | What it does in this setup |
|------|---------------------------|
| **[Coolify](https://coolify.io/)** *(`--paas coolify`, default)* | A web UI for deploying apps, databases, and services — like a self-hosted Heroku. This is what you'll use day-to-day to manage what runs on your server. |
| **[dFlow](https://github.com/dflow-sh/dflow)** *(`--paas dflow`)* | An open-source Dokku-based PaaS. The worker is "attached" to a remote dFlow controller which installs Docker, Dokku 0.35.x, Beszel agent, and Restic backups; this project hardens the substrate and gates the controller's auth path. |
| **[Tailscale](https://tailscale.com/)** | A VPN that connects your laptop directly to your server over an encrypted private network. With Coolify, the admin dashboard and SSH live here. With dFlow, this is one of two supported paths for the controller to reach the worker. |
| **[Cloudflare](https://cloudflare.com/)** *(Coolify only)* | Sits in front of your server for public traffic. Handles HTTPS certificates, DDoS protection, and (in the default mode) routes traffic through an outbound tunnel so your server never needs to open inbound ports 80/443. dFlow uses Traefik on the worker instead. |

---

## How it works

### Coolify mode (`--paas coolify`, default)

```
Your laptop
     │
     │  ssh (Tailscale VPN only, 100.x.x.x)
     ▼
 ┌────────────────────────────────────┐
 │           Your VPS                 │
 │                                    │
 │  Coolify (admin dashboard :8000)   │◄── only reachable via Tailscale
 │  Traefik (reverse proxy)           │
 │  Your apps (Docker containers)     │
 │                                    │
 │  cloudflared ──────────────────────┼──► Cloudflare edge ──► public internet
 │  (outbound tunnel, default mode)   │         ↑
 └────────────────────────────────────┘    https://appname.your-domain.com
                                            (your users visit this)
```

**The key insight:** the VPS never opens inbound ports 80 or 443 to the internet (in the default tunnel mode). Instead, a lightweight `cloudflared` process on the server dials *out* to Cloudflare. Traffic from your users flows into Cloudflare's edge and back through that tunnel to your apps. Your server's public IP is never directly reachable for web traffic.

Admin access (Coolify dashboard, SSH) goes a different route entirely: only through the Tailscale private network.

### dFlow mode (`--paas dflow`)

```
                                       ┌──────────────────────┐
                                       │  dFlow controller    │
                                       │  (you run this       │
                                       │  elsewhere, or use   │
                                       │  app.dflow.sh)       │
                                       └──────────┬───────────┘
                                                  │ "attach worker"
                  ┌───────────────────────────────┼──────────────────────┐
                  │ auth-mode=ssh                 │ auth-mode=tailscale  │
                  │ root SSH from controller IP   │ Tailscale SSH path   │
                  ▼                               ▼                      │
 ┌──────────────────────────────────────────────────────────────────────┐
 │                            Your VPS                                  │
 │                                                                      │
 │  Hardening substrate: UFW, SSH, kernel, audit, fail2ban, swap        │
 │  Docker daemon (hardened)                                            │
 │                                                                      │
 │  Installed by the dFlow controller during attach:                    │
 │    • Dokku 0.35.x + Railpack default builder                         │
 │    • Pre-deploy resource hook                                        │
 │    • Beszel agent (TCP 45876, controller CIDR only)                  │
 │    • Restic backups                                                  │
 │    • Traefik (app routing — managed by Dokku)                        │
 │                                                                      │
 │  Your apps (deployed via dFlow UI / `git push dokku`)                │
 └──────────────────────────────────────────────────────────────────────┘
```

**Division of responsibilities.** The hardening overlay guarantees the *substrate* — UFW, SSH, kernel, swap, audit, fail2ban — and locks down which path the controller is allowed to use. Everything inside dFlow's contract (Docker, Dokku, plugins, Beszel agent, Restic backups, Traefik) is owned by the dFlow controller and installed during the first attach. Phases 3 and 4 in this project are intentional no-ops for dFlow; phase 5 only verifies the substrate and surfaces dFlow-specific failures from `base/validate.sh`.

**Two supported controller auth paths:**
- `--dflow-auth-mode ssh` *(default)* — controller's SSH pubkey is installed for `root`. A `Match Address` block in `/etc/ssh/sshd_config.d/16-dflow-root-match.conf` permits root login *only* from the configured `--dflow-control-cidr`. If the CIDR is omitted, the drop-in is not installed and root SSH stays restricted to localhost — defense-in-depth: the controller cannot attach until you opt in by supplying its CIDR.
- `--dflow-auth-mode tailscale` — Tailscale SSH brokers the session. The base hardening's localhost-only root rule stays in place; no pubkey or `Match Address` block is installed.

---

## Deployment phases

The automation runs in 5 sequential phases, each with a verification gate before the next one starts:

```
                              Coolify (--paas coolify)        dFlow (--paas dflow)
Phase 1: Harden               same                            same
          ↓ gate              all 15 controls pass            all 15 controls pass
Phase 2: Tailscale switch     same                            same
          ↓ gate              Tailscale reachable             Tailscale reachable
Phase 3: PaaS install         install Docker + Coolify        no-op (controller installs)
          ↓ gate              Coolify dashboard on Tailscale  substrate ready
Phase 4: Routing              Cloudflare DNS + tunnel         no-op (Traefik via dFlow)
          ↓ gate              tunnel established              n/a
Phase 5: Verify               dashboard HTTPS, websockets     dFlow contract checks
                                                              (Dokku 0.35.x, Beszel,
                                                              backups, SSH path)
```

If any gate fails, the script stops and tells you exactly what went wrong and how to resume.

---

## Prerequisites

You need these before running anything:

| What | Coolify | dFlow | How to get it |
|------|:-:|:-:|---------------|
| **Ubuntu 24.04 VPS** (2 GB RAM, 40 GB disk min) | required | required | Any provider: Hetzner, DigitalOcean, Linode, Vultr, etc. |
| **A domain on Cloudflare** | required | not used | [Move your domain to Cloudflare](https://developers.cloudflare.com/dns/zone-setups/) (free tier works) |
| **Tailscale account + auth key** | required | required for `auth-mode=tailscale`; recommended even with `ssh` for admin SSH | [tailscale.com](https://tailscale.com); generate keys at [admin/settings/keys](https://login.tailscale.com/admin/settings/keys) (tick "Reusable" and "Ephemeral") |
| **Cloudflare API token** | required | not used | [Create one](https://dash.cloudflare.com/profile/api-tokens) with: `Zone:Read`, `Zone:DNS:Edit`, `Account:Cloudflare Tunnel:Edit` |
| **dFlow controller pubkey** *(`--dflow-auth-mode ssh`)* | n/a | required | Generated on the dFlow controller; copy `~/.ssh/id_ed25519.pub` (or equivalent) to a file on your laptop |
| **dFlow controller CIDR** | n/a | recommended | Public IPv4 (or `/32`) of the dFlow controller — restricts root SSH `Match Address` |
| **SSH public key** (your own, not the controller's) | required | required | Run `ssh-keygen -t ed25519` if you don't have one |
| **Bash 4+** | required | required | macOS ships Bash 3.2 which is too old. Install: `brew install bash` |
| **sshpass** *(`deploy.sh` only)* | required | required | `brew install hudochenkov/sshpass/sshpass` |

> **Domain tip (Coolify):** You don't need to move your whole domain — just ensure the zone is managed by Cloudflare. A subdomain delegation also works.

> **dFlow note:** the dFlow controller (the thing this worker attaches to) is hosted by you separately, or you can use the managed app at `app.dflow.sh`. This project only hardens and prepares the worker; the controller is out of scope.

---

## Quick start

### Option A: From your laptop, Coolify (fully automated)

Run `deploy.sh` from your local machine. It SSHes into the VPS, runs everything, and hands you back a fully configured server:

```bash
git clone https://github.com/jroth1111/secure-ubuntu-paas.git
cd secure-ubuntu-paas

/opt/homebrew/bin/bash deploy.sh \
  --paas coolify \
  --server-ip <your-vps-ip> \
  --root-pass-file /path/to/root.pass \
  --admin-user myuser \
  --pubkey-file ~/.ssh/id_ed25519.pub \
  --tailscale-auth-key tskey-auth-... \
  --server-timezone UTC \
  --domain myapp.example.com \
  --cf-api-token-file /path/to/cf.token \
  --yes
```

`root.pass` is a file containing just your VPS root password (one line, no trailing newline). Never pass passwords as shell arguments.

> `--paas coolify` is the default; you can omit it.

### Option B: From your laptop, dFlow worker

Hardens the VPS, opens the dFlow controller's auth path, and stops. The controller then attaches and installs Dokku, Beszel, Restic, and Traefik on the worker:

```bash
/opt/homebrew/bin/bash deploy.sh \
  --paas dflow \
  --server-ip <your-vps-ip> \
  --root-pass-file /path/to/root.pass \
  --admin-user dflowadmin \
  --pubkey-file ~/.ssh/id_ed25519.pub \
  --tailscale-auth-key tskey-auth-... \
  --server-timezone UTC \
  --dflow-auth-mode ssh \
  --dflow-control-pubkey-file /path/to/dflow-controller.pub \
  --dflow-control-cidr 203.0.113.42/32 \
  --yes
```

After `deploy.sh` finishes, register the worker in your dFlow controller (UI or CLI). The controller will SSH in as root from `203.0.113.42` and run its own onboarding.

For the Tailscale-only auth path, swap the dFlow flags for `--dflow-auth-mode tailscale` (no pubkey/CIDR needed).

### Option C: Already on the server

If you've already SSH'd into the VPS, use `setup.sh` instead — same flag surface, runs locally:

```bash
# Coolify variant
./setup.sh \
  --paas coolify \
  --admin-user myuser \
  --pubkey-file ~/.ssh/id_ed25519.pub \
  --tailscale-auth-key tskey-auth-... \
  --server-timezone UTC \
  --domain myapp.example.com \
  --cf-api-token-file /path/to/cf.token \
  --yes

# dFlow variant
./setup.sh \
  --paas dflow \
  --admin-user dflowadmin \
  --pubkey-file ~/.ssh/id_ed25519.pub \
  --tailscale-auth-key tskey-auth-... \
  --server-timezone UTC \
  --dflow-auth-mode ssh \
  --dflow-control-pubkey-file /path/to/dflow-controller.pub \
  --dflow-control-cidr 203.0.113.42/32 \
  --yes
```

### Option D: Hardening only (no PaaS)

To just harden a server without installing or preparing for any PaaS:

```bash
sudo ./base/bootstrap.sh \
  --admin-user myuser \
  --admin-pubkey "ssh-ed25519 AAAA... user@host" \
  --install-tailscale \
  --tailscale-auth-key tskey-auth-...
```

---

## After deployment

### Coolify

Three manual steps in the Cloudflare and Coolify web UIs unlock automatic HTTPS for all your apps:

1. **Cloudflare dashboard → SSL/TLS → Overview** — set mode to **Full** (not Flexible, not Full Strict)
2. **Coolify → Servers → your server → Wildcard Domain** — set to your zone root, e.g. `example.com`
3. **Coolify → each resource → domain** — use `http://` not `https://` (Traefik handles TLS internally)

After this, every app you deploy in Coolify automatically gets:
- A subdomain (`appname.example.com`)
- A wildcard DNS record
- HTTPS from Cloudflare's Universal SSL
- Routing through the tunnel to the right container

No per-app DNS or certificate work needed.

### dFlow

After hardening completes, finish onboarding from the dFlow controller:

1. **Add the worker** in the dFlow controller (UI or CLI) using the public IP and the admin user you configured.
2. **The controller attaches over the auth path you chose.** With `auth-mode=ssh`, that's root SSH from the controller's IP/CIDR (gated by the `Match Address` block this project installed). With `auth-mode=tailscale`, the controller reaches the worker via the tailnet.
3. **First attach installs the dFlow contract** on the worker: Docker, Dokku 0.35.x, Railpack default builder, the pre-deploy resource hook, the Beszel agent (TCP 45876, restricted to your `--dflow-control-cidr`), Restic backups, and Traefik.
4. **Re-run the validator** any time to confirm the contract is intact:
   ```bash
   sudo ./base/validate.sh --json
   ```
   The dFlow checks (`dflow_dokku_check`, `dflow_beszel_check`, `dflow_backups_check`, `dflow_predeploy_hook_check`, `dflow_ssh_path_check`) report PASS once the controller has finished its installation. Before first attach they emit `INFO` (dependency not yet installed by controller), which is expected.

You then deploy apps through the dFlow UI or via `git push dokku <app> main` from your laptop — same as any Dokku worker.

---

## Deployment modes

| | Tunnel mode (default) | Standard mode |
|---|---|---|
| **Select with** | `--mode tunnel` | `--mode standard` |
| **Inbound ports open** | None | 80, 443 |
| **How traffic reaches apps** | Server dials out to Cloudflare | Cloudflare proxies to origin IP |
| **Server IP exposure** | Never directly reachable | Hidden behind Cloudflare (still exposed if proxying bypassed) |
| **Best for** | Maximum security, typical web apps | Apps with large uploads, streaming, or webhook-heavy workloads |

**Tunnel mode caveats** — read these before choosing:

- **100 MB upload limit** — Cloudflare's free/pro plans cap request bodies. Apps with large file uploads (Nextcloud, Immich, Gitea LFS) need standard mode or chunked upload support.
- **Nested subdomains** — Universal SSL covers `*.example.com` but not `*.app.example.com`. Keep subdomains single-level.
- **Video streaming** — Heavy streaming (Jellyfin, Plex) may violate Cloudflare's CDN terms of service. Use standard mode with DNS-only for those services.

If any of these apply, use `--mode standard`.

---

## What the hardening actually does

`base/bootstrap.sh` applies 15 security controls. Full technical detail in [HARDENING_PROCEDURE.md](HARDENING_PROCEDURE.md).

| # | Control | What it does |
|---|---------|--------------|
| 1 | **Preflight** | Validates OS version, checks SSH session safety, detects network interfaces |
| 2 | **NTP + timezone** | Configures time sync and your chosen timezone |
| 3 | **Swap** | Creates a swap file (default 2 GB) for OOM protection |
| 4 | **Service cleanup** | Disables unnecessary network services (rpcbind, avahi-daemon, cups) |
| 5 | **Login banner** | Adds an authorized-access-only warning to the login prompt |
| 6 | **SSH hardening** | Key-only auth, modern ciphers only, root login disabled, timeout set |
| 7 | **Auditd** | System call auditing — tracks identity changes, sudo use, Docker socket access |
| 8 | **Kernel hardening** | SYN flood protection, ASLR, BBR congestion control, ICMP hardening, ptrace restrictions |
| 9 | **UFW firewall** | Default-deny inbound; allow Tailscale CIDR, SSH, and (in standard mode) 80/443 |
| 10 | **Docker daemon** | Hardens Docker's own configuration: log limits, live restore, private IPC, resource limits |
| 11 | **DOCKER-USER rules** | iptables rules that enforce your UFW policy for Docker container traffic |
| 12 | **Fail2ban** | Bans IPs with repeated SSH failures via UFW |
| 13 | **Journald** | Enables persistent logs with configurable retention |
| 14 | **Auto-updates** | Unattended security patches with optional scheduled reboot |
| 15 | **Post-checks** | Runs `base/validate.sh` and emits a JSON report |

---

## Verifying the deployment

After hardening, you can run the validator at any time to check the server's security state:

```bash
sudo ./base/validate.sh           # human-readable output
sudo ./base/validate.sh --json    # machine-readable JSON (used by deploy.sh gates)
```

The validator checks all 15 controls and reports PASS / FAIL / INFO per control. `deploy.sh` runs this automatically at each gate and stops if anything is failing.

---

## Troubleshooting

<details>
<summary>SSH connection refused after hardening</summary>

**Cause:** You're connecting to the public IP. After hardening, SSH only accepts connections from the Tailscale network.

**Fix:** Find your server's Tailscale IP (printed in the script output, or run `tailscale ip -4` on the server) and connect via that:
```bash
ssh myuser@100.x.x.x
```
Also ensure Tailscale is running on your laptop (`tailscale status`).

</details>

<details>
<summary>Coolify dashboard not accessible</summary>

**Cause:** Management ports are bound to the `tailscale0` interface only.

**Fix:**
1. Confirm Tailscale is connected on your laptop: `tailscale status`
2. Access the dashboard at `https://your-domain.com` (via Tailscale), not via public IP
3. Fallback (if DNS isn't set up yet): `http://100.x.x.x:8000`

</details>

<details>
<summary>Cloudflare tunnel not working</summary>

**Cause:** API token is missing permissions, or the tunnel service isn't running.

**Fix:**
- Token must have: `Zone:Read`, `Zone:DNS:Edit`, `Account:Cloudflare Tunnel:Edit`
- Check tunnel service: `sudo systemctl status cloudflared`
- Check Cloudflare dashboard → Zero Trust → Networks → Tunnels to confirm the tunnel shows as "Healthy"

</details>

<details>
<summary>"Cannot connect to real-time service" in Coolify UI</summary>

**Cause:** Coolify's WebSocket connection (used for live log streaming) isn't routing correctly through the private Traefik setup.

**Fix:**
1. In Coolify's `.env`: confirm `PUSHER_HOST=ws.your-domain.com`, `PUSHER_PORT=443`, `PUSHER_SCHEME=https`
2. Confirm `/etc/cloudflared/config.yml` does **not** route `localhost:6001` or `localhost:6002` (those go through private Traefik, not the tunnel)
3. Confirm DNS has `A` records for `your-domain.com` and `ws.your-domain.com` pointing to the server's Tailscale IP (`100.x.x.x`) with Cloudflare proxy **disabled** (DNS-only, grey cloud)

</details>

<details>
<summary>Validation failures from base/validate.sh</summary>

Common fixes:
- **UFW inactive:** `sudo ufw enable`
- **Auditd not running:** `sudo systemctl enable --now auditd`
- **Docker not installed:** `base/bootstrap.sh` alone doesn't install Docker; for Coolify it's installed in Phase 3, for dFlow it's installed by the dFlow controller during attach

</details>

<details>
<summary>dFlow: validator shows INFO for dokku/beszel/backups</summary>

**Cause:** the dFlow controller hasn't attached yet, so Dokku, the Beszel agent, and Restic backups aren't installed. The checks emit `INFO` (not `FAIL`) and the gate still passes.

**Fix:** complete the controller's attach flow. After it finishes, re-run `sudo ./base/validate.sh` — the same checks should flip to `PASS`. If they stay `INFO` after attach, check the controller's onboarding logs.

</details>

<details>
<summary>dFlow: controller can't reach the worker</summary>

**`auth-mode=ssh`:**
- Confirm the controller's source IP is in `--dflow-control-cidr` — the SSH `Match Address` block is the gate.
- Check the worker: `sudo sshd -T -C addr=<controller-ip>,user=root,host=worker,laddr=<worker-ip> | grep permitrootlogin` should return `prohibit-password`.
- Confirm the controller pubkey is in `/root/.ssh/authorized_keys` (or whatever path the dFlow ssh module installed).

**`auth-mode=tailscale`:**
- Confirm both worker and controller are tagged correctly in your Tailscale ACLs.
- On the worker: `sudo tailscale status` should show the controller node.
- Tailscale SSH must be enabled by the worker; this project's `tailscale_ssh.sh` module handles that.
- For secondary dFlow tailnet diagnostics, inspect `systemctl cat tailscaled-dfi.service` and use the
  unit's actual `--socket` value. Managed workers use `/run/tailscale-dfi.sock`; do not assume
  `/run/tailscale-dfi/tailscaled.sock`.

</details>

<details>
<summary>Live audit artifacts and secrets</summary>

Do not write raw app environment output into audit artifacts. Commands like `dokku config:show`,
`docker inspect`, `env`, and `printenv` can include Restic, S3, Beszel, Cloudflare, or app secrets.
For audits, record key names, value presence, public-key fingerprints, service state, listeners,
and validation JSON. If a server lacks `/root/base/validate.sh`, resume with `deploy.sh --ts-ip` to
resync companions before treating gate output as authoritative.

</details>

---

## Reference

<details>
<summary>📋 deploy.sh / setup.sh flags</summary>

**Common (both PaaS):**

| Flag | Default | Description |
|------|---------|-------------|
| `--paas <coolify\|dflow>` | `coolify` | Which PaaS to install/prepare on the worker |
| `--server-ip <ip>` | *(required for deploy.sh)* | VPS public IP |
| `--root-pass-file <path>` | *(required for deploy.sh)* | File containing root password |
| `--admin-user <name>` | `coolifyadmin` (`dflowadmin` for dFlow) | Admin username to create |
| `--pubkey-file <path>` | `~/.ssh/id_ed25519.pub` | SSH public key file |
| `--tailscale-auth-key <key>` | *(required)* | Tailscale auth key |
| `--server-timezone <IANA>` | prompted / `UTC` | Server timezone |
| `--swap-size <size>` | `2G` | Swap file size |
| `--tailscale-direct-wan` | `false` | Open WAN UDP 41641 for direct Tailscale paths |
| `--ts-ip <ip>` | — | Skip Phase 1 and resume from known Tailscale IP |
| `--preflight-only` | `false` | Run pre-flight checks only (no changes) |
| `--yes` | `false` | Skip confirmation prompts |

**Coolify-only (`--paas coolify`):**

| Flag | Default | Description |
|------|---------|-------------|
| `--domain <domain>` | *(required)* | Your domain or subdomain |
| `--cf-api-token-file <path>` | *(required)* | File containing Cloudflare API token |
| `--mode <tunnel\|standard>` | `tunnel` | Deployment mode |
| `--app-domain-mode <apex\|vps>` | `apex` | `apex` = `appname.zone`, `vps` = `appname.domain` |

**dFlow-only (`--paas dflow`):**

| Flag | Default | Description |
|------|---------|-------------|
| `--dflow-auth-mode <ssh\|tailscale>` | `ssh` | How the dFlow controller reaches the worker |
| `--dflow-control-pubkey-file <path>` | required when `auth-mode=ssh` | dFlow controller's SSH public key file |
| `--dflow-control-cidr <ipv4-cidr>` | empty *(controller cannot attach over WAN)* | Permit root SSH from this CIDR via a `Match Address` drop-in. Required to give the controller a path under `auth-mode=ssh`. |
| `--dflow-beszel-port <port>` | `45876` | TCP port for Beszel agent (controller-only ingress) |

</details>

<details>
<summary>📋 base/bootstrap.sh flags</summary>

| Flag | Default | Description |
|------|---------|-------------|
| `--admin-user <name>` | *(required)* | Admin username to create |
| `--admin-pubkey "<key>"` | *(required)* | SSH public key string |
| `--tunnel-mode` | `false` | Skip WAN 80/443 (for Cloudflare Tunnel use) |
| `--swap-size <size>` | `2G` | Swap size (`0` to skip) |
| `--timezone <IANA>` | `UTC` | System timezone |
| `--ssh-port <port>` | `22` | SSH port |
| `--install-tailscale` | `false` | Install and enroll Tailscale |
| `--tailscale-auth-key <key>` | — | Auth key (with `--install-tailscale`) |
| `--bind-dashboard-to-tailscale` | `false` | Watchdog to re-enforce Tailscale-only UFW rules for ports 8000/6001/6002 |
| `--enable-auto-reboot <bool>` | `false` | Auto-reboot after security updates |
| `--auto-reboot-time <HH:MM>` | `03:30` | Reboot window |
| `--update-profile <name>` | `security-only` | `security-only` or `balanced` |
| `--journal-retention <span>` | `3month` | Journald retention |
| `--strict-docker-ssh-cidrs` | `true` | Restrict UFW bridge allowlist to discovered Docker bridge CIDRs |
| `--env-file <path>` | — | Load options from a `KEY=VALUE` file |
| `--dry-run` | `false` | Preview changes without applying |
| `--force` | `false` | Override safety gates |

All flags can also be set via environment variables (e.g. `ADMIN_USER`, `TUNNEL_MODE`). CLI flags override env-file values.

**Env file example:**
```bash
cat > /etc/server-hardening.env << 'EOF'
ADMIN_USER=myuser
ADMIN_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... user@host"
TUNNEL_MODE=true
SWAP_SIZE=4G
TIMEZONE=UTC
ENABLE_AUTO_REBOOT=false
EOF
chmod 0600 /etc/server-hardening.env

sudo ./base/bootstrap.sh --env-file /etc/server-hardening.env
```

</details>

---

## Project layout

```
secure-ubuntu-paas/
├── deploy.sh                       # Run from your laptop — SSHes in and runs everything
├── setup.sh                        # Run on the server directly
├── base/
│   ├── bootstrap.sh                # Security hardening (15 controls)
│   ├── validate.sh                 # Post-hardening verifier (outputs JSON)
│   ├── modules/                    # Hardening modules: ssh, ufw, auditd, docker, ...
│   └── checks/                     # Validation checks (one file per control)
├── overlays/
│   ├── coolify/
│   │   ├── coolify-common.sh       # Shared phase orchestration
│   │   ├── modules/                # Coolify install, reconcile, TLS, binding
│   │   └── checks/                 # Coolify-specific validation
│   ├── dflow/
│   │   ├── dflow-common.sh         # dFlow phase orchestration (phase3/4 no-op, phase5 verifies)
│   │   ├── modules/                # ufw, ssh_access, ssh_match_dropin, tailscale_ssh, predeploy_hook
│   │   └── checks/                 # dflow_dokku, dflow_beszel, dflow_backups, dflow_predeploy_hook, dflow_ssh_path
│   └── docker-host/
│       ├── modules/                # Docker daemon config, CIDR sync
│       └── checks/                 # Docker-specific validation
├── lib/
│   ├── common.sh                   # Shared utilities (logging, die, is_true)
│   ├── tailscale.sh                # Tailscale install and detect helpers
│   └── overlay-loader.sh           # Overlay dependency resolution
├── docs/
│   ├── DEPLOYMENT_RUNBOOK.md       # Manual step-by-step guide
│   └── HARDENING_PROCEDURE.md      # Technical detail for all 15 controls
└── tests/                          # BATS test suite
    ├── base/                       # Bootstrap and validate tests
    ├── overlays/coolify/           # Coolify overlay tests
    ├── overlays/dflow/             # dFlow overlay tests (phase dispatch, input collection)
    └── orchestrator/               # Deploy/setup orchestrator tests
```

---

## Contributing

```bash
git clone https://github.com/jroth1111/secure-ubuntu-paas.git
cd secure-ubuntu-paas
make setup-bats
make test-unit-local   # fast, no Docker needed
make test-ci-pr        # full suite (requires Docker)
```

Please run `make test-ci-pr` before opening a pull request. All scripts must pass `shellcheck`.

---

## Security

To report a vulnerability, please use [GitHub Security Advisories](https://github.com/jroth1111/secure-ubuntu-paas/security/advisories/new) rather than a public issue. You should receive a response within 48 hours.

---

## License

[MIT](LICENSE)
