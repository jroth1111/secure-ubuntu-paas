# AGENTS.md — Agent Governance + Deployment Operator Spec

This is the single canonical agent guide for this repository.
`AGENTS_DEPLOY.md` has been retired; keep deployment governance and runbook content here.

---

## 1. Intent → Atomic Tasks

Decompose user requests into tasks.

---

## 2. State Transitions

Work follows claim → execute → verify → close. Project-specific additions:

- **Never start a deployment task** without first verifying operator machine prerequisites.
- **Never start phase 3** (Docker+Coolify) unless Gate C (`base/validate.sh --json --gate-c`) shows `"fail":0`.
- **Never close a deployment task** without recording gate output in task notes.
- **Never close a script-change task** without `bash -n <script>` passing and result recorded.

---

## 3. First-Principles LLM Model

An LLM can run this project safely only if it tracks this operator model:

1. **Project goal**: provision and harden Ubuntu, then prepare it for one of two PaaS surfaces (Coolify or dFlow) selected with `--paas`.
2. **Execution surfaces**: `deploy.sh` (operator laptop), `setup.sh` (server-local).
3. **External systems**: VPS provider, Tailscale, Docker, plus PaaS-specific systems:
   - **Coolify** path: Cloudflare API, Coolify itself.
   - **dFlow** path: the remote dFlow controller (operator-supplied or `app.dflow.sh`); Cloudflare is unused.
4. **Prerequisites**: operator machine has Tailscale connected, SSH keypair, and required CLI tools.
5. **Required inputs/secrets** (PaaS-conditional):
   - Common: server IP, root auth (laptop flow), Tailscale auth key, server timezone.
   - Coolify only: domain, Cloudflare token(s).
   - dFlow only: no additional credentials — the controller attaches via Tailscale SSH.
6. **Mode decision**:
   - Coolify: `tunnel` vs `standard` changes exposure, DNS, and verification behavior.
   - dFlow: `--mode` is not consumed. The controller attaches exclusively via Tailscale SSH; there is no ssh/tailscale auth-mode choice.
7. **State machine**: phases `[0/5]..[5/5]` with hard gates (A-F); do not skip failed gates. For `--paas dflow`, phases 3 and 4 are intentional no-ops (the dFlow controller installs Docker/Dokku/Beszel/Restic/Traefik on first attach); phase 5 runs the validator with dFlow-specific checks.
8. **Machine contracts**:
   - `base/bootstrap.sh` emits `HARDEN_RESULT_TAILSCALE_IP=<ip>` on stdout.
   - `base/validate.sh --json` emits `{pass,fail,info,checks}` (PaaS-aware: branches on `PAAS=` from state).
   - `PAAS` env var (default `coolify`) is propagated through `deploy.env` into `bootstrap.sh` and `validate.sh` via the bootstrap key allowlist.
9. **Security invariants**: UFW default-deny, strict SSH posture, DOCKER-USER WAN drop semantics (Coolify only — dFlow defers Docker config to controller, but the substrate's UFW posture stands), fail2ban posture. dFlow adds: Tailscale SSH exclusively for controller attach; no root SSH pubkey or CIDR rules managed by this project.
10. **Idempotency/resume**: reruns must be safe; `--ts-ip` resumes from phase 2; companion scripts re-sync in phase 2.
11. **Destructive-op discipline**: deploying is high impact regardless of PaaS. Cloudflare mutations apply only to `--paas coolify`. State command + effect and require explicit confirmation.
12. **Recovery discipline**: separate real misconfiguration from validation false positives before editing checks. For dFlow, INFO results from `dflow_dokku_check`/`dflow_beszel_check`/`dflow_backups_check` before the controller has attached are expected, not failures.
13. **Success criteria**: final validation must report `"fail":0` and gate evidence must be captured in notes.
14. **Change control**: shell scripts are frozen unless explicitly authorized (exception: confirmed Gate C false positive fix).

---

## 4. Deployment Collection Sequence (LLM)

Use this sequence when driving deployment with a user.

### Step 1: Verify Operator Machine First (no secret collection yet)

Run locally:

```bash
tailscale status
ls ~/.ssh/id_ed25519.pub
command -v ssh && command -v scp && command -v curl && command -v jq && command -v sshpass && command -v ssh-keygen && command -v openssl
```

If any prerequisite fails, fix that first.

### Step 2: Collect Non-Secret Deployment Shape

Always ask first:

- **PaaS choice** (`--paas`): `coolify` (default) or `dflow`.

Then, branched by PaaS:

| | Coolify | dFlow |
|---|---|---|
| Domain | Cloudflare-managed (required) | not used |
| Server public IPv4 | required | required |
| Coolify mode | `tunnel` (default) or `standard` | n/a |
| App-domain mode | `apex` (default) or `vps` | n/a |

### Step 3: Collect Secrets and Required Credentials

Collect:

- root password (or root password file path for automation) for `deploy.sh` fresh runs (not required for `--ts-ip` resume or `--preflight-only`)
- Tailscale auth key (`tskey-auth-*`) unless resuming with `--ts-ip` or running `--preflight-only`
- **Coolify only**: Cloudflare API token (or `--cf-api-token-file`); Cloudflare tunnel token if split-token model is used (`--cf-tunnel-api-token-file`)
- **dFlow only**: no additional credentials required beyond the common set above

### Step 4: Confirm Defaults

Unless user overrides:

- PaaS: `coolify`
- admin user: `coolifyadmin` (Coolify) or `dflowadmin` (dFlow)
- pubkey file: `~/.ssh/id_ed25519.pub`
- swap size: `2G`
- deploy mode: `tunnel` (Coolify only)
- app domain mode: `apex` (Coolify only)
- tailscale direct WAN: disabled (`--no-tailscale-direct-wan`)
- server timezone: operator must choose explicitly (no implicit recommendation)

### Step 5: Confirm Command + Impact, Then Execute

Before running `deploy.sh` or `setup.sh`, state exact command and impact and wait for explicit user confirmation.

### Step 6: Workflow Input Contract (No Guesswork)

Use this checklist to avoid over-asking or missing required inputs.

| Workflow | Must be user-provided/decided | Optional overrides (safe defaults exist) | Not required in this workflow |
|----------|-------------------------------|------------------------------------------|-------------------------------|
| `deploy.sh` fresh run | `--server-ip`, `--domain`, root password (prompt or `--root-pass-file`), `--tailscale-auth-key`, Cloudflare API token (`CF_API_TOKEN` or `--cf-api-token-file`), server timezone choice (`--server-timezone`; mandatory with `--yes`) | `--admin-user` (`coolifyadmin`), `--pubkey-file` (`~/.ssh/id_ed25519.pub`), `--mode` (`tunnel`), `--app-domain-mode` (`apex`), `--swap-size` (`2G`), `--tailscale-direct-wan` (disabled by default), `--cf-zone`, `--cf-zone-id`, `--cf-account-id`, split tunnel token file (`--cf-tunnel-api-token-file`) | `--ts-ip` |
| `deploy.sh --preflight-only` | `--server-ip`, `--domain`, Cloudflare API token (`CF_API_TOKEN` or `--cf-api-token-file`), server timezone choice (`--server-timezone`; mandatory with `--yes`) | `--admin-user` (`coolifyadmin`), `--pubkey-file` (`~/.ssh/id_ed25519.pub`), `--mode` (`tunnel`), `--app-domain-mode` (`apex`), `--swap-size` (`2G`), `--tailscale-direct-wan` (disabled by default), `--cf-zone`, `--cf-zone-id`, `--cf-account-id`, split tunnel token file (`--cf-tunnel-api-token-file`) | root password / `--root-pass-file`, `--tailscale-auth-key`, `--ts-ip` |
| `deploy.sh --ts-ip <ip>` resume | `--server-ip`, `--domain`, `--ts-ip`, Cloudflare API token (`CF_API_TOKEN` or `--cf-api-token-file`), server timezone choice (`--server-timezone`; mandatory with `--yes`) | Same overrides/defaults as fresh run | root password, `--root-pass-file`, `--tailscale-auth-key` |
| `setup.sh` server-local run | `--server-ip`, `--admin-user`, `--pubkey-file`, `--domain`, Cloudflare API token (`CF_API_TOKEN` or `--cf-api-token-file`), `--tailscale-auth-key` unless `--preflight-only`, server timezone choice (`--server-timezone`; mandatory with `--yes`) | `--mode` (`tunnel`), `--app-domain-mode` (`apex`), `--swap-size` (`2G`), `--tailscale-direct-wan` (disabled by default), `--cf-zone`, `--cf-zone-id`, `--cf-account-id`, split tunnel token file (`--cf-tunnel-api-token-file`) | root password / `--root-pass-file`, `--ts-ip` |
| `setup.sh --preflight-only` | `--server-ip`, `--admin-user`, `--pubkey-file`, `--domain`, Cloudflare API token (`CF_API_TOKEN` or `--cf-api-token-file`), server timezone choice (`--server-timezone`; mandatory with `--yes`) | `--mode` (`tunnel`), `--app-domain-mode` (`apex`), `--swap-size` (`2G`), `--tailscale-direct-wan` (disabled by default), `--cf-zone`, `--cf-zone-id`, `--cf-account-id`, split tunnel token file (`--cf-tunnel-api-token-file`) | `--tailscale-auth-key`, root password / `--root-pass-file`, `--ts-ip` |

Recommended defaults (when user is undecided):
- `--mode tunnel`
- `--app-domain-mode apex`
- `--admin-user coolifyadmin`
- `--pubkey-file ~/.ssh/id_ed25519.pub`
- `--swap-size 2G`
- `--no-tailscale-direct-wan`

Minimal command templates:

```bash
# Coolify: deploy.sh fresh run
/opt/homebrew/bin/bash deploy.sh --paas coolify --server-ip <ip> --domain <fqdn> --root-pass-file <path> \
  --tailscale-auth-key <tskey-auth-...> --server-timezone <IANA> \
  --cf-api-token-file <path> --yes

# Coolify: deploy.sh resume from phase 2
/opt/homebrew/bin/bash deploy.sh --paas coolify --server-ip <ip> --domain <fqdn> --ts-ip <100.x.x.x> \
  --server-timezone <IANA> --cf-api-token-file <path> --yes

# Coolify: deploy.sh preflight-only
/opt/homebrew/bin/bash deploy.sh --paas coolify --server-ip <ip> --domain <fqdn> --server-timezone <IANA> \
  --cf-api-token-file <path> --preflight-only --yes

# Coolify: setup.sh server-local
sudo /opt/homebrew/bin/bash setup.sh --paas coolify --server-ip <ip> --admin-user <name> --pubkey-file <path> \
  --domain <fqdn> --tailscale-auth-key <tskey-auth-...> --server-timezone <IANA> \
  --cf-api-token-file <path> --yes

# dFlow: deploy.sh fresh run
/opt/homebrew/bin/bash deploy.sh --paas dflow --server-ip <ip> --root-pass-file <path> \
  --admin-user dflowadmin --pubkey-file <path> \
  --tailscale-auth-key <tskey-auth-...> --server-timezone <IANA> --yes

# dFlow: setup.sh server-local
sudo /opt/homebrew/bin/bash setup.sh --paas dflow --server-ip <ip> --admin-user <name> --pubkey-file <path> \
  --tailscale-auth-key <tskey-auth-...> --server-timezone <IANA> --yes
```

Decision tree:
- Exposure model: choose `tunnel` (private-only dashboard/realtime, no inbound 80/443) or `standard` (public 80/443).
- App hostnames: choose `apex` (`appname.<zone>`) or `vps` (`appname.<domain>`).
- Token model: choose combined token (single API token) or split tokens (DNS token + tunnel token).

Non-interactive caveat:
- With `--yes`, pass `--server-timezone` (or `SERVER_TIMEZONE`) explicitly. The scripts do not prompt in non-interactive mode.
- `--cf-api-token` and `--cf-tunnel-api-token` flags are removed; use env vars or `--*-token-file`.

Resume semantics:
- `--ts-ip` means phase 1 hardening is skipped.
- In `--ts-ip` mode, root password and Tailscale auth key are intentionally not required.

Pre-run checklist:
- Confirm execution surface: `deploy.sh` on laptop, `setup.sh` on server.
- Confirm server target: public IPv4 and (for resume) Tailscale IPv4.
- Confirm domain target and mode (`tunnel` or `standard`).
- Confirm app-domain mode (`apex` or `vps`).
- Confirm timezone value (IANA string).
- Confirm token source: env var vs token file path(s).

---

## 5. Deployment Phases and Gates

- **[0/5] Pre-flight**: local tools, key validity. Coolify: Cloudflare auth/capability checks. dFlow: Cloudflare checks skipped.
- **[1/5] Harden**: upload companion scripts + run `base/bootstrap.sh`; capture `HARDEN_RESULT_TAILSCALE_IP=<ip>`. Same for both PaaS.
- **[2/5] Gates**:
  - Gate A: SSH admin over Tailscale works.
  - Gate B: admin identity check.
  - Gate C: `base/validate.sh --json --gate-c` reports 0 failures.
- **[3/5] PaaS install**:
  - Coolify: Docker + Coolify; Gate D = DOCKER-USER hardening service/rules active.
  - dFlow: no-op (controller installs Docker/Dokku/plugins/Beszel/Restic on first attach); substrate readiness logged.
- **[4/5] Routing**:
  - Coolify: configure dashboard binding, Cloudflare DNS/tunnel depending on mode.
  - dFlow: no-op (Traefik is owned by dFlow).
- **[5/5] Final verify**:
  - Coolify: Gate E (dashboard/websocket reachable on Tailscale and blocked on public paths) + Gate F (mode-specific external/private route assertions).
  - dFlow: Gate F runs `base/validate.sh --json` on the worker; dFlow-specific checks (`dflow_substrate_check`, `dflow_dokku_check`, `dflow_beszel_check`, `dflow_backups_check`, `dflow_predeploy_hook_check`) must not regress. INFO results from runtime checks pre-attach are expected.
  - Final `base/validate.sh --json` must report 0 failures.

---

## 6. Quality Gates (Machine-Checkable)

### Pre-Work Gate (run before starting any task)

```bash
bash -n deploy.sh setup.sh \
     overlays/coolify/coolify-common.sh \
     overlays/dflow/dflow-common.sh \
     base/validate.sh \
     base/bootstrap.sh \
     overlays/coolify/configure_coolify_binding.sh
```

Must be clean. If syntax check fails on an unmodified file, stop and escalate.

### Pre-Close Gate (run before closing a task)

| Task type | Required evidence |
|-----------|------------------|
| Script edited | `bash -n <script>` -> zero errors; recorded in task notes |
| Gate C ran | `base/validate.sh --json --gate-c` output with `"fail":0`; recorded in task notes |
| DNS/tunnel changed | CF API GET confirms record exists with correct value; recorded in task notes |
| Full deploy completed | Final `base/validate.sh --json` with `"fail":0`; summary box captured in task notes |

---

## 7. Invariants — Do Not Break

These are external contracts and security properties. Treat them as read-only unless invariant
change is the explicit, user-confirmed goal.

### Machine-Readable API Contracts

| Contract | Defined in | Consumed by |
|----------|-----------|-------------|
| `base/validate.sh --json` schema: `{"pass":N,"fail":N,"info":N,"checks":[...]}` | `base/validate.sh` | `report_validation_result()` in `lib/common.sh` (shared by both overlays) |
| `HARDEN_RESULT_TAILSCALE_IP=<ip>` sentinel (stdout) | `base/bootstrap.sh` | `deploy.sh` phase 1 capture via `tee` |
| State file `/var/lib/server-hardening/state` (key=value) | `base/bootstrap.sh write_state()` | `base/validate.sh` (state-derived checks; `PAAS=` selects branch) |
| `PAAS=` env var allowlisted in bootstrap env-file parsing | `base/bootstrap.sh env_file_key_supported` | `setup.sh phase1_harden` writes `deploy.env`; bootstrap reads it |
| Tunnel name `coolify-<domain-slug>-<sha256-12>` | `overlays/coolify/coolify-common.sh coolify_tunnel_name()` / `cf_create_tunnel()` | same function on re-run (reuse configured tunnel when possible; otherwise reconcile by deterministic name) |
| dFlow controller attach path: Tailscale SSH (`RunSSH=true`) on secondary `tailscaled-dfi` instance (controller tailnet) | `overlays/dflow/modules/tailscale_ssh.sh`, `overlays/dflow/checks/dflow_substrate_check.sh` | dFlow controller; `tailscale_check` (PAAS=dflow expects RunSSH=true) |

Changing these without updating all consumers is a breaking change.

### Security Invariants — Must Not Weaken

- **UFW**: default-deny incoming; SSH allowed only on `tailscale0` plus managed Docker bridge
  CIDRs (`docker_ssh_cidrs` from state); dashboard ports (8000/6001/6002) only on `tailscale0`;
  WAN 80/443 absent in tunnel mode.
- **DOCKER-USER**: WAN ingress dropped in tunnel mode; bridge traffic returned; no WAN bypass.
- **SSH**: global `PermitRootLogin no`; key-only root login only from localhost (`127.0.0.1`, `::1`)
  plus Docker bridge CIDRs via `Match Address`. CIDRs come from strict discovery
  (`STRICT_DOCKER_SSH_CIDRS=true`) with compatibility fallback to `10.0.0.0/8,172.16.0.0/12`.
- **fail2ban**: ignores Tailscale CIDR (`100.64.0.0/10`); bans WAN brute-force.

### Idempotency Contract

Every operation in every script must be safe to re-run on an already-provisioned server.
Companion scripts are re-uploaded every `--ts-ip` resume via `sync_companion_scripts()` in phase 2.
Any non-idempotent logic is a bug.

---

## 8. Auditability

Every task close must include evidence, not just intent. Example:

```text
Fixed fstab grep pattern in base/validate.sh swap_check;
bash -n exits 0; Gate C passed on resume with --ts-ip 100.x.x.x (0 failures)
```

Append raw gate output to task notes for deployment tasks. Trace each code change back to a task.

### Live Server Audit Hygiene

- Treat live host audits as secret-sensitive. Do **not** capture raw `dokku config:show`,
  `docker inspect`, `env`, `printenv`, or app environment output into repo artifacts unless the
  command redacts values before writing. Prefer key-presence checks and fingerprints.
- dFlow secondary tailnet diagnostics must derive the local socket from
  `systemctl cat tailscaled-dfi.service`; current managed hosts use `/run/tailscale-dfi.sock`, not
  `/run/tailscale-dfi/tailscaled.sock`.
- If `/root/base/validate.sh` is missing or stale on a server, do not claim Gate C or Gate F from
  ad-hoc inspection. Resync companion scripts through the normal `deploy.sh --paas <paas> --ts-ip`
  resume path, or record a rollback-backed manual companion upload before running validation.
- Netdata is not part of the dFlow worker contract. If found active on a dFlow worker, verify whether
  the operator intentionally installed it; otherwise disable or bind it to loopback before closing a
  security/performance audit, and record `systemctl enable --now netdata` as the rollback when only
  disabling the service.

---

## 9. Destructive Operations — Confirm Before Executing

These affect live infrastructure and are difficult/impossible to reverse:

| Operation | Impact |
|-----------|--------|
| Running `deploy.sh` or `setup.sh` against a server | Irreversible system changes (UFW reset, SSH hardening) |
| Deleting a Cloudflare Tunnel *(Coolify only)* | Drops live traffic for all tunnel-routed apps immediately |
| Deleting/modifying Cloudflare DNS records *(Coolify only)* | Drops or misdirects live traffic |
| `ufw --force reset` on a live server | Removes all firewall rules; can lock out SSH |
| Editing `/data/coolify` files or querying `coolify-db` | Risk of Coolify data corruption |
| Detaching a worker from the dFlow controller, or `dokku apps:destroy` | Removes app data and config; uninstalls dFlow-managed services |
| Modifying `/etc/ssh/sshd_config.d/16-dflow-root-match.conf` directly | Can lock out the dFlow controller; manage via overlay re-run |

State exact command and effect before running. Wait for explicit user confirmation.

---

## Script Edit Policy

The shell scripts are frozen. **Do not edit any `.sh` file** without explicit instruction:

- `base/bootstrap.sh`
- `base/validate.sh`
- `deploy.sh`
- `setup.sh`
- `overlays/coolify/coolify-common.sh`
- `overlays/coolify/configure_coolify_binding.sh`
- `overlays/coolify/modules/*.sh`, `overlays/coolify/checks/*.sh`
- `overlays/dflow/dflow-common.sh`
- `overlays/dflow/modules/*.sh`, `overlays/dflow/checks/*.sh`
- `lib/*.sh`

Files free to edit by default:

- `AGENTS.md`, `README.md`, `HARDENING_PROCEDURE.md`

**Exception — Gate C false positives**: If Gate C fails but server state is actually correct,
the validator may be wrong.

Protocol:

1. Confirm expected state directly on server (for example `swapon --show`, `cat /etc/fstab`).
2. Fix `base/validate.sh` locally.
3. Resume with `--ts-ip <ip>`; corrected script re-syncs in phase 2.
4. Never weaken checks to suppress a real failure.

---

## Recovery Rules

### Phase 1 output gap (3-5 minutes of silence)

Normal when output is file-buffered through `tee`; `unattended-upgrades` and Tailscale install can
be quiet. Wait for `PASS Hardening completed` then `PASS Server Tailscale IP: 100.x.x.x`.

### Wrong root password (`sshpass` exit code 5)

VPS providers often rotate root password after rebuild. Verify in provider panel and re-run with
correct `--root-pass-file` (or interactive prompt).

### Gate A/B fails (SSH timeout)

Check operator `tailscale status`. If server appears in Tailscale admin with `100.x.x.x`, resume
with `--ts-ip <ip>`.

### Gate C fails

Distinguish cause before changes:

1. **Real server failure**: inspect `/var/log/server-hardening.log`; run
   `sudo /root/base/validate.sh --json --gate-c`; fix server state; resume with `--ts-ip`.
2. **Script false positive**: verify expected state manually, then fix validator logic.

### No ready tasks mid-deployment

If phase 1 completed (server has Tailscale IP), create task to resume from phase 2 via `--ts-ip`.

### Escalation trigger

If two consecutive recovery attempts make no progress, stop and request user decision.

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:ca08a54f -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

## Session Completion

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bd dolt push
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
<!-- END BEADS INTEGRATION -->
