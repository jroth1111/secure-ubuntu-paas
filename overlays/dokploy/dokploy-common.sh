#!/usr/bin/env bash
# overlays/dokploy/dokploy-common.sh — Dokploy-overlay shared phase logic.
# Source this file; do not execute it directly.
# Requires: set -Eeuo pipefail in the caller.

[[ "${BASH_SOURCE[0]}" != "${0}" ]] \
  || { printf 'Source this file, do not execute it.\n' >&2; exit 1; }
if [[ -z "${BASH_VERSINFO:-}" || "${BASH_VERSINFO[0]}" -lt 4 ]]; then
  printf 'Bash 4+ is required (found %s). On macOS use Homebrew bash and run via its absolute path.\n' "${BASH_VERSION:-unknown}" >&2
  return 1
fi
[[ -z "${_DOKPLOY_COMMON_LOADED:-}" ]] || return 0
_DOKPLOY_COMMON_LOADED=1

_dir="$(dirname "${BASH_SOURCE[0]}")"

# shellcheck source=../../lib/common.sh
# shellcheck disable=SC1091
source "${_dir}/../../lib/common.sh"

finalize_dokploy_inputs() {
  # Dokploy uses direct public 80/443 app ingress and Tailscale-only admin/API
  # access. Cloudflare is not managed by this adapter; DOMAIN is optional and
  # only recorded as the intended public app domain when supplied.
  DEPLOY_MODE="standard"
  APP_DOMAIN_MODE=""
  PRIVATE_TLS_CA=""
}

collect_dokploy_setup_inputs() {
  [[ -n "${SERVER_IP}" ]]   || prompt_value  SERVER_IP "Server public IP" "" "${IPV4_RE}"
  [[ -n "${ADMIN_USER}" ]]  || prompt_value  ADMIN_USER "Admin username" "dokployadmin" "${LINUX_USER_RE}"
  [[ -n "${PUBKEY_FILE}" ]] || prompt_value  PUBKEY_FILE "SSH public key file" "${HOME}/.ssh/id_ed25519.pub"
  [[ -n "${TAILSCALE_AUTH_KEY}" ]] || prompt_value TAILSCALE_AUTH_KEY "Tailscale auth key (tskey-auth-...)" ""
  [[ -n "${SWAP_SIZE}" ]]   || SWAP_SIZE="2G"
  if [[ -z "${SERVER_TIMEZONE:-}" ]]; then
    if is_true "${AUTO_YES:-false}"; then
      die "Server timezone is required in non-interactive mode. Set SERVER_TIMEZONE or use --server-timezone."
    fi
    prompt_value SERVER_TIMEZONE "Server timezone (IANA, e.g. Australia/Melbourne)" "UTC" "${TIMEZONE_RE}"
  fi
  finalize_dokploy_inputs
}

dokploy_remove_stale_coolify_dashboard_ufw_script() {
  cat <<'EOF'
set -Eeuo pipefail
while true; do
  line="$(ufw status numbered 2>/dev/null | grep -E 'coolify-hardening-(dashboard|soketi|terminal)' | head -1 || true)"
  [[ -n "${line}" ]] || break
  num="$(sed -n 's/^\[[[:space:]]*\([0-9][0-9]*\)\].*/\1/p' <<< "${line}")"
  [[ -n "${num}" ]] || break
  ufw --force delete "${num}"
done
EOF
}

dokploy_dashboard_ufw_policy_script() {
  # Full Dokploy host port policy:
  #  - dashboard/API 3000/tcp: tailscale0 only, explicit public deny
  #  - Swarm control/data plane (2377/tcp mgmt, 7946/tcp+udp gossip,
  #    4789/udp VXLAN): tailscale0 only, explicit public deny — multi-node
  #    swarms must join over the tailnet, never the WAN.
  # Explicit denies are belt-and-braces over the default-deny inbound policy
  # and keep the intent visible in `ufw status`.
  cat <<'EOF'
set -Eeuo pipefail
ufw delete allow 3000/tcp >/dev/null 2>&1 || true
ufw delete limit 3000/tcp >/dev/null 2>&1 || true
ufw allow in on tailscale0 proto tcp to any port 3000 comment "dokploy-dashboard-tailscale" >/dev/null
ufw deny 3000/tcp >/dev/null 2>&1 || true

ufw allow in on tailscale0 proto tcp to any port 2377 comment "docker-swarm-mgmt-tailscale" >/dev/null
ufw deny 2377/tcp >/dev/null 2>&1 || true
ufw allow in on tailscale0 proto tcp to any port 7946 comment "docker-swarm-gossip-tailscale" >/dev/null
ufw deny 7946/tcp >/dev/null 2>&1 || true
ufw allow in on tailscale0 proto udp to any port 7946 comment "docker-swarm-gossip-udp-tailscale" >/dev/null
ufw deny 7946/udp >/dev/null 2>&1 || true
ufw allow in on tailscale0 proto udp to any port 4789 comment "docker-swarm-vxlan-tailscale" >/dev/null
ufw deny 4789/udp >/dev/null 2>&1 || true
EOF
}

dokploy_finalize_runtime_script() {
  cat <<'EOF'
set -Eeuo pipefail
TRAEFIK_VERSION="${TRAEFIK_VERSION:-3.6.7}"
daemon_json="/etc/docker/daemon.json"
unlock_key_file="/root/.docker/swarm-unlock-key"

if command -v jq >/dev/null 2>&1 && [[ -f "${daemon_json}" ]]; then
  if jq -e 'has("live-restore")' "${daemon_json}" >/dev/null 2>&1; then
    jq 'del(.["live-restore"])' "${daemon_json}" > "${daemon_json}.tmp"
    mv "${daemon_json}.tmp" "${daemon_json}"
    systemctl restart docker
    sleep 8
  fi
fi

swarm_state="$(docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null || true)"
if [[ "${swarm_state}" == "active" || "${swarm_state}" == "pending" || "${swarm_state}" == "locked" ]]; then
  install -d -m 700 -o root -g root /root/.docker
  if [[ ! -s "${unlock_key_file}" ]]; then
    unlock_key="$(docker swarm unlock-key -q 2>/dev/null || true)"
    if [[ -n "${unlock_key}" ]]; then
      printf '%s\n' "${unlock_key}" > "${unlock_key_file}"
      chmod 600 "${unlock_key_file}"
    fi
  fi
  if [[ -s "${unlock_key_file}" ]]; then
    # Helper script instead of inline ExecStart bash: systemd expands ${...}
    # inside ExecStart itself, so inline shell variables reach bash empty and
    # the unlock silently never fires.
    cat > /usr/local/sbin/docker-swarm-unlock.sh <<'HELPER'
#!/usr/bin/env bash
# Unlock an autolocked Docker Swarm once dockerd is responsive.
set -uo pipefail
material="/root/.docker/swarm-unlock-key"
[[ -s "${material}" ]] || { echo "unlock material ${material} missing" >&2; exit 1; }
for _ in $(seq 1 30); do
  state="$(docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null || true)"
  case "${state}" in
    active) exit 0 ;;
    locked|pending) docker swarm unlock < "${material}" 2>/dev/null && exit 0 ;;
  esac
  sleep 3
done
echo "swarm not unlocked after 90s (state=${state:-unknown})" >&2
exit 1
HELPER
    chmod 755 /usr/local/sbin/docker-swarm-unlock.sh
    # PartOf=docker.service re-runs the unlock on every docker restart
    # (apt docker-ce upgrades, daemon reconfigure) — not only at boot.
    cat > /etc/systemd/system/docker-swarm-unlock.service <<'UNIT'
[Unit]
Description=Unlock Docker Swarm after Docker starts
After=docker.service
Requires=docker.service
PartOf=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/docker-swarm-unlock.sh

[Install]
WantedBy=multi-user.target docker.service
UNIT
    systemctl daemon-reload
    systemctl enable docker-swarm-unlock.service
    current_state="$(docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null || true)"
    if [[ "${current_state}" == "locked" || "${current_state}" == "pending" ]]; then
      /usr/local/sbin/docker-swarm-unlock.sh
      sleep 5
    fi
  fi
fi

# Dokploy's default Traefik static config ships api.insecure=true (:8080
# API/dashboard reachable by any container on dokploy-network). Disable it;
# Dokploy manages Traefik via file provider, not the API.
traefik_yml="/etc/dokploy/traefik/traefik.yml"
if [[ -f "${traefik_yml}" ]] && grep -qE '^[[:space:]]*insecure:[[:space:]]*true' "${traefik_yml}"; then
  sed -i.bak-hardening 's/^\([[:space:]]*\)insecure:[[:space:]]*true/\1insecure: false/' "${traefik_yml}"
  if docker service inspect dokploy-traefik >/dev/null 2>&1; then
    docker service update --force --quiet dokploy-traefik >/dev/null 2>&1 || true
  fi
fi

# The Dokploy installer leaves /etc/dokploy world-writable (0777). The
# Dokploy container runs as root, so 0755 is sufficient and safe.
if [[ -d /etc/dokploy ]]; then
  chmod 755 /etc/dokploy
fi

# Dokploy regenerates dynamic/dokploy.yml with a default
# Host(`dokploy.docker.localhost`) router on the PUBLIC web/websecure
# entrypoints, re-exposing the dashboard login on public 80/443 to any client
# sending that Host header. Install a higher-priority hardening router that
# shadows it and denies every public client. Lives in its own file Dokploy
# does not manage, so it survives dokploy.yml regeneration and reboots.
block_file="/etc/dokploy/traefik/dynamic/zz-hardening-dashboard-block.yml"
if [[ -d /etc/dokploy/traefik/dynamic ]]; then
  cat > "${block_file}" <<'BLOCK'
# Managed by secure-ubuntu-paas hardening (Dokploy overlay). Do not edit.
# Shadows Dokploy's default Host(`dokploy.docker.localhost`) dashboard router
# on the public web/websecure entrypoints and denies all public clients.
# Legitimate dashboard access is over Tailscale on :3000 and never traverses
# Traefik.
http:
  routers:
    zz-hardening-dashboard-localhost:
      rule: "Host(`dokploy.docker.localhost`)"
      priority: 100000
      entryPoints:
        - web
        - websecure
      service: zz-hardening-blackhole
      middlewares:
        - zz-hardening-deny-public
  middlewares:
    zz-hardening-deny-public:
      ipAllowList:
        sourceRange:
          - 192.0.2.0/32
  services:
    zz-hardening-blackhole:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:9"
BLOCK
  chmod 644 "${block_file}"
fi

# Dokploy/Swarm leaves many exited task containers after updates; prune safely.
docker container prune -f >/dev/null 2>&1 || true
docker image prune -f >/dev/null 2>&1 || true

if ! docker service inspect dokploy-traefik >/dev/null 2>&1; then
  docker pull "traefik:v${TRAEFIK_VERSION}"
  docker service create \
    --name dokploy-traefik \
    --constraint 'node.role==manager' \
    --network dokploy-network \
    --publish mode=host,target=80,published=80,protocol=tcp \
    --publish mode=host,target=443,published=443,protocol=tcp \
    --publish mode=host,target=443,published=443,protocol=udp \
    --mount type=bind,source=/etc/dokploy/traefik/traefik.yml,target=/etc/traefik/traefik.yml \
    --mount type=bind,source=/etc/dokploy/traefik/dynamic,target=/etc/dokploy/traefik/dynamic \
    --mount type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock \
    "traefik:v${TRAEFIK_VERSION}"
fi
EOF
}

dokploy_install_dokploy_script() {
  cat <<'EOF'
set -Eeuo pipefail
installer_url="https://dokploy.com/install.sh"
tmp="$(mktemp /tmp/dokploy-install.XXXXXX.sh)"
cleanup() { rm -f "${tmp}"; }
trap cleanup EXIT

curl -fsSL "${installer_url}" -o "${tmp}"
[[ -s "${tmp}" ]] || { echo "Downloaded Dokploy installer is empty" >&2; exit 1; }
head -1 "${tmp}" | grep -Eq '^#!.*/(ba)?sh$' || { echo "Unexpected Dokploy installer header" >&2; exit 1; }
chmod 700 "${tmp}"
if command -v timeout >/dev/null 2>&1; then
  if ! timeout --signal=TERM --kill-after=60 1800 bash "${tmp}"; then
    rc=$?
    if [[ "${rc}" -eq 124 || "${rc}" -eq 137 ]]; then
      echo "Dokploy installer timed out after 1800s (likely blocked image pull or Swarm task convergence)." >&2
    fi
    exit "${rc}"
  fi
else
  bash "${tmp}"
fi
EOF
}

dokploy_phase3_install_shared() {
  local has_docker_fn="$1"
  local install_docker_fn="$2"
  local start_docker_user_fn="$3"
  local verify_docker_user_fn="$4"
  local has_dokploy_fn="$5"
  local install_dokploy_fn="$6"
  local reconcile_docker_daemon_fn="$7"
  local restart_docker_user_fn="$8"
  local sync_docker_ssh_cidrs_fn="$9"
  local finalize_dokploy_runtime_fn="${10:-}"

  step "3/5" "Install Docker & Dokploy"

  if "${has_docker_fn}"; then
    log "Docker already installed — skipping install."
  else
    log "Installing Docker via official apt repository..."
    run_with_heartbeat "Docker installation" "${install_docker_fn}" \
      || die "Docker installation failed."
    pass "Docker installed"
  fi
  pass "Docker present"

  "${start_docker_user_fn}" || die "Failed to start docker-user-hardening.service"
  "${verify_docker_user_fn}" "Gate D"

  if "${has_dokploy_fn}"; then
    log "Dokploy service found — skipping install (already installed)."
    pass "Dokploy already installed"
  else
    log "Installing Dokploy via official installer (this may take a few minutes)..."
    run_with_heartbeat "Dokploy installation" "${install_dokploy_fn}" \
      || die "Dokploy installation failed."
    pass "Dokploy installed"
  fi

  "${reconcile_docker_daemon_fn}"
  "${restart_docker_user_fn}" \
    || die "Failed to restart docker-user-hardening.service after Docker daemon reconciliation."
  "${verify_docker_user_fn}" "Gate D (post-Dokploy)"

  log "Reconciling Docker bridge SSH CIDRs..."
  "${sync_docker_ssh_cidrs_fn}" || die "Failed to reconcile Docker bridge SSH CIDRs."
  pass "Docker bridge SSH CIDRs reconciled"

  if [[ -n "${finalize_dokploy_runtime_fn}" ]]; then
    log "Finalizing Dokploy runtime (Swarm unlock, Traefik, daemon reconcile)..."
    run_with_heartbeat "Dokploy runtime finalization" "${finalize_dokploy_runtime_fn}" \
      || die "Dokploy runtime finalization failed."
    pass "Dokploy runtime finalized"
  fi
}

dokploy_phase4_routing_shared() {
  local configure_dashboard_ufw_fn="$1"
  local remove_stale_coolify_ufw_fn="${2:-}"

  step "4/5" "Configure Dokploy access policy"
  if [[ -n "${remove_stale_coolify_ufw_fn}" ]]; then
    log "Removing stale Coolify dashboard/Soketi/terminal UFW rules..."
    "${remove_stale_coolify_ufw_fn}" || die "Failed to remove stale Coolify UFW rules."
    pass "Stale Coolify dashboard UFW rules removed"
  fi
  log "Restricting Dokploy dashboard/API port 3000 to Tailscale while leaving public 80/443 for apps..."
  "${configure_dashboard_ufw_fn}" || die "Failed to configure Dokploy dashboard/API firewall policy."
  pass "Dokploy dashboard/API restricted to tailscale0:3000"
}

dokploy_phase5_verify_shared() {
  local fetch_validate_json_fn="${1:-}"
  [[ -n "${fetch_validate_json_fn}" ]] || die "dokploy_phase5_verify_shared requires fetch_validate_json_fn"

  step "5/5" "Final verification"

  log "Gate F: Running base/validate.sh on the Dokploy host..."
  local validate_json
  validate_json="$("${fetch_validate_json_fn}")" \
    || die "Gate F failed: validate.sh did not produce JSON output."
  report_validation_result "Gate F" "${validate_json}" \
    "Gate F failed. Fix validation failures before using this Dokploy host."
}

print_dokploy_deployment_summary() {
  printf '\n'
  printf '┌─────────────────────────────────────────────────────────────┐\n'
  printf '│                    DOKPLOY DEPLOYMENT READY                 │\n'
  printf '├─────────────────────────────────────────────────────────────┤\n'
  summary_box_print_field "Server Public IP" "${SERVER_IP}"
  summary_box_print_field "Tailscale IP" "${TS_IP}"
  summary_box_print_field "Admin User" "${ADMIN_USER}"
  summary_box_print_field "Server Timezone" "${SERVER_TIMEZONE}"
  summary_box_print_field "Dashboard URL" "http://${TS_IP}:3000"
  summary_box_print_field "SSH Access" "ssh ${ADMIN_USER}@${TS_IP}"
  summary_box_print_field "Public Ingress" "80/tcp and 443/tcp only"
  [[ -n "${DOMAIN:-}" ]] && summary_box_print_field "App Domain" "${DOMAIN}"
  printf '├─────────────────────────────────────────────────────────────┤\n'
  summary_box_print_field "Public Dashboard" "blocked by UFW + DOCKER-USER"
  summary_box_print_field "Docker API/Swarm" "not exposed publicly"
  printf '└─────────────────────────────────────────────────────────────┘\n'
  printf '\n'
  log "Next steps:"
  log "  1. Open http://${TS_IP}:3000 over Tailscale and create the first Dokploy admin account."
  log "  2. Create a Dokploy API key and use the Tailscale URL for CLI/MCP/API automation."
  log "  3. Point public app DNS records at ${SERVER_IP}; do not create public DNS for the dashboard."
  log "  4. Configure Dokploy backups and run a restore test before trusting production data."
  log "  5. Swarm auto-unlock survives reboots AND docker restarts (docker-swarm-unlock.service)."
  log ""
  log "SECURITY — never set a panel domain in Dokploy Settings → Web Server:"
  log "  it writes a Traefik route that re-exposes the dashboard on public 80/443,"
  log "  bypassing the UFW port-3000 lockdown. The validator fails if one is set."
}
