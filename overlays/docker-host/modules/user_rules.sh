install_docker_user_assets() {
  write_file "${DOCKER_USER_SCRIPT}" "0750" "root" "root" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

DOCKER_USER_LOCK_FILE="${DOCKER_USER_LOCK_FILE:-/run/lock/docker-user-hardening.lock}"
exec 9>"${DOCKER_USER_LOCK_FILE}"
flock -x 9

WAN_IFACE="${WAN_IFACE:-${1:-}}"
TAILSCALE_IFACE="${TAILSCALE_IFACE:-tailscale0}"
TUNNEL_MODE="${TUNNEL_MODE:-}"
DOCKER_USER_MANAGEMENT_PORT="${DOCKER_USER_MANAGEMENT_PORT:-}"
DOKPLOY_ENROLLMENT_SOURCE_IP=""
DOKPLOY_ENROLLMENT_COMPLETE="false"

if [[ -z "${WAN_IFACE}" ]]; then
  echo "WAN_IFACE is required." >&2
  exit 1
fi

case "${TUNNEL_MODE}" in
  true|false) ;;
  *)
    echo "TUNNEL_MODE must be exactly true or false." >&2
    exit 1
    ;;
esac

if ! command -v iptables >/dev/null 2>&1; then
  echo "iptables is required." >&2
  exit 1
fi

is_true() {
  case "${1,,}" in
    1|true|yes|y|on) return 0 ;;
    *) return 1 ;;
  esac
}

is_tailscale_ipv4() {
  local ip="$1" a b c d
  IFS=. read -r a b c d <<< "${ip}"
  [[ "${a}" == "100" && "${b}" =~ ^[0-9]+$ && "${c}" =~ ^[0-9]+$ && "${d}" =~ ^[0-9]+$ ]] \
    || return 1
  (( b >= 64 && b <= 127 && c <= 255 && d <= 255 ))
}

ipv6_disabled_without_listeners() {
  [[ -d /proc/sys/net/ipv6/conf/all ]] || return 0
  [[ -r /proc/sys/net/ipv6/conf/all/disable_ipv6 ]] \
    && [[ "$(< /proc/sys/net/ipv6/conf/all/disable_ipv6)" == "1" ]] \
    && [[ -r /proc/sys/net/ipv6/conf/all/forwarding ]] \
    && [[ "$(< /proc/sys/net/ipv6/conf/all/forwarding)" == "0" ]] \
    && [[ -r /proc/sys/net/ipv6/conf/default/forwarding ]] \
    && [[ "$(< /proc/sys/net/ipv6/conf/default/forwarding)" == "0" ]] \
    && command -v ss >/dev/null 2>&1 \
    && ! ss -H -l -6 2>/dev/null | grep -q .
}

if ! command -v ip6tables >/dev/null 2>&1 && ! ipv6_disabled_without_listeners; then
  echo "ip6tables is unavailable while IPv6 is enabled; refusing to apply only IPv4 Docker ingress hardening." >&2
  exit 1
fi

# Dokploy publishes its panel through Docker, so host INPUT/UFW rules alone do
# not prove source restriction. Resolve only account counts and the managed
# source IP; never read or emit application configuration or credential data.
# Before first-admin enrollment completes, Docker-forwarded port 3000 traffic
# is accepted only from the provisioning operator's Tailscale IPv4. IPv6 and
# every other tailnet source fail closed.
if [[ "${DOCKER_USER_MANAGEMENT_PORT}" == "3000" ]]; then
  state_file="/var/lib/server-hardening/state"
  if [[ -f "${state_file}" && ! -L "${state_file}" ]]; then
    DOKPLOY_ENROLLMENT_SOURCE_IP="$(
      flock -s "${state_file}.lock" awk -F= \
        '$1 == "dokploy_enrollment_source_ip" { print substr($0, index($0, "=") + 1); exit }' \
        "${state_file}" 2>/dev/null || true
    )"
  fi
  if ! is_tailscale_ipv4 "${DOKPLOY_ENROLLMENT_SOURCE_IP}"; then
    DOKPLOY_ENROLLMENT_SOURCE_IP=""
  fi
  pg_cid="$(docker ps -q --filter name=dokploy-postgres 2>/dev/null | head -1 || true)"
  if [[ -n "${pg_cid}" ]]; then
    account_table_exists="$(docker exec "${pg_cid}" psql -U dokploy -d dokploy -tAc \
      "SELECT count(*) FROM pg_catalog.pg_tables WHERE schemaname='public' AND tablename='user'" \
      2>/dev/null | tr -d '[:space:]' || true)"
    if [[ "${account_table_exists}" == "1" ]]; then
      account_count="$(docker exec "${pg_cid}" psql -U dokploy -d dokploy -tAc \
        'SELECT count(*) FROM "user"' 2>/dev/null | tr -d '[:space:]' || true)"
      no2fa="$(docker exec "${pg_cid}" psql -U dokploy -d dokploy -tAc \
        'SELECT count(*) FROM "user" u WHERE u.two_factor_enabled IS DISTINCT FROM TRUE OR NOT EXISTS (SELECT 1 FROM two_factor tf WHERE tf.user_id = u.id AND tf.verified IS TRUE AND length(tf.secret) > 0)' \
        2>/dev/null | tr -d '[:space:]' || true)"
      if [[ "${account_count}" =~ ^[1-9][0-9]*$ && "${no2fa}" == "0" ]]; then
        DOKPLOY_ENROLLMENT_COMPLETE="true"
      fi
    fi
  fi
fi

# The Docker-managed DOCKER-USER chain is a shared hook.  Appending policy
# directly to it is unsafe: an older/unmanaged unconditional RETURN can be
# ahead of the appended rules.  We therefore put one managed jump at the head
# of DOCKER-USER and own the policy in a separate chain. Routine refreshes are
# double-buffered through a staging chain: the complete replacement becomes
# active before the stable chain is rebuilt, so bridge inventory refreshes do
# not interrupt container traffic. A temporary DROP guard is used only when no
# complete managed policy is active (first install or recovery from corruption).
run_ipt() {
  local binary="$1"
  shift
  "${binary}" -w "$@"
}

managed_policy_is_active() {
  local binary="$1"
  local policy_chain="$2"
  local jump_comment="$3"
  local unmatched_comment="$4"
  local shared_rules policy_rules first_rule

  shared_rules="$(run_ipt "${binary}" -t filter -S DOCKER-USER 2>/dev/null || true)"
  policy_rules="$(run_ipt "${binary}" -t filter -S "${policy_chain}" 2>/dev/null || true)"
  first_rule="$(awk '$1 == "-A" { print; exit }' <<< "${shared_rules}")"
  [[ "${first_rule}" == *"${jump_comment}"* \
    && "${first_rule}" == *"-j ${policy_chain}"* ]] \
    && grep -qE "${unmatched_comment}.* -j DROP$" <<< "${policy_rules}"
}

populate_policy_chain() {
  local binary="$1"
  local policy_chain="$2"
  local suffix="$3"
  local network_id bridge_iface docker_network_driver docker_network_full_id

  run_ipt "${binary}" -t filter -N "${policy_chain}" 2>/dev/null || true
  run_ipt "${binary}" -t filter -F "${policy_chain}"
  if [[ "${DOCKER_USER_MANAGEMENT_PORT}" =~ ^[1-9][0-9]*$ ]] \
    && (( DOCKER_USER_MANAGEMENT_PORT <= 65535 )); then
    if [[ "${DOKPLOY_ENROLLMENT_COMPLETE}" == "true" ]]; then
      run_ipt "${binary}" -t filter -A "${policy_chain}" -i "${TAILSCALE_IFACE}" \
        -p tcp -m conntrack --ctorigdstport "${DOCKER_USER_MANAGEMENT_PORT}" \
        -m comment --comment "coolify-hardening-management-tailnet-enrolled${suffix}" -j ACCEPT
    else
      if [[ -z "${suffix}" && -n "${DOKPLOY_ENROLLMENT_SOURCE_IP}" ]]; then
        run_ipt "${binary}" -t filter -A "${policy_chain}" -i "${TAILSCALE_IFACE}" \
          -s "${DOKPLOY_ENROLLMENT_SOURCE_IP}/32" -p tcp -m conntrack \
          --ctorigdstport "${DOCKER_USER_MANAGEMENT_PORT}" \
          -m comment --comment "coolify-hardening-management-tailnet-source${suffix}" -j ACCEPT
      fi
      run_ipt "${binary}" -t filter -A "${policy_chain}" -i "${TAILSCALE_IFACE}" \
        -p tcp -m conntrack --ctorigdstport "${DOCKER_USER_MANAGEMENT_PORT}" \
        -m comment --comment "coolify-hardening-management-tailnet-drop${suffix}" -j DROP
    fi
    # This deny is deliberately before RELATED,ESTABLISHED. It revokes public,
    # IPv6, and container-origin panel request flows that predate policy
    # convergence. Restrict it to ORIGINAL direction so authorized replies can
    # reach the established return below.
    run_ipt "${binary}" -t filter -A "${policy_chain}" \
      -p tcp -m conntrack --ctorigdstport "${DOCKER_USER_MANAGEMENT_PORT}" --ctdir ORIGINAL \
      -m comment --comment "coolify-hardening-management-container-drop${suffix}" -j DROP
  fi
  run_ipt "${binary}" -t filter -A "${policy_chain}" -m conntrack --ctstate RELATED,ESTABLISHED \
    -m comment --comment "coolify-hardening-estab${suffix}" -j RETURN
  run_ipt "${binary}" -t filter -A "${policy_chain}" -i "${TAILSCALE_IFACE}" \
    -m comment --comment "coolify-hardening-tailscale${suffix}" -j ACCEPT
  # Classify the selected WAN interface before Docker-owned bridge returns. A
  # provider may legitimately expose the host through a bridge master such as
  # br0; trusting an interface-name prefix would bypass the WAN drop and hand
  # the packet back to Docker's published-port rules.
  if ! is_true "${TUNNEL_MODE}"; then
    run_ipt "${binary}" -t filter -A "${policy_chain}" -i "${WAN_IFACE}" -p tcp \
      -m multiport --dports 80,443 -m comment --comment "coolify-hardening-wan-web${suffix}" -j ACCEPT
  fi
  run_ipt "${binary}" -t filter -A "${policy_chain}" -i "${WAN_IFACE}" \
    -m comment --comment "coolify-hardening-wan-drop${suffix}" -j DROP
  run_ipt "${binary}" -t filter -A "${policy_chain}" -i docker0 \
    -m comment --comment "coolify-hardening-bridge-docker0${suffix}" -j RETURN
  # Swarm containers leave the host through Docker's gateway bridge. Keep this
  # trusted internal path ahead of the terminal drop so new container egress
  # can reach registries, DNS, ACME, and application dependencies.
  run_ipt "${binary}" -t filter -A "${policy_chain}" -i docker_gwbridge \
    -m comment --comment "coolify-hardening-bridge-docker-gw${suffix}" -j RETURN
  # Permit only bridge interfaces positively reported by Docker's network
  # inventory.  Interface-name prefixes are not provenance: a provider or a
  # later network workflow can create an externally routed br-prefixed link.
  # Refreshing this allowlist is handled by the companion systemd timer.
  if command -v docker >/dev/null 2>&1 && command -v ip >/dev/null 2>&1; then
    while IFS= read -r network_id; do
      [[ "${network_id}" =~ ^[0-9a-f]{12,64}$ ]] || continue
      bridge_iface="$(docker network inspect --format '{{index .Options "com.docker.network.bridge.name"}}' \
        "${network_id}" 2>/dev/null || true)"
      if [[ -z "${bridge_iface}" || "${bridge_iface}" == "<no value>" ]]; then
        # Docker-generated Compose bridges omit the explicit name option.
        # Derive the kernel name only from a matching, bridge-driver ID.
        read -r docker_network_driver docker_network_full_id < <(docker network inspect \
          --format '{{.Driver}} {{.Id}}' "${network_id}" 2>/dev/null || true) || continue
        [[ "${docker_network_driver}" == "bridge" \
          && "${docker_network_full_id}" =~ ^[0-9a-f]{64}$ \
          && "${docker_network_full_id}" == "${network_id}"* ]] || continue
        bridge_iface="br-${docker_network_full_id:0:12}"
      fi
      [[ "${bridge_iface}" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || continue
      case "${bridge_iface}" in
        docker0|docker_gwbridge) continue ;;
      esac
      ip link show "${bridge_iface}" >/dev/null 2>&1 || continue
      run_ipt "${binary}" -t filter -A "${policy_chain}" -i "${bridge_iface}" \
        -m comment --comment "coolify-hardening-bridge-docker-owned${suffix}" -j RETURN
    done < <(docker network ls --filter driver=bridge --format '{{.ID}}' 2>/dev/null || true)
  fi
  # The WAN interface is not the only possible ingress path.  A new physical
  # interface, a provider-created bridge, or a renamed uplink must not bypass
  # the policy merely because it was absent from state at install time.
  # Trusted interfaces were handled above; every other ingress fails closed.
  run_ipt "${binary}" -t filter -A "${policy_chain}" \
    -m comment --comment "coolify-hardening-unmatched-drop${suffix}" -j DROP
  run_ipt "${binary}" -t filter -A "${policy_chain}" \
    -m comment --comment "coolify-hardening-return${suffix}" -j RETURN
}

activate_policy_chain() {
  local binary="$1"
  local policy_chain="$2"
  local jump_comment="$3"
  local line_no first_rule

  # Insert the complete replacement before the old managed policy, then remove
  # only stale managed entries. Unmanaged DOCKER-USER rules are preserved.
  run_ipt "${binary}" -t filter -I DOCKER-USER 1 \
    -m comment --comment "${jump_comment}" -j "${policy_chain}"
  while true; do
    line_no="$(run_ipt "${binary}" -t filter -L DOCKER-USER --line-numbers -n \
      | awk '$1 != 1 && /coolify-hardening-|secure-ubuntu-paas-docker-user-(jump|reconcile-guard)/ { print $1; exit }')"
    [[ -n "${line_no}" ]] || break
    run_ipt "${binary}" -t filter -D DOCKER-USER "${line_no}"
  done

  first_rule="$(run_ipt "${binary}" -t filter -S DOCKER-USER \
    | awk '$1 == "-A" { print; exit }')"
  [[ "${first_rule}" == *"${jump_comment}"* \
    && "${first_rule}" == *"-j ${policy_chain}"* ]] || {
    echo "Failed to activate managed Docker policy chain ${policy_chain}." >&2
    return 1
  }
}

reconcile_family() {
  local binary="$1"
  local policy_chain="$2"
  local suffix="$3"
  local staging_chain="${policy_chain}-NEXT"
  local jump_comment="secure-ubuntu-paas-docker-user-jump${suffix}"
  local guard_comment="secure-ubuntu-paas-docker-user-reconcile-guard${suffix}"
  local unmatched_comment="coolify-hardening-unmatched-drop${suffix}"

  run_ipt "${binary}" -t filter -N DOCKER-USER 2>/dev/null || true
  if ! run_ipt "${binary}" -t filter -C FORWARD -j DOCKER-USER >/dev/null 2>&1; then
    run_ipt "${binary}" -t filter -I FORWARD 1 -j DOCKER-USER
  fi

  if managed_policy_is_active \
    "${binary}" "${staging_chain}" "${jump_comment}" "${unmatched_comment}"; then
    # Recover from an interrupted prior refresh. The staging policy is already
    # complete and active, so rebuild and switch directly to the stable chain.
    populate_policy_chain "${binary}" "${policy_chain}" "${suffix}"
    activate_policy_chain "${binary}" "${policy_chain}" "${jump_comment}"
  elif managed_policy_is_active \
    "${binary}" "${policy_chain}" "${jump_comment}" "${unmatched_comment}"; then
    # Healthy refresh: build off-path, switch, rebuild the stable chain while
    # staging remains active, then switch back. At every point a complete
    # policy is first in DOCKER-USER.
    populate_policy_chain "${binary}" "${staging_chain}" "${suffix}"
    activate_policy_chain "${binary}" "${staging_chain}" "${jump_comment}"
    populate_policy_chain "${binary}" "${policy_chain}" "${suffix}"
    activate_policy_chain "${binary}" "${policy_chain}" "${jump_comment}"
  else
    # No complete managed policy is active. Fail closed during the initial
    # build; if population fails, set -e deliberately leaves this guard first.
    run_ipt "${binary}" -t filter -I DOCKER-USER 1 \
      -m comment --comment "${guard_comment}" -j DROP
    populate_policy_chain "${binary}" "${policy_chain}" "${suffix}"
    activate_policy_chain "${binary}" "${policy_chain}" "${jump_comment}"
  fi
}

# --- IPv4 ---

reconcile_family iptables SECURE-DOCKER-USER ""

# --- IPv6 ---

if command -v ip6tables >/dev/null 2>&1; then
  reconcile_family ip6tables SECURE-DOCKER-USER6 6
else
  echo "IPv6 is explicitly disabled and has no listening sockets; no IPv6 DOCKER-USER chain is required." >&2
fi
EOF

  write_file "${DOCKER_USER_ENV_FILE}" "0644" "root" "root" <<EOF
WAN_IFACE=${WAN_IFACE}
TAILSCALE_IFACE=${TAILSCALE_IFACE}
TUNNEL_MODE=${TUNNEL_MODE}
DOCKER_USER_MANAGEMENT_PORT=${DOCKER_USER_MANAGEMENT_PORT}
EOF

  write_file "${DOCKER_USER_UNIT_FILE}" "0644" "root" "root" <<EOF
[Unit]
Description=Apply managed DOCKER-USER hardening rules
After=docker.service
Requires=docker.service
PartOf=docker.service

[Service]
Type=oneshot
EnvironmentFile=${DOCKER_USER_ENV_FILE}
ExecStart=${DOCKER_USER_SCRIPT}
RemainAfterExit=yes

[Install]
WantedBy=docker.service
EOF

  local refresh_service_file="${DOCKER_USER_REFRESH_SERVICE_FILE:-/etc/systemd/system/docker-user-hardening-refresh.service}"
  local refresh_timer_file="${DOCKER_USER_REFRESH_TIMER_FILE:-/etc/systemd/system/docker-user-hardening-refresh.timer}"
  write_file "${refresh_service_file}" "0644" "root" "root" <<EOF
[Unit]
Description=Refresh managed Docker bridge firewall allowlist
After=docker.service docker-user-hardening.service
Requires=docker.service
PartOf=docker.service

[Service]
Type=oneshot
EnvironmentFile=${DOCKER_USER_ENV_FILE}
ExecStart=${DOCKER_USER_SCRIPT}
EOF

  write_file "${refresh_timer_file}" "0644" "root" "root" <<'EOF'
[Unit]
Description=Periodically refresh managed Docker bridge firewall allowlist

[Timer]
OnBootSec=30s
OnUnitActiveSec=60s
AccuracySec=15s
Unit=docker-user-hardening-refresh.service

[Install]
WantedBy=timers.target
EOF
}

configure_docker_user() {
  install_docker_user_assets

  # Remove stale WantedBy=multi-user.target symlinks from prior script versions
  if ! is_true "${DRY_RUN}"; then
    systemctl disable docker-user-hardening.service 2>/dev/null || true
  fi
  run systemctl daemon-reload
  local docker_service_present="false"
  if unit_available "docker.service"; then
    docker_service_present="true"
    run systemctl enable docker-user-hardening.service
  else
    log "docker.service not found yet; deferring docker-user-hardening enable until Docker is installed."
  fi

  if [[ "${DOCKER_PRESENT}" == "true" ]]; then
    # Docker CLI may exist while docker.service is not yet installed/available.
    if [[ "${docker_service_present}" == "true" ]]; then
      ensure_docker_user_service_applied "Docker hardening"
    else
      warn "Docker CLI detected but docker.service is not present; DOCKER-USER enable/start deferred."
    fi
  else
    log "Docker not detected; DOCKER-USER unit installed with deferred enable/start until Docker is installed."
  fi
}
