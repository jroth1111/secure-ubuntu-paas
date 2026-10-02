docker_daemon_ready() {
  systemctl is-active --quiet docker.service 2>/dev/null || return 1
  docker info >/dev/null 2>&1
}

wait_for_systemd_unit_success() {
  local unit_name="$1"
  local attempts="${2:-15}"
  local delay="${3:-2}"
  local attempt active_state result

  for (( attempt=1; attempt<=attempts; attempt++ )); do
    if systemctl is-active --quiet "${unit_name}" 2>/dev/null; then
      return 0
    fi

    active_state="$(systemctl show "${unit_name}" --property=ActiveState --value 2>/dev/null || true)"
    result="$(systemctl show "${unit_name}" --property=Result --value 2>/dev/null || true)"
    if [[ "${active_state}" == "inactive" && "${result}" == "success" ]]; then
      return 0
    fi

    (( attempt < attempts )) || break
    sleep "${delay}"
  done

  return 1
}

wait_for_docker_daemon_ready() {
  local attempts="${1:-20}"
  local delay="${2:-2}"
  local attempt

  [[ "${DOCKER_PRESENT}" == "true" ]] || return 0
  for (( attempt=1; attempt<=attempts; attempt++ )); do
    if docker_daemon_ready; then
      return 0
    fi
    (( attempt < attempts )) || break
    sleep "${delay}"
  done

  return 1
}

docker_ipv6_disabled_without_listeners() {
  # Non-Linux operator test environments have no procfs; only the live host
  # path is required to prove the explicit IPv6-disabled fallback.
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

docker_user_family_rules_present() {
  local binary="$1"
  local shared_chain="$2"
  local policy_chain="$3"
  local jump_comment="$4"
  local drop_comment="$5"
  local unmatched_comment="$6"
  local web_comment="$7"
  local shared_rules policy_rules first_rule wan_drop_line unmatched_drop_line management_drop_line management_drop_rule bridge_line bridge_order_ok="true"
  local network_id bridge_iface bridge_comment seen_bridges=",docker0,docker_gwbridge,"
  local management_port="${DOCKER_USER_MANAGEMENT_PORT:-}"
  local -a expected_bridge_ifaces=(docker0 docker_gwbridge)
  shared_rules="$(${binary} -t filter -S "${shared_chain}" 2>/dev/null || true)"
  policy_rules="$(${binary} -t filter -S "${policy_chain}" 2>/dev/null || true)"
  first_rule="$(awk '$1 == "-A" { print; exit }' <<< "${shared_rules}")"
  wan_drop_line="$(grep -n -- "-i ${WAN_IFACE:-}" <<< "${policy_rules}" | grep -F "${drop_comment}" | head -1 | cut -d: -f1 || true)"
  unmatched_drop_line="$(grep -n -F -- "${unmatched_comment}" <<< "${policy_rules}" | head -1 | cut -d: -f1 || true)"
  if [[ -z "${management_port}" && -r /etc/default/docker-user-hardening ]]; then
    management_port="$(awk -F= '$1 == "DOCKER_USER_MANAGEMENT_PORT" { print substr($0, index($0, "=") + 1); exit }' /etc/default/docker-user-hardening)"
  fi
  if [[ -z "${management_port}" && "${PAAS:-coolify}" == "dokploy" ]]; then
    management_port="3000"
  fi
  if [[ "${management_port}" =~ ^[1-9][0-9]*$ ]] \
    && (( management_port <= 65535 )); then
    management_drop_line="$(grep -n -F -- "coolify-hardening-management-container-drop${web_comment##*wan-web}" <<< "${policy_rules}" | head -1 | cut -d: -f1 || true)"
    management_drop_rule="$(grep -F -- "coolify-hardening-management-container-drop${web_comment##*wan-web}" <<< "${policy_rules}" | head -1 || true)"
  else
    management_port=""
  fi
  if command -v docker >/dev/null 2>&1 && command -v ip >/dev/null 2>&1; then
    while IFS= read -r network_id; do
      [[ "${network_id}" =~ ^[0-9a-f]{12,64}$ ]] || continue
      bridge_iface="$(docker network inspect --format '{{index .Options "com.docker.network.bridge.name"}}' \
        "${network_id}" 2>/dev/null || true)"
      [[ "${bridge_iface}" != "<no value>" ]] || continue
      [[ "${bridge_iface}" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || continue
      case "${bridge_iface}" in
        docker0|docker_gwbridge) continue ;;
      esac
      ip link show "${bridge_iface}" >/dev/null 2>&1 || continue
      case "${seen_bridges}" in
        *,"${bridge_iface}",*) continue ;;
      esac
      seen_bridges+="${bridge_iface},"
      expected_bridge_ifaces+=("${bridge_iface}")
    done < <(docker network ls --filter driver=bridge --format '{{.ID}}' 2>/dev/null || true)
  fi
  for bridge_iface in "${expected_bridge_ifaces[@]}"; do
    case "${bridge_iface}" in
      docker0) bridge_comment="coolify-hardening-bridge-docker0${web_comment##*wan-web}" ;;
      docker_gwbridge) bridge_comment="coolify-hardening-bridge-docker-gw${web_comment##*wan-web}" ;;
      *) bridge_comment="coolify-hardening-bridge-docker-owned${web_comment##*wan-web}" ;;
    esac
    bridge_line="$(grep -n -F -- "${bridge_comment}" <<< "${policy_rules}" | head -1 | cut -d: -f1 || true)"
    if [[ -z "${wan_drop_line}" || -z "${bridge_line}" || -z "${unmatched_drop_line}" \
      || "${wan_drop_line}" -ge "${bridge_line}" || "${bridge_line}" -ge "${unmatched_drop_line}" \
      || ( -n "${management_port}" && ( -z "${management_drop_line}" || "${management_drop_line}" -ge "${bridge_line}" ) ) ]]; then
      bridge_order_ok="false"
    fi
  done
  [[ "${first_rule}" == *"${jump_comment}"* \
    && "${first_rule}" == *"-j ${policy_chain}"* ]] \
    && grep -q "${drop_comment}" <<< "${policy_rules}" \
    && grep -q "${unmatched_comment}" <<< "${policy_rules}" \
    && grep -q "coolify-hardening-bridge-docker0" <<< "${policy_rules}" \
    && grep -q "coolify-hardening-bridge-docker-gw" <<< "${policy_rules}" \
    && ! grep -qE -- '(^|[[:space:]])-i br\+([[:space:]]|$)' <<< "${policy_rules}" \
    && [[ "${bridge_order_ok}" == "true" ]] \
    && if [[ -n "${management_port}" ]]; then
         [[ -n "${management_drop_line}" && "${management_drop_line}" -gt 0 && "${management_drop_line}" -lt "${unmatched_drop_line}" ]] \
           && [[ "${management_drop_rule}" == *"--ctdir ORIGINAL"* \
             && "${management_drop_rule}" != *"--ctstate NEW"* ]]
       else
         true
       fi \
    && if [[ "${TUNNEL_MODE:-false}" == "true" ]]; then
         ! grep -q "${web_comment}" <<< "${policy_rules}"
       else
         grep -q "${web_comment}" <<< "${policy_rules}"
       fi
}

docker_user_rules_present() {
  case "${TUNNEL_MODE:-false}" in
    true|false) ;;
    *) return 1 ;;
  esac

  docker_user_family_rules_present \
    iptables DOCKER-USER SECURE-DOCKER-USER \
    secure-ubuntu-paas-docker-user-jump \
    coolify-hardening-wan-drop \
    coolify-hardening-unmatched-drop \
    coolify-hardening-wan-web \
    || return 1

  if command -v ip6tables >/dev/null 2>&1; then
    docker_user_family_rules_present \
      ip6tables DOCKER-USER SECURE-DOCKER-USER6 \
      secure-ubuntu-paas-docker-user-jump6 \
      coolify-hardening-wan-drop6 \
      coolify-hardening-unmatched-drop6 \
      coolify-hardening-wan-web6
  else
    docker_ipv6_disabled_without_listeners
  fi
}

ensure_docker_user_service_applied() {
  local context="${1:-docker-user-hardening}"

  if [[ "${DOCKER_PRESENT}" != "true" ]]; then
    return 0
  fi

  wait_for_docker_daemon_ready 20 2 \
    || die "${context}: Docker daemon did not become ready."
  if systemctl is-active --quiet docker-user-hardening.service 2>/dev/null; then
    # RemainAfterExit oneshots do not execute again on `start` while active.
    run systemctl restart docker-user-hardening.service
  else
    run systemctl start docker-user-hardening.service
  fi
  if is_true "${DRY_RUN}"; then
    return 0
  fi

  wait_for_systemd_unit_success "docker-user-hardening.service" 15 2 \
    || die "${context}: docker-user-hardening.service did not complete successfully."
  docker_user_rules_present \
    || die "${context}: DOCKER-USER rules were not applied."
  if [[ -f "${DOCKER_USER_REFRESH_TIMER_FILE:-/etc/systemd/system/docker-user-hardening-refresh.timer}" ]]; then
    run systemctl enable --now docker-user-hardening-refresh.timer
  fi
  DOCKER_RULES_APPLIED="true"
}

wait_for_fail2ban_sshd_jail() {
  local attempts="${1:-15}"
  local delay="${2:-2}"
  local attempt

  if is_true "${DRY_RUN}"; then
    return 0
  fi

  for (( attempt=1; attempt<=attempts; attempt++ )); do
    if systemctl is-active --quiet fail2ban 2>/dev/null \
      && fail2ban-client status sshd >/dev/null 2>&1; then
      return 0
    fi
    (( attempt < attempts )) || break
    sleep "${delay}"
  done

  return 1
}
