docker_user_check() {
  if ! command -v iptables >/dev/null 2>&1; then
    record "FAIL" "docker-user: iptables" "iptables not found"
    return
  fi

  # Check if Docker is installed first
  if ! command -v docker >/dev/null 2>&1; then
    record "INFO" "docker-user: Docker" "Docker not installed; skipping DOCKER-USER checks"
    return
  fi

  # Prove the effective backend positively. A failed/empty/unrecognized
  # docker-info response must never certify iptables-only DOCKER-USER policy.
  local firewall_backend_json="" firewall_backend="" firewall_info=""
  firewall_backend_json="$(docker info --format '{{json .FirewallBackend}}' 2>/dev/null || true)"
  if [[ -n "${firewall_backend_json}" ]] && command -v jq >/dev/null 2>&1; then
    firewall_backend="$(jq -r \
      'if type == "object" then (.Driver // empty) elif type == "string" then . else empty end' \
      <<< "${firewall_backend_json}" 2>/dev/null || true)"
  fi
  if [[ -z "${firewall_backend}" ]]; then
    firewall_info="$(docker info 2>/dev/null || true)"
    firewall_backend="$(awk -F: \
      '/^[[:space:]]*Firewall Backend:[[:space:]]*/ {gsub(/[[:space:]]/, "", $2); print tolower($2); exit} \
       /^[[:space:]]*iptables:[[:space:]]*true[[:space:]]*$/ {print "iptables"; exit}' \
      <<< "${firewall_info}")"
  fi
  if [[ "${firewall_backend}" != "iptables" ]]; then
    record "FAIL" "docker-user: backend" \
      "expected a positively identified iptables backend, got ${firewall_backend:-unavailable}"
    return
  else
    record "PASS" "docker-user: iptables backend"
  fi

  local docker_service_present="false"
  if unit_available "docker.service"; then
    docker_service_present="true"
  fi
  if [[ "${DOCKER_RULES_APPLIED}" != "true" && "${docker_service_present}" != "true" ]]; then
    record "INFO" "docker-user: IPv4" "docker.service unavailable and DOCKER-USER apply deferred"
    return
  fi

  local rules attempt chain_ready="false"
  for (( attempt=1; attempt<=10; attempt++ )); do
    rules="$(iptables -t filter -S DOCKER-USER 2>/dev/null)" || rules=""
    if [[ -n "${rules}" ]]; then
      chain_ready="true"
      break
    fi
    (( attempt < 10 )) || break
    sleep 2
  done
  if [[ "${chain_ready}" != "true" ]]; then
    record "FAIL" "docker-user: IPv4" "DOCKER-USER chain absent (Docker may need restart)"
    return
  fi

  local policy_chain="SECURE-DOCKER-USER"
  local policy_rules first_rule drop_line unmatched_drop_line management_drop_line final_return_line bridge_line legacy_inline_rules="false" wildcard_bridge_rules="false" bridge_order_ok="true"
  local network_id bridge_iface bridge_comment seen_bridges=",docker0,docker_gwbridge,"
  local management_port="${DOCKER_USER_MANAGEMENT_PORT:-}"
  local -a expected_bridge_ifaces=(docker0 docker_gwbridge)
  policy_rules="$(iptables -t filter -S "${policy_chain}" 2>/dev/null)" || policy_rules=""
  first_rule="$(awk '$1 == "-A" { print; exit }' <<< "${rules}")"
  drop_line="$(grep -n "coolify-hardening-wan-drop" <<< "${policy_rules}" | head -1 | cut -d: -f1)"
  unmatched_drop_line="$(grep -n "coolify-hardening-unmatched-drop" <<< "${policy_rules}" | head -1 | cut -d: -f1)"
  if [[ -z "${management_port}" && -r /etc/default/docker-user-hardening ]]; then
    management_port="$(awk -F= '$1 == "DOCKER_USER_MANAGEMENT_PORT" { print substr($0, index($0, "=") + 1); exit }' /etc/default/docker-user-hardening)"
  fi
  if [[ -z "${management_port}" && "${PAAS:-coolify}" == "dokploy" ]]; then
    management_port="3000"
  fi
  if [[ "${management_port}" =~ ^[1-9][0-9]*$ ]] \
    && (( management_port <= 65535 )); then
    management_drop_line="$(grep -n -F -- "coolify-hardening-management-container-drop" <<< "${policy_rules}" | head -1 | cut -d: -f1 || true)"
  else
    management_port=""
  fi
  final_return_line="$(awk -v chain="${policy_chain}" \
    '$1 == "-A" && $2 == chain && $0 !~ /--ctstate/ && $0 !~ / -i / && $0 ~ / -j RETURN$/ { print NR; exit }' \
    <<< "${policy_rules}")"
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
      docker0) bridge_comment="coolify-hardening-bridge-docker0" ;;
      docker_gwbridge) bridge_comment="coolify-hardening-bridge-docker-gw" ;;
      *) bridge_comment="coolify-hardening-bridge-docker-owned" ;;
    esac
    bridge_line="$(grep -n -F -- "${bridge_comment}" <<< "${policy_rules}" | head -1 | cut -d: -f1 || true)"
    if ! [[ -n "${bridge_line}" && -n "${drop_line}" && -n "${unmatched_drop_line}" \
      && ${drop_line:-0} -lt ${bridge_line:-0} && ${bridge_line:-0} -lt ${unmatched_drop_line:-0} \
      && ( -z "${management_port}" || ( -n "${management_drop_line}" && ${management_drop_line:-0} -lt ${bridge_line:-0} ) ) ]]; then
      bridge_order_ok="false"
    fi
  done
  if grep -qE '^-A DOCKER-USER .*coolify-hardening-' <<< "${rules}"; then
    legacy_inline_rules="true"
  fi
  if grep -qE -- '(^|[[:space:]])-i br\+([[:space:]]|$)' <<< "${policy_rules}"; then
    wildcard_bridge_rules="true"
  fi

  if [[ "${first_rule}" == *"secure-ubuntu-paas-docker-user-jump"* \
    && "${first_rule}" == *"-j ${policy_chain}"* \
    && -n "${drop_line}" && -n "${unmatched_drop_line}" && -n "${final_return_line}" \
    && ${drop_line:-0} -lt ${final_return_line:-0} \
    && ${unmatched_drop_line:-0} -lt ${final_return_line:-0} \
    && "${wildcard_bridge_rules}" == "false" \
    && "${bridge_order_ok}" == "true" \
    && "${legacy_inline_rules}" == "false" ]]; then
    record "PASS" "docker-user: IPv4 control-flow"
  else
    record "FAIL" "docker-user: IPv4 control-flow" \
      "managed jump is not first, policy chain is missing, or terminal drops are not before the unconditional return"
  fi

  if grep -q "coolify-hardening-wan-drop" <<< "${policy_rules}"; then
    record "PASS" "docker-user: IPv4 wan-drop"
  else
    record "FAIL" "docker-user: IPv4 wan-drop" "rule missing from ${policy_chain}"
  fi
  if [[ -n "${management_port}" ]]; then
    if [[ -n "${management_drop_line}" && ${management_drop_line:-0} -gt 0 \
      && -n "${unmatched_drop_line}" && ${management_drop_line:-0} -lt ${unmatched_drop_line:-0} ]]; then
      record "PASS" "docker-user: management port ${management_port} container boundary"
    else
      record "FAIL" "docker-user: management port ${management_port} container boundary" \
        "container-origin traffic to the published management port is not denied before bridge returns"
    fi
  fi

  if grep -q "coolify-hardening-bridge-docker0" <<< "${policy_rules}"; then
    record "PASS" "docker-user: IPv4 bridge-docker0"
  else
    record "FAIL" "docker-user: IPv4 bridge-docker0" "rule missing from ${policy_chain}"
  fi
  if grep -q "coolify-hardening-bridge-docker-gw" <<< "${policy_rules}"; then
    record "PASS" "docker-user: IPv4 bridge-docker-gw"
  else
    record "FAIL" "docker-user: IPv4 bridge-docker-gw" "rule missing from ${policy_chain}; container egress would hit unmatched drop"
  fi

  if is_true "${TUNNEL_MODE}" && grep -q "coolify-hardening-wan-web" <<< "${policy_rules}"; then
    record "FAIL" "docker-user: tunnel-mode no wan-web" "wan-web ACCEPT present"
  elif is_true "${TUNNEL_MODE}"; then
    record "PASS" "docker-user: tunnel-mode no wan-web"
  elif ! grep -q "coolify-hardening-wan-web" <<< "${policy_rules}"; then
    record "FAIL" "docker-user: IPv4 wan-web" "standard-mode web ACCEPT rule missing"
  fi

  if command -v ip6tables >/dev/null 2>&1; then
    local rules6 policy_rules6 first_rule6 drop_line6 unmatched_drop_line6 management_drop_line6 final_return_line6 bridge_line6 legacy_inline_rules6="false" wildcard_bridge_rules6="false" bridge_order_ok6="true"
    rules6="$(ip6tables -t filter -S DOCKER-USER 2>/dev/null)" || {
      record "FAIL" "docker-user: IPv6" \
        "ip6tables is available but the DOCKER-USER chain is absent; IPv6 Docker ingress policy cannot be proved"
      return
    }
    policy_rules6="$(ip6tables -t filter -S SECURE-DOCKER-USER6 2>/dev/null)" || policy_rules6=""
    first_rule6="$(awk '$1 == "-A" { print; exit }' <<< "${rules6}")"
    drop_line6="$(grep -n "coolify-hardening-wan-drop6" <<< "${policy_rules6}" | head -1 | cut -d: -f1)"
    unmatched_drop_line6="$(grep -n "coolify-hardening-unmatched-drop6" <<< "${policy_rules6}" | head -1 | cut -d: -f1)"
    if [[ -n "${management_port}" ]]; then
      management_drop_line6="$(grep -n -F -- "coolify-hardening-management-container-drop6" <<< "${policy_rules6}" | head -1 | cut -d: -f1 || true)"
    fi
    final_return_line6="$(awk -v chain="SECURE-DOCKER-USER6" \
      '$1 == "-A" && $2 == chain && $0 !~ /--ctstate/ && $0 !~ / -i / && $0 ~ / -j RETURN$/ { print NR; exit }' \
      <<< "${policy_rules6}")"
    if grep -qE '^-A DOCKER-USER .*coolify-hardening-' <<< "${rules6}"; then
      legacy_inline_rules6="true"
    fi
    if grep -qE -- '(^|[[:space:]])-i br\+([[:space:]]|$)' <<< "${policy_rules6}"; then
      wildcard_bridge_rules6="true"
    fi
    for bridge_iface in "${expected_bridge_ifaces[@]}"; do
      case "${bridge_iface}" in
        docker0) bridge_comment="coolify-hardening-bridge-docker06" ;;
        docker_gwbridge) bridge_comment="coolify-hardening-bridge-docker-gw6" ;;
        *) bridge_comment="coolify-hardening-bridge-docker-owned6" ;;
      esac
      bridge_line6="$(grep -n -F -- "${bridge_comment}" <<< "${policy_rules6}" | head -1 | cut -d: -f1 || true)"
      if ! [[ -n "${bridge_line6}" && -n "${drop_line6}" && -n "${unmatched_drop_line6}" \
        && ${drop_line6:-0} -lt ${bridge_line6:-0} && ${bridge_line6:-0} -lt ${unmatched_drop_line6:-0} \
        && ( -z "${management_port}" || ( -n "${management_drop_line6}" && ${management_drop_line6:-0} -lt ${bridge_line6:-0} ) ) ]]; then
        bridge_order_ok6="false"
      fi
    done

    if [[ "${first_rule6}" == *"secure-ubuntu-paas-docker-user-jump6"* \
      && "${first_rule6}" == *"-j SECURE-DOCKER-USER6"* \
      && -n "${drop_line6}" && -n "${unmatched_drop_line6}" && -n "${final_return_line6}" \
      && ${drop_line6:-0} -lt ${final_return_line6:-0} \
      && ${unmatched_drop_line6:-0} -lt ${final_return_line6:-0} \
      && "${wildcard_bridge_rules6}" == "false" \
      && "${bridge_order_ok6}" == "true" \
      && "${legacy_inline_rules6}" == "false" ]]; then
      record "PASS" "docker-user: IPv6 control-flow"
    else
      record "FAIL" "docker-user: IPv6 control-flow" "managed jump/policy order is unsafe"
    fi

    if grep -q "coolify-hardening-wan-drop6" <<< "${policy_rules6}"; then
      record "PASS" "docker-user: IPv6 wan-drop6"
    else
      record "FAIL" "docker-user: IPv6 wan-drop6" "rule missing from SECURE-DOCKER-USER6"
    fi
    if [[ -n "${management_port}" ]]; then
      if [[ -n "${management_drop_line6}" && ${management_drop_line6:-0} -gt 0 \
        && -n "${unmatched_drop_line6}" && ${management_drop_line6:-0} -lt ${unmatched_drop_line6:-0} ]]; then
        record "PASS" "docker-user: IPv6 management port ${management_port} container boundary"
      else
        record "FAIL" "docker-user: IPv6 management port ${management_port} container boundary" \
          "container-origin traffic to the published management port is not denied before bridge returns"
      fi
    fi
    if grep -q "coolify-hardening-bridge-docker0" <<< "${policy_rules6}"; then
      record "PASS" "docker-user: IPv6 bridge-docker0"
    else
      record "FAIL" "docker-user: IPv6 bridge-docker0" "rule missing from SECURE-DOCKER-USER6"
    fi
    if grep -q "coolify-hardening-bridge-docker-gw6" <<< "${policy_rules6}"; then
      record "PASS" "docker-user: IPv6 bridge-docker-gw"
    else
      record "FAIL" "docker-user: IPv6 bridge-docker-gw" "rule missing from SECURE-DOCKER-USER6; container egress would hit unmatched drop"
    fi
    if is_true "${TUNNEL_MODE}" && grep -q "coolify-hardening-wan-web6" <<< "${policy_rules6}"; then
      record "FAIL" "docker-user: IPv6 tunnel-mode no wan-web" "wan-web ACCEPT present"
    elif is_true "${TUNNEL_MODE}"; then
      record "PASS" "docker-user: IPv6 tunnel-mode no wan-web"
    elif ! grep -q "coolify-hardening-wan-web6" <<< "${policy_rules6}"; then
      record "FAIL" "docker-user: IPv6 wan-web" "standard-mode web ACCEPT rule missing"
    fi
  else
    local ipv6_disabled="false"
    if [[ ! -d /proc/sys/net/ipv6/conf/all ]]; then
      ipv6_disabled="true"
    elif [[ -r /proc/sys/net/ipv6/conf/all/disable_ipv6 ]] \
      && [[ "$(< /proc/sys/net/ipv6/conf/all/disable_ipv6)" == "1" ]] \
      && [[ -r /proc/sys/net/ipv6/conf/all/forwarding ]] \
      && [[ "$(< /proc/sys/net/ipv6/conf/all/forwarding)" == "0" ]] \
      && [[ -r /proc/sys/net/ipv6/conf/default/forwarding ]] \
      && [[ "$(< /proc/sys/net/ipv6/conf/default/forwarding)" == "0" ]] \
      && command -v ss >/dev/null 2>&1 \
      && ! ss -H -l -6 2>/dev/null | grep -q .; then
      ipv6_disabled="true"
    fi
    if [[ "${ipv6_disabled}" == "true" ]]; then
      record "PASS" "docker-user: IPv6 disabled safely" "ip6tables unavailable but IPv6 publication and forwarding are disabled"
    else
      record "FAIL" "docker-user: IPv6" "ip6tables unavailable and a safe IPv6-disabled posture was not proved"
    fi
  fi
}
