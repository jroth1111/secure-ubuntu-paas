ufw_find_stale_coolify_management_rule() {
  local ufw_numbered=""
  ufw_numbered="$(ufw status numbered 2>/dev/null || true)"
  awk -v ts_iface="${TAILSCALE_IFACE}" '
    function is_management_port(line) {
      return line ~ /(^|[[:space:]])(8000|6001|6002)(\/tcp)?([[:space:]]|$)/
    }
    /ALLOW IN/ && is_management_port($0) && index($0, "on " ts_iface) == 0 {
      print
      exit
    }
  ' <<< "${ufw_numbered}"
}

remove_stale_coolify_management_rules() {
  local stale_rule stale_num
  while true; do
    stale_rule="$(ufw_find_stale_coolify_management_rule)"
    [[ -n "${stale_rule}" ]] || break
    stale_num="$(sed -n 's/^\[[[:space:]]*\([0-9][0-9]*\)[[:space:]]*\].*/\1/p' <<< "${stale_rule}")"
    [[ -n "${stale_num}" ]] \
      || die "Unable to parse stale Coolify management UFW rule number: ${stale_rule}"
    run ufw --force delete "${stale_num}"
  done
}

configure_ufw() {
  local cidr

  # Reconcile managed rules by comment to avoid an all-open fail window from `ufw reset`.
  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: reconcile managed UFW rules (remove stale coolify-hardening-* rules)"
  else
    local ufw_numbered
    local managed_nums=()
    local line rule_num idx
    ufw_numbered="$(ufw status numbered 2>/dev/null || true)"
    while IFS= read -r line; do
      [[ "${line}" == *"coolify-hardening-"* ]] || continue
      rule_num="$(sed -n 's/^\[[[:space:]]*\([0-9][0-9]*\)[[:space:]]*\].*/\1/p' <<< "${line}")"
      [[ -n "${rule_num}" ]] && managed_nums+=("${rule_num}")
    done <<< "${ufw_numbered}"
    for (( idx=${#managed_nums[@]}-1; idx>=0; idx-- )); do
      run ufw --force delete "${managed_nums[$idx]}"
    done
    # Remove stale broad/WAN Coolify dashboard, realtime, and terminal allows
    # even when an older release created them without our managed comment.
    remove_stale_coolify_management_rules
    if is_true "${TUNNEL_MODE}"; then
      # Tunnel mode has no public 80/443 listener policy. Remove legacy
      # unscoped, WAN-scoped, and source-scoped web allows; only an explicit
      # Tailscale interface rule may remain.
      while true; do
        local stale_web_rule stale_web_num
        stale_web_rule="$(ufw status numbered 2>/dev/null | awk -v ts_iface="${TAILSCALE_IFACE}" '
          /ALLOW IN/ && ($0 ~ /80\/tcp/ || $0 ~ /443\/tcp/) && index($0, "on " ts_iface) == 0 { print; exit }
        ')"
        [[ -n "${stale_web_rule}" ]] || break
        stale_web_num="$(sed -n 's/^\[[[:space:]]*\([0-9][0-9]*\)[[:space:]]*\].*/\1/p' <<< "${stale_web_rule}")"
        [[ -n "${stale_web_num}" ]] \
          || die "Unable to parse tunnel-mode UFW web rule number: ${stale_web_rule}"
        run ufw --force delete "${stale_web_num}"
      done
    fi
  fi

  run ufw default deny incoming
  run ufw default allow outgoing
  run ufw default deny routed

  run ufw allow in on "${TAILSCALE_IFACE}" proto tcp to any port "${SSH_PORT}" comment "coolify-hardening-ssh-tailscale"

  # Allow Coolify to SSH to the host from Docker bridge CIDRs.
  # Compatibility mode uses broad ranges; strict mode uses discovered bridge CIDRs.
  # Coolify-only: dFlow and Dokploy never SSH from containers to the host, so
  # the bridge→SSH path stays closed for them (reconciliation above removes
  # stale coolify-hardening-ssh-docker-bridge rules on PaaS switch).
  if [[ "${PAAS}" == "coolify" ]]; then
    for cidr in "${DOCKER_SSH_CIDRS[@]}"; do
      run ufw allow in proto tcp from "${cidr}" to any port "${SSH_PORT}" comment "coolify-hardening-ssh-docker-bridge"
    done
  fi

  # Coolify dashboard/Soketi/terminal on Tailscale only. Dokploy uses port 3000 instead.
  if [[ "${PAAS}" == "coolify" ]]; then
    # 8000 = dashboard, 6001 = Soketi real-time, 6002 = terminal (required since beta.336)
    run ufw allow in on "${TAILSCALE_IFACE}" proto tcp to any port 8000 comment "coolify-hardening-dashboard-tailscale"
    run ufw allow in on "${TAILSCALE_IFACE}" proto tcp to any port 6001 comment "coolify-hardening-soketi-tailscale"
    run ufw allow in on "${TAILSCALE_IFACE}" proto tcp to any port 6002 comment "coolify-hardening-terminal-tailscale"
  fi

  if is_true "${TUNNEL_MODE}"; then
    log "Tunnel mode: skipping WAN 80/443 UFW rules (traffic arrives via outbound tunnel)."
  else
    run ufw allow in on "${WAN_IFACE}" proto tcp to any port 80 comment "coolify-hardening-http"
    run ufw allow in on "${WAN_IFACE}" proto tcp to any port 443 comment "coolify-hardening-https"
  fi

  if is_true "${TAILSCALE_DIRECT_WAN}"; then
    run ufw allow in on "${WAN_IFACE}" proto udp to any port 41641 comment "coolify-hardening-tailscale-direct"
  else
    log "Tailscale direct WAN optimization disabled: keeping WAN UDP 41641 closed (DERP fallback only)."
  fi

  # ICMP is allowed via UFW's default before.rules (ufw allow proto icmp is not supported)

  run ufw --force enable
}
