dokploy_check() {
  if ! command -v docker >/dev/null 2>&1; then
    record "INFO" "dokploy: Docker" "Docker not installed; Dokploy runtime checks skipped"
    return
  fi

  local swarm_state swarm_node_count=""
  swarm_state="$(docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null || true)"
  if [[ "${swarm_state}" == "active" ]]; then
    record "PASS" "dokploy: Docker Swarm active"
  else
    record "FAIL" "dokploy: Docker Swarm active" "state=${swarm_state:-unknown}"
  fi
  if [[ "${swarm_state}" == "active" ]]; then
    swarm_node_count="$(docker node ls -q 2>/dev/null | sed '/^[[:space:]]*$/d' | wc -l | tr -d '[:space:]' || true)"
  fi

  # A Swarm manager created with the VPS public address advertises that
  # endpoint in join instructions. The managed firewall still blocks WAN
  # 2377/7946/4789, so this is not an active exposure; surface the drift so a
  # future multi-node operator does not weaken the firewall to make a join
  # work. Changing an existing manager address requires a separately approved
  # Swarm reinitialization/maintenance window.
  if [[ "${swarm_state}" == "active" ]] && command -v docker >/dev/null 2>&1; then
    local swarm_advertise_addr swarm_tailscale_ip
    swarm_advertise_addr="$(docker node inspect self --format '{{.ManagerStatus.Addr}}' 2>/dev/null || true)"
    swarm_tailscale_ip="$(tailscale ip -4 2>/dev/null || true)"
    if [[ -n "${swarm_advertise_addr}" && -n "${swarm_tailscale_ip}" \
      && "${swarm_advertise_addr}" == "${swarm_tailscale_ip}:2377" ]]; then
      record "PASS" "dokploy: swarm advertise address" "Tailscale manager endpoint ${swarm_advertise_addr}"
    elif [[ -n "${swarm_advertise_addr}" ]]; then
      record "INFO" "dokploy: swarm advertise address" \
        "${swarm_advertise_addr}; WAN control ports remain blocked; use the Tailscale endpoint for future joins"
    else
      record "INFO" "dokploy: swarm advertise address" "could not inspect the manager endpoint"
    fi
  fi

  local services
  services="$(docker service ls --format '{{.Name}}' 2>/dev/null || true)"
  if grep -qx "dokploy" <<< "${services}"; then
    record "PASS" "dokploy: service present" "dokploy"
  else
    record "FAIL" "dokploy: service present" "dokploy service missing"
  fi

  # Dokploy mounts the Docker socket and has host-root equivalent authority.
  # The operator selected automatic latest-stable updates. Require Swarm's
  # digest-resolved latest tag and, on a live systemd host, fresh updater state.
  if grep -qx "dokploy" <<< "${services}"; then
    local panel_image
    panel_image="$(docker service inspect dokploy --format '{{.Spec.TaskTemplate.ContainerSpec.Image}}' 2>/dev/null || true)"
    if [[ "${panel_image}" =~ ^dokploy/dokploy:latest@sha256:[0-9a-f]{64}$ ]] \
      || { [[ -x /usr/local/sbin/paas-image-provenance ]] \
        && /usr/local/sbin/paas-image-provenance dokploy "${panel_image}" >/dev/null 2>&1; }; then
      record "PASS" "dokploy: panel tracks latest stable" "${panel_image}"
    else
      record "FAIL" "dokploy: panel tracks latest stable" \
        "expected official latest digest or protected tested derivative provenance, got ${panel_image:-unavailable}"
    fi

    if [[ -d /run/systemd/system || "${DOKPLOY_REQUIRE_AUTO_UPDATE_RUNTIME:-false}" == "true" ]]; then
      local update_script="${DOKPLOY_AUTO_UPDATE_SCRIPT:-/usr/local/sbin/dokploy-auto-update}"
      local update_state="${DOKPLOY_AUTO_UPDATE_STATE:-/var/lib/server-hardening/dokploy-update-state}"
      local last_check_epoch="" resolved_image="" state_age="" now_epoch
      if [[ -x "${update_script}" ]] \
        && grep -Fq 'DOKPLOY_IMAGE="dokploy/dokploy:latest"' "${update_script}" \
        && systemctl is-enabled --quiet dokploy-auto-update.timer \
        && systemctl is-active --quiet dokploy-auto-update.timer; then
        record "PASS" "dokploy: latest auto-update timer"
      else
        record "FAIL" "dokploy: latest auto-update timer" \
          "managed latest updater or enabled/active timer is missing"
      fi

      if [[ -f "${update_state}" && ! -L "${update_state}" \
        && "$(stat -c '%a:%U:%G' "${update_state}" 2>/dev/null || true)" == "600:root:root" ]]; then
        last_check_epoch="$(awk -F= '$1=="last_check_epoch" {print substr($0, index($0,"=")+1); exit}' "${update_state}")"
        resolved_image="$(awk -F= '$1=="resolved_image" {print substr($0, index($0,"=")+1); exit}' "${update_state}")"
        now_epoch="$(date +%s)"
        if [[ "${last_check_epoch}" =~ ^[0-9]+$ && "${last_check_epoch}" -le "${now_epoch}" ]]; then
          state_age=$((now_epoch - last_check_epoch))
        fi
      fi
      if [[ "${resolved_image}" == "${panel_image}" && "${state_age}" =~ ^[0-9]+$ \
        && "${state_age}" -le 28800 ]]; then
        record "PASS" "dokploy: latest update freshness" \
          "resolved digest checked ${state_age}s ago"
      else
        record "FAIL" "dokploy: latest update freshness" \
          "protected updater state is missing, stale, or does not match the running image"
      fi

      if grep -Fq 'TRAEFIK_CHANNEL="traefik:v3.7"' "${update_script}" 2>/dev/null \
        && grep -Fq 'POSTGRES_CHANNEL="postgres:16"' "${update_script}" 2>/dev/null \
        && grep -Fq 'Encrypted database backup failed; no updates applied.' "${update_script}" 2>/dev/null; then
        record "PASS" "dokploy: proxy and database patch update policy"
      else
        record "FAIL" "dokploy: proxy and database patch update policy" "same-series patch channels or backup-before-update guard missing"
      fi
      local backup_file="" recorded_postgres="" live_postgres=""
      if [[ "${state_age}" =~ ^[0-9]+$ && "${state_age}" -le 28800 ]]; then
        backup_file="$(awk -F= '$1=="backup_file" {print substr($0,index($0,"=")+1);exit}' "${update_state}")"
        recorded_postgres="$(awk -F= '$1=="postgres_resolved_image" {print substr($0,index($0,"=")+1);exit}' "${update_state}")"
      fi
      live_postgres="$(docker service inspect dokploy-postgres --format '{{.Spec.TaskTemplate.ContainerSpec.Image}}' 2>/dev/null || true)"
      if [[ "${recorded_postgres}" == "${live_postgres}" ]] \
        && { [[ "${recorded_postgres}" =~ ^postgres:16@sha256:[0-9a-f]{64}$ ]] \
          || { [[ -x /usr/local/sbin/paas-image-provenance ]] \
            && /usr/local/sbin/paas-image-provenance postgres "${recorded_postgres}" >/dev/null 2>&1; }; }; then
        record "PASS" "dokploy: PostgreSQL patch receipt matches live image"
      else
        record "FAIL" "dokploy: PostgreSQL patch receipt" "fresh protected PostgreSQL 16 image receipt does not match live service"
      fi
      if [[ "${backup_file}" =~ ^/var/lib/server-hardening/dokploy-backups/dokploy-[0-9]{8}T[0-9]{6}Z\.sql\.gz\.age$ \
        && -s "${backup_file}" && ! -L "${backup_file}" \
        && "$(stat -c '%a:%U:%G' "${backup_file}" 2>/dev/null || true)" == "600:root:root" \
        && "$(head -n 1 "${backup_file}" 2>/dev/null)" == 'age-encryption.org/v1' ]]; then
        record "PASS" "dokploy: encrypted pre-update backup"
      else
        record "FAIL" "dokploy: encrypted pre-update backup" "fresh root-owned encrypted snapshot is missing or unsafe"
      fi
    fi
  fi

  if grep -qx "dokploy-traefik" <<< "${services}" || grep -qx "traefik" <<< "${services}"; then
    record "PASS" "dokploy: proxy service present"
  else
    record "INFO" "dokploy: proxy service" "Traefik not deployed yet (deployed on first app setup)"
  fi

  # Resolve the privileged enrollment state once and use it for both firewall
  # authorization and the final account/TOTP gate.  An unreadable state is
  # treated as incomplete, never as permission to expose the registration UI.
  local pg_cid="" account_table_exists="" account_count="" no2fa=""
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
    fi
  fi

  # The panel and database mount the Docker socket and therefore have
  # host-root-equivalent authority. Keep them on a dedicated control overlay;
  # a workload on the shared application network must not be able to address
  # the panel's container port directly. The live default path is strict; the
  # test/non-live path remains informative unless explicitly forced.
  local control_network_name="dokploy-control-network" control_network_id="" legacy_network_id=""
  local panel_network_ids="" postgres_network_ids="" traefik_network_ids="" network_check_strict="false"
  if [[ "${DOKPLOY_NETWORK_CHECK_STRICT:-false}" == "true" \
    || ( "${dokploy_etc:-/etc/dokploy}" == "/etc/dokploy" \
      && -d "/etc/dokploy" && "$(id -u)" -eq 0 ) ]]; then
    network_check_strict="true"
  fi
  if [[ "${network_check_strict}" == "true" ]] && grep -qx "dokploy" <<< "${services}"; then
    control_network_id="$(docker network inspect --format '{{.Id}}' "${control_network_name}" 2>/dev/null || true)"
    legacy_network_id="$(docker network inspect --format '{{.Id}}' dokploy-network 2>/dev/null || true)"
    panel_network_ids="$(docker service inspect dokploy --format '{{range .Spec.TaskTemplate.Networks}}{{println .Target}}{{end}}' 2>/dev/null || true)"
    if [[ -z "${control_network_id}" ]] \
      || ! grep -Fqx "${control_network_id}" <<< "${panel_network_ids}" \
      || { [[ -n "${legacy_network_id}" ]] && grep -Fqx "${legacy_network_id}" <<< "${panel_network_ids}"; }; then
      record "FAIL" "dokploy: panel control network isolation" \
        "panel must use ${control_network_name} and not dokploy-network"
    else
      record "PASS" "dokploy: panel control network isolation" \
        "panel is not attached to the shared application network"
    fi

    if grep -qx "dokploy-postgres" <<< "${services}"; then
      postgres_network_ids="$(docker service inspect dokploy-postgres --format '{{range .Spec.TaskTemplate.Networks}}{{println .Target}}{{end}}' 2>/dev/null || true)"
      if [[ -z "${control_network_id}" ]] \
        || ! grep -Fqx "${control_network_id}" <<< "${postgres_network_ids}" \
        || { [[ -n "${legacy_network_id}" ]] && grep -Fqx "${legacy_network_id}" <<< "${postgres_network_ids}"; }; then
        record "FAIL" "dokploy: database control network isolation" \
          "database must use ${control_network_name} and not dokploy-network"
      else
        record "PASS" "dokploy: database control network isolation" \
          "database is not attached to the shared application network"
      fi
    fi

    if grep -qx "dokploy-traefik" <<< "${services}" || grep -qx "traefik" <<< "${services}"; then
      traefik_network_ids="$(docker service inspect dokploy-traefik --format '{{range .Spec.TaskTemplate.Networks}}{{println .Target}}{{end}}' 2>/dev/null || true)"
      if [[ -n "${control_network_id}" ]] && grep -Fqx "${control_network_id}" <<< "${traefik_network_ids}"; then
        record "FAIL" "dokploy: proxy outside control network" \
          "Traefik must not join ${control_network_name}"
      else
        record "PASS" "dokploy: proxy outside control network" \
          "Traefik is not attached to the panel control network"
      fi
    fi
  else
    record "INFO" "dokploy: control network isolation" \
      "live control-network membership check deferred outside the target host"
  fi

  local ufw_status enrollment_complete="false" expected_enrollment_source
  ufw_status="$(ufw status verbose 2>/dev/null || true)"
  expected_enrollment_source="${dokploy_enrollment_source_ip:-}"
  if [[ "${account_count}" =~ ^[1-9][0-9]*$ && "${no2fa}" == "0" ]]; then
    enrollment_complete="true"
  fi

  if [[ "${enrollment_complete}" == "true" ]] \
    && grep -Eq '^3000/tcp[[:space:]]+on tailscale0[[:space:]]+ALLOW IN.*dokploy-dashboard-tailscale' <<< "${ufw_status}"; then
    record "PASS" "dokploy: dashboard UFW tailscale0" "enrollment complete; managed tailnet rule active"
  elif [[ "${enrollment_complete}" != "true" \
    && -n "${expected_enrollment_source}" ]] \
    && is_tailscale_ipv4 "${expected_enrollment_source}" \
    && grep -Eq "^3000/tcp[[:space:]]+on tailscale0[[:space:]]+ALLOW IN[[:space:]]+${expected_enrollment_source//./\\.}([[:space:]]|$).*dokploy-enrollment-operator" <<< "${ufw_status}" \
    && ! grep -Eq '^3000/tcp[[:space:]]+on tailscale0[[:space:]]+ALLOW IN.*dokploy-dashboard-tailscale' <<< "${ufw_status}"; then
    record "PASS" "dokploy: dashboard UFW enrollment guard" \
      "first-admin access restricted to operator ${expected_enrollment_source}"
  else
    record "FAIL" "dokploy: dashboard UFW enrollment guard" \
      "expected operator-only rule before admin+TOTP and managed tailscale0 rule only after enrollment"
  fi

  if grep -Eq '^3000/tcp[[:space:]]+(ALLOW|LIMIT) IN[[:space:]]+Anywhere\b|^3000[[:space:]]+(ALLOW|LIMIT) IN[[:space:]]+Anywhere\b' <<< "${ufw_status}"; then
    record "FAIL" "dokploy: dashboard not public" "public UFW allow/limit for 3000 detected"
  else
    record "PASS" "dokploy: dashboard not public"
  fi

  # Tailscale netfilter mode "on" inserts ts-input before UFW and accepts all
  # tailscale0 traffic there. Prove the managed Dokploy chain runs first and
  # that nodivert prevents tailscaled from silently moving its accept ahead of
  # the source-specific dashboard and single-node Swarm policy.
  if [[ "${network_check_strict}" == "true" ]]; then
    local input_rules tailnet_chain tailnet_chain_line ts_input_line tailnet_policy operator_dashboard_rule
    local input_rules6 tailnet_chain6 tailnet_chain_line6 ts_input_line6 tailnet_policy6
    local netfilter_mode="" tailnet_order_ok="false" tailnet_wan_drop_ok="false"
    local tailnet_established_line="" tailnet_privileged_drop_line="" tailnet_dashboard_guard_line=""
    local tailnet_wan_drop_line="" tailnet_wan_drop_rule="" tailnet_return_line=""
    input_rules="$(iptables -S INPUT 2>/dev/null || true)"
    tailnet_chain="$(awk '$1 == "-A" && $2 == "INPUT" && $3 == "-j" && $4 ~ /^SECURE-TAILSCALE-INPUT-[AB]$/ { print $4; exit }' <<< "${input_rules}")"
    tailnet_chain_line="$(awk '$1 == "-A" && $2 == "INPUT" && $3 == "-j" && $4 ~ /^SECURE-TAILSCALE-INPUT-[AB]$/ { print NR; exit }' <<< "${input_rules}")"
    ts_input_line="$(awk '$1 == "-A" && $2 == "INPUT" && $3 == "-j" && $4 == "ts-input" { print NR; exit }' <<< "${input_rules}")"
    tailnet_policy="$(iptables -S "${tailnet_chain:-__missing__}" 2>/dev/null || true)"
    tailnet_established_line="$(grep -n 'dokploy-tailnet-established-ipv4.* -j ACCEPT$' <<< "${tailnet_policy}" | head -1 | cut -d: -f1 || true)"
    tailnet_privileged_drop_line="$(grep -n 'dokploy-tailnet-privileged-tcp-drop-ipv4.* -j DROP$' <<< "${tailnet_policy}" | head -1 | cut -d: -f1 || true)"
    tailnet_dashboard_guard_line="$(grep -n 'dokploy-tailnet-dashboard-guard-ipv4.* -j DROP$' <<< "${tailnet_policy}" | head -1 | cut -d: -f1 || true)"
    tailnet_wan_drop_line="$(grep -n 'dokploy-tailnet-tailscale-wan-drop-ipv4.* -j DROP$' <<< "${tailnet_policy}" | head -1 | cut -d: -f1 || true)"
    tailnet_wan_drop_rule="$(grep 'dokploy-tailnet-tailscale-wan-drop-ipv4.* -j DROP$' <<< "${tailnet_policy}" | head -1 || true)"
    tailnet_return_line="$(grep -n 'dokploy-tailnet-return-ipv4.* -j RETURN$' <<< "${tailnet_policy}" | head -1 | cut -d: -f1 || true)"
    if [[ -n "${tailnet_established_line}" && -n "${tailnet_privileged_drop_line}" ]] \
      && (( tailnet_privileged_drop_line < tailnet_established_line )) \
      && { [[ "${enrollment_complete}" == "true" ]] \
        || { [[ -n "${tailnet_dashboard_guard_line}" ]] \
          && (( tailnet_dashboard_guard_line < tailnet_established_line )); }; }; then
      tailnet_order_ok="true"
    fi
    if is_true "${TAILSCALE_DIRECT_WAN:-false}" \
      || { [[ -n "${tailnet_wan_drop_line}" && -n "${tailnet_return_line}" ]] \
        && (( tailnet_wan_drop_line < tailnet_return_line )) \
        && [[ "${tailnet_wan_drop_rule}" == *"! -i tailscale0"* \
          && "${tailnet_wan_drop_rule}" == *"--dport 41641"* ]]; }; then
      tailnet_wan_drop_ok="true"
    fi
    netfilter_mode="$(tailscale debug prefs 2>/dev/null | jq -r '.NetfilterMode // empty' 2>/dev/null || true)"
    if [[ "${netfilter_mode}" == "1" \
      && -n "${tailnet_chain}" && -n "${tailnet_chain_line}" && -n "${ts_input_line}" \
      && ${tailnet_chain_line:-0} -lt ${ts_input_line:-0} \
      && "${tailnet_policy}" == *"dokploy-tailnet-root-ssh-ipv4"* \
      && "${tailnet_policy}" == *"dokploy-tailnet-privileged-tcp-drop-ipv4"* \
      && "${tailnet_policy}" == *"dokploy-tailnet-swarm-udp-drop-ipv4"* \
      && "${tailnet_policy}" == *"dokploy-tailnet-unmatched-drop-ipv4"* \
      && "${tailnet_order_ok}" == "true" && "${tailnet_wan_drop_ok}" == "true" ]]; then
      record "PASS" "dokploy: effective IPv4 tailnet INPUT policy" \
        "managed chain precedes ts-input with Tailscale nodivert"
    else
      record "FAIL" "dokploy: effective IPv4 tailnet INPUT policy" \
        "expected nodivert=1 and a restrictive managed INPUT jump before ts-input"
    fi

    if [[ "${enrollment_complete}" == "true" ]]; then
      if grep -q 'dokploy-tailnet-dashboard-enrolled-ipv4.* -j ACCEPT$' <<< "${tailnet_policy}" \
        && ! grep -q 'dokploy-tailnet-dashboard-guard-ipv4' <<< "${tailnet_policy}"; then
        record "PASS" "dokploy: effective dashboard tailnet authorization" \
          "enrollment complete; panel accepted through the managed tailnet chain"
      else
        record "FAIL" "dokploy: effective dashboard tailnet authorization" \
          "enrolled dashboard rule is missing from the effective INPUT chain"
      fi
    else
      operator_dashboard_rule="$(grep 'dokploy-tailnet-dashboard-operator-ipv4' <<< "${tailnet_policy}" | head -1 || true)"
    fi
    if [[ "${enrollment_complete}" != "true" && -n "${expected_enrollment_source}" \
      && "${operator_dashboard_rule}" == *"-s ${expected_enrollment_source}/32"* \
      && "${operator_dashboard_rule}" == *"-j ACCEPT"* \
      ]] && grep -q 'dokploy-tailnet-dashboard-guard-ipv4.* -j DROP$' <<< "${tailnet_policy}"; then
      record "PASS" "dokploy: effective dashboard tailnet authorization" \
        "pre-enrollment panel traffic accepted only from ${expected_enrollment_source}"
    elif [[ "${enrollment_complete}" != "true" ]]; then
      record "FAIL" "dokploy: effective dashboard tailnet authorization" \
        "operator source allow and fallback dashboard drop are not both effective"
    fi

    if command -v ip6tables >/dev/null 2>&1; then
      local ipv6_dashboard_policy_ok="false" tailnet_order_ok6="false" tailnet_wan_drop_ok6="false"
      local tailnet_established_line6="" tailnet_privileged_drop_line6="" tailnet_dashboard_guard_line6=""
      local tailnet_wan_drop_line6="" tailnet_wan_drop_rule6="" tailnet_return_line6=""
      input_rules6="$(ip6tables -S INPUT 2>/dev/null || true)"
      tailnet_chain6="$(awk '$1 == "-A" && $2 == "INPUT" && $3 == "-j" && $4 ~ /^SECURE-TAILSCALE-INPUT-[AB]$/ { print $4; exit }' <<< "${input_rules6}")"
      tailnet_chain_line6="$(awk '$1 == "-A" && $2 == "INPUT" && $3 == "-j" && $4 ~ /^SECURE-TAILSCALE-INPUT-[AB]$/ { print NR; exit }' <<< "${input_rules6}")"
      ts_input_line6="$(awk '$1 == "-A" && $2 == "INPUT" && $3 == "-j" && $4 == "ts-input" { print NR; exit }' <<< "${input_rules6}")"
      tailnet_policy6="$(ip6tables -S "${tailnet_chain6:-__missing__}" 2>/dev/null || true)"
      tailnet_established_line6="$(grep -n 'dokploy-tailnet-established-ipv6.* -j ACCEPT$' <<< "${tailnet_policy6}" | head -1 | cut -d: -f1 || true)"
      tailnet_privileged_drop_line6="$(grep -n 'dokploy-tailnet-privileged-tcp-drop-ipv6.* -j DROP$' <<< "${tailnet_policy6}" | head -1 | cut -d: -f1 || true)"
      tailnet_dashboard_guard_line6="$(grep -n 'dokploy-tailnet-dashboard-guard-ipv6.* -j DROP$' <<< "${tailnet_policy6}" | head -1 | cut -d: -f1 || true)"
      tailnet_wan_drop_line6="$(grep -n 'dokploy-tailnet-tailscale-wan-drop-ipv6.* -j DROP$' <<< "${tailnet_policy6}" | head -1 | cut -d: -f1 || true)"
      tailnet_wan_drop_rule6="$(grep 'dokploy-tailnet-tailscale-wan-drop-ipv6.* -j DROP$' <<< "${tailnet_policy6}" | head -1 || true)"
      tailnet_return_line6="$(grep -n 'dokploy-tailnet-return-ipv6.* -j RETURN$' <<< "${tailnet_policy6}" | head -1 | cut -d: -f1 || true)"
      if [[ -n "${tailnet_established_line6}" && -n "${tailnet_privileged_drop_line6}" ]] \
        && (( tailnet_privileged_drop_line6 < tailnet_established_line6 )) \
        && { [[ "${enrollment_complete}" == "true" ]] \
          || { [[ -n "${tailnet_dashboard_guard_line6}" ]] \
            && (( tailnet_dashboard_guard_line6 < tailnet_established_line6 )); }; }; then
        tailnet_order_ok6="true"
      fi
      if is_true "${TAILSCALE_DIRECT_WAN:-false}" \
        || { [[ -n "${tailnet_wan_drop_line6}" && -n "${tailnet_return_line6}" ]] \
          && (( tailnet_wan_drop_line6 < tailnet_return_line6 )) \
          && [[ "${tailnet_wan_drop_rule6}" == *"! -i tailscale0"* \
            && "${tailnet_wan_drop_rule6}" == *"--dport 41641"* ]]; }; then
        tailnet_wan_drop_ok6="true"
      fi
      if [[ "${enrollment_complete}" == "true" ]] \
        && grep -q 'dokploy-tailnet-dashboard-enrolled-ipv6.* -j ACCEPT$' <<< "${tailnet_policy6}"; then
        ipv6_dashboard_policy_ok="true"
      elif [[ "${enrollment_complete}" != "true" ]] \
        && grep -q 'dokploy-tailnet-dashboard-guard-ipv6.* -j DROP$' <<< "${tailnet_policy6}"; then
        ipv6_dashboard_policy_ok="true"
      fi
      if [[ -n "${tailnet_chain6}" && -n "${tailnet_chain_line6}" && -n "${ts_input_line6}" \
        && ${tailnet_chain_line6:-0} -lt ${ts_input_line6:-0} \
        && "${tailnet_policy6}" == *"dokploy-tailnet-root-ssh-ipv6"* \
        && "${tailnet_policy6}" == *"dokploy-tailnet-privileged-tcp-drop-ipv6"* \
        && "${tailnet_policy6}" == *"dokploy-tailnet-swarm-udp-drop-ipv6"* \
        && "${tailnet_policy6}" == *"dokploy-tailnet-unmatched-drop-ipv6"* \
        && "${ipv6_dashboard_policy_ok}" == "true" \
        && "${tailnet_order_ok6}" == "true" && "${tailnet_wan_drop_ok6}" == "true" ]]; then
        record "PASS" "dokploy: effective IPv6 tailnet INPUT policy"
      else
        record "FAIL" "dokploy: effective IPv6 tailnet INPUT policy" \
          "managed IPv6 chain is missing, ordered after ts-input, or lacks fail-closed rules"
      fi
    fi

    local tailnet_filter_script_path="${DOKPLOY_TAILNET_FILTER_SCRIPT:-/usr/local/sbin/dokploy-tailnet-input-hardening}"
    if [[ -x "${tailnet_filter_script_path}" ]] \
      && systemctl is-enabled --quiet dokploy-tailnet-input-hardening.timer \
      && systemctl is-active --quiet dokploy-tailnet-input-hardening.timer; then
      record "PASS" "dokploy: tailnet INPUT policy persistence"
    else
      record "FAIL" "dokploy: tailnet INPUT policy persistence" \
        "hardening script or enabled/active refresh timer is missing"
    fi
  else
    record "INFO" "dokploy: effective tailnet INPUT policy" \
      "live netfilter ordering check deferred outside the target host"
  fi

  # Docker host publishes :3000 on 0.0.0.0; UFW does not govern published ports.
  # DOCKER-USER is a shared hook, so validate the first managed jump and the
  # dedicated chain's control flow rather than comment presence alone.
  local docker_user_rules docker_user_policy first_rule wan_drop_line unmatched_drop_line final_return_line management_drop_line first_bridge_return_line legacy_inline_rules="false" web_rule_present="false"
  local management_tailnet_source_line management_tailnet_drop_line management_tailnet_enrolled_line tailscale_accept_line established_return_line management_drop_rule
  docker_user_rules="$(iptables -t filter -S DOCKER-USER 2>/dev/null || true)"
  docker_user_policy="$(iptables -t filter -S SECURE-DOCKER-USER 2>/dev/null || true)"
  first_rule="$(awk '$1 == "-A" { print; exit }' <<< "${docker_user_rules}")"
  wan_drop_line="$(grep -nE 'coolify-hardening-wan-drop.* -j DROP$' <<< "${docker_user_policy}" | head -1 | cut -d: -f1)"
  unmatched_drop_line="$(grep -nE 'coolify-hardening-unmatched-drop.* -j DROP$' <<< "${docker_user_policy}" | head -1 | cut -d: -f1)"
  management_drop_line="$(grep -nE -- '(^|[[:space:]])-p tcp([[:space:]].*)--ctorigdstport 3000([[:space:]].*)coolify-hardening-management-container-drop([[:space:]].*)-j DROP$' <<< "${docker_user_policy}" | head -1 | cut -d: -f1)"
  management_drop_rule="$(grep -E -- '(^|[[:space:]])-p tcp([[:space:]].*)--ctorigdstport 3000([[:space:]].*)coolify-hardening-management-container-drop([[:space:]].*)-j DROP$' <<< "${docker_user_policy}" | head -1 || true)"
  management_tailnet_source_line="$(grep -nE 'coolify-hardening-management-tailnet-source.* -j ACCEPT$' <<< "${docker_user_policy}" | head -1 | cut -d: -f1 || true)"
  management_tailnet_drop_line="$(grep -nE 'coolify-hardening-management-tailnet-drop.* -j DROP$' <<< "${docker_user_policy}" | head -1 | cut -d: -f1 || true)"
  management_tailnet_enrolled_line="$(grep -nE 'coolify-hardening-management-tailnet-enrolled.* -j ACCEPT$' <<< "${docker_user_policy}" | head -1 | cut -d: -f1 || true)"
  established_return_line="$(grep -nE 'coolify-hardening-estab.* -j RETURN$' <<< "${docker_user_policy}" | head -1 | cut -d: -f1 || true)"
  tailscale_accept_line="$(grep -nE 'coolify-hardening-tailscale.* -j ACCEPT$' <<< "${docker_user_policy}" | head -1 | cut -d: -f1 || true)"
  first_bridge_return_line="$(grep -nE 'coolify-hardening-bridge-.* -j RETURN$' <<< "${docker_user_policy}" | head -1 | cut -d: -f1)"
  final_return_line="$(awk -v chain='SECURE-DOCKER-USER' \
    '$1 == "-A" && $2 == chain && $0 !~ /--ctstate/ && $0 !~ / -i / && $0 ~ / -j RETURN$/ { print NR; exit }' \
    <<< "${docker_user_policy}")"
  if grep -qE '^-A DOCKER-USER .*coolify-hardening-' <<< "${docker_user_rules}"; then
    legacy_inline_rules="true"
  fi
  if grep -qE 'coolify-hardening-wan-web.* -j ACCEPT$' <<< "${docker_user_policy}"; then
    web_rule_present="true"
  fi
  if [[ "${first_rule}" == *"secure-ubuntu-paas-docker-user-jump"* \
    && "${first_rule}" == *"-j SECURE-DOCKER-USER"* \
    && -n "${wan_drop_line}" && -n "${unmatched_drop_line}" && -n "${final_return_line}" \
    && ${wan_drop_line:-0} -lt ${final_return_line:-0} \
    && ${unmatched_drop_line:-0} -lt ${final_return_line:-0} \
    && "${legacy_inline_rules}" == "false" \
    && "${web_rule_present}" == "true" ]]; then
    record "PASS" "dokploy: DOCKER-USER WAN drop" "dedicated policy drops non-80/443 WAN traffic before return"
  else
    record "FAIL" "dokploy: DOCKER-USER WAN drop" \
      "DOCKER-USER must jump first to SECURE-DOCKER-USER with WAN drop before the unconditional return"
  fi
  if [[ -n "${management_drop_line}" && -n "${established_return_line}" && -n "${first_bridge_return_line}" \
    && -n "${unmatched_drop_line}" && ${management_drop_line:-0} -lt ${first_bridge_return_line:-0} \
    && ${management_drop_line:-0} -lt ${established_return_line:-0} \
    && ${management_drop_line:-0} -lt ${unmatched_drop_line:-0} \
    && "${management_drop_rule}" == *"--ctdir ORIGINAL"* \
    && "${management_drop_rule}" != *"--ctstate NEW"* ]]; then
    record "PASS" "dokploy: panel container boundary" \
      "unauthorized 3000/tcp is dropped before established and Docker bridge returns"
  else
    record "FAIL" "dokploy: panel container boundary" \
      "DOCKER-USER must drop original-direction destination port 3000 before established or Docker bridge returns"
  fi
  if [[ "${enrollment_complete}" == "true" ]]; then
    if [[ -n "${management_tailnet_enrolled_line}" && -n "${management_drop_line}" \
      && -n "${established_return_line}" && -z "${management_tailnet_drop_line}" \
      && ${management_tailnet_enrolled_line:-0} -lt ${management_drop_line:-0} \
      && ${management_drop_line:-0} -lt ${established_return_line:-0} ]]; then
      record "PASS" "dokploy: Docker-forwarded dashboard authorization" \
        "enrolled tailnet panel accept precedes the global panel drop and established return"
    else
      record "FAIL" "dokploy: Docker-forwarded dashboard authorization" \
        "stale pre-enrollment tailnet drop remains in DOCKER-USER"
    fi
  elif [[ -n "${management_tailnet_source_line}" && -n "${management_tailnet_drop_line}" \
    && -n "${management_drop_line}" && -n "${established_return_line}" && -n "${tailscale_accept_line}" \
    && ${management_tailnet_source_line:-0} -lt ${management_tailnet_drop_line:-0} \
    && ${management_tailnet_drop_line:-0} -lt ${management_drop_line:-0} \
    && ${management_drop_line:-0} -lt ${established_return_line:-0} \
    && ${established_return_line:-0} -lt ${tailscale_accept_line:-0} ]]; then
    record "PASS" "dokploy: Docker-forwarded dashboard authorization" \
      "operator source allow and fallback drop precede broad tailnet acceptance"
  else
    record "FAIL" "dokploy: Docker-forwarded dashboard authorization" \
      "pre-enrollment source restriction is absent or ordered after broad tailnet acceptance"
  fi

  local listeners
  listeners="$(ss -lntH 2>/dev/null || true)"
  if awk '{print $4}' <<< "${listeners}" | grep -Eq '(^|:|\])3000$'; then
    record "PASS" "dokploy: dashboard listener" "3000/tcp listening"
  else
    record "FAIL" "dokploy: dashboard listener" "3000/tcp not listening"
  fi

  if awk '{print $4}' <<< "${listeners}" | grep -Eq '(^|:|\])2375$|(^|:|\])2376$'; then
    record "FAIL" "dokploy: Docker TCP API closed" "Docker API listener detected"
  else
    record "PASS" "dokploy: Docker TCP API closed"
  fi

  # Panel must never be reachable through public Traefik 80/443.
  #  (a) Setting a real panel domain in Settings → Web Server writes a
  #      Host(<domain>) router in dynamic/dokploy.yml — a hard bypass of the
  #      UFW port-3000 lockdown.
  #  (b) Dokploy's built-in default Host(`dokploy.docker.localhost`) router is
  #      published on the public web/websecure entrypoints too; it is only safe
  #      when the hardening block file shadows and denies it.
  local dokploy_etc="${DOKPLOY_ETC_DIR:-/etc/dokploy}"
  local dyn_dir="${dokploy_etc}/traefik/dynamic"
  local panel_route="${dyn_dir}/dokploy.yml"
  local block_file="${dyn_dir}/zz-hardening-dashboard-block.yml"

  if [[ -f "${panel_route}" ]] \
    && grep -oE 'Host\(`[^`]+`\)' "${panel_route}" | grep -qvE '`[^`]*\.docker\.localhost`'; then
    record "FAIL" "dokploy: panel not on public domain" \
      "a non-default Host router exists in ${panel_route} — clear Settings → Web Server domain; dashboard must stay Tailscale-only on :3000"
  else
    record "PASS" "dokploy: panel not on public domain"
  fi

  local block_file_valid="false" block_file_owner block_file_mode proxy_mounts public_dashboard_code
  block_file_owner="$(stat -c '%U:%G' "${block_file}" 2>/dev/null || true)"
  block_file_mode="$(stat -c '%a' "${block_file}" 2>/dev/null || true)"
  if [[ -f "${block_file}" && ! -L "${block_file}" ]] \
    && [[ "${block_file_owner}" == "root:root" && "${block_file_mode}" == "600" ]] \
    && grep -q 'zz-hardening-dashboard-localhost' "${block_file}" \
    && grep -q 'priority: 100000' "${block_file}" \
    && grep -q 'zz-hardening-deny-public' "${block_file}" \
    && grep -q 'zz-hardening-blackhole' "${block_file}" \
    && grep -q '192.0.2.0/32' "${block_file}"; then
    block_file_valid="true"
  fi
  if [[ "${block_file_valid}" == "true" ]] && grep -qx "dokploy-traefik" <<< "${services}"; then
    proxy_mounts="$(docker service inspect dokploy-traefik --format '{{range .Spec.TaskTemplate.ContainerSpec.Mounts}}{{println .Source "->" .Target}}{{end}}' 2>/dev/null || true)"
    public_dashboard_code="000"
    for dashboard_probe_attempt in 1 2 3 4 5; do
      public_dashboard_code="$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 5 \
        -H 'Host: dokploy.docker.localhost' http://127.0.0.1:80 2>/dev/null || true)"
      public_dashboard_code="${public_dashboard_code:-000}"
      [[ "${public_dashboard_code}" =~ ^[45][0-9][0-9]$ ]] && break
      if (( dashboard_probe_attempt < 5 )); then
        sleep 1
      fi
    done
    if grep -Fq '/etc/dokploy/traefik/dynamic -> /etc/dokploy/traefik/dynamic' <<< "${proxy_mounts}" \
      && [[ "${public_dashboard_code}" =~ ^[45][0-9][0-9]$ ]]; then
      record "PASS" "dokploy: default dashboard route blocked publicly" \
        "validated hardening file, Traefik dynamic mount, and local public probe (HTTP ${public_dashboard_code})"
    else
      record "FAIL" "dokploy: default dashboard route blocked publicly" \
        "hardening marker is not effective (dynamic mount or local public probe failed; HTTP ${public_dashboard_code})"
    fi
  elif [[ "${block_file_valid}" == "true" ]]; then
    record "INFO" "dokploy: default dashboard route blocked publicly" \
      "Traefik service is not deployed yet; validated block file will be checked again when proxy starts"
  else
    record "FAIL" "dokploy: default dashboard route blocked publicly" \
      "missing, incomplete, or unsafe ${block_file} (owner=${block_file_owner:-unknown}, mode=${block_file_mode:-unknown}) — Dokploy's default localhost router may re-expose the dashboard login"
  fi

  # Traefik insecure API/dashboard (:8080) is reachable by any container on
  # dokploy-network when enabled.
  local traefik_yml="${dokploy_etc}/traefik/traefik.yml"
  if [[ -f "${traefik_yml}" ]]; then
    if grep -qE '^[[:space:]]*insecure:[[:space:]]*true' "${traefik_yml}"; then
      record "FAIL" "dokploy: Traefik API not insecure" "api.insecure=true in ${traefik_yml}"
    else
      record "PASS" "dokploy: Traefik API not insecure"
    fi

    # Without an access log the public 80/443 ingress leaves no forensic trail.
    if grep -qE '^accessLog:' "${traefik_yml}"; then
      record "PASS" "dokploy: Traefik access log enabled"
    else
      record "FAIL" "dokploy: Traefik access log enabled" \
        "no accessLog in ${traefik_yml} — public ingress requests are unlogged"
    fi

    # File state is insufficient after a Swarm update: a stale task can keep
    # api.insecure enabled while the mounted file looks hardened. Docker host
    # hardening can intentionally make overlay task IPs unreachable from the
    # host, so inspect listeners from inside the task's network namespace.
    local traefik_container_id="" traefik_pid="" traefik_baseline_code=""
    traefik_container_id="$(docker ps --filter label=com.docker.swarm.service.name=dokploy-traefik --format '{{.ID}}' 2>/dev/null | head -1 || true)"
    if [[ -n "${traefik_container_id}" ]]; then
      traefik_pid="$(docker inspect --format '{{.State.Pid}}' "${traefik_container_id}" 2>/dev/null || true)"
      if [[ "${traefik_pid}" =~ ^[1-9][0-9]*$ ]] \
        && command -v curl >/dev/null 2>&1 \
        && command -v nsenter >/dev/null 2>&1 \
        && command -v ss >/dev/null 2>&1; then
        traefik_baseline_code="$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 5 \
          "http://127.0.0.1:80" 2>/dev/null || true)"
        if [[ "${traefik_baseline_code:-000}" =~ ^[1-5][0-9][0-9]$ \
          ]] && nsenter -t "${traefik_pid}" -n ss -H -lnt 'sport = :80' 2>/dev/null | grep -q . \
          && ! nsenter -t "${traefik_pid}" -n ss -H -lnt 'sport = :8080' 2>/dev/null | grep -q .; then
          record "PASS" "dokploy: Traefik live API disabled" \
            "published HTTP ${traefik_baseline_code}; network namespace listens on 80 and not 8080"
        else
          record "FAIL" "dokploy: Traefik live API disabled" \
            "baseline HTTP=${traefik_baseline_code:-000}; could not prove namespace listener 80 present and 8080 absent"
        fi
      else
        record "FAIL" "dokploy: Traefik live API disabled" \
          "could not inspect the running Traefik task network namespace"
      fi
    fi
  fi

  # The proxy mounts the Docker socket, so a mutable tag or an unexpected
  # digest is an executable-integrity failure even when its version appears
  # current. Accept the reviewed floor or a protected, fresh receipt from the
  # same-minor updater that exercised the live security boundary.
  local expected_traefik_digest="sha256:24841fe2de7304c149343d877d2923b4c8800a38ba015dea9174c23b20e344a0"
  local running_traefik running_traefik_digest proxy_receipt_image="" proxy_receipt_version=""
  local proxy_receipt_file="${DOKPLOY_AUTO_UPDATE_STATE:-/var/lib/server-hardening/dokploy-update-state}"
  local proxy_receipt_epoch="" proxy_receipt_ok="false" proxy_now
  if [[ -f "${proxy_receipt_file}" && ! -L "${proxy_receipt_file}" \
    && "$(stat -c '%a:%U:%G' "${proxy_receipt_file}" 2>/dev/null || true)" == "600:root:root" ]]; then
    proxy_receipt_image="$(awk -F= '$1=="traefik_resolved_image" {print substr($0,index($0,"=")+1);exit}' "${proxy_receipt_file}")"
    proxy_receipt_version="$(awk -F= '$1=="traefik_version" {print substr($0,index($0,"=")+1);exit}' "${proxy_receipt_file}")"
    proxy_receipt_epoch="$(awk -F= '$1=="last_check_epoch" {print substr($0,index($0,"=")+1);exit}' "${proxy_receipt_file}")"
    proxy_now="$(date +%s)"
    if [[ "${proxy_receipt_image}" =~ ^traefik:v3\.7@sha256:[0-9a-f]{64}$ \
      && "${proxy_receipt_version}" =~ ^3\.7\.([0-9]+)$ && "${BASH_REMATCH[1]}" -ge 13 \
      && "${proxy_receipt_epoch}" =~ ^[0-9]+$ && "${proxy_receipt_epoch}" -le "${proxy_now}" \
      && $((proxy_now - proxy_receipt_epoch)) -le 28800 ]]; then
      proxy_receipt_ok="true"
    fi
  fi
  if docker service inspect dokploy-traefik >/dev/null 2>&1; then
    running_traefik="$(docker service inspect dokploy-traefik --format '{{.Spec.TaskTemplate.ContainerSpec.Image}}' 2>/dev/null || true)"
    running_traefik_digest="${running_traefik##*@}"
    if { [[ "${running_traefik}" =~ ^traefik(@sha256:|:v3\.7\.13@sha256:) \
      && "${running_traefik_digest}" == "${expected_traefik_digest}" ]]; } \
      || { [[ "${proxy_receipt_ok}" == "true" && "${running_traefik}" == "${proxy_receipt_image}" ]]; }; then
      record "PASS" "dokploy: Traefik immutable image" "running ${running_traefik}"
    else
      record "FAIL" "dokploy: Traefik immutable image" \
        "expected Traefik digest ${expected_traefik_digest}, got ${running_traefik:-unknown}"
    fi
  fi

  # Registration and TOTP require operator-chosen credentials and cannot be
  # safely automated, but they are mandatory provisioning gates.  The staged
  # UFW policy above keeps the unclaimed page bound to the intended operator.
  if [[ -n "${pg_cid}" ]]; then
    if [[ "${account_table_exists}" == "1" ]]; then
      if [[ "${account_count}" =~ ^[1-9][0-9]*$ ]]; then
        record "PASS" "dokploy: first admin registered" "${account_count} panel account(s)"
        if [[ "${no2fa}" == "0" ]]; then
          record "PASS" "dokploy: panel accounts use 2FA"
        elif [[ "${no2fa}" =~ ^[0-9]+$ ]]; then
          record "FAIL" "dokploy: panel accounts use 2FA" \
            "${no2fa} account(s) without 2FA — enable TOTP under panel Profile → 2FA"
        else
          record "FAIL" "dokploy: panel accounts use 2FA" "could not query the dokploy database"
        fi
      elif [[ "${account_count}" == "0" ]]; then
        record "FAIL" "dokploy: first admin registered" \
          "no panel account exists — registration remains restricted to the provisioning operator"
        record "FAIL" "dokploy: panel accounts use 2FA" \
          "no panel account exists — create the first admin and enable TOTP before completion"
      else
        record "FAIL" "dokploy: first admin registered" "could not query the dokploy database"
        record "FAIL" "dokploy: panel accounts use 2FA" "could not query the dokploy database"
      fi
    else
      record "FAIL" "dokploy: first admin registered" \
        "account table is unavailable — enrollment cannot be verified"
      record "FAIL" "dokploy: panel accounts use 2FA" \
        "account table is unavailable — TOTP enrollment cannot be verified"
    fi
  else
    record "FAIL" "dokploy: first admin registered" "Dokploy PostgreSQL container is not running"
    record "FAIL" "dokploy: panel accounts use 2FA" "Dokploy PostgreSQL container is not running"
  fi

  # Dokploy installer leaves /etc/dokploy 0777. Validate the complete mounted
  # configuration tree, not just the root directory: Traefik consumes every
  # descendant and also has Docker-socket authority. Regular files are
  # sensitive by default because future Dokploy versions or operator-managed
  # certificates may add secrets whose names this validator does not know.
  if [[ -d "${dokploy_etc}" ]]; then
    local dokploy_mode unsafe_dokploy_entry
    dokploy_mode="$(stat -c '%a' "${dokploy_etc}" 2>/dev/null || true)"
    if [[ "${dokploy_mode}" =~ ^[0-7]?[0-7][0-5][0-5]$ ]]; then
      record "PASS" "dokploy: /etc/dokploy not world-writable" "mode=${dokploy_mode}"
    else
      record "FAIL" "dokploy: /etc/dokploy not world-writable" "mode=${dokploy_mode:-unknown} — expected 0755"
    fi
    if [[ "${DOKPLOY_CONFIG_OWNERSHIP_CHECK:-auto}" == "true" \
      || "${dokploy_etc}" == "/etc/dokploy" || "$(id -u)" -eq 0 ]]; then
      unsafe_dokploy_entry="$(find -P "${dokploy_etc}" -xdev -mindepth 1 \
        \( -type l -o ! \( -type f -o -type d \) -o ! -user root -o ! -group root \
          -o \( -type d -perm /022 \) -o \( -type f -perm /077 \) \) \
        -print -quit 2>/dev/null || true)"
      if [[ -z "${unsafe_dokploy_entry}" ]]; then
        record "PASS" "dokploy: config tree descendants secure"
      else
        record "FAIL" "dokploy: config tree descendants secure" \
          "unsafe symlink, file type, owner, group, writable directory, or group/other-accessible file: ${unsafe_dokploy_entry}"
      fi
    else
      record "INFO" "dokploy: config tree descendants secure" \
        "ownership check deferred outside a root-owned live host"
    fi
  fi

  # Swarm autolock protects manager state at rest. The unlock key must be held
  # outside the VPS; a same-host key and automatic unit would defeat the disk
  # protection after theft of a snapshot or manager filesystem.
  local autolock unlock_key_file="${DOKPLOY_UNLOCK_KEY_FILE:-/root/.docker/swarm-unlock-key}"
  local unit_file="${DOKPLOY_UNLOCK_UNIT_FILE:-/etc/systemd/system/docker-swarm-unlock.service}"
  local unlock_helper="${DOKPLOY_UNLOCK_HELPER:-/usr/local/sbin/docker-swarm-unlock.sh}"
  local unlock_handoff="${DOKPLOY_UNLOCK_HANDOFF_FILE:-/run/secure-ubuntu-paas-dokploy-swarm-unlock-key}"
  autolock="$(docker info 2>/dev/null | grep -i 'Autolock Managers' | awk '{print tolower($NF)}' || true)"
  if [[ "${autolock}" == "true" ]]; then
    if [[ -e "${unlock_handoff}" || -L "${unlock_handoff}" ]]; then
      record "FAIL" "dokploy: swarm autolock external key" \
        "one-time unlock handoff remains on the VPS at ${unlock_handoff}"
    elif [[ -e "${unlock_key_file}" || -L "${unlock_key_file}" ]]; then
      record "FAIL" "dokploy: swarm autolock external key" \
        "persistent unlock material exists at ${unlock_key_file}"
    elif [[ -e "${unit_file}" || -L "${unit_file}" || -e "${unlock_helper}" || -L "${unlock_helper}" ]]; then
      record "FAIL" "dokploy: swarm autolock external key" \
        "same-host automatic unlock mechanism remains installed"
    else
      record "PASS" "dokploy: swarm autolock external key" \
        "no persistent same-host unlock key or automatic unlock unit"
    fi
  elif [[ "${autolock}" == "false" ]]; then
    if [[ -f /usr/local/sbin/paas-recovery-policy && ! -L /usr/local/sbin/paas-recovery-policy \
      && "$(stat -c '%a:%U:%G' /usr/local/sbin/paas-recovery-policy 2>/dev/null)" == '700:root:root' ]] \
      && python3 /usr/local/sbin/paas-recovery-policy >/dev/null 2>&1; then
      record "PASS" "dokploy: approved unattended recovery policy" "explicit root-owned policy permits disabled autolock"
      record "INFO" "dokploy: swarm at-rest tradeoff" "automatic startup accepted; no off-server unlock password protects the stored manager key"
    else
      record "FAIL" "dokploy: swarm autolock enabled" "autolock is disabled without a protected explicit unattended-recovery approval"
    fi
  else
    record "INFO" "dokploy: swarm autolock enabled" "Docker did not report manager autolock status"
  fi

  # A single-node Swarm has no legitimate remote control/data-plane caller.
  # Keep these ports closed even to the tailnet; broad tailnet exposure turns
  # every compromised peer into a caller of privileged Swarm listeners. A
  # future multi-node deployment must use separately approved source-scoped
  # rules rather than restoring the historical all-tailnet policy.
  local spec
  for spec in "2377:tcp:mgmt" "7946:tcp:gossip" "7946:udp:gossip" "4789:udp:vxlan"; do
    local port proto label
    port="${spec%%:*}"; proto="$(cut -d: -f2 <<< "${spec}")"; label="${spec##*:}"
    if grep -Eq "^${port}(/${proto})?[[:space:]]+(ALLOW|LIMIT) IN[[:space:]]+Anywhere\b" <<< "${ufw_status}"; then
      record "FAIL" "dokploy: swarm ${label} ${port}/${proto} not public" "public UFW allow detected"
    elif grep -Eq "^${port}/${proto} on tailscale0[[:space:]]+ALLOW IN" <<< "${ufw_status}"; then
      if [[ "${swarm_node_count}" == "1" ]]; then
        record "FAIL" "dokploy: swarm ${label} ${port}/${proto} closed" \
          "single-node Swarm is unnecessarily open to all tailnet peers"
      else
        record "INFO" "dokploy: swarm ${label} ${port}/${proto} tailscale-only" \
          "multi-node or unknown topology; verify every permitted source is an approved Swarm node"
      fi
    else
      record "PASS" "dokploy: swarm ${label} ${port}/${proto} closed" \
        "no public or all-tailnet allow rule"
    fi
  done
}
