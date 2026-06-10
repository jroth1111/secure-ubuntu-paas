dokploy_check() {
  if ! command -v docker >/dev/null 2>&1; then
    record "INFO" "dokploy: Docker" "Docker not installed; Dokploy runtime checks skipped"
    return
  fi

  local swarm_state
  swarm_state="$(docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null || true)"
  if [[ "${swarm_state}" == "active" ]]; then
    record "PASS" "dokploy: Docker Swarm active"
  else
    record "FAIL" "dokploy: Docker Swarm active" "state=${swarm_state:-unknown}"
  fi

  local services
  services="$(docker service ls --format '{{.Name}}' 2>/dev/null || true)"
  if grep -qx "dokploy" <<< "${services}"; then
    record "PASS" "dokploy: service present" "dokploy"
  else
    record "FAIL" "dokploy: service present" "dokploy service missing"
  fi

  if grep -qx "dokploy-traefik" <<< "${services}" || grep -qx "traefik" <<< "${services}"; then
    record "PASS" "dokploy: proxy service present"
  else
    record "INFO" "dokploy: proxy service" "Traefik not deployed yet (deployed on first app setup)"
  fi

  local ufw_status
  ufw_status="$(ufw status verbose 2>/dev/null || true)"
  if grep -Eq '^3000/tcp[[:space:]]+on tailscale0[[:space:]]+ALLOW IN' <<< "${ufw_status}"; then
    record "PASS" "dokploy: dashboard UFW tailscale0"
  else
    record "FAIL" "dokploy: dashboard UFW tailscale0" "missing allow on tailscale0 for 3000/tcp"
  fi

  if grep -Eq '^3000/tcp[[:space:]]+(ALLOW|LIMIT) IN[[:space:]]+Anywhere\b|^3000[[:space:]]+(ALLOW|LIMIT) IN[[:space:]]+Anywhere\b' <<< "${ufw_status}"; then
    record "FAIL" "dokploy: dashboard not public" "public UFW allow/limit for 3000 detected"
  else
    record "PASS" "dokploy: dashboard not public"
  fi

  # Docker host publishes :3000 on 0.0.0.0; UFW does not govern published ports.
  # DOCKER-USER must drop WAN traffic to non-web ports before the final RETURN.
  local docker_user_rules
  docker_user_rules="$(iptables -S DOCKER-USER 2>/dev/null || true)"
  if grep -q 'coolify-hardening-wan-drop' <<< "${docker_user_rules}" \
    && grep -q 'coolify-hardening-wan-web' <<< "${docker_user_rules}"; then
    record "PASS" "dokploy: DOCKER-USER WAN drop" "non-80/443 WAN traffic dropped before RETURN"
  else
    record "FAIL" "dokploy: DOCKER-USER WAN drop" "missing coolify-hardening-wan-drop/web rules — published :3000 may be WAN-reachable"
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

  if [[ -f "${block_file}" ]] && grep -q 'zz-hardening-deny-public' "${block_file}"; then
    record "PASS" "dokploy: default dashboard route blocked publicly"
  else
    record "FAIL" "dokploy: default dashboard route blocked publicly" \
      "missing ${block_file} — Dokploy's default localhost router re-exposes the dashboard login on public 80/443"
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
  fi

  # Dokploy installer leaves /etc/dokploy 0777.
  if [[ -d "${dokploy_etc}" ]]; then
    local dokploy_mode
    dokploy_mode="$(stat -c '%a' "${dokploy_etc}" 2>/dev/null || true)"
    if [[ "${dokploy_mode}" =~ ^[0-7]?[0-7][0-5][0-5]$ ]]; then
      record "PASS" "dokploy: /etc/dokploy not world-writable" "mode=${dokploy_mode}"
    else
      record "FAIL" "dokploy: /etc/dokploy not world-writable" "mode=${dokploy_mode:-unknown} — expected 0755"
    fi
  fi

  # Swarm autolock needs an unlock unit that fires on docker restarts
  # (PartOf=docker.service), not only at boot; inline ExecStart shell
  # variables are silently emptied by systemd ${} expansion.
  local autolock unit_file="${DOKPLOY_UNLOCK_UNIT_FILE:-/etc/systemd/system/docker-swarm-unlock.service}"
  local unlock_helper="${DOKPLOY_UNLOCK_HELPER:-/usr/local/sbin/docker-swarm-unlock.sh}"
  autolock="$(docker info 2>/dev/null | grep -i 'Autolock Managers' | awk '{print tolower($NF)}' || true)"
  if [[ "${autolock}" == "true" ]]; then
    if [[ ! -f "${unit_file}" ]]; then
      record "FAIL" "dokploy: swarm auto-unlock unit" "${unit_file} missing while autolock is enabled"
    elif ! grep -q '^PartOf=docker.service' "${unit_file}"; then
      record "FAIL" "dokploy: swarm auto-unlock unit" "PartOf=docker.service missing — unlock will not re-fire on docker restarts"
    elif grep -qE '^ExecStart=.*\$\{' "${unit_file}"; then
      record "FAIL" "dokploy: swarm auto-unlock unit" "ExecStart uses \${...} — systemd expands it before bash; use a helper script"
    elif [[ ! -x "${unlock_helper}" ]]; then
      record "FAIL" "dokploy: swarm auto-unlock unit" "${unlock_helper} missing or not executable"
    else
      record "PASS" "dokploy: swarm auto-unlock unit"
    fi
  fi

  # Swarm control/data plane must be tailnet-only.
  local spec
  for spec in "2377:tcp:mgmt" "7946:tcp:gossip" "7946:udp:gossip" "4789:udp:vxlan"; do
    local port proto label
    port="${spec%%:*}"; proto="$(cut -d: -f2 <<< "${spec}")"; label="${spec##*:}"
    if grep -Eq "^${port}/${proto}[[:space:]]+(ALLOW|LIMIT) IN[[:space:]]+Anywhere\b" <<< "${ufw_status}"; then
      record "FAIL" "dokploy: swarm ${label} ${port}/${proto} not public" "public UFW allow detected"
    elif grep -Eq "^${port}/${proto} on tailscale0[[:space:]]+ALLOW IN" <<< "${ufw_status}"; then
      record "PASS" "dokploy: swarm ${label} ${port}/${proto} tailscale-only"
    else
      record "INFO" "dokploy: swarm ${label} ${port}/${proto}" "no tailscale allow rule (single-node default-deny covers it; multi-node joins need it)"
    fi
  done
}
