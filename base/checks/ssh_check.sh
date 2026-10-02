ssh_check() {
  local effective
  effective="$(sshd -T 2>/dev/null)" || { record "FAIL" "ssh: sshd -T" "cannot query"; return; }

  local field val expected
  declare -A ssh_expects=(
    [permitrootlogin]="no"
    [passwordauthentication]="no"
    [kbdinteractiveauthentication]="no"
    [pubkeyauthentication]="yes"
    [authenticationmethods]="publickey"
    [permitemptypasswords]="no"
    [compression]="no"
  )

  for field in "${!ssh_expects[@]}"; do
    expected="${ssh_expects[${field}]}"
    val="$(grep -m1 "^${field} " <<< "${effective}" | awk '{print $2}')"
    if [[ "${val}" == "${expected}" ]]; then
      record "PASS" "ssh: ${field}=${val}"
    else
      record "FAIL" "ssh: ${field}" "expected ${expected}, got ${val:-<empty>}"
    fi
  done

  if grep -q "chacha20-poly1305@openssh.com" <<< "${effective}"; then
    record "PASS" "ssh: cipher restrictions present"
  else
    record "FAIL" "ssh: cipher restrictions" "chacha20-poly1305 not in ciphers"
  fi

  if grep -q "sntrup761x25519-sha512@openssh.com" <<< "${effective}"; then
    record "PASS" "ssh: post-quantum KEX algorithm present"
  else
    record "FAIL" "ssh: post-quantum KEX algorithm" "sntrup761x25519-sha512@openssh.com not in kexalgorithms"
  fi

  if [[ -n "${ADMIN_USER}" ]]; then
    if [[ "${PAAS}" == "dokploy" ]] \
      && grep -qE '^allowusers .*\broot\b' <<< "${effective}" \
      && ! grep -qE "^allowusers .*\\b${ADMIN_USER}\\b" <<< "${effective}"; then
      record "PASS" "ssh: Dokploy AllowUsers is root-only"
    elif [[ "${PAAS}" == "dokploy" ]]; then
      record "FAIL" "ssh: Dokploy AllowUsers is root-only" \
        "expected root and no ${ADMIN_USER} in the effective AllowUsers policy"
    elif grep -qE "^allowusers .*\\b${ADMIN_USER}\\b" <<< "${effective}"; then
      record "PASS" "ssh: AllowUsers includes ${ADMIN_USER}"
    else
      record "FAIL" "ssh: AllowUsers" "${ADMIN_USER} not listed"
    fi
  fi

  # Match Address carve-outs: Coolify needs root key-only login from
  # localhost/Docker bridge CIDRs; Dokploy permits the emergency root key
  # only from the Tailscale source range; dFlow has neither path.
  local match_local
  match_local="$(sshd -T -C addr=127.0.0.1,user=root,host=localhost,laddr=127.0.0.1 2>/dev/null)" || true
  if [[ "${PAAS}" != "coolify" ]]; then
    if [[ -n "${match_local}" ]] && grep -qE "^permitrootlogin (prohibit-password|without-password|yes)$" <<< "${match_local}"; then
      record "FAIL" "ssh: no root Match carve-out" "localhost/bridge root login permitted — Coolify-only path active for PAAS=${PAAS}"
    else
      record "PASS" "ssh: no root Match carve-out"
    fi
  fi
  if [[ "${PAAS}" == "coolify" && -n "${match_local}" ]]; then
    local match_root_val
    match_root_val="$(grep -m1 "^permitrootlogin " <<< "${match_local}" | awk '{print $2}')"
    if grep -qE "^permitrootlogin (prohibit-password|without-password)$" <<< "${match_local}"; then
      record "PASS" "ssh: Match localhost root=prohibit-password"
    else
      record "FAIL" "ssh: Match localhost root" "expected prohibit-password/without-password, got ${match_root_val:-<empty>}"
    fi

    if grep -qE "^allowusers .*\\broot\\b" <<< "${match_local}"; then
      record "PASS" "ssh: Match localhost AllowUsers includes root"
    else
      record "FAIL" "ssh: Match localhost AllowUsers" "root not listed"
    fi
  fi

  if [[ "${PAAS}" == "dokploy" ]]; then
    local tailscale_ip match_tailscale match_root_val
    tailscale_ip="$(tailscale ip -4 2>/dev/null || true)"
    match_tailscale=""
    if [[ -n "${tailscale_ip}" ]]; then
      match_tailscale="$(sshd -T -C "addr=${tailscale_ip},user=root,host=localhost,laddr=${tailscale_ip}" 2>/dev/null)" || true
    fi
    match_root_val="$(grep -m1 '^permitrootlogin ' <<< "${match_tailscale}" | awk '{print $2}')"
    if [[ -n "${tailscale_ip}" ]] \
      && grep -qE '^permitrootlogin (prohibit-password|without-password)$' <<< "${match_tailscale}" \
      && grep -qE '^allowusers .*\broot\b' <<< "${match_tailscale}" \
      && ! grep -qE "^allowusers .*\\b${ADMIN_USER}\\b" <<< "${match_tailscale}" \
      && grep -q '^passwordauthentication no$' <<< "${match_tailscale}" \
      && grep -q '^kbdinteractiveauthentication no$' <<< "${match_tailscale}" \
      && grep -q '^authenticationmethods publickey$' <<< "${match_tailscale}"; then
      record "PASS" "ssh: Dokploy root key access is Tailscale-only"
    else
      record "FAIL" "ssh: Dokploy root key access is Tailscale-only" \
        "expected root-only AllowUsers with prohibit-password and publickey-only authentication, got permitrootlogin=${match_root_val:-<empty>}"
    fi
  fi

  # When socket activation is installed, verify that its listeners use the
  # same configured SSH port as sshd and remain bound only to Tailscale and
  # localhost. This prevents a custom SSH_PORT from silently restoring a
  # public 22/tcp listener through ssh.socket.
  local socket_dropin="${SSH_SOCKET_DROPIN:-/etc/systemd/system/ssh.socket.d/10-bind-tailscale.conf}"
  if [[ -f "${socket_dropin}" ]]; then
    local socket_ok="true" socket_expected socket_tailscale_ip="${TAILSCALE_IP:-}"
    if [[ -z "${socket_tailscale_ip}" ]] && command -v tailscale >/dev/null 2>&1; then
      socket_tailscale_ip="$(tailscale ip -4 2>/dev/null || true)"
    fi
    for socket_expected in \
      "${socket_tailscale_ip}:${SSH_PORT}" \
      "127.0.0.1:${SSH_PORT}" \
      "[::1]:${SSH_PORT}"; do
      if ! grep -Fqx "ListenStream=${socket_expected}" "${socket_dropin}"; then
        socket_ok="false"
      fi
    done
    if grep -Eq '^ListenStream=0\.0\.0\.0:|^ListenStream=\[::\]:' "${socket_dropin}"; then
      socket_ok="false"
    fi
    if [[ "${socket_ok}" == "true" ]]; then
      record "PASS" "ssh: socket listener port and binding" "${socket_dropin} matches ${SSH_PORT}/tcp and Tailscale/localhost bindings"
    else
      record "FAIL" "ssh: socket listener port and binding" "${socket_dropin} does not match SSH_PORT=${SSH_PORT} or contains a public listener"
    fi
  fi

  {
    # Root password should be locked
    local root_pw_status
    root_pw_status="$(passwd -S root 2>/dev/null | awk '{print $2}')" || true
    if [[ "${root_pw_status}" == "L" ]]; then
      record "PASS" "ssh: root password locked"
    elif [[ -n "${root_pw_status}" ]]; then
      record "FAIL" "ssh: root password locked" "expected L (locked), got ${root_pw_status}"
    fi

    # Dokploy deliberately retains only the supplied admin key for emergency
    # root access over Tailscale. Other PaaS modes clear provider keys.
    local root_auth="/root/.ssh/authorized_keys"
    if [[ -f "${root_auth}" ]]; then
      local root_auth_mode
      root_auth_mode="$(stat -c '%a' "${root_auth}" 2>/dev/null || true)"
      if [[ "${PAAS}" == "dokploy" ]]; then
        if [[ -s "${root_auth}" && "${root_auth_mode}" == "600" ]]; then
          record "PASS" "ssh: Dokploy root authorized_keys restricted to Tailscale policy"
        else
          record "FAIL" "ssh: Dokploy root authorized_keys restricted to Tailscale policy" \
            "expected a non-empty mode-600 root key file, got mode=${root_auth_mode:-<empty>}"
        fi
      elif [[ ! -s "${root_auth}" ]] || grep -qE "^[[:space:]]*$" "${root_auth}" && ! grep -qE "[^[:space:]]" "${root_auth}"; then
        record "PASS" "ssh: root authorized_keys empty"
      else
        record "FAIL" "ssh: root authorized_keys empty" "file contains keys — provisioning artifacts not cleaned"
      fi
    elif [[ "${PAAS}" == "dokploy" ]]; then
      record "FAIL" "ssh: Dokploy root authorized_keys restricted to Tailscale policy" \
        "${root_auth} missing"
    fi

    # DSA host key should not exist (deprecated)
    if [[ ! -f /etc/ssh/ssh_host_dsa_key ]]; then
      record "PASS" "ssh: no deprecated DSA host key"
    else
      record "FAIL" "ssh: DSA host key" "/etc/ssh/ssh_host_dsa_key exists — deprecated and should be removed"
    fi
  }

  local ssh_dropin docker_match_dropin match_line cidr
  ssh_dropin="/etc/ssh/sshd_config.d/00-base-hardening.conf"
  docker_match_dropin="/etc/ssh/sshd_config.d/15-docker-ssh-match.conf"

  # Docker bridge match dropin: required for Coolify, forbidden otherwise.
  if [[ "${PAAS}" == "coolify" ]]; then
    if [[ -f "${docker_match_dropin}" ]]; then
      match_line="$(grep -m1 '^Match Address ' "${docker_match_dropin}" || true)"
      if [[ -n "${match_line}" ]]; then
        while IFS= read -r cidr; do
          if grep -qE "(^|,|[[:space:]])$(regex_escape "${cidr}")($|,|[[:space:]])" <<< "${match_line}"; then
            record "PASS" "ssh: Match includes Docker CIDR ${cidr}"
          else
            record "FAIL" "ssh: Match Docker CIDR ${cidr}" "missing from ${docker_match_dropin}"
          fi
        done < <(load_docker_ssh_cidrs)
      else
        record "FAIL" "ssh: Docker match dropin" "Match Address block missing in ${docker_match_dropin}"
      fi
    else
      record "FAIL" "ssh: Docker match dropin" "${docker_match_dropin} not found"
    fi
  else
    if [[ -f "${docker_match_dropin}" ]]; then
      record "FAIL" "ssh: Docker match dropin absent" "${docker_match_dropin} exists — Coolify-only root-over-bridge path must be removed for PAAS=${PAAS}"
    else
      record "PASS" "ssh: Docker match dropin absent"
    fi
  fi

  if [[ -f "${ssh_dropin}" ]]; then
    if grep -q '^Ciphers \^' "${ssh_dropin}"; then
      record "PASS" "ssh: Ciphers policy uses operator mode"
    else
      record "FAIL" "ssh: Ciphers policy mode" "expected '^' operator to preserve OpenSSH defaults"
    fi

    if grep -q '^MACs \^' "${ssh_dropin}"; then
      record "PASS" "ssh: MACs policy uses operator mode"
    else
      record "FAIL" "ssh: MACs policy mode" "expected '^' operator to preserve OpenSSH defaults"
    fi

    if grep -q '^KexAlgorithms \^' "${ssh_dropin}"; then
      record "PASS" "ssh: KexAlgorithms policy uses operator mode"
    else
      record "FAIL" "ssh: KexAlgorithms policy mode" "expected '^' operator to preserve OpenSSH defaults"
    fi

    if grep -q '^HostKeyAlgorithms \^' "${ssh_dropin}"; then
      record "PASS" "ssh: HostKeyAlgorithms policy uses operator mode"
    else
      record "FAIL" "ssh: HostKeyAlgorithms policy mode" "expected '^' operator to preserve OpenSSH defaults"
    fi
  else
    record "FAIL" "ssh: base hardening dropin" "${ssh_dropin} not found"
  fi

  # Verify external addresses still deny root
  local match_external
  match_external="$(sshd -T -C addr=203.0.113.1,user=root,host=example.com,laddr=0.0.0.0 2>/dev/null)" || true
  if [[ -n "${match_external}" ]]; then
    local ext_root_val
    ext_root_val="$(grep -m1 "^permitrootlogin " <<< "${match_external}" | awk '{print $2}')"
    if [[ "${ext_root_val}" == "no" ]]; then
      record "PASS" "ssh: external root login denied"
    else
      record "FAIL" "ssh: external root login" "expected no, got ${ext_root_val:-<empty>}"
    fi
  fi
}
