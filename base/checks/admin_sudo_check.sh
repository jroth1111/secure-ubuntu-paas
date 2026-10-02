admin_sudo_check() {
  # Skip if no admin user configured
  if [[ -z "${ADMIN_USER}" ]]; then
    record "INFO" "admin: sudo" "no admin user in state file"
    return 0
  fi

  # Check if admin user exists
  if ! id "${ADMIN_USER}" >/dev/null 2>&1; then
    record "FAIL" "admin: user" "${ADMIN_USER} does not exist"
    return 0
  fi

  local sudoers_file="/etc/sudoers.d/${ADMIN_USER}"
  if [[ "${PAAS:-}" == "dokploy" ]]; then
    # Dokploy privileged orchestration uses root@Tailscale with the supplied
    # key. The named operator account must not retain a sudo escalation path
    # through any effective sudoers source, not merely the conventional sudo
    # group or one managed drop-in.
    local sudo_state_rc
    if sudo_effective_grant_state "${ADMIN_USER}"; then
      record "FAIL" "admin: no privileged sudo" \
        "${ADMIN_USER} has an effective sudo grant (group or sudoers policy)"
    else
      sudo_state_rc=$?
      if (( sudo_state_rc == 1 )); then
        record "PASS" "admin: no privileged sudo" \
          "effective sudo policy explicitly denies ${ADMIN_USER}"
      else
        record "FAIL" "admin: no privileged sudo" \
          "unable to determine effective sudo policy for ${ADMIN_USER}; refusing to treat it as non-privileged"
      fi
    fi

    local admin_shell admin_pw_status home_dir auth_file
    admin_shell="$(getent passwd "${ADMIN_USER}" | cut -d: -f7 2>/dev/null || true)"
    admin_pw_status="$(passwd -S "${ADMIN_USER}" 2>/dev/null | awk '{print $2}' || true)"
    home_dir="$(getent passwd "${ADMIN_USER}" | cut -d: -f6 2>/dev/null || true)"
    auth_file="${home_dir}/.ssh/authorized_keys"
    if [[ "${admin_shell}" == "/usr/sbin/nologin" ]]; then
      record "PASS" "admin: Dokploy metadata account shell disabled"
    else
      record "FAIL" "admin: Dokploy metadata account shell disabled" \
        "expected /usr/sbin/nologin, got ${admin_shell:-unknown}"
    fi
    if [[ "${admin_pw_status}" == "L" ]]; then
      record "PASS" "admin: Dokploy metadata account password locked"
    else
      record "FAIL" "admin: Dokploy metadata account password locked" \
        "expected L, got ${admin_pw_status:-unknown}"
    fi
    if [[ ! -s "${auth_file}" ]]; then
      record "PASS" "admin: Dokploy metadata account has no SSH keys"
    else
      record "FAIL" "admin: Dokploy metadata account has no SSH keys" \
        "${auth_file} is non-empty; root must be the sole SSH principal"
    fi
    return 0
  else
    # Legacy non-Dokploy orchestrators execute remote scripts through
    # admin@TS_IP sudo and therefore require passwordless sudo.
    if id -nG "${ADMIN_USER}" | tr ' ' '\n' | grep -qx "sudo"; then
      record "PASS" "admin: in sudo group"
    else
      record "FAIL" "admin: sudo group" "${ADMIN_USER} not in sudo group"
      return 0
    fi

    if [[ -f "${sudoers_file}" ]]; then
      if grep -q "NOPASSWD" "${sudoers_file}" 2>/dev/null; then
        record "PASS" "admin: passwordless sudo"
      else
        record "FAIL" "admin: sudo" "sudoers file exists but NOPASSWD not set — ssh_admin_sudo will hang"
      fi
    else
      # Check if sudo -l shows NOPASSWD for this user
      if sudo -l -U "${ADMIN_USER}" 2>/dev/null | grep -q "NOPASSWD"; then
        record "PASS" "admin: passwordless sudo (via other config)"
      else
        record "FAIL" "admin: sudo" "NOPASSWD not configured — ssh_admin_sudo will hang"
      fi
    fi
  fi

  # Check admin authorized_keys: file must exist, be non-empty, and each key must be
  # on its own line. The concatenation bug (missing trailing newline on a prior key)
  # would still allow sudo to work while silently breaking SSH login.
  local home_dir auth_file
  home_dir="$(getent passwd "${ADMIN_USER}" | cut -d: -f6 2>/dev/null)" || true
  auth_file="${home_dir}/.ssh/authorized_keys"
  if [[ ! -f "${auth_file}" ]]; then
    record "FAIL" "admin: authorized_keys exists" "${auth_file} not found"
  elif [[ ! -s "${auth_file}" ]]; then
    record "FAIL" "admin: authorized_keys non-empty" "${auth_file} is empty"
  else
    # Allow valid key lines with optional OpenSSH options prefix:
    # from="...",command="...",no-agent-forwarding,... ssh-ed25519 AAAA...
    # Flag only lines that do not contain a recognized key type token.
    local bad_lines
    bad_lines="$(
      awk '
        /^[[:space:]]*($|#)/ { next }
        /(^|[[:space:]])(ssh-[^[:space:]]+|ecdsa-sha2-[^[:space:]]+|sk-[^[:space:]]+)[[:space:]]+/ { next }
        { bad++ }
        END { print bad + 0 }
      ' "${auth_file}" 2>/dev/null
    )" || bad_lines="0"
    if [[ "${bad_lines}" -eq 0 ]]; then
      record "PASS" "admin: authorized_keys format"
    else
      record "FAIL" "admin: authorized_keys format" \
        "${bad_lines} line(s) do not start with a valid key type (possible concatenation bug)"
    fi
  fi
}
