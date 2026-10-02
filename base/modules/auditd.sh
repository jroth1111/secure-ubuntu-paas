build_audit_rules() {
  # Modern syscall-form rules — higher performance than legacy -w syntax.
  # File watches use: -a always,exit -F path=... -F perm=wa
  # Dir  watches use: -a always,exit -F dir=...  -F perm=wa
  # Exec watches use: -a always,exit -F path=... -F perm=x
  cat <<'EOF'
# Managed by bootstrap hardening (syscall-form)
# Identity files
-a always,exit -F path=/etc/passwd -F perm=wa -k identity
-a always,exit -F path=/etc/shadow -F perm=wa -k identity
-a always,exit -F path=/etc/group -F perm=wa -k identity
-a always,exit -F path=/etc/gshadow -F perm=wa -k identity
# SSH config
-a always,exit -F path=/etc/ssh/sshd_config -F perm=wa -k sshd-config
-a always,exit -F dir=/etc/ssh/sshd_config.d -F perm=wa -k sshd-config
# Time
-a always,exit -F path=/etc/localtime -F perm=wa -k time-change
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change
# Network / locale
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
# Sudoers
-a always,exit -F path=/etc/sudoers -F perm=wa -k sudoers-change
-a always,exit -F dir=/etc/sudoers.d -F perm=wa -k sudoers-change
# Kernel module loading (important for container hosts)
-a always,exit -F path=/etc/modules -F perm=wa -k kernel-module
-a always,exit -F dir=/etc/modprobe.d -F perm=wa -k kernel-module
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -F auid>=1000 -F auid!=unset -k kernel-module
-a always,exit -F arch=b32 -S init_module,finit_module,delete_module -F auid>=1000 -F auid!=unset -k kernel-module
# User command tracking — forensic attribution via auid
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=unset -k user_commands
-a always,exit -F arch=b32 -S execve -F auid>=1000 -F auid!=unset -k user_commands
# Dokploy operators authenticate directly as root (auid=0). Excluding these
# sessions would omit the primary operator's commands from the audit trail.
-a always,exit -F arch=b64 -S execve -F auid=0 -k root_commands
-a always,exit -F arch=b32 -S execve -F auid=0 -k root_commands
# Prevent a process from changing its loginuid after it has been assigned.
# This preserves audit attribution across privilege transitions.
--loginuid-immutable
EOF

  local bin
  for bin in /usr/bin/docker /usr/bin/dockerd /usr/bin/containerd; do
    if [[ -e "${bin}" ]]; then
      printf -- "-a always,exit -F path=%s -F perm=x -k container-runtime\n" "${bin}"
    fi
  done

  local path
  for path in /var/run/docker.sock /etc/docker/; do
    if [[ -e "${path}" ]]; then
      if [[ -d "${path}" ]]; then
        printf -- "-a always,exit -F dir=%s -F perm=wa -k docker-config\n" "${path%/}"
      else
        printf -- "-a always,exit -F path=%s -F perm=wa -k docker-config\n" "${path}"
      fi
    fi
  done

  # Lock the loaded policy against runtime deletion or weakening. This must
  # remain the final rule; auditd accepts configuration changes again only
  # after a reboot, which is the intended maintenance boundary.
  printf '%s\n' '-e 2'
}

set_auditd_conf_kv() {
  local key="$1"
  local value="$2"

  [[ -f "${AUDITD_CONF_FILE}" ]] || return 0

  if grep -qE "^[[:space:]]*${key}[[:space:]]*=" "${AUDITD_CONF_FILE}"; then
    run sed -i -E "s|^[[:space:]]*${key}[[:space:]]*=.*|${key} = ${value}|" "${AUDITD_CONF_FILE}"
  else
    if is_true "${DRY_RUN}"; then
      log "DRY-RUN: append '${key} = ${value}' to ${AUDITD_CONF_FILE}"
    else
      printf '%s = %s\n' "${key}" "${value}" >> "${AUDITD_CONF_FILE}"
    fi
  fi
}

configure_auditd_policy() {
  if [[ ! -f "${AUDITD_CONF_FILE}" ]]; then
    warn "${AUDITD_CONF_FILE} not found; skipping auditd failure-policy tuning."
    return 0
  fi

  # Keep execve attribution bounded.  The managed rules intentionally record
  # user commands, but an unbounded keep_logs policy lets a local workload fill
  # the filesystem and eventually suspend audit or other security services.
  # 50 MB x 10 rotated files is a bounded forensic window. The kernel event
  # rate is applied by the ordered auditd start hook because this Ubuntu build
  # does not accept rate_limit in auditd.conf.
  set_auditd_conf_kv "max_log_file" "50"
  set_auditd_conf_kv "num_logs" "10"
  set_auditd_conf_kv "max_log_file_action" "rotate"
  set_auditd_conf_kv "space_left" "100"
  set_auditd_conf_kv "space_left_action" "syslog"
  set_auditd_conf_kv "admin_space_left" "50"
  set_auditd_conf_kv "admin_space_left_action" "syslog"
  set_auditd_conf_kv "disk_full_action" "suspend"
  set_auditd_conf_kv "disk_error_action" "suspend"
}

install_auditd_rate_limit_persistence() {
  local helper_dest="${AUDITD_RATE_LIMIT_HELPER:-/usr/local/sbin/hardening-auditd-rate-limit}"
  local dropin_dest="${AUDITD_RATE_LIMIT_DROPIN:-/etc/systemd/system/auditd.service.d/10-secure-ubuntu-paas-rate-limit.conf}"
  local helper_tmp dropin_tmp

  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: install auditd rate-limit helper ${helper_dest} and ordered service drop-in ${dropin_dest}."
    run systemctl daemon-reload
    return 0
  fi

  helper_tmp="$(mktemp)"
  dropin_tmp="$(mktemp)"
  cat > "${helper_tmp}" <<'RATELIMITEOF'
#!/usr/bin/env bash
set -Eeuo pipefail
command -v auditctl >/dev/null 2>&1 || { echo "auditctl is unavailable" >&2; exit 1; }
current_rate="$(auditctl -s 2>/dev/null | awk '$1 == "rate_limit" {print $2; exit}' || true)"
if [[ "${current_rate}" == "10000" ]]; then
  exit 0
fi
audit_enabled="$(auditctl -s 2>/dev/null | awk '$1 == "enabled" {print $2;exit}')"
if [[ "${audit_enabled}" == "2" ]]; then
  echo "Audit rate change staged for next boot; immutable live policy left untouched." >&2
  exit 0
fi
auditctl -r 10000 >/dev/null
RATELIMITEOF
  {
    printf '%s\n' '[Service]'
    # Reset the vendor ExecStartPost list. The rate must be applied before
    # augenrules loads the final -e 2 rule; appending a helper would run it
    # after the kernel policy was already immutable.
    printf '%s\n' 'ExecStartPost='
    printf 'ExecStartPost=%s\n' "${helper_dest}"
    printf '%s\n' 'ExecStartPost=-/sbin/augenrules --load'
  } > "${dropin_tmp}"

  install -d -m 0755 -o root -g root "$(dirname "${helper_dest}")" "$(dirname "${dropin_dest}")"
  install -m 0750 -o root -g root "${helper_tmp}" "${helper_dest}"
  install -m 0644 -o root -g root "${dropin_tmp}" "${dropin_dest}"
  rm -f -- "${helper_tmp}" "${dropin_tmp}"
  run systemctl daemon-reload
}

configure_auditd() {
  local tmp audit_enabled="" audit_rate=""
  tmp="$(mktemp)"
  build_audit_rules > "${tmp}"

  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: write ${AUDIT_RULES_FILE}"
    rm -f "${tmp}"
  else
    install -d -m 0755 "$(dirname "${AUDIT_RULES_FILE}")"
    install -m 0640 -o root -g root "${tmp}" "${AUDIT_RULES_FILE}"
    rm -f "${tmp}"
  fi

  configure_auditd_policy
  # Install this before the first managed restart. Ubuntu's vendor unit loads
  # rules in ExecStartPost; because our rules end in -e 2, the runtime rate
  # must be set by an earlier ExecStartPost command on every boot.
  install_auditd_rate_limit_persistence

  if ! is_true "${DRY_RUN}" && command -v auditctl >/dev/null 2>&1; then
    audit_enabled="$(auditctl -s 2>/dev/null | awk '$1 == "enabled" {print $2; exit}' || true)"
    audit_rate="$(auditctl -s 2>/dev/null | awk '$1 == "rate_limit" {print $2; exit}' || true)"
  fi

  if [[ "${audit_enabled}" == "2" ]]; then
    log "Audit rule configuration is already immutable; keeping the kernel policy locked until reboot."
    if [[ "${audit_rate}" != "10000" ]]; then
      warn "Audit event rate limit is ${audit_rate:-unavailable}; the ordered auditd start hook will apply 10000 events/sec at the required reboot."
    fi
    return 0
  fi

  run systemctl enable auditd || warn "auditd could not be enabled (container/kernel limitation); rules file written."
  run systemctl restart auditd || warn "auditd restart failed after auditd.conf policy update."
  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: apply audit rate 10000 before loading immutable loginuid and rule policy (-e 2)."
  elif command -v auditctl >/dev/null 2>&1; then
    local loginuid_immutable_after enabled_after rate_after
    loginuid_immutable_after="$(auditctl -s 2>/dev/null | awk '$1 == "loginuid_immutable" {print $2; exit}' || true)"
    enabled_after="$(auditctl -s 2>/dev/null | awk '$1 == "enabled" {print $2; exit}' || true)"
    rate_after="$(auditctl -s 2>/dev/null | awk '$1 == "rate_limit" {print $2; exit}' || true)"
    if [[ "${loginuid_immutable_after}" == "1" ]]; then
      log "Audit loginuid immutability enforced."
    else
      warn "Unable to enforce immutable audit loginuids; validation will report this as a security failure."
    fi
    if [[ "${enabled_after}" == "2" ]]; then
      log "Audit rule configuration locked (-e 2)."
    else
      warn "Audit rule configuration is not immutable (enabled=${enabled_after:-unavailable}); validation will report this as a security failure."
    fi
    if [[ "${rate_after}" == "10000" ]]; then
      log "Audit event rate limit enforced (10000 events/sec)."
    else
      warn "Audit event rate limit is ${rate_after:-unavailable}; validation will report this as a security failure."
    fi
  else
    warn "auditctl is unavailable; validation will report immutable audit state as unavailable."
  fi
}
