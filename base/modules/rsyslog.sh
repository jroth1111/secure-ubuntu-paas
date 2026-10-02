rsyslog_collect_log_targets() {
  local cfg
  local -a cfgs=()
  local config_root="${RSYSLOG_CONFIG_ROOT:-/etc}"

  [[ -f "${config_root}/rsyslog.conf" ]] && cfgs+=("${config_root}/rsyslog.conf")
  for cfg in "${config_root}"/rsyslog.d/*.conf; do
    [[ -f "${cfg}" ]] || continue
    cfgs+=("${cfg}")
  done

  ((${#cfgs[@]} > 0)) || return 0

  awk '
    /^[[:space:]]*#/ { next }
    {
      line = $0
      while (match(line, /-?\/var\/log\/[A-Za-z0-9_.\/-]+/)) {
        target = substr(line, RSTART, RLENGTH)
        sub(/^-/, "", target)
        print target
        line = substr(line, RSTART + RLENGTH)
      }
    }
  ' "${cfgs[@]}" | sort -u
}

install_rsyslog_tmpfiles_override() {
  local override="${RSYSLOG_TMPFILES_OVERRIDE:-/etc/tmpfiles.d/00rsyslog.conf}"
  if [[ -L "${override}" || ( -e "${override}" && ! -f "${override}" ) ]]; then
    die "Refusing unsafe rsyslog tmpfiles override path: ${override}"
  fi
  # Ubuntu's /usr/lib/tmpfiles.d/00rsyslog.conf changes /var/log to
  # root:syslog 0775 on every boot. A same-basename /etc override has higher
  # precedence and keeps the parent non-writable by service groups; rsyslog's
  # individual files remain writable through their explicit ownership.
  cat <<'EOF' | write_file "${override}" "0644" "root" "root"
# Managed by secure-ubuntu-paas; overrides /usr/lib/tmpfiles.d/00rsyslog.conf.
z /var/log 0755 root root -
EOF
}

ensure_logrotate_create_directive() {
  local file="$1"
  local log_owner="syslog"
  local log_group="$2"
  if [[ $# -ge 3 ]]; then
    log_owner="$2"
    log_group="$3"
  fi
  local create_line="create 640 ${log_owner} ${log_group}"

  if [[ ! -f "${file}" ]]; then
    warn "Logrotate file ${file} not found; skipping create directive check."
    return 0
  fi

  if grep -Eq "^[[:space:]]*create[[:space:]]+640[[:space:]]+${log_owner}[[:space:]]+${log_group}([[:space:]]|$)" "${file}"; then
    return 0
  fi

  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: add '${create_line}' to ${file}"
    return 0
  fi

  if grep -qE '^[[:space:]]*delaycompress[[:space:]]*$' "${file}"; then
    sed -i "/^[[:space:]]*delaycompress[[:space:]]*$/a\\\t${create_line}" "${file}"
    return 0
  fi

  if grep -qE '^[[:space:]]*compress[[:space:]]*$' "${file}"; then
    sed -i "/^[[:space:]]*compress[[:space:]]*$/a\\\t${create_line}" "${file}"
    return 0
  fi

  if grep -qE '^[[:space:]]*sharedscripts[[:space:]]*$' "${file}"; then
    sed -i "/^[[:space:]]*sharedscripts[[:space:]]*$/i\\\t${create_line}" "${file}"
    return 0
  fi

  sed -i "/^[[:space:]]*}[[:space:]]*$/i\\\t${create_line}" "${file}"
}

configure_rsyslog_targets() {
  local target
  local log_owner="syslog"
  local log_group="adm"

  install_rsyslog_tmpfiles_override

  if ! getent passwd "${log_owner}" >/dev/null 2>&1; then
    warn "User '${log_owner}' not found; using fallback owner root for managed log files."
    log_owner="root"
  fi

  if ! getent group "${log_group}" >/dev/null 2>&1; then
    if getent group syslog >/dev/null 2>&1; then
      log_group="syslog"
    else
      warn "Neither 'adm' nor 'syslog' group found; using fallback group root for managed log files."
      log_group="root"
    fi
  fi

  if getent group syslog >/dev/null 2>&1; then
    if is_true "${DRY_RUN}"; then
      log "DRY-RUN: ensure /var/log is root:root mode 0755"
    else
      install -d -m 0755 -o root -g root /var/log
      chown root:root /var/log
      chmod 0755 /var/log
    fi
  else
    if ! is_true "${DRY_RUN}"; then
      install -d -m 0755 -o root -g root /var/log
      chown root:root /var/log
      chmod 0755 /var/log
    fi
    warn "Group 'syslog' not found; using root-owned /var/log."
  fi

  while IFS= read -r target; do
    [[ -n "${target}" ]] || continue
    if is_true "${DRY_RUN}"; then
      log "DRY-RUN: ensure ${target} exists (0640 ${log_owner}:${log_group})"
      continue
    fi
    local target_dir
    target_dir="$(dirname "${target}")"
    if [[ -L "${target_dir}" ]]; then
      rm -f -- "${target_dir}" || return 1
    fi
    if [[ -e "${target_dir}" && ! -d "${target_dir}" ]]; then
      warn "Refusing non-directory rsyslog target parent: ${target_dir}"
      return 1
    fi
    install -d -m 0755 -o root -g root "${target_dir}"
    if [[ -L "${target}" || ( -e "${target}" && ! -f "${target}" ) ]]; then
      # Remove only the directory entry; never follow a symlink to its target.
      rm -f -- "${target}" || return 1
    fi
    if [[ ! -e "${target}" ]]; then
      install -m 0640 -o "${log_owner}" -g "${log_group}" /dev/null "${target}"
    else
      [[ -f "${target}" && ! -L "${target}" ]] || return 1
      chown "${log_owner}:${log_group}" "${target}"
      chmod 0640 "${target}"
    fi
  done < <(rsyslog_collect_log_targets)

  ensure_logrotate_create_directive "/etc/logrotate.d/ufw" "${log_owner}" "${log_group}"
  ensure_logrotate_create_directive "/etc/logrotate.d/rsyslog" "${log_owner}" "${log_group}"

  if unit_available "rsyslog.service"; then
    run systemctl restart rsyslog
  else
    warn "rsyslog.service not found; skipping restart."
  fi
}
