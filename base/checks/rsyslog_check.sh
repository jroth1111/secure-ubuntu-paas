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

rsyslog_check() {
  local rsyslog_rotate="${RSYSLOG_LOGROTATE_FILE:-/etc/logrotate.d/rsyslog}"
  local ufw_rotate="${UFW_LOGROTATE_FILE:-/etc/logrotate.d/ufw}"
  local mode owner group
  local target q_target target_owner target_group target_mode
  local target_count=0
  local expected_dir_group="root"
  local expected_target_owner="syslog"
  local expected_target_group="adm"
  local rsyslog_service_loaded="false"

  if ! getent passwd syslog >/dev/null 2>&1; then
    expected_target_owner="root"
  fi
  if ! getent group "${expected_target_group}" >/dev/null 2>&1; then
    if getent group syslog >/dev/null 2>&1; then
      expected_target_group="syslog"
    else
      expected_target_group="root"
    fi
  fi
  if systemctl show -p LoadState --value rsyslog 2>/dev/null | grep -qx 'loaded'; then
    rsyslog_service_loaded="true"
  fi

  owner="$(stat -c '%U' /var/log 2>/dev/null || true)"
  group="$(stat -c '%G' /var/log 2>/dev/null || true)"
  mode="$(stat -c '%a' /var/log 2>/dev/null || true)"

  if [[ "${owner}" == "root" && "${group}" == "${expected_dir_group}" ]]; then
    record "PASS" "rsyslog: /var/log owner/group"
  else
    record "FAIL" "rsyslog: /var/log owner/group" \
      "expected root:${expected_dir_group}, got ${owner:-unknown}:${group:-unknown}"
  fi

  if [[ "${mode}" == "755" ]]; then
    record "PASS" "rsyslog: /var/log mode"
  elif [[ "${mode}" =~ ^[0-7]{3,4}$ ]]; then
    record "FAIL" "rsyslog: /var/log mode" \
      "expected 755 with no service-group write access, got ${mode}"
  else
    record "FAIL" "rsyslog: /var/log mode" "unreadable (${mode:-unknown})"
  fi

  while IFS= read -r target; do
    [[ -n "${target}" ]] || continue
    ((++target_count))
    if [[ -L "${target}" || -L "$(dirname "${target}")" ]]; then
      record "FAIL" "rsyslog: target exists (${target})" \
        "target or immediate parent is a symlink; refusing path traversal"
    elif [[ -f "${target}" ]]; then
      record "PASS" "rsyslog: target exists (${target})"
      target_owner="$(stat -c '%U' "${target}" 2>/dev/null || true)"
      target_group="$(stat -c '%G' "${target}" 2>/dev/null || true)"
      target_mode="$(stat -c '%a' "${target}" 2>/dev/null || true)"
      if [[ "${target_owner}" == "${expected_target_owner}" && "${target_group}" == "${expected_target_group}" && "${target_mode}" == "640" ]]; then
        record "PASS" "rsyslog: target ownership (${target})"
      else
        record "FAIL" "rsyslog: target ownership (${target})" \
          "expected ${expected_target_owner}:${expected_target_group} mode 640, got ${target_owner:-unknown}:${target_group:-unknown} mode ${target_mode:-unknown}"
      fi
      printf -v q_target '%q' "${target}"
      if getent passwd syslog >/dev/null 2>&1; then
        if su -s /bin/sh -c "test -w ${q_target}" syslog >/dev/null 2>&1; then
          record "PASS" "rsyslog: target writable by syslog (${target})"
        else
          record "FAIL" "rsyslog: target writable by syslog (${target})" "permission denied"
        fi
      else
        record "INFO" "rsyslog: target writable by syslog (${target})" "syslog user unavailable; ownership fallback in effect"
      fi
    else
      record "FAIL" "rsyslog: target exists (${target})" "missing"
    fi
  done < <(rsyslog_collect_log_targets)

  if (( target_count == 0 )); then
    record "INFO" "rsyslog: configured /var/log targets" "none found in rsyslog config"
  fi

  if [[ -f "${rsyslog_rotate}" ]] \
    && grep -Eq "^[[:space:]]*create[[:space:]]+640[[:space:]]+${expected_target_owner}[[:space:]]+${expected_target_group}([[:space:]]|$)" "${rsyslog_rotate}"; then
    record "PASS" "rsyslog: logrotate create directive"
  elif [[ ! -f "${rsyslog_rotate}" ]]; then
    record "INFO" "rsyslog: logrotate create directive" "${rsyslog_rotate} missing; rsyslog package may be absent"
  else
    record "FAIL" "rsyslog: logrotate create directive" \
      "missing in ${rsyslog_rotate} (expected create 640 ${expected_target_owner} ${expected_target_group})"
  fi

  if [[ -f "${ufw_rotate}" ]] \
    && grep -Eq "^[[:space:]]*create[[:space:]]+640[[:space:]]+${expected_target_owner}[[:space:]]+${expected_target_group}([[:space:]]|$)" "${ufw_rotate}"; then
    record "PASS" "rsyslog: ufw logrotate create directive"
  else
    record "FAIL" "rsyslog: ufw logrotate create directive" \
      "missing in ${ufw_rotate} (expected create 640 ${expected_target_owner} ${expected_target_group})"
  fi

  if [[ "${rsyslog_service_loaded}" == "true" ]] && systemctl is-active --quiet rsyslog 2>/dev/null; then
    record "PASS" "rsyslog: service active"
  elif [[ "${rsyslog_service_loaded}" != "true" ]]; then
    record "INFO" "rsyslog: service active" "service not running (unit absent)"
  else
    record "FAIL" "rsyslog: service active" "service not running"
  fi

  local active_since
  active_since="$(systemctl show -p ActiveEnterTimestamp --value rsyslog 2>/dev/null || true)"
  if [[ -n "${active_since}" ]]; then
    if journalctl -u rsyslog --since "${active_since}" --no-pager -o cat 2>/dev/null \
      | grep -Eq 'suspended \(module '\''builtin:omfile'\''\)|Permission denied|open error|e/2007|e/2433'; then
      record "FAIL" "rsyslog: runtime log-write health" \
        "omfile suspend/permission errors present since last restart"
    else
      record "PASS" "rsyslog: runtime log-write health"
    fi
  else
    record "INFO" "rsyslog: runtime log-write health" "unable to determine service activation timestamp"
  fi
}
