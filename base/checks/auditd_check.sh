auditd_check() {
  if systemctl is-active --quiet auditd 2>/dev/null; then
    record "PASS" "auditd: active"
  elif [[ "${IS_CONTAINER}" == "true" ]]; then
    record "INFO" "auditd: active" "not active in container test environment"
  else
    record "FAIL" "auditd: active" "service not running"
    return
  fi

  local rules
  rules="$(auditctl -l 2>/dev/null)" || { record "FAIL" "auditd: rules" "cannot list"; return; }

  if grep -q "identity" <<< "${rules}"; then
    record "PASS" "auditd: identity rules loaded"
  else
    record "FAIL" "auditd: identity rules" "not loaded"
  fi

  if grep -q "sudoers-change" <<< "${rules}"; then
    record "PASS" "auditd: sudoers rules loaded"
  else
    record "FAIL" "auditd: sudoers rules" "not loaded"
  fi

  if grep -q "kernel-module" <<< "${rules}"; then
    record "PASS" "auditd: kernel-module rules loaded"
  else
    record "FAIL" "auditd: kernel-module rules" "not loaded"
  fi

  if grep -q "user_commands" <<< "${rules}"; then
    record "PASS" "auditd: user_commands execve rules loaded"
  else
    record "FAIL" "auditd: user_commands execve rules" "not loaded"
  fi

  if is_true "${DOCKER_PRESENT:-false}"; then
    if grep -q "container-runtime" <<< "${rules}" \
      && grep -q "docker-config" <<< "${rules}"; then
      record "PASS" "auditd: Docker runtime rules loaded"
    else
      record "FAIL" "auditd: Docker runtime rules" \
        "Docker is present but container-runtime and/or docker-config audit rules are not loaded"
    fi
  fi

  if [[ "${PAAS:-coolify}" == "dokploy" ]]; then
    if grep -q 'root_commands' <<< "${rules}"; then
      record "PASS" "auditd: root operator commands loaded"
    else
      record "FAIL" "auditd: root operator commands" "direct root SSH sessions need auid=0 execve auditing"
    fi
  fi

  if [[ -f "${AUDITD_CONF}" ]]; then
    local max_log_file num_logs
    max_log_file="$(grep -E '^[[:space:]]*max_log_file[[:space:]]*=' "${AUDITD_CONF}" | tail -1 | sed 's/.*=[[:space:]]*//')"
    num_logs="$(grep -E '^[[:space:]]*num_logs[[:space:]]*=' "${AUDITD_CONF}" | tail -1 | sed 's/.*=[[:space:]]*//')"
    if [[ "${max_log_file:-0}" =~ ^[0-9]+$ ]] && (( max_log_file > 0 && max_log_file <= 100 )); then
      record "PASS" "auditd: max_log_file=${max_log_file}MB"
    else
      record "FAIL" "auditd: max_log_file" "expected a bounded value between 1 and 100 MB"
    fi

    if [[ "${num_logs:-0}" =~ ^[0-9]+$ ]] && (( num_logs >= 2 && num_logs <= 20 )); then
      record "PASS" "auditd: num_logs=${num_logs}"
    else
      record "FAIL" "auditd: num_logs" "expected a bounded rotation count between 2 and 20"
    fi

    if grep -qE '^[[:space:]]*max_log_file_action[[:space:]]*=[[:space:]]*rotate' "${AUDITD_CONF}"; then
      record "PASS" "auditd: max_log_file_action=rotate"
    else
      record "FAIL" "auditd: max_log_file_action" "expected rotate in ${AUDITD_CONF}"
    fi

    if grep -qE '^[[:space:]]*disk_full_action[[:space:]]*=[[:space:]]*suspend' "${AUDITD_CONF}" \
      && grep -qE '^[[:space:]]*disk_error_action[[:space:]]*=[[:space:]]*suspend' "${AUDITD_CONF}"; then
      record "PASS" "auditd: disk failure actions configured"
    else
      record "FAIL" "auditd: disk failure actions" "expected disk_full_action/disk_error_action=suspend"
    fi

    local space_left space_left_action admin_space_left admin_space_left_action
    space_left="$(grep -E '^[[:space:]]*space_left[[:space:]]*=' "${AUDITD_CONF}" | tail -1 | sed 's/.*=[[:space:]]*//')"
    space_left_action="$(grep -E '^[[:space:]]*space_left_action[[:space:]]*=' "${AUDITD_CONF}" | tail -1 | sed 's/.*=[[:space:]]*//')"
    if [[ "${space_left:-0}" =~ ^[0-9]+$ ]] && (( space_left > 0 )) && [[ "${space_left_action}" == "syslog" ]]; then
      record "PASS" "auditd: space_left=${space_left}, space_left_action=syslog"
    else
      record "FAIL" "auditd: space_left thresholds" "expected space_left>0 and space_left_action=syslog"
    fi

    admin_space_left="$(grep -E '^[[:space:]]*admin_space_left[[:space:]]*=' "${AUDITD_CONF}" | tail -1 | sed 's/.*=[[:space:]]*//')"
    admin_space_left_action="$(grep -E '^[[:space:]]*admin_space_left_action[[:space:]]*=' "${AUDITD_CONF}" | tail -1 | sed 's/.*=[[:space:]]*//')"
    if [[ "${admin_space_left:-0}" =~ ^[0-9]+$ ]] && (( admin_space_left > 0 )) && [[ "${admin_space_left_action}" == "syslog" ]]; then
      record "PASS" "auditd: admin_space_left=${admin_space_left}, admin_space_left_action=syslog"
    else
      record "FAIL" "auditd: admin_space_left thresholds" "expected admin_space_left>0 and admin_space_left_action=syslog"
    fi
  else
    record "INFO" "auditd: policy config" "${AUDITD_CONF} not found"
  fi

  local audit_status audit_enabled lost backlog audit_rate_limit
  audit_status="$(auditctl -s 2>/dev/null || true)"
  if [[ -n "${audit_status}" ]]; then
    audit_enabled="$(awk '$1 == "enabled" {print $2; exit}' <<< "${audit_status}")"
    if [[ "${audit_enabled}" == "2" ]]; then
      record "PASS" "auditd: rule configuration immutable"
    elif [[ "${audit_enabled}" =~ ^[0-9]+$ ]]; then
      record "FAIL" "auditd: rule configuration immutable" \
        "kernel reports enabled=${audit_enabled}; expected 2 (-e 2)"
    elif [[ "${IS_CONTAINER}" == "true" ]]; then
      record "INFO" "auditd: rule configuration immutable" "kernel status is unavailable in container test environment"
    else
      record "FAIL" "auditd: rule configuration immutable" "auditctl -s did not report enabled=2"
    fi

    audit_rate_limit="$(awk '$1 == "rate_limit" {print $2; exit}' <<< "${audit_status}")"
    if [[ "${audit_rate_limit}" == "10000" ]]; then
      record "PASS" "auditd: rate_limit=10000"
    else
      record "FAIL" "auditd: rate_limit" "kernel reports rate_limit=${audit_rate_limit:-unavailable}; expected 10000"
    fi

    local loginuid_immutable
    loginuid_immutable="$(awk '$1 == "loginuid_immutable" {print $2; exit}' <<< "${audit_status}")"
    if [[ "${loginuid_immutable}" == "1" ]]; then
      record "PASS" "auditd: loginuid immutable"
    elif [[ "${loginuid_immutable}" =~ ^[0-9]+$ ]]; then
      record "FAIL" "auditd: loginuid immutable" "kernel reports loginuid_immutable=${loginuid_immutable}; expected 1"
    elif [[ "${IS_CONTAINER}" == "true" ]]; then
      record "INFO" "auditd: loginuid immutable" "kernel status is unavailable in container test environment"
    else
      record "FAIL" "auditd: loginuid immutable" "auditctl -s did not report loginuid_immutable=1"
    fi

    lost="$(awk '/^lost[[:space:]]/ {print $2; exit}' <<< "${audit_status}")"
    backlog="$(awk '/^backlog[[:space:]]/ {print $2; exit}' <<< "${audit_status}")"
    if [[ "${lost:-}" =~ ^[0-9]+$ ]] && [[ "${lost}" == "0" ]]; then
      record "PASS" "auditd: queue loss (lost=0)"
    elif [[ "${lost:-}" =~ ^[0-9]+$ ]]; then
      record "FAIL" "auditd: queue loss" "lost=${lost}; any dropped audit event creates a forensic gap"
    elif [[ "${IS_CONTAINER}" == "true" ]]; then
      record "INFO" "auditd: queue loss" "unable to parse 'lost' in container test environment"
    else
      record "FAIL" "auditd: queue loss" "unable to parse 'lost' from auditctl -s"
    fi
    [[ -n "${backlog}" ]] && record "INFO" "auditd: backlog" "backlog=${backlog}"
  else
    if [[ "${IS_CONTAINER}" == "true" ]]; then
      record "INFO" "auditd: rule configuration immutable" "auditctl -s unavailable in container test environment"
    else
      record "FAIL" "auditd: rule configuration immutable" "auditctl -s unavailable"
    fi
    if [[ "${IS_CONTAINER}" == "true" ]]; then
      record "INFO" "auditd: loginuid immutable" "auditctl -s unavailable in container test environment"
    else
      record "FAIL" "auditd: loginuid immutable" "auditctl -s unavailable"
    fi
    record "INFO" "auditd: queue status" "auditctl -s unavailable"
  fi
}
