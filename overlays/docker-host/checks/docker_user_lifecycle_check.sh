docker_user_lifecycle_check() {
  local unit_file="${DOCKER_USER_UNIT_FILE:-/etc/systemd/system/docker-user-hardening.service}"
  if [[ ! -f "${unit_file}" ]]; then
    if docker_hardening_expected; then
      record "FAIL" "docker-user: unit file" "not found at ${unit_file}"
    else
      record "INFO" "docker-user: unit file" "Docker hardening not yet expected; skipped"
    fi
    return
  fi

  if grep -q "PartOf=docker.service" "${unit_file}"; then
    record "PASS" "docker-user: PartOf=docker.service"
  else
    record "FAIL" "docker-user: PartOf=docker.service" "missing — rules lost on Docker daemon restart"
  fi

  if grep -q "WantedBy=docker.service" "${unit_file}"; then
    record "PASS" "docker-user: WantedBy=docker.service"
  else
    record "FAIL" "docker-user: WantedBy=docker.service" "missing — rules may not re-apply after Docker start"
  fi

  local hardening_script="${DOCKER_USER_SCRIPT:-/usr/local/sbin/docker-user-hardening.sh}"
  if [[ -x "${hardening_script}" ]] \
    && grep -Fq 'DOCKER_USER_LOCK_FILE="${DOCKER_USER_LOCK_FILE:-/run/lock/docker-user-hardening.lock}"' "${hardening_script}" \
    && grep -Fq 'exec 9>"${DOCKER_USER_LOCK_FILE}"' "${hardening_script}" \
    && grep -Eq '^[[:space:]]*flock -x 9[[:space:]]*$' "${hardening_script}"; then
    record "PASS" "docker-user: reconciliation mutex"
  else
    record "FAIL" "docker-user: reconciliation mutex" \
      "${hardening_script} lacks the managed exclusive lock"
  fi

  local docker_service_present="false"
  if unit_available "docker.service"; then
    docker_service_present="true"
  fi
  if [[ "${docker_service_present}" != "true" ]]; then
    record "INFO" "docker-user: enabled state" "docker.service unavailable; enable/start deferred"
    return
  fi

  local refresh_service_file="/etc/systemd/system/docker-user-hardening-refresh.service"
  local refresh_timer_file="/etc/systemd/system/docker-user-hardening-refresh.timer"
  if [[ -f "${refresh_service_file}" ]] \
    && grep -q "ExecStart=/usr/local/sbin/docker-user-hardening.sh" "${refresh_service_file}" \
    && grep -q "After=docker.service docker-user-hardening.service" "${refresh_service_file}"; then
    record "PASS" "docker-user: bridge refresh service"
  else
    record "FAIL" "docker-user: bridge refresh service" "missing or not ordered after Docker hardening"
  fi
  if [[ -f "${refresh_timer_file}" ]] \
    && grep -q "OnUnitActiveSec=60s" "${refresh_timer_file}" \
    && grep -q "Unit=docker-user-hardening-refresh.service" "${refresh_timer_file}"; then
    record "PASS" "docker-user: bridge refresh timer"
  else
    record "FAIL" "docker-user: bridge refresh timer" "missing or not periodic"
  fi
  local refresh_enabled_state refresh_active_state
  refresh_enabled_state="$(systemctl is-enabled docker-user-hardening-refresh.timer 2>/dev/null || echo "unknown")"
  if [[ "${refresh_enabled_state}" == "enabled" || "${refresh_enabled_state}" == "enabled-runtime" ]]; then
    record "PASS" "docker-user: bridge refresh timer enabled"
  else
    record "FAIL" "docker-user: bridge refresh timer enabled" "state=${refresh_enabled_state}"
  fi
  refresh_active_state="$(systemctl is-active docker-user-hardening-refresh.timer 2>/dev/null || echo "unknown")"
  if [[ "${refresh_active_state}" == "active" ]]; then
    record "PASS" "docker-user: bridge refresh timer active"
  else
    record "FAIL" "docker-user: bridge refresh timer active" "state=${refresh_active_state}"
  fi

  local enabled_state
  enabled_state="$(systemctl is-enabled docker-user-hardening.service 2>/dev/null || echo "unknown")"
  if [[ "${enabled_state}" == "enabled" || "${enabled_state}" == "enabled-runtime" ]]; then
    record "PASS" "docker-user: enabled"
  else
    record "FAIL" "docker-user: enabled" "state=${enabled_state} — rules may not re-apply on Docker restart"
  fi

  # Functional: service must have run at least once since boot (rules are only in iptables if it did).
  local active_state
  active_state="$(systemctl show docker-user-hardening.service --property=ActiveState --value 2>/dev/null || echo "unknown")"
  if [[ "${active_state}" == "active" || "${active_state}" == "activating" ]]; then
    record "PASS" "docker-user: service has run (${active_state})"
  else
    # For a oneshot service, "inactive" is normal after a successful run.
    local result
    result="$(systemctl show docker-user-hardening.service --property=Result --value 2>/dev/null || echo "unknown")"
    if [[ "${result}" == "success" ]]; then
      record "PASS" "docker-user: service completed successfully"
    else
      record "FAIL" "docker-user: service result" "result=${result} — rules may not have been applied"
    fi
  fi
}
