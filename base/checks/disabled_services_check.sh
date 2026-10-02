disabled_services_check() {
  local svc
  for svc in rpcbind avahi-daemon cups ModemManager udisks2 fwupd fwupd-refresh upower; do
    local state="not-found"
    state="$(systemctl is-enabled "${svc}.service" 2>/dev/null || true)"
    state="${state%%$'\n'*}"
    [[ -n "${state}" ]] || state="not-found"

    if [[ "${state}" == masked* || "${state}" == "not-found" ]]; then
      record "PASS" "disabled: ${svc} (${state})"
    else
      record "FAIL" "disabled: ${svc}" "state is ${state}, expected masked"
    fi
  done

  local timer_state="not-found"
  timer_state="$(systemctl is-enabled fwupd-refresh.timer 2>/dev/null || true)"
  timer_state="${timer_state%%$'\n'*}"
  [[ -n "${timer_state}" ]] || timer_state="not-found"
  if [[ "${timer_state}" == masked* || "${timer_state}" == "not-found" ]]; then
    record "PASS" "disabled: fwupd-refresh.timer (${timer_state})"
  else
    record "FAIL" "disabled: fwupd-refresh.timer" "state is ${timer_state}, expected masked"
  fi
}
