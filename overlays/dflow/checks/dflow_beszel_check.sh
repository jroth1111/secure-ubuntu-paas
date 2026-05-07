dflow_beszel_check() {
  local app_name="${DFLOW_BESZEL_APP:-monitoring-beszel-agent}"
  local container_port="${DFLOW_BESZEL_PORT:-45876}"

  if ! command -v dokku >/dev/null 2>&1; then
    record "INFO" "dflow: beszel agent app" "dokku not present yet (controller installs ${app_name} during onboarding)"
    return 0
  fi

  if ! dokku apps:exists "${app_name}" >/dev/null 2>&1; then
    record "INFO" "dflow: beszel agent app" "${app_name} not present yet (controller deploys it on attach)"
    return 0
  fi
  record "PASS" "dflow: beszel agent app exists" "${app_name}"

  local ps_report
  ps_report="$(dokku ps:report "${app_name}" 2>/dev/null)" || ps_report=""
  if grep -Eq '^[[:space:]]*Running:[[:space:]]+true' <<< "${ps_report}"; then
    record "PASS" "dflow: beszel agent running"
  else
    record "FAIL" "dflow: beszel agent running" "ps:report does not show Running:true"
  fi

  local ports_report
  ports_report="$(dokku ports:report "${app_name}" 2>/dev/null)" || ports_report=""
  if grep -Eq "Ports map:[[:space:]]+[a-z]+:[0-9]+:${container_port}([[:space:]]|$)" <<< "${ports_report}"; then
    record "PASS" "dflow: beszel agent port map" "container :${container_port} routed via Dokku proxy"
  else
    record "FAIL" "dflow: beszel agent port map" "no Dokku port map ending in :${container_port} on ${app_name}"
  fi

  local config
  config="$(dokku config:show "${app_name}" 2>/dev/null)" || config=""
  if grep -Eq '^HUB_URL:' <<< "${config}"; then
    record "PASS" "dflow: beszel agent HUB_URL configured"
  else
    record "FAIL" "dflow: beszel agent HUB_URL" "missing on ${app_name} (controller sets this at onboarding)"
  fi
}
