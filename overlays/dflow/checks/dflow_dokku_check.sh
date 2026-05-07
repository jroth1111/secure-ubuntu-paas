dflow_dokku_check() {
  if ! command -v dokku >/dev/null 2>&1; then
    record "INFO" "dflow: dokku CLI" "not installed yet (run dFlow onboarder to install Dokku 0.35.x)"
    return 0
  fi

  local dokku_version
  dokku_version="$(dokku version 2>/dev/null | awk 'NR==1 {print $NF}')"
  if [[ -z "${dokku_version}" ]]; then
    record "FAIL" "dflow: dokku version" "could not determine version (dokku binary present but unresponsive)"
    return 0
  fi

  if [[ "${dokku_version}" =~ ^(v?0\.35\.) ]]; then
    record "PASS" "dflow: dokku ${dokku_version}"
  else
    record "INFO" "dflow: dokku ${dokku_version}" "dFlow pins 0.35.x; other versions may work but are unsupported"
  fi

  # Verify the railpack builder is selected (dFlow's default).
  local builder
  builder="$(dokku builder:report --global 2>/dev/null | awk -F: '/Builder selected:/ {gsub(/^[[:space:]]+|[[:space:]]+$/,"",$2); print $2}' | head -n1)"
  if [[ "${builder}" == "railpack" ]]; then
    record "PASS" "dflow: dokku builder = railpack"
  elif [[ -z "${builder}" || "${builder}" == "herokuish" ]]; then
    record "INFO" "dflow: dokku builder" "expected railpack, found ${builder:-default(herokuish)} — dFlow will set this on first deploy"
  else
    record "INFO" "dflow: dokku builder" "found ${builder} (dFlow expects railpack)"
  fi

  # Plugins required by dFlow (subset; absence is informational because dFlow
  # installs them lazily on first matching deploy).
  local required_plugins=(letsencrypt postgres redis)
  local plugin_list
  plugin_list="$(dokku plugin:list 2>/dev/null | awk 'NR>1 {print $1}')"
  local missing=()
  for plugin in "${required_plugins[@]}"; do
    grep -qx "${plugin}" <<< "${plugin_list}" || missing+=("${plugin}")
  done
  if (( ${#missing[@]} == 0 )); then
    record "PASS" "dflow: dokku core plugins present (${required_plugins[*]})"
  else
    record "INFO" "dflow: dokku plugins missing" "${missing[*]} (installed on demand by dFlow)"
  fi
}
