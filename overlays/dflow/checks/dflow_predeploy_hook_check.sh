dflow_predeploy_hook_check() {
  local helper="/usr/local/sbin/dokku-predeploy-resource-check.sh"
  local plugin_hook="/var/lib/dokku/plugins/enabled/dflow-resource-check/pre-deploy"

  if [[ -x "${helper}" ]]; then
    record "PASS" "dflow: predeploy helper executable" "${helper}"
  else
    record "INFO" "dflow: predeploy helper" "${helper} not installed yet"
  fi

  if ! command -v dokku >/dev/null 2>&1; then
    record "INFO" "dflow: predeploy Dokku hook" "dokku not present yet"
    return 0
  fi

  if [[ -x "${plugin_hook}" ]]; then
    record "PASS" "dflow: predeploy Dokku hook" "${plugin_hook}"
  else
    record "INFO" "dflow: predeploy Dokku hook" "${plugin_hook} not installed"
  fi
}
