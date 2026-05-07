# dflow/modules/predeploy_hook.sh — stage an optional Dokku pre-deploy helper.

configure_dflow_predeploy_hook() {
  [[ "${PAAS:-}" == "dflow" ]] || return 0

  local source_hook="${SCRIPT_DIR}/../overlays/dflow/data/dokku-predeploy-resource-check.sh"
  local target_hook="/usr/local/sbin/dokku-predeploy-resource-check.sh"
  local plugin_dir="/var/lib/dokku/plugins/enabled/dflow-resource-check"
  local plugin_hook="${plugin_dir}/pre-deploy"

  if [[ ! -f "${source_hook}" ]]; then
    warn "dFlow pre-deploy helper missing at ${source_hook}; skipping hook staging."
    return 0
  fi

  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: would install dFlow pre-deploy helper at ${target_hook}."
    return 0
  fi

  install -m 0755 -o root -g root "${source_hook}" "${target_hook}"

  if command -v dokku >/dev/null 2>&1 && [[ -d /var/lib/dokku/plugins/enabled ]]; then
    install -d -m 0755 -o dokku -g dokku "${plugin_dir}"
    cat > "${plugin_hook}" <<EOF
#!/usr/bin/env bash
exec ${target_hook} "\$@"
EOF
    chmod 0755 "${plugin_hook}"
    chown dokku:dokku "${plugin_hook}"
    log "Installed dFlow Dokku pre-deploy hook."
  else
    log "Staged dFlow pre-deploy helper; Dokku is not installed yet."
  fi
}
