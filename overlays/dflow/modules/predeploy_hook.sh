# dflow/modules/predeploy_hook.sh — stage an optional Dokku pre-deploy helper.

configure_dflow_predeploy_hook() {
  [[ "${PAAS:-}" == "dflow" ]] || return 0

  local source_hook="${SCRIPT_DIR}/../overlays/dflow/data/dokku-predeploy-resource-check.sh"
  local target_hook="/usr/local/sbin/dokku-predeploy-resource-check.sh"
  local plugin_dir="/var/lib/dokku/plugins/enabled/dflow-resource-check"
  local plugin_hook="${plugin_dir}/pre-deploy"
  local target_parent="${target_hook%/*}"

  if [[ ! -f "${source_hook}" ]]; then
    warn "dFlow pre-deploy helper missing at ${source_hook}; skipping hook staging."
    return 0
  fi

  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: would install dFlow pre-deploy helper at ${target_hook}."
    return 0
  fi

  if [[ -L "${target_parent}" || ( -e "${target_parent}" && ! -d "${target_parent}" ) ]]; then
    die "dFlow pre-deploy helper parent is a symlink or unexpected file: ${target_parent}"
  fi
  install -d -m 0755 -o root -g root "${target_parent}"
  read -r target_parent_uid target_parent_mode < <(stat -c '%u %a' "${target_parent}")
  [[ "${target_parent_uid}" == "0" && $((8#${target_parent_mode} & 8#022)) -eq 0 ]] \
    || die "dFlow pre-deploy helper parent is not root-owned and non-writable: ${target_parent}"
  if [[ -L "${target_hook}" || ( -e "${target_hook}" && ! -f "${target_hook}" ) ]]; then
    die "dFlow pre-deploy helper is a symlink or unexpected file: ${target_hook}"
  fi
  local target_tmp
  target_tmp="$(mktemp "${target_parent}/.dokku-predeploy-resource-check.XXXXXX")" \
    || die "Unable to stage dFlow pre-deploy helper safely."
  install -m 0755 -o root -g root "${source_hook}" "${target_tmp}"
  mv -f "${target_tmp}" "${target_hook}" \
    || { rm -f "${target_tmp}"; die "Unable to install dFlow pre-deploy helper atomically."; }

  if command -v dokku >/dev/null 2>&1 && [[ -d /var/lib/dokku/plugins/enabled ]]; then
    # Dokku owns most of its plugin tree.  Do not let a Dokku-controlled
    # directory redirect this root operation through a symlink on a rerun.
    # The enabled hook only needs to be executable/readable, so keep this
    # integration directory root-owned and replace the wrapper atomically.
    for protected_dir in /var/lib/dokku /var/lib/dokku/plugins /var/lib/dokku/plugins/enabled; do
      if [[ -L "${protected_dir}" || ( -e "${protected_dir}" && ! -d "${protected_dir}" ) ]]; then
        die "Dokku plugin path is a symlink or unexpected file: ${protected_dir}"
      fi
      [[ -d "${protected_dir}" ]] || install -d -m 0755 -o root -g root "${protected_dir}"
      read -r protected_uid protected_mode < <(stat -c '%u %a' "${protected_dir}")
      [[ "${protected_uid}" == "0" && $((8#${protected_mode} & 8#022)) -eq 0 ]] \
        || die "Dokku plugin path is not root-owned and non-writable: ${protected_dir}"
    done
    if [[ -L "${plugin_dir}" || ( -e "${plugin_dir}" && ! -d "${plugin_dir}" ) ]]; then
      die "dFlow resource-check plugin directory is a symlink or unexpected file."
    fi
    install -d -m 0755 -o root -g root "${plugin_dir}"
    read -r plugin_uid plugin_mode < <(stat -c '%u %a' "${plugin_dir}")
    [[ "${plugin_uid}" == "0" && $((8#${plugin_mode} & 8#022)) -eq 0 ]] \
      || die "dFlow resource-check plugin directory is not root-owned and non-writable."
    if [[ -L "${plugin_hook}" || ( -e "${plugin_hook}" && ! -f "${plugin_hook}" ) ]]; then
      die "dFlow pre-deploy hook is a symlink or unexpected file."
    fi
    local staged_hook
    staged_hook="$(mktemp "${plugin_dir}/.pre-deploy.XXXXXX")" \
      || die "Unable to stage dFlow pre-deploy hook safely."
    cat > "${staged_hook}" <<EOF
#!/usr/bin/env bash
exec ${target_hook} "\$@"
EOF
    chmod 0755 "${staged_hook}"
    chown root:root "${staged_hook}"
    mv -f "${staged_hook}" "${plugin_hook}" \
      || { rm -f "${staged_hook}"; die "Unable to install dFlow pre-deploy hook atomically."; }
    chmod 0755 "${plugin_hook}"
    chown root:root "${plugin_hook}"
    log "Installed dFlow Dokku pre-deploy hook."
  else
    log "Staged dFlow pre-deploy helper; Dokku is not installed yet."
  fi
}
