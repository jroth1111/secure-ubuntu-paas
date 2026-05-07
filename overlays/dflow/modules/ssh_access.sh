# dflow/modules/ssh_access.sh — install the controller's managed root key.

configure_dflow_ssh_access() {
  [[ "${PAAS:-}" == "dflow" ]] || return 0
  [[ "${DFLOW_AUTH_MODE:-ssh}" == "ssh" ]] || return 0

  if [[ -z "${DFLOW_CONTROL_PUBKEY:-}" ]]; then
    log "dFlow auth-mode=ssh but no controller public key was supplied; leaving root authorized_keys unchanged."
    return 0
  fi

  local auth_dir="/root/.ssh"
  local auth_file="${auth_dir}/authorized_keys"
  local managed_comment="dflow-control@managed"
  local managed_key="${DFLOW_CONTROL_PUBKEY}"

  if [[ "${managed_key}" != *" ${managed_comment}" ]]; then
    managed_key="${managed_key% *} ${managed_comment}"
  fi

  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: would install dFlow controller root SSH key tagged ${managed_comment}."
    return 0
  fi

  install -d -m 0700 -o root -g root "${auth_dir}"
  touch "${auth_file}"
  chmod 0600 "${auth_file}"
  grep -v " ${managed_comment}$" "${auth_file}" > "${auth_file}.tmp" || true
  printf '%s\n' "${managed_key}" >> "${auth_file}.tmp"
  install -m 0600 -o root -g root "${auth_file}.tmp" "${auth_file}"
  rm -f "${auth_file}.tmp"
  log "Installed dFlow controller root SSH key tagged ${managed_comment}."
}
