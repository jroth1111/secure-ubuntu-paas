# dflow/modules/ssh_match_dropin.sh — restrict controller root SSH by CIDR.

DFLOW_ROOT_MATCH_DROPIN="${DFLOW_ROOT_MATCH_DROPIN:-/etc/ssh/sshd_config.d/16-dflow-root-match.conf}"

configure_dflow_ssh_match_dropin() {
  [[ "${PAAS:-}" == "dflow" ]] || return 0
  [[ "${DFLOW_AUTH_MODE:-ssh}" == "ssh" ]] || return 0

  if [[ -z "${DFLOW_CONTROL_CIDR:-}" ]]; then
    if is_true "${DRY_RUN}"; then
      log "DRY-RUN: would remove ${DFLOW_ROOT_MATCH_DROPIN}; dFlow controller CIDR is unset."
    else
      rm -f "${DFLOW_ROOT_MATCH_DROPIN}"
    fi
    log "dFlow controller CIDR unset; root SSH remains limited to base hardening paths."
    return 0
  fi

  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: would permit root SSH from dFlow controller CIDR ${DFLOW_CONTROL_CIDR}."
    return 0
  fi

  write_file "${DFLOW_ROOT_MATCH_DROPIN}" "0644" "root" "root" <<EOF
# Managed by ${SCRIPT_NAME}
Match Address ${DFLOW_CONTROL_CIDR}
    PermitRootLogin prohibit-password
    AllowUsers root ${ADMIN_USER}
EOF

  sshd -t || die "sshd -t failed after writing ${DFLOW_ROOT_MATCH_DROPIN}."
  reload_ssh_service || die "Failed to reload SSH after writing ${DFLOW_ROOT_MATCH_DROPIN}."
  log "Restricted dFlow controller root SSH to ${DFLOW_CONTROL_CIDR}."
}
