dflow_ssh_path_check() {
  local auth_mode="${DFLOW_AUTH_MODE:-ssh}"
  local root_auth="/root/.ssh/authorized_keys"
  local match_dropin="${DFLOW_ROOT_MATCH_DROPIN:-/etc/ssh/sshd_config.d/16-dflow-root-match.conf}"

  case "${auth_mode}" in
    tailscale)
      if [[ "$(tailscale_runssh_pref_value 5 1)" == "true" ]]; then
        record "PASS" "dflow: tailscale ssh enabled"
      else
        record "FAIL" "dflow: tailscale ssh enabled" "RunSSH is not true"
      fi
      return 0
      ;;
    ssh) ;;
    *)
      record "FAIL" "dflow: ssh path auth mode" "unsupported auth mode ${auth_mode}"
      return 0
      ;;
  esac

  if [[ -f "${root_auth}" ]] && grep -q ' dflow-control@managed$' "${root_auth}"; then
    record "PASS" "dflow: controller root key installed"
  else
    record "INFO" "dflow: controller root key" "managed key not present; required before controller SSH attach"
  fi

  if [[ -z "${DFLOW_CONTROL_CIDR:-}" ]]; then
    record "INFO" "dflow: controller ssh CIDR" "unset; public-controller root SSH attach disabled by design"
    return 0
  fi

  if [[ -f "${match_dropin}" ]] \
    && grep -qE "^[[:space:]]*Match[[:space:]]+Address[[:space:]]+${DFLOW_CONTROL_CIDR//./\\.}([[:space:]]|\$)" "${match_dropin}" \
    && grep -qE '^[[:space:]]*PermitRootLogin[[:space:]]+prohibit-password' "${match_dropin}"; then
    record "PASS" "dflow: controller ssh Match Address" "${DFLOW_CONTROL_CIDR}"
  else
    record "FAIL" "dflow: controller ssh Match Address" "${match_dropin} missing or does not restrict root SSH to ${DFLOW_CONTROL_CIDR}"
  fi
}
