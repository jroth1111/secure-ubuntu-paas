# dflow/modules/ufw.sh — dFlow-specific firewall apertures.

configure_dflow_ufw() {
  [[ "${PAAS:-}" == "dflow" ]] || return 0

  local beszel_port="${DFLOW_BESZEL_PORT:-45876}"

  if [[ "${DFLOW_AUTH_MODE:-ssh}" == "ssh" && -n "${DFLOW_CONTROL_CIDR:-}" ]]; then
    run ufw allow in proto tcp from "${DFLOW_CONTROL_CIDR}" to any port "${SSH_PORT}" comment "dflow-hardening-controller-ssh"
  fi

  run ufw allow in on "${TAILSCALE_IFACE}" proto tcp to any port "${beszel_port}" comment "dflow-hardening-beszel-tailscale"
}
