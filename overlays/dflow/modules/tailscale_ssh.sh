# dflow/modules/tailscale_ssh.sh — re-enable Tailscale SSH on the worker.
#
# dFlow controllers (tag:dflow-proxy / tag:dflow-support) reach worker hosts
# tagged tag:customer-machine via Tailscale SSH; auth and ACL are enforced by
# tailscaled itself. The base hardening's lib/tailscale.sh runs
# ensure_tailscale_ssh_disabled on the assumption that host-sshd over Tailscale
# is the control plane (Coolify). Under --paas dflow we reverse that: the
# controller's only routine path to the worker is Tailscale SSH, so flip
# RunSSH back to true after the base step has run.

configure_dflow_tailscale_ssh() {
  if [[ "${PAAS:-}" != "dflow" ]]; then
    return 0
  fi

  if ! command -v tailscale >/dev/null 2>&1; then
    warn "tailscale CLI not found; cannot enable Tailscale SSH for dFlow."
    return 0
  fi

  local run_ssh_pref
  run_ssh_pref="$(tailscale_runssh_pref_value 5 1)"

  if [[ "${run_ssh_pref}" == "true" ]]; then
    log "Tailscale SSH already enabled (RunSSH=true); dFlow controller can connect via tailnet."
    return 0
  fi

  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: would run 'tailscale set --ssh=true' so the dFlow controller can attach over the tailnet."
    return 0
  fi

  run tailscale set --ssh=true
  run_ssh_pref="$(tailscale_runssh_pref_value 5 1)"
  [[ "${run_ssh_pref}" == "true" ]] \
    || die "Failed to enable Tailscale SSH for dFlow (RunSSH=${run_ssh_pref:-unknown})."
  log "Tailscale SSH enabled for dFlow controller (tag:dflow-proxy → tag:customer-machine)."
}
