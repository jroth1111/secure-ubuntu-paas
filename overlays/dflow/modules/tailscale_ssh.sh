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

configure_dflow_ssh_access() {
  [[ "${PAAS:-}" == "dflow" ]] || return 0
  # dFlow's controller path is Tailscale SSH. The base OpenSSH listener is
  # still restricted to the tailnet for the operator account, but dFlow must
  # not inherit Coolify's Docker-bridge root SSH carve-out.
  log "dFlow SSH access: controller uses Tailscale SSH; Docker-bridge root SSH is disabled."
}

configure_dflow_ssh_match_dropin() {
  [[ "${PAAS:-}" == "dflow" ]] || return 0
  local stale_dropin="/etc/ssh/sshd_config.d/15-docker-ssh-match.conf"
  if [[ -L "${stale_dropin}" || -f "${stale_dropin}" ]]; then
    rm -f -- "${stale_dropin}"
    sshd -t || die "sshd validation failed after removing stale Docker SSH Match drop-in."
  fi
  log "dFlow SSH Match policy verified: no Docker-bridge root carve-out."
}

configure_dflow_ufw() {
  [[ "${PAAS:-}" == "dflow" ]] || return 0
  # configure_ufw already owns the deny-by-default policy and Tailscale-only
  # SSH rule. This explicit overlay hook documents and verifies the contract
  # without adding public controller ports.
  if command -v ufw >/dev/null 2>&1; then
    ufw status | grep -q "^Status: active$" \
      || die "dFlow UFW policy is not active."
  fi
  log "dFlow UFW policy verified: controller ingress remains Tailscale-only."
}
