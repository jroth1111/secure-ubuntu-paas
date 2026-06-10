#!/usr/bin/env bash
# overlays/dflow/dflow-common.sh — dFlow-overlay shared phase logic.
# Source this file; do not execute it directly.
# Requires: set -Eeuo pipefail in the caller.

[[ "${BASH_SOURCE[0]}" != "${0}" ]] \
  || { printf 'Source this file, do not execute it.\n' >&2; exit 1; }
if [[ -z "${BASH_VERSINFO:-}" || "${BASH_VERSINFO[0]}" -lt 4 ]]; then
  printf 'Bash 4+ is required (found %s). On macOS use Homebrew bash and run via its absolute path.\n' "${BASH_VERSION:-unknown}" >&2
  return 1
fi
[[ -z "${_DFLOW_COMMON_LOADED:-}" ]] || return 0
_DFLOW_COMMON_LOADED=1

_dir="$(dirname "${BASH_SOURCE[0]}")"

# shellcheck source=../../lib/common.sh
# shellcheck disable=SC1091
source "${_dir}/../../lib/common.sh"

finalize_dflow_inputs() {
  # dFlow uses Tailscale SSH exclusively; there are no operator-supplied
  # controller credentials to validate. This function is retained as a
  # call-site stub so deploy.sh / setup.sh can call it symmetrically with
  # the Coolify equivalent.
  :
}

# collect_dflow_inputs — dFlow has no PAAS-specific operator inputs beyond the
# universal ones (server-ip, admin-user, pubkey-file, tailscale-auth-key, swap,
# timezone). The dFlow controller drives all worker configuration after attach.
# Kept as an explicit stub so deploy.sh / setup.sh can call it symmetrically
# with collect_coolify_inputs.
collect_dflow_inputs() {
  return 0
}

# collect_dflow_setup_inputs — Wrapper that prompts for the universal inputs
# also needed when running setup.sh directly on a server.
collect_dflow_setup_inputs() {
  [[ -n "${SERVER_IP}" ]]   || prompt_value  SERVER_IP "Server public IP" "" "${IPV4_RE}"
  [[ -n "${ADMIN_USER}" ]]  || prompt_value  ADMIN_USER "Admin username" "dflowadmin" "${LINUX_USER_RE}"
  [[ -n "${PUBKEY_FILE}" ]] || prompt_value  PUBKEY_FILE "SSH public key file" "${HOME}/.ssh/id_ed25519.pub"
  [[ -n "${TAILSCALE_AUTH_KEY}" ]] || prompt_value TAILSCALE_AUTH_KEY "Tailscale auth key (tskey-auth-...)" ""
  [[ -n "${SWAP_SIZE}" ]]   || SWAP_SIZE="2G"
  if [[ -z "${SERVER_TIMEZONE:-}" ]]; then
    if is_true "${AUTO_YES:-false}"; then
      die "Server timezone is required in non-interactive mode. Set SERVER_TIMEZONE or use --server-timezone."
    fi
    prompt_value SERVER_TIMEZONE "Server timezone (IANA, e.g. Australia/Melbourne)" "UTC" "${TIMEZONE_RE}"
  fi
  collect_dflow_inputs
}

# dFlow's controller owns Docker, Dokku 0.35.x, plugins, the Beszel agent app,
# the backups app, and the Dokku-managed reverse proxy. The hardening overlay
# only guarantees the substrate (UFW, SSH, kernel, swap, audit, fail2ban) and
# re-enables Tailscale SSH so the controller can attach. Phases 3 and 4 are
# therefore intentional no-ops.

dflow_phase3_install_shared() {
  step "3/5" "dFlow worker substrate"
  log "dFlow controller installs Docker + Dokku + apps on attach; nothing to install here."
  pass "Substrate ready for dFlow onboarding (kernel, UFW, SSH, swap, audit, fail2ban, Tailscale SSH)"
}

dflow_phase4_routing_shared() {
  step "4/5" "dFlow routing"
  log "dFlow uses Dokku's nginx-vhosts proxy for app routing; nothing to configure on the worker."
  pass "Routing delegated to dFlow controller"
}

# dflow_phase5_verify_shared — Run validate.sh and surface dFlow-specific
# failures. Caller injects fetch_validate_json_fn (returns JSON) so this
# works the same on operator (setup.sh) and remote (deploy.sh) transports.
dflow_phase5_verify_shared() {
  local fetch_validate_json_fn="${1:-}"
  [[ -n "${fetch_validate_json_fn}" ]] || die "dflow_phase5_verify_shared requires fetch_validate_json_fn"

  step "5/5" "Final verification"

  log "Gate F: Running base/validate.sh on the worker..."
  local validate_json
  validate_json="$("${fetch_validate_json_fn}")" \
    || die "Gate F failed: validate.sh did not produce JSON output."
  report_validation_result "Gate F" "${validate_json}" \
    "Gate F failed. Fix validation failures before exposing this worker to dFlow."
}
