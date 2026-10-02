#!/usr/bin/env bash
if [[ -z "${BASH_VERSINFO:-}" || "${BASH_VERSINFO[0]}" -lt 4 ]]; then
  for candidate in /opt/homebrew/bin/bash /usr/local/bin/bash; do
    if [[ -x "${candidate}" ]]; then
      exec "${candidate}" "$0" "$@"
    fi
  done
  printf 'FATAL: %s requires Bash 4+ (found %s). On macOS: brew install bash, then run with /opt/homebrew/bin/bash %s ...\n' \
    "$(basename "$0")" "${BASH_VERSION:-unknown}" "$(basename "$0")" >&2
  exit 1
fi
set -Eeuo pipefail

# deploy.sh — Laptop-side orchestrator for secure Coolify deployment
# Runs on the operator's machine; SSHes into the remote server.
#
# Interactive mode:  ./deploy.sh
# Non-interactive:   ./deploy.sh --server-ip 1.2.3.4 --root-pass-file /path/root.pass --yes
# Mixed:             ./deploy.sh --server-ip 1.2.3.4  (prompted for the rest)

SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=overlays/coolify/coolify-common.sh
source "${SCRIPT_DIR}/overlays/coolify/coolify-common.sh"
# shellcheck source=overlays/dflow/dflow-common.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/overlays/dflow/dflow-common.sh"
# shellcheck source=overlays/dokploy/dokploy-common.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/overlays/dokploy/dokploy-common.sh"
# shellcheck source=lib/overlay-loader.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/overlay-loader.sh"
# shellcheck source=lib/hardening_resume_reconcile.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/hardening_resume_reconcile.sh"
# shellcheck source=lib/secret_transport.sh
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/secret_transport.sh"

# ── Inputs (populated by flags or prompts) ──────────────────────────────────

SERVER_IP="${SERVER_IP:-}"
SERVER_HOST_KEY_FILE="${SERVER_HOST_KEY_FILE:-}"
ROOT_PASS="${ROOT_PASS:-}"
ROOT_PASS_FILE="${ROOT_PASS_FILE:-}"
ROOT_PASS_RUNTIME_FILE=""
PAAS="${PAAS:-coolify}"
ADMIN_USER="${ADMIN_USER:-}"
PUBKEY_FILE="${PUBKEY_FILE:-}"
TAILSCALE_AUTH_KEY="${TAILSCALE_AUTH_KEY:-}"
TAILSCALE_AUTH_KEY_FILE="${TAILSCALE_AUTH_KEY_FILE:-}"
DEPLOY_MODE="${DEPLOY_MODE:-}"
DOMAIN="${DOMAIN:-}"
CF_API_TOKEN="${CF_API_TOKEN:-}"
CF_API_TOKEN_FILE="${CF_API_TOKEN_FILE:-}"
CF_TUNNEL_API_TOKEN="${CF_TUNNEL_API_TOKEN:-}"
CF_TUNNEL_API_TOKEN_FILE="${CF_TUNNEL_API_TOKEN_FILE:-}"
CF_ZONE="${CF_ZONE:-}"
CF_ZONE_ID="${CF_ZONE_ID:-}"
CF_ACCOUNT_ID="${CF_ACCOUNT_ID:-}"
APP_DOMAIN_MODE="${APP_DOMAIN_MODE:-}"
SWAP_SIZE="${SWAP_SIZE:-}"
SERVER_TIMEZONE="${SERVER_TIMEZONE:-}"
DOKPLOY_ENROLLMENT_SOURCE_IP="${DOKPLOY_ENROLLMENT_SOURCE_IP:-}"
TAILSCALE_DIRECT_WAN="${TAILSCALE_DIRECT_WAN:-false}"
PRIVATE_TLS_CA="${PRIVATE_TLS_CA:-}"
ZEROSSL_EAB_KID="${ZEROSSL_EAB_KID:-}"
ZEROSSL_EAB_KID_FILE="${ZEROSSL_EAB_KID_FILE:-}"
ZEROSSL_EAB_HMAC="${ZEROSSL_EAB_HMAC:-}"
ZEROSSL_EAB_HMAC_FILE="${ZEROSSL_EAB_HMAC_FILE:-}"
AUTO_YES="${AUTO_YES:-false}"
SKIP_HARDEN="${SKIP_HARDEN:-false}"  # set via --ts-ip to resume after partial harden
PREFLIGHT_ONLY="${PREFLIGHT_ONLY:-false}"

# ── Derived at runtime ──────────────────────────────────────────────────────

ADMIN_PUBKEY=""
PRIVATE_KEY=""
TS_IP=""
CF_ZONE_NAME=""
APP_DOMAIN=""
TUNNEL_ID=""
TUNNEL_SECRET=""
REMOTE_DEPLOY_ENV_PATH="/root/deploy.env"
DEPLOY_ENV_REMOTE_PENDING="false"
ROOT_SSH_HOST=""
DOKPLOY_SWARM_UNLOCK_KEY_RUNTIME=""

# ── SSH options ─────────────────────────────────────────────────────────────

# Temp known-hosts files are created in init_ssh_options() (called from main)
# so sourcing this file for tests doesn't trigger mktemp/trap side-effects.
DEPLOY_KNOWN_HOSTS=""
ADMIN_KNOWN_HOSTS=""
declare -a SSH_OPTS=()
declare -a ROOT_SSH_OPTS=()

cleanup_temp_files() {
  rm -f "${DEPLOY_KNOWN_HOSTS:-}" "${ADMIN_KNOWN_HOSTS:-}" "${ROOT_PASS_RUNTIME_FILE:-}"
  secret_transport_cleanup_all
}

sync_operator_known_host_entries() {
  local source_file="${1:-}"
  shift || true
  [[ -n "${HOME:-}" ]] || return 0
  [[ -n "${source_file}" && -s "${source_file}" ]] || return 0

  local ssh_dir="${HOME}/.ssh"
  local operator_known_hosts="${ssh_dir}/known_hosts"
  if ! mkdir -p "${ssh_dir}" 2>/dev/null; then
    warn "Could not create ${ssh_dir}; skipping operator known_hosts refresh."
    return 0
  fi
  chmod 700 "${ssh_dir}" >/dev/null 2>&1 || true
  if ! touch "${operator_known_hosts}" 2>/dev/null; then
    warn "Could not write ${operator_known_hosts}; skipping operator known_hosts refresh."
    return 0
  fi
  chmod 600 "${operator_known_hosts}" >/dev/null 2>&1 || true

  local line added=0
  while IFS= read -r line; do
    [[ -n "${line}" ]] || continue
    if ! grep -qxF -- "${line}" "${operator_known_hosts}" 2>/dev/null; then
      printf '%s\n' "${line}" >> "${operator_known_hosts}" || {
        warn "Could not update ${operator_known_hosts}; skipping remaining operator known_hosts refresh."
        return 0
      }
      added=$((added + 1))
    fi
  done < "${source_file}"

  if (( added > 0 )) && [[ $# -gt 0 ]]; then
    log "Operator known_hosts refreshed for: $*"
  fi
}

known_host_entry_present() {
  local host="$1"
  local known_hosts_file="$2"
  [[ -n "${host}" && -s "${known_hosts_file}" ]] \
    && ssh-keygen -F "${host}" -f "${known_hosts_file}" >/dev/null 2>&1
}

known_host_key_material() {
  local host="$1"
  local known_hosts_file="$2"
  ssh-keygen -F "${host}" -f "${known_hosts_file}" 2>/dev/null \
    | awk 'NF >= 3 && $2 ~ /^(ssh-|ecdsa-|sk-)/ { print $2 " " $3 }' \
    | sort -u || true
}

pin_known_host_alias() {
  local source_host="$1"
  local alias_host="$2"
  local source_file="$3"
  local target_file="$4"
  [[ -n "${source_host}" && -n "${alias_host}" && -s "${source_file}" && -n "${target_file}" ]] || return 1

  local key_material alias_key_material key_type key_blob entry
  key_material="$(known_host_key_material "${source_host}" "${source_file}")"
  [[ -n "${key_material}" ]] || return 1

  alias_key_material="$(known_host_key_material "${alias_host}" "${target_file}")"
  if [[ -n "${alias_key_material}" ]]; then
    # An alias is safe only when its complete key set is exactly the set
    # already verified for the source endpoint.  Presence of any prior key is
    # not proof of identity and must never authorize a privileged transition.
    [[ "${alias_key_material}" == "${key_material}" ]] || return 1
    return 0
  fi

  while read -r key_type key_blob; do
    [[ -n "${key_type}" && -n "${key_blob}" ]] || continue
    entry="${alias_host} ${key_type} ${key_blob}"
    printf '%s\n' "${entry}" >> "${target_file}"
  done <<< "${key_material}"
  alias_key_material="$(known_host_key_material "${alias_host}" "${target_file}")"
  [[ "${alias_key_material}" == "${key_material}" ]]
}

cleanup_remote_deploy_env() {
  [[ "${DEPLOY_ENV_REMOTE_PENDING}" == "true" ]] || return 0

  local cleaned="false"
  if [[ -n "${TS_IP:-}" && -n "${ADMIN_USER:-}" && -n "${PRIVATE_KEY:-}" && ${#SSH_OPTS[@]} -gt 0 ]]; then
    if ssh_admin_sudo "rm -f ${REMOTE_DEPLOY_ENV_PATH}" >/dev/null 2>&1; then
      cleaned="true"
    fi
  fi

  if [[ "${cleaned}" != "true" && -n "${ROOT_SSH_HOST:-}" && -n "${ROOT_PASS_RUNTIME_FILE:-}" && -f "${ROOT_PASS_RUNTIME_FILE}" && ${#ROOT_SSH_OPTS[@]} -gt 0 ]]; then
    if ssh_root "rm -f ${REMOTE_DEPLOY_ENV_PATH}" >/dev/null 2>&1; then
      cleaned="true"
    fi
  fi

  if [[ "${cleaned}" == "true" ]]; then
    DEPLOY_ENV_REMOTE_PENDING="false"
  fi
}

is_tailscale_ipv4() {
  local address="$1" octet1 octet2 octet3 octet4
  [[ "${address}" =~ ${IPV4_RE} ]] || return 1
  IFS=. read -r octet1 octet2 octet3 octet4 <<< "${address}"
  [[ "${octet1}" == "100" && -n "${octet2}" ]] \
    && (( 10#${octet2} >= 64 && 10#${octet2} <= 127 ))
}

deploy_exit_trap() {
  local exit_code=$?
  cleanup_remote_deploy_env
  cleanup_temp_files
  run_report_finalize "${exit_code}"
}

init_ssh_options() {
  # Work from a snapshot of the operator's pinned known_hosts database.  Never
  # accept a first public root host key automatically: the root password and
  # deployment secrets must not cross an unverified SSH endpoint.
  DEPLOY_KNOWN_HOSTS="$(mktemp)" || die "Failed to create temp file for deploy known hosts"
  ADMIN_KNOWN_HOSTS="$(mktemp)" || die "Failed to create temp file for admin known hosts"
  local known_hosts_source="${SERVER_HOST_KEY_FILE:-${HOME:-}/.ssh/known_hosts}"
  if [[ -n "${SERVER_HOST_KEY_FILE}" && ! -f "${known_hosts_source}" ]]; then
    die "Pinned SSH host-key file not found: ${known_hosts_source}"
  fi
  if [[ -f "${known_hosts_source}" ]]; then
    cp "${known_hosts_source}" "${DEPLOY_KNOWN_HOSTS}"
    cp "${known_hosts_source}" "${ADMIN_KNOWN_HOSTS}"
  fi
  chmod 600 "${DEPLOY_KNOWN_HOSTS}" "${ADMIN_KNOWN_HOSTS}"

  SSH_OPTS=(
    -o StrictHostKeyChecking=yes
    -o "UserKnownHostsFile=${ADMIN_KNOWN_HOSTS}"
    -o ConnectTimeout=10
    -o LogLevel=ERROR
  )
  # Root SSH uses password auth; PreferredAuthentications ensures sshpass works even when server
  # advertises publickey first (macOS OpenSSH skips password challenge otherwise).
  ROOT_SSH_OPTS=(
    -o StrictHostKeyChecking=yes
    -o "UserKnownHostsFile=${DEPLOY_KNOWN_HOSTS}"
    -o ConnectTimeout=10
    -o LogLevel=ERROR
    -o PubkeyAuthentication=no
    -o NumberOfPasswordPrompts=1
    -o PreferredAuthentications=keyboard-interactive,password
  )
  ROOT_SSH_HOST="${SERVER_IP}"
}

init_root_password_auth() {
  if is_true "${SKIP_HARDEN}" || is_true "${PREFLIGHT_ONLY}"; then
    return 0
  fi
  [[ -n "${ROOT_PASS}" ]] || die "Root password is required for phase 1."
  ROOT_PASS_RUNTIME_FILE="$(mktemp)" || die "Failed to create temp file for root password"
  chmod 600 "${ROOT_PASS_RUNTIME_FILE}"
  printf '%s' "${ROOT_PASS}" > "${ROOT_PASS_RUNTIME_FILE}"
  ROOT_PASS=""
}

file_sha256() {
  local path="$1"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${path}" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${path}" | awk '{print $1}'
  else
    die "Neither shasum nor sha256sum is available to fingerprint ${path}."
  fi
}

# ── Usage ───────────────────────────────────────────────────────────────────

usage() {
  cat <<'EOF'
deploy.sh — Laptop-side orchestrator for secure PaaS deployment
Run this on your LOCAL MACHINE (laptop/workstation), not on the server.

Usage:
  deploy.sh [options]

If all required flags are provided, runs non-interactively.
If any are missing, prompts for them (mixed mode supported).

Required:
  --server-ip <ip>              Server public IPv4 address
  --server-host-key-file <path> Pinned known_hosts file for first root SSH contact (default: ~/.ssh/known_hosts)
  Root password                 Required unless --preflight-only or --ts-ip is used
  --tailscale-auth-key-file <path>
                                File containing the Tailscale auth key (required unless --preflight-only or --ts-ip)
  --domain <fqdn>               Domain name for Coolify; optional public app domain for Dokploy
  Cloudflare API token          Required for Coolify only; provide via CF_API_TOKEN, --cf-api-token-file, or prompt

Optional:
  --cf-api-token-file <path>    File containing Cloudflare API token
  --cf-tunnel-api-token-file <path>
                                Dedicated tunnel token file (required in tunnel mode)
  --admin-user <name>           Admin username (default: coolifyadmin; dokployadmin for Dokploy)
  --root-pass-file <path>       Read root password from file (recommended for automation)
  --pubkey-file <path>          SSH public key file (default: ~/.ssh/id_ed25519.pub)
  --mode <tunnel|standard>       Deployment mode (default: tunnel)
  --app-domain-mode <vps|apex>  App subdomain scope: vps=appname.DOMAIN, apex=appname.ZONE (default: apex)
  --cf-zone <zone>              Cloudflare zone (default: derived from domain)
  --cf-zone-id <id>             Cloudflare zone ID override (32-char hex)
  --cf-account-id <id>          Cloudflare account ID override (32-char hex)
  --swap-size <size>            Swap size (default: 2G)
  --server-timezone <IANA>      Server timezone (for example: Australia/Melbourne, UTC)
  --dokploy-enrollment-source-ip <100.x.x.x>
                                Operator laptop Tailscale IPv4 allowed to claim the first Dokploy admin
  --private-tls-ca <letsencrypt|zerossl>
                                Private dashboard/websocket CA in tunnel mode (default: letsencrypt)
  --zerossl-eab-kid-file <path> File containing ZeroSSL EAB kid (required when --private-tls-ca zerossl)
  --zerossl-eab-hmac-file <path>
                                File containing ZeroSSL EAB hmac (required when --private-tls-ca zerossl)
  --tailscale-direct-wan        Allow WAN UDP 41641 for direct Tailscale paths (optional optimization)
  --no-tailscale-direct-wan     Keep WAN UDP 41641 closed (default; DERP fallback remains available)
  --preflight-only              Run local/Cloudflare preflight checks only, then exit
  --yes                         Skip confirmation prompts (for automation)
  --ts-ip <ip>                  Skip phase 1 (hardening already done); set Tailscale IP directly
  -h, --help                    Show this help
EOF
}

# ── Argument parsing ────────────────────────────────────────────────────────

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --server-ip)       SERVER_IP="${2:?--server-ip requires a value}"; shift 2 ;;
      --server-host-key-file) SERVER_HOST_KEY_FILE="${2:?--server-host-key-file requires a value}"; shift 2 ;;
      --root-pass)
        die "--root-pass is disabled for security (CLI args leak to process list/history). Use --root-pass-file or interactive prompt."
        ;;
      --root-pass-file)  ROOT_PASS_FILE="${2:?--root-pass-file requires a value}"; shift 2 ;;
      --admin-user)      ADMIN_USER="${2:?--admin-user requires a value}"; shift 2 ;;
      --pubkey-file)     PUBKEY_FILE="${2:?--pubkey-file requires a value}"; shift 2 ;;
      --tailscale-auth-key)
        die "--tailscale-auth-key is disabled because CLI arguments leak secrets to process lists/history. Use --tailscale-auth-key-file, TAILSCALE_AUTH_KEY_FILE, or the silent prompt."
        ;;
      --tailscale-auth-key-file) TAILSCALE_AUTH_KEY_FILE="${2:?--tailscale-auth-key-file requires a value}"; shift 2 ;;
      --mode)            DEPLOY_MODE="${2:?--mode requires a value}"; shift 2 ;;
      --domain)          DOMAIN="${2:?--domain requires a value}"; shift 2 ;;
      --cf-api-token)
        die "--cf-api-token is removed for security. Use CF_API_TOKEN env var or --cf-api-token-file."
        ;;
      --cf-tunnel-api-token)
        die "--cf-tunnel-api-token is removed for security. Use CF_TUNNEL_API_TOKEN env var or --cf-tunnel-api-token-file."
        ;;
      --cf-api-token-file) CF_API_TOKEN_FILE="${2:?--cf-api-token-file requires a value}"; shift 2 ;;
      --cf-tunnel-api-token-file) CF_TUNNEL_API_TOKEN_FILE="${2:?--cf-tunnel-api-token-file requires a value}"; shift 2 ;;
      --cf-zone)         CF_ZONE="${2:?--cf-zone requires a value}"; shift 2 ;;
      --cf-zone-id)      CF_ZONE_ID="${2:?--cf-zone-id requires a value}"; shift 2 ;;
      --cf-account-id)   CF_ACCOUNT_ID="${2:?--cf-account-id requires a value}"; shift 2 ;;
      --app-domain-mode) APP_DOMAIN_MODE="${2:?--app-domain-mode requires a value}"; shift 2 ;;
      --swap-size)       SWAP_SIZE="${2:?--swap-size requires a value}"; shift 2 ;;
      --server-timezone|--timezone) SERVER_TIMEZONE="${2:?$1 requires a value}"; shift 2 ;;
      --dokploy-enrollment-source-ip) DOKPLOY_ENROLLMENT_SOURCE_IP="${2:?--dokploy-enrollment-source-ip requires a value}"; shift 2 ;;
      --private-tls-ca)  PRIVATE_TLS_CA="${2:?--private-tls-ca requires a value}"; shift 2 ;;
      --zerossl-eab-kid-file) ZEROSSL_EAB_KID_FILE="${2:?--zerossl-eab-kid-file requires a value}"; shift 2 ;;
      --zerossl-eab-hmac-file) ZEROSSL_EAB_HMAC_FILE="${2:?--zerossl-eab-hmac-file requires a value}"; shift 2 ;;
      --tailscale-direct-wan) TAILSCALE_DIRECT_WAN="true"; shift ;;
      --no-tailscale-direct-wan) TAILSCALE_DIRECT_WAN="false"; shift ;;
      --preflight-only)  PREFLIGHT_ONLY="true"; shift ;;
      --paas)            PAAS="${2:-coolify}"; shift 2 ;;
      --yes)             AUTO_YES="true"; shift ;;
      --ts-ip)           TS_IP="${2:?--ts-ip requires a value}"; SKIP_HARDEN="true"; shift 2 ;;
      -h|--help)         usage; exit 0 ;;
      *)                 die "Unknown option: $1 (use --help)" ;;
    esac
  done
}

# ── Input collection (flag → prompt fallback) ──────────────────────────────

collect_inputs() {
  if [[ -z "${TAILSCALE_AUTH_KEY}" && -n "${TAILSCALE_AUTH_KEY_FILE}" ]]; then
    TAILSCALE_AUTH_KEY="$(read_secret_file "${TAILSCALE_AUTH_KEY_FILE}" "Tailscale auth key")"
  fi
  # When hardening is being skipped (--ts-ip) or only preflight is requested,
  # tailscale auth key is not needed.
  # Pre-populate to bypass the interactive prompt in collect_common_inputs so that
  # automated --yes --ts-ip runs don't block on read waiting for a key.
  if { is_true "${SKIP_HARDEN}" || is_true "${PREFLIGHT_ONLY}"; } \
    && [[ -z "${TAILSCALE_AUTH_KEY}" ]]; then
    TAILSCALE_AUTH_KEY="(not-needed)"
  fi
  if [[ "${PAAS}" == "dokploy" && -z "${DOKPLOY_ENROLLMENT_SOURCE_IP}" ]] \
    && command -v tailscale >/dev/null 2>&1; then
    local operator_ts_candidate
    operator_ts_candidate="$(tailscale ip -4 2>/dev/null | head -1 | tr -d '[:space:]' || true)"
    if is_tailscale_ipv4 "${operator_ts_candidate}"; then
      DOKPLOY_ENROLLMENT_SOURCE_IP="${operator_ts_candidate}"
    fi
  fi
  case "${PAAS}" in
    dflow)   collect_dflow_setup_inputs ;;
    dokploy) collect_dokploy_setup_inputs ;;
    coolify) collect_common_inputs ;;
    *)       die "Unsupported PAAS: ${PAAS} (expected coolify, dflow, or dokploy)" ;;
  esac
  if ! is_true "${SKIP_HARDEN}" && ! is_true "${PREFLIGHT_ONLY}" \
    && [[ -z "${ROOT_PASS}" ]] && [[ -n "${ROOT_PASS_FILE}" ]]; then
    ROOT_PASS="$(read_secret_file "${ROOT_PASS_FILE}" "Root password")"
  fi
  # ROOT_PASS not needed when --ts-ip is supplied (hardening already done)
  if ! is_true "${SKIP_HARDEN}" && ! is_true "${PREFLIGHT_ONLY}"; then
    [[ -n "${ROOT_PASS}" ]] || prompt_secret ROOT_PASS "Root password"
  fi
}

# ── Input validation ───────────────────────────────────────────────────────

validate_inputs() {
  [[ "${SERVER_IP}" =~ ${IPV4_RE} ]]      || die "Invalid server IP: ${SERVER_IP}"

  # ROOT_PASS not required when --ts-ip or --preflight-only is supplied.
  if ! is_true "${SKIP_HARDEN}" && ! is_true "${PREFLIGHT_ONLY}"; then
    [[ -n "${ROOT_PASS}" ]]               || die "Root password is required."
  fi
  [[ "${ADMIN_USER}" =~ ${LINUX_USER_RE} ]] || die "Invalid admin username: ${ADMIN_USER}"
  [[ "${ADMIN_USER}" != "root" ]]          || die "Admin user must not be root."

  [[ -f "${PUBKEY_FILE}" ]]                || die "Public key file not found: ${PUBKEY_FILE}"
  ssh-keygen -l -f "${PUBKEY_FILE}" >/dev/null 2>&1 \
    || die "Invalid SSH public key: ${PUBKEY_FILE}"
  ADMIN_PUBKEY="$(cat "${PUBKEY_FILE}")"
  PRIVATE_KEY="${PUBKEY_FILE%.pub}"
  [[ -f "${PRIVATE_KEY}" ]] || die "Private key not found: ${PRIVATE_KEY} (expected alongside ${PUBKEY_FILE})"

  # Auth key only required when hardening will run; --ts-ip / --preflight-only skip hardening.
  if ! is_true "${SKIP_HARDEN}" && ! is_true "${PREFLIGHT_ONLY}"; then
    [[ "${TAILSCALE_AUTH_KEY}" != *$'\n'* && "${TAILSCALE_AUTH_KEY}" != *$'\r'* ]] \
      || die "Tailscale auth key must be a single line."
    [[ "${TAILSCALE_AUTH_KEY}" == tskey-auth-* ]] \
      || die "Tailscale auth key must start with 'tskey-auth-' (got: ${TAILSCALE_AUTH_KEY:0:12}...)"
  fi

  # When resuming via --ts-ip, validate the supplied IP is a valid IPv4 address.
  if is_true "${SKIP_HARDEN}"; then
    is_tailscale_ipv4 "${TS_IP}" \
      || die "Invalid Tailscale IP supplied via --ts-ip: '${TS_IP}'"
  fi

  [[ "${SWAP_SIZE}" =~ ${SWAP_RE} ]]       || die "Invalid swap size: ${SWAP_SIZE} (expected e.g. 2G, 512M)"
  [[ "${SERVER_TIMEZONE}" =~ ${TIMEZONE_RE} ]] \
    || die "Invalid server timezone: ${SERVER_TIMEZONE} (expected IANA name like Australia/Melbourne or UTC)"
  case "${TAILSCALE_DIRECT_WAN,,}" in
    true|false|1|0|yes|no|y|n|on|off) ;;
    *) die "TAILSCALE_DIRECT_WAN must be true/false (got: ${TAILSCALE_DIRECT_WAN})" ;;
  esac

  case "${PAAS}" in
    coolify|dflow|dokploy) ;;
    *) die "Invalid --paas value: ${PAAS} (expected coolify|dflow|dokploy)" ;;
  esac

  if [[ "${PAAS}" == "coolify" ]]; then
    # Normalize and validate Cloudflare secrets after basic operator inputs so
    # an ordinary malformed IP/user/key error is not masked by token policy.
    finalize_cloudflare_tokens
    finalize_private_tls_ca_inputs

    [[ "${DEPLOY_MODE}" == "standard" || "${DEPLOY_MODE}" == "tunnel" ]] \
      || die "Mode must be 'standard' or 'tunnel' (got: ${DEPLOY_MODE})"
    [[ "${PRIVATE_TLS_CA}" == "letsencrypt" || "${PRIVATE_TLS_CA}" == "zerossl" ]] \
      || die "Private TLS CA must be 'letsencrypt' or 'zerossl' (got: ${PRIVATE_TLS_CA})"
    if [[ "${DEPLOY_MODE}" == "tunnel" && "${PRIVATE_TLS_CA}" == "zerossl" ]]; then
      [[ -n "${ZEROSSL_EAB_KID}" ]] || die "ZeroSSL EAB kid is required when --private-tls-ca zerossl."
      [[ -n "${ZEROSSL_EAB_HMAC}" ]] || die "ZeroSSL EAB hmac is required when --private-tls-ca zerossl."
    fi

    [[ "${APP_DOMAIN_MODE}" == "vps" || "${APP_DOMAIN_MODE}" == "apex" ]] \
      || die "App domain mode must be 'vps' or 'apex' (got: ${APP_DOMAIN_MODE})"

    [[ "${DOMAIN}" =~ ${FQDN_RE} ]]         || die "Invalid domain: ${DOMAIN}"
    [[ -n "${CF_API_TOKEN}" ]]               || die "Cloudflare API token is required."
    [[ -z "${CF_ZONE_ID}" || "${CF_ZONE_ID}" =~ ${CF_ID_RE} ]] \
      || die "Invalid --cf-zone-id: ${CF_ZONE_ID} (expected 32-char hex)"
    [[ -z "${CF_ACCOUNT_ID}" || "${CF_ACCOUNT_ID}" =~ ${CF_ID_RE} ]] \
      || die "Invalid --cf-account-id: ${CF_ACCOUNT_ID} (expected 32-char hex)"
  elif [[ "${PAAS}" == "dflow" ]]; then
    finalize_dflow_inputs
  else
    finalize_dokploy_inputs
    [[ -z "${DOMAIN}" || "${DOMAIN}" =~ ${FQDN_RE} ]] || die "Invalid Dokploy public app domain: ${DOMAIN}"
    if ! is_true "${PREFLIGHT_ONLY}"; then
      is_tailscale_ipv4 "${DOKPLOY_ENROLLMENT_SOURCE_IP}" \
        || die "Invalid Dokploy enrollment source IP: ${DOKPLOY_ENROLLMENT_SOURCE_IP:-unset} (expected operator Tailscale IPv4 in 100.64.0.0/10)"
    fi
  fi

  # Verify companion scripts exist before prompting to proceed
  local scripts=(base/bootstrap.sh base/validate.sh)
  if [[ "${PAAS}" == "coolify" ]]; then
    scripts+=(overlays/coolify/configure_coolify_binding.sh)
  fi
  for script in "${scripts[@]}"; do
    [[ -f "${SCRIPT_DIR}/${script}" ]] || die "Required script not found: ${SCRIPT_DIR}/${script}"
  done

  if [[ "${PAAS}" == "dokploy" ]]; then
    local dokploy_required=(
      overlays/dokploy/dokploy-common.sh
      overlays/dokploy/checks/dokploy_check.sh
    )
    for f in "${dokploy_required[@]}"; do
      [[ -f "${SCRIPT_DIR}/${f}" ]] || die "Required Dokploy file not found: ${SCRIPT_DIR}/${f}"
    done
  fi
}

# ── SSH wrappers ────────────────────────────────────────────────────────────

ssh_root() {
  [[ -n "${ROOT_PASS_RUNTIME_FILE}" && -f "${ROOT_PASS_RUNTIME_FILE}" ]] \
    || die "Root password runtime file is missing."
  [[ -n "${ROOT_SSH_HOST:-}" ]] || die "ROOT_SSH_HOST is not set."
  sshpass -f "${ROOT_PASS_RUNTIME_FILE}" ssh "${ROOT_SSH_OPTS[@]}" "root@${ROOT_SSH_HOST}" "$@"
}

scp_root() {
  [[ -n "${ROOT_PASS_RUNTIME_FILE}" && -f "${ROOT_PASS_RUNTIME_FILE}" ]] \
    || die "Root password runtime file is missing."
  sshpass -f "${ROOT_PASS_RUNTIME_FILE}" scp "${ROOT_SSH_OPTS[@]}" "$@"
}

retry_root_transport() {
  local description="$1"
  shift

  local attempt rc
  for attempt in 1 2 3; do
    if "$@"; then
      return 0
    else
      rc=$?
    fi
    if (( rc == 255 && attempt < 3 )); then
      warn "${description} failed with SSH/SCP exit 255 on attempt ${attempt}/3; retrying in 3s."
      sleep 3
      continue
    fi
    return "${rc}"
  done
}

extract_bootstrap_tailscale_ip() {
  local capture_file="${1:-}"
  [[ -n "${capture_file}" && -f "${capture_file}" ]] || return 0
  local ip
  ip="$(awk -F= '/^HARDEN_RESULT_TAILSCALE_IP=/{ip=$2} END{gsub(/[[:space:]]/,"",ip); print ip}' "${capture_file}")"
  if is_tailscale_ipv4 "${ip}"; then
    printf '%s\n' "${ip}"
  fi
  # A failed first transport attempt may not have emitted a sentinel yet;
  # callers handle the empty result and decide whether to retry or fail.
  return 0
}

scp_admin() {
  scp "${SSH_OPTS[@]}" -i "${PRIVATE_KEY}" "$@"
}

ssh_admin() {
  if [[ "${PAAS:-coolify}" == "dokploy" ]]; then
    ssh_root_tailscale "$@"
  else
    ssh "${SSH_OPTS[@]}" -i "${PRIVATE_KEY}" "${ADMIN_USER}@${TS_IP}" "$@"
  fi
}

ssh_root_tailscale() {
  is_tailscale_ipv4 "${TS_IP:-}" || die "Tailscale IP is not a valid 100.64.0.0/10 address."
  [[ -n "${PRIVATE_KEY:-}" && -f "${PRIVATE_KEY}" ]] || die "Private key is missing for root Tailscale transport."
  ssh "${SSH_OPTS[@]}" -i "${PRIVATE_KEY}" "root@${TS_IP}" "$@"
}

ssh_admin_sudo() {
  [[ $# -eq 1 ]] || die "ssh_admin_sudo expects exactly one remote command string."
  if [[ "${PAAS:-coolify}" == "dokploy" ]]; then
    # Dokploy keeps the metadata account non-login and non-privileged. Privileged
    # orchestration uses the root key on the Tailscale-only SSH path.
    ssh_root_tailscale "$1"
  else
    ssh "${SSH_OPTS[@]}" -i "${PRIVATE_KEY}" "${ADMIN_USER}@${TS_IP}" "sudo $1"
  fi
}

dokploy_swarm_unlock_keychain_service() {
  printf 'secure-ubuntu-paas/dokploy/swarm-unlock/%s\n' "${SERVER_IP}"
}

store_dokploy_swarm_unlock_key() {
  local unlock_key="$1"
  local account="${USER:-operator}"
  local service
  service="$(dokploy_swarm_unlock_keychain_service)"
  [[ "${unlock_key}" =~ ^SWMKEY- ]] \
    || die "Dokploy Swarm unlock handoff was missing or malformed; the key was not stored."
  command -v security >/dev/null 2>&1 \
    || die "macOS Keychain CLI is unavailable; retrieve the one-time remote handoff before removing it."
  command -v expect >/dev/null 2>&1 \
    || die "expect is required for non-argv Keychain handoff; retrieve the one-time remote handoff before removing it."
  # macOS security's -w option prompts on its controlling terminal rather than
  # consuming a normal pipe. Feed the key to an expect-owned pseudo-terminal:
  # the value travels only on expect's stdin and in its memory, never in the
  # argv or environment of security or expect. The remote copy is removed only
  # after this Keychain write and verification succeed.
  if ! DOKPLOY_KEYCHAIN_ACCOUNT="${account}" DOKPLOY_KEYCHAIN_SERVICE="${service}" \
    printf '%s\n' "${unlock_key}" \
    | DOKPLOY_KEYCHAIN_ACCOUNT="${account}" DOKPLOY_KEYCHAIN_SERVICE="${service}" \
      expect -c '
        set unlock_key [string trimright [read stdin] "\r\n"]
        spawn security add-generic-password -a $env(DOKPLOY_KEYCHAIN_ACCOUNT) -s $env(DOKPLOY_KEYCHAIN_SERVICE) -U -w
        expect {
          -re {password data for new item:} { send -- "$unlock_key\r"; exp_continue }
          -re {retype password for new item:} { send -- "$unlock_key\r"; exp_continue }
          eof {}
        }
        catch wait result
        exit [lindex $result 3]
      ' >/dev/null 2>&1; then
    die "Failed to store the Dokploy Swarm unlock key in the operator Keychain."
  fi
  security find-generic-password -a "${account}" -s "${service}" >/dev/null 2>&1 \
    || die "Keychain verification failed for the Dokploy Swarm unlock key."
}

load_dokploy_swarm_unlock_key() {
  local account="${USER:-operator}" service unlock_key
  service="$(dokploy_swarm_unlock_keychain_service)"
  unlock_key="$(security find-generic-password -a "${account}" -s "${service}" -w 2>/dev/null)" \
    || die "The Dokploy Swarm unlock key is unavailable in the operator Keychain."
  [[ "${unlock_key}" =~ ^SWMKEY- ]] \
    || die "The Dokploy Swarm unlock key in the operator Keychain is malformed."
  DOKPLOY_SWARM_UNLOCK_KEY_RUNTIME="${unlock_key}"
  unset unlock_key
}

capture_dokploy_swarm_unlock_handoff_remote() {
  local unlock_key
  unlock_key="$(ssh_admin_sudo "set -Eeuo pipefail; handoff=${DOKPLOY_SWARM_UNLOCK_HANDOFF_FILE}; [[ -f \"\${handoff}\" && ! -L \"\${handoff}\" ]] || exit 4; read -r uid gid mode < <(stat -c '%u %g %a' \"\${handoff}\"); [[ \"\${uid}:\${gid}:\${mode}\" == '0:0:600' ]]; cat \"\${handoff}\"")" \
    || die "Dokploy Swarm unlock handoff is missing or does not meet the root:root 0600 contract."
  [[ "${unlock_key}" =~ ^SWMKEY- ]] \
    || die "Dokploy Swarm unlock handoff was malformed; the remote copy was preserved."
  store_dokploy_swarm_unlock_key "${unlock_key}"
  DOKPLOY_SWARM_UNLOCK_KEY_RUNTIME="${unlock_key}"
  unset unlock_key
  ssh_admin_sudo "rm -f -- ${DOKPLOY_SWARM_UNLOCK_HANDOFF_FILE}" \
    || die "Swarm unlock key reached Keychain, but the temporary VPS handoff could not be removed."
}

dokploy_swarm_state_remote() {
  ssh_admin_sudo 'state="$(docker info --format "{{.Swarm.LocalNodeState}}" 2>/dev/null || true)"; autolock="$(docker info 2>/dev/null | awk -F: '\''/Autolock Managers/ {gsub(/[[:space:]]/, "", $2); print tolower($2); exit}'\'' || true)"; printf "%s\t%s\n" "${state}" "${autolock}"'
}

unlock_dokploy_swarm_remote() {
  local secret_dir secret_file secret_file_q rc=0 attempt state
  [[ "${DOKPLOY_SWARM_UNLOCK_KEY_RUNTIME:-}" =~ ^SWMKEY- ]] \
    || die "Refusing Dokploy Swarm unlock without a validated operator-held key."

  for (( attempt=1; attempt<=24; attempt++ )); do
    state="$(dokploy_swarm_state_remote | cut -f1 | tr -d '[:space:]')"
    [[ "${state}" == "locked" ]] && break
    if [[ "${state}" == "active" ]]; then
      pass "Docker Swarm was already active after reboot"
      return 0
    fi
    (( attempt < 24 )) || die "Docker Swarm did not reach a state that can be unlocked after reboot."
    sleep 5
  done

  secret_dir="$(remote_secret_dir_create)" \
    || die "Failed to create protected remote Swarm unlock staging."
  secret_file="${secret_dir}/swarm-unlock-key"
  secret_file_q="$(printf '%q' "${secret_file}")"
  if ! remote_secret_write_file "${secret_file}" "${DOKPLOY_SWARM_UNLOCK_KEY_RUNTIME}"; then
    remote_secret_cleanup_dir "${secret_dir}"
    die "Failed to transfer the Swarm unlock key over protected stdin."
  fi
  if ssh_admin_sudo "timeout 30 docker swarm unlock < ${secret_file_q}" >/dev/null; then
    rc=0
  else
    rc=$?
  fi
  remote_secret_cleanup_dir "${secret_dir}"
  (( rc == 0 )) || die "Docker Swarm unlock failed after reboot. The Keychain copy was preserved."

  for (( attempt=1; attempt<=12; attempt++ )); do
    state="$(dokploy_swarm_state_remote | cut -f1 | tr -d '[:space:]')"
    [[ "${state}" == "active" ]] && break
    (( attempt < 12 )) || die "Docker Swarm did not return to active state after unlock."
    sleep 5
  done
  pass "Docker Swarm unlocked from the external operator key"
}

ensure_dokploy_swarm_unlocked_remote() {
  [[ "${PAAS:-coolify}" == "dokploy" ]] || return 0
  local state_line state autolock
  state_line="$(dokploy_swarm_state_remote)"
  IFS=$'\t' read -r state autolock <<< "${state_line}"
  case "${state}" in
    active|inactive|"") return 0 ;;
    locked)
      if ssh_admin_sudo "test -f ${DOKPLOY_SWARM_UNLOCK_HANDOFF_FILE}" >/dev/null 2>&1; then
        capture_dokploy_swarm_unlock_handoff_remote
      else
        load_dokploy_swarm_unlock_key
      fi
      unlock_dokploy_swarm_remote
      DOKPLOY_SWARM_UNLOCK_KEY_RUNTIME=""
      ;;
    *) die "Unexpected Docker Swarm state '${state}' on the Dokploy host." ;;
  esac
}

remote_secret_dir_create() {
  ssh_admin_sudo 'install -d -m 0700 -o root -g root /run/secure-ubuntu-paas; umask 077; mktemp -d -p /run/secure-ubuntu-paas deploy-secrets.XXXXXXXX'
}

remote_secret_write_file() {
  local path="$1" value="$2" path_q
  [[ "${value}" != *$'\n'* && "${value}" != *$'\r'* ]] \
    || die "Refusing multiline remote secret material."
  path_q="$(printf '%q' "${path}")"
  printf '%s\n' "${value}" | ssh_admin_sudo "install -m 0600 -o root -g root /dev/stdin ${path_q}"
}

remote_secret_cleanup_dir() {
  local dir="$1" dir_q
  dir_q="$(printf '%q' "${dir}")"
  ssh_admin_sudo "find ${dir_q} -mindepth 1 -maxdepth 1 -type f -delete 2>/dev/null || true; rmdir ${dir_q} 2>/dev/null || true" \
    >/dev/null 2>&1 || true
}

package_deployment_tree() {
  local dest="$1"
  local -a tar_metadata_args=()
  for d in base lib overlays; do
    [[ -d "${SCRIPT_DIR}/${d}" ]] || die "Required directory not found: ${SCRIPT_DIR}/${d}"
  done
  # bsdtar on macOS can archive com.apple.* metadata as SCHILY pax headers
  # even with COPYFILE_DISABLE=1, producing noisy extraction warnings on Linux.
  if tar --no-xattrs -cf /dev/null --files-from /dev/null >/dev/null 2>&1; then
    tar_metadata_args+=(--no-xattrs)
  fi
  if ! ( cd "${SCRIPT_DIR}" && COPYFILE_DISABLE=1 tar "${tar_metadata_args[@]}" --exclude '._*' --exclude '.DS_Store' -czf "${dest}" base lib overlays ); then
    die "Failed to package deployment tree from ${SCRIPT_DIR}"
  fi
}

install_deployment_tree_remote_script() {
  cat <<'EOF'
set -Eeuo pipefail
archive="${DEPLOY_TREE_ARCHIVE:?DEPLOY_TREE_ARCHIVE is required}"
expected_sha256="${DEPLOY_TREE_SHA256:?DEPLOY_TREE_SHA256 is required}"
[[ "${archive}" == /run/secure-ubuntu-paas/deploy-trees/deploy-tree.*/tree.tar.gz ]] \
  || { echo "Deployment archive must use the protected staging directory." >&2; exit 1; }
archive_dir="$(dirname -- "${archive}")"
[[ -f "${archive}" && ! -L "${archive}" ]] \
  || { echo "Deployment archive is missing or is a symlink." >&2; exit 1; }
read -r archive_uid archive_mode < <(stat -c '%u %a' "${archive_dir}" 2>/dev/null)
[[ "${archive_uid}" == "0" && "${archive_mode}" == "700" ]] \
  || { echo "Deployment archive directory is not root-owned mode 0700." >&2; exit 1; }
read -r archive_uid archive_mode < <(stat -c '%u %a' "${archive}" 2>/dev/null)
[[ "${archive_uid}" == "0" && "${archive_mode}" == "600" ]] \
  || { echo "Deployment archive is not root-owned mode 0600." >&2; exit 1; }
actual_sha256="$(sha256sum "${archive}" | awk '{print $1}')"
[[ "${actual_sha256}" == "${expected_sha256}" ]] \
  || { echo "Deployment archive integrity check failed." >&2; exit 1; }
if tar -tzf "${archive}" | awk '
  $0 ~ /^\// || $0 ~ /(^|\/)\.\.($|\/)/ || $0 !~ /^(base|lib|overlays)(\/|$)/ { bad=1 }
  END { exit(bad ? 1 : 0) }
'; then
  :
else
  echo "Deployment archive contains an unsafe path." >&2
  exit 1
fi
tar -C /root --no-same-owner --no-same-permissions -xzf "${archive}"
rm -f -- "${archive}"
rmdir -- "${archive_dir}" 2>/dev/null || true
chown -R root:root /root/base /root/lib /root/overlays
chmod 755 /root/base/bootstrap.sh /root/base/validate.sh
chmod 755 /root/overlays/coolify/configure_coolify_binding.sh 2>/dev/null || true
chmod 755 /root/overlays/dflow/data/dokku-predeploy-resource-check.sh 2>/dev/null || true
EOF
}

remote_tree_dir_create() {
  ssh_admin_sudo 'install -d -m 0700 -o root -g root /run/secure-ubuntu-paas/deploy-trees; umask 077; mktemp -d -p /run/secure-ubuntu-paas/deploy-trees deploy-tree.XXXXXXXX'
}

remote_tree_cleanup() {
  local tree_dir="$1" tree_dir_q
  [[ "${tree_dir}" == /run/secure-ubuntu-paas/deploy-trees/deploy-tree.* ]] || return 0
  tree_dir_q="$(printf '%q' "${tree_dir}")"
  ssh_admin_sudo "find ${tree_dir_q} -mindepth 1 -maxdepth 1 -type f -delete 2>/dev/null || true; rmdir ${tree_dir_q} 2>/dev/null || true" \
    >/dev/null 2>&1 || true
}

# Upload base/, lib/, and overlays/ as one tarball. Phase 2 always re-syncs the
# full tree so --ts-ip resumes get new validators without 60+ sequential SCPs.
sync_companion_scripts() {
  local tree_tar tree_sha256 tree_dir tree_archive tree_archive_q tree_sha256_q extract_command
  local tree_dir_output tree_dir_attempt tree_dir_rc
  log "Syncing deployment tree to server /root/ (tarball)..."
  tree_tar="$(mktemp -t deploy-tree.XXXXXXXX.tar.gz)" || die "Failed to create temp tarball"
  if ! package_deployment_tree "${tree_tar}"; then
    rm -f "${tree_tar}"
    die "Failed to package deployment tree"
  fi
  tree_sha256="$(file_sha256 "${tree_tar}")" \
    || { rm -f "${tree_tar}"; die "Failed to fingerprint deployment tree"; }
  tree_dir="$(remote_tree_dir_create | tr -d '[:space:]')" \
    || { rm -f "${tree_tar}"; die "Failed to create protected deployment staging directory"; }
  [[ "${tree_dir}" == /run/secure-ubuntu-paas/deploy-trees/deploy-tree.* ]] \
    || { rm -f "${tree_tar}"; remote_tree_cleanup "${tree_dir}"; die "Remote deployment staging directory was unexpected"; }
  tree_archive="${tree_dir}/tree.tar.gz"
  tree_archive_q="$(printf '%q' "${tree_archive}")"
  if ! cat "${tree_tar}" | ssh_admin_sudo "install -m 0600 -o root -g root /dev/stdin ${tree_archive_q}"; then
    rm -f "${tree_tar}"
    remote_tree_cleanup "${tree_dir}"
    die "Failed to upload deployment tree to protected staging directory"
  fi
  rm -f "${tree_tar}"
  local extract_script
  extract_script="$(mktemp)" || die "Failed to create temp extract script"
  install_deployment_tree_remote_script > "${extract_script}"
  tree_sha256_q="$(printf '%q' "${tree_sha256}")"
  extract_command="DEPLOY_TREE_ARCHIVE=${tree_archive_q} DEPLOY_TREE_SHA256=${tree_sha256_q} bash -s"
  ssh_admin_sudo "${extract_command}" < "${extract_script}" \
    || { rm -f "${extract_script}"; remote_tree_cleanup "${tree_dir}"; die "Failed to extract deployment tree on server"; }
  rm -f "${extract_script}"
  pass "Deployment tree synced to server"
}

run_remote_script_via_admin() {
  local label="$1"
  shift
  local script_tmp attempt rc
  script_tmp="$(mktemp)" || die "Failed to create temp script for ${label}"
  "$@" > "${script_tmp}"
  for attempt in 1 2 3 4 5 6; do
    rc=0
    ssh_admin_sudo 'bash -s' < "${script_tmp}" || rc=$?
    if (( rc == 0 )); then
      rm -f "${script_tmp}"
      return 0
    fi
    if (( rc != 255 || attempt == 6 )); then
      rm -f "${script_tmp}"
      die "${label} failed on server."
    fi
    warn "${label}: SSH transport unavailable after network reconciliation (attempt ${attempt}/6); retrying in 5s."
    sleep 5
  done
}

reconcile_resume_hardening_remote() {
  log "Reconciling idempotent hardening state before Gate C..."
  run_remote_script_via_admin "Base hardening reconcile" hardening_resume_reconcile_script
  case "${PAAS}" in
    dokploy)
      run_remote_script_via_admin "Dokploy root Tailscale SSH policy" dokploy_root_tailscale_reconcile_script
      run_remote_script_via_admin "Stale Coolify UFW cleanup" dokploy_remove_stale_coolify_dashboard_ufw_script \
        || true
      run_remote_script_via_admin "Dokploy dashboard UFW policy" dokploy_dashboard_ufw_policy_script
      ;;
  esac
  pass "Hardening state reconciled for Gate C"
}

verify_docker_user_gate_remote() {
  local gate_label="$1"
  local gate_d_inactive_msg="Gate D failed: docker-user-hardening.service is not active."
  local attempt rc service_active="false" rules_present="false"

  for attempt in 1 2 3 4 5 6; do
    rc=0
    ssh_admin_sudo 'systemctl is-active --quiet docker-user-hardening.service' || rc=$?
    if (( rc == 0 )); then
      service_active="true"
      break
    fi
    if (( attempt == 6 )); then
      break
    fi
    if (( rc == 255 )); then
      warn "${gate_label}: SSH transport unavailable while checking docker-user-hardening.service (attempt ${attempt}/6); retrying in 5s."
    else
      warn "${gate_label}: docker-user-hardening.service has not converged yet (attempt ${attempt}/6); retrying in 5s."
    fi
    sleep 5
  done
  if [[ "${service_active}" == "true" ]]; then
    pass "${gate_label}: docker-user-hardening.service is active"
  else
    fail "${gate_label}: docker-user-hardening.service is not active"
    die "${gate_d_inactive_msg}"
  fi

  for attempt in 1 2 3 4 5 6; do
    rc=0
    ssh_admin_sudo 'source /root/overlays/docker-host/modules/readiness.sh; TUNNEL_MODE="$(awk -F= '\''$1 == "TUNNEL_MODE" { print substr($0, index($0, "=") + 1); exit }'\'' /etc/default/docker-user-hardening 2>/dev/null || true)"; DOCKER_PRESENT="true"; docker_user_rules_present' || rc=$?
    if (( rc == 0 )); then
      rules_present="true"
      break
    fi
    if (( attempt == 6 )); then
      break
    fi
    if (( rc == 255 )); then
      warn "${gate_label}: SSH transport unavailable while checking DOCKER-USER rules (attempt ${attempt}/6); retrying in 5s."
    else
      warn "${gate_label}: DOCKER-USER policy has not converged yet (attempt ${attempt}/6); retrying in 5s."
    fi
    sleep 5
  done
  if [[ "${rules_present}" == "true" ]]; then
    pass "${gate_label}: DOCKER-USER hardening rules active"
  else
    fail "${gate_label}: DOCKER-USER hardening rules not found"
    die "${gate_label} failed. Check: sudo systemctl status docker-user-hardening.service"
  fi
}

reconcile_docker_daemon_remote() {
  local reconcile_fn="coolify_reconcile_docker_daemon_script"
  if [[ "${PAAS:-coolify}" == "dokploy" ]]; then
    reconcile_fn="dokploy_reconcile_docker_daemon_script"
  fi
  log "Reconciling Docker daemon settings after ${PAAS:-coolify} install..."
  if [[ "${PAAS:-coolify}" == "dokploy" ]]; then
    "${reconcile_fn}" | ssh_root_tailscale 'bash -s' \
      || die "Failed to reconcile Docker daemon hardening settings."
  else
    "${reconcile_fn}" | ssh_admin 'sudo bash -s' \
      || die "Failed to reconcile Docker daemon hardening settings."
  fi
  if [[ "${PAAS:-coolify}" == "dokploy" ]]; then
    pass "Docker daemon hardening reconciled (Swarm-safe json-file log rotation)"
  else
    pass "Docker daemon hardening reconciled (json-file log rotation + live-restore)"
  fi
}

# ── Pre-flight ──────────────────────────────────────────────────────────────

preflight() {
  step "0/5" "Pre-flight checks"

  # Check local tools
  local required_cmds=(ssh scp curl jq sshpass ssh-keygen openssl tar)
  if [[ "${PAAS}" == "dokploy" ]]; then
    required_cmds+=(expect security)
  fi
  for cmd in "${required_cmds[@]}"; do
    command -v "${cmd}" >/dev/null 2>&1 || die "Required command not found: ${cmd}. Install it first."
  done
  pass "Local tools present: ${required_cmds[*]}"

  # Validate pubkey
  ssh-keygen -l -f "${PUBKEY_FILE}" >/dev/null 2>&1 || die "Invalid SSH public key file: ${PUBKEY_FILE}"
  pass "SSH public key valid: ${PUBKEY_FILE}"

  if [[ "${PAAS}" == "coolify" ]]; then
    # Verify Cloudflare token
    cf_verify_token
    cf_get_zone_id
    cf_verify_dns_write_token
    cf_get_account_id  # always fetch — needed for tunnel (default mode)
    cf_verify_tunnel_token
    resolve_app_domain
    cf_verify_private_tls_ca_caa
    pass "Cloudflare API verified (zone: ${CF_ZONE_ID})"
  elif [[ "${PAAS}" == "dflow" ]]; then
    pass "dFlow: Cloudflare preflight skipped (controller manages routing)"
  else
    pass "Dokploy: Cloudflare preflight skipped (public app DNS is operator-managed)"
  fi

  # Test SSH connectivity (skipped for --ts-ip and --preflight-only).
  if is_true "${SKIP_HARDEN}" || is_true "${PREFLIGHT_ONLY}"; then
    log "Skipping root SSH check (--ts-ip/--preflight-only mode)."
  else
    log "Testing SSH to root@${SERVER_IP}..."
    if ! known_host_entry_present "${SERVER_IP}" "${DEPLOY_KNOWN_HOSTS}"; then
      die "No pinned SSH host key for ${SERVER_IP}. Add the provider-verified key to ${SERVER_HOST_KEY_FILE:-${HOME}/.ssh/known_hosts} (or pass --server-host-key-file) before sending the root password."
    fi
    if ssh_root 'echo ok' >/dev/null 2>&1; then
      sync_operator_known_host_entries "${DEPLOY_KNOWN_HOSTS}" "${SERVER_IP}"
      pass "SSH root@${SERVER_IP} reachable"
    else
      die "Cannot SSH to root@${SERVER_IP}. Check IP and root password."
    fi
  fi
}

# ── Phase 1: Upload + Harden ───────────────────────────────────────────────

phase1_upload_harden() {
  step "1/5" "Upload scripts & harden server"
  local bootstrap_cmd bootstrap_cmd_script
  bootstrap_cmd_script="$(cat <<EOF
set -Eeuo pipefail
cleanup() { rm -f -- ${REMOTE_DEPLOY_ENV_PATH@Q}; }
trap cleanup EXIT
/root/base/bootstrap.sh --env-file ${REMOTE_DEPLOY_ENV_PATH@Q} --install-tailscale --force
EOF
)"
  printf -v bootstrap_cmd 'bash -lc %q' "${bootstrap_cmd_script}"
  local bootstrap_transport="root"

  local tree_tar tree_sha256 tree_dir tree_archive tree_archive_q tree_sha256_q extract_command
  tree_tar="$(mktemp -t deploy-tree.XXXXXXXX.tar.gz)" || die "Failed to create temp tarball"
  if ! package_deployment_tree "${tree_tar}"; then
    rm -f "${tree_tar}"
    die "Failed to package deployment tree"
  fi

  tree_sha256="$(file_sha256 "${tree_tar}")" \
    || { rm -f "${tree_tar}"; die "Failed to fingerprint deployment tree"; }
  tree_dir_output="$(mktemp)" \
    || { rm -f "${tree_tar}"; die "Failed to allocate local staging-path capture file"; }
  tree_dir_rc=0
  for tree_dir_attempt in 1 2 3; do
    if ssh_root 'install -d -m 0700 -o root -g root /run/secure-ubuntu-paas/deploy-trees; umask 077; mktemp -d -p /run/secure-ubuntu-paas/deploy-trees deploy-tree.XXXXXXXX' \
      > "${tree_dir_output}"; then
      tree_dir_rc=0
      break
    else
      tree_dir_rc=$?
      : > "${tree_dir_output}"
    fi
    if (( tree_dir_rc == 255 && tree_dir_attempt < 3 )); then
      warn "Creating protected deployment staging directory failed with SSH exit 255 on attempt ${tree_dir_attempt}/3; retrying in 3s."
      sleep 3
      continue
    fi
    break
  done
  if (( tree_dir_rc != 0 )); then
    rm -f "${tree_tar}" "${tree_dir_output}"
    die "Failed to create protected deployment staging directory on ${SERVER_IP} (SSH exit ${tree_dir_rc})"
  fi
  tree_dir="$(tr -d '[:space:]' < "${tree_dir_output}")"
  rm -f "${tree_dir_output}"
  [[ "${tree_dir}" == /run/secure-ubuntu-paas/deploy-trees/deploy-tree.* ]] \
    || { rm -f "${tree_tar}"; die "Remote deployment staging directory was unexpected"; }
  tree_archive="${tree_dir}/tree.tar.gz"
  if ! retry_root_transport "Uploading deployment tree to ${SERVER_IP}" \
       scp_root "${tree_tar}" "root@${SERVER_IP}:${tree_archive}"; then
    rm -f "${tree_tar}"
    die "Failed to upload deployment tree to ${SERVER_IP}"
  fi
  rm -f "${tree_tar}"

  tree_archive_q="$(printf '%q' "${tree_archive}")"
  tree_sha256_q="$(printf '%q' "${tree_sha256}")"
  extract_command="DEPLOY_TREE_ARCHIVE=${tree_archive_q} DEPLOY_TREE_SHA256=${tree_sha256_q} bash -s"
  retry_root_transport "Extracting deployment tree on ${SERVER_IP}" \
    ssh_root "${extract_command}" \
    < <(install_deployment_tree_remote_script) \
    || die "Failed to extract deployment tree on ${SERVER_IP}"
  pass "Scripts uploaded"

  # We have just opened a burst of short-lived root password-auth sessions for upload/chmod.
  # Some providers intermittently wobble on the first immediately-following long SSH command,
  # even though root password auth is otherwise valid. Re-probe the transport here before
  # placing secrets on the server so a failing transport does not strand deploy.env remotely.
  if ! retry_root_transport "Pre-bootstrap root SSH probe to ${SERVER_IP}" ssh_root 'true'; then
    die "Root SSH probe failed after companion upload burst; refusing to upload deploy.env or start base/bootstrap.sh."
  fi
  pass "Root SSH probe succeeded before deploy env upload"

  # Write env file on server (avoids quoting issues with SSH pubkey)
  local tunnel_flag="false"
  [[ "${DEPLOY_MODE}" == "tunnel" ]] && tunnel_flag="true"
  [[ "${TAILSCALE_AUTH_KEY}" != *$'\n'* && "${TAILSCALE_AUTH_KEY}" != *$'\r'* ]] \
    || die "Tailscale auth key must be a single line before it is serialized."
  [[ "${ADMIN_PUBKEY}" != *$'\n'* && "${ADMIN_PUBKEY}" != *$'\r'* ]] \
    || die "Administrator public key must be a single line before it is serialized."
  local deploy_env_tmp
  deploy_env_tmp="$(mktemp)" || die "Failed to create temp file for deploy env"
  {
    printf 'ADMIN_USER="%s"\n' "${ADMIN_USER//\"/\\\"}"
    printf 'ADMIN_PUBKEY="%s"\n' "${ADMIN_PUBKEY//\"/\\\"}"
    printf 'DOMAIN="%s"\n' "${DOMAIN//\"/\\\"}"
    printf 'TAILSCALE_CIDR="100.64.0.0/10"\n'
    printf 'SSH_PORT="22"\n'
    printf 'TUNNEL_MODE="%s"\n' "${tunnel_flag//\"/\\\"}"
    printf 'SWAP_SIZE="%s"\n' "${SWAP_SIZE//\"/\\\"}"
    printf 'TIMEZONE="%s"\n' "${SERVER_TIMEZONE//\"/\\\"}"
    printf 'INSTALL_TAILSCALE="true"\n'
    printf 'TAILSCALE_AUTH_KEY="%s"\n' "${TAILSCALE_AUTH_KEY//\"/\\\"}"
    printf 'TAILSCALE_DIRECT_WAN="%s"\n' "${TAILSCALE_DIRECT_WAN//\"/\\\"}"
    printf 'BIND_DASHBOARD_TO_TAILSCALE="false"\n'
    printf 'PAAS="%s"\n' "${PAAS//\"/\\\"}"
  } > "${deploy_env_tmp}"
  chmod 600 "${deploy_env_tmp}"
  if ! scp_root "${deploy_env_tmp}" "root@${SERVER_IP}:${REMOTE_DEPLOY_ENV_PATH}"; then
    rm -f "${deploy_env_tmp}"
    die "Failed to upload deploy env file to ${SERVER_IP}"
  fi
  rm -f "${deploy_env_tmp}"
  if ! ssh_root "chmod 600 ${REMOTE_DEPLOY_ENV_PATH}"; then
    die "Failed to set permissions on ${REMOTE_DEPLOY_ENV_PATH}"
  fi
  DEPLOY_ENV_REMOTE_PENDING="true"
  pass "Environment file written"

  # Run hardening, streaming output to terminal while capturing it for TS_IP extraction.
  # base/bootstrap.sh emits HARDEN_RESULT_TAILSCALE_IP as soon as Tailscale is
  # verified, and again at the end. Retries pivot to the PaaS-specific
  # Tailscale transport once public root password auth is no longer valid:
  # root@TS_IP for Dokploy, otherwise admin@TS_IP via sudo.
  log "Running base/bootstrap.sh (this may take a few minutes)..."
  local harden_tmp bootstrap_attempt bootstrap_rc
  harden_tmp="$(mktemp)" || die "Failed to create temp file for hardening output"
  bootstrap_rc=0

  bootstrap_remote_exec() {
    if [[ "${bootstrap_transport}" == "admin" ]]; then
      ssh_admin_sudo "${bootstrap_cmd}"
    else
      ssh_root "${bootstrap_cmd}"
    fi
  }

  bootstrap_remote_tail_log() {
    if [[ "${bootstrap_transport}" == "admin" ]]; then
      ssh_admin_sudo 'tail -n 50 /var/log/server-hardening.log 2>/dev/null || true'
    else
      ssh_root 'tail -n 50 /var/log/server-hardening.log 2>/dev/null || true'
    fi
  }

  promote_bootstrap_transport_to_admin() {
    [[ "${bootstrap_transport}" == "admin" ]] && return 0
    is_tailscale_ipv4 "${TS_IP:-}" || return 1
    if ssh_admin 'echo ok' >/dev/null 2>&1; then
      bootstrap_transport="admin"
      if [[ "${PAAS:-coolify}" == "dokploy" ]]; then
        log "Phase 1 fallback: using root@${TS_IP} over Tailscale for privileged retries (Dokploy admin has no sudo)"
      else
        log "Phase 1 fallback: switching bootstrap retries to ${ADMIN_USER}@${TS_IP} via sudo"
      fi
      return 0
    fi
    return 1
  }

  # Capture stdout/stderr while preserving failure semantics from the SSH command.
  # Emit heartbeat lines so the operator sees progress even when apt/tee is quiet.
  for bootstrap_attempt in 1 2 3; do
    if run_with_heartbeat \
      "base/bootstrap.sh via ${bootstrap_transport}@${ROOT_SSH_HOST:-${TS_IP:-${SERVER_IP}}} (attempt ${bootstrap_attempt}/3)" \
      stream_command_output "${harden_tmp}" \
      bootstrap_remote_exec; then
      bootstrap_rc=0
      break
    else
      bootstrap_rc=$?
      local captured_ts_ip=""
      captured_ts_ip="$(extract_bootstrap_tailscale_ip "${harden_tmp}")"
      if is_tailscale_ipv4 "${captured_ts_ip}"; then
        TS_IP="${captured_ts_ip}"
        if [[ "${ROOT_SSH_HOST}" != "${TS_IP}" ]]; then
          pin_known_host_alias "${SERVER_IP}" "${TS_IP}" "${DEPLOY_KNOWN_HOSTS}" "${ADMIN_KNOWN_HOSTS}" \
            || die "Could not pin the verified public SSH host key to Tailscale address ${TS_IP}. Refusing the phase 1 recovery transition."
          ROOT_SSH_HOST="${TS_IP}"
          log "Phase 1 fallback: switching root retries to Tailscale IP ${TS_IP}"
        fi
      fi
      if (( bootstrap_rc == 255 && bootstrap_attempt < 3 )); then
        if promote_bootstrap_transport_to_admin; then
          if [[ "${PAAS:-coolify}" == "dokploy" ]]; then
            warn "base/bootstrap.sh SSH transport failed on attempt ${bootstrap_attempt}/3; retrying via root@${TS_IP} in 3s."
          else
            warn "base/bootstrap.sh SSH transport failed on attempt ${bootstrap_attempt}/3; retrying via admin sudo in 3s."
          fi
        else
          warn "base/bootstrap.sh SSH transport/auth failed on attempt ${bootstrap_attempt}/3; retrying in 3s."
        fi
        sleep 3
        continue
      fi
      break
    fi
  done

  if (( bootstrap_rc != 0 )); then
    warn "base/bootstrap.sh failed. Last 50 lines of captured output:"
    tail -n 50 "${harden_tmp}" || true
    warn "Attempting to fetch remote /var/log/server-hardening.log tail (best effort)..."
    bootstrap_remote_tail_log || true
    rm -f "${harden_tmp}"
    die "base/bootstrap.sh failed. Check server logs: /var/log/server-hardening.log"
  fi
  pass "Hardening completed"

  # Extract Tailscale IP from captured bootstrap output (sentinel line).
  TS_IP="$(extract_bootstrap_tailscale_ip "${harden_tmp}")"
  rm -f "${harden_tmp}"
  is_tailscale_ipv4 "${TS_IP}" || die "Failed to get a valid Tailscale IP from bootstrap output."
  pin_known_host_alias "${SERVER_IP}" "${TS_IP}" "${DEPLOY_KNOWN_HOSTS}" "${ADMIN_KNOWN_HOSTS}" \
    || die "Could not pin the verified public SSH host key to Tailscale address ${TS_IP}. Refusing the admin transition."
  pass "Server Tailscale IP: ${TS_IP}"

  # deploy.env cleanup is attempted by the remote bootstrap wrapper and retained
  # as a phase2/EXIT-trap fallback in case the remote session dies mid-transition.
}

phase1_skipped() {
  step "1/5" "Upload scripts & harden server (skipped)"
  pass "Phase 1 skipped: --ts-ip supplied (${TS_IP})"
}

# ── Phase 2: Gate checks ───────────────────────────────────────────────────

wait_for_admin_ssh_or_die() {
  local context="$1"
  local max_attempts="${2:-6}"
  local delay="${3:-10}"
  local attempt

  for (( attempt=1; attempt<=max_attempts; attempt++ )); do
    if ssh_admin 'echo ok' >/dev/null 2>&1; then
      return 0
    fi
    if (( attempt == max_attempts )); then
      break
    fi
    log "  ${context}: attempt ${attempt}/${max_attempts} failed, retrying in ${delay}s..."
    sleep "${delay}"
  done
  return 1
}

gate_c_failures_are_transient() {
  local json="$1"
  [[ -n "${json}" ]] || return 1
  jq -e '
    .checks
    | [ .[] | select(.status=="FAIL") | .check ] as $fails
    | ($fails|length) > 0
      and
      all($fails[];
        . == "timesync: NTPSynchronized"
        or . == "fail2ban: active"
        or . == "fail2ban: sshd jail"
        or . == "fail2ban: f2b-sshd iptables chain"
        or . == "docker-user: IPv4"
      )
  ' >/dev/null 2>&1 <<< "${json}"
}

fetch_phase1_state_line_remote() {
  local remote_target remote_command
  if [[ "${PAAS:-coolify}" == "dokploy" ]]; then
    remote_target="root@${TS_IP}"
    remote_command="bash -s"
  else
    remote_target="${ADMIN_USER}@${TS_IP}"
    remote_command="sudo bash -s"
  fi
  ssh "${SSH_OPTS[@]}" -i "${PRIVATE_KEY}" "${remote_target}" "${remote_command}" 2>/dev/null <<'REMOTE' || true
set -Eeuo pipefail
state_file="/var/lib/server-hardening/state"
state_lock_file="${state_file}.lock"
state_snapshot="$(mktemp)"
cleanup() {
  rm -f "${state_snapshot}"
}
trap cleanup EXIT
[[ -f "${state_file}" ]] || exit 4
if command -v flock >/dev/null 2>&1; then
  flock -s "${state_lock_file}" cp "${state_file}" "${state_snapshot}"
else
  cp "${state_file}" "${state_snapshot}"
fi
# shellcheck disable=SC1090
source "${state_snapshot}"
printf "%s\t%s\n" "${domain:-}" "${tunnel_mode:-}"
REMOTE
}

recover_interrupted_phase1_dokploy_remote() {
  if [[ "${ALLOW_CONTROLLED_REBOOT:-false}" != true ]]; then
    ssh_admin_sudo '[[ -f /usr/local/sbin/paas-recovery-policy && ! -L /usr/local/sbin/paas-recovery-policy && "$(stat -c "%a:%U:%G" /usr/local/sbin/paas-recovery-policy)" == "700:root:root" ]] && python3 /usr/local/sbin/paas-recovery-policy' >/dev/null 2>&1 \
      || die "Interrupted recovery needs explicit reboot approval or a protected approved unattended recovery policy."
  fi
  [[ "${PAAS:-coolify}" == "dokploy" ]] || return 1

  local proof_script recovery_env_tmp recovery_cmd recovery_cmd_q
	proof_script="$(cat <<EOF
	set -Eeuo pipefail
	trap 'rc=\$?; printf "Interrupted phase 1 proof failed at predicate line %s (rc=%s)\\n" "\$LINENO" "\$rc" >&2; exit "\$rc"' ERR
	expected_ts_ip=${TS_IP@Q}
expected_source_ip=${DOKPLOY_ENROLLMENT_SOURCE_IP@Q}
expected_domain=${DOMAIN@Q}
expected_admin=${ADMIN_USER@Q}
expected_key=${ADMIN_PUBKEY@Q}

# This path is only for a bootstrap that crossed the public-to-Tailscale SSH
# boundary but failed before write_state(). Refuse a generic state-less host.
[[ ! -e /var/lib/server-hardening/state ]]
[[ "\$(tailscale ip -4 2>/dev/null | head -1 | tr -d '[:space:]')" == "\${expected_ts_ip}" ]]
[[ -z "\${expected_domain}" || "\$(hostname -f 2>/dev/null)" == "\${expected_domain}" ]]
[[ "\$(passwd -S root 2>/dev/null | awk '{print \$2}')" == "L" ]]
[[ -f /root/.ssh/authorized_keys && ! -L /root/.ssh/authorized_keys ]]
[[ "\$(wc -l < /root/.ssh/authorized_keys | tr -d '[:space:]')" == "1" ]]
[[ "\$(cat /root/.ssh/authorized_keys)" == "\${expected_key}" ]]

admin_entry="\$(getent passwd "\${expected_admin}")"
[[ -n "\${admin_entry}" && "\${admin_entry##*:}" == "/usr/sbin/nologin" ]]
[[ "\$(passwd -S "\${expected_admin}" 2>/dev/null | awk '{print \$2}')" == "L" ]]
admin_home="\$(awk -F: -v user="\${expected_admin}" '\$1 == user {print \$6; exit}' /etc/passwd)"
[[ -n "\${admin_home}" ]]
[[ ! -s "\${admin_home}/.ssh/authorized_keys" ]]
! id -nG "\${expected_admin}" 2>/dev/null | tr ' ' '\n' | grep -Eq '^(sudo|docker)$'

	global_policy="\$(sshd -T 2>/dev/null)"
	grep -qx 'permitrootlogin no' <<< "\${global_policy}"
	grep -qx 'passwordauthentication no' <<< "\${global_policy}"
	grep -qx 'allowusers root' <<< "\${global_policy}"
match_policy="\$(sshd -T -C user=root,addr="\${expected_source_ip}",host="\${expected_domain:-localhost}" 2>/dev/null)"
grep -Eq '^permitrootlogin (without-password|prohibit-password)$' <<< "\${match_policy}"
grep -qx 'passwordauthentication no' <<< "\${match_policy}"
grep -qx 'authenticationmethods publickey' <<< "\${match_policy}"
grep -qx 'allowusers root' <<< "\${match_policy}"

listener_endpoints="\$(ss -H -lnt 'sport = :22' | awk '{print \$4}')"
grep -qx "\${expected_ts_ip}:22" <<< "\${listener_endpoints}"
! grep -Eq '^(0\.0\.0\.0|\[::\]|\*):22$' <<< "\${listener_endpoints}"
EOF
)"

  if ! printf '%s\n' "${proof_script}" | ssh_admin_sudo 'bash -s'; then
    return 1
  fi

  warn "Interrupted phase 1 was strictly proven on the pinned Dokploy host; beginning Tailscale-only recovery."
  sync_companion_scripts

  # The current kernel audit policy is immutable. Install only the corrected
  # boot ordering, then reboot so rate_limit=10000 is applied before -e 2.
  if ! ssh_admin_sudo 'bash -s' <<'REMOTE'; then
set -Eeuo pipefail
source /root/base/modules/auditd.sh
DRY_RUN="false"
is_true() { case "${1,,}" in 1|true|yes|y|on) return 0 ;; *) return 1 ;; esac; }
run() { "$@"; }
log() { printf '%s\n' "$*"; }
warn() { printf '%s\n' "$*" >&2; }
install_auditd_rate_limit_persistence
REMOTE
    die "Interrupted phase 1 recovery failed to install the ordered auditd boot hook."
  fi

  warn "Interrupted phase 1 recovery: rebooting to apply the upgraded kernel and audit rate-before-lock ordering."
  ssh_admin_sudo 'nohup bash -c "sleep 1; systemctl reboot" >/dev/null 2>&1 &' || true
  local reboot_drop_attempt
  for (( reboot_drop_attempt=1; reboot_drop_attempt<=12; reboot_drop_attempt++ )); do
    if ! ssh_admin 'echo ok' >/dev/null 2>&1; then
      break
    fi
    sleep 5
  done
  wait_for_admin_ssh_or_die "Interrupted phase 1 reboot wait" 36 10 \
    || die "Interrupted phase 1 recovery failed: server did not return over pinned Tailscale SSH."
  ssh_admin_sudo 'auditctl -s 2>/dev/null | awk '\''$1 == "enabled" {enabled=$2} $1 == "rate_limit" {rate=$2} END {exit(enabled == 2 && rate == 10000 ? 0 : 1)}'\'' ' \
    || die "Interrupted phase 1 recovery failed: auditd did not return immutable with rate_limit=10000 after reboot."

  recovery_env_tmp="$(mktemp)" || die "Failed to create interrupted phase 1 recovery env file."
  {
    printf 'ADMIN_USER="%s"\n' "${ADMIN_USER//\"/\\\"}"
    printf 'ADMIN_PUBKEY="%s"\n' "${ADMIN_PUBKEY//\"/\\\"}"
    printf 'DOMAIN="%s"\n' "${DOMAIN//\"/\\\"}"
    printf 'TAILSCALE_CIDR="100.64.0.0/10"\n'
    printf 'SSH_PORT="22"\n'
    printf 'TUNNEL_MODE="false"\n'
    printf 'SWAP_SIZE="%s"\n' "${SWAP_SIZE//\"/\\\"}"
    printf 'TIMEZONE="%s"\n' "${SERVER_TIMEZONE//\"/\\\"}"
    printf 'INSTALL_TAILSCALE="false"\n'
    printf 'TAILSCALE_DIRECT_WAN="%s"\n' "${TAILSCALE_DIRECT_WAN//\"/\\\"}"
    printf 'BIND_DASHBOARD_TO_TAILSCALE="false"\n'
    printf 'PAAS="dokploy"\n'
  } > "${recovery_env_tmp}"
  chmod 600 "${recovery_env_tmp}"
  if ! ssh_admin_sudo 'install -d -m 0700 -o root -g root /run/secure-ubuntu-paas; install -m 0600 -o root -g root /dev/stdin /run/secure-ubuntu-paas/interrupted-phase1.env' < "${recovery_env_tmp}"; then
    rm -f "${recovery_env_tmp}"
    die "Interrupted phase 1 recovery failed to upload its protected non-secret environment."
  fi
  rm -f "${recovery_env_tmp}"

  recovery_cmd='set -Eeuo pipefail; cleanup() { rm -f /run/secure-ubuntu-paas/interrupted-phase1.env; }; trap cleanup EXIT; /root/base/bootstrap.sh --env-file /run/secure-ubuntu-paas/interrupted-phase1.env --force'
  printf -v recovery_cmd_q '%q' "${recovery_cmd}"
  run_with_heartbeat "interrupted phase 1 bootstrap over root@${TS_IP}" \
    ssh_admin_sudo "bash -lc ${recovery_cmd_q}" \
    || die "Interrupted phase 1 recovery bootstrap failed. Check /var/log/server-hardening.log."

  [[ -n "$(fetch_phase1_state_line_remote)" ]] \
    || die "Interrupted phase 1 recovery completed without a readable state file."
  pass "Interrupted phase 1 recovered over pinned root@${TS_IP} without Tailscale re-enrollment"
}

assert_resume_phase1_contract_remote() {
  is_true "${SKIP_HARDEN}" || return 0

  local state_line state_domain state_tunnel_mode expected_tunnel_mode
  expected_tunnel_mode="false"
  [[ "${DEPLOY_MODE}" == "tunnel" ]] && expected_tunnel_mode="true"

  state_line="$(fetch_phase1_state_line_remote)"

  if [[ -z "${state_line}" ]]; then
    recover_interrupted_phase1_dokploy_remote \
      || die "Resume contract failed: phase 1 state is unavailable and strict interrupted-Dokploy proof failed. Run a fresh deploy instead of --ts-ip."
    state_line="$(fetch_phase1_state_line_remote)"
  fi
  [[ -n "${state_line}" ]] || die "Resume contract failed: interrupted phase 1 recovery did not produce readable state."

  IFS=$'\t' read -r state_domain state_tunnel_mode <<< "${state_line}"
  # Domain may be empty for Dokploy (optional public app domain).
  if [[ -n "${DOMAIN}" || "${PAAS}" == "coolify" ]]; then
    [[ -n "${state_domain}" ]] || die "Resume contract failed: phase 1 state does not contain a domain. Run a fresh deploy instead of --ts-ip."
  fi
  [[ -n "${state_tunnel_mode}" ]] || state_tunnel_mode="false"

  if [[ -n "${DOMAIN}" && "${state_domain}" != "${DOMAIN}" ]]; then
    die "Resume contract failed: --domain ${DOMAIN} does not match phase 1 state (${state_domain}). Run a fresh deploy."
  fi

  if [[ "${state_tunnel_mode}" != "${expected_tunnel_mode}" ]]; then
    die "Resume contract failed: --mode ${DEPLOY_MODE} does not match phase 1 state ($( [[ "${state_tunnel_mode}" == "true" ]] && printf 'tunnel' || printf 'standard' )). Run a fresh deploy."
  fi
}

wait_for_gate_c_timesync_remote() {
  local max_attempts="${1:-12}" delay="${2:-5}"
  local attempt synced_val waited=0

  for (( attempt=1; attempt<=max_attempts; attempt++ )); do
    synced_val="$(ssh_admin_sudo 'timedatectl show --property=NTPSynchronized --value 2>/dev/null || true' 2>/dev/null | tr -d '[:space:]')"
    if [[ "${synced_val}" == "yes" ]]; then
      (( waited == 1 )) && pass "Gate C pre-check: timesync synchronized"
      return 0
    fi
    [[ -n "${synced_val}" ]] || break
    if (( waited == 0 )); then
      log "Gate C pre-check: waiting for system clock synchronization..."
      waited=1
    fi
    (( attempt < max_attempts )) || break
    sleep "${delay}"
  done

  (( waited == 1 )) && warn "Gate C pre-check: timesync still not synchronized after $((max_attempts * delay))s; continuing to validator retries."
  return 1
}

verify_post_reboot_services_remote() {
  local gate_label="${1:-Gate B.5}"

  if ssh_admin_sudo 'systemctl is-active --quiet tailscaled.service'; then
    pass "${gate_label}: tailscaled.service is active"
  else
    fail "${gate_label}: tailscaled.service is not active"
    die "${gate_label} failed: tailscaled.service is not active after reboot."
  fi

  if ssh_admin_sudo 'ufw status 2>/dev/null | grep -q "^Status: active$"'; then
    pass "${gate_label}: UFW remains active"
  else
    fail "${gate_label}: UFW is not active"
    die "${gate_label} failed: UFW is not active after reboot."
  fi

  if ssh_admin_sudo 'systemctl is-active --quiet fail2ban.service'; then
    pass "${gate_label}: fail2ban.service is active"
  else
    fail "${gate_label}: fail2ban.service is not active"
    die "${gate_label} failed: fail2ban.service is not active after reboot."
  fi

  if ssh_admin_sudo 'fail2ban-client status sshd >/dev/null 2>&1'; then
    pass "${gate_label}: fail2ban sshd jail is active"
  else
    fail "${gate_label}: fail2ban sshd jail is not active"
    die "${gate_label} failed: fail2ban sshd jail is not active after reboot."
  fi

  if ssh_admin_sudo 'test "$(systemctl show docker.service --property=LoadState --value 2>/dev/null)" = loaded'; then
    if ssh_admin_sudo 'systemctl is-active --quiet docker.service'; then
      pass "${gate_label}: docker.service is active"
    else
      fail "${gate_label}: docker.service is not active"
      die "${gate_label} failed: docker.service is not active after reboot."
    fi
    verify_docker_user_gate_remote "${gate_label}"
  fi
}

docker_audit_runtime_state_remote() {
  local script_tmp state
  script_tmp="$(mktemp)" || die "Failed to create Docker audit reconciliation script."
  docker_audit_runtime_reconcile_script > "${script_tmp}"
  if state="$(ssh_admin_sudo 'bash -s' < "${script_tmp}")"; then
    rm -f "${script_tmp}"
  else
    rm -f "${script_tmp}"
    die "Docker audit runtime reconciliation failed on the server."
  fi
  state="$(tr -d '[:space:]' <<< "${state}")"
  case "${state}" in
    ready|reboot-required|not-applicable) printf '%s\n' "${state}" ;;
    *) die "Docker audit runtime reconciliation returned an unexpected state." ;;
  esac
}

reboot_for_docker_audit_remote() {
  local gate_label="$1" state_line state autolock reboot_drop_attempt drop_seen="false"
  if [[ "${ALLOW_CONTROLLED_REBOOT:-false}" != true ]]; then
    [[ "${PAAS:-coolify}" == dokploy ]] && ssh_admin_sudo '[[ -f /usr/local/sbin/paas-recovery-policy && ! -L /usr/local/sbin/paas-recovery-policy && "$(stat -c "%a:%U:%G" /usr/local/sbin/paas-recovery-policy)" == "700:root:root" ]] && python3 /usr/local/sbin/paas-recovery-policy' >/dev/null 2>&1 \
      || die "${gate_label}: host reboot requires explicit approval or a protected approved unattended recovery policy."
  fi

  DOKPLOY_SWARM_UNLOCK_KEY_RUNTIME=""
  if [[ "${PAAS:-coolify}" == "dokploy" ]]; then
    ensure_dokploy_swarm_unlocked_remote
    state_line="$(dokploy_swarm_state_remote)"
    IFS=$'\t' read -r state autolock <<< "${state_line}"
    if [[ "${state}" == "active" && "${autolock}" == "true" ]]; then
      if ssh_admin_sudo "test -f ${DOKPLOY_SWARM_UNLOCK_HANDOFF_FILE}" >/dev/null 2>&1; then
        capture_dokploy_swarm_unlock_handoff_remote
      else
        load_dokploy_swarm_unlock_key
      fi
    elif [[ "${state}" != "active" && "${state}" != "inactive" && -n "${state}" ]]; then
      die "${gate_label}: Dokploy Swarm state '${state}' is unsafe for the audit-policy reboot."
    fi
  fi

  warn "${gate_label}: immutable Docker audit watches require one controlled reboot; rebooting now."
  ssh_admin_sudo 'nohup bash -c "sleep 1; systemctl reboot" >/dev/null 2>&1 &' || true

  for (( reboot_drop_attempt=1; reboot_drop_attempt<=12; reboot_drop_attempt++ )); do
    if ! ssh_admin 'echo ok' >/dev/null 2>&1; then
      drop_seen="true"
      break
    fi
    sleep 5
  done
  [[ "${drop_seen}" == "true" ]] \
    || die "${gate_label}: reboot was requested but the pinned Tailscale SSH path never dropped."
  wait_for_admin_ssh_or_die "${gate_label} reboot wait" 36 10 \
    || die "${gate_label}: server did not return over pinned Tailscale SSH after reboot."

  if [[ -n "${DOKPLOY_SWARM_UNLOCK_KEY_RUNTIME}" ]]; then
    unlock_dokploy_swarm_remote
  fi
  DOKPLOY_SWARM_UNLOCK_KEY_RUNTIME=""
  verify_post_reboot_services_remote "${gate_label}"
  [[ "$(docker_audit_runtime_state_remote)" == "ready" ]] \
    || die "${gate_label}: Docker audit watches were not loaded after reboot."
  pass "${gate_label}: Docker audit watches loaded after controlled reboot"
}

reconcile_docker_audit_runtime_remote() {
  local gate_label="${1:-Docker audit reconciliation}" state
  state="$(docker_audit_runtime_state_remote)"
  case "${state}" in
    ready)
      pass "${gate_label}: Docker runtime audit watches are loaded"
      ;;
    not-applicable)
      return 0
      ;;
    reboot-required)
      reboot_for_docker_audit_remote "${gate_label}"
      ;;
  esac
}

phase2_gates() {
  local gate_ssh_user="${ADMIN_USER}"
  [[ "${PAAS}" == "dokploy" ]] && gate_ssh_user="root"
  step "2/5" "Gate checks (SSH transition to ${gate_ssh_user}@tailscale)"

  # Gate A: SSH through the PaaS-specific Tailscale principal using key auth.
  log "Gate A: Testing SSH ${gate_ssh_user}@${TS_IP} via key auth..."
  if ! known_host_entry_present "${TS_IP}" "${ADMIN_KNOWN_HOSTS}"; then
    pin_known_host_alias "${SERVER_IP}" "${TS_IP}" "${DEPLOY_KNOWN_HOSTS}" "${ADMIN_KNOWN_HOSTS}" \
      || die "No pinned SSH host key for ${TS_IP}; refusing the Tailscale SSH transition."
  fi
  # (Gate A runs first so we know SSH works before syncing scripts)
  if wait_for_admin_ssh_or_die "Gate A (Tailscale peering may need time)" 6 10; then
    sync_operator_known_host_entries "${ADMIN_KNOWN_HOSTS}" "${TS_IP}"
    pass "Gate A: SSH ${gate_ssh_user}@${TS_IP} works"
  else
    fail "Gate A: Cannot SSH to ${gate_ssh_user}@${TS_IP} after retries"
    die "Gate A failed. Tailscale peering may not be established. Check 'tailscale status' on both machines."
  fi

  # Gate B: Verify the expected Tailscale SSH identity.
  local whoami_result
  whoami_result="$(ssh_admin 'whoami' 2>/dev/null | tr -d '[:space:]')"
  if [[ "${whoami_result}" == "${gate_ssh_user}" ]]; then
    pass "Gate B: whoami=${gate_ssh_user}"
  else
    fail "Gate B: Expected ${gate_ssh_user}, got '${whoami_result}'"
    die "Gate B failed."
  fi

  assert_resume_phase1_contract_remote

  # If package upgrades during hardening require a reboot, perform it here before Gate C.
  if ssh_admin_sudo 'test -f /run/reboot-required' >/dev/null 2>&1; then
    local reboot_pkgs reboot_drop_attempt reboot_swarm_state_line reboot_swarm_state reboot_swarm_autolock
    reboot_pkgs="$(ssh_admin_sudo "tr '\n' ',' < /run/reboot-required.pkgs 2>/dev/null | sed 's/,$//'" 2>/dev/null || true)"
    warn "Gate B.5: Reboot required before validation (${reboot_pkgs:-unknown packages}). Rebooting now."

    # A resumed Dokploy host may already have Swarm autolock enabled. Never
    # reboot it before the external key is available locally, and never leave
    # the post-reboot manager locked while continuing validation.
    DOKPLOY_SWARM_UNLOCK_KEY_RUNTIME=""
    if [[ "${PAAS:-coolify}" == "dokploy" ]] \
      && ssh_admin_sudo 'docker version >/dev/null 2>&1'; then
      ensure_dokploy_swarm_unlocked_remote
      reboot_swarm_state_line="$(dokploy_swarm_state_remote)"
      IFS=$'\t' read -r reboot_swarm_state reboot_swarm_autolock <<< "${reboot_swarm_state_line}"
      if [[ "${reboot_swarm_state}" == "active" && "${reboot_swarm_autolock}" == "true" ]]; then
        if ssh_admin_sudo "test -f ${DOKPLOY_SWARM_UNLOCK_HANDOFF_FILE}" >/dev/null 2>&1; then
          capture_dokploy_swarm_unlock_handoff_remote
        else
          load_dokploy_swarm_unlock_key
        fi
      elif [[ "${reboot_swarm_state}" != "active" \
        && "${reboot_swarm_state}" != "inactive" && -n "${reboot_swarm_state}" ]]; then
        die "Gate B.5 failed: Dokploy Swarm state '${reboot_swarm_state}' is unsafe for reboot."
      fi
    fi

    ssh_admin_sudo 'nohup bash -c "sleep 1; systemctl reboot" >/dev/null 2>&1 &' || true

    # Wait for SSH to drop at least once to confirm reboot started.
    for (( reboot_drop_attempt=1; reboot_drop_attempt<=12; reboot_drop_attempt++ )); do
      if ! ssh_admin 'echo ok' >/dev/null 2>&1; then
        break
      fi
      sleep 5
    done

    if wait_for_admin_ssh_or_die "Gate B.5 reboot wait" 36 10; then
      if ssh_admin_sudo 'test ! -f /run/reboot-required' >/dev/null 2>&1; then
        pass "Gate B.5: Reboot completed and reboot-required cleared"
        if [[ -n "${DOKPLOY_SWARM_UNLOCK_KEY_RUNTIME}" ]]; then
          unlock_dokploy_swarm_remote
        fi
        DOKPLOY_SWARM_UNLOCK_KEY_RUNTIME=""
        verify_post_reboot_services_remote "Gate B.5"
      else
        die "Gate B.5 failed: server came back but /run/reboot-required still present."
      fi
    else
      die "Gate B.5 failed: server did not come back after reboot."
    fi
  fi

  # Clean up sensitive deploy.env left on server by phase 1.
  # Done here (not in phase 1) because post-hardening UFW blocks root SSH on the public IP.
  if ssh_admin_sudo "rm -f ${REMOTE_DEPLOY_ENV_PATH}" 2>/dev/null; then
    DEPLOY_ENV_REMOTE_PENDING="false"
  fi

  # Always re-sync companion scripts via admin SCP after Gate A/B confirm SSH works.
  # This ensures the latest versions are used even when phase 1 (root upload) was skipped.
  sync_companion_scripts
  reconcile_resume_hardening_remote

  # Resume safety: if Docker was already installed by a prior partial run, re-apply
  # hardening-owned Docker settings before Gate C validation. This keeps --ts-ip
  # resumes from failing on expected pre-phase3 drift.
  if ssh_admin_sudo 'docker version >/dev/null 2>&1'; then
    log "Gate C pre-check: Docker detected; reconciling daemon and bridge-SSH rules..."
    reconcile_docker_daemon_remote
    ssh_admin_sudo 'systemctl enable --now docker-user-hardening.service 2>/dev/null || true'
    ssh_admin_sudo 'systemctl start docker-ssh-cidr-sync.service 2>/dev/null || true'
    reconcile_docker_audit_runtime_remote "Gate C pre-check"
  fi
  wait_for_gate_c_timesync_remote 12 5 || true

  # Gate C: Validation passes
  log "Gate C: Running base/validate.sh..."
  local validate_json gate_c_fail attempt max_attempts=6 delay=10
  for (( attempt=1; attempt<=max_attempts; attempt++ )); do
    validate_json="$(ssh_admin_sudo '/root/base/validate.sh --json --gate-c' 2>/dev/null)" || true
    gate_c_fail="$(jq -r '.fail // 999' 2>/dev/null <<< "${validate_json:-}" || echo "999")"
    if [[ "${gate_c_fail}" == "0" ]]; then
      report_validation_result "Gate C" "${validate_json}" \
        "Gate C failed. Fix validation failures before continuing."
      break
    fi
    if (( attempt < max_attempts )) && gate_c_failures_are_transient "${validate_json}"; then
      log "  Gate C transient failure (timesync/fail2ban/docker-user not ready yet); retrying in ${delay}s (${attempt}/${max_attempts})..."
      sleep "${delay}"
      continue
    fi
    report_validation_result "Gate C" "${validate_json}" \
      "Gate C failed. Fix validation failures before continuing."
  done
}

# ── Phase 3: Docker + Coolify ──────────────────────────────────────────────

paas_phase3_dispatch() {
  overlay_topo_sort "${PAAS}"
  case "${PAAS}" in
    dflow)   dflow_phase3_install_shared "$@" ;;
    dokploy) dokploy_phase3_install_shared "$@" ;;
    coolify) coolify_phase3_docker_coolify_shared "$@" ;;
    *)       die "Unsupported PAAS: ${PAAS}" ;;
  esac
}

paas_phase4_dispatch() {
  case "${PAAS}" in
    dflow)   dflow_phase4_routing_shared "$@" ;;
    dokploy) dokploy_phase4_routing_shared "$@" ;;
    coolify) coolify_phase4_binding_dns_shared "$@" ;;
    *)       die "Unsupported PAAS: ${PAAS}" ;;
  esac
}

paas_phase5_dispatch() {
  case "${PAAS}" in
    dflow)   dflow_phase5_verify_shared "${1:-}" ;;
    dokploy) dokploy_phase5_verify_shared "$@" ;;
    coolify) coolify_phase5_verify_shared "$@" ;;
    *)       die "Unsupported PAAS: ${PAAS}" ;;
  esac
}

phase3_docker_coolify() {
  phase3_has_docker() { ssh_admin_sudo 'docker version >/dev/null 2>&1'; }
  phase3_install_docker() { coolify_install_docker_engine_script | ssh_admin_sudo 'bash -s'; }
  phase3_start_docker_user() { ssh_admin_sudo 'systemctl enable --now docker-user-hardening.service'; }
  phase3_verify_docker_user() { verify_docker_user_gate_remote "$1"; }
  phase3_has_coolify_env() {
    ssh_admin_sudo "bash -c 'test -f /data/coolify/source/.env && docker inspect coolify >/dev/null 2>&1'" >/dev/null 2>&1
  }
  phase3_install_coolify() { coolify_install_coolify_script | ssh_admin_sudo 'bash -s'; }
  phase3_reconcile_docker_daemon() { reconcile_docker_daemon_remote; }
  phase3_restart_docker_user() { ssh_admin_sudo 'systemctl restart docker-user-hardening.service'; }
  phase3_add_coolify_root_key() { coolify_add_coolify_root_key_script | ssh_admin_sudo 'bash -s'; }
  phase3_fix_host_docker_internal() { coolify_fix_host_docker_internal_script | ssh_admin_sudo 'bash -s'; }
  phase3_sync_docker_ssh_cidrs() { ssh_admin_sudo 'systemctl start docker-ssh-cidr-sync.service'; }

  # Gate D: Verify DOCKER-USER rules
  paas_phase3_dispatch \
    phase3_has_docker \
    phase3_install_docker \
    phase3_start_docker_user \
    phase3_verify_docker_user \
    phase3_has_coolify_env \
    phase3_install_coolify \
    phase3_reconcile_docker_daemon \
    phase3_restart_docker_user \
    phase3_add_coolify_root_key \
    phase3_fix_host_docker_internal \
    phase3_sync_docker_ssh_cidrs
}

phase3_docker_dokploy() {
  phase3_has_docker() { ssh_admin_sudo 'docker version >/dev/null 2>&1'; }
  phase3_install_docker() { coolify_install_docker_engine_script | ssh_admin_sudo 'bash -s'; }
  phase3_start_docker_user() { ssh_admin_sudo 'systemctl enable --now docker-user-hardening.service'; }
  phase3_verify_docker_user() { verify_docker_user_gate_remote "$1"; }
  phase3_has_dokploy() { ssh_admin_sudo 'docker service inspect dokploy >/dev/null 2>&1'; }
  phase3_install_dokploy() { dokploy_install_dokploy_script | ssh_admin_sudo 'bash -s'; }
  phase3_reconcile_docker_daemon() { reconcile_docker_daemon_remote; }
  phase3_restart_docker_user() { ssh_admin_sudo 'systemctl restart docker-user-hardening.service'; }
  phase3_finalize_dokploy_runtime() {
    local script_tmp rc swarm_unlock_key
    script_tmp="$(mktemp)"
    dokploy_finalize_runtime_script > "${script_tmp}"
    if ssh_admin_sudo 'bash -s' < "${script_tmp}"; then
      rc=0
    else
      rc=$?
    fi
    rm -f "${script_tmp}"
    (( rc == 0 )) || return "${rc}"

    swarm_unlock_key="$(ssh_admin_sudo 'cat /run/secure-ubuntu-paas-dokploy-swarm-unlock-key 2>/dev/null || true')"
    store_dokploy_swarm_unlock_key "${swarm_unlock_key}"
    ssh_admin_sudo 'rm -f -- /run/secure-ubuntu-paas-dokploy-swarm-unlock-key'
  }

  paas_phase3_dispatch \
    phase3_has_docker \
    phase3_install_docker \
    phase3_start_docker_user \
    phase3_verify_docker_user \
    phase3_has_dokploy \
    phase3_install_dokploy \
    phase3_reconcile_docker_daemon \
    phase3_restart_docker_user \
    "" \
    phase3_finalize_dokploy_runtime
}

# ── Phase 4: Binding + DNS ─────────────────────────────────────────────────

phase4_binding_dns() {
  phase4_coolify_env_exists() { ssh_admin_sudo 'test -f /data/coolify/source/.env' >/dev/null 2>&1; }
  phase4_configure_binding() { ssh_admin_sudo "/root/overlays/coolify/configure_coolify_binding.sh --tailscale-ip ${TS_IP}"; }
  phase4_mark_binding_state() {
    {
      coolify_mark_bind_dashboard_state_script
      coolify_install_binding_guard_script
    } | ssh_admin_sudo 'bash -s'
  }
  phase4_set_wildcard_domain() {
    local app_domain_q
    app_domain_q="$(printf '%q' "${APP_DOMAIN}")"
    coolify_set_wildcard_domain_script | ssh_admin_sudo "APP_DOMAIN=${app_domain_q} bash -s"
  }
  phase4_reconcile_instance_settings() {
    local deploy_mode_q domain_q
    deploy_mode_q="$(printf '%q' "${DEPLOY_MODE}")"
    domain_q="$(printf '%q' "${DOMAIN}")"
    coolify_reconcile_instance_settings_script | ssh_admin_sudo "DEPLOY_MODE=${deploy_mode_q} DOMAIN=${domain_q} bash -s"
  }
  phase4_reconcile_pusher_env() {
    local deploy_mode_q ts_ip_q domain_q
    deploy_mode_q="$(printf '%q' "${DEPLOY_MODE}")"
    ts_ip_q="$(printf '%q' "${TS_IP}")"
    domain_q="$(printf '%q' "${DOMAIN}")"
    coolify_reconcile_pusher_env_script \
      | ssh_admin_sudo "DEPLOY_MODE=${deploy_mode_q} TS_IP=${ts_ip_q} DOMAIN=${domain_q} bash -s"
  }
  phase4_install_cloudflared() { coolify_install_cloudflared_script | ssh_admin_sudo 'bash -s'; }
  phase4_configure_cloudflared() {
    local secret_dir secret_file_q secret_dir_q domain_q app_domain_q cf_account_id_q cf_zone_name_q rc
    secret_dir="$(remote_secret_dir_create)" || die "Failed to create protected remote tunnel-secret directory."
    if ! remote_secret_write_file "${secret_dir}/tunnel_secret" "${TUNNEL_SECRET}"; then
      remote_secret_cleanup_dir "${secret_dir}"
      die "Failed to transfer the Cloudflare tunnel secret over protected stdin."
    fi
    secret_file_q="$(printf '%q' "${secret_dir}/tunnel_secret")"
    secret_dir_q="$(printf '%q' "${secret_dir}")"
    cf_account_id_q="$(printf '%q' "${CF_ACCOUNT_ID}")"
    domain_q="$(printf '%q' "${DOMAIN}")"
    app_domain_q="$(printf '%q' "${APP_DOMAIN}")"
    cf_zone_name_q="$(printf '%q' "${CF_ZONE_NAME}")"
    if coolify_configure_cloudflared_script \
      | ssh_admin_sudo "TUNNEL_ID=${TUNNEL_ID@Q} TUNNEL_SECRET_FILE=${secret_file_q} TUNNEL_SECRET_DIR=${secret_dir_q} CF_ACCOUNT_ID=${cf_account_id_q} DOMAIN=${domain_q} APP_DOMAIN=${app_domain_q} CF_ZONE_NAME=${cf_zone_name_q} bash -s"; then
      rc=0
    else
      rc=$?
    fi
    remote_secret_cleanup_dir "${secret_dir}"
    return "${rc}"
  }
  phase4_stop_cloudflared() {
    ssh_admin_sudo 'systemctl disable --now cloudflared 2>/dev/null || systemctl stop cloudflared 2>/dev/null || true'
  }
  phase4_fetch_existing_tunnel() {
    ssh_admin_sudo 'bash -s' <<'EOF'
set -Eeuo pipefail
config="/etc/cloudflared/config.yml"
[[ -f "${config}" ]] || exit 0
tunnel_id="$(awk -F': *' '/^tunnel:/ {print $2; exit}' "${config}")"
[[ -n "${tunnel_id}" ]] || exit 0
creds_path="$(awk -F': *' '/^credentials-file:/ {print $2; exit}' "${config}")"
[[ -n "${creds_path}" ]] || creds_path="/etc/cloudflared/${tunnel_id}.json"
[[ -f "${creds_path}" ]] || exit 0
creds_id="$(jq -r '.TunnelID // empty' "${creds_path}")"
tunnel_secret="$(jq -r '.TunnelSecret // empty' "${creds_path}")"
[[ -n "${creds_id}" && "${creds_id}" == "${tunnel_id}" && -n "${tunnel_secret}" ]] || exit 0
printf '%s\t%s\n' "${creds_id}" "${tunnel_secret}"
EOF
  }
  phase4_configure_private_routes() {
    local domain_q resolver_q
    domain_q="$(printf '%q' "${DOMAIN}")"
    resolver_q="$(printf '%q' "$(private_tls_resolver_name)")"
    coolify_configure_private_dashboard_routes_script \
      | ssh_admin_sudo "DOMAIN=${domain_q} PRIVATE_TLS_RESOLVER=${resolver_q} bash -s"
  }
  phase4_configure_private_tls() {
    local secret_dir cf_zone_name_q resolver_q private_tls_ca_q domain_q secret_dir_q rc
    secret_dir="$(remote_secret_dir_create)" || die "Failed to create protected remote TLS-secret directory."
    if ! remote_secret_write_file "${secret_dir}/cf_dns_api_token" "${CF_API_TOKEN}" \
      || ! remote_secret_write_file "${secret_dir}/zerossl_eab_kid" "${ZEROSSL_EAB_KID}" \
      || ! remote_secret_write_file "${secret_dir}/zerossl_eab_hmac" "${ZEROSSL_EAB_HMAC}"; then
      remote_secret_cleanup_dir "${secret_dir}"
      die "Failed to transfer private TLS secrets over protected stdin."
    fi
    secret_dir_q="$(printf '%q' "${secret_dir}")"
    cf_zone_name_q="$(printf '%q' "${CF_ZONE_NAME}")"
    domain_q="$(printf '%q' "${DOMAIN}")"
    resolver_q="$(printf '%q' "$(private_tls_resolver_name)")"
    private_tls_ca_q="$(printf '%q' "${PRIVATE_TLS_CA}")"
    if coolify_configure_private_tls_dns_script \
      | ssh_admin_sudo "PRIVATE_TLS_SECRET_DIR=${secret_dir_q} CF_ZONE_NAME=${cf_zone_name_q} DOMAIN=${domain_q} PRIVATE_TLS_RESOLVER=${resolver_q} PRIVATE_TLS_CA=${private_tls_ca_q} bash -s"; then
      rc=0
    else
      rc=$?
    fi
    remote_secret_cleanup_dir "${secret_dir}"
    return "${rc}"
  }
  phase4_remove_private_routes() {
    coolify_remove_private_dashboard_routes_script | ssh_admin_sudo 'bash -s'
  }
  phase4_restore_public_tls() {
    local domain_q cf_zone_name_q resolver_q
    domain_q="$(printf '%q' "${DOMAIN}")"
    cf_zone_name_q="$(printf '%q' "${CF_ZONE_NAME}")"
    resolver_q="$(printf '%q' "$(private_tls_resolver_name)")"
    coolify_restore_public_dashboard_tls_script \
      | ssh_admin_sudo "DOMAIN=${domain_q} CF_ZONE_NAME=${cf_zone_name_q} PRIVATE_TLS_RESOLVER=${resolver_q} bash -s"
  }

  # Contract anchors kept for tests/docs:
  # mode="${DEPLOY_MODE}"
  # PUSHER_HOST=ws.${DOMAIN}
  # coolify-private-dashboard.yaml
  # ws.${DOMAIN}
  paas_phase4_dispatch \
    phase4_coolify_env_exists \
    phase4_configure_binding \
    phase4_mark_binding_state \
    phase4_set_wildcard_domain \
    phase4_reconcile_instance_settings \
    phase4_reconcile_pusher_env \
    phase4_install_cloudflared \
    phase4_configure_cloudflared \
    phase4_stop_cloudflared \
    phase4_fetch_existing_tunnel \
    phase4_configure_private_routes \
    phase4_configure_private_tls \
    phase4_remove_private_routes \
    phase4_restore_public_tls
}

phase4_dokploy_access_policy() {
  phase4_remove_stale_coolify_dashboard_ufw() {
    local script_tmp
    script_tmp="$(mktemp)"
    dokploy_remove_stale_coolify_dashboard_ufw_script > "${script_tmp}"
    ssh_admin_sudo 'bash -s' < "${script_tmp}"
    local rc=$?
    rm -f "${script_tmp}"
    return "${rc}"
  }
  phase4_configure_dokploy_dashboard_ufw() {
    local script_tmp
    script_tmp="$(mktemp)"
    dokploy_dashboard_ufw_policy_script > "${script_tmp}"
    ssh_admin_sudo 'bash -s' < "${script_tmp}"
    local rc=$?
    rm -f "${script_tmp}"
    return "${rc}"
  }

  paas_phase4_dispatch \
    phase4_configure_dokploy_dashboard_ufw \
    phase4_remove_stale_coolify_dashboard_ufw
}

# ── Phase 5: Verification ─────────────────────────────────────────────────

phase5_fetch_validate_json() { ssh_admin_sudo '/root/base/validate.sh --json'; }
phase5_noop_operator_confirm() { :; }
phase5_dokploy_operator_confirm() {
  local message="${1:-Complete Dokploy first-admin registration and TOTP 2FA, then continue}"
  if is_true "${AUTO_YES}"; then
    die "${message}. The dashboard is restricted to ${DOKPLOY_ENROLLMENT_SOURCE_IP}; complete enrollment and rerun the same deploy command."
  fi
  printf '\n  \033[1;33m⏸  %s\033[0m\n' "${message}"
  printf '  Press Enter when ready...'
  read -r
}

phase5_verify() {
  # Contract anchors kept for docs/consistency checks:
  # Gate E: Checking dashboard accessibility...
  # Running final base/validate.sh...
  paas_phase5_dispatch phase5_fetch_validate_json external \
    phase5_dokploy_operator_confirm phase4_configure_dokploy_dashboard_ufw
}

# ── Main ────────────────────────────────────────────────────────────────────

main() {
  run_report_init "${SCRIPT_NAME}"
  parse_args "$@"
  init_ssh_options
  ROOT_SSH_HOST="${SERVER_IP}"
  collect_inputs
  validate_inputs
  init_root_password_auth

  # Show summary before proceeding
  printf '\n'
  log "Deployment configuration:"
  log "  PaaS:      ${PAAS}"
  log "  Server:    ${SERVER_IP}"
  if [[ "${PAAS}" == "dokploy" ]]; then
    log "  SSH:       root over Tailscale only"
  else
    log "  Admin:     ${ADMIN_USER}"
  fi
  log "  Pubkey:    ${PUBKEY_FILE}"
  log "  Swap:      ${SWAP_SIZE}"
  log "  Timezone:  ${SERVER_TIMEZONE}"
  log "  Local TZ:  $(local_tz_offset) (logs use UTC)"
  if [[ "${PAAS}" == "coolify" ]]; then
    log "  Mode:      ${DEPLOY_MODE}"
    log "  Domain:    ${DOMAIN}"
    log "  App scope: ${APP_DOMAIN_MODE}"
    [[ "${DEPLOY_MODE}" == "tunnel" ]] && log "  Private TLS CA: ${PRIVATE_TLS_CA}"
    print_private_tls_ca_notice
    [[ "${CF_TUNNEL_API_TOKEN}" != "${CF_API_TOKEN}" ]] && log "  CF tunnel token: custom"
  elif [[ "${PAAS}" == "dflow" ]]; then
    log "  Controller: dFlow (Tailscale SSH)"
  else
    log "  Public app ingress: 80/443"
    [[ -n "${DOMAIN:-}" ]] && log "  App domain: ${DOMAIN}"
    log "  Dashboard/API: Tailscale port 3000"
  fi
  is_true "${PREFLIGHT_ONLY}" && log "  Mode:      preflight-only (no server changes)"
  is_true "${SKIP_HARDEN}" && log "  TS IP:     ${TS_IP} (--ts-ip; skipping phase 1)"
  confirm "Proceed with deployment?"

  preflight
  if is_true "${PREFLIGHT_ONLY}"; then
    pass "Preflight-only checks completed. Exiting without deployment changes."
    return 0
  fi
  if is_true "${SKIP_HARDEN}"; then
    phase1_skipped
    log "Skipping phase 1 (--ts-ip supplied; hardening already complete on ${TS_IP})"
  else
    phase1_upload_harden
  fi
  phase2_gates
  case "${PAAS}" in
    dflow)
      paas_phase3_dispatch
      paas_phase4_dispatch
      ;;
    dokploy)
      phase3_docker_dokploy
      reconcile_docker_audit_runtime_remote "Post-Dokploy audit reconciliation"
      phase4_dokploy_access_policy
      ;;
    coolify)
      phase3_docker_coolify
      phase4_binding_dns
      ;;
  esac
  phase5_verify
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  trap 'deploy_exit_trap' EXIT
  main "$@"
fi
