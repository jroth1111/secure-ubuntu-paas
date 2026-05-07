#!/usr/bin/env bats
# Unit tests for dflow-common.sh — dFlow overlay shared logic.

load '../../../helpers/helpers'

DFLOW_COMMON="${PROJECT_ROOT}/overlays/dflow/dflow-common.sh"

source_dflow_common() {
  if declare -f run >/dev/null 2>&1; then
    eval "$(declare -f run | sed '1s/^run /bats_run /')" 2>/dev/null
  fi
  local _old_opts
  _old_opts="$(set +o)"
  local _old_traps
  _old_traps="$(trap -p ERR)"

  source "${DFLOW_COMMON}"

  eval "${_old_opts}"
  trap - ERR
  if [[ -n "${_old_traps}" ]]; then
    eval "${_old_traps}"
  fi
  eval "$(declare -f bats_run | sed '1s/^bats_run /run /')"
}

setup() {
  source_dflow_common
  SERVER_IP=""
  ADMIN_USER=""
  PUBKEY_FILE=""
  TAILSCALE_AUTH_KEY=""
  SWAP_SIZE=""
  SERVER_TIMEZONE=""
  AUTO_YES="true"
}

@test "dflow-common.sh: sources without errors" {
  # Already sourced in source_dflow_common; reaching here means success.
  true
}

@test "collect_dflow_inputs: is a no-op stub (always succeeds)" {
  run collect_dflow_inputs
  assert_success
  assert_output ""
}

@test "collect_dflow_inputs: idempotent — safe to call multiple times" {
  collect_dflow_inputs
  collect_dflow_inputs
  run collect_dflow_inputs
  assert_success
}

@test "collect_dflow_setup_inputs: does not prompt when SERVER_IP already set" {
  SERVER_IP="192.0.2.1"
  ADMIN_USER="sysadmin"
  PUBKEY_FILE="/dev/null"
  TAILSCALE_AUTH_KEY="tskey-auth-test"
  SWAP_SIZE="2G"
  SERVER_TIMEZONE="UTC"
  run collect_dflow_setup_inputs
  assert_success
}

@test "collect_dflow_setup_inputs: dies in AUTO_YES mode when SERVER_TIMEZONE unset" {
  SERVER_IP="192.0.2.1"
  ADMIN_USER="sysadmin"
  PUBKEY_FILE="/dev/null"
  TAILSCALE_AUTH_KEY="tskey-auth-test"
  SWAP_SIZE="2G"
  SERVER_TIMEZONE=""
  AUTO_YES="true"
  run collect_dflow_setup_inputs
  assert_failure
  assert_output --partial "Server timezone is required"
}

@test "collect_dflow_setup_inputs: defaults SWAP_SIZE to 2G when unset" {
  SERVER_IP="192.0.2.1"
  ADMIN_USER="sysadmin"
  PUBKEY_FILE="/dev/null"
  TAILSCALE_AUTH_KEY="tskey-auth-test"
  SWAP_SIZE=""
  SERVER_TIMEZONE="UTC"
  collect_dflow_setup_inputs
  [[ "${SWAP_SIZE}" == "2G" ]]
}
