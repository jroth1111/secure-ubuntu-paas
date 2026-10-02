#!/usr/bin/env bats
load '../../helpers/helpers'

setup() {
  source_validate_script
  reset_validate_runtime
  TAILSCALE_EXPIRY_RECEIPT="${BATS_TEST_TMPDIR}/expiry.json"
  ip() { return 0; }
  unit_available() { return 1; }
  tailscale() {
    case "$1 $2" in
      'status --json') echo '{"BackendState":"Running","Self":{"ID":"test-node"},"Peer":[]}' ;;
      'ip -4') echo 100.64.0.2 ;;
      'debug prefs') echo '{"RunSSH":false,"AutoUpdate":{"Apply":true}}' ;;
    esac
  }
}

@test "tailscale_check: only explicit disabled node-key expiry passes" {
  local value json
  for value in true false null '"true"'; do
    reset_validate_runtime
    jq -n --argjson value "${value}" --argjson now "$(date +%s)" \
      '{nodeId:"test-node",tailscaleIp:"100.64.0.2",checkedAt:$now,keyExpiryDisabled:$value}' > "${TAILSCALE_EXPIRY_RECEIPT}"
    chmod 600 "${TAILSCALE_EXPIRY_RECEIPT}"
    tailscale_check
    json="$(emit_validate_results_json)"
    case "$value" in
      true) assert_json_check_status "$json" 'tailscale: node-key expiry disabled' PASS ;;
      false) assert_json_check_status "$json" 'tailscale: node-key expiry disabled' FAIL ;;
      *) assert_json_check_status "$json" 'tailscale: node-key expiry verification' INFO ;;
    esac
  done
}

@test "tailscale_check: stale or wrong-node receipt cannot prove disabled expiry" {
  local identity epoch
  for identity in test-node another-node; do
    epoch=$(( $(date +%s) - 2592001 ))
    [[ "$identity" != another-node ]] || epoch="$(date +%s)"
    jq -n --arg identity "$identity" --argjson epoch "$epoch" \
      '{nodeId:$identity,tailscaleIp:"100.64.0.2",checkedAt:$epoch,keyExpiryDisabled:true}' > "${TAILSCALE_EXPIRY_RECEIPT}"
    chmod 600 "${TAILSCALE_EXPIRY_RECEIPT}"
    reset_validate_runtime
    tailscale_check
    assert_json_check_status "$(emit_validate_results_json)" 'tailscale: node-key expiry verification' INFO
  done
}
