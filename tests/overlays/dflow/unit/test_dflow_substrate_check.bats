#!/usr/bin/env bats
# Unit tests for dFlow substrate validation checks.

load '../../../helpers/helpers'

DFLOW_SUBSTRATE_CHECK="${PROJECT_ROOT}/overlays/dflow/checks/dflow_substrate_check.sh"

setup() {
  tmpdir="$(mktemp -d)"
  DFLOW_DOCKER_DAEMON_JSON="${tmpdir}/daemon.json"
  cat > "${DFLOW_DOCKER_DAEMON_JSON}" <<'JSON'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "live-restore": true
}
JSON

  PASS_COUNT=0
  FAIL_COUNT=0
  INFO_COUNT=0
  RESULTS=()
  JSON_MODE="true"

  record() {
    local status="$1"
    local check="$2"
    local detail="${3:-}"
    case "${status}" in
      PASS) PASS_COUNT=$((PASS_COUNT + 1)) ;;
      FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
      INFO) INFO_COUNT=$((INFO_COUNT + 1)) ;;
    esac
    RESULTS+=("$(jq -nc --arg status "${status}" --arg check "${check}" --arg detail "${detail}" '{status:$status,check:$check,detail:$detail}')")
  }

  source "${DFLOW_SUBSTRATE_CHECK}"
}

teardown() {
  [[ -n "${tmpdir:-}" && -d "${tmpdir}" ]] && rm -rf "${tmpdir}"
}

emit_results() {
  emit_validate_results_json
}

systemctl() {
  [[ "$1" == "is-active" && "$2" == "--quiet" && "$3" == "tailscaled-dfi" ]]
}

sysctl() {
  [[ "$1" == "-n" && "$2" == "net.ipv4.conf.all.log_martians" ]] && echo "1"
}

auditctl() {
  if [[ "$1" == "-l" ]]; then
    for i in {1..30}; do
      echo "-w /example/${i} -p wa -k test"
    done
  fi
}

fail2ban-client() {
  [[ "$1" == "status" && "$2" == "sshd" ]]
}

@test "dflow_substrate_check: parses Ubuntu aa-status --count numeric profile line" {
  aa-status() {
    [[ "$1" == "--count" ]] || return 1
    printf '%s\n' \
      "apparmor module is loaded." \
      "116" \
      "6" \
      "116 profiles are loaded."
  }

  dflow_substrate_check
  json="$(emit_results)"

  assert_json_check_status "${json}" "dflow: AppArmor profiles" "PASS"
  assert_json_check_detail_contains "${json}" "dflow: AppArmor profiles" "116 profiles loaded"
}

@test "dflow_substrate_check: fails AppArmor profile check when count output has no numeric line" {
  aa-status() {
    [[ "$1" == "--count" ]] || return 1
    printf '%s\n' "apparmor module is loaded."
  }

  dflow_substrate_check
  json="$(emit_results)"

  assert_json_check_status "${json}" "dflow: AppArmor profiles" "FAIL"
  assert_json_check_detail_contains "${json}" "dflow: AppArmor profiles" "0 profiles"
}
