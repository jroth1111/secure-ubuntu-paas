# Common BATS helpers — loaded by all test files

# Derive PROJECT_ROOT from this helpers file's own location (tests/helpers/helpers.bash → project root)
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
SCRIPT="${PROJECT_ROOT}/base/bootstrap.sh"
VALIDATE_SCRIPT="${PROJECT_ROOT}/base/validate.sh"
DEPLOY_SCRIPT="${PROJECT_ROOT}/deploy.sh"
SETUP_SCRIPT="${PROJECT_ROOT}/setup.sh"
COMMON_LIB="${PROJECT_ROOT}/overlays/coolify/coolify-common.sh"

# Load bats-support and bats-assert from the first available location
_helpers_loaded=false

# 1. Local project checkout (tests/lib/ — installed by `make setup-bats`)
if [[ -f "${PROJECT_ROOT}/tests/lib/bats-support/load.bash" ]]; then
  load "${PROJECT_ROOT}/tests/lib/bats-support/load"
  load "${PROJECT_ROOT}/tests/lib/bats-assert/load"
  _helpers_loaded=true
fi

# 2. Docker container path (Dockerfile.test installs here)
if ! $_helpers_loaded && [[ -f "/opt/bats-support/load.bash" ]]; then
  load '/opt/bats-support/load'
  load '/opt/bats-assert/load'
  _helpers_loaded=true
fi

# 3. Linux package-manager path
if ! $_helpers_loaded && [[ -f "/usr/lib/bats-support/load.bash" ]]; then
  load '/usr/lib/bats-support/load'
  load '/usr/lib/bats-assert/load'
  _helpers_loaded=true
fi

# 4. macOS Homebrew path
if ! $_helpers_loaded && [[ -f "/usr/local/lib/bats-support/load.bash" ]]; then
  load '/usr/local/lib/bats-support/load'
  load '/usr/local/lib/bats-assert/load'
  _helpers_loaded=true
fi

# 5. Fallback: rely on BATS_LIB_PATH / npm
if ! $_helpers_loaded; then
  load 'bats-support'
  load 'bats-assert'
fi

unset _helpers_loaded

# The project also defines a logging-only fail(), which must never replace
# bats-support's assertion failure semantics inside an assertion call.
eval "$(declare -f fail | sed '1s/^fail /_bats_assertion_fail /')"
eval "$(declare -f run | sed '1s/^run /_bats_native_run /')"

# Production bootstrap helpers must call their own dry-run executor, not the
# BATS capture function. Otherwise a dry-run test can execute real commands.
restore_test_run_dispatcher() {
  run() {
    case "${BASH_SOURCE[1]:-}" in
      "${PROJECT_ROOT}/base/"*)
        if declare -F script_run >/dev/null; then script_run "$@"; else _bats_native_run "$@"; fi
        ;;
      *) _bats_native_run "$@" ;;
    esac
  }
}

# Source the script to import functions.
# Guards against:
#   1. set -Eeuo pipefail and ERR trap leaking into the BATS process
#   2. The script's run() function shadowing BATS's run builtin
source_script() {
  # Save BATS's run function before it gets overwritten
  if declare -f run >/dev/null 2>&1; then
    eval "$(declare -f _bats_native_run | sed '1s/^_bats_native_run /bats_run /')" 2>/dev/null
  fi

  local _old_opts _old_errexit="${-//[^e]/}"
  _old_opts="$(set +o)"          # capture current shell options as restore commands
  local _old_traps
  _old_traps="$(trap -p ERR)"    # capture current ERR trap (if any)

  source "${SCRIPT}"

  eval "${_old_opts}"            # restore original shell options
  [[ "${_old_errexit}" != "e" ]] || set -e
  trap - ERR                     # clear any ERR trap set by the script
  if [[ -n "${_old_traps}" ]]; then
    eval "${_old_traps}"         # restore original ERR trap if there was one
  fi

  # Rename the script's run() → script_run(), restore BATS's run
  if declare -f run >/dev/null 2>&1; then
    eval "$(declare -f run | sed '1s/^run /script_run /')"
  fi
  restore_test_run_dispatcher
}

# Source deploy.sh to import functions for unit testing.
# Same guards as source_script() above.
source_deploy_script() {
  # Save BATS's run function before it gets overwritten
  if declare -f run >/dev/null 2>&1; then
    eval "$(declare -f _bats_native_run | sed '1s/^_bats_native_run /bats_run /')" 2>/dev/null
  fi

  local _old_opts _old_errexit="${-//[^e]/}"
  _old_opts="$(set +o)"
  local _old_traps
  _old_traps="$(trap -p ERR)"

  source "${DEPLOY_SCRIPT}"

  eval "${_old_opts}"
  [[ "${_old_errexit}" != "e" ]] || set -e
  trap - ERR
  if [[ -n "${_old_traps}" ]]; then
    eval "${_old_traps}"
  fi

  # Rename the script's run() → deploy_run(), restore BATS's run
  if declare -f run >/dev/null 2>&1; then
    eval "$(declare -f run | sed '1s/^run /deploy_run /')"
  fi
  restore_test_run_dispatcher
}

# Source setup.sh to import functions for unit testing.
# Same guards as source_script() above.
source_setup_script() {
  # Save BATS's run function before it gets overwritten
  if declare -f run >/dev/null 2>&1; then
    eval "$(declare -f _bats_native_run | sed '1s/^_bats_native_run /bats_run /')" 2>/dev/null
  fi

  local _old_opts _old_errexit="${-//[^e]/}"
  _old_opts="$(set +o)"
  local _old_traps
  _old_traps="$(trap -p ERR)"

  source "${SETUP_SCRIPT}"

  eval "${_old_opts}"
  [[ "${_old_errexit}" != "e" ]] || set -e
  trap - ERR
  if [[ -n "${_old_traps}" ]]; then
    eval "${_old_traps}"
  fi

  # Rename the script's run() → setup_run(), restore BATS's run
  if declare -f run >/dev/null 2>&1; then
    eval "$(declare -f run | sed '1s/^run /setup_run /')"
  fi
  restore_test_run_dispatcher
}

# Source validate_hardening.sh to import functions for unit testing.
# Same guards as source_script() above.
source_validate_script() {
  # Save BATS's run function before it gets overwritten
  if declare -f run >/dev/null 2>&1; then
    eval "$(declare -f _bats_native_run | sed '1s/^_bats_native_run /bats_run /')" 2>/dev/null
  fi

  local _old_opts _old_errexit="${-//[^e]/}"
  _old_opts="$(set +o)"
  local _old_traps
  _old_traps="$(trap -p ERR)"

  source "${VALIDATE_SCRIPT}"

  eval "${_old_opts}"
  [[ "${_old_errexit}" != "e" ]] || set -e
  trap - ERR
  if [[ -n "${_old_traps}" ]]; then
    eval "${_old_traps}"
  fi

  # Restore BATS run
  restore_test_run_dispatcher
}

# Source shared common library for direct unit testing.
source_common_lib() {
  # Save BATS's run function before it gets overwritten
  if declare -f run >/dev/null 2>&1; then
    eval "$(declare -f _bats_native_run | sed '1s/^_bats_native_run /bats_run /')" 2>/dev/null
  fi

  local _old_opts _old_errexit="${-//[^e]/}"
  _old_opts="$(set +o)"
  local _old_traps
  _old_traps="$(trap -p ERR)"

  source "${COMMON_LIB}"

  eval "${_old_opts}"
  [[ "${_old_errexit}" != "e" ]] || set -e
  trap - ERR
  if [[ -n "${_old_traps}" ]]; then
    eval "${_old_traps}"
  fi

  # Restore BATS run
  restore_test_run_dispatcher
}

# Reset validate_hardening.sh runtime counters/arrays in tests.
reset_validate_runtime() {
  PASS_COUNT=0
  FAIL_COUNT=0
  INFO_COUNT=0
  RESULTS=()
  JSON_MODE="true"
  HEALTH_CHECK_MODE="false"
}

# Render the in-memory validate results arrays into the same JSON shape as --json.
emit_validate_results_json() {
  local checks_json='[]'
  if ((${#RESULTS[@]} > 0)); then
    checks_json="$(printf '%s\n' "${RESULTS[@]}" | jq -s '.')"
  fi

  jq -nc \
    --argjson pass "${PASS_COUNT}" \
    --argjson fail "${FAIL_COUNT}" \
    --argjson info "${INFO_COUNT}" \
    --argjson checks "${checks_json}" \
    '{pass:$pass,fail:$fail,info:$info,checks:$checks}'
}

json_check_status() {
  local json="$1"
  local check="$2"
  jq -r --arg check "${check}" '[.checks[] | select(.check == $check) | .status][0] // ""' <<< "${json}"
}

json_check_detail() {
  local json="$1"
  local check="$2"
  jq -r --arg check "${check}" '[.checks[] | select(.check == $check) | .detail][0] // ""' <<< "${json}"
}

assert_json_fail_count() {
  local json="$1"
  local expected="$2"
  local actual
  actual="$(jq -r '.fail' <<< "${json}")"
  [[ "${actual}" == "${expected}" ]]
}

assert_json_check_status() {
  local json="$1"
  local check="$2"
  local expected="$3"
  local actual
  actual="$(json_check_status "${json}" "${check}")"
  [[ "${actual}" == "${expected}" ]]
}

assert_json_check_detail_contains() {
  local json="$1"
  local check="$2"
  local needle="$3"
  local detail
  detail="$(json_check_detail "${json}" "${check}")"
  [[ "${detail}" == *"${needle}"* ]]
}

# Bind only assertion-library failure calls to the saved BATS function.
# Keep function names/call stacks intact (__assert_stream inspects them).
# This affects loaded test functions, not vendored files or production code.
while read -r _bats_assert_name; do
  [[ "${_bats_assert_name}" =~ ^(assert_|refute_|__assert_|__refute_)[a-zA-Z0-9_]+$ ]] || continue
  eval "$(declare -f "${_bats_assert_name}" | sed -E 's/(^|[|;{])[[:space:]]*fail([[:space:]]*;?[[:space:]]*)$/\1 _bats_assertion_fail\2/')"
done < <(declare -F | awk '{print $3}')
unset _bats_assert_name
