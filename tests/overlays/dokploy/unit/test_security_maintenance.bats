#!/usr/bin/env bats

load '../../../helpers/helpers'

setup() {
  source "${PROJECT_ROOT}/overlays/dokploy/dokploy-common.sh"
  ADMIN_PUBKEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyData operator@test'
}

@test "Hermes maintenance: rootless compose policy preserves data and refuses unsafe overrides" {
  run python3 "${PROJECT_ROOT}/tests/overlays/dokploy/unit/test_hermes_runtime_policy.py"
  assert_success
}

@test "Hermes maintenance: updater refuses root init and verifies rollback without claiming rootless success" {
  run python3 "${PROJECT_ROOT}/tests/overlays/dokploy/unit/test_hermes_updater.py"
  assert_success
}

@test "Dokploy maintenance: Go security floors refuse prereleases downgrades and import-major jumps" {
  run python3 "${PROJECT_ROOT}/tests/overlays/dokploy/unit/test_go_security_floors.py"
  assert_success
}

@test "Dokploy maintenance: native compiler discovery preserves stable API versions" {
  run python3 "${PROJECT_ROOT}/tests/overlays/dokploy/unit/test_native_compilers.py"
  assert_success
}

@test "Dokploy maintenance: generated finalizer and updater have valid Bash syntax" {
  local script updater
  script="${BATS_TEST_TMPDIR}/finalize.sh"
  updater="${BATS_TEST_TMPDIR}/updater.sh"
  dokploy_finalize_runtime_script > "${script}"
  run bash -n "${script}"
  assert_success
  awk '/^cat > .*DOKPLOY_UPDATER/ {inside=1;next} /^DOKPLOY_UPDATER$/ {inside=0} inside' "${script}" > "${updater}"
  [ -s "${updater}" ]
  run bash -n "${updater}"
  assert_success
}

@test "Dokploy enrollment: every policy consumer uses current auth schema and verified authenticator presence" {
  local path
  for path in overlays/dokploy/dokploy-common.sh overlays/dokploy/checks/dokploy_check.sh overlays/docker-host/modules/user_rules.sh; do
    grep -Fq 'u.two_factor_enabled IS DISTINCT FROM TRUE' "${PROJECT_ROOT}/${path}"
    grep -Fq 'tf.verified IS TRUE AND length(tf.secret) > 0' "${PROJECT_ROOT}/${path}"
    ! grep -Fq 'is2FAEnabled' "${PROJECT_ROOT}/${path}"
  done
}

@test "Dokploy maintenance: patches approved channels only and resolves immutable images" {
  run dokploy_finalize_runtime_script
  assert_success
  assert_output --partial 'TRAEFIK_CHANNEL="traefik:v3.7"'
  assert_output --partial 'POSTGRES_CHANNEL="postgres:16"'
  assert_output --partial 'proxy_image="${TRAEFIK_CHANNEL}@${proxy_digest}"'
  assert_output --partial 'postgres_image="${POSTGRES_CHANNEL}@${postgres_digest}"'
  assert_output --partial 'PostgreSQL candidate is outside approved major 16'
  assert_output --partial 'Traefik candidate is outside approved 3.7 security floor'
  assert_output --partial '--update-failure-action rollback'
  refute_output --partial 'POSTGRES_CHANNEL="postgres:latest"'
  assert_output --partial 'if [[ "${unattended_recovery}" == true ]]'
  assert_output --partial 'python3 /usr/local/sbin/paas-recovery-policy'
  assert_output --partial 'Unsafe or unapproved unattended recovery policy'
}

@test "Dokploy maintenance: requires an encrypted backup before applying image updates" {
  local output backup_line update_line
  output="$(dokploy_finalize_runtime_script)"
  [[ "${output}" == *'pg_dump -U dokploy -d dokploy --no-owner --no-acl'* ]]
  [[ "${output}" == *'gzip -c | age -r "${backup_recipient}"'* ]]
  [[ "${output}" == *'Encrypted database backup failed; no updates applied.'* ]]
  backup_line="$(printf '%s\n' "${output}" | awk '/pg_dump -U/{print NR;exit}')"
  update_line="$(printf '%s\n' "${output}" | awk '/docker service update --image "\$\{postgres_image\}"/{print NR;exit}')"
  [ "${backup_line}" -lt "${update_line}" ]
}

@test "Dokploy maintenance: verifies the live proxy boundary and records evidence" {
  run dokploy_finalize_runtime_script
  assert_success
  assert_output --partial 'The live Traefik task does not match the approved digest.'
  assert_output --partial "-H 'Host: dokploy.docker.localhost'"
  assert_output --partial '"${block_code}" == "403"'
  assert_output --partial "sport = :8080"
  assert_output --partial 'traefik_resolved_image=%s'
  assert_output --partial 'postgres_resolved_image=%s'
  assert_output --partial 'systemctl enable --now docker-user-hardening-refresh.timer'
}

@test "Dokploy maintenance: deployment invokes audit recovery before routing or acceptance" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    PAAS=dokploy
    parse_args() { :; }; init_root_password_auth() { :; }; collect_inputs() { :; }
    validate_inputs() { :; }; confirm() { :; }; preflight() { :; }
    phase1_upload_harden() { :; }; phase2_gates() { :; }
    phase3_docker_dokploy() { echo INSTALL; }
    reconcile_docker_audit_runtime_remote() { echo AUDIT; }
    phase4_dokploy_access_policy() { echo ROUTING; }
    phase5_verify() { echo VERIFY; }
    main
  '
  assert_success
  assert_output --partial $'INSTALL\nAUDIT\nROUTING\nVERIFY'
}

@test "Dokploy validator: accepts fresh protected same-minor proxy receipt and rejects stale or unsafe receipts" {
  source_validate_script
  reset_validate_runtime
  DOKPLOY_AUTO_UPDATE_STATE="${BATS_TEST_TMPDIR}/update-state"
  MOCK_STATE_PERMS='600:root:root'
  local digest image epoch json
  digest="sha256:$(printf '%064d' 1)"
  image="traefik:v3.7@${digest}"
  epoch="$(date +%s)"
  write_receipt() {
    printf 'last_check_epoch=%s\ntraefik_resolved_image=%s\ntraefik_version=%s\n' \
      "$1" "${image}" "$2" > "${DOKPLOY_AUTO_UPDATE_STATE}"
  }
  stat() {
    if [[ "${3:-}" == "${DOKPLOY_AUTO_UPDATE_STATE}" ]]; then printf '%s\n' "${MOCK_STATE_PERMS}"; else command stat "$@"; fi
  }
  docker() {
    case "$1 $2" in
      'info --format') echo active ;;
      'service ls') echo dokploy-traefik ;;
      'service inspect') echo "${image}" ;;
      *) return 1 ;;
    esac
  }
  ufw() { :; }; ss() { :; }; iptables() { :; }; curl() { echo 403; }
  write_receipt "${epoch}" 3.7.14
  dokploy_check
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" 'dokploy: Traefik immutable image' PASS
  reset_validate_runtime
  write_receipt "$((epoch - 90000))" 3.7.14
  dokploy_check
  assert_json_check_status "$(emit_validate_results_json)" 'dokploy: Traefik immutable image' FAIL
  reset_validate_runtime
  write_receipt "${epoch}" 4.0.0
  dokploy_check
  assert_json_check_status "$(emit_validate_results_json)" 'dokploy: Traefik immutable image' FAIL
  reset_validate_runtime
  MOCK_STATE_PERMS='644:root:root'
  write_receipt "${epoch}" 3.7.14
  dokploy_check
  assert_json_check_status "$(emit_validate_results_json)" 'dokploy: Traefik immutable image' FAIL
}
