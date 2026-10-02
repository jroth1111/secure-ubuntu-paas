#!/usr/bin/env bats
load '../../helpers/helpers'

@test "test harness: bootstrap dry-run executor cannot execute a real mutation" {
  source_script
  DRY_RUN=true
  local marker="${BATS_TEST_TMPDIR}/must-not-exist"
  timedatectl() { touch "${marker}"; }
  TIMEZONE=Australia/Melbourne
  run configure_timezone
  assert_success
  [ ! -e "${marker}" ]
  assert_output --partial 'DRY-RUN'
}

@test "test harness: a failed assertion stays failed after importing the project logger" {
  local fixture="${BATS_TEST_TMPDIR}/failure.bats"
  cat > "${fixture}" <<EOF
#!/usr/bin/env bats
load '${PROJECT_ROOT}/tests/helpers/helpers'
setup() { source_common_lib; }
@test 'intentional assertion failure' {
  run printf have
  assert_output --partial want
}
EOF
  run bats "${fixture}"
  assert_failure
  assert_output --partial 'not ok 1'
  assert_output --partial 'output does not contain substring'
}

@test "test harness: a failed JSON assertion is not lost when validate is sourced" {
  local fixture="${BATS_TEST_TMPDIR}/json-failure.bats"
  cat > "${fixture}" <<EOF
#!/usr/bin/env bats
load '${PROJECT_ROOT}/tests/helpers/helpers'
setup() { source_validate_script; }
@test 'intentional JSON failure followed by successful command' {
  assert_json_fail_count '{"fail":1}' 0
  true
}
EOF
  run bats "${fixture}"
  assert_failure
  assert_output --partial 'not ok 1'
}
