#!/usr/bin/env bats

load '../../helpers/helpers'

setup() {
  # shellcheck disable=SC1091
  source "${PROJECT_ROOT}/lib/hardening_resume_reconcile.sh"
}

@test "hardening_resume_reconcile_script: installs timer, modules, and normalizes SSH crypto" {
  run hardening_resume_reconcile_script

  assert_success
  assert_output --partial '99-zzz-hardening-modules.conf'
  assert_output --partial 'hardening-validate.timer'
  assert_output --partial 'Ciphers \^+/Ciphers ^/'
  assert_output --partial 'chmod 0770 /var/log'
}
