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
  assert_output --partial 'chmod 0755 /var/log'
  assert_output --partial 'chown root:root /var/log'
}

@test "hardening_resume_reconcile_script: invokes rollback-backed Netplan repair on resume" {
  run hardening_resume_reconcile_script

  assert_success
  assert_output --partial 'network_services_module="/root/base/modules/services.sh"'
  assert_output --partial 'source "${network_services_module}"'
  assert_output --partial 'NETPLAN_CONFIG_DIR="/etc/netplan"'
  assert_output --partial 'repair_netplan_offlink_ipv6_default_route'
  assert_output --partial 'configure_ufw_sysctl_martian_logging'
  assert_output --partial 'install_rsyslog_tmpfiles_override'
}

@test "docker_audit_runtime_reconcile_script: distinguishes loaded rules from immutable reboot debt" {
  run docker_audit_runtime_reconcile_script

  assert_success
  assert_output --partial 'hardening-auditd-runtime-reconcile'
  assert_output --partial "printf '%s\\n' 'ready'"
  assert_output --partial "printf '%s\\n' 'reboot-required'"
  assert_output --partial 'audit_enabled}" == "2"'
  assert_output --partial 'audit_rate}" != "10000"'
  assert_output --partial 'audit_loginuid}" == "1"'
  assert_output --partial 'audit_lost}" == "0"'
}
