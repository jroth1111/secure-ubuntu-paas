#!/usr/bin/env bats
# Additional behavior tests for uncovered deploy/setup functions.

load '../../helpers/helpers'

@test "known_host_key_material: extracts the complete pinned key set" {
  source_deploy_script
  known_hosts_file="$(mktemp)"
  printf '%s\n' '203.0.113.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyDataForDryRunTests test@bats' > "${known_hosts_file}"
  run known_host_key_material "203.0.113.10" "${known_hosts_file}"
  assert_success
  assert_output 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyDataForDryRunTests'
}

@test "cleanup_temp_files: removes known-host and runtime secret temp files" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    DEPLOY_KNOWN_HOSTS="$(mktemp)"
    ADMIN_KNOWN_HOSTS="$(mktemp)"
    ROOT_PASS_RUNTIME_FILE="$(mktemp)"
    cleanup_temp_files
    [[ ! -e "${DEPLOY_KNOWN_HOSTS}" ]]
    [[ ! -e "${ADMIN_KNOWN_HOSTS}" ]]
    [[ ! -e "${ROOT_PASS_RUNTIME_FILE}" ]]
  '
  assert_success
}

@test "deploy security helpers: validate Tailscale addresses, preserve SSH pins, and transport secrets over stdin" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    is_tailscale_ipv4 "100.127.255.254"
    ! is_tailscale_ipv4 "100.128.0.1"

    known_hosts_file="$(mktemp)"
    target_known_hosts="$(mktemp)"
    printf "%s\n" "203.0.113.10 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyDataForDryRunTests test@bats" > "${known_hosts_file}"
    known_host_entry_present "203.0.113.10" "${known_hosts_file}"
    [[ "$(known_host_key_material "203.0.113.10" "${known_hosts_file}")" == "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyDataForDryRunTests" ]]
    ! known_host_entry_present "100.64.0.10" "${known_hosts_file}"
    pin_known_host_alias "203.0.113.10" "100.64.0.10" "${known_hosts_file}" "${target_known_hosts}"
    grep -q "100.64.0.10 ssh-ed25519" "${target_known_hosts}"
    printf "%s\n" "100.64.0.10 ssh-ed25519 AAAAWRONGKEY" > "${target_known_hosts}"
    ! pin_known_host_alias "203.0.113.10" "100.64.0.10" "${known_hosts_file}" "${target_known_hosts}"

    captured_secret="$(mktemp)"
    remote_command=""
    ssh_admin_sudo() {
      remote_command="$1"
      case "$1" in
        *mktemp*) printf "/run/secure-ubuntu-paas/deploy-secrets.TEST\n" ;;
        *install*) cat > "${captured_secret}" ;;
        *) : ;;
      esac
    }
    remote_secret_dir_create >/dev/null
    remote_dir="$(remote_secret_dir_create)"
    [[ "${remote_dir}" == "/run/secure-ubuntu-paas/deploy-secrets.TEST" ]]
    remote_secret_write_file "${remote_dir}/token" "test-secret"
    [[ "${remote_command}" != *test-secret* ]]
    [[ "$(<"${captured_secret}")" == "test-secret" ]]
    remote_secret_cleanup_dir "${remote_dir}"
  '
  echo "INNER_STATUS=${status} INNER_OUTPUT=${output}"
  assert_success
}

@test "Dokploy Keychain helpers store and load the Swarm key without argv exposure" {
  source_deploy_script
  SERVER_IP="203.0.113.10"
  dokploy_swarm_unlock_keychain_service >/dev/null
  service="$(dokploy_swarm_unlock_keychain_service)"
  [[ "${service}" == "secure-ubuntu-paas/dokploy/swarm-unlock/203.0.113.10" ]]
  expect_args=""
  expect_input=""
  expect() {
    printf '%s' "$*" > "${BATS_TEST_TMPDIR}/expect-args"
    cat > "${BATS_TEST_TMPDIR}/expect-input"
    return 0
  }
  security() {
    case "$1" in
      find-generic-password)
        [[ " $* " == *" -w "* ]] && printf '%s\n' 'SWMKEY-test'
        return 0
        ;;
      *) return 1 ;;
    esac
  }
  store_dokploy_swarm_unlock_key "SWMKEY-test"
  expect_args="$(cat "${BATS_TEST_TMPDIR}/expect-args")"
  expect_input="$(cat "${BATS_TEST_TMPDIR}/expect-input"; printf '.')"
  expect_input="${expect_input%.}"
  [[ "${expect_input}" == $'SWMKEY-test\n' ]]
  [[ "${expect_args}" != *SWMKEY-test* ]]
  load_dokploy_swarm_unlock_key
  [[ "${DOKPLOY_SWARM_UNLOCK_KEY_RUNTIME}" == "SWMKEY-test" ]]
}

@test "Dokploy remote handoff and unlock helpers use root-only files and protected stdin" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    PAAS="dokploy"
    DOKPLOY_SWARM_UNLOCK_KEY_RUNTIME=""
    stored=""
    removed=0
    unlock_command=""
    staged_value=""
    state_file="$(mktemp)"
    printf "%s\n" 0 > "${state_file}"
    store_dokploy_swarm_unlock_key() { stored="$1"; }
    ssh_admin_sudo() {
      case "$1" in
        "set -Eeuo pipefail; handoff="*) printf "%s\n" "SWMKEY-test" ;;
        "rm -f -- /run/secure-ubuntu-paas-dokploy-swarm-unlock-key") removed=1 ;;
        "timeout 30 docker swarm unlock < "*) unlock_command="$1" ;;
        *) return 0 ;;
      esac
    }
    remote_secret_dir_create() { printf "%s\n" "/run/secure-ubuntu-paas/deploy-secrets.TEST"; }
    remote_secret_write_file() { staged_value="$2"; }
    remote_secret_cleanup_dir() { :; }
    dokploy_swarm_state_remote() {
      state_calls="$(cat "${state_file}")"
      state_calls=$((state_calls + 1))
      printf "%s\n" "${state_calls}" > "${state_file}"
      if (( state_calls == 1 )); then printf "locked\\ttrue\\n"; else printf "active\\ttrue\\n"; fi
    }
    capture_dokploy_swarm_unlock_handoff_remote
    [[ "${stored}" == "SWMKEY-test" && "${removed}" -eq 1 ]]
    unlock_dokploy_swarm_remote
    [[ "${staged_value}" == "SWMKEY-test" ]]
    [[ "${unlock_command}" != *SWMKEY-test* ]]
  '
  assert_success
}

@test "Dokploy Swarm state and recovery helpers unlock a locked resume" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    PAAS="dokploy"
    ssh_admin_sudo() { printf "active\\ttrue\\n"; }
    state_file="$(mktemp)"
    dokploy_swarm_state_remote > "${state_file}"
    [[ "$(<"${state_file}")" == active*true ]]
    dokploy_swarm_state_remote() { printf "locked\\ttrue\\n"; }
    ssh_admin_sudo() { return 1; }
    load_dokploy_swarm_unlock_key() { DOKPLOY_SWARM_UNLOCK_KEY_RUNTIME="SWMKEY-test"; }
    unlock_called=0
    unlock_dokploy_swarm_remote() { unlock_called=1; }
    ensure_dokploy_swarm_unlocked_remote
    [[ "${unlock_called}" -eq 1 ]]
    [[ -z "${DOKPLOY_SWARM_UNLOCK_KEY_RUNTIME}" ]]
  '
  assert_success
}

@test "Docker audit remote helpers reconcile and perform a verified reboot" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    ALLOW_CONTROLLED_REBOOT=true
    PAAS="coolify"
    docker_audit_runtime_reconcile_script() { printf "%s\n" "printf ready"; }
    ssh_admin_sudo() {
      if [[ "$1" == "bash -s" ]]; then bash -s; return; fi
      return 0
    }
    state_file="$(mktemp)"
    docker_audit_runtime_state_remote > "${state_file}"
    [[ "$(<"${state_file}")" == "ready" ]]

    drop_calls=0
    ssh_admin() { drop_calls=$((drop_calls + 1)); return 1; }
    wait_for_admin_ssh_or_die() { return 0; }
    verify_post_reboot_services_remote() { :; }
    docker_audit_runtime_state_remote() { printf "%s\n" "ready"; }
    reboot_for_docker_audit_remote "Audit reboot"

    reboot_called=0
    docker_audit_runtime_state_remote() { printf "%s\n" "reboot-required"; }
    reboot_for_docker_audit_remote() { reboot_called=1; }
    reconcile_docker_audit_runtime_remote "Audit reconcile"
    [[ "${reboot_called}" -eq 1 ]]
  '
  assert_success
  assert_output --partial "Docker audit watches loaded after controlled reboot"
}

@test "setup Docker audit and Swarm helpers fail closed at operator-owned reboot boundaries" {
  run bash -c '
    source "'"${SETUP_SCRIPT}"'"
    PAAS="dokploy"
    AUTO_YES="true"
    docker() {
      if [[ "$1" == "info" ]]; then printf "%s\n" "locked"; return 0; fi
      return 0
    }
    ensure_dokploy_swarm_unlocked_local
  '
  assert_failure
  assert_output --partial "Docker Swarm is locked"

  run bash -c '
    source "'"${SETUP_SCRIPT}"'"
    docker_audit_runtime_reconcile_script() { printf "%s\n" "printf ready"; }
    state_file="$(mktemp)"
    docker_audit_runtime_state_local > "${state_file}"
    [[ "$(<"${state_file}")" == "ready" ]]
    PAAS="dokploy"
    docker_audit_runtime_state_local() { printf "%s\n" "reboot-required"; }
    reconcile_docker_audit_runtime_local "Post-Dokploy audit reconciliation"
  '
  assert_failure
  assert_output --partial "docker swarm unlock"
}

@test "sync_operator_known_host_entries: preserves existing pins and appends verified session keys" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    HOME="$(mktemp -d)"
    mkdir -p "${HOME}/.ssh"
    printf "100.64.0.10 ssh-ed25519 AAAAOLDKEY\n" > "${HOME}/.ssh/known_hosts"
    source_file="$(mktemp)"
    printf "100.64.0.10 ssh-ed25519 AAAANEWKEY\n" > "${source_file}"
    sync_operator_known_host_entries "${source_file}" "100.64.0.10"
    grep -q "AAAAOLDKEY" "${HOME}/.ssh/known_hosts"
    grep -q "AAAANEWKEY" "${HOME}/.ssh/known_hosts"
  '
  assert_success
}

@test "deploy_exit_trap: best-effort cleans remote deploy env then local temp files" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    DEPLOY_ENV_REMOTE_PENDING="true"
    REMOTE_DEPLOY_ENV_PATH="/root/deploy.env"
    pin_known_host_alias() { :; }
    TS_IP="100.64.0.10"
    ADMIN_USER="alice"
    PRIVATE_KEY="/tmp/id_ed25519"
    SSH_OPTS=(-o StrictHostKeyChecking=accept-new)
    DEPLOY_KNOWN_HOSTS="$(mktemp)"
    ADMIN_KNOWN_HOSTS="$(mktemp)"
    ROOT_PASS_RUNTIME_FILE="$(mktemp)"
    remote_rm=0
    ssh_admin_sudo() { [[ "$1" == "rm -f /root/deploy.env" ]] && remote_rm=1; return 0; }
    run_report_finalize() { :; }
    set +e
    false
    deploy_exit_trap
    [[ "${remote_rm}" -eq 1 ]]
    [[ "${DEPLOY_ENV_REMOTE_PENDING}" == "false" ]]
    [[ ! -e "${DEPLOY_KNOWN_HOSTS}" ]]
    [[ ! -e "${ADMIN_KNOWN_HOSTS}" ]]
    [[ ! -e "${ROOT_PASS_RUNTIME_FILE}" ]]
  '
  assert_success
}

@test "cleanup_remote_deploy_env: clears pending remote env via admin sudo path" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    DEPLOY_ENV_REMOTE_PENDING="true"
    REMOTE_DEPLOY_ENV_PATH="/root/deploy.env"
    pin_known_host_alias() { :; }
    TS_IP="100.64.0.10"
    ADMIN_USER="alice"
    PRIVATE_KEY="/tmp/id_ed25519"
    SSH_OPTS=(-o StrictHostKeyChecking=accept-new)
    ssh_admin_sudo() { [[ "$1" == "rm -f /root/deploy.env" ]]; }
    cleanup_remote_deploy_env
    [[ "${DEPLOY_ENV_REMOTE_PENDING}" == "false" ]]
  '
  assert_success
}

@test "deploy helper state functions: extract bootstrap tailscale IP and validate resume state" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    capture="$(mktemp)"
    printf "noise\nHARDEN_RESULT_TAILSCALE_IP=100.64.0.44\n" > "${capture}"
    extract_bootstrap_tailscale_ip "${capture}" > "${capture}.out"
    extracted_ip="$(cat "${capture}.out")"
    [[ "${extracted_ip}" == "100.64.0.44" ]]

    SKIP_HARDEN="true"
    DEPLOY_MODE="tunnel"
    DOMAIN="coolify.example.com"
    fetch_phase1_state_line_remote() {
      printf "coolify.example.com\ttrue\n"
    }
    assert_resume_phase1_contract_remote
  '
  assert_success
}

@test "verify_post_reboot_services_remote: accepts healthy post-reboot services" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    ssh_admin_sudo() {
      case "$1" in
        "systemctl is-active --quiet tailscaled.service") return 0 ;;
        "ufw status 2>/dev/null | grep -q \"^Status: active$\"") return 0 ;;
        "systemctl is-active --quiet fail2ban.service") return 0 ;;
        "fail2ban-client status sshd >/dev/null 2>&1") return 0 ;;
        "test \"$(systemctl show docker.service --property=LoadState --value 2>/dev/null)\" = loaded") return 1 ;;
      esac
      return 1
    }
    verify_post_reboot_services_remote "Gate B.5"
  '
  assert_success
  assert_output --partial "tailscaled.service is active"
}

@test "phase5_fetch_validate_json (deploy): requests remote validator json via sudo" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    ssh_admin_sudo() {
      [[ "$1" == "/root/base/validate.sh --json" ]]
      echo "{\"fail\":0,\"checks\":[]}"
    }
    phase5_fetch_validate_json
  '
  assert_success
  assert_output --partial '"fail":0'
}

@test "phase5_noop_operator_confirm (deploy): returns success" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    phase5_noop_operator_confirm
  '
  assert_success
}

@test "phase5_dokploy_operator_confirm (deploy): refuses non-interactive completion before enrollment" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    AUTO_YES="true"
    DOKPLOY_ENROLLMENT_SOURCE_IP="100.100.100.50"
    phase5_dokploy_operator_confirm "Complete Dokploy enrollment"
  '
  assert_failure
  assert_output --partial "restricted to 100.100.100.50"
  assert_output --partial "rerun the same deploy command"
}

@test "setup_exit_trap: removes pending deploy env file" {
  run bash -c '
    source "'"${SETUP_SCRIPT}"'"
    pending="$(mktemp)"
    PENDING_DEPLOY_ENV_FILE="${pending}"
    run_report_finalize() { :; }
    set +e
    false
    setup_exit_trap
    [[ ! -e "${pending}" ]]
    [[ -z "${PENDING_DEPLOY_ENV_FILE}" ]]
  '
  assert_success
}

@test "setup reboot marker helpers: return overridable file paths" {
  run bash -c '
    source "'"${SETUP_SCRIPT}"'"
    REBOOT_REQUIRED_FILE="/tmp/reboot-required.test"
    REBOOT_REQUIRED_PKGS_FILE="/tmp/reboot-required.pkgs.test"
    setup_reboot_required_file > /tmp/setup-reboot-required-file.out
    setup_reboot_required_pkgs_file > /tmp/setup-reboot-required-pkgs-file.out
    reboot_file="$(cat /tmp/setup-reboot-required-file.out)"
    reboot_pkgs_file="$(cat /tmp/setup-reboot-required-pkgs-file.out)"
    [[ "${reboot_file}" == "/tmp/reboot-required.test" ]]
    [[ "${reboot_pkgs_file}" == "/tmp/reboot-required.pkgs.test" ]]
  '
  assert_success
}

@test "phase5_fetch_validate_json (setup): executes local validator with --json" {
  run bash -c '
    source "'"${SETUP_SCRIPT}"'"
    tmpdir="$(mktemp -d)"
    SCRIPT_DIR="${tmpdir}"
    mkdir -p "${tmpdir}/base"
    cat > "${tmpdir}/base/validate.sh" <<EOF
#!/usr/bin/env bash
echo "{\"fail\":0,\"checks\":[]}"
EOF
    chmod +x "${tmpdir}/base/validate.sh"
    phase5_fetch_validate_json
  '
  assert_success
  assert_output --partial '"fail":0'
}

@test "init_ssh_options: initializes SSH and root SSH options as arrays" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    SERVER_IP="203.0.113.10"
    TS_IP="100.64.0.10"
    init_ssh_options
    [[ "${#SSH_OPTS[@]}" -gt 0 ]]
    [[ "${#ROOT_SSH_OPTS[@]}" -gt 0 ]]
    [[ " ${ROOT_SSH_OPTS[*]} " == *" PubkeyAuthentication=no "* ]]
    [[ " ${ROOT_SSH_OPTS[*]} " == *" NumberOfPasswordPrompts=1 "* ]]
  '
  assert_success
}

@test "init_root_password_auth: writes runtime password file and clears in-memory secret" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    ROOT_PASS="super-secret"
    init_root_password_auth
    [[ -n "${ROOT_PASS_RUNTIME_FILE}" ]]
    [[ -f "${ROOT_PASS_RUNTIME_FILE}" ]]
    [[ -z "${ROOT_PASS}" ]]
    rm -f "${ROOT_PASS_RUNTIME_FILE}"
  '
  assert_success
}

@test "parse_args (deploy): extracts --server-timezone" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    parse_args --server-timezone "UTC"
    [[ "${SERVER_TIMEZONE}" == "UTC" ]]
  '
  assert_success
}

@test "collect_inputs (deploy): prompts for root password only when needed" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    collect_common_inputs() {
      SERVER_IP="203.0.113.10"
      ADMIN_USER="alice"
      PUBKEY_FILE="/tmp/id.pub"
      TAILSCALE_AUTH_KEY="tskey-auth-x"
      DEPLOY_MODE="tunnel"
      DOMAIN="vps.example.com"
      CF_API_TOKEN="token"
      SWAP_SIZE="2G"
      SERVER_TIMEZONE="UTC"
      APP_DOMAIN_MODE="apex"
    }
    prompt_secret() { ROOT_PASS="from-prompt"; }
    SKIP_HARDEN="false"
    ROOT_PASS=""
    collect_inputs
    [[ "${ROOT_PASS}" == "from-prompt" ]]
  '
  assert_success
}

@test "scp_admin: uses identity file and ssh options" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    PRIVATE_KEY="/tmp/id_ed25519"
    SSH_OPTS=(-o StrictHostKeyChecking=accept-new)
    scp() { printf "%s\n" "$*"; }
    scp_admin a b
  '
  assert_success
  assert_output --partial "-i /tmp/id_ed25519 a b"
}

@test "ssh_root: uses sshpass file-based auth and root ssh options" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    ROOT_PASS_RUNTIME_FILE="$(mktemp)"
    printf "pw" > "${ROOT_PASS_RUNTIME_FILE}"
    ROOT_SSH_HOST="203.0.113.10"
    ROOT_SSH_OPTS=(-o StrictHostKeyChecking=accept-new)
    sshpass() { printf "%s\n" "$*"; }
    ssh_root "echo ok"
  '
  assert_success
  assert_output --partial "-f"
  assert_output --partial "root@203.0.113.10 echo ok"
}

@test "scp_root: uses sshpass file-based auth for root scp" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    ROOT_PASS_RUNTIME_FILE="$(mktemp)"
    printf "pw" > "${ROOT_PASS_RUNTIME_FILE}"
    ROOT_SSH_OPTS=(-o StrictHostKeyChecking=accept-new)
    sshpass() { printf "%s\n" "$*"; }
    scp_root /tmp/a root@host:/tmp/b
  '
  assert_success
  assert_output --partial "-f"
  assert_output --partial "scp"
}

@test "ssh_admin: uses admin key and tailscale destination" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    SSH_OPTS=(-o StrictHostKeyChecking=accept-new)
    PRIVATE_KEY="/tmp/id_ed25519"
    ADMIN_USER="alice"
    TS_IP="100.64.0.10"
    ssh() { printf "%s\n" "$*"; }
    ssh_admin "echo ok"
  '
  assert_success
  assert_output --partial "-i /tmp/id_ed25519 alice@100.64.0.10 echo ok"
}

@test "ssh_admin: Dokploy uses root as the sole Tailscale principal" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    SSH_OPTS=(-o StrictHostKeyChecking=accept-new)
    PRIVATE_KEY="$(mktemp)"
    ADMIN_USER="dokployadmin"
    PAAS="dokploy"
    TS_IP="100.64.0.10"
    ssh() { printf "%s\n" "$*"; }
    ssh_admin "echo ok"
    rm -f "${PRIVATE_KEY}"
  '
  assert_success
  assert_output --partial "root@100.64.0.10 echo ok"
  refute_output --partial "dokployadmin@100.64.0.10"
}

@test "ssh_admin_sudo: prefixes remote command with sudo" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    SSH_OPTS=(-o StrictHostKeyChecking=accept-new)
    PRIVATE_KEY="/tmp/id_ed25519"
    ADMIN_USER="alice"
    TS_IP="100.64.0.10"
    ssh() { printf "%s\n" "$*"; }
    ssh_admin_sudo "echo ok"
  '
  assert_success
  assert_output --partial "alice@100.64.0.10 sudo echo ok"
}

@test "ssh_admin_sudo: Dokploy uses root over Tailscale instead of admin sudo" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    SSH_OPTS=(-o StrictHostKeyChecking=accept-new)
    PRIVATE_KEY="$(mktemp)"
    ADMIN_USER="dokployadmin"
    PAAS="dokploy"
    TS_IP="100.64.0.10"
    ssh() { printf "%s\n" "$*"; }
    ssh_admin_sudo "echo ok"
    rm -f "${PRIVATE_KEY}"
  '
  assert_success
  assert_output --partial "root@100.64.0.10 echo ok"
}

@test "ssh_root_tailscale: uses root key and Tailscale destination" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    SSH_OPTS=(-o StrictHostKeyChecking=accept-new)
    PRIVATE_KEY="$(mktemp)"
    TS_IP="100.64.0.10"
    ssh() { printf "%s\n" "$*"; }
    ssh_root_tailscale "echo ok"
    rm -f "${PRIVATE_KEY}"
  '
  assert_success
  assert_output --partial "root@100.64.0.10 echo ok"
}

@test "sync_companion_scripts: uploads deployment tree tarball and extracts once" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    SCRIPT_DIR="'"${PROJECT_ROOT}"'"
    ADMIN_USER="alice"
    TS_IP="100.64.0.10"
    calls_marker="$(mktemp)"
    remote_tree_dir_create() { printf "/run/secure-ubuntu-paas/deploy-trees/deploy-tree.TEST\n"; }
    ssh_admin_sudo() {
      cat >/dev/null || true
      printf '%s' "$1" >> "${calls_marker}"
      return 0
    }
    sync_companion_scripts
    grep -q "install -m 0600" "${calls_marker}"
    grep -q "DEPLOY_TREE_ARCHIVE=" "${calls_marker}"
  '
  assert_success
}

@test "reconcile_resume_hardening_remote: runs base and dokploy reconciles" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    PAAS="dokploy"
    remote_calls=0
    hardening_resume_reconcile_script() { echo "base-reconcile"; }
    dokploy_root_tailscale_reconcile_script() { echo "dokploy-ssh"; }
    dokploy_remove_stale_coolify_dashboard_ufw_script() { echo "coolify-ufw"; }
    dokploy_dashboard_ufw_policy_script() { echo "dokploy-ufw"; }
    ssh_admin_sudo() { remote_calls=$((remote_calls + 1)); return 0; }
    reconcile_resume_hardening_remote
    [[ "${remote_calls}" -eq 4 ]]
  '
  assert_success
}

@test "recover_interrupted_phase1_dokploy_remote: proves partial state, reboots, and reruns bootstrap without Tailscale enrollment" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    tmpdir="$(mktemp -d)"
    trap "rm -rf \"${tmpdir}\"" EXIT
    PAAS="dokploy"
    TS_IP="100.64.0.10"
    DOKPLOY_ENROLLMENT_SOURCE_IP="100.64.0.20"
    DOMAIN="vps.example.com"
    ADMIN_USER="dokployadmin"
    ADMIN_PUBKEY="ssh-ed25519 AAAATEST operator"
    SWAP_SIZE="2G"
    SERVER_TIMEZONE="Australia/Melbourne"
    TAILSCALE_DIRECT_WAN="false"
    scripts_file="${tmpdir}/remote-scripts"
    env_file="${tmpdir}/recovery-env"
    sync_marker="${tmpdir}/synced"
    ssh_admin_sudo() {
      case "$1" in
        "bash -s")
          printf "%s\n" "---" >> "${scripts_file}"
          cat >> "${scripts_file}"
          return 0
          ;;
        "install -d -m 0700"*)
          cat > "${env_file}"
          return 0
          ;;
        auditctl*) return 0 ;;
        nohup*) return 0 ;;
        "bash -lc "*) return 0 ;;
      esac
      return 0
    }
    ssh_admin() { return 1; }
    sync_companion_scripts() { : > "${sync_marker}"; }
    wait_for_admin_ssh_or_die() { return 0; }
    fetch_phase1_state_line_remote() { printf "vps.example.com\tfalse\n"; }
    run_with_heartbeat() { local label="$1"; shift; "$@"; }
    sleep() { :; }

    recover_interrupted_phase1_dokploy_remote

    [[ -e "${sync_marker}" ]]
    grep -Fq "Refuse a generic state-less host" "${scripts_file}"
    ! grep -Fq "sshd -T 2>/dev/null | grep" "${scripts_file}"
    grep -Fq "global_policy=" "${scripts_file}"
    grep -Fq "install_auditd_rate_limit_persistence" "${scripts_file}"
    grep -Fqx "INSTALL_TAILSCALE=\"false\"" "${env_file}"
    ! grep -Fq "TAILSCALE_AUTH_KEY" "${env_file}"
  '
  assert_success
}

@test "recover_interrupted_phase1_dokploy_remote: refuses when strict partial-state proof fails" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    PAAS="dokploy"
    TS_IP="100.64.0.10"
    DOKPLOY_ENROLLMENT_SOURCE_IP="100.64.0.20"
    DOMAIN="vps.example.com"
    ADMIN_USER="dokployadmin"
    ADMIN_PUBKEY="ssh-ed25519 AAAATEST operator"
    sync_companion_scripts() { echo unsafe-sync; return 99; }
    ssh_admin_sudo() { cat >/dev/null; return 1; }
    recover_interrupted_phase1_dokploy_remote
  '
  assert_failure
  refute_output --partial "unsafe-sync"
}

@test "reconcile_docker_daemon_remote: pipes generated script over ssh_admin" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    coolify_reconcile_docker_daemon_script() { echo "echo reconcile"; }
    ssh_admin() { cat >/dev/null; }
    reconcile_docker_daemon_remote
  '
  assert_success
}

@test "reconcile_docker_daemon_remote: selects Dokploy Swarm-safe reconciler" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    PAAS="dokploy"
    TS_IP="100.64.0.10"
    coolify_reconcile_docker_daemon_script() { echo "echo wrong-reconciler"; return 1; }
    dokploy_reconcile_docker_daemon_script() { echo "echo dokploy-reconciler"; }
    ssh_root_tailscale() { cat; }
    reconcile_docker_daemon_remote
  '
  assert_success
  assert_output --partial "echo dokploy-reconciler"
  assert_output --partial "Swarm-safe"
  refute_output --partial "wrong-reconciler"
}

@test "retry_root_transport: retries ssh 255 failures and then succeeds" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    tmpdir="$(mktemp -d)"
    trap "rm -rf \"${tmpdir}\"" EXIT
    counter_file="${tmpdir}/attempts"
    echo 0 > "${counter_file}"
    flaky_root_cmd() {
      attempt="$(cat "${counter_file}")"
      attempt=$((attempt + 1))
      echo "${attempt}" > "${counter_file}"
      if (( attempt == 1 )); then
        return 255
      fi
      echo ok
      return 0
    }
    sleep() { :; }
    retry_root_transport "upload test" flaky_root_cmd
    [[ "$(cat "${counter_file}")" -eq 2 ]]
  '
  assert_success
  assert_output --partial "ok"
}

@test "phase1_upload_harden: retries bootstrap exec after transient ssh 255 and captures tailscale ip" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    tmpdir="$(mktemp -d)"
    trap "rm -rf \"${tmpdir}\"" EXIT
    counter_file="${tmpdir}/bootstrap-attempts"
    echo 0 > "${counter_file}"
    SCRIPT_DIR="${tmpdir}"
    mkdir -p "${tmpdir}/base" "${tmpdir}/overlays/coolify"
    for script in base/bootstrap.sh base/validate.sh overlays/coolify/configure_coolify_binding.sh; do
      : > "${tmpdir}/${script}"
    done
    mkdir -p "${tmpdir}/lib"
    : > "${tmpdir}/lib/tailscale.sh"
    : > "${tmpdir}/lib/common.sh"
    SERVER_IP="203.0.113.10"
    ADMIN_USER="alice"
    ADMIN_PUBKEY="ssh-ed25519 AAAA test@example"
    DEPLOY_MODE="tunnel"
    SWAP_SIZE="2G"
    SERVER_TIMEZONE="UTC"
    TAILSCALE_AUTH_KEY="tskey-auth-test"
    TAILSCALE_DIRECT_WAN="false"
    REMOTE_DEPLOY_ENV_PATH="/root/deploy.env"
    pin_marker="${tmpdir}/pin-called"
    pin_known_host_alias() {
      [[ "$1" == "203.0.113.10" ]]
      [[ "$2" == "100.64.0.10" ]]
      : > "${pin_marker}"
    }
    probe_counter="${tmpdir}/probe-attempts"
    echo 0 > "${probe_counter}"
    scp_root() { return 0; }
    ssh_root() {
      if [[ "$1" == *"mktemp -d -p /run/secure-ubuntu-paas/deploy-trees"* ]]; then
        echo "/run/secure-ubuntu-paas/deploy-trees/deploy-tree.TEST"
        return 0
      fi
      if [[ "$1" == "true" ]]; then
        count="$(cat "${probe_counter}")"
        count=$((count + 1))
        echo "${count}" > "${probe_counter}"
        return 0
      fi
      if [[ "$1" == *"/root/base/bootstrap.sh --env-file "* ]] && [[ "$1" == *"--install-tailscale --force"* ]]; then
        attempt="$(cat "${counter_file}")"
        attempt=$((attempt + 1))
        echo "${attempt}" > "${counter_file}"
        if [[ "${attempt}" -eq 1 ]]; then
          echo "Permission denied" >&2
          return 255
        fi
        echo "HARDEN_RESULT_TAILSCALE_IP=100.64.0.10"
        return 0
      fi
      return 0
    }
    run_with_heartbeat() { local label="$1"; shift; "$@"; }
    sleep() { :; }
    phase1_upload_harden
    [[ "$(cat "${counter_file}")" -eq 2 ]]
    [[ "$(cat "${probe_counter}")" -eq 1 ]]
    [[ "${TS_IP}" == "100.64.0.10" ]]
  '
  assert_success
}

@test "phase1_upload_harden: retries transient root upload transport failures" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    tmpdir="$(mktemp -d)"
    trap "rm -rf \"${tmpdir}\"" EXIT
    SCRIPT_DIR="${tmpdir}"
    mkdir -p "${tmpdir}/base" "${tmpdir}/overlays/coolify"
    for script in base/bootstrap.sh base/validate.sh overlays/coolify/configure_coolify_binding.sh; do
      : > "${tmpdir}/${script}"
    done
    mkdir -p "${tmpdir}/lib"
    : > "${tmpdir}/lib/tailscale.sh"
    : > "${tmpdir}/lib/common.sh"
    SERVER_IP="203.0.113.10"
    ADMIN_USER="alice"
    ADMIN_PUBKEY="ssh-ed25519 AAAA test@example"
    DEPLOY_MODE="tunnel"
    SWAP_SIZE="2G"
    SERVER_TIMEZONE="UTC"
    TAILSCALE_AUTH_KEY="tskey-auth-test"
    TAILSCALE_DIRECT_WAN="false"
    REMOTE_DEPLOY_ENV_PATH="/root/deploy.env"
    pin_known_host_alias() { :; }
    staging_counter="${tmpdir}/staging-count"
    upload_counter="${tmpdir}/upload-count"
    extract_counter="${tmpdir}/extract-count"
    echo 0 > "${staging_counter}"
    echo 0 > "${upload_counter}"
    echo 0 > "${extract_counter}"
    scp_root() {
      count="$(cat "${upload_counter}")"
      count=$((count + 1))
      echo "${count}" > "${upload_counter}"
      if (( count == 1 )); then
        return 255
      fi
      return 0
    }
    ssh_root() {
      if [[ "$1" == *"mktemp -d -p /run/secure-ubuntu-paas/deploy-trees"* ]]; then
        count="$(cat "${staging_counter}")"
        count=$((count + 1))
        echo "${count}" > "${staging_counter}"
        if (( count == 1 )); then
          return 255
        fi
        echo "/run/secure-ubuntu-paas/deploy-trees/deploy-tree.TEST"
        return 0
      fi
      if [[ "$1" == *"DEPLOY_TREE_ARCHIVE=/run/secure-ubuntu-paas/deploy-trees/"* ]]; then
        count="$(cat "${extract_counter}")"
        count=$((count + 1))
        echo "${count}" > "${extract_counter}"
        if (( count == 1 )); then
          return 255
        fi
        return 0
      fi
      if [[ "$1" == *"/root/base/bootstrap.sh --env-file "* ]] && [[ "$1" == *"--install-tailscale --force"* ]]; then
        echo "HARDEN_RESULT_TAILSCALE_IP=100.64.0.10"
      fi
      return 0
    }
    run_with_heartbeat() { local label="$1"; shift; "$@"; }
    sleep() { :; }
    phase1_upload_harden
    # protected staging creation retried once after SSH exit 255
    [[ "$(cat "${staging_counter}")" -eq 2 ]]
    # tarball upload retried once = 2 + deploy.env = 3 scp_root calls
    [[ "$(cat "${upload_counter}")" -eq 3 ]]
    # extract retried once = 2 ssh_root tar -xzf calls
    [[ "$(cat "${extract_counter}")" -eq 2 ]]
    [[ "${TS_IP}" == "100.64.0.10" ]]
  '
  assert_success
}

@test "phase1_upload_harden: switches root retries to Tailscale IP after early sentinel" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    tmpdir="$(mktemp -d)"
    trap "rm -rf \"${tmpdir}\"" EXIT
    SCRIPT_DIR="${tmpdir}"
    mkdir -p "${tmpdir}/base" "${tmpdir}/overlays/coolify"
    for script in base/bootstrap.sh base/validate.sh overlays/coolify/configure_coolify_binding.sh; do
      : > "${tmpdir}/${script}"
    done
    mkdir -p "${tmpdir}/lib"
    : > "${tmpdir}/lib/tailscale.sh"
    : > "${tmpdir}/lib/common.sh"
    SERVER_IP="203.0.113.10"
    ROOT_SSH_HOST="${SERVER_IP}"
    ADMIN_USER="alice"
    ADMIN_PUBKEY="ssh-ed25519 AAAA test@example"
    DEPLOY_MODE="tunnel"
    DOMAIN="server.example.com"
    SWAP_SIZE="2G"
    SERVER_TIMEZONE="UTC"
    TAILSCALE_AUTH_KEY="tskey-auth-test"
    TAILSCALE_DIRECT_WAN="false"
    REMOTE_DEPLOY_ENV_PATH="/root/deploy.env"
    pin_marker="${tmpdir}/pin-called"
    pin_known_host_alias() {
      [[ "$1" == "203.0.113.10" ]]
      [[ "$2" == "100.64.0.10" ]]
      : > "${pin_marker}"
    }
    bootstrap_counter="${tmpdir}/bootstrap-count"
    echo 0 > "${bootstrap_counter}"
    scp_root() { return 0; }
    ssh_admin() { return 1; }
    ssh_root() {
      if [[ "$1" == *"mktemp -d -p /run/secure-ubuntu-paas/deploy-trees"* ]]; then
        echo "/run/secure-ubuntu-paas/deploy-trees/deploy-tree.TEST"
        return 0
      fi
      if [[ "$1" == "true" || "$1" == chmod\ +x\ /root/* || "$1" == "chmod 600 /root/deploy.env" ]]; then
        return 0
      fi
      if [[ "$1" == *"/root/base/bootstrap.sh --env-file "* ]] && [[ "$1" == *"--install-tailscale --force"* ]]; then
        count="$(cat "${bootstrap_counter}")"
        count=$((count + 1))
        echo "${count}" > "${bootstrap_counter}"
        if (( count == 1 )); then
          [[ "${ROOT_SSH_HOST}" == "203.0.113.10" ]]
          echo "HARDEN_RESULT_TAILSCALE_IP=100.64.0.10"
          return 255
        fi
        [[ "${ROOT_SSH_HOST}" == "100.64.0.10" ]]
        [[ -e "${pin_marker}" ]]
        echo "HARDEN_RESULT_TAILSCALE_IP=100.64.0.10"
        return 0
      fi
      return 0
    }
    run_with_heartbeat() { local label="$1"; shift; "$@"; }
    sleep() { :; }
    phase1_upload_harden
    [[ "${TS_IP}" == "100.64.0.10" ]]
    [[ "${ROOT_SSH_HOST}" == "100.64.0.10" ]]
    [[ -e "${pin_marker}" ]]
    [[ "$(cat "${bootstrap_counter}")" -eq 2 ]]
  '
  assert_success
}

@test "phase1_upload_harden: promotes retries to admin sudo when root transport is no longer valid" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    tmpdir="$(mktemp -d)"
    trap "rm -rf \"${tmpdir}\"" EXIT
    SCRIPT_DIR="${tmpdir}"
    mkdir -p "${tmpdir}/base" "${tmpdir}/overlays/coolify"
    for script in base/bootstrap.sh base/validate.sh overlays/coolify/configure_coolify_binding.sh; do
      : > "${tmpdir}/${script}"
    done
    mkdir -p "${tmpdir}/lib"
    : > "${tmpdir}/lib/tailscale.sh"
    : > "${tmpdir}/lib/common.sh"
    SERVER_IP="203.0.113.10"
    ROOT_SSH_HOST="${SERVER_IP}"
    ADMIN_USER="alice"
    ADMIN_PUBKEY="ssh-ed25519 AAAA test@example"
    PRIVATE_KEY="${tmpdir}/id_ed25519"
    : > "${PRIVATE_KEY}"
    TS_IP="100.64.0.10"
    DEPLOY_MODE="tunnel"
    DOMAIN="server.example.com"
    SWAP_SIZE="2G"
    SERVER_TIMEZONE="UTC"
    TAILSCALE_AUTH_KEY="tskey-auth-test"
    TAILSCALE_DIRECT_WAN="false"
    REMOTE_DEPLOY_ENV_PATH="/root/deploy.env"
    pin_known_host_alias() { :; }
    bootstrap_counter="${tmpdir}/bootstrap-count"
    admin_counter="${tmpdir}/admin-bootstrap-count"
    echo 0 > "${bootstrap_counter}"
    echo 0 > "${admin_counter}"
    scp_root() { return 0; }
    ssh_root() {
      if [[ "$1" == *"mktemp -d -p /run/secure-ubuntu-paas/deploy-trees"* ]]; then
        echo "/run/secure-ubuntu-paas/deploy-trees/deploy-tree.TEST"
        return 0
      fi
      if [[ "$1" == "true" || "$1" == chmod\ +x\ /root/* || "$1" == "chmod 600 /root/deploy.env" ]]; then
        return 0
      fi
      if [[ "$1" == *"/root/base/bootstrap.sh --env-file "* ]] && [[ "$1" == *"--install-tailscale --force"* ]]; then
        count="$(cat "${bootstrap_counter}")"
        count=$((count + 1))
        echo "${count}" > "${bootstrap_counter}"
        if (( count == 1 )); then
          echo "HARDEN_RESULT_TAILSCALE_IP=100.64.0.10"
          return 255
        fi
        echo "root transport should not be reused after admin promotion" >&2
        return 99
      fi
      return 0
    }
    ssh_admin() {
      if [[ "$1" == "echo ok" ]]; then
        return 0
      fi
      return 1
    }
    ssh_admin_sudo() {
      if [[ "$1" == *"/root/base/bootstrap.sh --env-file "* ]] && [[ "$1" == *"--install-tailscale --force"* ]]; then
        count="$(cat "${admin_counter}")"
        count=$((count + 1))
        echo "${count}" > "${admin_counter}"
        echo "HARDEN_RESULT_TAILSCALE_IP=100.64.0.10"
        return 0
      fi
      return 0
    }
    run_with_heartbeat() { local label="$1"; shift; "$@"; }
    sleep() { :; }
    phase1_upload_harden
    [[ "${TS_IP}" == "100.64.0.10" ]]
    [[ "$(cat "${bootstrap_counter}")" -eq 1 ]]
    [[ "$(cat "${admin_counter}")" -eq 1 ]]
  '
  assert_success
  assert_output --partial "switching bootstrap retries to alice@100.64.0.10 via sudo"
}

@test "phase1_upload_harden: uploads DOMAIN in bootstrap env file" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    tmpdir="$(mktemp -d)"
    trap "rm -rf \"${tmpdir}\"" EXIT
    SCRIPT_DIR="${tmpdir}"
    mkdir -p "${tmpdir}/base" "${tmpdir}/overlays/coolify"
    for script in base/bootstrap.sh base/validate.sh overlays/coolify/configure_coolify_binding.sh; do
      : > "${tmpdir}/${script}"
    done
    mkdir -p "${tmpdir}/lib"
    : > "${tmpdir}/lib/tailscale.sh"
    : > "${tmpdir}/lib/common.sh"
    captured_env="${tmpdir}/deploy.env.captured"
    SERVER_IP="203.0.113.10"
    ADMIN_USER="alice"
    ADMIN_PUBKEY="ssh-ed25519 AAAA test@example"
    DOMAIN="vps.example.com"
    DEPLOY_MODE="tunnel"
    SWAP_SIZE="2G"
    SERVER_TIMEZONE="UTC"
    TAILSCALE_AUTH_KEY="tskey-auth-test"
    TAILSCALE_DIRECT_WAN="false"
    REMOTE_DEPLOY_ENV_PATH="/root/deploy.env"
    pin_known_host_alias() { :; }
    scp_root() {
      if [[ "${2:-}" == "root@203.0.113.10:/root/deploy.env" ]]; then
        cp "${1}" "${captured_env}"
      fi
      return 0
    }
    ssh_root() {
      if [[ "$1" == *"mktemp -d -p /run/secure-ubuntu-paas/deploy-trees"* ]]; then
        echo "/run/secure-ubuntu-paas/deploy-trees/deploy-tree.TEST"
        return 0
      fi
      if [[ "$1" == *"/root/base/bootstrap.sh --env-file "* ]] && [[ "$1" == *"--install-tailscale --force"* ]]; then
        echo "HARDEN_RESULT_TAILSCALE_IP=100.64.0.10"
      fi
      return 0
    }
    run_with_heartbeat() { local label="$1"; shift; "$@"; }
    phase1_upload_harden
    grep -q "^DOMAIN=\\\"vps.example.com\\\"$" "${captured_env}"
  '
  assert_success
}

@test "phase3_docker_coolify (deploy): executes docker/coolify reconcile flow" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    gate_calls=0
    ssh_admin_sudo() {
      if [[ "$1" == *"bash -s"* ]]; then
        cat >/dev/null || true
      fi
      case "$1" in
        "docker version >/dev/null 2>&1") return 0 ;;
        *"/data/coolify/source/.env"*) return 0 ;;
        *) return 0 ;;
      esac
    }
    verify_docker_user_gate_remote() { gate_calls=$((gate_calls + 1)); }
    reconcile_docker_daemon_remote() { :; }
    coolify_add_coolify_root_key_script() { echo true; }
    coolify_fix_host_docker_internal_script() { echo true; }
    phase3_docker_coolify
    [[ "${gate_calls}" -ge 2 ]]
  '
  assert_success
}

@test "verify_docker_user_gate_remote: retries transient SSH after Docker reconciliation" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    attempts_file="$(mktemp)"
    trap "rm -f \"${attempts_file}\"" EXIT
    printf "%s\n" 0 > "${attempts_file}"
    ssh_admin_sudo() {
      attempts="$(cat "${attempts_file}")"
      attempts=$((attempts + 1))
      printf "%s\n" "${attempts}" > "${attempts_file}"
      if (( attempts == 1 || attempts == 3 )); then
        return 255
      fi
      return 0
    }
    sleep() { :; }

    verify_docker_user_gate_remote "Gate D (post-Dokploy)"
    [[ "$(cat "${attempts_file}")" -eq 4 ]]
  '
  assert_success
  assert_output --partial "SSH transport unavailable while checking docker-user-hardening.service"
  assert_output --partial "SSH transport unavailable while checking DOCKER-USER rules"
  assert_output --partial "Gate D (post-Dokploy): DOCKER-USER hardening rules active"
}

@test "verify_docker_user_gate_remote: retries transient firewall convergence" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    attempts_file="$(mktemp)"
    trap "rm -f \"${attempts_file}\"" EXIT
    printf "%s\n" 0 > "${attempts_file}"
    ssh_admin_sudo() {
      attempts="$(cat "${attempts_file}")"
      attempts=$((attempts + 1))
      printf "%s\n" "${attempts}" > "${attempts_file}"
      # Service check succeeds immediately; the first two policy reads land
      # during the managed chain rebuild and then converge.
      if (( attempts == 2 || attempts == 3 )); then
        return 1
      fi
      return 0
    }
    sleep() { :; }

    verify_docker_user_gate_remote "Gate D (post-Dokploy)"
    [[ "$(cat "${attempts_file}")" -eq 4 ]]
  '
  assert_success
  assert_output --partial "DOCKER-USER policy has not converged yet"
  assert_output --partial "Gate D (post-Dokploy): DOCKER-USER hardening rules active"
}

@test "phase3_docker_dokploy (deploy): executes docker/dokploy reconcile flow" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    PAAS="dokploy"
    ADMIN_PUBKEY='"'"'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyData test@example.com'"'"'
    calls_file="$(mktemp)"
    ssh_admin_sudo() {
      if [[ "$1" == "docker version >/dev/null 2>&1" ]]; then return 0; fi
      if [[ "$1" == "docker service inspect dokploy >/dev/null 2>&1" ]]; then return 1; fi
      if [[ "$1" == "bash -s" ]]; then cat >/dev/null || true; echo installer >> "${calls_file}"; return 0; fi
      if [[ "$1" == "set -Eeuo pipefail; handoff="* ]]; then echo "SWMKEY-test"; return 0; fi
      return 0
    }
    store_dokploy_swarm_unlock_key() { [[ "$1" == "SWMKEY-test" ]]; }
    verify_docker_user_gate_remote() { echo "gate:$1" >> "${calls_file}"; }
    reconcile_docker_daemon_remote() { :; }
    run_with_heartbeat() { local label="$1"; shift; "$@"; }
    phase3_docker_dokploy
    grep -q "^gate:Gate D$" "${calls_file}"
    grep -q "^gate:Gate D (post-Dokploy)$" "${calls_file}"
    grep -q "^installer$" "${calls_file}"
  '
  assert_success
}

@test "phase4_dokploy_access_policy (deploy): restricts dashboard and swarm ports to tailscale0" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    PAAS="dokploy"
    ssh_admin_sudo() { if [[ "$1" == "bash -s" ]]; then cat; else printf "%s\n" "$1"; fi; }
    phase4_dokploy_access_policy
  '
  assert_success
  assert_output --partial "ufw delete allow 3000/tcp"
  assert_output --partial "ufw allow in on tailscale0 proto tcp to any port 3000"
  assert_output --partial "ufw deny 3000/tcp"
  assert_output --partial "ufw delete allow in on tailscale0 proto tcp to any port 2377"
  assert_output --partial "ufw deny 2377/tcp"
  assert_output --partial "ufw delete allow in on tailscale0 proto udp to any port 4789"
  assert_output --partial "ufw deny 4789/udp"
}

@test "collect_inputs (setup): populates shared fields via common collector" {
  run bash -c '
    source "'"${SETUP_SCRIPT}"'"
    collect_common_inputs() {
      SERVER_IP="203.0.113.10"
      ADMIN_USER="alice"
      PUBKEY_FILE="/tmp/id.pub"
      TAILSCALE_AUTH_KEY="tskey-auth-x"
      DEPLOY_MODE="tunnel"
      DOMAIN="vps.example.com"
      CF_API_TOKEN="token"
      SWAP_SIZE="2G"
      SERVER_TIMEZONE="UTC"
      APP_DOMAIN_MODE="apex"
    }
    collect_inputs
    [[ "${SERVER_IP}" == "203.0.113.10" ]]
    [[ "${ADMIN_USER}" == "alice" ]]
  '
  assert_success
}

@test "reconcile_docker_daemon_local: runs generated script locally" {
  run bash -c '
    source "'"${SETUP_SCRIPT}"'"
    coolify_reconcile_docker_daemon_script() { echo "echo reconcile"; }
    reconcile_docker_daemon_local
  '
  assert_success
}

@test "phase1_harden (setup): writes DOMAIN into bootstrap env file" {
  run bash -c '
    source "'"${SETUP_SCRIPT}"'"
    tmpdir="$(mktemp -d)"
    trap "rm -rf \"${tmpdir}\"" EXIT
    SCRIPT_DIR="${tmpdir}"
    DEPLOY_ENV_FILE="${tmpdir}/deploy.env"
    captured_env="${tmpdir}/captured.env"
    SERVER_IP="203.0.113.10"
    ADMIN_USER="coolifyadmin"
    ADMIN_PUBKEY="ssh-ed25519 AAAATEST key"
    DOMAIN="vps.example.com"
    TAILSCALE_AUTH_KEY="tskey-auth-test"
    DEPLOY_MODE="tunnel"
    SWAP_SIZE="2G"
    SERVER_TIMEZONE="UTC"
    TAILSCALE_DIRECT_WAN="false"

    mkdir -p "${tmpdir}/base"
    cat > "${tmpdir}/base/bootstrap.sh" <<EOF
#!/usr/bin/env bash
cp "\$2" "${captured_env}"
echo "bootstrap stub"
EOF
    chmod +x "${tmpdir}/base/bootstrap.sh"

    tailscale() { echo "100.64.0.44"; }

    phase1_harden
    grep -q "^DOMAIN=\"vps.example.com\"$" "${captured_env}"
  '
  assert_success
}

@test "phase3_docker_coolify (setup): executes local docker/coolify reconcile flow" {
  run bash -c '
    source "'"${SETUP_SCRIPT}"'"
    gate_calls=0
    docker() {
      [[ "$1" == "version" ]] && return 0
      return 0
    }
    systemctl() { return 0; }
    verify_docker_user_gate_local() { gate_calls=$((gate_calls + 1)); }
    reconcile_docker_daemon_local() { :; }
    coolify_install_coolify_script() { echo true; }
    coolify_add_coolify_root_key_script() { echo true; }
    coolify_fix_host_docker_internal_script() { echo true; }
    phase3_docker_coolify
    [[ "${gate_calls}" -ge 2 ]]
  '
  assert_success
}

@test "phase3_docker_dokploy (setup): executes local docker/dokploy reconcile flow" {
  run bash -c '
    source "'"${SETUP_SCRIPT}"'"
    PAAS="dokploy"
    ADMIN_PUBKEY='"'"'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyData test@example.com'"'"'
    calls_file="$(mktemp)"
    docker() {
      if [[ "$1" == "version" ]]; then return 0; fi
      if [[ "$1 $2" == "service inspect" ]]; then return 1; fi
      return 0
    }
    systemctl() { return 0; }
    verify_docker_user_gate_local() { echo "gate:$1" >> "${calls_file}"; }
    bash() { cat >/dev/null || true; echo installer >> "${calls_file}"; }
    run_with_heartbeat() { local label="$1"; shift; "$@"; }
    phase3_docker_dokploy
    grep -q "^gate:Gate D$" "${calls_file}"
    grep -q "^gate:Gate D (post-Dokploy)$" "${calls_file}"
    grep -q "^installer$" "${calls_file}"
  '
  assert_success
}

@test "phase4_dokploy_access_policy (setup): restricts dashboard and swarm ports to tailscale0" {
  run bash -c '
    source "'"${SETUP_SCRIPT}"'"
    PAAS="dokploy"
    bash() { if [[ "$1" == "-s" ]]; then cat; else printf "%s\n" "$*"; fi; }
    phase4_dokploy_access_policy
  '
  assert_success
  assert_output --partial "ufw delete allow 3000/tcp"
  assert_output --partial "ufw allow in on tailscale0 proto tcp to any port 3000"
  assert_output --partial "ufw deny 3000/tcp"
  assert_output --partial "ufw delete allow in on tailscale0 proto tcp to any port 2377"
  assert_output --partial "ufw deny 2377/tcp"
  assert_output --partial "ufw delete allow in on tailscale0 proto udp to any port 4789"
  assert_output --partial "ufw deny 4789/udp"
}

@test "main (deploy): executes all deployment phases in order with stubs" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    parse_args() { :; }
    init_root_password_auth() { :; }
    collect_inputs() { :; }
    validate_inputs() { :; }
    confirm() { :; }
    preflight() { echo preflight; }
    phase1_upload_harden() { echo phase1; }
    phase2_gates() { echo phase2; }
    phase3_docker_coolify() { echo phase3; }
    reconcile_docker_audit_runtime_remote() { echo audit; }
    phase4_binding_dns() { echo phase4; }
    phase5_verify() { echo phase5; }
    main
  '
  assert_success
  assert_output --partial "phase5"
}

@test "pause_for_operator (setup): displays prompt and accepts enter" {
  run bash -c '
    source "'"${SETUP_SCRIPT}"'"
    printf "\n" | pause_for_operator "check gate"
  '
  assert_success
  assert_output --partial "check gate"
}

@test "pause_for_operator (setup): AUTO_YES=true fails with operator guidance" {
  run bash -c '
    source "'"${SETUP_SCRIPT}"'"
    AUTO_YES="true"
    pause_for_operator "check gate"
  '
  assert_failure
  assert_output --partial "Operator confirmation required"
  assert_output --partial "use deploy.sh"
}

@test "main (setup): executes setup phases with stubbed actions" {
  run bash -c '
    source "'"${SETUP_SCRIPT}"'"
    parse_args() { :; }
    collect_inputs() { :; }
    validate_inputs() { :; }
    confirm() { :; }
    preflight() { echo preflight; }
    phase1_harden() { echo phase1; }
    phase2_gates() { echo phase2; }
    phase3_docker_coolify() { echo phase3; }
    phase4_binding_dns() { echo phase4; }
    phase5_verify() { echo phase5; }
    main
  '
  assert_success
  assert_output --partial "phase5"
}

@test "overlay_topo_sort: returns single overlay with no deps" {
  tmpdir="$(mktemp -d)"
  mkdir -p "${tmpdir}/overlays/base"
  printf 'version: 1\ndepends_on: []\n' > "${tmpdir}/overlays/base/overlay.yaml"
  source_deploy_script
  SCRIPT_DIR="${tmpdir}"
  run overlay_topo_sort base
  assert_success
  assert_output --partial "base"
}

@test "overlay_topo_sort: detects dependency cycle" {
  tmpdir="$(mktemp -d)"
  mkdir -p "${tmpdir}/overlays/a" "${tmpdir}/overlays/b"
  printf 'version: 1\ndepends_on: [b]\n' > "${tmpdir}/overlays/a/overlay.yaml"
  printf 'version: 1\ndepends_on: [a]\n' > "${tmpdir}/overlays/b/overlay.yaml"
  source_deploy_script
  SCRIPT_DIR="${tmpdir}"
  run overlay_topo_sort a
  assert_failure
  assert_output --partial "cycle detected"
}

@test "overlay_topo_sort: respects dependency order" {
  tmpdir="$(mktemp -d)"
  mkdir -p "${tmpdir}/overlays/base" "${tmpdir}/overlays/app"
  printf 'version: 1\ndepends_on: []\n' > "${tmpdir}/overlays/base/overlay.yaml"
  printf 'version: 1\ndepends_on: [base]\n' > "${tmpdir}/overlays/app/overlay.yaml"
  source_deploy_script
  SCRIPT_DIR="${tmpdir}"
  run overlay_topo_sort app
  assert_success
  # base must appear before app in topo-sorted output
  result="$output"
  [[ "${result%%app*}" == *"base"* ]]
}

@test "paas_phase3_dispatch (deploy): calls overlay_topo_sort then coolify shared" {
  tmpdir="$(mktemp -d)"
  mkdir -p "${tmpdir}/overlays/coolify"
  cp "${PROJECT_ROOT}/overlays/coolify/overlay.yaml" "${tmpdir}/overlays/coolify/overlay.yaml"
  mkdir -p "${tmpdir}/overlays/docker-host"
  cp "${PROJECT_ROOT}/overlays/docker-host/overlay.yaml" "${tmpdir}/overlays/docker-host/overlay.yaml"
  source_deploy_script
  coolify_phase3_docker_coolify_shared() { echo "dispatched3:$*"; }
  SCRIPT_DIR="${tmpdir}"
  PAAS=coolify
  run paas_phase3_dispatch arg1 arg2
  assert_success
  assert_output --partial "dispatched3:arg1 arg2"
}

@test "paas_phase4_dispatch (deploy): delegates to coolify shared" {
  source_deploy_script
  coolify_phase4_binding_dns_shared() { echo "dispatched4:$*"; }
  run paas_phase4_dispatch myarg
  assert_success
  assert_output --partial "dispatched4:myarg"
}

@test "paas_phase5_dispatch (deploy): delegates to coolify shared" {
  source_deploy_script
  coolify_phase5_verify_shared() { echo "dispatched5:$*"; }
  run paas_phase5_dispatch verifyarg
  assert_success
  assert_output --partial "dispatched5:verifyarg"
}

@test "paas_phase3_dispatch (setup): calls overlay_topo_sort then coolify shared" {
  tmpdir="$(mktemp -d)"
  mkdir -p "${tmpdir}/overlays/coolify"
  cp "${PROJECT_ROOT}/overlays/coolify/overlay.yaml" "${tmpdir}/overlays/coolify/overlay.yaml"
  mkdir -p "${tmpdir}/overlays/docker-host"
  cp "${PROJECT_ROOT}/overlays/docker-host/overlay.yaml" "${tmpdir}/overlays/docker-host/overlay.yaml"
  source_setup_script
  coolify_phase3_docker_coolify_shared() { echo "sdispatched3:$*"; }
  SCRIPT_DIR="${tmpdir}"
  PAAS=coolify
  run paas_phase3_dispatch sarg1
  assert_success
  assert_output --partial "sdispatched3:sarg1"
}

@test "paas_phase4_dispatch (setup): delegates to coolify shared" {
  source_setup_script
  coolify_phase4_binding_dns_shared() { echo "sdispatched4:$*"; }
  run paas_phase4_dispatch sarg
  assert_success
  assert_output --partial "sdispatched4:sarg"
}

@test "paas_phase5_dispatch (setup): delegates to coolify shared" {
  source_setup_script
  coolify_phase5_verify_shared() { echo "sdispatched5:$*"; }
  run paas_phase5_dispatch sarg5
  assert_success
  assert_output --partial "sdispatched5:sarg5"
}

@test "package_deployment_tree (deploy): creates a tarball from base lib overlays" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    SCRIPT_DIR="'"${PROJECT_ROOT}"'"
    dest="$(mktemp -t deploy-tree.XXXXXXXX.tar.gz)"
    package_deployment_tree "${dest}"
    [[ -s "${dest}" ]]
    rm -f "${dest}"
  '
  assert_success
}

@test "package_deployment_tree (deploy): suppresses extended attributes when tar supports it" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    tmpdir="$(mktemp -d)"
    trap "rm -rf \"${tmpdir}\"" EXIT
    SCRIPT_DIR="${tmpdir}"
    mkdir -p "${tmpdir}/base" "${tmpdir}/lib" "${tmpdir}/overlays"
    args_file="${tmpdir}/tar-args"
    tar() {
      printf "%s\n" "$*" >> "${args_file}"
      return 0
    }
    package_deployment_tree "${tmpdir}/tree.tar.gz"
    [[ "$(sed -n "2p" "${args_file}")" == *"--no-xattrs"* ]]
  '
  assert_success
}

@test "install_deployment_tree_remote_script (deploy): emits a tar extraction script" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    tmpout="$(mktemp)"
    install_deployment_tree_remote_script > "${tmpout}"
    grep -q "tar" "${tmpout}"
    grep -q "chown -R root:root" "${tmpout}"
    rm -f "${tmpout}"
  '
  assert_success
}

@test "run_remote_script_via_admin (deploy): pipes script to ssh_admin_sudo" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    received=""
    ssh_admin_sudo() { if [[ "$1" == "bash -s" ]]; then received="$(cat)"; fi; }
    myscript() { echo "hello-from-script"; }
    run_remote_script_via_admin "test-label" myscript
    [[ "${received}" == *"hello-from-script"* ]]
  '
  assert_success
}

@test "run_remote_script_via_admin (deploy): retries transient SSH after network reconcile" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    tmpdir="$(mktemp -d)"
    trap "rm -rf \"${tmpdir}\"" EXIT
    attempts="${tmpdir}/attempts"
    received="${tmpdir}/received"
    echo 0 > "${attempts}"
    ssh_admin_sudo() {
      cat >> "${received}"
      count="$(cat "${attempts}")"
      count=$((count + 1))
      echo "${count}" > "${attempts}"
      if (( count == 1 )); then return 255; fi
      return 0
    }
    myscript() { echo "hello-after-network-reconcile"; }
    sleep() { :; }

    run_remote_script_via_admin "test-label" myscript
    [[ "$(cat "${attempts}")" -eq 2 ]]
    [[ "$(grep -c "hello-after-network-reconcile" "${received}")" -eq 2 ]]
  '
  assert_success
  assert_output --partial "SSH transport unavailable after network reconciliation"
}

@test "fetch_phase1_state_line_remote (deploy): attempts remote state read via SSH" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    SSH_OPTS=(-o ConnectTimeout=1 -o StrictHostKeyChecking=no)
    PRIVATE_KEY="/nonexistent"
    ADMIN_USER="nobody"
    TS_IP="192.0.2.1"
    fetch_phase1_state_line_remote >/dev/null 2>&1 || true
  '
  assert_success
}

@test "remote_tree_dir_create: requests a protected root deployment staging directory" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    ssh_admin_sudo() { [[ "$1" == *"deploy-trees"* && "$1" == *"mktemp -d"* ]]; }
    remote_tree_dir_create >/dev/null
  '
  assert_success
}

@test "remote_tree_cleanup: only cleans a protected deployment staging directory" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    cleanup_target=""
    ssh_admin_sudo() { cleanup_target="$1"; return 0; }
    remote_tree_cleanup "/run/secure-ubuntu-paas/deploy-trees/deploy-tree.TEST"
    [[ "${cleanup_target}" == *"deploy-tree.TEST"* ]]
  '
  assert_success
}

@test "file_sha256: fingerprints deployment archives with an available SHA-256 tool" {
  run bash -c '
    source "'"${DEPLOY_SCRIPT}"'"
    sample="$(mktemp)"
    printf test > "${sample}"
    digest_file="$(mktemp)"
    file_sha256 "${sample}" > "${digest_file}"
    digest="$(<"${digest_file}")"
    [[ "${digest}" =~ ^[0-9a-f]{64}$ ]]
    rm -f "${sample}" "${digest_file}"
  '
  assert_success
}
