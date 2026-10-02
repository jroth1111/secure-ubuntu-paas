#!/usr/bin/env bats

load '../../../helpers/helpers'

setup() {
  source "${PROJECT_ROOT}/overlays/dokploy/dokploy-common.sh"
  ADMIN_PUBKEY='ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyData operator@test'
  DOKPLOY_ENROLLMENT_SOURCE_IP=100.74.193.51
}

@test "finalize_dokploy_inputs: forces direct public app ingress mode" {
  DEPLOY_MODE="tunnel"
  APP_DOMAIN_MODE="apex"
  PRIVATE_TLS_CA="letsencrypt"

  finalize_dokploy_inputs

  [ "${DEPLOY_MODE}" = "standard" ]
  [ -z "${APP_DOMAIN_MODE}" ]
  [ -z "${PRIVATE_TLS_CA}" ]
}

@test "dokploy_install_dokploy_script: downloads, validates, and executes official installer" {
  run dokploy_install_dokploy_script

  assert_success
  assert_output --partial 'installer_url="https://dokploy.com/install.sh"'
  assert_output --partial 'export DOKPLOY_VERSION="latest"'
  assert_output --partial "curl --proto '=https'"
  assert_output --partial '"${installer_url}" -o "${tmp}"'
  assert_output --partial 'head -1 "${tmp}" | grep -Eq'
  assert_output --partial 'run_installer_redacted timeout --signal=TERM --kill-after=60 1800 bash "${tmp}"'
}

@test "dokploy_reconcile_docker_daemon_script: is Swarm-safe and removes live-restore" {
  run dokploy_reconcile_docker_daemon_script

  assert_success
  assert_output --partial 'del(.["live-restore"])'
  assert_output --partial 'json-file'
  refute_output --partial '"live-restore":true'
}

@test "dokploy_finalize_runtime_script: removes live-restore, hands off swarm key, and installs traefik" {
  run dokploy_finalize_runtime_script

  assert_success
  assert_output --partial 'del(.["live-restore"])'
  assert_output --partial 'docker swarm unlock-key -q'
  assert_output --partial 'swarm_unlock_handoff="/run/secure-ubuntu-paas-dokploy-swarm-unlock-key"'
  assert_output --partial 'rm -f -- /etc/systemd/system/docker-swarm-unlock.service'
  assert_output --partial 'docker container prune -f'
  assert_output --partial 'dokploy-traefik'
}

@test "dokploy_finalize_runtime_script: never installs a same-host swarm unlock mechanism" {
  run dokploy_finalize_runtime_script

  assert_success
  refute_output --partial 'WantedBy=multi-user.target docker.service'
  refute_output --partial 'ExecStart=/usr/local/sbin/docker-swarm-unlock.sh'
  refute_output --partial 'docker swarm unlock <'
}

@test "dokploy_finalize_runtime_script: disables insecure Traefik API and tightens /etc/dokploy" {
  run dokploy_finalize_runtime_script

  assert_success
  assert_output --partial 'insecure: false'
  assert_output --partial 'chmod 0755 /etc/dokploy'
  assert_output --partial 'cp -R --no-preserve=mode,ownership "${dokploy_root}/." "${dokploy_stage}/"'
  assert_output --partial 'chmod 600 "${dokploy_entry}"'
  assert_output --partial 'block_tmp="$(mktemp "/etc/dokploy/traefik/dynamic/.zz-hardening-dashboard-block.XXXXXX")"'
  assert_output --partial 'chown root:root "${block_tmp}"'
  assert_output --partial 'mv -f -- "${block_tmp}" "${block_file}"'
}

@test "dokploy_dashboard_ufw_policy_script: locks dashboard and swarm ports to tailscale0" {
  run dokploy_dashboard_ufw_policy_script

  assert_success
  assert_output --partial 'port 3000 comment "dokploy-dashboard-tailscale"'
  assert_output --partial 'ufw deny 3000/tcp'
  refute_output --partial 'ufw allow in on tailscale0 proto tcp to any port 2377'
  assert_output --partial 'ufw deny 2377/tcp'
  refute_output --partial 'ufw allow in on tailscale0 proto tcp to any port 7946'
  assert_output --partial 'ufw deny 7946/udp'
  refute_output --partial 'ufw allow in on tailscale0 proto udp to any port 4789'
  assert_output --partial 'ufw deny 4789/udp'
}

@test "dokploy_remove_stale_coolify_dashboard_ufw_script: deletes coolify dashboard rules" {
  run dokploy_remove_stale_coolify_dashboard_ufw_script

  assert_success
  assert_output --partial 'coolify-hardening-(dashboard|soketi|terminal)'
}

@test "dokploy_root_tailscale_reconcile_script: enforces root-only SSH on resume" {
  ADMIN_USER="dokployadmin"
  ADMIN_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyData operator@test"

  run dokploy_root_tailscale_reconcile_script

  assert_success
  assert_output --partial 'usermod -s /usr/sbin/nologin "$admin_user"'
  assert_output --partial 'passwd -l "$admin_user"'
  assert_output --partial 'rm -f -- "$admin_auth"'
  assert_output --partial 'print "AllowUsers root"'
  assert_output --partial 'grep -qE '\''^allowusers .*\broot\b'\'' <<< "$effective_global"'
  assert_output --partial '! grep -qE "^allowusers .*\\b$admin_user\\b" <<< "$effective_global"'
  assert_output --partial 'Match Address $tailscale_cidr'
  assert_output --partial '    AllowUsers root'
}

@test "dokploy_phase3_install_shared: installs Dokploy when service is missing" {
  calls_file="$(mktemp)"

  has_docker() { return 0; }
  install_docker() { echo install_docker >> "${calls_file}"; }
  start_docker_user() { echo start_docker_user >> "${calls_file}"; }
  verify_docker_user() { echo "verify:$1" >> "${calls_file}"; }
  has_dokploy() { return 1; }
  install_dokploy() { echo install_dokploy >> "${calls_file}"; }
  reconcile_docker_daemon() { echo reconcile_docker_daemon >> "${calls_file}"; }
  restart_docker_user() { echo restart_docker_user >> "${calls_file}"; }
  sync_docker_ssh_cidrs() { echo sync_docker_ssh_cidrs >> "${calls_file}"; }
  sleep() { :; }

  run dokploy_phase3_install_shared \
    has_docker install_docker start_docker_user verify_docker_user \
    has_dokploy install_dokploy reconcile_docker_daemon restart_docker_user \
    sync_docker_ssh_cidrs

  assert_success
  grep -q '^install_dokploy$' "${calls_file}"
  grep -q '^verify:Gate D$' "${calls_file}"
  grep -q '^verify:Gate D (post-Dokploy)$' "${calls_file}"
}

@test "dokploy_phase3_install_shared: finalizes an existing Dokploy service" {
  calls_file="$(mktemp)"

  has_docker() { return 0; }
  install_docker() { echo install_docker >> "${calls_file}"; }
  start_docker_user() { echo start_docker_user >> "${calls_file}"; }
  verify_docker_user() { echo "verify:$1" >> "${calls_file}"; }
  has_dokploy() { return 0; }
  install_dokploy() { echo unexpected_install_dokploy >> "${calls_file}"; }
  reconcile_docker_daemon() { echo reconcile_docker_daemon >> "${calls_file}"; }
  restart_docker_user() { echo restart_docker_user >> "${calls_file}"; }
  finalize_dokploy() { echo finalize_dokploy >> "${calls_file}"; }
  sleep() { :; }

  run dokploy_phase3_install_shared \
    has_docker install_docker start_docker_user verify_docker_user \
    has_dokploy install_dokploy reconcile_docker_daemon restart_docker_user \
    "" finalize_dokploy

  assert_success
  grep -q '^finalize_dokploy$' "${calls_file}"
  ! grep -q '^unexpected_install_dokploy$' "${calls_file}"
}
