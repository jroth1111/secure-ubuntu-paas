#!/usr/bin/env bats

load '../../../helpers/helpers'

setup() {
  source "${PROJECT_ROOT}/overlays/dokploy/dokploy-common.sh"
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
  assert_output --partial 'curl -fsSL "${installer_url}" -o "${tmp}"'
  assert_output --partial 'head -1 "${tmp}" | grep -Eq'
  assert_output --partial 'timeout --signal=TERM --kill-after=60 1800 bash "${tmp}"'
}

@test "dokploy_finalize_runtime_script: removes live-restore, unlocks swarm, and installs traefik" {
  run dokploy_finalize_runtime_script

  assert_success
  assert_output --partial 'del(.["live-restore"])'
  assert_output --partial 'docker-swarm-unlock.service'
  assert_output --partial 'docker container prune -f'
  assert_output --partial 'dokploy-traefik'
}

@test "dokploy_finalize_runtime_script: unlock unit uses helper script and re-fires on docker restarts" {
  run dokploy_finalize_runtime_script

  assert_success
  assert_output --partial 'PartOf=docker.service'
  assert_output --partial 'WantedBy=multi-user.target docker.service'
  assert_output --partial 'ExecStart=/usr/local/sbin/docker-swarm-unlock.sh'
  # systemd expands ${...} inside ExecStart — inline shell variables there are a bug
  refute_output --partial "ExecStart=/bin/bash -c 'state="
}

@test "dokploy_finalize_runtime_script: disables insecure Traefik API and tightens /etc/dokploy" {
  run dokploy_finalize_runtime_script

  assert_success
  assert_output --partial 'insecure: false'
  assert_output --partial 'chmod 755 /etc/dokploy'
}

@test "dokploy_dashboard_ufw_policy_script: locks dashboard and swarm ports to tailscale0" {
  run dokploy_dashboard_ufw_policy_script

  assert_success
  assert_output --partial 'port 3000 comment "dokploy-dashboard-tailscale"'
  assert_output --partial 'ufw deny 3000/tcp'
  assert_output --partial 'port 2377 comment "docker-swarm-mgmt-tailscale"'
  assert_output --partial 'ufw deny 2377/tcp'
  assert_output --partial 'port 7946 comment "docker-swarm-gossip-tailscale"'
  assert_output --partial 'port 7946 comment "docker-swarm-gossip-udp-tailscale"'
  assert_output --partial 'ufw deny 7946/udp'
  assert_output --partial 'port 4789 comment "docker-swarm-vxlan-tailscale"'
  assert_output --partial 'ufw deny 4789/udp'
}

@test "dokploy_remove_stale_coolify_dashboard_ufw_script: deletes coolify dashboard rules" {
  run dokploy_remove_stale_coolify_dashboard_ufw_script

  assert_success
  assert_output --partial 'coolify-hardening-(dashboard|soketi|terminal)'
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
