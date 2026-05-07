#!/usr/bin/env bats
# Verifies that --paas dflow routes phase3/4/5 dispatch to dFlow shared
# functions in both deploy.sh and setup.sh.

load '../../../helpers/helpers'

setup() {
  tmpdir="$(mktemp -d)"
  mkdir -p "${tmpdir}/overlays/dflow"
  cp "${PROJECT_ROOT}/overlays/dflow/overlay.yaml" "${tmpdir}/overlays/dflow/overlay.yaml"
  mkdir -p "${tmpdir}/overlays/docker-host"
  cp "${PROJECT_ROOT}/overlays/docker-host/overlay.yaml" "${tmpdir}/overlays/docker-host/overlay.yaml"
}

teardown() {
  [[ -n "${tmpdir:-}" && -d "${tmpdir}" ]] && rm -rf "${tmpdir}"
}

@test "deploy: paas_phase3_dispatch routes to dflow_phase3_install_shared when PAAS=dflow" {
  source_deploy_script
  dflow_phase3_install_shared() { echo "dflow3:$*"; }
  coolify_phase3_docker_coolify_shared() { echo "coolify3:$*"; }
  SCRIPT_DIR="${tmpdir}"
  PAAS=dflow
  run paas_phase3_dispatch ignored1 ignored2
  assert_success
  assert_output --partial "dflow3:ignored1 ignored2"
  refute_output --partial "coolify3"
}

@test "deploy: paas_phase4_dispatch routes to dflow_phase4_routing_shared when PAAS=dflow" {
  source_deploy_script
  dflow_phase4_routing_shared() { echo "dflow4:$*"; }
  coolify_phase4_binding_dns_shared() { echo "coolify4:$*"; }
  PAAS=dflow
  run paas_phase4_dispatch ignored
  assert_success
  assert_output --partial "dflow4:ignored"
  refute_output --partial "coolify4"
}

@test "deploy: paas_phase5_dispatch routes to dflow_phase5_verify_shared when PAAS=dflow" {
  source_deploy_script
  dflow_phase5_verify_shared() { echo "dflow5:$*"; }
  coolify_phase5_verify_shared() { echo "coolify5:$*"; }
  PAAS=dflow
  # dflow path forwards only the first argument (validate_json fetcher).
  run paas_phase5_dispatch validatefn extra1 extra2
  assert_success
  assert_output --partial "dflow5:validatefn"
  refute_output --partial "coolify5"
}

@test "deploy: unsupported PAAS dies" {
  source_deploy_script
  PAAS=unknown
  run paas_phase4_dispatch
  assert_failure
  assert_output --partial "Unsupported PAAS: unknown"
}

@test "setup: paas_phase3_dispatch routes to dflow_phase3_install_shared when PAAS=dflow" {
  source_setup_script
  dflow_phase3_install_shared() { echo "sdflow3:$*"; }
  coolify_phase3_docker_coolify_shared() { echo "scoolify3:$*"; }
  SCRIPT_DIR="${tmpdir}"
  PAAS=dflow
  run paas_phase3_dispatch x y
  assert_success
  assert_output --partial "sdflow3:x y"
  refute_output --partial "scoolify3"
}

@test "setup: paas_phase4_dispatch routes to dflow_phase4_routing_shared when PAAS=dflow" {
  source_setup_script
  dflow_phase4_routing_shared() { echo "sdflow4:$*"; }
  PAAS=dflow
  run paas_phase4_dispatch sarg
  assert_success
  assert_output --partial "sdflow4:sarg"
}

@test "setup: paas_phase5_dispatch forwards only validate_json fn to dflow_phase5_verify_shared" {
  source_setup_script
  dflow_phase5_verify_shared() { echo "sdflow5:$*"; }
  PAAS=dflow
  run paas_phase5_dispatch validate_json_fn external pause_fn
  assert_success
  assert_output --partial "sdflow5:validate_json_fn"
  refute_output --partial "external"
}

@test "overlay topo sort: dflow resolves docker-host first" {
  source_setup_script
  SCRIPT_DIR="${tmpdir}"
  run overlay_topo_sort dflow
  assert_success
  result="$output"
  [[ "${result%%dflow*}" == *"docker-host"* ]]
}
