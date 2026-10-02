#!/usr/bin/env bats

@test "Docker-owned generated bridges work without weakening management or WAN drops" {
  local root="${BATS_TEST_DIRNAME}/../../../.."
  run bash -c '
    set -euo pipefail
    source <(sed -n "/^populate_policy_chain() {$/,/^}$/p" "$1")
    DOCKER_USER_MANAGEMENT_PORT=3000 DOKPLOY_ENROLLMENT_COMPLETE=true
    TAILSCALE_IFACE=tailscale0 WAN_IFACE=eth0 TUNNEL_MODE=false
    run_ipt() { printf "%s " "$@"; printf "\n"; }
    is_true() { [[ "$1" == true ]]; }
    docker() {
      if [[ "$1 $2" == "network ls" ]]; then printf "%s\n" aaaaaaaaaaaa bbbbbbbbbbbb cccccccccccc; return; fi
      local id="${*: -1}"
      if [[ "$4" == *".Options"* ]]; then printf "<no value>\n"; return; fi
      case "$id" in
        aaaaaaaaaaaa) printf "bridge %064d\n" 0 | sed "s/0/a/g" ;;
        bbbbbbbbbbbb) printf "overlay %064d\n" 0 | sed "s/0/b/g" ;;
        cccccccccccc) printf "bridge %064d\n" 0 | sed "s/0/d/g" ;;
      esac
    }
    ip() { [[ "${*: -1}" == br-aaaaaaaaaaaa ]]; }
    rules=$(populate_policy_chain iptables TEST "")
    grep -q -- "-i br-aaaaaaaaaaaa .*docker-owned .*RETURN" <<< "$rules"
    ! grep -q -- "-i br-bbbbbbbbbbbb\|-i br-dddddddddddd\|-i br+" <<< "$rules"
    management=$(grep -n management-container-drop <<< "$rules" | cut -d: -f1)
    wan=$(grep -n wan-drop <<< "$rules" | cut -d: -f1)
    bridge=$(grep -n br-aaaaaaaaaaaa <<< "$rules" | cut -d: -f1)
    [[ "$management" -lt "$bridge" && "$wan" -lt "$bridge" ]]
    grep -q -- "unmatched-drop .*DROP" <<< "$rules"
  ' bash "${root}/overlays/docker-host/modules/user_rules.sh"
  [[ "$status" -eq 0 ]] || return 1
}
