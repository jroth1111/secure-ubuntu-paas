#!/usr/bin/env bats

load '../../../helpers/helpers'

setup() {
  source_validate_script
  reset_validate_runtime
  dokploy_enrollment_source_ip=100.74.193.51
  # A live Traefik denial is the only valid public-route proof; 000 is now a
  # failure.  Unit fixtures model the converged local proxy with HTTP 403.
  curl() { echo 403; }
}

@test "dokploy_check: passes for Swarm, services, tailscale UFW, and closed Docker API" {
  DOKPLOY_ETC_DIR="${BATS_TEST_TMPDIR}/dokploy"
  mkdir -p "${DOKPLOY_ETC_DIR}/traefik/dynamic"
  run bash -c 'source "'"${PROJECT_ROOT}"'/overlays/dokploy/dokploy-common.sh"; ADMIN_PUBKEY=test; dokploy_finalize_runtime_script'
  assert_success
  printf '%s\n' "${output}" | awk '/^# Managed by secure-ubuntu-paas hardening \(Dokploy overlay\)/ {body=1} /^BLOCK$/ {body=0} body' \
    > "${DOKPLOY_ETC_DIR}/traefik/dynamic/zz-hardening-dashboard-block.yml"
  chmod 0600 "${DOKPLOY_ETC_DIR}/traefik/dynamic/zz-hardening-dashboard-block.yml"
  stat() {
    case "$2" in
      '%U:%G') echo root:root ;;
      '%a') if [[ "$3" == *zz-hardening-dashboard-block.yml ]]; then echo 600; else echo 755; fi ;;
      *) command stat "$@" ;;
    esac
  }
  command() {
    if [[ "$1" == "-v" && "$2" == "docker" ]]; then
      return 0
    fi
    builtin command "$@"
  }
  docker() {
    case "$1 $2" in
      "info --format") echo "active" ;;
      "info ") echo 'Autolock Managers: true' ;;
      "service ls") printf "dokploy\ndokploy-traefik\n" ;;
      "service inspect")
        if [[ "$*" == *'ContainerSpec.Mounts'* ]]; then echo '/etc/dokploy/traefik/dynamic -> /etc/dokploy/traefik/dynamic';
        elif [[ "$3" == dokploy-traefik ]]; then echo 'traefik:v3.7.13@sha256:24841fe2de7304c149343d877d2923b4c8800a38ba015dea9174c23b20e344a0';
        else echo 'dokploy/dokploy:latest@sha256:cb24001d40c6da4b220683522b98e3070530c8423b7bc390f503efc515b6b24f'; fi ;;
      "ps -q") echo pgcontainer ;;
      "exec pgcontainer")
        if [[ "$*" == *'IS DISTINCT FROM TRUE'* ]]; then echo 0; else echo 1; fi ;;
      *) return 1 ;;
    esac
  }
  ufw() {
    cat <<'UFW'
Status: active
3000/tcp on tailscale0      ALLOW IN    Anywhere # dokploy-dashboard-tailscale
3000/tcp                   DENY IN     Anywhere
80/tcp                     ALLOW IN    Anywhere
443/tcp                    ALLOW IN    Anywhere
UFW
  }
  ss() {
    cat <<'SS'
LISTEN 0 4096 0.0.0.0:80 0.0.0.0:*
LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*
LISTEN 0 4096 0.0.0.0:3000 0.0.0.0:*
SS
  }
  iptables() {
    if [[ "${4:-}" == "DOCKER-USER" ]]; then
      cat <<'IPT'
-N DOCKER-USER
-A DOCKER-USER -m comment --comment secure-ubuntu-paas-docker-user-jump -j SECURE-DOCKER-USER
IPT
    elif [[ "${4:-}" == "SECURE-DOCKER-USER" ]]; then
      cat <<'IPT'
-N SECURE-DOCKER-USER
-A SECURE-DOCKER-USER -i tailscale0 -p tcp -m conntrack --ctorigdstport 3000 --ctdir ORIGINAL -m comment --comment coolify-hardening-management-tailnet-enrolled -j ACCEPT
-A SECURE-DOCKER-USER -p tcp -m conntrack --ctorigdstport 3000 --ctdir ORIGINAL -m comment --comment coolify-hardening-management-container-drop -j DROP
-A SECURE-DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment coolify-hardening-estab -j RETURN
-A SECURE-DOCKER-USER -i eth0 -m comment --comment coolify-hardening-wan-web -j ACCEPT
-A SECURE-DOCKER-USER -i eth0 -m comment --comment coolify-hardening-wan-drop -j DROP
-A SECURE-DOCKER-USER -i docker0 -m comment --comment coolify-hardening-bridge-docker0 -j RETURN
-A SECURE-DOCKER-USER -i docker_gwbridge -m comment --comment coolify-hardening-bridge-docker-gw -j RETURN
-A SECURE-DOCKER-USER -m comment --comment coolify-hardening-unmatched-drop -j DROP
-A SECURE-DOCKER-USER -m comment --comment coolify-hardening-return -j RETURN
IPT
    fi
  }

  dokploy_check
  json="$(emit_validate_results_json)"

  assert_json_check_status "${json}" "dokploy: Docker Swarm active" "PASS"
  assert_json_check_status "${json}" "dokploy: service present" "PASS"
  assert_json_check_status "${json}" "dokploy: dashboard UFW tailscale0" "PASS"
  assert_json_check_status "${json}" "dokploy: dashboard not public" "PASS"
  assert_json_check_status "${json}" "dokploy: DOCKER-USER WAN drop" "PASS"
  assert_json_check_status "${json}" "dokploy: panel container boundary" "PASS"
  assert_json_check_status "${json}" "dokploy: panel tracks latest stable" "PASS"
  assert_json_check_status "${json}" "dokploy: Docker TCP API closed" "PASS"
  if [[ "$(jq -r .fail <<< "${json}")" != 0 ]]; then jq '.checks[] | select(.status=="FAIL")' <<< "${json}"; fi
  assert_json_fail_count "${json}" "0"
}

@test "dokploy_check: fails broad tailnet Swarm exposure on one node and passes when closed" {
  command() {
    if [[ "$1" == "-v" && "$2" == "docker" ]]; then
      return 0
    fi
    builtin command "$@"
  }
  docker() {
    case "$1 $2" in
      "info --format") echo "active" ;;
      "node ls") echo "single-node-id" ;;
      "node inspect") echo "203.0.113.10:2377" ;;
      "service ls") printf "dokploy\ndokploy-traefik\n" ;;
      "service inspect") printf '%s\n' 'dokploy/dokploy:v0.29.13@sha256:cb24001d40c6da4b220683522b98e3070530c8423b7bc390f503efc515b6b24f' ;;
      *) return 1 ;;
    esac
  }
  ss() { echo "LISTEN 0 4096 0.0.0.0:3000 0.0.0.0:*"; }
  tailscale() { echo "100.73.142.119"; }
  MOCK_SWARM_OPEN="true"
  ufw() {
    if [[ "${MOCK_SWARM_OPEN}" == "true" ]]; then
      cat <<'UFW'
Status: active
2377/tcp on tailscale0 ALLOW IN Anywhere # docker-swarm-mgmt-tailscale
7946/tcp on tailscale0 ALLOW IN Anywhere # docker-swarm-gossip-tailscale
7946/udp on tailscale0 ALLOW IN Anywhere # docker-swarm-gossip-udp-tailscale
4789/udp on tailscale0 ALLOW IN Anywhere # docker-swarm-vxlan-tailscale
UFW
    else
      echo "Status: active"
    fi
  }

  dokploy_check
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "dokploy: swarm mgmt 2377/tcp closed" "FAIL"
  assert_json_check_status "${json}" "dokploy: swarm vxlan 4789/udp closed" "FAIL"

  reset_validate_runtime
  MOCK_SWARM_OPEN="false"
  dokploy_check
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "dokploy: swarm mgmt 2377/tcp closed" "PASS"
  assert_json_check_status "${json}" "dokploy: swarm vxlan 4789/udp closed" "PASS"
}

@test "dokploy_check: rejects Tailscale acceptance before the managed INPUT policy" {
  DOKPLOY_NETWORK_CHECK_STRICT="true"
  DOKPLOY_TAILNET_FILTER_SCRIPT="$(mktemp)"
  chmod +x "${DOKPLOY_TAILNET_FILTER_SCRIPT}"
  MOCK_INPUT_ORDER="unsafe"
  command() {
    if [[ "$1" == "-v" && ( "$2" == "docker" || "$2" == "ip6tables" ) ]]; then
      return 0
    fi
    builtin command "$@"
  }
  docker() {
    case "$1 $2" in
      "info --format") echo "active" ;;
      "node ls") echo "single-node-id" ;;
      "node inspect") echo "203.0.113.10:2377" ;;
      "service ls") printf "dokploy\ndokploy-traefik\ndokploy-postgres\n" ;;
      "service inspect") printf '%s\n' 'dokploy/dokploy:v0.29.13@sha256:cb24001d40c6da4b220683522b98e3070530c8423b7bc390f503efc515b6b24f' ;;
      "ps -q") echo "pgcontainer" ;;
      "exec pgcontainer")
        if [[ "$*" == *"pg_catalog.pg_tables"* ]]; then echo "1"; else echo "0"; fi
        ;;
      *) return 1 ;;
    esac
  }
  ufw() {
    cat <<'UFW'
Status: active
3000/tcp on tailscale0 ALLOW IN 100.74.193.51 # dokploy-enrollment-operator
3000/tcp DENY IN Anywhere
UFW
  }
  tailscale() {
    if [[ "$1 $2" == "debug prefs" ]]; then
      echo '{"NetfilterMode":1}'
    elif [[ "$1 $2" == "ip -4" ]]; then
      echo "100.73.142.119"
    fi
  }
  input_rules() {
    if [[ "${MOCK_INPUT_ORDER}" == "unsafe" ]]; then
      printf '%s\n' '-A INPUT -j ts-input' '-A INPUT -j SECURE-TAILSCALE-INPUT-A'
    else
      printf '%s\n' '-A INPUT -j SECURE-TAILSCALE-INPUT-A' '-A INPUT -j ts-input'
    fi
  }
  iptables() {
    if [[ "$*" == "-S INPUT" ]]; then
      input_rules
    elif [[ "$*" == "-S SECURE-TAILSCALE-INPUT-A" ]]; then
      cat <<'IPT'
-A SECURE-TAILSCALE-INPUT-A -i tailscale0 -p tcp --dport 22 -m comment --comment dokploy-tailnet-root-ssh-ipv4 -j ACCEPT
-A SECURE-TAILSCALE-INPUT-A -s 100.74.193.51/32 -i tailscale0 -p tcp --dport 3000 -m comment --comment dokploy-tailnet-dashboard-operator-ipv4 -j ACCEPT
-A SECURE-TAILSCALE-INPUT-A -i tailscale0 -p tcp --dport 3000 -m comment --comment dokploy-tailnet-dashboard-guard-ipv4 -j DROP
-A SECURE-TAILSCALE-INPUT-A -i tailscale0 -m comment --comment dokploy-tailnet-privileged-tcp-drop-ipv4 -j DROP
-A SECURE-TAILSCALE-INPUT-A -i tailscale0 -m comment --comment dokploy-tailnet-swarm-udp-drop-ipv4 -j DROP
-A SECURE-TAILSCALE-INPUT-A -i tailscale0 -m comment --comment dokploy-tailnet-unmatched-drop-ipv4 -j DROP
-A SECURE-TAILSCALE-INPUT-A -i tailscale0 -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment dokploy-tailnet-established-ipv4 -j ACCEPT
-A SECURE-TAILSCALE-INPUT-A ! -i tailscale0 -p udp --dport 41641 -m comment --comment dokploy-tailnet-tailscale-wan-drop-ipv4 -j DROP
-A SECURE-TAILSCALE-INPUT-A -m comment --comment dokploy-tailnet-return-ipv4 -j RETURN
IPT
    elif [[ "${4:-}" == "DOCKER-USER" ]]; then
      echo '-A DOCKER-USER -m comment --comment secure-ubuntu-paas-docker-user-jump -j SECURE-DOCKER-USER'
    elif [[ "${4:-}" == "SECURE-DOCKER-USER" ]]; then
      cat <<'IPT'
-A SECURE-DOCKER-USER -s 100.74.193.51/32 -i tailscale0 -p tcp -m conntrack --ctorigdstport 3000 -m comment --comment coolify-hardening-management-tailnet-source -j ACCEPT
-A SECURE-DOCKER-USER -i tailscale0 -p tcp -m conntrack --ctorigdstport 3000 -m comment --comment coolify-hardening-management-tailnet-drop -j DROP
-A SECURE-DOCKER-USER -p tcp -m conntrack --ctorigdstport 3000 --ctdir ORIGINAL -m comment --comment coolify-hardening-management-container-drop -j DROP
-A SECURE-DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment coolify-hardening-estab -j RETURN
-A SECURE-DOCKER-USER -i tailscale0 -m comment --comment coolify-hardening-tailscale -j ACCEPT
-A SECURE-DOCKER-USER -i eth0 -p tcp -m multiport --dports 80,443 -m comment --comment coolify-hardening-wan-web -j ACCEPT
-A SECURE-DOCKER-USER -i eth0 -m comment --comment coolify-hardening-wan-drop -j DROP
-A SECURE-DOCKER-USER -i docker0 -m comment --comment coolify-hardening-bridge-docker0 -j RETURN
-A SECURE-DOCKER-USER -m comment --comment coolify-hardening-unmatched-drop -j DROP
-A SECURE-DOCKER-USER -m comment --comment coolify-hardening-return -j RETURN
IPT
    fi
  }
  ip6tables() {
    if [[ "$*" == "-S INPUT" ]]; then
      input_rules
    elif [[ "$*" == "-S SECURE-TAILSCALE-INPUT-A" ]]; then
      cat <<'IP6T'
-A SECURE-TAILSCALE-INPUT-A -i tailscale0 -p tcp --dport 22 -m comment --comment dokploy-tailnet-root-ssh-ipv6 -j ACCEPT
-A SECURE-TAILSCALE-INPUT-A -i tailscale0 -p tcp --dport 3000 -m comment --comment dokploy-tailnet-dashboard-guard-ipv6 -j DROP
-A SECURE-TAILSCALE-INPUT-A -i tailscale0 -m comment --comment dokploy-tailnet-privileged-tcp-drop-ipv6 -j DROP
-A SECURE-TAILSCALE-INPUT-A -i tailscale0 -m comment --comment dokploy-tailnet-swarm-udp-drop-ipv6 -j DROP
-A SECURE-TAILSCALE-INPUT-A -i tailscale0 -m comment --comment dokploy-tailnet-unmatched-drop-ipv6 -j DROP
-A SECURE-TAILSCALE-INPUT-A -i tailscale0 -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment dokploy-tailnet-established-ipv6 -j ACCEPT
-A SECURE-TAILSCALE-INPUT-A ! -i tailscale0 -p udp --dport 41641 -m comment --comment dokploy-tailnet-tailscale-wan-drop-ipv6 -j DROP
-A SECURE-TAILSCALE-INPUT-A -m comment --comment dokploy-tailnet-return-ipv6 -j RETURN
IP6T
    fi
  }
  systemctl() {
    [[ "$1" == "is-enabled" || "$1" == "is-active" ]]
  }
  ss() { echo "LISTEN 0 4096 0.0.0.0:3000 0.0.0.0:*"; }

  dokploy_check
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "dokploy: effective IPv4 tailnet INPUT policy" "FAIL"

  reset_validate_runtime
  MOCK_INPUT_ORDER="safe"
  dokploy_check
  json="$(emit_validate_results_json)"
  rm -f "${DOKPLOY_TAILNET_FILTER_SCRIPT}"
  assert_json_check_status "${json}" "dokploy: effective IPv4 tailnet INPUT policy" "PASS"
  assert_json_check_status "${json}" "dokploy: effective IPv6 tailnet INPUT policy" "PASS"
  assert_json_check_status "${json}" "dokploy: Docker-forwarded dashboard authorization" "PASS"
}

@test "dokploy_check: fails when panel image is mutable or an unreviewed digest" {
  command() {
    if [[ "$1" == "-v" && "$2" == "docker" ]]; then
      return 0
    fi
    builtin command "$@"
  }
  docker() {
    case "$1 $2" in
      "info --format") echo "active" ;;
      "service ls") printf "dokploy\n" ;;
      "service inspect") printf '%s\n' 'dokploy/dokploy:v0.29.14' ;;
      *) return 1 ;;
    esac
  }
  ufw() {
    printf '%s\n' '3000/tcp                   ALLOW IN    on tailscale0'
  }
  ss() { printf 'LISTEN 0 4096 0.0.0.0:3000 0.0.0.0:*\n'; }
  iptables() { printf '%s\n' '-N DOCKER-USER'; }

  dokploy_check
  json="$(emit_validate_results_json)"

  assert_json_check_status "${json}" "dokploy: panel tracks latest stable" "FAIL"
}

@test "dokploy_check: fails when DOCKER-USER WAN drop rules are missing" {
  command() {
    if [[ "$1" == "-v" && "$2" == "docker" ]]; then
      return 0
    fi
    builtin command "$@"
  }
  docker() {
    case "$1 $2" in
      "info --format") echo "active" ;;
      "service ls") printf "dokploy\ndokploy-traefik\n" ;;
      *) return 1 ;;
    esac
  }
  ufw() {
    cat <<'UFW'
Status: active
3000/tcp                   ALLOW IN    on tailscale0
3000/tcp                   DENY IN     Anywhere
UFW
  }
  ss() { printf 'LISTEN 0 4096 0.0.0.0:3000 0.0.0.0:*\n'; }
  iptables() { printf '%s\n' '-N DOCKER-USER'; }

  dokploy_check
  json="$(emit_validate_results_json)"

  assert_json_check_status "${json}" "dokploy: DOCKER-USER WAN drop" "FAIL"
}

@test "dokploy_check: fails when dashboard 3000 is publicly allowed" {
  command() {
    if [[ "$1" == "-v" && "$2" == "docker" ]]; then
      return 0
    fi
    builtin command "$@"
  }
  docker() {
    case "$1 $2" in
      "info --format") echo "active" ;;
      "service ls") printf "dokploy\ndokploy-traefik\n" ;;
      *) return 1 ;;
    esac
  }
  ufw() {
    cat <<'UFW'
Status: active
3000/tcp                   ALLOW IN    Anywhere
UFW
  }
  ss() { echo "LISTEN 0 4096 0.0.0.0:3000 0.0.0.0:*"; }

  dokploy_check
  json="$(emit_validate_results_json)"

  assert_json_check_status "${json}" "dokploy: dashboard not public" "FAIL"
}

@test "dokploy_check: fails when a real panel domain is routed via public Traefik" {
  command() {
    if [[ "$1" == "-v" && "$2" == "docker" ]]; then
      return 0
    fi
    builtin command "$@"
  }
  docker() {
    case "$1 $2" in
      "info --format") echo "active" ;;
      "service ls") printf "dokploy\ndokploy-traefik\n" ;;
      *) return 1 ;;
    esac
  }
  ufw() { echo "Status: active"; }
  ss() { echo "LISTEN 0 4096 0.0.0.0:3000 0.0.0.0:*"; }

  DOKPLOY_ETC_DIR="$(mktemp -d)"
  mkdir -p "${DOKPLOY_ETC_DIR}/traefik/dynamic"
  cat > "${DOKPLOY_ETC_DIR}/traefik/dynamic/dokploy.yml" <<'YAML'
http:
  routers:
    dokploy-router-app:
      rule: Host(`panel.example.com`)
      entryPoints:
        - web
YAML

  dokploy_check
  json="$(emit_validate_results_json)"
  rm -rf "${DOKPLOY_ETC_DIR}"

  assert_json_check_status "${json}" "dokploy: panel not on public domain" "FAIL"
}

@test "dokploy_check: default localhost route passes domain check but needs the block file" {
  command() {
    if [[ "$1" == "-v" && "$2" == "docker" ]]; then
      return 0
    fi
    builtin command "$@"
  }
  docker() {
    case "$1 $2" in
      "info --format") echo "active" ;;
      "service ls") printf "dokploy\ndokploy-traefik\n" ;;
      "service inspect") echo '/etc/dokploy/traefik/dynamic -> /etc/dokploy/traefik/dynamic' ;;
      *) return 1 ;;
    esac
  }
  ufw() { echo "Status: active"; }
  ss() { echo "LISTEN 0 4096 0.0.0.0:3000 0.0.0.0:*"; }
  stat() {
    if [[ "${1:-}" == "-c" && "${2:-}" == "%U:%G" && "${3:-}" == *"zz-hardening-dashboard-block.yml" ]]; then
      echo "root:root"
      return 0
    fi
    if [[ "${1:-}" == "-c" && "${2:-}" == "%a" && "${3:-}" == *"zz-hardening-dashboard-block.yml" ]]; then
      echo "600"
      return 0
    fi
    command stat "$@"
  }

  DOKPLOY_ETC_DIR="$(mktemp -d)"
  mkdir -p "${DOKPLOY_ETC_DIR}/traefik/dynamic"
  cat > "${DOKPLOY_ETC_DIR}/traefik/dynamic/dokploy.yml" <<'YAML'
http:
  routers:
    dokploy-router-app:
      rule: Host(`dokploy.docker.localhost`) && PathPrefix(`/`)
      entryPoints:
        - web
YAML

  # No block file yet → default route check must FAIL, domain check PASS.
  dokploy_check
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "dokploy: panel not on public domain" "PASS"
  assert_json_check_status "${json}" "dokploy: default dashboard route blocked publicly" "FAIL"

  reset_validate_runtime
  run bash -c 'source "'"${PROJECT_ROOT}"'/overlays/dokploy/dokploy-common.sh"; ADMIN_PUBKEY=test; dokploy_finalize_runtime_script'
  assert_success
  printf '%s\n' "${output}" | awk '/^# Managed by secure-ubuntu-paas hardening \(Dokploy overlay\)/ {body=1} /^BLOCK$/ {body=0} body' \
    > "${DOKPLOY_ETC_DIR}/traefik/dynamic/zz-hardening-dashboard-block.yml"
  dokploy_check
  json="$(emit_validate_results_json)"
  rm -rf "${DOKPLOY_ETC_DIR}"
  assert_json_check_status "${json}" "dokploy: default dashboard route blocked publicly" "PASS"
}

@test "dokploy_check: fails when Traefik API is insecure and passes when disabled" {
  command() {
    if [[ "$1" == "-v" && "$2" == "docker" ]]; then
      return 0
    fi
    builtin command "$@"
  }
  docker() {
    case "$1 $2" in
      "info --format") echo "active" ;;
      "service ls") printf "dokploy\ndokploy-traefik\n" ;;
      *) return 1 ;;
    esac
  }
  ufw() { echo "Status: active"; }
  ss() { echo "LISTEN 0 4096 0.0.0.0:3000 0.0.0.0:*"; }

  DOKPLOY_ETC_DIR="$(mktemp -d)"
  mkdir -p "${DOKPLOY_ETC_DIR}/traefik"
  printf 'api:\n  insecure: true\n' > "${DOKPLOY_ETC_DIR}/traefik/traefik.yml"

  dokploy_check
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "dokploy: Traefik API not insecure" "FAIL"

  reset_validate_runtime
  printf 'api:\n  insecure: false\n' > "${DOKPLOY_ETC_DIR}/traefik/traefik.yml"
  dokploy_check
  json="$(emit_validate_results_json)"
  rm -rf "${DOKPLOY_ETC_DIR}"
  assert_json_check_status "${json}" "dokploy: Traefik API not insecure" "PASS"
}

@test "dokploy_check: proves live Traefik API state from the task network namespace" {
  command() {
    case "${1:-} ${2:-}" in
      "-v docker"|"-v curl"|"-v nsenter"|"-v ss") return 0 ;;
    esac
    builtin command "$@"
  }
  docker() {
    case "${1:-} ${2:-}" in
      "info --format") echo "active" ;;
      "service ls") printf "dokploy-traefik\n" ;;
      "service inspect") printf '%s\n' 'traefik@sha256:fcdef599e6259359833dd2e1d49f9e964f66825d69bd3dd468f51102ce013d03' ;;
      "ps --filter") echo "traefik-container" ;;
      "inspect --format") echo "4242" ;;
      *) return 1 ;;
    esac
  }
  ufw() { echo "Status: active"; }
  ss() { echo "LISTEN 0 4096 0.0.0.0:3000 0.0.0.0:*"; }
  curl() { echo "404"; }
  MOCK_TRAEFIK_8080="false"
  nsenter() {
    if [[ "$*" == *"sport = :8080"* ]]; then
      [[ "${MOCK_TRAEFIK_8080}" == "true" ]] && echo "LISTEN 0 4096 *:8080 *:*"
      return 0
    fi
    if [[ "$*" == *"sport = :80"* ]]; then
      echo "LISTEN 0 4096 *:80 *:*"
      return 0
    fi
    return 1
  }

  DOKPLOY_ETC_DIR="$(mktemp -d)"
  mkdir -p "${DOKPLOY_ETC_DIR}/traefik"
  printf 'api:\n  insecure: false\naccessLog:\n  format: json\n' > "${DOKPLOY_ETC_DIR}/traefik/traefik.yml"

  dokploy_check
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "dokploy: Traefik live API disabled" "PASS"

  reset_validate_runtime
  MOCK_TRAEFIK_8080="true"
  dokploy_check
  json="$(emit_validate_results_json)"
  rm -rf "${DOKPLOY_ETC_DIR}"
  assert_json_check_status "${json}" "dokploy: Traefik live API disabled" "FAIL"
}

@test "dokploy_check: flags world-writable /etc/dokploy" {
  command() {
    if [[ "$1" == "-v" && "$2" == "docker" ]]; then
      return 0
    fi
    builtin command "$@"
  }
  docker() {
    case "$1 $2" in
      "info --format") echo "active" ;;
      "service ls") printf "dokploy\ndokploy-traefik\n" ;;
      *) return 1 ;;
    esac
  }
  ufw() { echo "Status: active"; }
  ss() { echo "LISTEN 0 4096 0.0.0.0:3000 0.0.0.0:*"; }
  stat() {
    if [[ "$1" == "-c" && "$2" == "%a" ]]; then
      echo "777"
    else
      builtin command stat "$@"
    fi
  }

  DOKPLOY_ETC_DIR="$(mktemp -d)"

  dokploy_check
  json="$(emit_validate_results_json)"
  rm -rf "${DOKPLOY_ETC_DIR}"

  assert_json_check_status "${json}" "dokploy: /etc/dokploy not world-writable" "FAIL"
}

@test "dokploy_check: fails when the Swarm unlock key or automatic unit remains on the host" {
  command() {
    if [[ "$1" == "-v" && "$2" == "docker" ]]; then
      return 0
    fi
    builtin command "$@"
  }
  docker() {
    if [[ "$1" == "info" && "${2:-}" == "--format" ]]; then echo "active"; return 0; fi
    if [[ "$1" == "info" ]]; then echo "  Autolock Managers: true"; return 0; fi
    if [[ "$1" == "service" && "${2:-}" == "ls" ]]; then printf "dokploy\ndokploy-traefik\n"; return 0; fi
    return 1
  }
  ufw() { echo "Status: active"; }
  ss() { echo "LISTEN 0 4096 0.0.0.0:3000 0.0.0.0:*"; }

  local tmpdir
  tmpdir="$(mktemp -d)"
  DOKPLOY_UNLOCK_KEY_FILE="${tmpdir}/swarm-unlock-key"
  DOKPLOY_UNLOCK_UNIT_FILE="${tmpdir}/docker-swarm-unlock.service"
  DOKPLOY_UNLOCK_HELPER="${tmpdir}/docker-swarm-unlock.sh"

  dokploy_check
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "dokploy: swarm autolock external key" "PASS"

  reset_validate_runtime
  printf 'SWMKEY-test\n' > "${DOKPLOY_UNLOCK_KEY_FILE}"
  dokploy_check
  json="$(emit_validate_results_json)"
  rm -rf "${tmpdir}"
  assert_json_check_status "${json}" "dokploy: swarm autolock external key" "FAIL"
}

@test "dokploy_check: requires panel and database control-network isolation" {
  DOKPLOY_NETWORK_CHECK_STRICT=true
  docker() {
    case "$1 $2 $3" in
      "info --format "*) echo "active" ;;
      "service ls "*) printf "dokploy\ndokploy-postgres\ndokploy-traefik\n" ;;
      "network inspect --format")
        if [[ "$5" == "dokploy-control-network" ]]; then echo "control-id"; else echo "legacy-id"; fi
        ;;
      "service inspect dokploy")
        if [[ "$5" == *"TaskTemplate.Networks"* ]]; then echo "control-id"; else echo 'dokploy/dokploy:latest@sha256:cb24001d40c6da4b220683522b98e3070530c8423b7bc390f503efc515b6b24f'; fi
        ;;
      "service inspect dokploy-postgres") echo "control-id" ;;
      "service inspect dokploy-traefik") echo "legacy-id" ;;
      *) return 1 ;;
    esac
  }
  ufw() { printf '%s\n' '3000/tcp                   ALLOW IN    on tailscale0'; }
  ss() { printf 'LISTEN 0 4096 0.0.0.0:3000 0.0.0.0:*\n'; }
  iptables() { printf '%s\n' '-N DOCKER-USER'; }

  dokploy_check
  json="$(emit_validate_results_json)"

  assert_json_check_status "${json}" "dokploy: panel control network isolation" "PASS"
  assert_json_check_status "${json}" "dokploy: database control network isolation" "PASS"
  assert_json_check_status "${json}" "dokploy: proxy outside control network" "PASS"
}
