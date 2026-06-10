#!/usr/bin/env bats

load '../../../helpers/helpers'

setup() {
  source_validate_script
  reset_validate_runtime
}

@test "dokploy_check: passes for Swarm, services, tailscale UFW, and closed Docker API" {
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
    cat <<'IPT'
-N DOCKER-USER
-A DOCKER-USER -m comment --comment coolify-hardening-wan-web -j ACCEPT
-A DOCKER-USER -m comment --comment coolify-hardening-wan-drop -j DROP
IPT
  }

  dokploy_check
  json="$(emit_validate_results_json)"

  assert_json_check_status "${json}" "dokploy: Docker Swarm active" "PASS"
  assert_json_check_status "${json}" "dokploy: service present" "PASS"
  assert_json_check_status "${json}" "dokploy: dashboard UFW tailscale0" "PASS"
  assert_json_check_status "${json}" "dokploy: dashboard not public" "PASS"
  assert_json_check_status "${json}" "dokploy: DOCKER-USER WAN drop" "PASS"
  assert_json_check_status "${json}" "dokploy: Docker TCP API closed" "PASS"
  assert_json_fail_count "${json}" "0"
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
  cat > "${DOKPLOY_ETC_DIR}/traefik/dynamic/zz-hardening-dashboard-block.yml" <<'YAML'
http:
  middlewares:
    zz-hardening-deny-public:
      ipAllowList:
        sourceRange:
          - 192.0.2.0/32
YAML
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

@test "dokploy_check: fails unlock unit without PartOf and passes hardened unit" {
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
  DOKPLOY_UNLOCK_UNIT_FILE="${tmpdir}/docker-swarm-unlock.service"
  DOKPLOY_UNLOCK_HELPER="${tmpdir}/docker-swarm-unlock.sh"

  cat > "${DOKPLOY_UNLOCK_UNIT_FILE}" <<'UNIT'
[Unit]
After=docker.service
[Service]
ExecStart=/bin/bash -c 'echo hi'
UNIT
  dokploy_check
  json="$(emit_validate_results_json)"
  assert_json_check_status "${json}" "dokploy: swarm auto-unlock unit" "FAIL"

  reset_validate_runtime
  cat > "${DOKPLOY_UNLOCK_UNIT_FILE}" <<'UNIT'
[Unit]
After=docker.service
PartOf=docker.service
[Service]
ExecStart=/usr/local/sbin/docker-swarm-unlock.sh
UNIT
  printf '#!/usr/bin/env bash\nexit 0\n' > "${DOKPLOY_UNLOCK_HELPER}"
  chmod 755 "${DOKPLOY_UNLOCK_HELPER}"
  dokploy_check
  json="$(emit_validate_results_json)"
  rm -rf "${tmpdir}"
  assert_json_check_status "${json}" "dokploy: swarm auto-unlock unit" "PASS"
}
