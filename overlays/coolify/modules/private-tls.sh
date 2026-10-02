#!/usr/bin/env bash
# overlays/coolify/modules/private-tls.sh — Private dashboard route and TLS DNS heredoc generators.
# Sourced by coolify-common.sh; do not execute directly.

[[ "${BASH_SOURCE[0]}" != "${0}" ]] \
  || { printf 'Source this file, do not execute it.\n' >&2; exit 1; }

# coolify_configure_private_dashboard_routes_script — Emit host-side script to
# write managed Traefik routes for private dashboard/realtime hostnames.
coolify_configure_private_dashboard_routes_script() {
  cat <<'EOF'
set -Eeuo pipefail
: "${DOMAIN:?DOMAIN is required}"

dynamic_dir="/data/coolify/proxy/dynamic"
route_file="${dynamic_dir}/coolify-private-dashboard.yaml"
route_backup_file="${dynamic_dir}/.coolify-private-dashboard.backup"
route_absent_marker="${dynamic_dir}/.coolify-private-dashboard.absent"
mkdir -p "${dynamic_dir}"

if [[ -f "${route_file}" ]]; then
  cp -f "${route_file}" "${route_backup_file}"
  rm -f "${route_absent_marker}"
else
  rm -f "${route_backup_file}"
  : > "${route_absent_marker}"
fi

cat > "${route_file}" <<CFG
# This file is managed by secure-ubuntu-paas.
http:
  middlewares:
    coolify-private-gzip:
      compress: true
    coolify-private-force-https:
      redirectScheme:
        scheme: https
        permanent: true
  routers:
    coolify-private-dashboard-http:
      entryPoints:
        - http
      rule: "Host(\`${DOMAIN}\`)"
      service: noop@internal
      middlewares:
        - coolify-private-force-https
    coolify-private-dashboard-https:
      entryPoints:
        - https
      rule: "Host(\`${DOMAIN}\`)"
      service: coolify-private-dashboard
      middlewares:
        - coolify-private-gzip
      tls: {}
    coolify-private-realtime-http:
      entryPoints:
        - http
      rule: "Host(\`ws.${DOMAIN}\`)"
      service: noop@internal
      middlewares:
        - coolify-private-force-https
    coolify-private-realtime-https:
      entryPoints:
        - https
      rule: "Host(\`ws.${DOMAIN}\`)"
      service: coolify-private-realtime
      tls: {}
    coolify-private-terminal-http:
      entryPoints:
        - http
      rule: "Host(\`ws.${DOMAIN}\`) && PathPrefix(\`/terminal/ws\`)"
      service: noop@internal
      middlewares:
        - coolify-private-force-https
      priority: 100
    coolify-private-terminal-https:
      entryPoints:
        - https
      rule: "Host(\`ws.${DOMAIN}\`) && PathPrefix(\`/terminal/ws\`)"
      service: coolify-private-terminal
      priority: 100
      tls: {}
  services:
    coolify-private-dashboard:
      loadBalancer:
        servers:
          - url: http://coolify:8080
    coolify-private-realtime:
      loadBalancer:
        servers:
          - url: http://coolify-realtime:6001
    coolify-private-terminal:
      loadBalancer:
        servers:
          - url: http://coolify-realtime:6002
CFG

echo "Private dashboard routes written: ${route_file}"
EOF
}

# coolify_configure_private_tls_dns_script — Emit a host-side certificate
# renewal workflow for private dashboard/realtime routes. The Cloudflare DNS
# credential stays in a root-only host file; Traefik receives only the renewed
# certificate and key through a read-only mount.
coolify_configure_private_tls_dns_script() {
  cat <<'EOF'
set -Eeuo pipefail
: "${PRIVATE_TLS_SECRET_DIR:?PRIVATE_TLS_SECRET_DIR is required}"
: "${CF_ZONE_NAME:?CF_ZONE_NAME is required}"
: "${DOMAIN:?DOMAIN is required}"
: "${PRIVATE_TLS_CA:=letsencrypt}"
: "${ZEROSSL_CA_SERVER:=https://acme.zerossl.com/v2/DV90}"

cf_dns_secret_file="${PRIVATE_TLS_SECRET_DIR}/cf_dns_api_token"
zerossl_kid_secret_file="${PRIVATE_TLS_SECRET_DIR}/zerossl_eab_kid"
zerossl_hmac_secret_file="${PRIVATE_TLS_SECRET_DIR}/zerossl_eab_hmac"
[[ -f "${cf_dns_secret_file}" && ! -L "${cf_dns_secret_file}" ]] \
  || { echo "Cloudflare DNS secret file is missing or is a symlink" >&2; exit 1; }
CF_DNS_API_TOKEN="$(<"${cf_dns_secret_file}")"
: "${CF_DNS_API_TOKEN:?CF_DNS_API_TOKEN is required}"

case "${PRIVATE_TLS_CA}" in
  letsencrypt)
    ;;
  zerossl)
    [[ -f "${zerossl_kid_secret_file}" && ! -L "${zerossl_kid_secret_file}" ]] \
      || { echo "ZeroSSL EAB kid secret file is missing or is a symlink" >&2; exit 1; }
    [[ -f "${zerossl_hmac_secret_file}" && ! -L "${zerossl_hmac_secret_file}" ]] \
      || { echo "ZeroSSL EAB hmac secret file is missing or is a symlink" >&2; exit 1; }
    ZEROSSL_EAB_KID="$(<"${zerossl_kid_secret_file}")"
    ZEROSSL_EAB_HMAC="$(<"${zerossl_hmac_secret_file}")"
    : "${ZEROSSL_EAB_KID:?ZEROSSL_EAB_KID is required when PRIVATE_TLS_CA=zerossl}"
    : "${ZEROSSL_EAB_HMAC:?ZEROSSL_EAB_HMAC is required when PRIVATE_TLS_CA=zerossl}"
    ;;
  *)
    echo "Unsupported PRIVATE_TLS_CA: ${PRIVATE_TLS_CA}" >&2
    exit 1
    ;;
esac

proxy_dir="/data/coolify/proxy"
compose_file="${proxy_dir}/docker-compose.yml"
env_file="${proxy_dir}/.env"
dynamic_dir="${proxy_dir}/dynamic"
default_redirect_file="${dynamic_dir}/default_redirect_503.yaml"
coolify_dynamic_file="${dynamic_dir}/coolify.yaml"
private_route_file="${dynamic_dir}/coolify-private-dashboard.yaml"
private_route_backup_file="${dynamic_dir}/.coolify-private-dashboard.backup"
private_route_absent_marker="${dynamic_dir}/.coolify-private-dashboard.absent"
private_tls_dir="/etc/coolify/private-tls"
certbot_config_dir="${private_tls_dir}/letsencrypt"
certbot_work_dir="${private_tls_dir}/work"
certbot_logs_dir="${private_tls_dir}/logs"
cert_name="coolify-private-tls"
certbot_live_dir="${certbot_config_dir}/live/${cert_name}"
certificate_file="${certbot_live_dir}/fullchain.pem"
private_key_file="${certbot_live_dir}/privkey.pem"
traefik_certificate_dir="/etc/traefik/private-tls/live/${cert_name}"
tls_dynamic_file="${dynamic_dir}/coolify-private-tls.yaml"
cloudflare_credentials_file="${private_tls_dir}/cloudflare.ini"
renew_hook_file="${certbot_config_dir}/renewal-hooks/deploy/coolify-private-tls-reload.sh"
renew_service_file="/etc/systemd/system/coolify-private-tls-renew.service"
renew_timer_file="/etc/systemd/system/coolify-private-tls-renew.timer"

[[ -f "${compose_file}" ]] || { echo "Missing ${compose_file}" >&2; exit 1; }
install -d -m 0700 "${proxy_dir}"

rollback_private_route_file() {
  if [[ -f "${private_route_backup_file}" ]]; then
    mv -f "${private_route_backup_file}" "${private_route_file}"
    rm -f "${private_route_absent_marker}"
  elif [[ -f "${private_route_absent_marker}" ]]; then
    rm -f "${private_route_file}" "${private_route_absent_marker}"
  fi
}

cleanup_private_tls_dns_script() {
  local rc=$?
  if (( rc == 0 )); then
    rm -f "${private_route_backup_file}" "${private_route_absent_marker}"
  else
    rollback_private_route_file || true
  fi
  rm -f -- "${cf_dns_secret_file}" "${zerossl_kid_secret_file}" "${zerossl_hmac_secret_file}" 2>/dev/null || true
  rmdir -- "${PRIVATE_TLS_SECRET_DIR}" 2>/dev/null || true
  return "${rc}"
}

trap cleanup_private_tls_dns_script EXIT

if [[ -L "${env_file}" || ( -e "${env_file}" && ! -f "${env_file}" ) ]]; then
  echo "${env_file} is a symlink or unexpected file" >&2
  exit 1
fi

install -d -m 0700 -o root -g root \
  "${private_tls_dir}" "${certbot_config_dir}" "${certbot_work_dir}" "${certbot_logs_dir}" \
  "${certbot_config_dir}/renewal-hooks/deploy"
( umask 077; printf 'dns_cloudflare_api_token = %s\n' "${CF_DNS_API_TOKEN}" > "${cloudflare_credentials_file}" )
chown root:root "${cloudflare_credentials_file}"
chmod 0600 "${cloudflare_credentials_file}"

if ! command -v certbot >/dev/null 2>&1 || ! python3 -c 'import certbot_dns_cloudflare' >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq certbot python3-certbot-dns-cloudflare
fi

cat > "${renew_hook_file}" <<HOOK
#!/usr/bin/env bash
set -Eeuo pipefail
compose_file="${compose_file}"
if docker compose -f "\${compose_file}" config >/dev/null 2>&1; then
  docker compose -f "\${compose_file}" up -d --no-deps traefik >/dev/null
else
  echo "Invalid Traefik compose while reloading renewed private TLS certificate" >&2
  exit 1
fi
HOOK
chown root:root "${renew_hook_file}"
chmod 0700 "${renew_hook_file}"

cat > "${renew_service_file}" <<UNIT
[Unit]
Description=Renew Coolify private TLS certificates
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=/usr/bin/certbot renew --non-interactive --config-dir ${certbot_config_dir} --work-dir ${certbot_work_dir} --logs-dir ${certbot_logs_dir} --deploy-hook ${renew_hook_file}
UNIT
chown root:root "${renew_service_file}"
chmod 0644 "${renew_service_file}"

cat > "${renew_timer_file}" <<UNIT
[Unit]
Description=Daily Coolify private TLS renewal

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
UNIT
chown root:root "${renew_timer_file}"
chmod 0644 "${renew_timer_file}"

certbot_args=(
  certonly
  --non-interactive
  --agree-tos
  --keep-until-expiring
  --expand
  --email "coolify-admin@${CF_ZONE_NAME}"
  --cert-name "${cert_name}"
  --dns-cloudflare
  --dns-cloudflare-credentials "${cloudflare_credentials_file}"
  --dns-cloudflare-propagation-seconds 30
  --config-dir "${certbot_config_dir}"
  --work-dir "${certbot_work_dir}"
  --logs-dir "${certbot_logs_dir}"
  --deploy-hook "${renew_hook_file}"
  -d "${DOMAIN}"
  -d "ws.${DOMAIN}"
)
if [[ "${PRIVATE_TLS_CA}" == "zerossl" ]]; then
  ZEROSSL_EAB_KID="$(<"${zerossl_kid_secret_file}")"
  ZEROSSL_EAB_HMAC="$(<"${zerossl_hmac_secret_file}")"
  certbot_args+=(--server "${ZEROSSL_CA_SERVER}" --eab-kid "${ZEROSSL_EAB_KID}" --eab-hmac-key "${ZEROSSL_EAB_HMAC}")
fi
certbot "${certbot_args[@]}"
[[ -s "${certificate_file}" && -s "${private_key_file}" ]] \
  || { echo "Certbot did not produce the private TLS certificate and key" >&2; exit 1; }
chmod 0640 "${private_key_file}"

cat > "${tls_dynamic_file}" <<CFG
# This file is managed by secure-ubuntu-paas; certificates are renewed by the host.
tls:
  certificates:
    - certFile: ${traefik_certificate_dir}/fullchain.pem
      keyFile: ${traefik_certificate_dir}/privkey.pem
CFG
chown root:root "${tls_dynamic_file}"
chmod 0640 "${tls_dynamic_file}"

systemctl daemon-reload
systemctl enable --now coolify-private-tls-renew.timer

reconcile_private_tls_compose() {
  python3 - "${compose_file}" "${private_tls_dir}" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
private_tls_dir = Path(sys.argv[2])
env_path = Path("/data/coolify/proxy/.env")
if env_path.exists():
    existing_env = env_path.read_text().splitlines()
    existing_env = [
        line for line in existing_env
        if not re.match(r"^(?:CLOUDFLARE_DNS_API_TOKEN|CF_DNS_API_TOKEN)=", line)
        and not line.startswith("TRAEFIK_CERTIFICATESRESOLVERS_PRIVATEDNS_ACME_EAB_")
    ]
    if existing_env:
        env_path.write_text("\n".join(existing_env) + "\n")
    else:
        env_path.unlink()

text = path.read_text()
lines = text.splitlines(keepends=True)

service_start = next((idx for idx, line in enumerate(lines) if re.match(r"^  traefik:\s*$", line)), None)
if service_start is None:
    raise SystemExit("Traefik service block not found in docker-compose.yml")

service_end = service_start + 1
while service_end < len(lines) and not re.match(r"^  [A-Za-z0-9_-]+:\s*$", lines[service_end]):
    service_end += 1

service_lines = lines[service_start + 1 : service_end]
scrubbed_service_lines = []
resolver_flag_pattern = re.compile(r"^ {6}- '?--certificatesresolvers\.privatedns\..*'?\s*$")
for line in service_lines:
    if re.match(r"^ {6}- (?:CLOUDFLARE_DNS_API_TOKEN|CF_DNS_API_TOKEN)=.*$", line):
        continue
    if re.match(r"^ {6}- .*certificatesresolvers\.letsencrypt\..*$", line):
        continue
    if resolver_flag_pattern.match(line):
        continue
    scrubbed_service_lines.append(line)
service_lines = scrubbed_service_lines

def find_section(block_lines, key):
    prefix = f"    {key}:"
    for idx, line in enumerate(block_lines):
        if line.startswith(prefix):
            return idx
    return None

def section_end(block_lines, start_idx):
    idx = start_idx + 1
    while idx < len(block_lines):
        if re.match(r"^    [A-Za-z0-9_-]+:\s*$", block_lines[idx]):
            break
        idx += 1
    return idx

env_idx = find_section(service_lines, "env_file")
if env_idx is not None:
    env_end = section_end(service_lines, env_idx)
    env_items = [
        line for line in service_lines[env_idx + 1 : env_end]
        if line.strip().removeprefix("-").strip() != str(env_path)
    ]
    if env_items:
        service_lines = service_lines[: env_idx + 1] + env_items + service_lines[env_end:]
    else:
        service_lines = service_lines[:env_idx] + service_lines[env_end:]

command_idx = find_section(service_lines, "command")
if command_idx is not None:
    command_end = section_end(service_lines, command_idx)
    command_items = [
        line for line in service_lines[command_idx + 1 : command_end]
        if not resolver_flag_pattern.match(line)
    ]
    service_lines = service_lines[: command_idx + 1] + command_items + service_lines[command_end:]

mount_line = f"      - {private_tls_dir}:/etc/traefik/private-tls:ro\n"
volumes_idx = find_section(service_lines, "volumes")
if volumes_idx is None:
    insert_idx = find_section(service_lines, "command")
    if insert_idx is None:
        insert_idx = len(service_lines)
    service_lines[insert_idx:insert_idx] = ["    volumes:\n", mount_line]
else:
    volumes_end = section_end(service_lines, volumes_idx)
    volume_items = service_lines[volumes_idx + 1 : volumes_end]
    if mount_line not in volume_items:
        volume_items.append(mount_line)
        service_lines = service_lines[: volumes_idx + 1] + volume_items + service_lines[volumes_end:]

lines = lines[: service_start + 1] + service_lines + lines[service_end:]
path.write_text("".join(lines))
PY
}

reconcile_private_tls_compose

scrub_default_redirect_public_resolver() {
  [[ -f "${default_redirect_file}" ]] || return 0
  python3 - "${default_redirect_file}" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text()
text = text.replace("      tls:\n        certResolver: letsencrypt\n", "")
path.write_text(text)
PY
}

scrub_coolify_public_https_routers() {
  [[ -f "${coolify_dynamic_file}" ]] || return 0
  python3 - "${coolify_dynamic_file}" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
text = path.read_text()
for router_name in ("coolify-http", "coolify-https", "coolify-realtime-ws", "coolify-realtime-wss", "coolify-terminal-ws", "coolify-terminal-wss"):
    pattern = rf"(?ms)^    {router_name}:\n(?:      .*\n|        .*\n)*"
    text = re.sub(pattern, "", text)
path.write_text(text)
PY
}

public_router_state_is_clean() {
  ! grep -Eq '^[[:space:]]*certResolver:[[:space:]]*letsencrypt[[:space:]]*$' "${default_redirect_file}" 2>/dev/null \
    && ! grep -Eq '^[[:space:]]*coolify-(http|https|realtime-ws|realtime-wss|terminal-ws|terminal-wss):[[:space:]]*$|^[[:space:]]*certresolver:[[:space:]]*letsencrypt[[:space:]]*$' "${coolify_dynamic_file}" 2>/dev/null
}

enforce_private_router_scrub() {
  scrub_default_redirect_public_resolver
  scrub_coolify_public_https_routers
  public_router_state_is_clean
}

# Coolify regenerates this catchall file with a public resolver; remove it in
# tunnel mode so wildcard traffic cannot trigger public ACME flows.
enforce_private_router_scrub || true

if docker compose -f "${compose_file}" config >/dev/null 2>&1; then
  docker compose -f "${compose_file}" up -d >/dev/null
else
  echo "Invalid Traefik compose generated at ${compose_file}" >&2
  exit 1
fi

for _ in $(seq 1 30); do
  if enforce_private_router_scrub; then
    break
  fi
  sleep 1
done

if ! public_router_state_is_clean; then
  echo "Public Traefik HTTPS routes/resolvers remained in ${dynamic_dir}" >&2
  exit 1
fi

wait_for_private_tls_ready() {
  local host="vps.invalid"
  local ws_host="ws.vps.invalid"
  local attempts=120
  local delay=5
  local attempt
  local dashboard_code dashboard_code_insecure dashboard_subject dashboard_issuer
  local ws_code ws_code_insecure ws_subject ws_issuer

  if ! command -v curl >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1; then
    return 0
  fi

  probe_private_tls_host() {
    local prefix="${1:?probe_private_tls_host requires prefix}"
    local probe_host="${2:?probe_private_tls_host requires host}"
    local probe_path="${3:?probe_private_tls_host requires path}"
    local ready_regex="${4:?probe_private_tls_host requires ready regex}"
    local code insecure_code cert_meta cert_subject cert_issuer

    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
      --resolve "${probe_host}:443:127.0.0.1" "https://${probe_host}${probe_path}" 2>/dev/null || true)"
    insecure_code="$(curl -k -s -o /dev/null -w '%{http_code}' --max-time 10 \
      --resolve "${probe_host}:443:127.0.0.1" "https://${probe_host}${probe_path}" 2>/dev/null || true)"
    code="${code:-000}"
    insecure_code="${insecure_code:-000}"
    code="${code:0:3}"
    insecure_code="${insecure_code:0:3}"

    cert_meta="$(printf '' | openssl s_client -connect 127.0.0.1:443 -servername "${probe_host}" -showcerts 2>/dev/null \
      | openssl x509 -noout -subject -issuer -ext subjectAltName 2>/dev/null || true)"
    cert_subject="$(awk -F= '/^subject=/{print $2; exit}' <<< "${cert_meta}" | sed 's/^ *//')"
    cert_issuer="$(awk -F= '/^issuer=/{print $2; exit}' <<< "${cert_meta}" | sed 's/^ *//')"

    printf -v "${prefix}_code" '%s' "${code}"
    printf -v "${prefix}_code_insecure" '%s' "${insecure_code}"
    printf -v "${prefix}_subject" '%s' "${cert_subject}"
    printf -v "${prefix}_issuer" '%s' "${cert_issuer}"

    if [[ "${code}" =~ ${ready_regex} ]] \
      && ! grep -Fq "TRAEFIK DEFAULT CERT" <<< "${cert_meta}" \
      && grep -Fq "DNS:${probe_host}" <<< "${cert_meta}"; then
      return 0
    fi

    return 1
  }

  host="${DOMAIN}"
  ws_host="ws.${DOMAIN}"
  for (( attempt=1; attempt<=attempts; attempt++ )); do
    enforce_private_router_scrub || true
    if probe_private_tls_host "dashboard" "${host}" "/api/v1/health" '^2[0-9][0-9]$' \
      && probe_private_tls_host "ws" "${ws_host}" "/" '^[234][0-9][0-9]$' \
      && public_router_state_is_clean; then
      echo "Private TLS certificates ready for ${host} and ${ws_host} (dashboard=${dashboard_code}, websocket=${ws_code})."
      return 0
    fi

    if (( attempt == 1 || attempt % 12 == 0 )); then
      if [[ "${dashboard_code_insecure}" =~ ^2[0-9][0-9]$ && ! "${dashboard_code}" =~ ^2[0-9][0-9]$ ]]; then
        echo "Waiting for trusted private TLS on ${host}: route is up behind untrusted cert (verified=${dashboard_code}, insecure=${dashboard_code_insecure}, subject=${dashboard_subject:-unknown}, issuer=${dashboard_issuer:-unknown}, attempt=${attempt}/${attempts})."
      else
        echo "Waiting for trusted private TLS on ${host}: verified=${dashboard_code}, insecure=${dashboard_code_insecure}, subject=${dashboard_subject:-unknown}, issuer=${dashboard_issuer:-unknown}, attempt=${attempt}/${attempts}."
      fi
      echo "Waiting for trusted private TLS on ${ws_host}: verified=${ws_code:-000}, insecure=${ws_code_insecure:-000}, subject=${ws_subject:-unknown}, issuer=${ws_issuer:-unknown}, attempt=${attempt}/${attempts}."
    fi

    if (( attempt < attempts )); then
      sleep "${delay}"
    fi
  done

  echo "Timed out waiting for trusted private TLS on ${host}; verified=${dashboard_code:-000}, insecure=${dashboard_code_insecure:-000}, subject=${dashboard_subject:-unknown}, issuer=${dashboard_issuer:-unknown}" >&2
  echo "Timed out waiting for trusted private TLS on ${ws_host}; verified=${ws_code:-000}, insecure=${ws_code_insecure:-000}, subject=${ws_subject:-unknown}, issuer=${ws_issuer:-unknown}" >&2
  return 1
}

wait_for_private_tls_ready
enforce_private_router_scrub || true
if ! public_router_state_is_clean; then
  echo "Public Coolify HTTPS routers remained in ${coolify_dynamic_file}" >&2
  exit 1
fi

echo "Private TLS certificate renewal configured by the host; the Traefik service receives no Cloudflare DNS credential."
EOF
}
