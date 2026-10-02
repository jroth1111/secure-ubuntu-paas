#!/usr/bin/env bash
# overlays/coolify/modules/server-config.sh — Server-side config heredoc generators
# (private route removal, Coolify SSH key, host.docker.internal, cloudflared).
# Sourced by coolify-common.sh; do not execute directly.

[[ "${BASH_SOURCE[0]}" != "${0}" ]] \
  || { printf 'Source this file, do not execute it.\n' >&2; exit 1; }

# coolify_remove_private_dashboard_routes_script — Emit host-side script to
# remove managed private dashboard route file when not in tunnel mode.
coolify_remove_private_dashboard_routes_script() {
  cat <<'EOF'
set -Eeuo pipefail
route_file="/data/coolify/proxy/dynamic/coolify-private-dashboard.yaml"
route_backup_file="/data/coolify/proxy/dynamic/.coolify-private-dashboard.backup"
route_absent_marker="/data/coolify/proxy/dynamic/.coolify-private-dashboard.absent"
if [[ -f "${route_file}" || -f "${route_backup_file}" || -f "${route_absent_marker}" ]]; then
  rm -f "${route_file}" "${route_backup_file}" "${route_absent_marker}"
  echo "Removed private dashboard routes: ${route_file}"
else
  echo "Private dashboard routes already absent: ${route_file}"
fi
EOF
}

# coolify_add_coolify_root_key_script — Emit host-side script that inserts Coolify's
# generated SSH public key into /root/.ssh/authorized_keys idempotently.
coolify_add_coolify_root_key_script() {
  cat <<'EOF'
set -Eeuo pipefail
key_dir="/data/coolify/ssh/keys"
keyfile="$(ls "${key_dir}"/ssh_key@* "${key_dir}"/id.root@* 2>/dev/null | head -1 || true)"
if [[ -z "${keyfile}" ]]; then
  keyfile="$(find "${key_dir}" -maxdepth 1 -type f ! -name '*.pub' 2>/dev/null | head -1 || true)"
fi
[[ -n "${keyfile}" ]] || { echo "No Coolify SSH key found — skipping"; exit 0; }
pubkey="$(ssh-keygen -y -f "${keyfile}")"
auth="/root/.ssh/authorized_keys"
mkdir -p /root/.ssh && chmod 700 /root/.ssh
touch "${auth}" && chmod 600 "${auth}"
tmp="$(mktemp)"
awk '
  $1 ~ /^(ssh-(rsa|ed25519|dss)|ecdsa-[^[:space:]]+)$/ && NF >= 2 {
    if (!seen[$2]++) {
      print $1 " " $2
    }
  }
' "${auth}" > "${tmp}" 2>/dev/null || true
key_data="$(awk '{print $2}' <<< "${pubkey}")"
if awk '{print $2}' "${tmp}" 2>/dev/null | grep -qxF "${key_data}"; then
  echo "Coolify key already in root authorized_keys"
else
  printf '%s\n' "${pubkey}" >> "${tmp}"
  echo "Coolify key added to root authorized_keys"
fi
install -m 600 "${tmp}" "${auth}"
rm -f "${tmp}"
EOF
}

# coolify_fix_host_docker_internal_script — Emit host-side script that patches
# host.docker.internal in Coolify compose files to the current coolify bridge gateway.
coolify_fix_host_docker_internal_script() {
  cat <<'EOF'
set -Eeuo pipefail
compose_yml="/data/coolify/source/docker-compose.yml"
[[ -f "${compose_yml}" ]] || { echo "docker-compose.yml not found — skipping"; exit 0; }
gateway="$(docker network inspect coolify --format '{{range .IPAM.Config}}{{.Subnet}} {{.Gateway}} {{end}}' 2>/dev/null \
  | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | grep -v '/[0-9]' | head -1 || true)"
if [[ -z "${gateway}" ]]; then
  echo "Cannot determine coolify network gateway — skipping host.docker.internal fix"
  exit 0
fi
current="$(grep -m1 'host\.docker\.internal:' "${compose_yml}" | awk -F: '{print $NF}' | tr -d ' ' || true)"
if [[ "${current}" == "${gateway}" ]]; then
  echo "host.docker.internal already set to ${gateway}"
  exit 0
fi
sed -i "s|host\.docker\.internal:.*|host.docker.internal:${gateway}|g" "${compose_yml}"
echo "Patched host.docker.internal → ${gateway}"
docker compose -f /data/coolify/source/docker-compose.yml \
               -f /data/coolify/source/docker-compose.prod.yml \
               up -d --force-recreate coolify soketi 2>&1 | tail -5
EOF
}

# coolify_install_cloudflared_script — Emit host-side script to install cloudflared
# with apt first, then Cloudflare repo fallback.
coolify_install_cloudflared_script() {
  cat <<'EOF'
set -Eeuo pipefail
export DEBIAN_FRONTEND=noninteractive
if bash -c "apt-get update -qq && apt-get install -y -qq cloudflared" 2>/dev/null; then
  exit 0
fi
echo "Trying Cloudflare repository..."
bash -o pipefail -c "curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null"
bash -c "echo \"deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared \$(lsb_release -cs) main\" | tee /etc/apt/sources.list.d/cloudflared.list >/dev/null"
bash -c "apt-get update -qq && apt-get install -y -qq cloudflared"
EOF
}

# coolify_configure_cloudflared_script — Emit host-side script to write tunnel creds/config
# and start cloudflared service. Requires TUNNEL_ID, TUNNEL_SECRET_FILE,
# TUNNEL_SECRET_DIR, CF_ACCOUNT_ID, DOMAIN, APP_DOMAIN, CF_ZONE_NAME in environment.
coolify_configure_cloudflared_script() {
  cat <<'EOF'
set -Eeuo pipefail
: "${TUNNEL_ID:?TUNNEL_ID is required}"
: "${TUNNEL_SECRET_FILE:?TUNNEL_SECRET_FILE is required}"
: "${TUNNEL_SECRET_DIR:?TUNNEL_SECRET_DIR is required}"
: "${CF_ACCOUNT_ID:?CF_ACCOUNT_ID is required}"
: "${DOMAIN:?DOMAIN is required}"
: "${APP_DOMAIN:?APP_DOMAIN is required}"
: "${CF_ZONE_NAME:?CF_ZONE_NAME is required}"

[[ -f "${TUNNEL_SECRET_FILE}" && ! -L "${TUNNEL_SECRET_FILE}" ]] \
  || { echo "TUNNEL_SECRET_FILE is missing or is a symlink" >&2; exit 1; }

cleanup_cloudflared_secret() {
  local rc=$?
  rm -f -- "${TUNNEL_SECRET_FILE}" 2>/dev/null || true
  rmdir -- "${TUNNEL_SECRET_DIR}" 2>/dev/null || true
  return "${rc}"
}
trap cleanup_cloudflared_secret EXIT

creds_json="$(jq -n --arg id "${TUNNEL_ID}" --rawfile secret "${TUNNEL_SECRET_FILE}" --arg account "${CF_ACCOUNT_ID}" \
  '{AccountTag:$account,TunnelID:$id,TunnelSecret:($secret | rtrimstr("\n"))}')"
cloudflared_dir="/etc/cloudflared"
if [[ -L "${cloudflared_dir}" || ( -e "${cloudflared_dir}" && ! -d "${cloudflared_dir}" ) ]]; then
  echo "${cloudflared_dir} is a symlink or unexpected file" >&2
  exit 1
fi
install -d -m 0700 -o root -g root "${cloudflared_dir}"
credential_path="${cloudflared_dir}/${TUNNEL_ID}.json"
if [[ -L "${credential_path}" || ( -e "${credential_path}" && ! -f "${credential_path}" ) ]]; then
  echo "${credential_path} is a symlink or unexpected file" >&2
  exit 1
fi
creds_tmp="$(mktemp "${cloudflared_dir}/.credentials.XXXXXX")"
( umask 077; printf '%s' "${creds_json}" > "${creds_tmp}" )
chown root:root "${creds_tmp}"
chmod 0600 "${creds_tmp}"
mv -f "${creds_tmp}" "${credential_path}"

config_path="${cloudflared_dir}/config.yml"
if [[ -L "${config_path}" || ( -e "${config_path}" && ! -f "${config_path}" ) ]]; then
  echo "${config_path} is a symlink or unexpected file" >&2
  exit 1
fi
config_tmp="$(mktemp "${cloudflared_dir}/.config.XXXXXX")"
cat > "${config_tmp}" <<CFG
tunnel: ${TUNNEL_ID}
credentials-file: /etc/cloudflared/${TUNNEL_ID}.json
metrics: 127.0.0.1:2000

ingress:
  - hostname: ${DOMAIN}
    service: http_status:404
  - hostname: ws.${DOMAIN}
    service: http_status:404
  - hostname: "*.${APP_DOMAIN}"
    service: http://localhost:80
  - service: http_status:404
CFG
chown root:root "${config_tmp}"
chmod 0600 "${config_tmp}"
mv -f "${config_tmp}" "${config_path}"

cloudflared service install 2>/dev/null || true
systemctl enable --now cloudflared
for attempt in $(seq 1 30); do
  if systemctl is-active --quiet cloudflared 2>/dev/null \
    && curl -sf --max-time 3 http://127.0.0.1:2000/ready >/dev/null 2>&1; then
    exit 0
  fi
  (( attempt < 30 )) || break
  sleep 2
done

echo "cloudflared service did not reach a ready state on 127.0.0.1:2000/ready" >&2
journalctl -u cloudflared -n 20 --no-pager >&2 || true
exit 1
EOF
}
