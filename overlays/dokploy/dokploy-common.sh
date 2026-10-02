#!/usr/bin/env bash
# overlays/dokploy/dokploy-common.sh — Dokploy-overlay shared phase logic.
# Source this file; do not execute it directly.
# Requires: set -Eeuo pipefail in the caller.

[[ "${BASH_SOURCE[0]}" != "${0}" ]] \
  || { printf 'Source this file, do not execute it.\n' >&2; exit 1; }
if [[ -z "${BASH_VERSINFO:-}" || "${BASH_VERSINFO[0]}" -lt 4 ]]; then
  printf 'Bash 4+ is required (found %s). On macOS use Homebrew bash and run via its absolute path.\n' "${BASH_VERSION:-unknown}" >&2
  return 1
fi
[[ -z "${_DOKPLOY_COMMON_LOADED:-}" ]] || return 0
_DOKPLOY_COMMON_LOADED=1

_dir="$(dirname "${BASH_SOURCE[0]}")"

# The operator explicitly chose automatic latest-stable Dokploy updates. Swarm
# resolves this mutable tag to a digest for each deployment, while the managed
# updater periodically refreshes it and records the resolved digest for the
# validator. Traefik follows only its approved minor series, also by digest.
DOKPLOY_IMAGE="dokploy/dokploy:latest"
DOKPLOY_SWARM_UNLOCK_HANDOFF_FILE="/run/secure-ubuntu-paas-dokploy-swarm-unlock-key"

# shellcheck source=../../lib/common.sh
# shellcheck disable=SC1091
source "${_dir}/../../lib/common.sh"

finalize_dokploy_inputs() {
  # Dokploy uses direct public 80/443 app ingress and Tailscale-only admin/API
  # access. Cloudflare is not managed by this adapter; DOMAIN is optional and
  # only recorded as the intended public app domain when supplied.
  DEPLOY_MODE="standard"
  APP_DOMAIN_MODE=""
  PRIVATE_TLS_CA=""
}

collect_dokploy_setup_inputs() {
  [[ -n "${SERVER_IP}" ]]   || prompt_value  SERVER_IP "Server public IP" "" "${IPV4_RE}"
  [[ -n "${ADMIN_USER}" ]]  || prompt_value  ADMIN_USER "Admin username" "dokployadmin" "${LINUX_USER_RE}"
  [[ -n "${PUBKEY_FILE}" ]] || prompt_value  PUBKEY_FILE "SSH public key file" "${HOME}/.ssh/id_ed25519.pub"
  [[ -n "${TAILSCALE_AUTH_KEY}" ]] || prompt_secret TAILSCALE_AUTH_KEY "Tailscale auth key (tskey-auth-...)"
  [[ -n "${SWAP_SIZE}" ]]   || SWAP_SIZE="2G"
  if [[ -z "${DOKPLOY_ENROLLMENT_SOURCE_IP:-}" && -n "${SSH_CONNECTION:-}" ]]; then
    local ssh_source_ip="${SSH_CONNECTION%% *}"
    if is_tailscale_ipv4 "${ssh_source_ip}"; then
      DOKPLOY_ENROLLMENT_SOURCE_IP="${ssh_source_ip}"
    fi
  fi
  if [[ -z "${DOKPLOY_ENROLLMENT_SOURCE_IP:-}" ]] && ! is_true "${PREFLIGHT_ONLY:-false}"; then
    if is_true "${AUTO_YES:-false}"; then
      die "Dokploy enrollment source is required in non-interactive mode. Set DOKPLOY_ENROLLMENT_SOURCE_IP or use --dokploy-enrollment-source-ip."
    fi
    prompt_value DOKPLOY_ENROLLMENT_SOURCE_IP \
      "Operator laptop Tailscale IPv4 for guarded first-admin enrollment" "" "${IPV4_RE}"
  fi
  if [[ -z "${SERVER_TIMEZONE:-}" ]]; then
    if is_true "${AUTO_YES:-false}"; then
      die "Server timezone is required in non-interactive mode. Set SERVER_TIMEZONE or use --server-timezone."
    fi
    prompt_value SERVER_TIMEZONE "Server timezone (IANA, e.g. Australia/Melbourne)" "UTC" "${TIMEZONE_RE}"
  fi
  finalize_dokploy_inputs
}

dokploy_remove_stale_coolify_dashboard_ufw_script() {
  cat <<'EOF'
set -Eeuo pipefail
while true; do
  line="$(ufw status numbered 2>/dev/null | grep -E 'coolify-hardening-(dashboard|soketi|terminal)' | head -1 || true)"
  [[ -n "${line}" ]] || break
  num="$(sed -n 's/^\[[[:space:]]*\([0-9][0-9]*\)\].*/\1/p' <<< "${line}")"
  [[ -n "${num}" ]] || break
  ufw --force delete "${num}"
done
EOF
}

dokploy_root_tailscale_reconcile_script() {
  printf 'admin_pubkey=%q\n' "$ADMIN_PUBKEY"
  printf 'admin_user=%q\n' "${ADMIN_USER:-dokployadmin}"
  cat <<'EOF'
set -Eeuo pipefail
[[ -n "$admin_pubkey" ]] || { echo "Dokploy root Tailscale policy requires the admin public key" >&2; exit 1; }

# The named account is intentionally non-privileged and non-login. All
# Dokploy SSH and privileged orchestration runs through root@Tailscale with
# the supplied key.
if id -nG "$admin_user" 2>/dev/null | tr ' ' '\n' | grep -qx sudo; then
  if command -v gpasswd >/dev/null 2>&1; then
    gpasswd -d "$admin_user" sudo >/dev/null
  else
    deluser "$admin_user" sudo >/dev/null
  fi
fi
rm -f "/etc/sudoers.d/$admin_user"
usermod -s /usr/sbin/nologin "$admin_user"
passwd -l "$admin_user" >/dev/null 2>&1 || true
admin_home="$(getent passwd "$admin_user" | cut -d: -f6)"
[[ -n "$admin_home" && -d "$admin_home" && ! -L "$admin_home" ]] \
  || { echo "Unsafe Dokploy metadata account home: ${admin_home:-missing}" >&2; exit 1; }
admin_ssh_dir="$admin_home/.ssh"
admin_auth="$admin_ssh_dir/authorized_keys"
if [[ -L "$admin_ssh_dir" || ( -e "$admin_ssh_dir" && ! -d "$admin_ssh_dir" ) ]]; then
  echo "Unsafe Dokploy metadata account SSH directory: $admin_ssh_dir" >&2
  exit 1
fi
if [[ -e "$admin_auth" || -L "$admin_auth" ]]; then
  if [[ -L "$admin_auth" || -f "$admin_auth" ]]; then
    rm -f -- "$admin_auth"
  else
    echo "Unsupported Dokploy metadata account authorized_keys: $admin_auth" >&2
    exit 1
  fi
fi

# Removing the conventional sudo group/file is not sufficient: sudoers can
# grant the account through /etc/sudoers, another drop-in, an included file, or
# a non-obvious group.  Reuse the same effective-policy query as bootstrap and
# the validator, and fail closed if sudo cannot prove an explicit denial.
source /root/base/sudo_policy.sh
if sudo_effective_grant_state "$admin_user"; then
  echo "$admin_user retains an effective sudo grant" >&2
  exit 1
else
  sudo_state_rc=$?
  (( sudo_state_rc == 1 )) || { echo "Unable to prove $admin_user has no effective sudo grant" >&2; exit 1; }
fi

root_ssh_dir="/root/.ssh"
root_auth="$root_ssh_dir/authorized_keys"
if [[ -L "$root_ssh_dir" || ( -e "$root_ssh_dir" && ! -d "$root_ssh_dir" ) ]]; then
  echo "$root_ssh_dir is a symlink or unexpected file" >&2
  exit 1
fi
install -d -m 0700 -o root -g root "$root_ssh_dir"
if [[ -L "$root_auth" || ( -e "$root_auth" && ! -f "$root_auth" ) ]]; then
  echo "$root_auth is a symlink or unexpected file" >&2
  exit 1
fi
root_auth_tmp="$(mktemp "$root_ssh_dir/.authorized_keys.XXXXXX")"
printf '%s\n' "$admin_pubkey" > "$root_auth_tmp"
chown root:root "$root_auth_tmp"
chmod 0600 "$root_auth_tmp"
mv -f "$root_auth_tmp" "$root_auth"
chown root:root "$root_auth"
chmod 0600 "$root_auth"

ssh_dropin="/etc/ssh/sshd_config.d/00-base-hardening.conf"
[[ -f "$ssh_dropin" ]] || { echo "Missing $ssh_dropin" >&2; exit 1; }
begin_marker="# BEGIN secure-ubuntu-paas Dokploy root Tailscale policy"
end_marker="# END secure-ubuntu-paas Dokploy root Tailscale policy"
tmp_dropin="$(mktemp)"
awk -v begin="$begin_marker" -v end="$end_marker" '
  $0 == begin { skip=1; next }
  $0 == end { skip=0; next }
  !skip { print }
' "$ssh_dropin" > "$tmp_dropin"
normalized_dropin="$(mktemp)"
awk '
  BEGIN { before_match=1; replaced=0 }
  before_match && /^Match[[:space:]]/ { before_match=0 }
  before_match && !replaced && /^AllowUsers[[:space:]]/ {
    print "AllowUsers root"
    replaced=1
    next
  }
  { print }
  END {
    if (!replaced) {
      exit 42
    }
  }
' "$tmp_dropin" > "$normalized_dropin" \
  || { rm -f "$tmp_dropin" "$normalized_dropin"; echo "Missing global AllowUsers policy in $ssh_dropin" >&2; exit 1; }
rm -f "$tmp_dropin"
mv "$normalized_dropin" "$ssh_dropin"

tailscale_cidr="$(sed -n 's/^tailscale_cidr=//p' /var/lib/server-hardening/state 2>/dev/null | head -1)"
if [[ -z "$tailscale_cidr" ]]; then
  tailscale_cidr="100.64.0.0/10"
fi
cat >> "$ssh_dropin" <<POLICY
$begin_marker
# Dokploy root emergency access is Tailscale-only and key-only.
Match Address $tailscale_cidr
    PermitRootLogin prohibit-password
    AllowUsers root
    KbdInteractiveAuthentication no
    AuthenticationMethods publickey
$end_marker
POLICY

sshd -t
tailscale_ip="$(tailscale ip -4 2>/dev/null || true)"
[[ -n "$tailscale_ip" ]] || { echo "Tailscale IPv4 unavailable" >&2; exit 1; }
effective_global="$(sshd -T)"
grep -q '^permitrootlogin no$' <<< "$effective_global"
grep -qE '^allowusers .*\broot\b' <<< "$effective_global"
! grep -qE "^allowusers .*\\b$admin_user\\b" <<< "$effective_global"
match_tailscale="$(sshd -T -C "addr=$tailscale_ip,user=root,host=localhost,laddr=$tailscale_ip")"
grep -qE '^permitrootlogin (prohibit-password|without-password)$' <<< "$match_tailscale"
grep -q '^passwordauthentication no$' <<< "$match_tailscale"
grep -q '^kbdinteractiveauthentication no$' <<< "$match_tailscale"
grep -q '^authenticationmethods publickey$' <<< "$match_tailscale"
grep -qE '^allowusers .*\broot\b' <<< "$match_tailscale"
! grep -qE "^allowusers .*\\b$admin_user\\b" <<< "$match_tailscale"
match_local="$(sshd -T -C addr=127.0.0.1,user=root,host=localhost,laddr=127.0.0.1)"
! grep -qE '^permitrootlogin (prohibit-password|without-password|yes)$' <<< "$match_local"
match_external="$(sshd -T -C addr=203.0.113.1,user=root,host=example.com,laddr=0.0.0.0)"
! grep -qE '^permitrootlogin (prohibit-password|without-password|yes)$' <<< "$match_external"

systemctl reload ssh 2>/dev/null || systemctl reload sshd
echo "Dokploy root SSH policy reconciled: key-only over Tailscale ($tailscale_ip)"
EOF
}

dokploy_dashboard_ufw_policy_script() {
  # Full Dokploy host port policy:
  #  - dashboard/API 3000/tcp: the provisioning operator's Tailscale IPv4
  #    only until the first account exists and every account has TOTP; the
  #    whole permitted tailnet may reach it only after that enrollment gate
  #  - Swarm control/data plane (2377/tcp mgmt, 7946/tcp+udp gossip,
  #    4789/udp VXLAN): closed on this single-node deployment. A future
  #    multi-node expansion must add source-scoped tailnet rules deliberately;
  #    never leave these privileged ports open to every tailnet peer.
  # Explicit denies are belt-and-braces over the default-deny inbound policy
  # and keep the intent visible in `ufw status`.
  printf 'enrollment_source_ip=%q\n' "${DOKPLOY_ENROLLMENT_SOURCE_IP:-}"
  cat <<'EOF'
set -Eeuo pipefail

is_tailscale_ipv4() {
  local ip="$1" a b c d
  IFS=. read -r a b c d <<< "${ip}"
  [[ "${a}" == "100" && "${b}" =~ ^[0-9]+$ && "${c}" =~ ^[0-9]+$ && "${d}" =~ ^[0-9]+$ ]] \
    || return 1
  (( b >= 64 && b <= 127 && c <= 255 && d <= 255 ))
}

is_tailscale_ipv4 "${enrollment_source_ip}" \
  || { echo "A valid operator Tailscale IPv4 is required for guarded Dokploy enrollment" >&2; exit 1; }

# Remove both the historical all-tailnet rule and any prior staged enrollment
# rule before rebuilding policy from current account state.  Numbered deletion
# is used so a source-address change cannot leave an obsolete allow behind.
while true; do
  managed_line="$(ufw status numbered 2>/dev/null \
    | grep -E 'dokploy-(dashboard-tailscale|enrollment-operator)' | head -1 || true)"
  [[ -n "${managed_line}" ]] || break
  managed_num="$(sed -n 's/^\[[[:space:]]*\([0-9][0-9]*\)\].*/\1/p' <<< "${managed_line}")"
  [[ -n "${managed_num}" ]] || { echo "Could not parse managed Dokploy UFW rule" >&2; exit 1; }
  ufw --force delete "${managed_num}" >/dev/null
done
ufw delete allow 3000/tcp >/dev/null 2>&1 || true
ufw delete limit 3000/tcp >/dev/null 2>&1 || true

enrollment_complete="false"
pg_cid="$(docker ps -q --filter name=dokploy-postgres 2>/dev/null | head -1 || true)"
if [[ -n "${pg_cid}" ]]; then
  account_table_exists="$(docker exec "${pg_cid}" psql -U dokploy -d dokploy -tAc \
    "SELECT count(*) FROM pg_catalog.pg_tables WHERE schemaname='public' AND tablename='user'" \
    2>/dev/null | tr -d '[:space:]' || true)"
  if [[ "${account_table_exists}" == "1" ]]; then
    account_count="$(docker exec "${pg_cid}" psql -U dokploy -d dokploy -tAc \
      'SELECT count(*) FROM "user"' 2>/dev/null | tr -d '[:space:]' || true)"
    no2fa="$(docker exec "${pg_cid}" psql -U dokploy -d dokploy -tAc \
      'SELECT count(*) FROM "user" u WHERE u.two_factor_enabled IS DISTINCT FROM TRUE OR NOT EXISTS (SELECT 1 FROM two_factor tf WHERE tf.user_id = u.id AND tf.verified IS TRUE AND length(tf.secret) > 0)' \
      2>/dev/null | tr -d '[:space:]' || true)"
    if [[ "${account_count}" =~ ^[1-9][0-9]*$ && "${no2fa}" == "0" ]]; then
      enrollment_complete="true"
    fi
  fi
fi

if [[ "${enrollment_complete}" == "true" ]]; then
  ufw allow in on tailscale0 proto tcp to any port 3000 comment "dokploy-dashboard-tailscale" >/dev/null
  echo "Dokploy enrollment complete: dashboard enabled on tailscale0:3000"
else
  ufw allow in on tailscale0 from "${enrollment_source_ip}" proto tcp to any port 3000 \
    comment "dokploy-enrollment-operator" >/dev/null
  echo "Dokploy enrollment incomplete: dashboard restricted to operator ${enrollment_source_ip}"
  echo "Create the first account and enable TOTP from that Tailscale device, then rerun deployment."
fi
ufw deny 3000/tcp >/dev/null 2>&1 || true

state_file="/var/lib/server-hardening/state"
if [[ -L "${state_file}" || ( -e "${state_file}" && ! -f "${state_file}" ) ]]; then
  echo "${state_file} is a symlink or unexpected file" >&2
  exit 1
fi
if [[ -f "${state_file}" ]]; then
  exec 9>"${state_file}.lock"
  flock -x 9
  if grep -q '^dokploy_enrollment_source_ip=' "${state_file}"; then
    sed -i "s|^dokploy_enrollment_source_ip=.*|dokploy_enrollment_source_ip=${enrollment_source_ip}|" "${state_file}"
  else
    printf 'dokploy_enrollment_source_ip=%s\n' "${enrollment_source_ip}" >> "${state_file}"
  fi
  chmod 0640 "${state_file}"
  flock -u 9
  exec 9>&-
fi

# The shared DOCKER-USER reconciler reads the enrollment source and account
# state each time it runs. Reapply it after updating state so fresh installs,
# source changes, and post-TOTP promotion cannot leave the forwarded Docker
# path on the previous authorization policy.
if [[ -x /usr/local/sbin/docker-user-hardening.sh ]] \
  && systemctl is-enabled --quiet docker-user-hardening.service 2>/dev/null; then
  systemctl restart docker-user-hardening.service
  systemctl start docker-user-hardening-refresh.service 2>/dev/null || true
fi

# Remove the historical all-tailnet Swarm policy. The managed deployment is a
# single-node Swarm, so these listeners have no legitimate remote caller. Keep
# explicit denies for both the public interface and tailscale0. Source-scoped
# rules for an approved future node are intentionally outside this workflow.
while true; do
  managed_line="$(ufw status numbered 2>/dev/null \
    | grep -E 'docker-swarm-(mgmt|gossip|gossip-udp|vxlan)-tailscale' | head -1 || true)"
  [[ -n "${managed_line}" ]] || break
  managed_num="$(sed -n 's/^\[[[:space:]]*\([0-9][0-9]*\)\].*/\1/p' <<< "${managed_line}")"
  [[ -n "${managed_num}" ]] || { echo "Could not parse managed Docker Swarm UFW rule" >&2; exit 1; }
  ufw --force delete "${managed_num}" >/dev/null
done
ufw delete allow in on tailscale0 proto tcp to any port 2377 >/dev/null 2>&1 || true
ufw delete allow in on tailscale0 proto tcp to any port 7946 >/dev/null 2>&1 || true
ufw delete allow in on tailscale0 proto udp to any port 7946 >/dev/null 2>&1 || true
ufw delete allow in on tailscale0 proto udp to any port 4789 >/dev/null 2>&1 || true
ufw deny 2377/tcp >/dev/null 2>&1 || true
ufw deny 7946/tcp >/dev/null 2>&1 || true
ufw deny 7946/udp >/dev/null 2>&1 || true
ufw deny 4789/udp >/dev/null 2>&1 || true

# Tailscale's default netfilter mode inserts ts-input before UFW and accepts
# all tailscale0 traffic there. UFW status can therefore look restrictive
# while packets bypass ufw-user-input. Install an owned pre-ts-input policy,
# switch Tailscale to nodivert so it cannot move its jump back to the front,
# then maintain the verified order with a small refresh timer.
tailnet_filter_script="/usr/local/sbin/dokploy-tailnet-input-hardening"
tailnet_filter_tmp="$(mktemp /run/dokploy-tailnet-input-hardening.XXXXXX)"
cat > "${tailnet_filter_tmp}" <<'TAILNET_FILTER'
#!/usr/bin/env bash
set -Eeuo pipefail

exec 9>/run/lock/dokploy-tailnet-input-hardening.lock
flock -x 9

TAILSCALE_IFACE="tailscale0"
STATE_FILE="/var/lib/server-hardening/state"
ENROLLMENT_SOURCE_IP=""
ENROLLMENT_COMPLETE="false"
TAILSCALE_DIRECT_WAN="false"

is_tailscale_ipv4() {
  local ip="$1" a b c d
  IFS=. read -r a b c d <<< "${ip}"
  [[ "${a}" == "100" && "${b}" =~ ^[0-9]+$ && "${c}" =~ ^[0-9]+$ && "${d}" =~ ^[0-9]+$ ]] \
    || return 1
  (( b >= 64 && b <= 127 && c <= 255 && d <= 255 ))
}

if [[ -f "${STATE_FILE}" && ! -L "${STATE_FILE}" ]]; then
  state_values="$(
    flock -s "${STATE_FILE}.lock" awk -F= \
      '$1 == "dokploy_enrollment_source_ip" || $1 == "tailscale_direct_wan" { print }' \
      "${STATE_FILE}" 2>/dev/null || true
  )"
  ENROLLMENT_SOURCE_IP="$(awk -F= '$1 == "dokploy_enrollment_source_ip" { print substr($0, index($0, "=") + 1); exit }' <<< "${state_values}")"
  TAILSCALE_DIRECT_WAN="$(awk -F= '$1 == "tailscale_direct_wan" { print substr($0, index($0, "=") + 1); exit }' <<< "${state_values}")"
fi
if ! is_tailscale_ipv4 "${ENROLLMENT_SOURCE_IP}"; then
  ENROLLMENT_SOURCE_IP=""
fi

pg_cid="$(docker ps -q --filter name=dokploy-postgres 2>/dev/null | head -1 || true)"
if [[ -n "${pg_cid}" ]]; then
  account_table_exists="$(docker exec "${pg_cid}" psql -U dokploy -d dokploy -tAc \
    "SELECT count(*) FROM pg_catalog.pg_tables WHERE schemaname='public' AND tablename='user'" \
    2>/dev/null | tr -d '[:space:]' || true)"
  if [[ "${account_table_exists}" == "1" ]]; then
    account_count="$(docker exec "${pg_cid}" psql -U dokploy -d dokploy -tAc \
      'SELECT count(*) FROM "user"' 2>/dev/null | tr -d '[:space:]' || true)"
    no2fa="$(docker exec "${pg_cid}" psql -U dokploy -d dokploy -tAc \
      'SELECT count(*) FROM "user" u WHERE u.two_factor_enabled IS DISTINCT FROM TRUE OR NOT EXISTS (SELECT 1 FROM two_factor tf WHERE tf.user_id = u.id AND tf.verified IS TRUE AND length(tf.secret) > 0)' \
      2>/dev/null | tr -d '[:space:]' || true)"
    if [[ "${account_count}" =~ ^[1-9][0-9]*$ && "${no2fa}" == "0" ]]; then
      ENROLLMENT_COMPLETE="true"
    fi
  fi
fi

run_ipt() {
  local binary="$1"
  shift
  "${binary}" -w "$@"
}

populate_policy_chain() {
  local binary="$1" chain="$2" family="$3"
  run_ipt "${binary}" -N "${chain}" 2>/dev/null || true
  run_ipt "${binary}" -F "${chain}"
  run_ipt "${binary}" -A "${chain}" -i "${TAILSCALE_IFACE}" -p tcp --dport 22 \
    -m comment --comment "dokploy-tailnet-root-ssh-${family}" -j ACCEPT
  if [[ "${family}" == "ipv4" ]]; then
    run_ipt "${binary}" -A "${chain}" -i "${TAILSCALE_IFACE}" -p icmp \
      -m comment --comment "dokploy-tailnet-icmp-ipv4" -j ACCEPT
  else
    run_ipt "${binary}" -A "${chain}" -i "${TAILSCALE_IFACE}" -p ipv6-icmp \
      -m comment --comment "dokploy-tailnet-icmp-ipv6" -j ACCEPT
  fi
  if [[ "${ENROLLMENT_COMPLETE}" == "true" ]]; then
    run_ipt "${binary}" -A "${chain}" -i "${TAILSCALE_IFACE}" -p tcp --dport 3000 \
      -m comment --comment "dokploy-tailnet-dashboard-enrolled-${family}" -j ACCEPT
  else
    if [[ "${family}" == "ipv4" && -n "${ENROLLMENT_SOURCE_IP}" ]]; then
      run_ipt "${binary}" -A "${chain}" -i "${TAILSCALE_IFACE}" \
        -s "${ENROLLMENT_SOURCE_IP}/32" -p tcp --dport 3000 \
        -m comment --comment "dokploy-tailnet-dashboard-operator-ipv4" -j ACCEPT
    fi
    run_ipt "${binary}" -A "${chain}" -i "${TAILSCALE_IFACE}" -p tcp --dport 3000 \
      -m comment --comment "dokploy-tailnet-dashboard-guard-${family}" -j DROP
  fi
  run_ipt "${binary}" -A "${chain}" -i "${TAILSCALE_IFACE}" -p tcp \
    -m multiport --dports 2375,2376,2377,5432,6379,7946 \
    -m comment --comment "dokploy-tailnet-privileged-tcp-drop-${family}" -j DROP
  run_ipt "${binary}" -A "${chain}" -i "${TAILSCALE_IFACE}" -p udp \
    -m multiport --dports 4789,7946 \
    -m comment --comment "dokploy-tailnet-swarm-udp-drop-${family}" -j DROP
  # Explicitly denied host services stay denied even for conntrack tuples
  # created before this policy converged. SSH, ICMP, and authorized panel
  # traffic were accepted above; only then preserve other established flows.
  run_ipt "${binary}" -A "${chain}" -i "${TAILSCALE_IFACE}" \
    -m conntrack --ctstate RELATED,ESTABLISHED \
    -m comment --comment "dokploy-tailnet-established-${family}" -j ACCEPT
  run_ipt "${binary}" -A "${chain}" -i "${TAILSCALE_IFACE}" \
    -m comment --comment "dokploy-tailnet-unmatched-drop-${family}" -j DROP
  if [[ "${TAILSCALE_DIRECT_WAN}" != "true" ]]; then
    # ts-input's WireGuard listener accept is intentionally after this chain.
    # Enforce the configured DERP-only posture before that accept can run.
    run_ipt "${binary}" -A "${chain}" ! -i "${TAILSCALE_IFACE}" -p udp --dport 41641 \
      -m comment --comment "dokploy-tailnet-tailscale-wan-drop-${family}" -j DROP
  fi
  run_ipt "${binary}" -A "${chain}" \
    -m comment --comment "dokploy-tailnet-return-${family}" -j RETURN
}

reconcile_family() {
  local binary="$1" family="$2"
  local chain_a="SECURE-TAILSCALE-INPUT-A" chain_b="SECURE-TAILSCALE-INPUT-B"
  local current_chain next_chain line_no
  current_chain="$(${binary} -S INPUT 2>/dev/null \
    | awk '/^-A INPUT .* -j SECURE-TAILSCALE-INPUT-[AB]$/ { print $NF; exit }')"
  if [[ "${current_chain}" == "${chain_a}" ]]; then
    next_chain="${chain_b}"
  else
    current_chain="${chain_b}"
    next_chain="${chain_a}"
  fi

  # Preserve the currently active policy while the replacement chain is
  # built. If a prior interrupted run left the next chain referenced, remove
  # that secondary jump while the first managed chain still protects traffic.
  while run_ipt "${binary}" -C INPUT -j "${next_chain}" >/dev/null 2>&1; do
    run_ipt "${binary}" -D INPUT -j "${next_chain}"
  done
  populate_policy_chain "${binary}" "${next_chain}" "${family}"
  run_ipt "${binary}" -I INPUT 1 -j "${next_chain}"
  while run_ipt "${binary}" -C INPUT -j "${current_chain}" >/dev/null 2>&1; do
    run_ipt "${binary}" -D INPUT -j "${current_chain}"
  done
  run_ipt "${binary}" -F "${current_chain}" 2>/dev/null || true
  run_ipt "${binary}" -X "${current_chain}" 2>/dev/null || true

  # In nodivert mode Tailscale owns ts-input's contents but not its jump.
  # Keep that jump immediately after the stricter Dokploy chain so WireGuard
  # UDP and CGNAT anti-spoof handling remain intact without bypassing policy.
  while run_ipt "${binary}" -C INPUT -j ts-input >/dev/null 2>&1; do
    run_ipt "${binary}" -D INPUT -j ts-input
  done
  if run_ipt "${binary}" -S ts-input >/dev/null 2>&1; then
    run_ipt "${binary}" -I INPUT 2 -j ts-input
  fi
}

reconcile_family iptables ipv4
if command -v ip6tables >/dev/null 2>&1; then
  reconcile_family ip6tables ipv6
fi
TAILNET_FILTER
chown root:root "${tailnet_filter_tmp}"
chmod 0750 "${tailnet_filter_tmp}"
mv -f -- "${tailnet_filter_tmp}" "${tailnet_filter_script}"

cat > /etc/systemd/system/dokploy-tailnet-input-hardening.service <<EOF_SERVICE
[Unit]
Description=Enforce Dokploy Tailscale INPUT policy before Tailscale acceptance
After=tailscaled.service docker.service ufw.service
Requires=tailscaled.service

[Service]
Type=oneshot
ExecStart=${tailnet_filter_script}
EOF_SERVICE
cat > /etc/systemd/system/dokploy-tailnet-input-hardening.timer <<'EOF_TIMER'
[Unit]
Description=Refresh Dokploy Tailscale INPUT policy

[Timer]
OnBootSec=20s
OnUnitActiveSec=60s
AccuracySec=10s
Unit=dokploy-tailnet-input-hardening.service

[Install]
WantedBy=timers.target
EOF_TIMER
chown root:root \
  /etc/systemd/system/dokploy-tailnet-input-hardening.service \
  /etc/systemd/system/dokploy-tailnet-input-hardening.timer
chmod 0644 \
  /etc/systemd/system/dokploy-tailnet-input-hardening.service \
  /etc/systemd/system/dokploy-tailnet-input-hardening.timer

# Stage the restrictive chain while Tailscale still manages its own jumps, so
# the current root SSH session remains explicitly accepted throughout the mode
# transition. Then switch to nodivert and rebuild the ordered jumps.
"${tailnet_filter_script}"
tailscale set --netfilter-mode=nodivert
"${tailnet_filter_script}"
systemctl daemon-reload
systemctl enable --now dokploy-tailnet-input-hardening.timer >/dev/null
systemctl start dokploy-tailnet-input-hardening.service
EOF
}

dokploy_reconcile_docker_daemon_script() {
  # Dokploy runs on Docker Swarm. Keep the shared hardening keys, but never
  # add live-restore: dockerd refuses to start in Swarm mode with that option.
  cat <<'EOF'
set -Eeuo pipefail
daemon_json="/etc/docker/daemon.json"
state_file="/var/lib/server-hardening/state"
nproc_hard="8192"
nproc_soft="4096"
tmp="$(mktemp)"
cleanup() { rm -f "${tmp}"; }
trap cleanup EXIT

if [[ -f "${state_file}" ]]; then
  nproc_hard="$(grep -m1 '^docker_nproc_hard=' "${state_file}" | cut -d= -f2- || echo "8192")"
  nproc_soft="$(grep -m1 '^docker_nproc_soft=' "${state_file}" | cut -d= -f2- || echo "4096")"
fi
[[ "${nproc_hard}" =~ ^[1-9][0-9]*$ ]] || nproc_hard="8192"
[[ "${nproc_soft}" =~ ^[1-9][0-9]*$ ]] || nproc_soft="4096"
if (( nproc_soft > nproc_hard )); then
  nproc_soft="${nproc_hard}"
fi

if [[ -f "${daemon_json}" ]]; then
  jq \
    --argjson nproc_hard "${nproc_hard}" \
    --argjson nproc_soft "${nproc_soft}" \
    '. + {
      "log-driver":"json-file",
      "log-opts":((.["log-opts"] // {}) + {"max-size":"10m","max-file":"3"}),
      "default-ipc-mode":"private",
      "storage-driver":"overlay2",
      "default-ulimits":((.["default-ulimits"] // {}) + {
        "nofile":{"Name":"nofile","Hard":65536,"Soft":65536},
        "nproc":{"Name":"nproc","Hard":$nproc_hard,"Soft":$nproc_soft}
      })
    }
    | del(.["live-restore"])' "${daemon_json}" > "${tmp}"
else
  jq -n \
    --argjson nproc_hard "${nproc_hard}" \
    --argjson nproc_soft "${nproc_soft}" \
    '{
      "log-driver":"json-file",
      "log-opts":{"max-size":"10m","max-file":"3"},
      "default-ipc-mode":"private",
      "storage-driver":"overlay2",
      "default-ulimits":{
        "nofile":{"Name":"nofile","Hard":65536,"Soft":65536},
        "nproc":{"Name":"nproc","Hard":$nproc_hard,"Soft":$nproc_soft}
      }
    }' > "${tmp}"
fi

if [[ -f "${daemon_json}" ]] && cmp -s "${tmp}" "${daemon_json}"; then
  exit 0
fi

if [[ -f "${daemon_json}" ]]; then
  cp -a "${daemon_json}" "${daemon_json}.bak.$(date +%s)"
fi
install -d -m 0755 -o root -g root /etc/docker
install -m 0644 -o root -g root "${tmp}" "${daemon_json}"
if ! systemctl restart docker; then
  echo "Failed to restart Docker after Dokploy daemon.json update" >&2
  exit 1
fi
EOF
}

dokploy_finalize_runtime_script() {
  printf 'backup_recipient=%q\n' "${ADMIN_PUBKEY:?Dokploy encrypted backups require the operator public key}"
  cat <<'EOF'
set -Eeuo pipefail
# Bootstrap from a reviewed security floor. The updater may advance within
# 3.7, but never hands Docker-socket privilege to an unresolved mutable tag.
TRAEFIK_IMAGE="traefik:v3.7.13@sha256:24841fe2de7304c149343d877d2923b4c8800a38ba015dea9174c23b20e344a0"
# Dokploy follows the operator-selected latest-stable channel. The updater
# below resolves this tag to a digest before accepting a deployment.
DOKPLOY_IMAGE="dokploy/dokploy:latest"
DOKPLOY_CONTROL_NETWORK="dokploy-control-network"
if ! command -v age >/dev/null 2>&1; then
  apt-get update >/dev/null
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends age >/dev/null
fi
install -d -m 0700 -o root -g root /var/lib/server-hardening
backup_recipient_tmp="$(mktemp /var/lib/server-hardening/.backup-recipient.XXXXXX)"
printf '%s\n' "${backup_recipient}" > "${backup_recipient_tmp}"
chown root:root "${backup_recipient_tmp}"
chmod 0600 "${backup_recipient_tmp}"
mv -f -- "${backup_recipient_tmp}" /var/lib/server-hardening/backup-recipient
daemon_json="/etc/docker/daemon.json"
swarm_unlock_handoff="/run/secure-ubuntu-paas-dokploy-swarm-unlock-key"
traefik_was_running="false"
block_tmp=""

# A Swarm autolock key must never be persisted beside the encrypted manager
# state. When runtime reconciliation stops Traefik, restore it before returning
# a failure so a partial hardening run does not leave the proxy down.
restore_traefik_on_exit() {
  local rc=$?
  if [[ "${traefik_was_running}" == "true" ]] \
    && docker service inspect dokploy-traefik >/dev/null 2>&1; then
    docker service update --replicas 1 --detach=false --quiet dokploy-traefik >/dev/null 2>&1 || true
  fi
  [[ -z "${block_tmp}" ]] || rm -f -- "${block_tmp}"
  exit "${rc}"
}
trap restore_traefik_on_exit EXIT

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is not installed yet; deferring Dokploy runtime finalization until phase 3."
  exit 0
fi

if command -v jq >/dev/null 2>&1 && [[ -f "${daemon_json}" ]]; then
  if jq -e 'has("live-restore")' "${daemon_json}" >/dev/null 2>&1; then
    jq 'del(.["live-restore"])' "${daemon_json}" > "${daemon_json}.tmp"
    mv "${daemon_json}.tmp" "${daemon_json}"
    systemctl restart docker
    sleep 8
  fi
fi

swarm_state="$(docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null || true)"
unattended_recovery=false
if [[ -e /etc/dokploy/recovery-policy.json || -L /etc/dokploy/recovery-policy.json ]]; then
  [[ -f /usr/local/sbin/paas-recovery-policy && ! -L /usr/local/sbin/paas-recovery-policy \
    && "$(stat -c '%a:%U:%G' /usr/local/sbin/paas-recovery-policy)" == '700:root:root' ]] \
    && python3 /usr/local/sbin/paas-recovery-policy \
    || { echo "Unsafe or unapproved unattended recovery policy" >&2; exit 1; }
  unattended_recovery=true
fi
if [[ "${swarm_state}" == "active" || "${swarm_state}" == "pending" || "${swarm_state}" == "locked" ]]; then
  if [[ "${swarm_state}" == "active" ]]; then
    swarm_autolock="$(docker info 2>/dev/null | awk -F: '/Autolock Managers/ {gsub(/[[:space:]]/, "", $2); print tolower($2); exit}' || true)"
    if [[ "${unattended_recovery}" == true ]]; then
      if [[ "${swarm_autolock}" != false ]]; then docker swarm update --autolock=false >/dev/null; fi
    else
    if [[ "${swarm_autolock}" != "true" ]]; then
      # Encrypt the Swarm Raft log and manager secrets at rest. Docker prints
      # the unlock material in some versions; suppress command output and
      # retrieve it only through the protected unlock-key command below.
      docker swarm update --autolock=true >/dev/null
      swarm_autolock="$(docker info 2>/dev/null | awk -F: '/Autolock Managers/ {gsub(/[[:space:]]/, "", $2); print tolower($2); exit}' || true)"
    fi
    [[ "${swarm_autolock}" == "true" ]] \
      || { echo "Docker Swarm autolock could not be enabled or verified" >&2; exit 1; }
    # The upstream installer prints a join token while initializing Swarm.
    # Invalidate every previously emitted worker/manager credential before
    # proceeding, and suppress the newly generated replacements too.
    docker swarm join-token --rotate worker >/dev/null 2>&1 \
      || { echo "Docker Swarm worker join token rotation failed" >&2; exit 1; }
    docker swarm join-token --rotate manager >/dev/null 2>&1 \
      || { echo "Docker Swarm manager join token rotation failed" >&2; exit 1; }
    unlock_key="$(docker swarm unlock-key -q 2>/dev/null || true)"
    [[ "${unlock_key}" =~ ^SWMKEY- ]] \
      || { echo "Docker Swarm autolock is enabled but no unlock-key handoff was available" >&2; exit 1; }
    handoff_tmp="$(mktemp /run/secure-ubuntu-paas-dokploy-swarm-unlock-key.XXXXXX)"
    umask 077
    printf '%s\n' "${unlock_key}" > "${handoff_tmp}"
    chown root:root "${handoff_tmp}"
    chmod 600 "${handoff_tmp}"
    mv -f -- "${handoff_tmp}" "${swarm_unlock_handoff}"
    unset unlock_key handoff_tmp
    fi
  else
    echo "Docker Swarm is ${swarm_state}; unlock it manually with the operator-held key before rerunning Dokploy finalization." >&2
    exit 1
  fi
fi

# Remove the legacy same-host key and automatic unlock mechanism. Autolock is
# intentionally manual after a daemon restart: the key is held outside the
# VPS, in the operator's protected credential store, rather than on the same
# disk as the encrypted Swarm manager state.
systemctl disable --now docker-swarm-unlock.service >/dev/null 2>&1 || true
rm -f -- /etc/systemd/system/docker-swarm-unlock.service \
  /usr/local/sbin/docker-swarm-unlock.sh \
  /root/.docker/swarm-unlock-key
systemctl daemon-reload

# Keep the panel and its database off the shared application network. Dokploy
# public workloads and Traefik may remain on dokploy-network, but a compromised
# workload must not be able to address the panel's container port directly.
if docker network inspect "${DOKPLOY_CONTROL_NETWORK}" >/dev/null 2>&1; then
  control_driver="$(docker network inspect --format '{{.Driver}}' "${DOKPLOY_CONTROL_NETWORK}" 2>/dev/null || true)"
  control_scope="$(docker network inspect --format '{{.Scope}}' "${DOKPLOY_CONTROL_NETWORK}" 2>/dev/null || true)"
  [[ "${control_driver}" == "overlay" && "${control_scope}" == "swarm" ]] \
    || { echo "${DOKPLOY_CONTROL_NETWORK} exists but is not a Swarm overlay network" >&2; exit 1; }
else
  docker network create --driver overlay --attachable "${DOKPLOY_CONTROL_NETWORK}" >/dev/null
fi

reconcile_dokploy_control_network() {
  local service="$1" control_id legacy_id network_ids
  local -a update_args=()
  docker service inspect "${service}" >/dev/null 2>&1 || return 0
  control_id="$(docker network inspect --format '{{.Id}}' "${DOKPLOY_CONTROL_NETWORK}" 2>/dev/null || true)"
  legacy_id="$(docker network inspect --format '{{.Id}}' dokploy-network 2>/dev/null || true)"
  network_ids="$(docker service inspect "${service}" --format '{{range .Spec.TaskTemplate.Networks}}{{println .Target}}{{end}}' 2>/dev/null || true)"
  [[ -n "${control_id}" ]] || { echo "Unable to inspect ${DOKPLOY_CONTROL_NETWORK}" >&2; return 1; }
  if ! grep -Fqx "${control_id}" <<< "${network_ids}"; then
    update_args+=(--network-add "${DOKPLOY_CONTROL_NETWORK}")
  fi
  if [[ -n "${legacy_id}" ]] && grep -Fqx "${legacy_id}" <<< "${network_ids}"; then
    update_args+=(--network-rm dokploy-network)
  fi
  if (( ${#update_args[@]} > 0 )); then
    docker service update "${update_args[@]}" --detach=false --quiet "${service}" >/dev/null
  fi
}

reconcile_dokploy_control_network dokploy-postgres
reconcile_dokploy_control_network dokploy

# Repair the Dokploy configuration root before consuming any descendant.  The
# installer and the Dokploy service are not trusted as writers of this
# privileged hardening state; a symlink or a world-writable parent must never
# redirect a root-owned edit elsewhere on the filesystem.
dokploy_root="/etc/dokploy"
if [[ -L "${dokploy_root}" || ( -e "${dokploy_root}" && ! -d "${dokploy_root}" ) ]]; then
  echo "${dokploy_root} is a symlink or unexpected file" >&2
  exit 1
fi
install -d -m 0755 -o root -g root "${dokploy_root}"
tree_needs_repair="false"
root_owner="$(stat -c '%U:%G' "${dokploy_root}" 2>/dev/null || true)"
root_mode="$(stat -c '%a' "${dokploy_root}" 2>/dev/null || true)"
[[ "${root_owner}" == "root:root" && "${root_mode}" == "755" ]] || tree_needs_repair="true"
while IFS= read -r -d '' dokploy_entry; do
  if [[ -L "${dokploy_entry}" ]]; then
    echo "${dokploy_entry} is a symlink inside the privileged Dokploy configuration tree" >&2
    exit 1
  elif [[ ! -d "${dokploy_entry}" && ! -f "${dokploy_entry}" ]]; then
    echo "${dokploy_entry} is an unsupported file type inside the privileged Dokploy configuration tree" >&2
    exit 1
  fi
  entry_owner="$(stat -c '%U:%G' "${dokploy_entry}" 2>/dev/null || true)"
  [[ "${entry_owner}" == "root:root" ]] || tree_needs_repair="true"
  if [[ -n "$(find -P "${dokploy_entry}" -prune -perm /022 -print -quit 2>/dev/null || true)" ]]; then
    tree_needs_repair="true"
  fi
  # Regular files can contain private keys, credentials, or future Dokploy
  # secrets whose names are not known to this version of the hardener. Treat
  # them as sensitive by default instead of allowlisting only acme.json.
  if [[ -f "${dokploy_entry}" \
    && -n "$(find -P "${dokploy_entry}" -prune -perm /077 -print -quit 2>/dev/null || true)" ]]; then
    tree_needs_repair="true"
  fi
  if [[ -f "${dokploy_entry}" && "${dokploy_entry##*/}" == "acme.json" \
    && "$(stat -c '%a' "${dokploy_entry}" 2>/dev/null || true)" != "600" ]]; then
    tree_needs_repair="true"
  fi
done < <(find -P "${dokploy_root}" -xdev -mindepth 1 -print0)

if [[ "${tree_needs_repair}" == "true" ]]; then
  if docker service inspect dokploy-traefik >/dev/null 2>&1; then
    traefik_replicas="$(docker service inspect dokploy-traefik --format '{{.Spec.Mode.Replicated.Replicas}}' 2>/dev/null || true)"
    if [[ "${traefik_replicas}" =~ ^[1-9][0-9]*$ ]]; then
      docker service update --replicas 0 --detach=false --quiet dokploy-traefik >/dev/null
      traefik_was_running="true"
    fi
  fi

  dokploy_stage="$(mktemp -d /etc/.dokploy-hardening.XXXXXX)"
  chmod 700 "${dokploy_stage}"
  cp -R --no-preserve=mode,ownership "${dokploy_root}/." "${dokploy_stage}/"
  while IFS= read -r -d '' dokploy_entry; do
    if [[ -L "${dokploy_entry}" ]]; then
      echo "${dokploy_entry} became a symlink while staging Dokploy configuration" >&2
      exit 1
    elif [[ -d "${dokploy_entry}" ]]; then
      chown root:root "${dokploy_entry}"
      chmod 755 "${dokploy_entry}"
    elif [[ -f "${dokploy_entry}" ]]; then
      chown root:root "${dokploy_entry}"
      # Fail closed for unknown future files: Traefik and Dokploy consume this
      # bind-mounted tree as root, so no regular descendant needs local
      # group/other readability.
      chmod 600 "${dokploy_entry}"
    else
      echo "${dokploy_entry} is an unsupported staged file type" >&2
      exit 1
    fi
  done < <(find -P "${dokploy_stage}" -xdev -mindepth 1 -print0)
  chown root:root "${dokploy_stage}"
  chmod 755 "${dokploy_stage}"
  dokploy_old="$(mktemp -d /etc/.dokploy-hardening-old.XXXXXX)"
  rmdir "${dokploy_old}"
  mv -- "${dokploy_root}" "${dokploy_old}"
  if ! mv -- "${dokploy_stage}" "${dokploy_root}"; then
    mv -- "${dokploy_old}" "${dokploy_root}"
    exit 1
  fi
  dokploy_stage=""
  rm -rf -- "${dokploy_old}"
  traefik_config_changed="true"
fi

chown root:root "${dokploy_root}"
chmod 0755 "${dokploy_root}"
for dokploy_dir in "${dokploy_root}/traefik" "${dokploy_root}/traefik/dynamic"; do
  if [[ -L "${dokploy_dir}" || ( -e "${dokploy_dir}" && ! -d "${dokploy_dir}" ) ]]; then
    echo "${dokploy_dir} is a symlink or unexpected file" >&2
    exit 1
  fi
  install -d -m 0755 -o root -g root "${dokploy_dir}"
  chown root:root "${dokploy_dir}"
  chmod 0755 "${dokploy_dir}"
done

# Dokploy's default Traefik static config ships api.insecure=true (:8080
# API/dashboard reachable by any container on dokploy-network). Disable it;
# Dokploy manages Traefik via file provider, not the API.
traefik_yml="${dokploy_root}/traefik/traefik.yml"
if [[ -L "${traefik_yml}" || ( -e "${traefik_yml}" && ! -f "${traefik_yml}" ) ]]; then
  echo "${traefik_yml} is a symlink or unexpected file" >&2
  exit 1
fi
traefik_config_changed="${traefik_config_changed:-false}"
if [[ -f "${traefik_yml}" ]] && grep -qE '^[[:space:]]*insecure:[[:space:]]*true' "${traefik_yml}"; then
  sed -i.bak-hardening 's/^\([[:space:]]*\)insecure:[[:space:]]*true/\1insecure: false/' "${traefik_yml}"
  traefik_config_changed="true"
fi

# Dokploy's starter config uses a non-deliverable placeholder. Remove it so
# ACME cannot silently report certificate failures to a dead mailbox. A real
# operator-supplied email may remain untouched.
if [[ -f "${traefik_yml}" ]] && grep -qE '^[[:space:]]*email:[[:space:]]*test@localhost\.com[[:space:]]*$' "${traefik_yml}"; then
  sed -i.bak-hardening -E '/^[[:space:]]*email:[[:space:]]*test@localhost\.com[[:space:]]*$/d' "${traefik_yml}"
  traefik_config_changed="true"
fi

# The backup suffix is intentionally retained for rollback, but it must not
# preserve the same non-deliverable placeholder that was just removed from
# the active configuration.  Sanitize an existing backup in place; this does
# not remove operator-supplied ACME settings.
traefik_backup="${traefik_yml}.bak-hardening"
if [[ -f "${traefik_backup}" ]]; then
  sed -i -E '/^[[:space:]]*email:[[:space:]]*test@localhost\.com[[:space:]]*$/d' "${traefik_backup}"
fi

# Dokploy ships no Traefik access log, so public 80/443 ingress leaves no
# forensic trail. JSON to stdout; the daemon's json-file log-opts rotate it.
if [[ -f "${traefik_yml}" ]] && ! grep -qE '^accessLog:' "${traefik_yml}"; then
  cat >> "${traefik_yml}" <<'ACCESSLOG'
accessLog:
  format: json
  fields:
    headers:
      names:
        User-Agent: keep
ACCESSLOG
  traefik_config_changed="true"
fi

# Dokploy regenerates dynamic/dokploy.yml with a default
# Host(`dokploy.docker.localhost`) router on the PUBLIC web/websecure
# entrypoints, re-exposing the dashboard login on public 80/443 to any client
# sending that Host header. Install a higher-priority hardening router that
# shadows it and denies every public client. Lives in its own file Dokploy
# does not manage, so it survives dokploy.yml regeneration and reboots.
block_file="/etc/dokploy/traefik/dynamic/zz-hardening-dashboard-block.yml"
if [[ -L "${block_file}" || ( -e "${block_file}" && ! -f "${block_file}" ) ]]; then
  echo "${block_file} is a symlink or unexpected file" >&2
  exit 1
fi
if [[ -d /etc/dokploy/traefik/dynamic ]]; then
  block_tmp="$(mktemp "/etc/dokploy/traefik/dynamic/.zz-hardening-dashboard-block.XXXXXX")" \
    || { echo "Unable to create root-owned Dokploy dashboard block staging file" >&2; exit 1; }
  chown root:root "${block_tmp}"
  chmod 600 "${block_tmp}"
  cat > "${block_tmp}" <<'BLOCK'
# Managed by secure-ubuntu-paas hardening (Dokploy overlay). Do not edit.
# Shadows Dokploy's default Host(`dokploy.docker.localhost`) dashboard router
# on the public web/websecure entrypoints and denies all public clients.
# Legitimate dashboard access is over Tailscale on :3000 and never traverses
# Traefik.
http:
  routers:
    zz-hardening-dashboard-localhost-web:
      rule: "Host(`dokploy.docker.localhost`)"
      priority: 100000
      entryPoints:
        - web
      service: zz-hardening-blackhole
      middlewares:
        - zz-hardening-deny-public
    # HostRegexp still matches the exact placeholder on HTTPS but does not
    # offer a literal .localhost identifier to the entrypoint-wide ACME
    # resolver. Traefik serves its default certificate, then denies access.
    zz-hardening-dashboard-localhost-websecure:
      rule: "HostRegexp(`^dokploy\\.docker\\.localhost$`)"
      priority: 100000
      entryPoints:
        - websecure
      tls: {}
      service: zz-hardening-blackhole
      middlewares:
        - zz-hardening-deny-public
  middlewares:
    zz-hardening-deny-public:
      ipAllowList:
        sourceRange:
          - 192.0.2.0/32
  services:
    zz-hardening-blackhole:
      loadBalancer:
        servers:
          - url: "http://127.0.0.1:9"
BLOCK
  chown root:root "${block_tmp}"
  chmod 600 "${block_tmp}"
  mv -f -- "${block_tmp}" "${block_file}"
  block_tmp=""
fi

# Dokploy/Swarm leaves many exited task containers after updates; prune safely.
docker container prune -f >/dev/null 2>&1 || true
docker image prune -f >/dev/null 2>&1 || true

wait_for_traefik_live_task() {
  local attempt traefik_container_id=""
  for attempt in $(seq 1 30); do
    traefik_container_id="$(docker ps --filter label=com.docker.swarm.service.name=dokploy-traefik --format '{{.ID}}' 2>/dev/null | head -1 || true)"
    if [[ -n "${traefik_container_id}" ]]; then
      printf '%s\n' "${traefik_container_id}"
      return 0
    fi
    (( attempt < 30 )) && sleep 2
  done
  return 1
}

verify_traefik_live_api_disabled() {
  local traefik_container_id="${1:-}"
  local traefik_pid baseline_code
  [[ -n "${traefik_container_id}" ]] || return 1
  command -v curl >/dev/null 2>&1 || return 1
  command -v nsenter >/dev/null 2>&1 || return 1
  command -v ss >/dev/null 2>&1 || return 1
  traefik_pid="$(docker inspect --format '{{.State.Pid}}' "${traefik_container_id}" 2>/dev/null || true)"
  [[ "${traefik_pid}" =~ ^[1-9][0-9]*$ ]] || return 1
  baseline_code="$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 5 \
    "http://127.0.0.1:80" 2>/dev/null || true)"
  [[ "${baseline_code:-000}" =~ ^[1-5][0-9][0-9]$ ]] \
    || { echo "Traefik published HTTP baseline probe was inconclusive (${baseline_code:-000})." >&2; return 1; }
  nsenter -t "${traefik_pid}" -n ss -H -lnt 'sport = :80' 2>/dev/null | grep -q . \
    || { echo "Traefik network namespace has no HTTP listener." >&2; return 1; }
  if nsenter -t "${traefik_pid}" -n ss -H -lnt 'sport = :8080' 2>/dev/null | grep -q .; then
    echo "Traefik insecure API listener is active inside its network namespace." >&2
    return 1
  fi
}

if docker service inspect dokploy-traefik >/dev/null 2>&1; then
  # Do not downgrade an already accepted automatic patch update on resume.
  prior_update_state="/var/lib/server-hardening/dokploy-update-state"
  if [[ -f "${prior_update_state}" && ! -L "${prior_update_state}" \
    && "$(stat -c '%a:%U:%G' "${prior_update_state}")" == "600:root:root" ]]; then
    prior_proxy="$(awk -F= '$1 == "traefik_resolved_image" {print substr($0,index($0,"=")+1);exit}' "${prior_update_state}")"
    prior_version="$(awk -F= '$1 == "traefik_version" {print substr($0,index($0,"=")+1);exit}' "${prior_update_state}")"
    current_proxy="$(docker service inspect dokploy-traefik --format '{{.Spec.TaskTemplate.ContainerSpec.Image}}')"
    if [[ "${prior_proxy}" =~ ^traefik:v3\.7@sha256:[0-9a-f]{64}$ \
      && "${prior_version}" =~ ^3\.7\.([0-9]+)$ && "${BASH_REMATCH[1]}" -ge 13 \
      && "${current_proxy}" == "${prior_proxy}" ]]; then
      TRAEFIK_IMAGE="${prior_proxy}"
    fi
  fi
  # Reconcile the running proxy to the immutable digest above.
  running_traefik="$(docker service inspect dokploy-traefik --format '{{.Spec.TaskTemplate.ContainerSpec.Image}}' 2>/dev/null || true)"
  if [[ "${running_traefik}" != "${TRAEFIK_IMAGE}" ]]; then
    docker pull -q "${TRAEFIK_IMAGE}" >/dev/null
    docker service update --image "${TRAEFIK_IMAGE}" --detach=false --quiet dokploy-traefik >/dev/null
  elif [[ "${traefik_config_changed}" == "true" ]]; then
    # Static config (api.insecure, accessLog) only loads on container restart.
    docker service update --force --detach=false --quiet dokploy-traefik >/dev/null
  fi
else
  docker pull "${TRAEFIK_IMAGE}"
  docker service create \
    --name dokploy-traefik \
    --constraint 'node.role==manager' \
    --network dokploy-network \
    --publish mode=host,target=80,published=80,protocol=tcp \
    --publish mode=host,target=443,published=443,protocol=tcp \
    --publish mode=host,target=443,published=443,protocol=udp \
    --mount type=bind,source=/etc/dokploy/traefik/traefik.yml,target=/etc/traefik/traefik.yml \
    --mount type=bind,source=/etc/dokploy/traefik/dynamic,target=/etc/dokploy/traefik/dynamic \
    --mount type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock \
    "${TRAEFIK_IMAGE}"
fi

traefik_live_task="$(wait_for_traefik_live_task)" \
  || { echo "Traefik Swarm service did not converge to a running task." >&2; exit 1; }
verify_traefik_live_api_disabled "${traefik_live_task}" \
  || { echo "Traefik live API hardening could not be verified after reconciliation." >&2; exit 1; }
traefik_was_running="false"

# Dokploy itself mounts /var/run/docker.sock and therefore has host-root
# equivalent authority. Track latest stable as explicitly requested, but make
# that mutable policy observable: every successful check records the resolved
# digest, and the validator fails if the timer or fresh digest evidence drifts.
dokploy_update_script="/usr/local/sbin/dokploy-auto-update"
dokploy_update_state="/var/lib/server-hardening/dokploy-update-state"
dokploy_update_tmp="$(mktemp /run/dokploy-auto-update.XXXXXX)"
cat > "${dokploy_update_tmp}" <<'DOKPLOY_UPDATER'
#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
DOKPLOY_IMAGE="dokploy/dokploy:latest"
TRAEFIK_CHANNEL="traefik:v3.7"
POSTGRES_CHANNEL="postgres:16"
UPDATE_STATE="/var/lib/server-hardening/dokploy-update-state"
UPDATE_LOCK="/run/lock/dokploy-auto-update.lock"

exec 9>"${UPDATE_LOCK}"
flock -x 9

# Preserve the explicitly approved tested-derivative policy on provisioning
# resumes; the protected dispatcher validates bases and isolated acceptance.
if [[ -x /usr/local/sbin/paas-auto-update && -f /etc/dokploy/security-image-policy.json \
  && ! -L /etc/dokploy/security-image-policy.json \
  && "$(stat -c '%a:%U:%G' /etc/dokploy/security-image-policy.json)" == '600:root:root' ]]; then
  exec /usr/local/sbin/paas-auto-update
fi

command -v docker >/dev/null 2>&1 \
  || { echo "Docker is unavailable; cannot update Dokploy." >&2; exit 1; }
[[ "$(docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null || true)" == "active" ]] \
  || { echo "Docker Swarm is not active; refusing to update Dokploy." >&2; exit 1; }
docker service inspect dokploy >/dev/null 2>&1 \
  || { echo "Dokploy service is missing; refusing automatic update." >&2; exit 1; }

# Back up the panel DB before either panel migrations or PostgreSQL patches.
# Ciphertext can leave the host; only the operator's SSH private key decrypts
# it. Neither raw database contents nor a decryption key enter the logs/VPS.
recipient_file="/var/lib/server-hardening/backup-recipient"
backup_dir="/var/lib/server-hardening/dokploy-backups"
[[ -f "${recipient_file}" && ! -L "${recipient_file}" \
  && "$(stat -c '%a:%U:%G' "${recipient_file}")" == "600:root:root" ]] \
  || { echo "Protected operator backup recipient is missing." >&2; exit 1; }
backup_recipient="$(<"${recipient_file}")"
install -d -m 0700 -o root -g root "${backup_dir}"
backup_file="${backup_dir}/dokploy-$(date -u +%Y%m%dT%H%M%SZ).sql.gz.age"
postgres_container="$(docker ps -q --filter label=com.docker.swarm.service.name=dokploy-postgres | head -1)"
[[ -n "${postgres_container}" ]] \
  || { echo "PostgreSQL task is unavailable; refusing updates without backup." >&2; exit 1; }
backup_tmp="$(mktemp "${backup_dir}/.backup.XXXXXX")"
if docker exec "${postgres_container}" pg_dump -U dokploy -d dokploy --no-owner --no-acl \
  | gzip -c | age -r "${backup_recipient}" > "${backup_tmp}"; then
  [[ -s "${backup_tmp}" ]] || { rm -f -- "${backup_tmp}"; exit 1; }
  chmod 0600 "${backup_tmp}"
  mv -f -- "${backup_tmp}" "${backup_file}"
else
  rm -f -- "${backup_tmp}"
  echo "Encrypted database backup failed; no updates applied." >&2
  exit 1
fi

# Reserve control-plane headroom on the supported 8 GiB/4-core host while
# leaving user-selected nonzero limits untouched on subsequent runs.
host_mem_kib="$(awk '$1 == "MemTotal:" {print $2}' /proc/meminfo)"
if [[ "${host_mem_kib}" -ge 6000000 ]]; then
  for spec in 'dokploy 2G 512M 2 0.25' 'dokploy-postgres 1G 256M 1 0.25' 'dokploy-traefik 512M 64M 1 0.1'; do
    read -r service limit_memory reserve_memory limit_cpu reserve_cpu <<< "${spec}"
    memory_limit="$(docker service inspect "${service}" --format '{{.Spec.TaskTemplate.Resources.Limits.MemoryBytes}}')"
    if [[ "${memory_limit}" == "0" || "${memory_limit}" == '<no value>' ]]; then
      docker service update --limit-memory "${limit_memory}" --reserve-memory "${reserve_memory}" \
        --limit-cpu "${limit_cpu}" --reserve-cpu "${reserve_cpu}" \
        --update-failure-action rollback --detach=false --quiet "${service}" >/dev/null
    fi
  done
fi

# PostgreSQL stays on major 16. Major migrations always require a separate
# approved migration/restore plan; only same-major image patches are applied.
docker pull -q "${POSTGRES_CHANNEL}" >/dev/null
postgres_digest="$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "${POSTGRES_CHANNEL}" \
  | awk -F@ '$1 ~ /(^|\/)postgres$/ && $2 ~ /^sha256:[0-9a-f]{64}$/ {print $2;exit}')"
[[ "${postgres_digest}" =~ ^sha256:[0-9a-f]{64}$ ]] \
  || { echo "Cannot resolve PostgreSQL 16 patch digest." >&2; exit 1; }
postgres_image="${POSTGRES_CHANNEL}@${postgres_digest}"
postgres_version="$(docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --entrypoint postgres "${postgres_image}" --version)"
[[ "${postgres_version}" =~ ^postgres\ \(PostgreSQL\)\ 16\.[0-9]+ ]] \
  || { echo "PostgreSQL candidate is outside approved major 16." >&2; exit 1; }
prior_postgres_image="$(docker service inspect dokploy-postgres --format '{{.Spec.TaskTemplate.ContainerSpec.Image}}')"
[[ "${prior_postgres_image}" =~ ^postgres:16@sha256:[0-9a-f]{64}$ ]] \
  || { echo "Database is outside approved PostgreSQL 16 series; refusing update." >&2; exit 1; }
if [[ "${prior_postgres_image}" != "${postgres_image}" ]]; then
  docker service update --image "${postgres_image}" --update-order stop-first \
    --update-failure-action rollback --detach=false --quiet dokploy-postgres >/dev/null
fi
postgres_ready="false"
for attempt in $(seq 1 30); do
  postgres_container="$(docker ps -q --filter label=com.docker.swarm.service.name=dokploy-postgres | head -1)"
  if [[ -n "${postgres_container}" ]] \
    && docker exec "${postgres_container}" pg_isready -U dokploy -d dokploy >/dev/null \
    && [[ "$(docker service inspect dokploy-postgres --format '{{.Spec.TaskTemplate.ContainerSpec.Image}}')" == "${postgres_image}" ]]; then
    postgres_ready="true"
    break
  fi
  (( attempt < 30 )) && sleep 2
done
[[ "${postgres_ready}" == "true" ]] \
  || { echo "PostgreSQL patch did not pass readiness; update not accepted." >&2; exit 1; }

docker pull -q "${DOKPLOY_IMAGE}" >/dev/null
latest_digest="$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "${DOKPLOY_IMAGE}" 2>/dev/null \
  | awk -F@ '$1 ~ /(^|\/)dokploy\/dokploy$/ && $2 ~ /^sha256:[0-9a-f]{64}$/ {print $2; exit}')"
[[ "${latest_digest}" =~ ^sha256:[0-9a-f]{64}$ ]] \
  || { echo "Could not resolve the latest Dokploy image to a trusted digest." >&2; exit 1; }
resolved_image="${DOKPLOY_IMAGE}@${latest_digest}"
current_image="$(docker service inspect dokploy --format '{{.Spec.TaskTemplate.ContainerSpec.Image}}' 2>/dev/null || true)"
updated="false"
if [[ "${current_image}" != "${resolved_image}" ]]; then
  docker service update --image "${resolved_image}" --update-failure-action rollback --detach=false --quiet dokploy >/dev/null
  updated="true"
fi

for attempt in $(seq 1 60); do
  current_image="$(docker service inspect dokploy --format '{{.Spec.TaskTemplate.ContainerSpec.Image}}' 2>/dev/null || true)"
  replicas="$(docker service ls --format '{{.Name}}\t{{.Replicas}}' 2>/dev/null \
    | awk -F '\t' '$1 == "dokploy" { print $2; exit }' || true)"
  running="${replicas%%/*}"
  desired="${replicas##*/}"
  if [[ "${current_image}" == "${resolved_image}" \
    && "${running}" =~ ^[1-9][0-9]*$ && "${running}" == "${desired}" ]]; then
    break
  fi
  (( attempt < 60 )) && sleep 2
done
[[ "${current_image}" == "${resolved_image}" \
  && "${running}" =~ ^[1-9][0-9]*$ && "${running}" == "${desired}" ]] \
  || { echo "Dokploy latest-stable service did not converge." >&2; exit 1; }

# Keep proxy security patches current within the approved minor series only.
# Pull the official channel, resolve it to a digest, and inspect the version
# in an isolated container before granting it the live Docker socket mount.
docker service inspect dokploy-traefik >/dev/null 2>&1 \
  || { echo "Traefik service is missing; refusing automatic proxy update." >&2; exit 1; }
docker pull -q "${TRAEFIK_CHANNEL}" >/dev/null
proxy_digest="$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "${TRAEFIK_CHANNEL}" \
  | awk -F@ '$1 ~ /(^|\/)traefik$/ && $2 ~ /^sha256:[0-9a-f]{64}$/ {print $2;exit}')"
[[ "${proxy_digest}" =~ ^sha256:[0-9a-f]{64}$ ]] \
  || { echo "Cannot resolve the approved Traefik channel to a digest." >&2; exit 1; }
proxy_image="${TRAEFIK_CHANNEL}@${proxy_digest}"
proxy_version="$(docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --entrypoint traefik "${proxy_image}" version \
  | awk '$1 == "Version:" {print $2;exit}')"
[[ "${proxy_version}" =~ ^3\.7\.([0-9]+)$ && "${BASH_REMATCH[1]}" -ge 13 ]] \
  || { echo "Traefik candidate is outside approved 3.7 security floor." >&2; exit 1; }
prior_proxy_image="$(docker service inspect dokploy-traefik --format '{{.Spec.TaskTemplate.ContainerSpec.Image}}')"
if [[ "${prior_proxy_image}" != "${proxy_image}" ]]; then
  docker service update --image "${proxy_image}" --update-failure-action rollback \
    --detach=false --quiet dokploy-traefik >/dev/null
fi
live_proxy_image="$(docker service inspect dokploy-traefik --format '{{.Spec.TaskTemplate.ContainerSpec.Image}}')"
[[ "${live_proxy_image}" == "${proxy_image}" ]] \
  || { echo "Traefik update rolled back or did not select the approved digest." >&2; exit 1; }
proxy_container="$(docker ps -q --filter label=com.docker.swarm.service.name=dokploy-traefik | head -1)"
[[ -n "${proxy_container}" ]] \
  && [[ "$(docker inspect --format '{{.Config.Image}}' "${proxy_container}")" == "${proxy_image}" ]] \
  || { echo "The live Traefik task does not match the approved digest." >&2; exit 1; }
proxy_pid="$(docker inspect --format '{{.State.Pid}}' "${proxy_container}")"
proxy_ok="false"
if [[ "${proxy_pid}" =~ ^[1-9][0-9]*$ ]]; then
  for attempt in $(seq 1 15); do
    block_code="$(curl --noproxy '*' -s -o /dev/null -w '%{http_code}' --max-time 5 \
      -H 'Host: dokploy.docker.localhost' http://127.0.0.1:80 || true)"
    if [[ "${block_code}" == "403" ]] \
      && nsenter -t "${proxy_pid}" -n ss -H -lnt 'sport = :80' | grep -q . \
      && ! nsenter -t "${proxy_pid}" -n ss -H -lnt 'sport = :8080' | grep -q .; then
      proxy_ok="true"
      break
    fi
    (( attempt < 15 )) && sleep 2
  done
fi
if [[ "${proxy_ok}" != "true" ]]; then
  if [[ "${prior_proxy_image}" != "${proxy_image}" ]]; then
    docker service update --image "${prior_proxy_image}" --detach=false --quiet dokploy-traefik >/dev/null || true
  fi
  echo "Traefik live security probes failed; update not accepted." >&2
  exit 1
fi

# A panel update must not weaken the generated host boundary or its protected
# configuration tree. Reconcile both immediately after every latest check.
if [[ -d /etc/dokploy && ! -L /etc/dokploy ]]; then
  chown root:root /etc/dokploy
  chmod 0755 /etc/dokploy
  find /etc/dokploy -xdev -type d -exec chown root:root {} + -exec chmod 0755 {} +
  find /etc/dokploy -xdev -type f -exec chown root:root {} + -exec chmod 0600 {} +
fi
systemctl start docker-user-hardening.service
systemctl start dokploy-tailnet-input-hardening.service
systemctl enable --now docker-user-hardening-refresh.timer

install -d -m 0700 -o root -g root "$(dirname "${UPDATE_STATE}")"
state_tmp="$(mktemp "${UPDATE_STATE}.XXXXXX")"
printf 'last_check_epoch=%s\nresolved_image=%s\nupdated=%s\ntraefik_resolved_image=%s\ntraefik_version=%s\npostgres_resolved_image=%s\nbackup_file=%s\n' \
  "$(date +%s)" "${current_image}" "${updated}" "${proxy_image}" "${proxy_version}" "${postgres_image}" "${backup_file}" > "${state_tmp}"
chown root:root "${state_tmp}"
chmod 0600 "${state_tmp}"
mv -f -- "${state_tmp}" "${UPDATE_STATE}"
# Bounded encrypted retention: retain the newest 28 six-hour snapshots (7d).
# Reject non-generated names and never traverse symlinks or another directory.
mapfile -t old_backups < <(find "${backup_dir}" -maxdepth 1 -type f -name 'dokploy-????????T??????Z.sql.gz.age' -printf '%f\n' | LC_ALL=C sort -r | tail -n +29)
for old_backup in "${old_backups[@]}"; do
  [[ "${old_backup}" =~ ^dokploy-[0-9]{8}T[0-9]{6}Z\.sql\.gz\.age$ ]] || exit 1
  rm -f -- "${backup_dir}/${old_backup}"
done
DOKPLOY_UPDATER
chown root:root "${dokploy_update_tmp}"
chmod 0750 "${dokploy_update_tmp}"
mv -f -- "${dokploy_update_tmp}" "${dokploy_update_script}"

cat > /etc/systemd/system/dokploy-auto-update.service <<'DOKPLOY_UPDATE_SERVICE'
[Unit]
Description=Patch Dokploy, Traefik 3.7 and PostgreSQL 16 with encrypted backups
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/dokploy-auto-update
TimeoutStartSec=30min
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
# nsenter needs access to the real host task /proc namespace for proxy probes.
ProtectSystem=strict
ProtectHome=read-only
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
LockPersonality=true
RestrictSUIDSGID=true
ReadWritePaths=/etc/dokploy /var/lib/server-hardening /run/lock
DOKPLOY_UPDATE_SERVICE

cat > /etc/systemd/system/dokploy-auto-update.timer <<'DOKPLOY_UPDATE_TIMER'
[Unit]
Description=Periodically patch Dokploy, Traefik and PostgreSQL

[Timer]
OnBootSec=15min
OnUnitActiveSec=6h
RandomizedDelaySec=20min
Persistent=true
Unit=dokploy-auto-update.service

[Install]
WantedBy=timers.target
DOKPLOY_UPDATE_TIMER
chown root:root \
  /etc/systemd/system/dokploy-auto-update.service \
  /etc/systemd/system/dokploy-auto-update.timer
chmod 0644 \
  /etc/systemd/system/dokploy-auto-update.service \
  /etc/systemd/system/dokploy-auto-update.timer
if [[ -f /etc/dokploy/security-image-policy.json && ! -L /etc/dokploy/security-image-policy.json \
  && "$(stat -c '%a:%U:%G' /etc/dokploy/security-image-policy.json)" == '600:root:root' \
  && -f /root/overlays/dokploy/maintenance/install.sh ]]; then
  bash /root/overlays/dokploy/maintenance/install.sh --refresh-installed
fi
systemctl daemon-reload
systemctl start dokploy-auto-update.service
systemctl enable --now dokploy-auto-update.timer >/dev/null

if docker service inspect dokploy >/dev/null 2>&1; then
  panel_image="$(docker service inspect dokploy --format '{{.Spec.TaskTemplate.ContainerSpec.Image}}' 2>/dev/null || true)"
  { [[ "${panel_image}" =~ ^dokploy/dokploy:latest@sha256:[0-9a-f]{64}$ ]] \
    || { [[ -x /usr/local/sbin/paas-image-provenance ]] \
      && /usr/local/sbin/paas-image-provenance dokploy "${panel_image}" >/dev/null 2>&1; }; } \
    || { echo "Dokploy service is not tracking latest stable by resolved digest: ${panel_image:-unavailable}" >&2; exit 1; }
fi

# Docker is installed before Dokploy is finalized. Rebuild and load the
# container-runtime audit rules now; the bootstrap may have run before Docker
# binaries and /var/run/docker.sock existed.
if [[ -x /usr/local/sbin/hardening-auditd-runtime-reconcile ]]; then
  /usr/local/sbin/hardening-auditd-runtime-reconcile
fi

# Bootstrap writes state before Docker/Dokploy exists. Refresh the runtime
# keys after finalization so future validators and resume decisions describe
# the host that is actually running, not the pre-install substrate.
state_file="/var/lib/server-hardening/state"
if [[ -L "${state_file}" || ( -e "${state_file}" && ! -f "${state_file}" ) ]]; then
  echo "${state_file} is a symlink or unexpected file" >&2
  exit 1
fi
if [[ -f "${state_file}" ]]; then
  exec 8>"${state_file}.lock"
  flock -x 8
  set_state_key() {
    local key="$1" value="$2"
    if grep -q "^${key}=" "${state_file}"; then
      sed -i "s|^${key}=.*|${key}=${value}|" "${state_file}"
    else
      printf '%s=%s\n' "${key}" "${value}" >> "${state_file}"
    fi
  }
  # The finalizer runs after the initial substrate state write and also on
  # --ts-ip resumes. Refresh both the version and timestamp so the state file
  # describes this reconciliation, not the pre-Dokploy bootstrap.
  set_state_key script_version "1.2.9"
  set_state_key applied_at "$(date -Iseconds)"
  set_state_key docker_present true
  if systemctl is-active --quiet docker-user-hardening.service 2>/dev/null \
    && iptables -t filter -S SECURE-DOCKER-USER 2>/dev/null | grep -q 'coolify-hardening-bridge-docker-gw' \
    && iptables -t filter -S SECURE-DOCKER-USER 2>/dev/null | grep -q 'coolify-hardening-unmatched-drop'; then
    set_state_key docker_rules_applied true
  else
    set_state_key docker_rules_applied false
  fi
  current_tailscale_ip="$(tailscale ip -4 2>/dev/null || true)"
  [[ "${current_tailscale_ip}" =~ ^100\.(6[4-9]|[78][0-9]|9[0-9]|1[01][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3}$ ]] \
    && set_state_key tailscale_ip "${current_tailscale_ip}"
  chmod 0640 "${state_file}"
  flock -u 8
  exec 8>&-
fi
EOF
}

dokploy_install_dokploy_script() {
  cat <<'EOF'
set -Eeuo pipefail
installer_url="https://dokploy.com/install.sh"
export DOKPLOY_VERSION="latest"
tmp="$(mktemp /run/dokploy-install.XXXXXX.sh)"
cleanup() { rm -f -- "${tmp}"; }
trap cleanup EXIT

curl --proto '=https' --proto-redir '=https' --tlsv1.2 \
  --fail --show-error --silent --location --connect-timeout 10 --max-time 120 \
  --retry 3 --retry-delay 2 "${installer_url}" -o "${tmp}"
[[ -s "${tmp}" ]] || { echo "Downloaded Dokploy installer is empty" >&2; exit 1; }
head -1 "${tmp}" | grep -Eq '^#!.*/(ba)?sh$' || { echo "Unexpected Dokploy installer header" >&2; exit 1; }
installer_size="$(wc -c < "${tmp}" | tr -d '[:space:]')"
[[ "${installer_size}" =~ ^[0-9]+$ && "${installer_size}" -ge 5000 && "${installer_size}" -le 200000 ]] \
  || { echo "Downloaded Dokploy installer has an unexpected size" >&2; exit 1; }
grep -Fq 'dokploy/dokploy' "${tmp}" \
  && grep -Fq 'docker service create' "${tmp}" \
  && grep -Fq 'docker swarm init' "${tmp}" \
  || { echo "Downloaded Dokploy installer is missing required operations" >&2; exit 1; }
chmod 700 "${tmp}"
run_installer_redacted() {
  local -a installer_pipeline_status=()
  set +e
  "$@" 2>&1 | sed -E \
    -e 's/SWMTKN-[A-Za-z0-9_-]+/[REDACTED-SWARM-JOIN-TOKEN]/g' \
    -e 's/SWMKEY-[A-Za-z0-9_-]+/[REDACTED-SWARM-UNLOCK-KEY]/g'
  installer_pipeline_status=("${PIPESTATUS[@]}")
  set -e
  (( installer_pipeline_status[1] == 0 )) || return "${installer_pipeline_status[1]}"
  return "${installer_pipeline_status[0]}"
}
if command -v timeout >/dev/null 2>&1; then
  run_installer_redacted timeout --signal=TERM --kill-after=60 1800 bash "${tmp}" || rc=$?
  rc="${rc:-0}"
else
  run_installer_redacted bash "${tmp}" || rc=$?
  rc="${rc:-0}"
fi
if [[ "${rc}" -ne 0 ]]; then
  if [[ "${rc}" -eq 124 || "${rc}" -eq 137 ]]; then
    echo "Dokploy installer timed out after 1800s (likely blocked image pull or Swarm task convergence)." >&2
  fi
  exit "${rc}"
fi
EOF
}


dokploy_phase3_install_shared() {
  local has_docker_fn="$1"
  local install_docker_fn="$2"
  local start_docker_user_fn="$3"
  local verify_docker_user_fn="$4"
  local has_dokploy_fn="$5"
  local install_dokploy_fn="$6"
  local reconcile_docker_daemon_fn="$7"
  local restart_docker_user_fn="$8"
  local sync_docker_ssh_cidrs_fn="$9"
  local finalize_dokploy_runtime_fn="${10:-}"

  step "3/5" "Install Docker & Dokploy"

  if "${has_docker_fn}"; then
    log "Docker already installed — skipping install."
  else
    log "Installing Docker via official apt repository..."
    run_with_heartbeat "Docker installation" "${install_docker_fn}" \
      || die "Docker installation failed."
    pass "Docker installed"
  fi
  pass "Docker present"

  "${start_docker_user_fn}" || die "Failed to start docker-user-hardening.service"
  "${verify_docker_user_fn}" "Gate D"

  if "${has_dokploy_fn}"; then
    log "Dokploy service found — skipping install (already installed)."
    pass "Dokploy already installed"
  else
    log "Installing Dokploy via official installer (this may take a few minutes)..."
    run_with_heartbeat "Dokploy installation" "${install_dokploy_fn}" \
      || die "Dokploy installation failed."
    pass "Dokploy installed"
  fi

  "${reconcile_docker_daemon_fn}"
  "${restart_docker_user_fn}" \
    || die "Failed to restart docker-user-hardening.service after Docker daemon reconciliation."
  "${verify_docker_user_fn}" "Gate D (post-Dokploy)"

  if [[ -n "${sync_docker_ssh_cidrs_fn}" ]]; then
    log "Reconciling Docker bridge SSH CIDRs..."
    "${sync_docker_ssh_cidrs_fn}" || die "Failed to reconcile Docker bridge SSH CIDRs."
    pass "Docker bridge SSH CIDRs reconciled"
  else
    log "Skipping Docker bridge SSH CIDR sync: Dokploy root SSH is Tailscale-only."
    pass "Docker bridge SSH CIDR sync not applicable (Dokploy)"
  fi

  if [[ -n "${finalize_dokploy_runtime_fn}" ]]; then
    log "Finalizing Dokploy runtime (Swarm autolock handoff, Traefik, daemon reconcile)..."
    run_with_heartbeat "Dokploy runtime finalization" "${finalize_dokploy_runtime_fn}" \
      || die "Dokploy runtime finalization failed."
    pass "Dokploy runtime finalized"
  fi

}

dokploy_phase4_routing_shared() {
  local configure_dashboard_ufw_fn="$1"
  local remove_stale_coolify_ufw_fn="${2:-}"

  step "4/5" "Configure Dokploy access policy"
  if [[ -n "${remove_stale_coolify_ufw_fn}" ]]; then
    log "Removing stale Coolify dashboard/Soketi/terminal UFW rules..."
    "${remove_stale_coolify_ufw_fn}" || die "Failed to remove stale Coolify UFW rules."
    pass "Stale Coolify dashboard UFW rules removed"
  fi
  log "Applying staged Dokploy dashboard policy (operator-only until admin+TOTP, then Tailscale) while leaving public 80/443 for apps..."
  "${configure_dashboard_ufw_fn}" || die "Failed to configure Dokploy dashboard/API firewall policy."
  pass "Dokploy dashboard/API staged firewall policy applied"
}

dokploy_phase5_verify_shared() {
  local fetch_validate_json_fn="${1:-}"
  local access_mode="${2:-external}"
  local operator_confirm_fn="${3:-}"
  local reconcile_dashboard_ufw_fn="${4:-}"
  [[ -n "${fetch_validate_json_fn}" ]] || die "dokploy_phase5_verify_shared requires fetch_validate_json_fn"

  step "5/5" "Final verification"

  log "Gate F: Running base/validate.sh on the Dokploy host..."
  local validate_json
  # validate.sh deliberately exits nonzero when its JSON contains FAIL checks.
  # Preserve that structured output so enrollment failures can drive the staged
  # operator flow; fail only when the output itself is absent or malformed.
  validate_json="$("${fetch_validate_json_fn}")" || true
  jq -e 'type == "object" and (.checks | type == "array") and (.fail | type == "number")' \
    >/dev/null 2>&1 <<< "${validate_json}" \
    || die "Gate F failed: validate.sh did not produce valid JSON output."

  local enrollment_passes
  enrollment_passes="$(jq -r '[.checks[] | select((.check == "dokploy: first admin registered" or .check == "dokploy: panel accounts use 2FA") and .status == "PASS")] | length' \
    <<< "${validate_json}" 2>/dev/null || echo 0)"
  if [[ "${enrollment_passes}" != "2" ]]; then
    log "Dokploy enrollment gate: the dashboard remains restricted to the provisioning operator."
    log "From that Tailscale device, open http://${TS_IP}:3000, create the first administrator, and enable TOTP 2FA."
    [[ -n "${operator_confirm_fn}" ]] \
      || die "Dokploy enrollment is incomplete; rerun after first-admin registration and TOTP enrollment."
    "${operator_confirm_fn}" \
      "Complete Dokploy first-admin registration and TOTP 2FA from the authorized Tailscale device (${access_mode}), then continue"
    [[ -n "${reconcile_dashboard_ufw_fn}" ]] \
      || die "Dokploy enrollment completed but no dashboard firewall reconciler was provided."
    "${reconcile_dashboard_ufw_fn}" \
      || die "Failed to promote Dokploy dashboard policy after enrollment."
    validate_json="$("${fetch_validate_json_fn}")" || true
    jq -e 'type == "object" and (.checks | type == "array") and (.fail | type == "number")' \
      >/dev/null 2>&1 <<< "${validate_json}" \
      || die "Gate F failed: validate.sh did not produce valid JSON output after enrollment."
  fi
  report_validation_result "Gate F" "${validate_json}" \
    "Gate F failed. Fix validation failures before using this Dokploy host."
  print_dokploy_deployment_summary
}

dokploy_summary_box_print_field() {
  local label="$1" value="$2" prefix available chunk
  local width=59
  printf -v prefix '  %-16s: ' "${label}"
  while :; do
    available=$(( width - ${#prefix} ))
    if (( ${#value} <= available )); then
      printf '│ %s%-*s│\n' "${prefix}" "${available}" "${value}"
      return 0
    fi
    chunk="${value:0:available}"
    [[ "${chunk}" != *" "* || "${value:available:1}" == " " ]] || chunk="${chunk% *}"
    [[ -n "${chunk}" ]] || chunk="${value:0:available}"
    printf '│ %s%-*s│\n' "${prefix}" "${available}" "${chunk}"
    value="${value:${#chunk}}"
    value="${value## }"
    prefix="                    "
  done
}

print_dokploy_deployment_summary() {
  printf '\n'
  printf '┌─────────────────────────────────────────────────────────────┐\n'
  printf '│                    DOKPLOY DEPLOYMENT READY                 │\n'
  printf '├─────────────────────────────────────────────────────────────┤\n'
  dokploy_summary_box_print_field "Server Public IP" "${SERVER_IP}"
  dokploy_summary_box_print_field "Tailscale IP" "${TS_IP}"
dokploy_summary_box_print_field "Metadata User" "${ADMIN_USER} (SSH disabled)"
  dokploy_summary_box_print_field "Server Timezone" "${SERVER_TIMEZONE}"
  dokploy_summary_box_print_field "Dashboard URL" "http://${TS_IP}:3000"
dokploy_summary_box_print_field "SSH Access" "ssh root@${TS_IP}"
  dokploy_summary_box_print_field "Public Ingress" "80/tcp and 443/tcp only"
  [[ -n "${DOMAIN:-}" ]] && dokploy_summary_box_print_field "App Domain" "${DOMAIN}"
  printf '├─────────────────────────────────────────────────────────────┤\n'
  dokploy_summary_box_print_field "Public Dashboard" "blocked by UFW + DOCKER-USER"
  dokploy_summary_box_print_field "Docker API/Swarm" "not exposed publicly"
  printf '└─────────────────────────────────────────────────────────────┘\n'
  printf '\n'
  log "Next steps:"
  log "  1. First-admin registration and TOTP 2FA are complete; keep every administrator enrolled in 2FA."
  log "  2. Create a Dokploy API key and use the Tailscale URL for CLI/MCP/API automation."
  log "  3. Point public app DNS records at ${SERVER_IP}; do not create public DNS for the dashboard."
  log "  4. Configure Dokploy backups and run a restore test before trusting production data."
  log "  5. Keep the Swarm unlock key in the operator's protected external store; a Docker restart requires a deliberate manual unlock."
  log ""
  log "SECURITY — never set a panel domain in Dokploy Settings → Web Server:"
  log "  it writes a Traefik route that re-exposes the dashboard on public 80/443,"
  log "  bypassing the UFW port-3000 lockdown. The validator fails if one is set."
}
