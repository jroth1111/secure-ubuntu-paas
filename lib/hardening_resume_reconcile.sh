#!/usr/bin/env bash
# lib/hardening_resume_reconcile.sh — Idempotent host-side reconciles for resume/update runs.
# Emits a bash script for remote (deploy.sh) or local (setup.sh) execution so Gate C
# does not fail on checks added after the original bootstrap.

[[ "${BASH_SOURCE[0]}" != "${0}" ]] \
  || { printf 'Source this file, do not execute it.\n' >&2; exit 1; }

hardening_resume_reconcile_script() {
  cat <<'EOF'
set -Eeuo pipefail

DRY_RUN="false"
is_true() {
  case "${1,,}" in 1|true|yes|y|on) return 0 ;; *) return 1 ;; esac
}
run() { "$@"; }
log() { printf '%s\n' "$*"; }
warn() { printf 'WARN: %s\n' "$*" >&2; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
if command -v tailscale >/dev/null 2>&1; then
  tailscale set --auto-update=true
fi
write_file() {
  local path="$1" mode="$2" owner="$3" group="$4" tmp
  tmp="$(mktemp)"
  cat > "${tmp}"
  install -d -m 0755 "$(dirname "${path}")"
  install -m "${mode}" -o "${owner}" -g "${group}" "${tmp}" "${path}"
  rm -f -- "${tmp}"
}

# Provider networking: some VPS images configure a static IPv6 address with
# an off-subnet default gateway but omit Netplan's on-link marker.  The base
# module owns the narrowly-scoped, rollback-backed repair; resume must invoke
# it too because --ts-ip deliberately skips the full phase-1 bootstrap.
network_services_module="/root/base/modules/services.sh"
if [[ -f "${network_services_module}" ]] && command -v netplan >/dev/null 2>&1; then
  source "${network_services_module}"
  WAN_IFACE="$(awk -F= '$1 == "wan_iface" { print substr($0, index($0, "=") + 1); exit }' /var/lib/server-hardening/state 2>/dev/null || true)"
  if [[ -z "${WAN_IFACE}" ]]; then
    WAN_IFACE="$(ip route show default 2>/dev/null | awk 'NR == 1 { print $5; exit }')"
  fi
  [[ -n "${WAN_IFACE}" ]] || { echo "Unable to determine WAN interface for Netplan reconciliation." >&2; exit 1; }
  NETPLAN_CONFIG_DIR="/etc/netplan"
  repair_netplan_offlink_ipv6_default_route
fi

# UFW applies its own sysctl file after systemd-sysctl and Ubuntu defaults
# log_martians back to zero there. Reconcile the later writer on every resume.
kernel_sysctl_module="/root/base/modules/kernel_sysctl.sh"
if [[ -f "${kernel_sysctl_module}" ]]; then
  source "${kernel_sysctl_module}"
  UFW_SYSCTL_FILE="/etc/ufw/sysctl.conf"
  configure_ufw_sysctl_martian_logging
fi

# Rsyslog: /var/log must not be writable by service groups, and known log
# paths must never be followed through a symlink on a resume.
rsyslog_module="/root/base/modules/rsyslog.sh"
if [[ -f "${rsyslog_module}" ]]; then
  source "${rsyslog_module}"
  RSYSLOG_TMPFILES_OVERRIDE="/etc/tmpfiles.d/00rsyslog.conf"
  install_rsyslog_tmpfiles_override
fi
install -d -m 0755 -o root -g root /var/log
chown root:root /var/log
chmod 0755 /var/log
hardening_log_file="/var/log/server-hardening.log"
if [[ -L "${hardening_log_file}" || ( -e "${hardening_log_file}" && ! -f "${hardening_log_file}" ) ]]; then
  rm -f -- "${hardening_log_file}"
fi
if [[ ! -e "${hardening_log_file}" ]]; then
  install -m 0600 -o root -g root /dev/null "${hardening_log_file}"
fi
[[ -f "${hardening_log_file}" && ! -L "${hardening_log_file}" ]] || exit 1
chown root:root "${hardening_log_file}"
chmod 0600 "${hardening_log_file}"

rsyslog_owner="syslog"
rsyslog_group="adm"
getent passwd "${rsyslog_owner}" >/dev/null 2>&1 || rsyslog_owner="root"
getent group "${rsyslog_group}" >/dev/null 2>&1 || rsyslog_group="syslog"
getent group "${rsyslog_group}" >/dev/null 2>&1 || rsyslog_group="root"
rsyslog_configs=()
[[ -f /etc/rsyslog.conf ]] && rsyslog_configs+=(/etc/rsyslog.conf)
for rsyslog_cfg in /etc/rsyslog.d/*.conf; do
  [[ -f "${rsyslog_cfg}" ]] || continue
  rsyslog_configs+=("${rsyslog_cfg}")
done
if ((${#rsyslog_configs[@]} > 0)); then
  while IFS= read -r rsyslog_target; do
    [[ -n "${rsyslog_target}" ]] || continue
    rsyslog_target_dir="$(dirname "${rsyslog_target}")"
    if [[ -L "${rsyslog_target_dir}" ]]; then
      rm -f -- "${rsyslog_target_dir}"
    fi
    [[ ! -e "${rsyslog_target_dir}" || -d "${rsyslog_target_dir}" ]] || exit 1
    install -d -m 0755 -o root -g root "${rsyslog_target_dir}"
    if [[ -L "${rsyslog_target}" || ( -e "${rsyslog_target}" && ! -f "${rsyslog_target}" ) ]]; then
      rm -f -- "${rsyslog_target}"
    fi
    if [[ ! -e "${rsyslog_target}" ]]; then
      install -m 0640 -o "${rsyslog_owner}" -g "${rsyslog_group}" /dev/null "${rsyslog_target}"
    else
      [[ -f "${rsyslog_target}" && ! -L "${rsyslog_target}" ]] || exit 1
      chown "${rsyslog_owner}:${rsyslog_group}" "${rsyslog_target}"
      chmod 0640 "${rsyslog_target}"
    fi
  done < <(awk '
    /^[[:space:]]*#/ { next }
    {
      for (i = 1; i <= NF; i++) {
        tok = $i
        if (tok ~ /^-?\/var\/log\//) {
          sub(/^-/, "", tok)
          sub(/[;,]+$/, "", tok)
          print tok
        }
      }
    }
  ' "${rsyslog_configs[@]}" | sort -u)
  if systemctl show --property=LoadState --value rsyslog.service 2>/dev/null | grep -qv '^not-found$'; then
    systemctl restart rsyslog
  fi
fi

# VPS hosts do not have firmware to refresh.  Keep the static refresh service
# and its timer masked on resume so neither can leave the host degraded.
for fwupd_unit in fwupd-refresh.service fwupd-refresh.timer; do
  if systemctl show --property=LoadState --value "${fwupd_unit}" 2>/dev/null | grep -qv '^not-found$'; then
    systemctl disable --now "${fwupd_unit}" 2>/dev/null || true
    systemctl mask "${fwupd_unit}" 2>/dev/null || true
    systemctl reset-failed "${fwupd_unit}" 2>/dev/null || true
  fi
done

# Sysctl drift: repair martian logging on existing interfaces as well as the
# all/default controls.  The persistent drop-in is owned by kernel_sysctl.sh;
# this runtime reconcile closes the gap for interfaces created after boot.
if command -v sysctl >/dev/null 2>&1; then
  sysctl -w net.ipv4.conf.all.log_martians=1 >/dev/null
  sysctl -w net.ipv4.conf.default.log_martians=1 >/dev/null
  sysctl -w net.ipv6.conf.all.accept_ra=0 >/dev/null
  sysctl -w net.ipv6.conf.default.accept_ra=0 >/dev/null
  for iface_path in /proc/sys/net/ipv4/conf/*/log_martians; do
    [[ -e "${iface_path}" ]] || continue
    iface="${iface_path%/log_martians}"
    iface="${iface##*/}"
    sysctl -w "net.ipv4.conf.${iface}.log_martians=1" >/dev/null
  done
  for iface_path in /proc/sys/net/ipv6/conf/*/accept_ra; do
    [[ -e "${iface_path}" ]] || continue
    iface="${iface_path%/accept_ra}"
    iface="${iface##*/}"
    sysctl -w "net.ipv6.conf.${iface}.accept_ra=0" >/dev/null
  done
fi

# Audit attribution: keep loginuid immutable after it is assigned.  This is
# deliberately reconciled on every resume so an older host state is repaired
# before Gate C and the state file records the live result.
audit_rules_file="/etc/audit/rules.d/60-coolify-baseline.rules"
install -d -m 0755 -o root -g root "$(dirname "${audit_rules_file}")"
if [[ ! -f "${audit_rules_file}" ]]; then
  install -m 0640 -o root -g root /dev/null "${audit_rules_file}"
fi
audit_enabled=""
if command -v auditctl >/dev/null 2>&1; then
  audit_enabled="$(auditctl -s 2>/dev/null | awk '$1 == "enabled" {print $2; exit}' || true)"
fi
if ! grep -Fq -- '--loginuid-immutable' "${audit_rules_file}"; then
  printf '\n# Managed by secure-ubuntu-paas: preserve audit attribution.\n--loginuid-immutable\n' >> "${audit_rules_file}"
  chmod 0640 "${audit_rules_file}"
  if [[ "${audit_enabled}" != "2" ]]; then
    augenrules --load
  fi
fi
if command -v auditctl >/dev/null 2>&1; then
  audit_enabled="$(auditctl -s 2>/dev/null | awk '$1 == "enabled" {print $2; exit}' || true)"
fi
if [[ "${audit_enabled}" != "2" ]] \
  && command -v auditctl >/dev/null 2>&1 \
  && auditctl --loginuid-immutable >/dev/null 2>&1; then
  state_file="/var/lib/server-hardening/state"
  if [[ -L "${state_file}" || ( -e "${state_file}" && ! -f "${state_file}" ) ]]; then
    echo "${state_file} is a symlink or unexpected file" >&2
    exit 1
  fi
  if [[ -f "${state_file}" ]]; then
    exec 8>"${state_file}.lock"
    flock -x 8
    if grep -q '^audit_loginuid_immutable=' "${state_file}"; then
      sed -i 's/^audit_loginuid_immutable=.*/audit_loginuid_immutable=true/' "${state_file}"
    else
      printf 'audit_loginuid_immutable=true\n' >> "${state_file}"
    fi
    chmod 0640 "${state_file}"
    flock -u 8
    exec 8>&-
  fi
fi

# Rebuild Docker-specific audit rules after a PaaS has installed Docker. A
# phase-1 bootstrap legitimately cannot emit path rules for absent binaries or
# sockets, so resume must repair and load the complete runtime policy.
auditd_runtime_reconcile_dest="/usr/local/sbin/hardening-auditd-runtime-reconcile"
cat > "${auditd_runtime_reconcile_dest}" <<'AUDITRUNTIMEEOF'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ ! -f /root/base/modules/auditd.sh ]]; then
  echo "auditd module tree is missing" >&2
  exit 1
fi
source /root/base/modules/auditd.sh
DRY_RUN="false"
AUDIT_RULES_FILE="/etc/audit/rules.d/60-coolify-baseline.rules"
AUDITD_CONF_FILE="/etc/audit/auditd.conf"
is_true() {
  case "${1,,}" in 1|true|yes|y|on) return 0 ;; *) return 1 ;; esac
}
run() { "$@"; }
log() { printf '%s\n' "$*"; }
warn() { printf '%s\n' "$*" >&2; }
configure_auditd
AUDITRUNTIMEEOF
chmod 0750 "${auditd_runtime_reconcile_dest}"

# Persist the Ubuntu auditd runtime event rate across every future daemon
# restart; rate_limit is not accepted in this host's auditd.conf parser.
auditd_rate_limit_dest="/usr/local/sbin/hardening-auditd-rate-limit"
cat > "${auditd_rate_limit_dest}" <<'RATELIMITEOF'
#!/usr/bin/env bash
set -Eeuo pipefail
command -v auditctl >/dev/null 2>&1 || { echo "auditctl is unavailable" >&2; exit 1; }
current_rate="$(auditctl -s 2>/dev/null | awk '$1 == "rate_limit" {print $2; exit}' || true)"
if [[ "${current_rate}" == "10000" ]]; then
  exit 0
fi
audit_enabled="$(auditctl -s 2>/dev/null | awk '$1 == "enabled" {print $2;exit}')"
if [[ "${audit_enabled}" == "2" ]]; then
  echo "Audit rate change staged for next boot; immutable live policy left untouched." >&2
  exit 0
fi
auditctl -r 10000 >/dev/null
RATELIMITEOF
chmod 0750 "${auditd_rate_limit_dest}"
install -d -m 0755 -o root -g root /etc/systemd/system/auditd.service.d
cat > /etc/systemd/system/auditd.service.d/10-secure-ubuntu-paas-rate-limit.conf <<'AUDITDROPINEOF'
[Service]
ExecStartPost=
ExecStartPost=/usr/local/sbin/hardening-auditd-rate-limit
ExecStartPost=-/sbin/augenrules --load
AUDITDROPINEOF
chmod 0644 /etc/systemd/system/auditd.service.d/10-secure-ubuntu-paas-rate-limit.conf
if command -v docker >/dev/null 2>&1 && systemctl is-active --quiet docker.service 2>/dev/null; then
  "${auditd_runtime_reconcile_dest}"
fi

# Docker firewall policy: companion scripts are re-uploaded on every resume,
# so also reinstall the current DOCKER-USER asset before starting its unit.
# Merely restarting the old unit would leave a pre-existing unconditional
# RETURN ahead of newly appended rules.  The module owns the generated
# fail-closed dedicated-chain reconciler; this small adapter only supplies its
# normal root-owned write_file contract.
docker_user_module="/root/overlays/docker-host/modules/user_rules.sh"
docker_user_env="/etc/default/docker-user-hardening"
if [[ -f "${docker_user_module}" ]]; then
  docker_user_wan_iface=""
  docker_user_tunnel_mode=""
  docker_user_management_port=""
  if [[ -r "${docker_user_env}" ]]; then
    docker_user_wan_iface="$(awk -F= '$1 == "WAN_IFACE" { print substr($0, index($0, "=") + 1); exit }' "${docker_user_env}")"
    docker_user_tunnel_mode="$(awk -F= '$1 == "TUNNEL_MODE" { print substr($0, index($0, "=") + 1); exit }' "${docker_user_env}")"
    docker_user_management_port="$(awk -F= '$1 == "DOCKER_USER_MANAGEMENT_PORT" { print substr($0, index($0, "=") + 1); exit }' "${docker_user_env}")"
  fi
  if [[ -z "${docker_user_management_port}" ]] \
    && grep -qx 'paas=dokploy' /var/lib/server-hardening/state 2>/dev/null; then
    docker_user_management_port="3000"
  fi
  case "${docker_user_tunnel_mode}" in
    true|false) ;;
    *)
      echo "Refusing Docker firewall resume: /etc/default/docker-user-hardening has missing or invalid TUNNEL_MODE='${docker_user_tunnel_mode}'." >&2
      exit 1
      ;;
  esac
  if [[ -z "${docker_user_wan_iface}" ]]; then
    docker_user_wan_iface="$(ip route show default 2>/dev/null | awk 'NR == 1 { print $5; exit }')"
  fi
  if [[ -n "${docker_user_wan_iface}" ]]; then
    source "${docker_user_module}"
    WAN_IFACE="${docker_user_wan_iface}"
    TAILSCALE_IFACE="tailscale0"
    TUNNEL_MODE="${docker_user_tunnel_mode:-false}"
    DOCKER_USER_SCRIPT="/usr/local/sbin/docker-user-hardening.sh"
    DOCKER_USER_ENV_FILE="${docker_user_env}"
    DOCKER_USER_UNIT_FILE="/etc/systemd/system/docker-user-hardening.service"
    DOCKER_USER_REFRESH_SERVICE_FILE="/etc/systemd/system/docker-user-hardening-refresh.service"
    DOCKER_USER_REFRESH_TIMER_FILE="/etc/systemd/system/docker-user-hardening-refresh.timer"
    DOCKER_USER_MANAGEMENT_PORT="${docker_user_management_port}"
    write_file() {
      local path="$1" mode="$2" owner="$3" group="$4" tmp
      tmp="$(mktemp)"
      cat > "${tmp}"
      install -d -m 0755 "$(dirname "${path}")"
      install -m "${mode}" -o "${owner}" -g "${group}" "${tmp}" "${path}"
      rm -f "${tmp}"
    }
    install_docker_user_assets
    systemctl daemon-reload
    if systemctl show --property=LoadState --value docker.service 2>/dev/null | grep -qv '^not-found$'; then
      systemctl enable docker-user-hardening.service
      # enable --now does not rerun a RemainAfterExit oneshot that is already
      # active; restart is required after replacing its ExecStart asset.
      systemctl restart docker-user-hardening.service
      source /root/overlays/docker-host/modules/readiness.sh
      DOCKER_PRESENT="true"
      docker_user_rules_present || {
        echo "Docker firewall resume did not produce the requested live IPv4/IPv6 policy." >&2
        exit 1
      }
      systemctl enable --now docker-user-hardening-refresh.timer
    fi
  fi
fi

# Keep state-derived checks truthful after Docker or a PaaS was installed
# after the original bootstrap write. The state file is root-owned control
# data; refuse symlinks before updating only the boolean runtime keys.
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
  docker_present_state="false"
  if command -v docker >/dev/null 2>&1 && systemctl is-active --quiet docker.service 2>/dev/null; then
    docker_present_state="true"
  fi
  docker_rules_state="false"
  if [[ "${docker_present_state}" == "true" ]] \
    && systemctl is-active --quiet docker-user-hardening.service 2>/dev/null \
    && iptables -t filter -S SECURE-DOCKER-USER 2>/dev/null | grep -q 'coolify-hardening-bridge-docker-gw' \
    && iptables -t filter -S SECURE-DOCKER-USER 2>/dev/null | grep -q 'coolify-hardening-unmatched-drop'; then
    docker_rules_state="true"
  fi
  set_state_key docker_present "${docker_present_state}"
  set_state_key docker_rules_applied "${docker_rules_state}"
  if command -v tailscale >/dev/null 2>&1; then
    current_tailscale_ip="$(tailscale ip -4 2>/dev/null || true)"
    [[ "${current_tailscale_ip}" =~ ^100\.(6[4-9]|[78][0-9]|9[0-9]|1[01][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3}$ ]] \
      && set_state_key tailscale_ip "${current_tailscale_ip}"
  fi
  chmod 0640 "${state_file}"
  flock -u 8
  exec 8>&-
fi

# Kernel module blacklist (matches base/modules/kernel_modules.sh).
modules_dropin="/etc/modprobe.d/99-zzz-hardening-modules.conf"
if [[ ! -f "${modules_dropin}" ]]; then
  cat > "${modules_dropin}" <<'MODULES'
# Managed by secure-ubuntu-paas hardening — block unused kernel modules.
# install <mod> /bin/false refuses autoload AND explicit modprobe.
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
MODULES
  chmod 0644 "${modules_dropin}"
fi

# Daily validation timer (matches base/modules/validation_timer.sh).
validate_src="/root/base/validate.sh"
validate_dest="/root/base/validate.sh"
auditd_reconcile_dest="/usr/local/sbin/hardening-auditd-loginuid-reconcile"
sysctl_reconcile_dest="/usr/local/sbin/hardening-sysctl-reconcile"
if [[ -f "${validate_src}" && -f /root/base/checks/_runtime.sh && -d /root/base/modules && -d /root/overlays ]]; then
  chmod 0750 "${validate_dest}"
  legacy_validator="/usr/local/sbin/validate-hardening"
  if [[ -L "${legacy_validator}" || ( -e "${legacy_validator}" && ! -f "${legacy_validator}" ) ]]; then
    echo "${legacy_validator} is a symlink or unexpected file" >&2
    exit 1
  fi
  rm -f -- "${legacy_validator}"
  cat > "${sysctl_reconcile_dest}" <<'SYSCTLEOF'
#!/usr/bin/env bash
set -Eeuo pipefail

sysctl -w net.ipv4.conf.all.log_martians=1 >/dev/null
sysctl -w net.ipv4.conf.default.log_martians=1 >/dev/null
sysctl -w net.ipv6.conf.all.accept_ra=0 >/dev/null
sysctl -w net.ipv6.conf.default.accept_ra=0 >/dev/null
for iface_path in /proc/sys/net/ipv4/conf/*/log_martians; do
  [[ -e "${iface_path}" ]] || continue
  iface="${iface_path%/log_martians}"
  iface="${iface##*/}"
  sysctl -w "net.ipv4.conf.${iface}.log_martians=1" >/dev/null
done
for iface_path in /proc/sys/net/ipv6/conf/*/accept_ra; do
  [[ -e "${iface_path}" ]] || continue
  iface="${iface_path%/accept_ra}"
  iface="${iface##*/}"
  sysctl -w "net.ipv6.conf.${iface}.accept_ra=0" >/dev/null
done
SYSCTLEOF
  chmod 0750 "${sysctl_reconcile_dest}"
  cat > "${auditd_reconcile_dest}" <<'AUDITEOF'
#!/usr/bin/env bash
set -Eeuo pipefail

rules_file="/etc/audit/rules.d/60-coolify-baseline.rules"
install -d -m 0755 -o root -g root "$(dirname "${rules_file}")"
if [[ ! -f "${rules_file}" ]]; then
  install -m 0640 -o root -g root /dev/null "${rules_file}"
fi
if ! grep -Fq -- '--loginuid-immutable' "${rules_file}"; then
  printf '\n# Managed by secure-ubuntu-paas: preserve audit attribution.\n--loginuid-immutable\n' >> "${rules_file}"
  chmod 0640 "${rules_file}"
  audit_enabled="$(auditctl -s 2>/dev/null | awk '$1 == "enabled" {print $2; exit}' || true)"
  if [[ "${audit_enabled}" != "2" ]]; then
    augenrules --load
  fi
fi
audit_enabled="$(auditctl -s 2>/dev/null | awk '$1 == "enabled" {print $2; exit}' || true)"
if [[ "${audit_enabled}" != "2" ]]; then
  auditctl --loginuid-immutable
fi
AUDITEOF
  chmod 0750 "${auditd_reconcile_dest}"
  ssh_socket_reconcile_dest="/usr/local/sbin/hardening-ssh-socket-reconcile"
  cat > "${ssh_socket_reconcile_dest}" <<'SSHEOF'
#!/usr/bin/env bash
set -Eeuo pipefail

socket_unit="ssh.socket"
socket_dropin="/etc/systemd/system/ssh.socket.d/10-bind-tailscale.conf"
systemctl show --property=LoadState --value "${socket_unit}" 2>/dev/null | grep -qv '^not-found$' || exit 0
tailscale_ip="$(tailscale ip -4 2>/dev/null || true)"
ssh_port="$(sshd -T 2>/dev/null | awk '$1 == "port" { if (!found) print $2; found=1 }')"
ssh_port="${ssh_port:-22}"
[[ "${ssh_port}" =~ ^[0-9]{1,5}$ && "${ssh_port}" -ge 1 && "${ssh_port}" -le 65535 ]] \
  || { echo "Unable to prove a valid SSH port for ssh.socket binding" >&2; exit 1; }
if [[ ! "${tailscale_ip}" =~ ^100\.(6[4-9]|[78][0-9]|9[0-9]|1[01][0-9]|12[0-7])\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
  # Fail closed if Tailscale is temporarily unavailable: remove the inherited
  # wildcard listener and leave only localhost while this reconciliation fails.
  install -d -m 0755 -o root -g root "$(dirname "${socket_dropin}")"
  tmp="$(mktemp)"
  cleanup() { rm -f -- "${tmp}"; }
  trap cleanup EXIT
  cat > "${tmp}" <<SOCKETEOF
[Socket]
# Managed by secure-ubuntu-paas: Tailscale unavailable, localhost only.
ListenStream=
ListenStream=127.0.0.1:${ssh_port}
ListenStream=[::1]:${ssh_port}
SOCKETEOF
  sshd -t
  install -m 0644 -o root -g root "${tmp}" "${socket_dropin}"
  systemctl daemon-reload
  systemctl restart "${socket_unit}"
  echo "Unable to prove a valid Tailscale IPv4; ssh.socket was restricted to localhost." >&2
  exit 1
fi
expected_ts="ListenStream=${tailscale_ip}:${ssh_port}"
expected_local="ListenStream=127.0.0.1:${ssh_port}"
expected_v6="ListenStream=[::1]:${ssh_port}"
if [[ -f "${socket_dropin}" ]] \
  && grep -Fqx "${expected_ts}" "${socket_dropin}" \
  && grep -Fqx "${expected_local}" "${socket_dropin}" \
  && grep -Fqx "${expected_v6}" "${socket_dropin}" \
  && ! grep -Eq '^ListenStream=0\.0\.0\.0:|^ListenStream=\[::\]:' "${socket_dropin}"; then
  exit 0
fi
install -d -m 0755 -o root -g root "$(dirname "${socket_dropin}")"
tmp="$(mktemp)"
cleanup() { rm -f -- "${tmp}"; }
trap cleanup EXIT
cat > "${tmp}" <<SOCKETEOF
[Socket]
# Managed by secure-ubuntu-paas: Tailscale and localhost only.
ListenStream=
${expected_ts}
${expected_local}
${expected_v6}
SOCKETEOF
sshd -t
install -m 0644 -o root -g root "${tmp}" "${socket_dropin}"
systemctl daemon-reload
systemctl restart "${socket_unit}"
SSHEOF
  chmod 0750 "${ssh_socket_reconcile_dest}"
  cat > /etc/systemd/system/hardening-validate.service <<SVCEOF
[Unit]
Description=Run hardening validation checks
After=network.target

[Service]
Type=oneshot
ExecStartPre=/usr/local/sbin/hardening-ssh-socket-reconcile
ExecStartPre=/usr/local/sbin/hardening-sysctl-reconcile
ExecStartPre=${auditd_runtime_reconcile_dest}
ExecStartPre=/usr/local/sbin/hardening-auditd-loginuid-reconcile
ExecStart=${validate_dest}
SVCEOF
  cat > /etc/systemd/system/hardening-validate.timer <<'TIMEREOF'
[Unit]
Description=Daily hardening validation

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
TIMEREOF
  systemctl daemon-reload
  "${auditd_rate_limit_dest}"
  systemctl enable --now hardening-validate.timer
  if [[ -x /usr/local/sbin/hardening-ssh-socket-reconcile ]]; then
    /usr/local/sbin/hardening-ssh-socket-reconcile
  fi
fi

# SSH crypto lines: normalize accidental duplicate '^' operators from manual edits.
ssh_dropin="/etc/ssh/sshd_config.d/00-base-hardening.conf"
if [[ -f "${ssh_dropin}" ]]; then
  sed -i -E \
    -e 's/^Ciphers \^+/Ciphers ^/' \
    -e 's/^MACs \^+/MACs ^/' \
    -e 's/^KexAlgorithms \^+/KexAlgorithms ^/' \
    -e 's/^HostKeyAlgorithms \^+/HostKeyAlgorithms ^/' \
    "${ssh_dropin}"
  if sshd -t 2>/dev/null; then
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
  fi
fi

# Netplan can generate a later /run drop-in at boot.  Keep the hardening
# override lexically later and remove the legacy name from older runs.
networkd_wait_dir="/etc/systemd/system/systemd-networkd-wait-online.service.d"
networkd_wait_dropin="${networkd_wait_dir}/99-hardening.conf"
if systemctl show --property=LoadState --value systemd-networkd-wait-online.service 2>/dev/null | grep -qv '^not-found$'; then
  install -d -m 0755 "${networkd_wait_dir}"
  rm -f "${networkd_wait_dir}/10-any-timeout.conf"
  cat > "${networkd_wait_dropin}" <<'WAITEOF'
[Service]
ExecStart=
ExecStart=/lib/systemd/systemd-networkd-wait-online --any --timeout=15
WAITEOF
  chmod 0644 "${networkd_wait_dropin}"
  systemctl daemon-reload
fi

# If ifupdown owns a real interface stanza, netplan's runtime generator must
# not resurrect systemd-networkd or its wait-online unit.  Masking only the
# wait-online unit prevents a recurring failed systemd state; networkd hosts
# keep the tuned wait-online service available.
ifupdown_authoritative="false"
if systemctl show --property=LoadState --value networking.service 2>/dev/null | grep -qv '^not-found$'; then
  for interfaces_file in /etc/network/interfaces /etc/network/interfaces.d/*; do
    [[ -f "${interfaces_file}" ]] || continue
    if awk '
      /^[[:space:]]*#/ { next }
      /^[[:space:]]*iface[[:space:]]+/ {
        if ($2 != "lo") { found=1; exit }
      }
      END { exit(found ? 0 : 1) }
    ' "${interfaces_file}"; then
      ifupdown_authoritative="true"
      break
    fi
  done
fi

if [[ "${ifupdown_authoritative}" == "true" ]]; then
  for unit in \
    systemd-networkd.socket \
    systemd-networkd.service \
    networkd-dispatcher.service \
    systemd-networkd-wait-online.service; do
    if systemctl show --property=LoadState --value "${unit}" 2>/dev/null | grep -qv '^not-found$'; then
      systemctl stop "${unit}" 2>/dev/null || true
      systemctl disable "${unit}" 2>/dev/null || true
    fi
  done
  systemctl mask systemd-networkd-wait-online.service 2>/dev/null || true
  if [[ ! -L /etc/systemd/system/systemd-networkd-wait-online.service ]] \
    || [[ "$(readlink /etc/systemd/system/systemd-networkd-wait-online.service 2>/dev/null || true)" != "/dev/null" ]]; then
    ln -sfn /dev/null /etc/systemd/system/systemd-networkd-wait-online.service
  fi
  systemctl daemon-reload
  systemctl reset-failed systemd-networkd-wait-online.service 2>/dev/null || true
else
  systemctl unmask systemd-networkd-wait-online.service 2>/dev/null || true
fi
EOF
}

# Emit the host-side reconciliation used after Docker appears. Phase 1 locks
# the audit policy before Docker is installed, so path watches for Docker and
# containerd can be written immediately but cannot enter an enabled=2 kernel
# policy until one controlled reboot. The single-word result is an
# orchestrator contract: ready | reboot-required | not-applicable.
docker_audit_runtime_reconcile_script() {
  cat <<'EOF'
set -Eeuo pipefail
runtime_helper="/usr/local/sbin/hardening-auditd-runtime-reconcile"
rules_file="/etc/audit/rules.d/60-coolify-baseline.rules"

if ! command -v docker >/dev/null 2>&1 \
  || ! systemctl is-active --quiet docker.service 2>/dev/null; then
  printf '%s\n' 'not-applicable'
  exit 0
fi

[[ -x "${runtime_helper}" && -f "${runtime_helper}" && ! -L "${runtime_helper}" ]] \
  || { echo "Docker audit runtime reconciler is missing or unsafe" >&2; exit 1; }
"${runtime_helper}" >/dev/null

[[ -f "${rules_file}" && ! -L "${rules_file}" ]] \
  || { echo "Docker audit rules file is missing or unsafe" >&2; exit 1; }
read -r rules_uid rules_gid rules_mode < <(stat -c '%u %g %a' "${rules_file}" 2>/dev/null)
[[ "${rules_uid}" == "0" && "${rules_gid}" == "0" && "${rules_mode}" == "640" ]] \
  || { echo "Docker audit rules file must be root:root mode 0640" >&2; exit 1; }
grep -q -- '-k container-runtime' "${rules_file}" \
  || { echo "Docker execution watches are missing from the persistent audit policy" >&2; exit 1; }
grep -q -- '-k docker-config' "${rules_file}" \
  || { echo "Docker configuration watches are missing from the persistent audit policy" >&2; exit 1; }

audit_status="$(auditctl -s 2>/dev/null)" \
  || { echo "Unable to read kernel audit status" >&2; exit 1; }
audit_enabled="$(awk '$1 == "enabled" {print $2; exit}' <<< "${audit_status}")"
audit_rate="$(awk '$1 == "rate_limit" {print $2; exit}' <<< "${audit_status}")"
audit_loginuid="$(awk '$1 == "loginuid_immutable" {print $2; exit}' <<< "${audit_status}")"
audit_lost="$(awk '$1 == "lost" {print $2; exit}' <<< "${audit_status}")"
[[ "${audit_enabled}" == "2" && "${audit_loginuid}" == "1" ]] \
  || { echo "Kernel audit baseline is not immutable with stable login attribution" >&2; exit 1; }
# An immutable old rate requires reboot to apply the corrected producer.
# Preserve/report existing loss, never reset it or claim the old boot passed.
if [[ "${audit_rate}" != "10000" ]]; then
  echo "Audit maintenance required: rate=${audit_rate}, historical lost=${audit_lost}; preserving this boot evidence." >&2
  printf '%s\n' 'reboot-required'
  exit 0
fi
[[ "${audit_lost}" == "0" ]] \
  || { echo "Audit events were lost at the corrected rate; investigate before retrying." >&2; exit 1; }

loaded_rules="$(auditctl -l 2>/dev/null)" \
  || { echo "Unable to list loaded kernel audit rules" >&2; exit 1; }
if grep -q 'container-runtime' <<< "${loaded_rules}" \
  && grep -q 'docker-config' <<< "${loaded_rules}"; then
  printf '%s\n' 'ready'
else
  # The complete policy is on disk and the kernel is deliberately immutable.
  # Reboot is the only supported transition; never weaken enabled=2 in place.
  printf '%s\n' 'reboot-required'
fi
EOF
}
