configure_hardening_validation_timer() {
  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: would install hardening-validate.timer (daily base/validate.sh run)."
    return 0
  fi

  # Keep the complete companion tree under /root. validate.sh sources its
  # checks/modules/overlays relatively, so installing only one executable in
  # /usr/local/sbin produces a timer that silently breaks on the next run.
  local script_dir project_root stable_component validate_src validate_dest legacy_validator
  if [[ -n "${BASH_SOURCE[0]:-}" ]]; then
    script_dir="$(cd "${BASH_SOURCE[0]%/*}" 2>/dev/null && pwd)" || {
      # Fallback 1: realpath (common on Linux)
      if command -v realpath >/dev/null 2>&1; then
        script_dir="$(dirname "$(realpath "${BASH_SOURCE[0]}")" 2>/dev/null)" || script_dir=""
      fi
      # Fallback 2: readlink -f (macOS/BSD)
      if [[ -z "${script_dir}" ]] && command -v readlink >/dev/null 2>&1; then
        script_dir="$(dirname "$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")")"
      fi
    }
  fi

  # Final fallback: use directory of script invocation
  script_dir="${script_dir:-$(pwd)}"

  project_root="$(cd "${script_dir}/../.." 2>/dev/null && pwd)" || project_root=""
  if [[ "${project_root}" != "/root" ]]; then
    [[ -n "${project_root}" && -d "${project_root}" ]] \
      || { warn "Unable to resolve companion tree root from ${script_dir}; skipping timer install."; return 0; }
    for stable_component in base lib overlays; do
      [[ -d "${project_root}/${stable_component}" ]] \
        || { warn "Missing ${project_root}/${stable_component}; skipping timer install."; return 0; }
      if [[ -L "/root/${stable_component}" || ( -e "/root/${stable_component}" && ! -d "/root/${stable_component}" ) ]]; then
        die "/root/${stable_component} is a symlink or unexpected file."
      fi
      install -d -m 0700 -o root -g root "/root/${stable_component}"
      cp -a "${project_root}/${stable_component}/." "/root/${stable_component}/"
      chown -R root:root "/root/${stable_component}"
    done
  fi
  validate_src="/root/base/validate.sh"
  validate_dest="/root/base/validate.sh"

  if [[ -f "${validate_src}" && -f /root/base/checks/_runtime.sh && -d /root/base/modules && -d /root/overlays ]]; then
    chmod 0750 "${validate_dest}"
    log "Installed stable validation tree under /root/base, /root/lib, and /root/overlays."
  else
    warn "Stable validation tree is incomplete; skipping timer install."
    return 0
  fi

  legacy_validator="/usr/local/sbin/validate-hardening"
  if [[ -L "${legacy_validator}" || ( -e "${legacy_validator}" && ! -f "${legacy_validator}" ) ]]; then
    die "${legacy_validator} is a symlink or unexpected file."
  fi
  if [[ -f "${legacy_validator}" ]]; then
    rm -f -- "${legacy_validator}"
    log "Removed stale standalone validator so the timer cannot execute an incomplete tree."
  fi

  local sysctl_reconcile_dest="/usr/local/sbin/hardening-sysctl-reconcile"
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

  local auditd_runtime_reconcile_dest="/usr/local/sbin/hardening-auditd-runtime-reconcile"
  cat > "${auditd_runtime_reconcile_dest}" <<'AUDITRUNTIMEEOF'
#!/usr/bin/env bash
set -Eeuo pipefail

# Rebuild the audit policy after Docker/PaaS installation. The bootstrap can
# legitimately run before Docker exists, so path rules must be regenerated
# once /usr/bin/docker and /var/run/docker.sock are present.
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

  # Ubuntu's auditd build applies the event rate through auditctl rather than
  # auditd.conf. Persist that runtime control across every future auditd start.
  local auditd_rate_limit_dest="/usr/local/sbin/hardening-auditd-rate-limit"
  cat > "${auditd_rate_limit_dest}" <<'RATELIMITEOF'
#!/usr/bin/env bash
set -Eeuo pipefail
command -v auditctl >/dev/null 2>&1 || { echo "auditctl is unavailable" >&2; exit 1; }
current_rate="$(auditctl -s 2>/dev/null | awk '$1 == "rate_limit" {print $2; exit}' || true)"
if [[ "${current_rate}" == "10000" ]]; then
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

  local auditd_reconcile_dest="/usr/local/sbin/hardening-auditd-loginuid-reconcile"
  cat > "${auditd_reconcile_dest}" <<'AUDITEOF'
#!/usr/bin/env bash
set -Eeuo pipefail

rules_file="/etc/audit/rules.d/60-coolify-baseline.rules"
install -d -m 0755 -o root -g root "$(dirname "${rules_file}")"
if [[ ! -f "${rules_file}" ]]; then
  install -m 0640 -o root -g root /dev/null "${rules_file}"
fi
audit_enabled="$(auditctl -s 2>/dev/null | awk '$1 == "enabled" {print $2; exit}' || true)"
if ! grep -Fq -- '--loginuid-immutable' "${rules_file}"; then
  printf '\n# Managed by secure-ubuntu-paas: preserve audit attribution.\n--loginuid-immutable\n' >> "${rules_file}"
  chmod 0640 "${rules_file}"
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

  local ssh_socket_reconcile_dest="/usr/local/sbin/hardening-ssh-socket-reconcile"
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
  # wildcard listener and leave only localhost while this validation run fails.
  install -d -m 0755 -o root -g root "$(dirname "${socket_dropin}")"
  tmp="$(mktemp)"
  cleanup() { rm -f -- "${tmp}"; }
  trap cleanup EXIT
  cat > "${tmp}" <<EOF
[Socket]
# Managed by secure-ubuntu-paas: Tailscale unavailable, localhost only.
ListenStream=
ListenStream=127.0.0.1:${ssh_port}
ListenStream=[::1]:${ssh_port}
EOF
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
cat > "${tmp}" <<EOF
[Socket]
# Managed by secure-ubuntu-paas: Tailscale and localhost only.
ListenStream=
${expected_ts}
${expected_local}
${expected_v6}
EOF
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
ExecStartPre=${ssh_socket_reconcile_dest}
ExecStartPre=${sysctl_reconcile_dest}
ExecStartPre=${auditd_runtime_reconcile_dest}
ExecStartPre=${auditd_reconcile_dest}
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

  run systemctl daemon-reload
  run "${auditd_rate_limit_dest}"
  run systemctl enable --now hardening-validate.timer
  log "hardening-validate.timer enabled (runs base/validate.sh daily)."
}
