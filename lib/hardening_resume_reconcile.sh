#!/usr/bin/env bash
# lib/hardening_resume_reconcile.sh — Idempotent host-side reconciles for resume/update runs.
# Emits a bash script for remote (deploy.sh) or local (setup.sh) execution so Gate C
# does not fail on checks added after the original bootstrap.

[[ "${BASH_SOURCE[0]}" != "${0}" ]] \
  || { printf 'Source this file, do not execute it.\n' >&2; exit 1; }

hardening_resume_reconcile_script() {
  cat <<'EOF'
set -Eeuo pipefail

# Rsyslog: /var/log must not be group-writable by arbitrary users.
if getent group syslog >/dev/null 2>&1; then
  install -d -m 0770 -o root -g syslog /var/log
  chown root:syslog /var/log
  chmod 0770 /var/log
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
validate_dest="/usr/local/sbin/validate-hardening"
if [[ -f "${validate_src}" ]]; then
  install -m 0750 -o root -g root "${validate_src}" "${validate_dest}"
  cat > /etc/systemd/system/hardening-validate.service <<'SVCEOF'
[Unit]
Description=Run hardening validation checks
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/validate-hardening
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
  systemctl enable --now hardening-validate.timer
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
EOF
}
