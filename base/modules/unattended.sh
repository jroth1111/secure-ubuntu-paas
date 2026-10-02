configure_unattended_upgrades() {
  local reboot_bool
  reboot_bool="false"
  if is_true "${ENABLE_AUTO_REBOOT}"; then
    reboot_bool="true"
  fi

  log "Configuring unattended-upgrades profile: ${UPDATE_PROFILE}"

  write_file "${APT_AUTO_FILE}" "0644" "root" "root" <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

  write_file "${APT_LOCAL_FILE}" "0644" "root" "root" <<EOF
Unattended-Upgrade::Origins-Pattern {
$(case "${UPDATE_PROFILE}" in
  security-only)
    cat <<'PROFILEEOF'
    "origin=Ubuntu,archive=${distro_codename}-security,label=Ubuntu";
PROFILEEOF
    ;;
  balanced)
    cat <<'PROFILEEOF'
    "origin=Ubuntu,archive=${distro_codename}-security,label=Ubuntu";
    "origin=Ubuntu,archive=${distro_codename}-updates,label=Ubuntu";
    "origin=Docker,label=Docker CE,archive=${distro_codename},component=stable";
    "origin=Tailscale,codename=${distro_codename},label=Tailscale,site=pkgs.tailscale.com";
PROFILEEOF
    ;;
esac)
};
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Automatic-Reboot "${reboot_bool}";
Unattended-Upgrade::Automatic-Reboot-Time "${AUTO_REBOOT_TIME}";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
$(if [[ -n "${UPGRADE_MAIL}" ]]; then
  printf 'Unattended-Upgrade::Mail "%s";\n' "${UPGRADE_MAIL}"
  printf 'Unattended-Upgrade::MailReport "only-on-error";\n'
fi)
EOF

  if [[ "${PAAS:-coolify}" == dokploy ]] \
    && ! { [[ -f /usr/local/sbin/paas-recovery-policy && ! -L /usr/local/sbin/paas-recovery-policy \
      && "$(stat -c '%a:%U:%G' /usr/local/sbin/paas-recovery-policy 2>/dev/null)" == '700:root:root' ]] \
      && python3 /usr/local/sbin/paas-recovery-policy >/dev/null 2>&1; }; then
    # A Docker restart seals Swarm secrets and requires the off-server unlock
    # key. Keep daemon/runtime maintenance supervised even in balanced mode.
    write_file /etc/apt/apt.conf.d/55-dokploy-runtime-maintenance 0644 root root <<'EOF'
Unattended-Upgrade::Package-Blacklist {
  "^docker-ce$";
  "^docker-ce-rootless-extras$";
  "^docker.io$";
  "^containerd.io$";
  "^containerd$";
  "^runc$";
  "^moby-engine$";
};
EOF
    if ! is_true "${DRY_RUN}"; then
      mkdir -p /etc/needrestart/conf.d
    fi
    write_file /etc/needrestart/conf.d/50-dokploy-runtime-supervised.conf 0644 root root <<'EOF'
$nrconf{override_rc}{qr(^docker\.service$)} = 0;
$nrconf{override_rc}{qr(^containerd\.service$)} = 0;
EOF
  fi

  run systemctl enable --now apt-daily.timer apt-daily-upgrade.timer

  # Set Persistent=false to prevent boot-time catch-up blocking other package operations
  # See: https://documentation.ubuntu.com/server/how-to/software/automatic-updates/
  if ! is_true "${DRY_RUN}"; then
    mkdir -p /etc/systemd/system/apt-daily.timer.d
    cat > /etc/systemd/system/apt-daily.timer.d/override.conf <<'EOF'
[Timer]
Persistent=false
EOF
    mkdir -p /etc/systemd/system/apt-daily-upgrade.timer.d
    cat > /etc/systemd/system/apt-daily-upgrade.timer.d/override.conf <<'EOF'
[Timer]
Persistent=false
EOF
    systemctl daemon-reload
    log "Configured apt timers with Persistent=false to prevent boot-time catch-up."
  else
    log "DRY-RUN: would configure apt timers with Persistent=false"
  fi

  if ! is_true "${DRY_RUN}"; then
    local dryrun_log_dir dryrun_log
    dryrun_log_dir="${UNATTENDED_DRYRUN_LOG_DIR:-/run}"
    [[ -d "${dryrun_log_dir}" && ! -L "${dryrun_log_dir}" ]] \
      || die "Unattended-upgrade dry-run log directory is missing or unsafe: ${dryrun_log_dir}"
    dryrun_log="$(mktemp "${dryrun_log_dir%/}/unattended-upgrade-dryrun.XXXXXX.log")" \
      || die "Could not allocate protected unattended-upgrade dry-run log"
    chmod 0600 "${dryrun_log}"
    if unattended-upgrade --dry-run --debug >"${dryrun_log}" 2>&1; then
      rm -f -- "${dryrun_log}"
    else
      warn "unattended-upgrade dry-run returned non-zero; protected diagnostics retained at ${dryrun_log}"
    fi
  fi
}
