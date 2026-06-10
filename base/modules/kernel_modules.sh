configure_kernel_modules() {
  # Reduce kernel attack surface by refusing to load unused modules. The
  # `install <mod> /bin/false` form is stronger than `blacklist`: it blocks
  # explicit `modprobe <mod>` too, not just autoload-by-alias. Matches the
  # convention Ubuntu already uses (e.g. /etc/modprobe.d/disable-algif_aead.conf).
  #
  # Network protocols: the distro's blacklist-rare-network.conf disables
  # ax25/x25/rose/decnet/econet/rds/af_802154 via `net-pf` aliases, but NOT
  # dccp, sctp, or tipc — none are used by Docker, Tailscale, or web workloads.
  #
  # Filesystems: legacy/uncommon formats that never appear on a cloud VPS.
  # Deliberately EXCLUDED: squashfs (snap), overlay/overlay2 + vxlan + bridge
  # (Docker/Swarm), vfat (EFI/attached storage), udf + iso9660 (cloud-init can
  # mount its NoCloud/ConfigDrive seed from these at boot).
  local -a blocked_modules=(
    dccp sctp rds tipc
    cramfs freevxfs jffs2 hfs hfsplus
  )

  if is_true "${DRY_RUN}"; then
    log "DRY-RUN: would write ${KERNEL_MODULES_DROPIN_FILE} blocking: ${blocked_modules[*]}"
    return 0
  fi

  {
    printf '# Managed by bootstrap hardening — block unused kernel modules.\n'
    printf '# install <mod> /bin/false refuses autoload AND explicit modprobe.\n'
    local mod
    for mod in "${blocked_modules[@]}"; do
      printf 'install %s /bin/false\n' "${mod}"
    done
  } | write_file "${KERNEL_MODULES_DROPIN_FILE}" "0644" "root" "root"

  # Best-effort unload for anything already loaded but idle. Non-fatal: a module
  # in use (refcount > 0) is left alone — the install rule still blocks future
  # loads and a reboot clears the rest.
  local mod
  for mod in "${blocked_modules[@]}"; do
    if lsmod | awk '{print $1}' | grep -qx "${mod}"; then
      if modprobe -r "${mod}" 2>/dev/null; then
        log "Unloaded idle kernel module: ${mod}"
      else
        warn "Kernel module ${mod} is loaded and in use; left in place (blocked from future loads)."
      fi
    fi
  done

  log "Kernel module hardening applied: ${#blocked_modules[@]} modules blocked via ${KERNEL_MODULES_DROPIN_FILE}."
}
