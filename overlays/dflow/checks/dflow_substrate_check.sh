dflow_substrate_check() {
  # Verify the dFlow installer's hardening substrate is intact and the gaps it
  # leaves are closed. Audit-derived (2026-05-07): these checks reflect what
  # app.dflow.sh's lockdown-run applies and what it omits, plus pass-2 tuning
  # derived from a follow-up bug/security/logic/performance audit.

  # ---- secondary tailscaled-dfi instance (dFlow controller tailnet) ----
  # Pass-2 derived: is-active alone misses the degraded "running but not
  # authenticated" state. Verify the daemon is actually attached to a tailnet.
  if systemctl is-active --quiet tailscaled-dfi 2>/dev/null; then
    local dfi_socket="" dfi_status=""
    for cand in /run/tailscale-dfi.sock /var/run/tailscale-dfi/tailscaled.sock; do
      if [[ -S "${cand}" ]]; then dfi_socket="${cand}"; break; fi
    done
    if [[ -z "${dfi_socket}" ]]; then
      record "FAIL" "dflow: tailscaled-dfi (controller tailnet)" \
        "active but local socket not found in /run/tailscale-dfi.sock or /var/run/tailscale-dfi/tailscaled.sock"
    else
      dfi_status="$(tailscale --socket="${dfi_socket}" status --self=true 2>/dev/null | head -1 || true)"
      if [[ -n "${dfi_status}" && "${dfi_status}" =~ ^[0-9] ]]; then
        record "PASS" "dflow: tailscaled-dfi (controller tailnet)" "connected via ${dfi_socket}"
      else
        record "FAIL" "dflow: tailscaled-dfi (controller tailnet)" \
          "active but not connected to a tailnet (socket=${dfi_socket})"
      fi
    fi
  else
    record "FAIL" "dflow: tailscaled-dfi (controller tailnet)" \
      "tailscaled-dfi is not active; dFlow controller cannot attach via its tailnet"
  fi

  # ---- Docker daemon: live-restore + log rotation ----
  local daemon_json="${DFLOW_DOCKER_DAEMON_JSON:-/etc/docker/daemon.json}"
  if [[ ! -f "${daemon_json}" ]]; then
    record "FAIL" "dflow: docker daemon.json" "missing — no log rotation or live-restore configured"
  else
    local live_restore
    live_restore="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(str(d.get("live-restore","")).lower())' "${daemon_json}" 2>/dev/null)"
    if [[ "${live_restore}" == "true" ]]; then
      record "PASS" "dflow: docker live-restore" "enabled"
    else
      record "FAIL" "dflow: docker live-restore" "not set in ${daemon_json}"
    fi

    local max_size
    max_size="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("log-opts",{}).get("max-size",""))' "${daemon_json}" 2>/dev/null)"
    if [[ -n "${max_size}" ]]; then
      record "PASS" "dflow: docker log rotation" "max-size=${max_size}"
    else
      record "FAIL" "dflow: docker log rotation" "log-opts.max-size not set in ${daemon_json}"
    fi
  fi

  # ---- sysctl: log_martians ----
  local martians_all
  martians_all="$(sysctl -n net.ipv4.conf.all.log_martians 2>/dev/null || true)"
  if [[ "${martians_all}" == "1" ]]; then
    record "PASS" "dflow: sysctl log_martians"
  else
    record "FAIL" "dflow: sysctl log_martians" \
      "net.ipv4.conf.all.log_martians=${martians_all:-MISSING} (expected 1)"
  fi

  # ---- network buffer tuning (pass-2) ----
  # Stock 256 KiB rmem/wmem under-utilizes BBR + fq on >50 Mbit/s links.
  local rmem_max wmem_max
  rmem_max="$(sysctl -n net.core.rmem_max 2>/dev/null || true)"
  wmem_max="$(sysctl -n net.core.wmem_max 2>/dev/null || true)"
  if [[ "${rmem_max}" =~ ^[0-9]+$ && "${wmem_max}" =~ ^[0-9]+$ ]] \
     && (( rmem_max >= 16777216 )) && (( wmem_max >= 16777216 )); then
    record "PASS" "dflow: net buffer tuning" "rmem_max=${rmem_max} wmem_max=${wmem_max}"
  else
    record "FAIL" "dflow: net buffer tuning" \
      "rmem_max=${rmem_max:-MISSING} wmem_max=${wmem_max:-MISSING} (expected ≥16777216 each)"
  fi

  # ---- systemd default soft fd limit (pass-2) ----
  # Default soft=1024 throttles build/proxy/db daemons; raise to 65536.
  local nofile_line nofile_soft
  nofile_line="$(grep -hE '^[[:space:]]*DefaultLimitNOFILE=' \
    /etc/systemd/system.conf /etc/systemd/system.conf.d/*.conf 2>/dev/null \
    | tail -1)"
  nofile_soft="${nofile_line#*=}"
  nofile_soft="${nofile_soft%%:*}"
  if [[ "${nofile_soft}" =~ ^[0-9]+$ ]] && (( nofile_soft >= 65536 )); then
    record "PASS" "dflow: systemd DefaultLimitNOFILE" "soft=${nofile_soft}"
  else
    record "FAIL" "dflow: systemd DefaultLimitNOFILE" \
      "soft=${nofile_soft:-DEFAULT(1024)} (expected ≥65536)"
  fi

  # ---- stale kernel packages (pass-2) ----
  # Old kernels accumulate as a local-priv attack surface; one running plus
  # one prior is acceptable, more than that means autoremove isn't keeping up.
  local running_kver kernel_pkg_count
  running_kver="$(uname -r)"
  kernel_pkg_count="$(dpkg -l 2>/dev/null \
    | awk '/^ii[[:space:]]+linux-image-[0-9]/ {print $2}' \
    | grep -v '^linux-image-generic$' \
    | wc -l)"
  if (( kernel_pkg_count <= 1 )); then
    record "PASS" "dflow: kernel package count" "${kernel_pkg_count} versioned image (running ${running_kver})"
  elif (( kernel_pkg_count == 2 )); then
    record "INFO" "dflow: kernel package count" "${kernel_pkg_count} versioned images (one prior retained; running ${running_kver})"
  else
    record "FAIL" "dflow: kernel package count" \
      "${kernel_pkg_count} versioned linux-image packages installed (expected ≤2; run apt autoremove --purge)"
  fi

  # ---- AppArmor denials in last 24h (pass-2) ----
  # A clean denial log is a daily signal that profiles aren't drifting from
  # actual workload behavior; persistent denials need profile updates.
  if command -v journalctl >/dev/null 2>&1; then
    local denials
    denials="$(journalctl --since '24 hours ago' --no-pager 2>/dev/null \
      | grep -ciE 'apparmor.*DENIED|audit.*DENIED' || true)"
    if [[ "${denials}" =~ ^[0-9]+$ ]] && (( denials == 0 )); then
      record "PASS" "dflow: AppArmor denials (24h)"
    elif (( denials < 10 )); then
      record "INFO" "dflow: AppArmor denials (24h)" "${denials} denial entries — investigate if recurring"
    else
      record "FAIL" "dflow: AppArmor denials (24h)" \
        "${denials} denial entries in last 24h — profile drift or active deny loop"
    fi
  fi

  # ---- auditd rules count ----
  local rule_count
  rule_count="$(auditctl -l 2>/dev/null | wc -l)"
  if (( rule_count >= 20 )); then
    record "PASS" "dflow: auditd rules" "${rule_count} rules loaded"
  else
    record "FAIL" "dflow: auditd rules" "${rule_count} rules (expected ≥20)"
  fi

  # ---- fail2ban sshd jail ----
  if fail2ban-client status sshd >/dev/null 2>&1; then
    record "PASS" "dflow: fail2ban sshd jail"
  else
    record "FAIL" "dflow: fail2ban sshd jail" "jail not active or fail2ban not running"
  fi

  # ---- AppArmor profiles ----
  local aa_count
  aa_count="$(aa-status --count 2>/dev/null | awk '/^[[:space:]]*[0-9]+[[:space:]]*$/ {print $1; exit}' || true)"
  if [[ "${aa_count}" =~ ^[0-9]+$ ]] && (( aa_count >= 50 )); then
    record "PASS" "dflow: AppArmor profiles" "${aa_count} profiles loaded"
  else
    record "FAIL" "dflow: AppArmor profiles" "${aa_count:-0} profiles (expected ≥50)"
  fi
}
