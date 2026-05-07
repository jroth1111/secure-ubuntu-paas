configure_system_limits() {
  # Pass-2 audit finding (2026-05-07): default soft fd limit (1024) throttles
  # daemons that accept many connections (proxies, build workers, agents) and
  # forces every daemon author to set their own LimitNOFILE override. Raising
  # the global default to 65536 fixes the common case while leaving the hard
  # cap at the kernel ceiling so a misbehaving service can still be diagnosed.
  local nofile_dropin="/etc/systemd/system.conf.d/99-nofile.conf"
  write_file "${nofile_dropin}" "0644" "root" "root" <<'EOF'
# Managed by bootstrap hardening — raise default soft nofile limit.
# Stock soft=1024 throttles build/proxy/database daemons; hard cap unchanged.
[Manager]
DefaultLimitNOFILE=65536:524288
EOF

  # daemon-reexec applies the new defaults to systemd itself; existing services
  # inherit them on next restart. We don't restart anything here — that would
  # bounce ssh/journald/etc. unnecessarily; the hardening service restarts that
  # follow this module are sufficient to pick up the new ceiling.
  run systemctl daemon-reexec
}
