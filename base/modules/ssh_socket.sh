configure_ssh_socket() {
  # Bind ssh.socket to Tailscale IP + localhost instead of 0.0.0.0:${SSH_PORT}.
  # Defense-in-depth: even if UFW is flushed, SSH is not exposed publicly.
  local socket_unit="/etc/systemd/system/ssh.socket"
  local ts_ip=""
  : "${SSH_PORT:=22}"
  [[ "${SSH_PORT}" =~ ^[0-9]{1,5}$ && "${SSH_PORT}" -ge 1 && "${SSH_PORT}" -le 65535 ]] \
    || die "SSH_PORT must be numeric and in range 1..65535 before configuring ssh.socket."

  ts_ip="$(tailscale ip -4 2>/dev/null || true)"
  if ! ssh_socket_is_tailscale_ipv4 "${ts_ip}"; then
    # Never leave the distribution wildcard listener in place when the
    # private address is unavailable. A loopback-only socket preserves local
    # recovery while failing closed until Tailscale is healthy again.
    if ! is_true "${DRY_RUN}"; then
      mkdir -p /etc/systemd/system/ssh.socket.d
      cat > /etc/systemd/system/ssh.socket.d/10-bind-tailscale.conf <<SOCKETEOF
[Socket]
# Tailscale address unavailable: fail closed to localhost until it returns.
ListenStream=
ListenStream=127.0.0.1:${SSH_PORT}
ListenStream=[::1]:${SSH_PORT}
SOCKETEOF
      systemctl daemon-reload
      systemctl restart ssh.socket
    fi
    die "Could not detect a valid Tailscale IPv4; ssh.socket was restricted to localhost until Tailscale returns."
  fi

  if ! is_true "${DRY_RUN}"; then
    mkdir -p /etc/systemd/system/ssh.socket.d
    cat > /etc/systemd/system/ssh.socket.d/10-bind-tailscale.conf <<SOCKETEOF
[Socket]
# Override default ListenStream=0.0.0.0:${SSH_PORT} — bind to Tailscale + localhost only
ListenStream=
ListenStream=${ts_ip}:${SSH_PORT}
ListenStream=127.0.0.1:${SSH_PORT}
ListenStream=[::1]:${SSH_PORT}
SOCKETEOF
    systemctl daemon-reload
    systemctl restart ssh.socket
    log "Bound ssh.socket to ${ts_ip}:${SSH_PORT}, 127.0.0.1:${SSH_PORT}, [::1]:${SSH_PORT}."
  else
    log "DRY-RUN: would bind ssh.socket to ${ts_ip}:${SSH_PORT} and localhost."
  fi
}

ssh_socket_is_tailscale_ipv4() {
  local ip="${1:-}"
  local o2 o3 o4
  IFS='.' read -r _ o2 o3 o4 <<< "${ip}"
  [[ "${ip}" == 100.* && "${o2:-}" =~ ^[0-9]+$ && "${o3:-}" =~ ^[0-9]+$ && "${o4:-}" =~ ^[0-9]+$ ]] || return 1
  (( 10#${o2} >= 64 && 10#${o2} <= 127 )) || return 1
  (( 10#${o3} <= 255 && 10#${o4} <= 255 )) || return 1
}
