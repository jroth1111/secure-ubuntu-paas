disable_unused_services() {
  local services=(rpcbind avahi-daemon cups cups-browsed ModemManager udisks2 fwupd fwupd-refresh upower)
  local unit
  for svc in "${services[@]}"; do
    for unit in "${svc}.service" "${svc}.socket"; do
      if systemctl list-unit-files --no-legend "${unit}" 2>/dev/null | grep -q "${unit}"; then
        log "Disabling and masking ${unit}"
        run systemctl disable --now "${unit}" 2>/dev/null || true
        run systemctl mask "${unit}" 2>/dev/null || true
      fi
    done
  done

  # fwupd installs a separate refresh timer on some Ubuntu images.  Mask it
  # as well as the service so the VPS cannot remain systemd-degraded after a
  # failed firmware metadata refresh.
  for unit in fwupd-refresh.timer; do
    if systemctl list-unit-files --no-legend "${unit}" 2>/dev/null | grep -q "${unit}"; then
      log "Disabling and masking ${unit}"
      run systemctl disable --now "${unit}" 2>/dev/null || true
      run systemctl mask "${unit}" 2>/dev/null || true
    fi
  done
}

configure_apport() {
  if [[ -f "${APPORT_DEFAULT_FILE}" ]]; then
    if grep -qE '^[[:space:]]*enabled[[:space:]]*=' "${APPORT_DEFAULT_FILE}"; then
      run sed -i -E 's/^[[:space:]]*enabled[[:space:]]*=.*/enabled=0/' "${APPORT_DEFAULT_FILE}"
    else
      if is_true "${DRY_RUN}"; then
        log "DRY-RUN: append 'enabled=0' to ${APPORT_DEFAULT_FILE}"
      else
        printf '\nenabled=0\n' >> "${APPORT_DEFAULT_FILE}"
      fi
    fi
  else
    warn "${APPORT_DEFAULT_FILE} not found; skipping apport defaults update."
  fi

  if unit_available "apport.service"; then
    run systemctl disable --now apport.service
    run systemctl mask apport.service
    log "Apport disabled and masked."
  else
    log "apport.service not installed; skipping."
  fi
}

configure_cron_extra_opts() {
  if ! unit_available "cron.service"; then
    log "cron.service not installed; skipping EXTRA_OPTS normalization."
    return 0
  fi

  write_file "${CRON_EXTRA_OPTS_DROPIN}" "0644" "root" "root" <<'EOF'
[Service]
Environment="EXTRA_OPTS="
EOF

  run systemctl daemon-reload
  run systemctl restart cron
  log "cron.service EXTRA_OPTS environment normalized."
}

restore_netplan_file() {
  local path="$1"
  local backup="$2"

  cp --preserve=all -- "${backup}" "${path}" || return 1
  netplan generate || return 1
  netplan apply || return 1
}

repair_netplan_offlink_ipv6_default_route() {
  command -v netplan >/dev/null 2>&1 || {
    log "netplan not installed; skipping off-link IPv6 route reconciliation."
    return 0
  }
  [[ -d "${NETPLAN_CONFIG_DIR}" ]] || return 0

  local had_nullglob="false"
  shopt -q nullglob && had_nullglob="true"
  shopt -s nullglob
  local -a netplan_files=("${NETPLAN_CONFIG_DIR}"/*.yaml "${NETPLAN_CONFIG_DIR}"/*.yml)
  [[ "${had_nullglob}" == "true" ]] || shopt -u nullglob
  (( ${#netplan_files[@]} > 0 )) || return 0

  local path owner_mode owner_uid
  for path in "${netplan_files[@]}"; do
    [[ -f "${path}" && ! -L "${path}" ]] \
      || die "Refusing unsafe netplan path: ${path} must be a regular, non-symlink file."
    owner_uid="$(stat -c '%u' "${path}")"
    owner_mode="$(stat -c '%a' "${path}")"
    [[ "${owner_uid}" == "0" ]] \
      || die "Refusing non-root-owned netplan file: ${path}."
    (( (8#${owner_mode} & 8#022) == 0 )) \
      || die "Refusing group/other-writable netplan file: ${path} (${owner_mode})."
  done

  local candidate
  if ! candidate="$(python3 - "${WAN_IFACE}" "${netplan_files[@]}" <<'PY'
import ipaddress
import pathlib
import re
import sys

iface = sys.argv[1]
paths = [pathlib.Path(value) for value in sys.argv[2:]]
iface_re = re.compile(r"^(\s*)[\"']?" + re.escape(iface) + r"[\"']?\s*:\s*(?:#.*)?$")
via_re = re.compile(r"^(\s*)via\s*:\s*[\"']?([^\s#\"']+)")
address_re = re.compile(r"(?<![0-9A-Fa-f:])([0-9A-Fa-f:]+/[0-9]{1,3})(?![0-9A-Fa-f:])")
candidates = []

def indentation(line):
    return len(line) - len(line.lstrip(" "))

for path in paths:
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    for iface_index, line in enumerate(lines):
        iface_match = iface_re.match(line)
        if not iface_match:
            continue
        iface_indent = len(iface_match.group(1))

        parent = None
        for index in range(iface_index - 1, -1, -1):
            stripped = lines[index].strip()
            if not stripped or stripped.startswith("#"):
                continue
            if indentation(lines[index]) < iface_indent:
                parent = stripped
                break
        if parent != "ethernets:":
            continue

        iface_end = len(lines)
        for index in range(iface_index + 1, len(lines)):
            stripped = lines[index].strip()
            if stripped and not stripped.startswith("#") and indentation(lines[index]) <= iface_indent:
                iface_end = index
                break

        networks = []
        for item in lines[iface_index + 1:iface_end]:
            # Only address-list entries are local prefixes. A route such as
            # `to: ::/0` is not an interface address: treating it as one makes
            # every IPv6 gateway appear on-link and silently skips the repair.
            if not re.match(r"^\s*-\s*[\"']?[0-9A-Fa-f:]+/[0-9]{1,3}[\"']?\s*(?:#.*)?$", item):
                continue
            for value in address_re.findall(item):
                try:
                    interface = ipaddress.ip_interface(value)
                except ValueError:
                    continue
                if interface.version == 6:
                    networks.append(interface.network)

        for via_index in range(iface_index + 1, iface_end):
            via_match = via_re.match(lines[via_index])
            if not via_match:
                continue
            gateway_text = via_match.group(2)
            try:
                gateway = ipaddress.ip_address(gateway_text)
            except ValueError:
                continue
            if gateway.version != 6:
                continue

            via_indent = len(via_match.group(1))
            route_start = None
            route_indent = None
            for index in range(via_index - 1, iface_index, -1):
                stripped = lines[index].strip()
                if not stripped or stripped.startswith("#"):
                    continue
                current_indent = indentation(lines[index])
                if current_indent < via_indent:
                    if stripped.startswith("-"):
                        route_start = index
                        route_indent = current_indent
                    break
            if route_start is None:
                continue

            route_end = iface_end
            for index in range(route_start + 1, iface_end):
                stripped = lines[index].strip()
                if stripped and not stripped.startswith("#") and indentation(lines[index]) <= route_indent:
                    route_end = index
                    break
            route_text = " ".join(item.strip().strip("\"'") for item in lines[route_start:route_end])
            if not re.search(r"(?:^|\s)to\s*:\s*(?:default|::/0)(?:\s|$)", route_text):
                continue
            if any(gateway in network for network in networks):
                continue
            on_link_state = "present" if re.search(
                r"(?:^|\s)on-link\s*:\s*true(?:\s|$)", route_text, re.IGNORECASE
            ) else "missing"
            candidates.append((str(path), via_index + 1, gateway_text, on_link_state))

if len(candidates) > 1:
    print("multiple off-link IPv6 default routes require explicit review", file=sys.stderr)
    raise SystemExit(2)
if candidates:
    print("\t".join(map(str, candidates[0])))
PY
)"; then
    die "Unable to inspect netplan safely for an off-link IPv6 default route."
  fi
  [[ -n "${candidate}" ]] || return 0

  local line_number gateway on_link_state
  IFS=$'\t' read -r path line_number gateway on_link_state <<< "${candidate}"
  [[ -n "${path}" && "${line_number}" =~ ^[0-9]+$ && "${gateway}" == *:* \
    && "${on_link_state}" =~ ^(missing|present)$ ]] \
    || die "Invalid off-link IPv6 route repair candidate."

  if is_true "${DRY_RUN}"; then
    if [[ "${on_link_state}" == "missing" ]]; then
      log "DRY-RUN: add on-link: true after ${path}:${line_number} for IPv6 gateway ${gateway}."
    else
      log "DRY-RUN: verify/reapply existing on-link IPv6 gateway ${gateway} from ${path}."
    fi
    return 0
  fi

  if [[ "${on_link_state}" == "present" ]] \
    && ip -6 route show default dev "${WAN_IFACE}" 2>/dev/null \
      | grep -Fq -- "via ${gateway}"; then
    log "Provider off-link IPv6 default route is already active via ${gateway} on ${WAN_IFACE}."
    return 0
  fi

  local backup patched
  backup="$(mktemp)"
  chmod 0600 "${backup}"
  cp --preserve=all -- "${path}" "${backup}"
  if [[ "${on_link_state}" == "missing" ]]; then
    patched="$(mktemp "${NETPLAN_CONFIG_DIR}/.hardening-netplan.XXXXXX")"
    chmod 0600 "${patched}"
    if ! python3 - "${path}" "${line_number}" > "${patched}" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
line_number = int(sys.argv[2])
lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
index = line_number - 1
if index < 0 or index >= len(lines) or not re.match(r"^\s*via\s*:", lines[index]):
    raise SystemExit("candidate line is no longer a via directive")
indent = re.match(r"^(\s*)", lines[index]).group(1)
ending = "\r\n" if lines[index].endswith("\r\n") else "\n"
lines.insert(index + 1, f"{indent}on-link: true{ending}")
sys.stdout.writelines(lines)
PY
    then
      rm -f -- "${backup}" "${patched}"
      die "Failed to construct repaired netplan file for ${path}."
    fi
    chown --reference="${path}" "${patched}"
    chmod --reference="${path}" "${patched}"
    mv -f -- "${patched}" "${path}"
  fi

  if ! netplan generate || ! netplan apply; then
    warn "Netplan rejected the off-link IPv6 repair; restoring ${path}."
    restore_netplan_file "${path}" "${backup}" \
      || die "Netplan repair failed and automatic rollback also failed for ${path}."
    rm -f -- "${backup}"
    die "Netplan repair failed; original configuration restored."
  fi

  local route_ready="false" attempt networkd_load_state
  for attempt in 1 2 3 4 5; do
    if ip -6 route show default dev "${WAN_IFACE}" 2>/dev/null \
      | grep -Fq -- "via ${gateway}"; then
      route_ready="true"
      break
    fi
    sleep 1
  done

  if [[ "${route_ready}" != "true" ]] && command -v networkctl >/dev/null 2>&1; then
    networkctl reload 2>/dev/null || true
    networkctl reconfigure "${WAN_IFACE}" 2>/dev/null || true
    for attempt in 1 2 3 4 5; do
      if ip -6 route show default dev "${WAN_IFACE}" 2>/dev/null \
        | grep -Fq -- "via ${gateway}"; then
        route_ready="true"
        break
      fi
      sleep 1
    done
  fi

  if [[ "${route_ready}" != "true" ]] && command -v systemctl >/dev/null 2>&1; then
    networkd_load_state="$(systemctl show --property=LoadState --value systemd-networkd.service 2>/dev/null || true)"
    if [[ -n "${networkd_load_state}" && "${networkd_load_state}" != "not-found" ]]; then
      systemctl restart systemd-networkd.service || true
      for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
        if ip -6 route show default dev "${WAN_IFACE}" 2>/dev/null \
          | grep -Fq -- "via ${gateway}"; then
          route_ready="true"
          break
        fi
        sleep 1
      done
    fi
  fi

  if [[ "${route_ready}" != "true" ]]; then
    warn "IPv6 default route did not become active; restoring ${path}."
    if [[ "${on_link_state}" == "missing" ]]; then
      restore_netplan_file "${path}" "${backup}" \
        || die "IPv6 route verification failed and automatic rollback also failed for ${path}."
    fi
    rm -f -- "${backup}"
    if [[ "${on_link_state}" == "missing" ]]; then
      die "IPv6 route verification failed; original configuration restored."
    fi
    die "IPv6 route verification failed for existing on-link configuration."
  fi

  rm -f -- "${backup}"
  log "Repaired provider off-link IPv6 default route via ${gateway} on ${WAN_IFACE}."
}

configure_networkd_wait_online() {
  if ! unit_available "systemd-networkd-wait-online.service"; then
    log "systemd-networkd-wait-online.service not installed; skipping wait-online tuning."
    return 0
  fi

  # Older releases used 10-any-timeout.conf.  Remove only that managed file;
  # the 99 name is intentional because netplan can add /run/10-netplan.conf
  # after bootstrap and otherwise override this ExecStart reset.
  local legacy_dropin="${NETWORKD_WAIT_ONLINE_DROPIN%/*}/10-any-timeout.conf"
  if [[ "${legacy_dropin}" != "${NETWORKD_WAIT_ONLINE_DROPIN}" ]]; then
    run rm -f "${legacy_dropin}"
  fi

  write_file "${NETWORKD_WAIT_ONLINE_DROPIN}" "0644" "root" "root" <<'EOF'
[Service]
ExecStart=
ExecStart=/lib/systemd/systemd-networkd-wait-online --any --timeout=15
EOF

  run systemctl daemon-reload

  if ifupdown_is_authoritative; then
    local -a stray_units=()
    unit_available "systemd-networkd.socket" && stray_units+=("systemd-networkd.socket")
    unit_available "systemd-networkd.service" && stray_units+=("systemd-networkd.service")
    unit_available "networkd-dispatcher.service" && stray_units+=("networkd-dispatcher.service")
    if (( ${#stray_units[@]} > 0 )); then
      run systemctl stop "${stray_units[@]}"
      run systemctl disable "${stray_units[@]}"
    fi
    if unit_available "systemd-networkd-wait-online.service"; then
      run systemctl stop systemd-networkd-wait-online.service
      run systemctl disable systemd-networkd-wait-online.service
      run systemctl mask systemd-networkd-wait-online.service
      if ! is_true "${DRY_RUN}"; then
        ln -sfn /dev/null /etc/systemd/system/systemd-networkd-wait-online.service
        run systemctl daemon-reload
        run systemctl reset-failed systemd-networkd-wait-online.service
      fi
    fi
    log "ifupdown is authoritative; disabled stray systemd-networkd units to keep apt-helper wait-online on networking.service."
    return 0
  fi

  repair_netplan_offlink_ipv6_default_route
  run systemctl unmask systemd-networkd-wait-online.service 2>/dev/null || true
  log "systemd-networkd-wait-online tuned for --any with 15s timeout."
}
