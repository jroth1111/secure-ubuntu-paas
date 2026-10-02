detect_docker() {
  if command -v docker >/dev/null 2>&1; then
    DOCKER_PRESENT="true"
    log "Docker detected."

    # Prove the effective backend positively. A failed/empty/unrecognized
    # docker-info response must never enable iptables-only DOCKER-USER policy.
    local firewall_backend_json="" firewall_backend="" firewall_info=""
    firewall_backend_json="$(docker info --format '{{json .FirewallBackend}}' 2>/dev/null || true)"
    if [[ -n "${firewall_backend_json}" ]] && command -v jq >/dev/null 2>&1; then
      firewall_backend="$(jq -r \
        'if type == "object" then (.Driver // empty) elif type == "string" then . else empty end' \
        <<< "${firewall_backend_json}" 2>/dev/null || true)"
    fi
    if [[ -z "${firewall_backend}" ]]; then
      firewall_info="$(docker info 2>/dev/null || true)"
      firewall_backend="$(awk -F: \
        '/^[[:space:]]*Firewall Backend:[[:space:]]*/ {gsub(/[[:space:]]/, "", $2); print tolower($2); exit} \
         /^[[:space:]]*iptables:[[:space:]]*true[[:space:]]*$/ {print "iptables"; exit}' \
        <<< "${firewall_info}")"
    fi
    if [[ "${firewall_backend}" != "iptables" ]]; then
      die "Expected a positively identified Docker iptables firewall backend, got ${firewall_backend:-unavailable}; DOCKER-USER hardening cannot continue safely."
    fi
  else
    log "Docker not detected."
  fi
}
