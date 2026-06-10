configure_journald() {
  # Remove legacy/conflicting drop-ins: files sorting after ours override our
  # limits silently (lexicographic parse order), e.g. an old hardening.conf
  # capping SystemMaxUse at 500M while we configure ${JOURNAL_MAX_USE}.
  local legacy
  for legacy in /etc/systemd/journald.conf.d/hardening.conf; do
    if [[ -f "${legacy}" && "${legacy}" != "${JOURNALD_DROPIN_FILE}" ]]; then
      if is_true "${DRY_RUN}"; then
        log "DRY-RUN: would remove conflicting journald drop-in ${legacy}."
      else
        rm -f "${legacy}"
        log "Removed conflicting journald drop-in ${legacy}."
      fi
    fi
  done

  write_file "${JOURNALD_DROPIN_FILE}" "0644" "root" "root" <<EOF
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=${JOURNAL_MAX_USE}
SystemKeepFree=500M
MaxRetentionSec=${JOURNAL_RETENTION}
EOF
  run journalctl --flush
  run systemctl restart systemd-journald

  # Verify persistent storage is active (journald should create /var/log/journal)
  if ! is_true "${DRY_RUN}"; then
    local flush_check=0
    local max_wait=10
    while (( flush_check < max_wait )); do
      if [[ -d /var/log/journal ]]; then
        log "Journald persistent storage verified (/var/log/journal exists)."
        break
      fi
      sleep 1
      ((++flush_check))
    done
    if (( flush_check >= max_wait )) && [[ ! -d /var/log/journal ]]; then
      warn "Journald persistent storage directory /var/log/journal not found after ${max_wait}s. Verify with: journalctl --verify"
    fi
  fi
}
