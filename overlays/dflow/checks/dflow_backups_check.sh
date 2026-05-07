dflow_backups_check() {
  local app_name="${DFLOW_BACKUPS_APP:-backups-app}"

  if ! command -v dokku >/dev/null 2>&1; then
    record "INFO" "dflow: backups app" "dokku not present yet (controller installs ${app_name} during onboarding)"
    return 0
  fi

  if dokku apps:exists "${app_name}" >/dev/null 2>&1; then
    record "PASS" "dflow: backups app exists" "${app_name}"
  else
    record "INFO" "dflow: backups app" "${app_name} not present yet (controller deploys it on attach)"
    return 0
  fi

  # The backups app uses Restic; the repository password and S3-compatible
  # credentials are set via dokku config. Confirm at least the password env
  # var is present (without leaking it).
  local config
  config="$(dokku config:show "${app_name}" 2>/dev/null)" || config=""
  if grep -q '^RESTIC_PASSWORD' <<< "${config}"; then
    record "PASS" "dflow: backups app config" "RESTIC_PASSWORD set"
  else
    record "FAIL" "dflow: backups app config" "RESTIC_PASSWORD missing on ${app_name}"
  fi
  if grep -Eq '^(AWS_ACCESS_KEY_ID|RESTIC_REPOSITORY)' <<< "${config}"; then
    record "PASS" "dflow: backups app config" "restic repository or AWS credential present"
  else
    record "INFO" "dflow: backups app config" "no AWS_ACCESS_KEY_ID / RESTIC_REPOSITORY found (operator may use a different storage backend)"
  fi
}
