sudo_effective_grant_state() {
  local user="$1"
  local listing=""
  local rc=0

  [[ -n "${user}" ]] || return 2
  command -v sudo >/dev/null 2>&1 || return 2

  listing="$(LC_ALL=C sudo -n -l -U "${user}" 2>&1)" || rc=$?
  # When root asks about another account, sudo may return exit 0 even when the
  # queried account is denied. Parse the C-locale denial text before trusting
  # the status code; otherwise a denied account is misclassified as privileged.
  if grep -Eqi 'not allowed to run sudo|may not run sudo' <<< "${listing}"; then
    return 1
  fi

  if (( rc == 0 )); then
    # Any successful sudo -l result without an explicit denial means the
    # account has an effective sudo policy, regardless of its source.
    return 0
  fi

  # Treat every other non-zero result as ambiguous and fail closed.
  return 2
}
