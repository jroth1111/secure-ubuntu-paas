kernel_modules_check() {
  local dropin="${KERNEL_MODULES_DROPIN_FILE:-/etc/modprobe.d/99-zzz-hardening-modules.conf}"
  local -a expected=(
    dccp sctp rds tipc
    cramfs freevxfs jffs2 hfs hfsplus
  )

  if [[ ! -f "${dropin}" ]]; then
    record "FAIL" "kernel-modules: blacklist drop-in" "missing ${dropin}"
    return
  fi

  local mod missing=() still_loaded=()
  for mod in "${expected[@]}"; do
    grep -qE "^install[[:space:]]+${mod}[[:space:]]+/bin/(false|true)\b" "${dropin}" || missing+=("${mod}")
    if lsmod 2>/dev/null | awk '{print $1}' | grep -qx "${mod}"; then
      still_loaded+=("${mod}")
    fi
  done

  if (( ${#missing[@]} == 0 )); then
    record "PASS" "kernel-modules: unused modules blocked" "${#expected[@]} modules"
  else
    record "FAIL" "kernel-modules: unused modules blocked" "not blocked: ${missing[*]}"
  fi

  # A blocked module that is still resident means the install rule was added
  # after it loaded; flag it (a reboot clears it).
  if (( ${#still_loaded[@]} > 0 )); then
    record "FAIL" "kernel-modules: no blocked module resident" "loaded: ${still_loaded[*]} — reboot to clear"
  else
    record "PASS" "kernel-modules: no blocked module resident"
  fi
}
