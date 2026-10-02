#!/usr/bin/env bash
# lib/secret_transport.sh — short-lived, file-based secret transport helpers.
#
# Values are written to a private temporary directory and are never supplied as
# command-line arguments.  Callers must register the directory cleanup through
# secret_transport_dir_create; the helper also supports explicit cleanup.

[[ "${BASH_SOURCE[0]}" != "${0}" ]] \
  || { printf 'Source this file, do not execute it.\n' >&2; exit 1; }

declare -a SECRET_TRANSPORT_DIRS=()

secret_transport_dir_create() {
  local temp_root="${TMPDIR:-/tmp}"
  temp_root="${temp_root%/}"
  local dir
  dir="$(mktemp -d "${temp_root}/secure-ubuntu-paas.secrets.XXXXXXXX")" || return 1
  chmod 700 "${dir}"
  SECRET_TRANSPORT_DIRS+=("${dir}")
  printf '%s\n' "${dir}"
}

secret_transport_write_file() {
  local path="$1" value="$2"
  [[ -n "${path}" ]] || return 1
  # The supported credentials are single-line values.  Rejecting newlines
  # prevents a value from becoming multiple records in the protected file.
  [[ "${value}" != *$'\n'* && "${value}" != *$'\r'* ]] || return 1
  [[ ! -e "${path}" && ! -L "${path}" ]] || return 1
  (
    umask 077
    set -o noclobber
    printf '%s\n' "${value}" > "${path}"
  ) || return 1
  chmod 600 "${path}"
}

secret_transport_cleanup_dir() {
  local dir="${1:-}"
  [[ -n "${dir}" ]] || return 0
  local temp_root="${TMPDIR:-/tmp}"
  temp_root="${temp_root%/}"
  case "${dir}" in
    "${temp_root}"/secure-ubuntu-paas.secrets.*) ;;
    *) return 1 ;;
  esac
  [[ -d "${dir}" && ! -L "${dir}" ]] || return 0
  local entry
  for entry in "${dir}"/*; do
    [[ -e "${entry}" || -L "${entry}" ]] || continue
    rm -f -- "${entry}"
  done
  rmdir -- "${dir}" 2>/dev/null || true
}

secret_transport_cleanup_all() {
  local dir
  for dir in "${SECRET_TRANSPORT_DIRS[@]:-}"; do
    [[ -n "${dir}" ]] || continue
    secret_transport_cleanup_dir "${dir}" || true
  done
  SECRET_TRANSPORT_DIRS=()
}
