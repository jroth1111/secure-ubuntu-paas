#!/usr/bin/env bats
# Unit tests for admin user and sudo access functionality
# Tests ensure_admin_access() and passwordless sudo configuration

load '../../helpers/helpers'

setup() {
  source_script

  # Avoid BW01 warnings in dry-run tests by stubbing user-management commands.
  useradd() { :; }
  usermod() { :; }
}

# ── Admin user creation ─────────────────────────────────────────────────────────

@test "ensure_admin_access: creates user with sudo group when user doesn't exist" {
  ADMIN_USER="testadmin_${BATS_TEST_NUMBER}_$$"
  DRY_RUN="true"
  ADMIN_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTesting test@example.com"

  run ensure_admin_access
  assert_success
  assert_output --partial "DRY-RUN: would create /home/${ADMIN_USER}/.ssh/authorized_keys"
  [ ! -d "/home/${ADMIN_USER}" ]
  [ ! -f "/etc/sudoers.d/${ADMIN_USER}" ]
}

@test "ensure_admin_access: adds sudo group to existing user without it" {
  ADMIN_USER="existinguser"
  ADMIN_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTesting test@example.com"
  DRY_RUN="true"

  id() {
    if [[ "$1" == "existinguser" ]]; then
      return 0
    fi
    if [[ "$1" == "-nG" && "$2" == "existinguser" ]]; then
      echo "users"
      return 0
    fi
    command id "$@"
  }
  getent() {
    echo "existinguser:x:1001:1001::/home/existinguser:/bin/bash"
  }

  run ensure_admin_access
  assert_success
  assert_output --partial "DRY-RUN: usermod -aG sudo existinguser"
  [ ! -f "/etc/sudoers.d/existinguser" ]
}

# ── Passwordless sudo configuration ─────────────────────────────────────────────

@test "ensure_admin_access: creates sudoers.d file with NOPASSWD" {
  ADMIN_USER="testadmin_sudo_${BATS_TEST_NUMBER}_$$"
  ADMIN_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTesting test@example.com"
  DRY_RUN="true"

  run ensure_admin_access
  assert_success
  assert_output --partial "passwordless sudo"
  [ ! -f "/etc/sudoers.d/${ADMIN_USER}" ]
}

@test "ensure_admin_access: Dokploy keeps admin non-privileged" {
  ADMIN_USER="dokployadmin_dry_${BATS_TEST_NUMBER}_$$"
  PAAS="dokploy"
  DRY_RUN="true"
  ADMIN_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTesting test@example.com"

  run ensure_admin_access
  assert_success
  assert_output --partial "useradd -m -s /usr/sbin/nologin ${ADMIN_USER}" || return 1
  assert_output --partial "root operations use Tailscale-only root SSH" || return 1
  assert_output --partial "would disable SSH login for ${ADMIN_USER} and remove its authorized_keys" || return 1
  assert_output --partial "sole root authorized key for Tailscale-only Dokploy access" || return 1
  [ ! -f "/etc/sudoers.d/${ADMIN_USER}" ]
}

# ── SSH key handling ────────────────────────────────────────────────────────────

@test "ensure_admin_access: creates .ssh directory with correct permissions" {
  ADMIN_USER="testadmin"
  ADMIN_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTesting test@example.com"
  DRY_RUN="true"

  run ensure_admin_access
  assert_success
  assert_output --partial ".ssh"
  [ ! -d "/home/${ADMIN_USER}/.ssh" ]
}

@test "ensure_admin_access: adds public key to authorized_keys" {
  ADMIN_USER="testadmin"
  ADMIN_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTesting test@example.com"
  DRY_RUN="true"

  run ensure_admin_access
  assert_success
  assert_output --partial "authorized_keys"
  [ ! -f "/home/${ADMIN_USER}/.ssh/authorized_keys" ]
}

@test "install_admin_authorized_keys_no_follow: stages in destination filesystem" {
  local tmphome current_user
  tmphome="$(mktemp -d)"
  current_user="$(command id -un)"
  chmod 0700 "${tmphome}"

  run install_admin_authorized_keys_no_follow \
    "${tmphome}" "${current_user}" \
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTesting test@example.com"
  if [[ "$(id -u)" -eq 0 ]]; then
    assert_success
    grep -q 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTesting test@example.com' \
      "${tmphome}/.ssh/authorized_keys"
  else
    assert_failure
    assert_output --partial "temporary file is not root-owned"
  fi

  rm -rf "${tmphome}"
}

@test "sudo_effective_grant_state: parses denied root queries before exit status" {
  sudo() {
    echo "User dokployadmin is not allowed to run sudo on host."
    return 0
  }

  run sudo_effective_grant_state dokployadmin
  assert_failure
  [ "${status}" -eq 1 ]
}

# ── Input validation for admin user ─────────────────────────────────────────────

@test "validate_inputs: rejects root as admin user" {
  ADMIN_USER="root"
  ADMIN_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTesting test@example.com"

  run validate_inputs
  assert_failure
  assert_output --partial "must not be root"
}

@test "validate_inputs: rejects invalid username format" {
  ADMIN_USER="invalid user name"
  ADMIN_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTesting test@example.com"

  run validate_inputs
  assert_failure
  assert_output --partial "valid Linux username"
}

@test "validate_inputs: rejects empty admin user" {
  ADMIN_USER=""
  ADMIN_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTesting test@example.com"

  run validate_inputs
  assert_failure
  assert_output --partial "Missing ADMIN_USER"
}

# ── SSH key validation ──────────────────────────────────────────────────────────

@test "validate_pubkey: accepts valid ed25519 key" {
  # Generate a test key for validation testing
  local tmpdir
  tmpdir="$(mktemp -d)"
  ssh-keygen -t ed25519 -f "${tmpdir}/testkey" -N "" -C "test@example.com" >/dev/null 2>&1
  ADMIN_PUBKEY="$(cat "${tmpdir}/testkey.pub")"

  run validate_pubkey
  assert_success

  rm -rf "${tmpdir}"
}

@test "validate_pubkey: accepts valid rsa key" {
  local tmpdir
  tmpdir="$(mktemp -d)"
  ssh-keygen -t rsa -b 2048 -f "${tmpdir}/testkey" -N "" -C "test@example.com" >/dev/null 2>&1
  ADMIN_PUBKEY="$(cat "${tmpdir}/testkey.pub")"

  run validate_pubkey
  assert_success

  rm -rf "${tmpdir}"
}

@test "validate_pubkey: rejects invalid key format" {
  ADMIN_PUBKEY="not-a-valid-ssh-key"

  run validate_pubkey
  assert_failure
  assert_output --partial "does not look like a valid SSH public key"
}

@test "validate_pubkey: rejects empty key" {
  ADMIN_PUBKEY=""

  run validate_pubkey
  assert_failure
}

@test "validate_pubkey: rejects key with only key type" {
  ADMIN_PUBKEY="ssh-ed25519"

  run validate_pubkey
  assert_failure
}
