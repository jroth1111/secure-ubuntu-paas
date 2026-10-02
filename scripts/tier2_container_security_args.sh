#!/usr/bin/env bash

# Security profile for the ephemeral systemd integration-test container.
#
# Tier 2 tests exercise UFW, iptables, audit-rule stubs, sshd, and systemd.
# They need more than Docker's default capability set, but they must not run
# with Docker's blanket privileged mode (all capabilities, all devices, and
# host LSM bypasses).
# Keep this list reviewed when a test gains a new host-facing operation.
declare -ag TIER2_CONTAINER_SECURITY_ARGS=(
  --cap-drop=ALL
  --cap-add=AUDIT_CONTROL
  --cap-add=AUDIT_WRITE
  --cap-add=CHOWN
  --cap-add=DAC_OVERRIDE
  --cap-add=DAC_READ_SEARCH
  --cap-add=FOWNER
  --cap-add=IPC_LOCK
  --cap-add=KILL
  --cap-add=MKNOD
  --cap-add=NET_ADMIN
  --cap-add=NET_RAW
  --cap-add=SETFCAP
  --cap-add=SETGID
  --cap-add=SETUID
  --cap-add=SYS_ADMIN
  --cap-add=SYS_CHROOT
  --cap-add=SYS_PTRACE
  --cap-add=SYS_RESOURCE
  --cgroupns=private
)
