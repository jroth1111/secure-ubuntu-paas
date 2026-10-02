#!/usr/bin/env python3
"""Require an explicit, protected approval before unattended runtime recovery."""
import json, pathlib, stat

path = pathlib.Path('/etc/dokploy/recovery-policy.json')
metadata = path.lstat()
if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
    raise SystemExit('Unsafe unattended recovery policy')
if json.loads(path.read_text()) != {'unattendedRecoveryApproved': True, 'swarmAutolock': False}:
    raise SystemExit('Unattended recovery is not approved')
