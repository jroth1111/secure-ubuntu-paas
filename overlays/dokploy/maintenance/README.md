# Approved security derivatives

This optional server-local policy tracks official Dokploy `latest`, PostgreSQL
major 16, and Traefik 3.7 security patches. It never restarts the Docker daemon
or reboots the host. Application restarts must be explicitly approved.

Current operator policy (2026-10-02, superseding earlier supervision rules): all
application/service restarts, Docker daemon restarts and host reboots may be
automatic. The operator explicitly approved disabling Swarm autolock for
unattended recovery. Enable that tradeoff only through the protected policy:

```bash
bash /root/overlays/dokploy/maintenance/enable-unattended-recovery.sh --approved-disable-autolock
```

The enablement requires a successful encrypted recovery backup, retains
rollback copies of the old update configuration, and enables required-reboot
maintenance at 04:45 server time. A two-minute watchdog requires three failed
checks, a 30-minute cooldown and at most three recovery attempts per day per
target. It avoids updater/backup/package-maintenance conflicts and does not
delete data, reboot on arbitrary health failures or revive deliberately stopped
Hermes containers. Swarm itself reconciles unhealthy service tasks. This
does not authorize automatic database major migrations, destructive restores,
bypassing acceptance tests, or restarting unrelated deployments without cause.

After base hardening and Dokploy admin/2FA enrollment, create a dedicated,
expiring API key with a bounded rate limit of at least 240 requests/hour.
Store it in a root-owned mode-0600 JSON file:

```json
{"url":"http://127.0.0.1:3000","token":"<dedicated key>"}
```

Optional `composeId` requests an additional read-only compose API check. No
Hermes deployment identifier or user credential is embedded in these scripts.

Following approval, install the policy from the synced companion tree:

```bash
bash /root/overlays/dokploy/maintenance/install.sh --approved-api-config /root/paas-api.json
systemctl start dokploy-auto-update.service
```

The installer does not itself deploy an image or restart Docker. The updater
builds immutable, root-provenanced images and tests a RAM-only cloned database
and isolated panel with no production mounts, published ports, or Docker
socket. It requires authenticated API acceptance and refuses unauthenticated
access. Only after paired acceptance and encrypted recovery snapshots does it
update production services. It verifies exact live image IDs and health, and
rolls failed image changes back without automatically overwriting user data.

Dokploy is rebuilt from its matching stable Git tag, with fixed-version
security floors that do not downgrade newer dependencies or cross majors.
The newer same-major Node runtime and Debian patches are included; unnecessary
Docker daemon packages are removed from the **image**, not the host. PostgreSQL
remains major 16; gosu is rebuilt from the corresponding upstream release with
the current stable Go compiler. No prerelease fixes are installed automatically.

Checks run every six hours through the existing timer. The patch layer refreshes
daily. Cached source stages avoid unnecessary recompilation; unchanged software
fingerprints preserve production tags and avoid application restarts. Root-owned
receipts live under `/var/lib/server-hardening/paas-images`; the validator requires
actual base-label/image-ID provenance, not merely a local image name.

Recovery archives include database, service definitions, configuration, registry
credentials and mounted Swarm secrets. Plaintext is confined to RAM/pipes; only
`age` ciphertext is written. The operator's off-server SSH private key decrypts
the archives. Automatic off-server replication needs an explicitly configured
destination. Restore drills and secret presence checks must be performed.

The updater cannot promise zero downtime on one VPS. Docker runtime maintenance
and required host reboot automation use the explicitly approved policy above.
Database major migrations and data restores remain explicit decisions. Archive
size/headroom guards fail closed rather than fill the disk.
Unfixed and major/prerelease-only vulnerability findings remain reportable.

Native esbuild binaries are discovered from the installed application modules,
rebuilt from their exact stable upstream tags with the current stable Go
compiler, and replaced without changing the JavaScript/API version. Upstream
logger/helper unit tests and byte-for-byte JS/TS/JSX transform comparisons must
pass. Symbolic links are not followed during discovery. Compiler version, source
commits and replacement hashes are recorded in the immutable candidate image
and included in its software fingerprint.

The builder updates both root/workspace package-manager pins and authoritative
workspace overrides. It preserves other workspace settings. An image-level
dependency-floor check refuses candidates that still contain stable package
versions below the reviewed floors; preparing a newer Corepack release alone
is not evidence that the project actually uses it. npm and pnpm refresh only
within their approved stable majors. Upstream manager-major changes fail closed.

With a checksum-verified `trivy` binary installed, the installer also enables a
daily read-only CVE scan using the current advisory database. It scans the host
and exact running PaaS/Hermes images, not secrets or unrelated workloads, and
stores root-only reports in `/var/lib/server-hardening/vulnerability-scans`.
This detects newly published advisories; it does **not** automatically change
the fixed-version application dependency floors. Review findings and advance
those floors through tests. The timer has bounded CPU/memory and does not
restart services. External alert delivery requires a configured destination.
