# Ubuntu / Dokploy / Hermes audit handoff

## Verified live result

Ubuntu 24.04 (not Debian), running kernel 6.8.0-146-generic; no host reboot
performed. Obsolete 6.8.0-31 packages were replaced by a 6.8.0-142 fallback.
The final live validator recorded **233 PASS, 0 FAIL, 9 INFO** after the approved
unattended-recovery policy change. Raw gates, scans and recovery receipts are
kept in the operator's private evidence directory, not this public repository.

Fixed Docker-generated bridge inventory without allowing arbitrary bridge
interfaces or bypassing WAN/management drops. Hermes outbound HTTPS works;
container-origin panel access remains blocked. Root key-only Tailscale access,
locked root password, non-privileged named account, private management ports,
TOTP enrollment, immutable audit policy and zero lost audit events were checked.
Deployment logs/configuration now have root-only parent permissions plus a
permission reconciliation timer; no unrelated application settings were read.

Deployed and tested source-rebuilt Dokploy and PostgreSQL derivatives. Dokploy
stays at upstream v0.30.8, with same-major Node and reviewed dependency security
floors. PostgreSQL stays at major 16. Its privilege helper is rebuilt with a
current Go compiler. Hermes stays on its tested private derivative with
non-root application execution, no Docker socket and protected persistent data.

After an encrypted backup, a real Docker daemon restart passed: Swarm returned
active without manual unlock; the panel and Hermes became healthy; firewall
reconciliation succeeded. A fresh SSH connection and full validator passed.
Hermes password login, protected config denial, authenticated config/session,
14 frontend assets and blocked public access also passed. No model configured,
so inference performance was not benchmarked.

Last observed capacity: 5.9 GiB RAM available, 35 MiB swap used, 101 GiB disk
available. There was no evidence requiring higher control-plane resource limits.

## Latest explicit operator policy

All service/application restarts, Docker restarts and required host reboots may
be automatic. The operator explicitly chose **disabled Swarm autolock** to
permit unattended recovery. Standard Swarm encryption remains, but the manager
key lacks an off-server unlock password. The root-owned recovery policy and
validator record this exception; default deployments still require autolock.
The old off-server key is retained for transition recovery.

Signed Ubuntu, Tailscale and Docker stable package updates are eligible for
unattended installation. Required host reboots are scheduled at **04:45 local
server time (Australia/Melbourne)**. The dry run passed. Container updates track
approved channels, build/test before rollout, back up before changes, verify
the actual live image and roll back failed image changes without restoring
data automatically. PostgreSQL major upgrades remain a separate decision.

The two-minute recovery watchdog waits for three failed checks, has a 30-minute
cooldown and a three-attempt rolling-day budget per target. It avoids managed
updater/backup locks and active host package maintenance. It may recover a
failed Docker daemon, unhealthy scoped Hermes container or failed security
reconciliation unit. It does not reboot on arbitrary health failures, delete
data or revive deliberately stopped Hermes containers. Swarm task health is
also reconciled by Swarm itself.

## Vulnerability discovery is not universal remediation

Daily Trivy scans refresh the advisory database and scan the host plus exact
running core/Hermes images. Host scans exclude container storage to avoid
counting cached layers as host-installed software. Reports are root-only,
bounded by CPU/memory/time, and contain vulnerabilities, not environment or
secret scans. External notification delivery is not configured.

Latest HIGH/CRITICAL **occurrences** (not unique exploitable vulnerabilities):

| Target | Findings | Critical | Upstream fix listed |
| --- | ---: | ---: | ---: |
| Host | 1690 | 50 | 7 |
| Dokploy derivative | 413 | 27 | 250 |
| PostgreSQL derivative | 62 | 1 | 0 |
| Traefik | 0 | 0 | 0 |
| Hermes derivative | 325 | 3 | 0 |

Host kernel findings contain repeated package metadata. A listed upstream fix
does not prove that a current signed vendor package contains it. Dokploy still
has build-helper/dependency findings requiring compatibility review, including
major/prerelease-only fixes. No blanket clean-image claim is made. Application
dependency security floors are a reviewed static manifest, not a complete
automatic CVE-to-compatible-patch resolver.

Complete control-plane recovery includes SQL, service definitions,
configuration, registry credentials and two mounted Swarm secrets. Plaintext
remains in RAM/pipes. An off-server ciphertext copy was decrypted in memory and
verified; paired SQL restore/API tests passed before rollout. Latest copied
archive SHA-256:
`f9ab7e5d33df5f7a0ec0b7034906e8f4ec1163ddc3f93c247c2c95dff19119a8`.
Automatic off-server replication still needs a destination. Other application
volumes need their own recovery contracts and were not deleted or modified.

## Repository quality and publication boundary

All shell source files passed `bash -n`; maintenance Python compiled; Node
patch scripts parsed; targeted security BATS tests passed **24/24**; scanner
tests passed **2/2**, recovery-budget tests **3/3**, and four mocked Hermes
update/rollback/refusal scenarios passed. Workflow consistency passed.
The active-credential comparison found no matching leaked credentials in
source; private receipts and encrypted backups are excluded from publication.

The broad isolated Linux unit run exited **1: 670 tests, 76 failures**. It is
not a release gate pass. Restoring real assertion semantics exposed fixture
and coverage-contract problems; not every failure has been classified.
Related accumulated code is published on a review branch, not merged to the
default branch. CI/contract repair, remaining dependency findings, alerting
and continuous off-server replication remain follow-up work. Do not run a
fresh production provisioning pass just to replay these changes.
