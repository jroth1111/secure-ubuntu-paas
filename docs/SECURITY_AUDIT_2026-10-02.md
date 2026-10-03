# Ubuntu / Dokploy / Hermes audit handoff

## 2026-10-03 primary-branch integration

The audited fixes are integrated into `main`. The Makefile's Docker unit target
now invokes the command runner with all seven unit-suite directories, instead
of passing multiple directories to a single-target runner. A fresh single-attempt
Linux run passed **692/692 tests**, with no `not ok` results; workflow/coverage
contracts and Bash syntax/error-level shellcheck also passed. Earlier failed or
interrupted runs are not acceptance evidence. This merge does not change the
remaining vulnerability findings or authorize another live deployment.

## 2026-10-03 native compiler continuation

Rebuilt esbuild from the exact installed stable upstream version with the
current stable Go compiler. Native discovery refuses prereleases and does not
follow symlinks. Upstream logger/helper tests passed; JavaScript, TypeScript and
JSX transform output matched the original binaries byte for byte. The compiled
replacement keeps the same JavaScript/API version, and its source commit,
compiler version and hash are recorded in the candidate image/fingerprint.

The real hardened updater passed the candidate build, dependency-floor checks,
isolated database restore and authenticated API acceptance, encrypted backup and
production rollout. Latest Dokploy scan: **271 HIGH/CRITICAL occurrences, 19
critical, 108 with listed upstream fixes** (previously 296/21/133). PostgreSQL
remained unchanged. Host and other component totals are unchanged.
Live validation: **234 PASS, 0 FAIL, 9 INFO**, no failed systemd units. Hermes
authenticated config/session, 14 frontend assets and blocked public port passed.
Two native-discovery regression tests passed; Python compile, shell syntax and
active-credential source comparison passed. Remaining compiler/Go dependency
and application-major/prerelease findings have not been declared fixed.

## 2026-10-03 package-manager continuation

Corrected an upstream project pin that was reactivating pnpm 10.22 despite a
newer prepared Corepack release. Root and workspace package-manager pins now
agree with the approved current stable pnpm 10 version. Workspace overrides are
merged without dropping other settings. Same-major compatible floors were added
for brace-expansion, minimatch, picomatch and tar. A package-metadata check runs
inside the candidate image and rejects any installed stable version below the
reviewed floors before production changes.

The hardened updater completed its real build, isolated restore/API tests,
encrypted backup and rollout. Live pnpm reports **10.34.6**. Latest Dokploy scan:
**296 HIGH/CRITICAL occurrences, 21 critical, 133 with listed upstream fixes**
(previously 337/22/174). PostgreSQL remained on its existing accepted image;
no database restart was needed for this panel-only recipe change. Host and other
component scan totals are unchanged. Live validator: **234 PASS, 0 FAIL, 9 INFO**.
Hermes authenticated session/config, 14 assets and blocked public port passed.

Two dependency-floor regression tests pass, including vulnerable-version
rejection, acceptance of newer versions without downgrade, and preservation of
workspace settings/project pins. Remaining findings are not considered fixed;
same-version native compiler rebuilds and Go helper dependency compatibility
remain follow-up work. No prerelease dependency was installed automatically.

## Continuation verification

The immutable-snapshot Linux unit suite now passes **676/676, exit 0**. All 338
tracked shell functions have a verified test mapping; workflow consistency,
shell syntax, error-level shellcheck and active-credential source comparison
passed. The earlier 76-failure run below is historical, not current acceptance.

Additional fixes: fail-closed Docker privilege inspection, actual DROP-target
validation, protocol-unspecified WAN SSH detection, correct dry-run dispatch
for overlay modules, and denial of unverifiable dashboard firewall acceptance.
Unattended image builds now use a dedicated writable Docker metadata directory
instead of attempting to write through the hardened service's read-only home.
The real hardened updater rebuilt, tested, backed up and deployed successfully.

Same-version Pack and Railpack helpers now use a current Go compiler; current
same-major package managers replace vulnerable cached copies. Fingerprints
include helper binary hashes and the dependency lock, with component-scoped
recipes so future compiler patches cannot be silently deduplicated away.

Latest scan: Dokploy **337 HIGH/CRITICAL occurrences, 22 critical, 174 with a
listed upstream fix** (previous derivative 413/27/250). Other scan totals are
unchanged. This is not a clean-image claim: remaining language/helper findings
still need compatibility work, and signed host packages do not yet contain every
listed upstream fix. No findings were hidden to make the scan green.

Tailscale administrator API independently returned keyExpiryDisabled=true for
the approved VPS device. A protected receipt is bound to its current node and
IP; missing CLI expiry fields are not interpreted as disabled. The API key was
not copied to the VPS. Live validation passed **234/0/9** and Hermes password
login, protected configuration, frontend assets and blocked public access passed.
Automatic Docker restarts/required reboots remain approved; no host reboot was
performed during this continuation.

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
The earlier review-branch publication boundary is superseded by the primary
integration above. Remaining dependency findings, alerting and continuous
off-server replication remain follow-up work. Do not run a
fresh production provisioning pass just to replay these changes.
