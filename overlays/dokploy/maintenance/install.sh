#!/usr/bin/env bash
# Explicit opt-in; does not deploy application images or restart Docker.
set -Eeuo pipefail
[[ "$(id -u)" == 0 ]] || { echo 'Run as root.' >&2; exit 1; }
refresh_only=false
if [[ $# == 1 && "$1" == --refresh-installed ]]; then
  refresh_only=true
  set -- --approved-api-config /etc/dokploy/paas-hardening/api.json
  python3 - <<'PY'
import json,pathlib,stat
p=pathlib.Path('/etc/dokploy/security-image-policy.json');s=p.lstat()
if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or stat.S_IMODE(s.st_mode)!=0o600:raise SystemExit('Unsafe existing policy')
if json.loads(p.read_text())!={'dokploy':'tested-source-latest','postgresMajor':16,'briefApplicationRestartsApproved':True}:raise SystemExit('Policy is not approved; refusing reactivation')
PY
fi
[[ $# == 2 && "$1" == --approved-api-config ]] || {
  echo 'Usage: install.sh --approved-api-config <root-owned 0600 JSON file>' >&2
  echo 'Run only after approving tested source derivatives and brief application restarts.' >&2
  exit 2
}
api_config="$2"
python3 - "${api_config}" <<'PY'
import json,pathlib,stat,sys
p=pathlib.Path(sys.argv[1]);s=p.lstat()
if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or stat.S_IMODE(s.st_mode)!=0o600:raise SystemExit('Unsafe API config')
d=json.loads(p.read_text())
if d.get('url')!='http://127.0.0.1:3000' or not isinstance(d.get('token'),str) or not d['token']:raise SystemExit('Invalid loopback credential config')
PY
source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
for prerequisite in docker age git python3 systemctl; do
  command -v "$prerequisite" >/dev/null || { echo "Missing prerequisite: $prerequisite" >&2; exit 1; }
done
[[ -f /var/lib/server-hardening/backup-recipient && ! -L /var/lib/server-hardening/backup-recipient \
  && "$(stat -c '%a:%U:%G' /var/lib/server-hardening/backup-recipient)" == '600:root:root' ]] \
  || { echo 'Provision the protected operator backup recipient first.' >&2; exit 1; }
install -d -m 0700 /usr/local/lib/paas-hardening /var/lib/server-hardening/paas-images \
  /var/lib/server-hardening/controlplane-backups /etc/dokploy/paas-hardening
for file in Dockerfile.dokploy-source Dockerfile.postgres security-overrides.json apply-overrides.cjs test-pair.py .dockerignore; do
  install -m 0600 "${source_dir}/${file}" "/usr/local/lib/paas-hardening/${file}"
done
for pair in 'paas-build.py paas-build-image' 'paas-auto-update.py paas-auto-update' \
  'provenance.py paas-image-provenance' 'controlplane-backup.py controlplane-backup' 'protect-config.py paas-protect-config' \
  'vulnerability-scan.py paas-vulnerability-scan' 'recovery-policy.py paas-recovery-policy'; do
  read -r from to <<< "$pair"
  install -m 0700 "${source_dir}/${from}" "/usr/local/sbin/${to}"
  python3 -m py_compile "/usr/local/sbin/${to}"
done
if [[ "$(readlink -f "${api_config}")" != /etc/dokploy/paas-hardening/api.json ]]; then
  install -m 0600 "${api_config}" /etc/dokploy/paas-hardening/api.json
fi
install -m 0644 "${source_dir}/controlplane-backup.service" "${source_dir}/controlplane-backup.timer" /etc/systemd/system/
install -m 0644 "${source_dir}/paas-config-permissions.service" "${source_dir}/paas-config-permissions.timer" /etc/systemd/system/
install -d /etc/systemd/system/dokploy-auto-update.service.d
install -m 0644 "${source_dir}/90-source-derivatives.conf" /etc/systemd/system/dokploy-auto-update.service.d/90-source-derivatives.conf
if [[ "${refresh_only}" != true ]]; then
python3 - <<'PY'
import json,os,pathlib,tempfile
path=pathlib.Path('/etc/dokploy/security-image-policy.json')
fd,name=tempfile.mkstemp(prefix='.policy-',dir=path.parent)
with os.fdopen(fd,'w') as f:json.dump({'dokploy':'tested-source-latest','postgresMajor':16,'briefApplicationRestartsApproved':True},f)
os.chmod(name,0o600);os.replace(name,path)
PY
fi
systemd-analyze verify /etc/systemd/system/controlplane-backup.service /etc/systemd/system/controlplane-backup.timer
systemctl daemon-reload
systemctl enable --now controlplane-backup.timer
systemctl start paas-config-permissions.service
systemctl enable --now paas-config-permissions.timer
if command -v trivy >/dev/null; then
  install -m 0644 "${source_dir}/vulnerability-scan.service" "${source_dir}/vulnerability-scan.timer" /etc/systemd/system/
  systemd-analyze verify /etc/systemd/system/vulnerability-scan.service /etc/systemd/system/vulnerability-scan.timer
  systemctl daemon-reload
  systemctl enable --now vulnerability-scan.timer
else
  echo 'CVE discovery timer not enabled: install a checksum-verified Trivy binary first.' >&2
fi
if [[ -e /etc/dokploy/recovery-policy.json || -L /etc/dokploy/recovery-policy.json ]]; then
  python3 /usr/local/sbin/paas-recovery-policy
  install -m 0700 "${source_dir}/autoheal.py" /usr/local/sbin/paas-autoheal
  install -m 0644 "${source_dir}/autoheal.service" "${source_dir}/autoheal.timer" /etc/systemd/system/
  install -m 0644 "${source_dir}/57-unattended-recovery" /etc/apt/apt.conf.d/57-unattended-recovery
  install -m 0644 "${source_dir}/51-runtime-automatic.conf" /etc/needrestart/conf.d/51-runtime-automatic.conf
  install -d /etc/systemd/system/docker.service.d
  install -m 0644 "${source_dir}/91-auto-recovery.conf" /etc/systemd/system/docker.service.d/91-auto-recovery.conf
  systemd-analyze verify /etc/systemd/system/autoheal.service /etc/systemd/system/autoheal.timer
  systemctl daemon-reload
  systemctl enable --now autoheal.timer
fi
echo 'Approved maintenance helpers installed. Run dokploy-auto-update.service to build, test, back up and roll out.'
