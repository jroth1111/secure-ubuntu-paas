#!/usr/bin/env bash
# Explicitly approved availability/security tradeoff; no immediate reboot.
set -Eeuo pipefail
[[ "$(id -u)" == 0 && $# == 1 && "$1" == --approved-disable-autolock ]] || {
  echo 'Usage (root, explicit approval required): enable-unattended-recovery.sh --approved-disable-autolock' >&2
  exit 2
}
source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ "$(docker info --format '{{.Swarm.LocalNodeState}}')" == active ]]
/usr/local/sbin/controlplane-backup
rollback="/var/lib/server-hardening/recovery/policy-backup-$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 0700 "$rollback" /etc/dokploy /etc/needrestart/conf.d
for file in /etc/apt/apt.conf.d/55-runtime-maintenance \
  /etc/apt/apt.conf.d/55-dokploy-runtime-maintenance \
  /etc/apt/apt.conf.d/52docker-supervised-maintenance \
  /etc/needrestart/conf.d/50-docker-supervised.conf \
  /etc/needrestart/conf.d/50-dokploy-runtime-supervised.conf; do
  if [[ -e "$file" ]]; then
    [[ -f "$file" && ! -L "$file" ]]
    install -m 0600 "$file" "$rollback/$(basename "$file")"
    rm -- "$file"
  fi
done
install -m 0700 "${source_dir}/recovery-policy.py" /usr/local/sbin/paas-recovery-policy
python3 - <<'PY'
import json,os,pathlib,tempfile
path=pathlib.Path('/etc/dokploy/recovery-policy.json')
fd,name=tempfile.mkstemp(prefix='.recovery-',dir=path.parent)
with os.fdopen(fd,'w') as f:
 json.dump({'unattendedRecoveryApproved':True,'swarmAutolock':False},f)
 f.flush();os.fsync(f.fileno())
os.chmod(name,0o600);os.replace(name,path)
PY
docker swarm update --autolock=false >/dev/null
[[ "$(docker info 2>/dev/null | awk -F: '/Autolock Managers/ {gsub(/[[:space:]]/,"",$2);print tolower($2)}')" == false ]]
python3 /usr/local/sbin/paas-recovery-policy
install -m 0644 "${source_dir}/57-unattended-recovery" /etc/apt/apt.conf.d/57-unattended-recovery
install -m 0644 "${source_dir}/51-runtime-automatic.conf" /etc/needrestart/conf.d/51-runtime-automatic.conf
install -m 0700 "${source_dir}/autoheal.py" /usr/local/sbin/paas-autoheal
install -m 0644 "${source_dir}/autoheal.service" "${source_dir}/autoheal.timer" /etc/systemd/system/
install -d /etc/systemd/system/docker.service.d
install -m 0644 "${source_dir}/91-auto-recovery.conf" /etc/systemd/system/docker.service.d/91-auto-recovery.conf
systemd-analyze verify /etc/systemd/system/autoheal.service /etc/systemd/system/autoheal.timer
systemctl daemon-reload
systemctl start autoheal.service
systemctl enable --now autoheal.timer
apt-config dump | grep -E 'Automatic-Reboot|Package-Blacklist' || true
echo "Unattended runtime recovery enabled. Rollback configuration: $rollback. No immediate reboot performed."
