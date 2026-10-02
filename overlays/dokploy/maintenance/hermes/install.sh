#!/usr/bin/env bash
# Refresh only an already approved deployment; no image build or deployment.
set -Eeuo pipefail
[[ "$(id -u)" == 0 && $# == 1 && "$1" == --refresh-installed ]] || exit 2
systemctl is-active --quiet hermes-auto-update.service && {
  echo 'Updater active; refusing concurrent replacement' >&2; exit 1;
}
python3 - <<'PY'
import json,pathlib,re,stat
p=pathlib.Path('/etc/dokploy/hermes-updater/config.json');s=p.lstat()
assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o600
c=json.loads(p.read_text())
assert c['url']=='http://127.0.0.1:3000' and c['token']
assert all(re.fullmatch(r'[A-Za-z0-9_-]+',c[k]) for k in ['appName','composeId'])
p=pathlib.Path('/var/lib/server-hardening/hermes/build-state.json');s=p.lstat()
assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and stat.S_IMODE(s.st_mode)==0o600
assert json.loads(p.read_text())['isolatedTestsPassed'] is True
PY
source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
install -d -m 0700 /usr/local/lib/hermes-hardening/image /var/lib/server-hardening/hermes/docker-config
for file in Dockerfile patch-python.py patch-node.cjs patch-uv.py smoke.py manifest.py test-image.py; do
  install -m 0600 "${source_dir}/${file}" "/usr/local/lib/hermes-hardening/image/${file}"
done
install -m 0700 "${source_dir}/build-image.py" /usr/local/sbin/hermes-build-image
install -m 0700 "${source_dir}/updater.py" /usr/local/sbin/hermes-auto-update
python3 -m py_compile /usr/local/sbin/hermes-build-image /usr/local/sbin/hermes-auto-update
install -d /etc/systemd/system/hermes-auto-update.service.d
install -m 0644 "${source_dir}/derivative.conf" /etc/systemd/system/hermes-auto-update.service.d/derivative.conf
systemctl daemon-reload
echo 'Existing approved Hermes helpers refreshed; no image deployed.'
