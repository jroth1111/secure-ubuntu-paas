#!/usr/bin/env bash
# Explicit same-GA fallback replacement. Never reboots or retires the running kernel.
set -Eeuo pipefail
[[ "$(id -u)" == 0 ]] || { echo 'Run as root.' >&2; exit 1; }
[[ $# == 3 && "$3" == --approved ]] || {
  echo 'Usage: kernel-fallback-maintenance.sh <new-fallback-release> <obsolete-release> --approved' >&2
  exit 2
}
fallback="$1";obsolete="$2";running="$(uname -r)"
for release in "$fallback" "$obsolete" "$running"; do
  [[ "$release" =~ ^[0-9]+\.[0-9]+\.0-[0-9]+-generic$ ]] || exit 1
done
[[ "$obsolete" != "$running" && "$fallback" != "$running" && "$obsolete" != "$fallback" ]]
[[ "${fallback%%.0-*}" == "${running%%.0-*}" ]]
dpkg --compare-versions "${fallback%-generic}" gt "${obsolete%-generic}"
dpkg --compare-versions "${running%-generic}" gt "${fallback%-generic}"
marker_before=false
[[ ! -e /var/run/reboot-required ]] || marker_before=true
linux_base_before="$(dpkg-query -W -f='${Version}' linux-base)"
env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get install -y \
  "linux-image-${fallback}" "linux-modules-extra-${fallback}"
test -s "/boot/vmlinuz-${fallback}";test -s "/boot/initrd.img-${fallback}"
apt-mark manual "linux-image-${fallback}" "linux-modules-${fallback}" "linux-modules-extra-${fallback}"
obsolete_abi="${obsolete%-generic}"
mapfile -t installed < <(dpkg-query -W -f='${binary:Package} ${db:Status-Abbrev}\n' 'linux*' \
  | awk -v target="-${obsolete_abi}" '$2=="ii" && (substr($1,length($1)-length(target)+1)==target || substr($1,length($1)-length(target)-7)==target"-generic") {print $1}')
for package in "${installed[@]}"; do
  [[ "$package" =~ ^linux-(image|modules|modules-extra|tools|headers)-[0-9]+\.[0-9]+\.0-[0-9]+(-generic)?$ ]] || exit 1
  [[ "$package" != *"$running"* ]]
done
if [[ ${#installed[@]} -gt 0 ]]; then
  env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get remove -y "${installed[@]}"
fi
test "$(uname -r)" = "$running"
test -L /boot/vmlinuz
ln -sfn "vmlinuz-${running}" /boot/vmlinuz
if [[ -L /boot/initrd.img ]]; then ln -sfn "initrd.img-${running}" /boot/initrd.img; fi
update-grub
first=$(awk '$1=="linux"||$1=="linuxefi" {print $2;exit}' /boot/grub/grub.cfg)
[[ "$first" == */vmlinuz-"$running" ]]
# Installing an older fallback invokes linux-base's generic reboot notifier.
# Reconcile only a newly-created marker listing this fallback and linux-base;
# preserve any pre-existing marker or additional cause. Keep rollback copies.
if [[ "$marker_before" == false && -f /var/run/reboot-required.pkgs \
  && "$(dpkg-query -W -f='${Version}' linux-base)" == "$linux_base_before" ]] \
  && ! grep -vEx "linux-image-${fallback}|linux-base|[[:space:]]*" /var/run/reboot-required.pkgs | grep -q .; then
  install -d -m 0700 /var/lib/server-hardening/kernel-maintenance
  install -m 0600 /var/run/reboot-required /var/lib/server-hardening/kernel-maintenance/fallback-reboot-marker
  install -m 0600 /var/run/reboot-required.pkgs /var/lib/server-hardening/kernel-maintenance/fallback-reboot-marker.pkgs
  rm -- /var/run/reboot-required /var/run/reboot-required.pkgs
fi
printf 'Fallback %s installed; obsolete %s retired; primary/running %s preserved; no reboot.\n' "$fallback" "$obsolete" "$running"
