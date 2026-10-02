configure_banner() {
  write_file "/etc/issue.net" "0644" "root" "root" <<'EOF'
***************************************************************************
                   AUTHORIZED ACCESS ONLY
This system is for authorized use only. All activity may be monitored
and reported. Unauthorized access is prohibited and may be subject to
criminal and civil penalties.
***************************************************************************
EOF
}

install_admin_authorized_keys_no_follow() {
  local home_dir="$1"
  local admin_user="$2"
  local admin_pubkey="$3"

  # Keep every pathname operation below on already-open directory descriptors.
  # The administrator owns (or can influence) its home tree, so pathname-based
  # cat/redirection would allow a symlink swap to turn this root operation into
  # a disclosure or write primitive.
  python3 - "${home_dir}" "${admin_user}" "${admin_pubkey}" <<'PY'
import os
import pwd
import secrets
import stat

home_path, username, public_key = os.sys.argv[1:]
if not public_key or "\x00" in public_key or "\n" in public_key or "\r" in public_key:
    raise SystemExit("invalid administrator public key")

no_follow = getattr(os, "O_NOFOLLOW", 0)
if not no_follow:
    raise SystemExit("O_NOFOLLOW is unavailable")
directory_flags = os.O_RDONLY | os.O_DIRECTORY | no_follow | os.O_CLOEXEC
file_flags = os.O_RDONLY | no_follow | os.O_CLOEXEC
account = pwd.getpwnam(username)
uid, gid = account.pw_uid, account.pw_gid

def check_directory(fd, label, allowed_uids):
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode):
        raise SystemExit(f"{label} is not a directory")
    if info.st_uid not in allowed_uids or (info.st_mode & 0o022):
        raise SystemExit(f"{label} has unsafe ownership or permissions")

def close_quietly(fd):
    if fd is not None:
        try:
            os.close(fd)
        except OSError:
            pass

home_fd = ssh_fd = None
temp_name = None
try:
    home_fd = os.open(home_path, directory_flags)
    check_directory(home_fd, home_path, {0, uid})
    try:
        os.mkdir(".ssh", 0o700, dir_fd=home_fd)
    except FileExistsError:
        pass
    ssh_fd = os.open(".ssh", directory_flags, dir_fd=home_fd)
    check_directory(ssh_fd, f"{home_path}/.ssh", {0, uid})
    os.fchown(ssh_fd, uid, gid)
    os.fchmod(ssh_fd, 0o700)

    existing = b""
    try:
        source_fd = os.open("authorized_keys", file_flags, dir_fd=ssh_fd)
    except FileNotFoundError:
        source_fd = None
    if source_fd is not None:
        try:
            source_info = os.fstat(source_fd)
            if not stat.S_ISREG(source_info.st_mode):
                raise SystemExit("administrator authorized_keys is not a regular file")
            if source_info.st_uid not in {0, uid} or (source_info.st_mode & 0o022):
                raise SystemExit("administrator authorized_keys has unsafe ownership or permissions")
            chunks = []
            while True:
                chunk = os.read(source_fd, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            existing = b"".join(chunks)
        finally:
            close_quietly(source_fd)

    if existing and not existing.endswith(b"\n"):
        existing += b"\n"
    key_bytes = public_key.encode("utf-8")
    if key_bytes not in existing.splitlines():
        existing += key_bytes + b"\n"

    # Create the temporary file inside the already-open destination directory.
    # /run is commonly tmpfs while /home is not, so staging there and renaming
    # into .ssh can raise EXDEV and abort hardening on a normal Ubuntu host.
    # O_EXCL + O_NOFOLLOW keeps the temporary creation race-safe.
    temp_fd = None
    temp_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow | os.O_CLOEXEC
    for _ in range(64):
        candidate = ".authorized_keys." + secrets.token_hex(12)
        try:
            temp_fd = os.open(candidate, temp_flags, 0o600, dir_fd=ssh_fd)
            temp_name = candidate
            break
        except FileExistsError:
            continue
    if temp_fd is None or temp_name is None:
        raise SystemExit("unable to create a unique authorized_keys temporary file")
    try:
        temp_info = os.fstat(temp_fd)
        if not stat.S_ISREG(temp_info.st_mode) or temp_info.st_uid != 0:
            raise SystemExit("authorized_keys temporary file is not root-owned")
        os.fchmod(temp_fd, 0o600)
        view = memoryview(existing)
        while view:
            written = os.write(temp_fd, view)
            if written <= 0:
                raise SystemExit("unable to write authorized_keys staging file")
            view = view[written:]
        os.fsync(temp_fd)
    finally:
        close_quietly(temp_fd)

    # Both names are in the same open directory, so this atomic replacement
    # cannot fail with EXDEV and does not follow an attacker-created target.
    os.rename(temp_name, "authorized_keys", src_dir_fd=ssh_fd, dst_dir_fd=ssh_fd)
    temp_name = None
    final_fd = os.open("authorized_keys", file_flags, dir_fd=ssh_fd)
    try:
        final_info = os.fstat(final_fd)
        if not stat.S_ISREG(final_info.st_mode) or final_info.st_uid != 0:
            raise SystemExit("installed authorized_keys is not the root-owned staged file")
        os.fchown(final_fd, uid, gid)
        os.fchmod(final_fd, 0o600)
        os.fsync(final_fd)
    finally:
        close_quietly(final_fd)
finally:
    if temp_name is not None and ssh_fd is not None:
        try:
            os.unlink(temp_name, dir_fd=ssh_fd)
        except OSError:
            pass
    close_quietly(ssh_fd)
    close_quietly(home_fd)
PY
}

ensure_admin_access() {
  local home_dir
  local user_exists="false"

  if id "${ADMIN_USER}" >/dev/null 2>&1; then
    user_exists="true"
    log "Admin user exists: ${ADMIN_USER}"
  else
    if [[ "${PAAS}" == "dokploy" ]]; then
      run useradd -m -s /usr/sbin/nologin "${ADMIN_USER}"
    else
      run useradd -m -s /bin/bash -G sudo "${ADMIN_USER}"
    fi
  fi

  if [[ "${PAAS}" != "dokploy" ]] \
    && [[ "${user_exists}" == "true" ]] \
    && ! id -nG "${ADMIN_USER}" | tr ' ' '\n' | grep -qx "sudo"; then
    run usermod -aG sudo "${ADMIN_USER}"
  fi

  local sudoers_file="/etc/sudoers.d/${ADMIN_USER}"
  if [[ "${PAAS}" == "dokploy" ]]; then
    # Dokploy privileged orchestration uses the dedicated root key over the
    # Tailscale address. Keep the named metadata account non-privileged and
    # non-login: root is the only SSH principal for this PaaS mode.
    if id -nG "${ADMIN_USER}" 2>/dev/null | tr ' ' '\n' | grep -qx "sudo"; then
      if is_true "${DRY_RUN}"; then
        log "DRY-RUN: would remove ${ADMIN_USER} from the sudo group"
      elif command -v gpasswd >/dev/null 2>&1; then
        run gpasswd -d "${ADMIN_USER}" sudo >/dev/null
      else
        run deluser "${ADMIN_USER}" sudo >/dev/null
      fi
    fi
    if is_true "${DRY_RUN}"; then
      log "DRY-RUN: would remove ${sudoers_file} (Dokploy root operations use Tailscale-only root SSH)"
    else
      run rm -f "${sudoers_file}"
      local sudo_state_rc
      if sudo_effective_grant_state "${ADMIN_USER}"; then
        die "Dokploy admin ${ADMIN_USER} retains an effective sudo grant; refusing non-privileged setup."
      else
        sudo_state_rc=$?
        (( sudo_state_rc == 1 )) || die "Unable to prove that Dokploy admin ${ADMIN_USER} has no effective sudo grant; refusing setup."
      fi
      run usermod -s /usr/sbin/nologin "${ADMIN_USER}"
      passwd -l "${ADMIN_USER}" >/dev/null 2>&1 || true
    fi
  else
    # Configure passwordless sudo for non-Dokploy workflows. Those legacy
    # orchestrators still execute remote scripts through admin@TS_IP sudo;
    # Dokploy uses the root Tailscale transport above instead.
    if is_true "${DRY_RUN}"; then
      log "DRY-RUN: would create ${sudoers_file} with passwordless sudo for ${ADMIN_USER}"
    else
      cat > "${sudoers_file}" <<EOF
Defaults:${ADMIN_USER} timestamp_timeout=0
${ADMIN_USER} ALL=(ALL) NOPASSWD: ALL
EOF
      chmod 440 "${sudoers_file}"
      # Validate sudoers syntax before committing
      if ! visudo -c -f "${sudoers_file}" >/dev/null 2>&1; then
        rm -f "${sudoers_file}"
        die "Failed to create valid sudoers file for ${ADMIN_USER}"
      fi
      log "Configured passwordless sudo for ${ADMIN_USER}"
    fi
  fi

  if is_true "${DRY_RUN}" && [[ "${user_exists}" == "false" ]]; then
    # useradd is not executed in dry-run mode, so NSS cannot yet resolve the
    # account that would be created.
    home_dir="/home/${ADMIN_USER}"
  else
    home_dir="$(getent passwd "${ADMIN_USER}" | cut -d: -f6)"
  fi
  [[ -n "${home_dir}" ]] || die "Unable to resolve home directory for ${ADMIN_USER}."

  if [[ "${PAAS}" == "dokploy" ]]; then
    if is_true "${DRY_RUN}"; then
      log "DRY-RUN: would disable SSH login for ${ADMIN_USER} and remove its authorized_keys."
    else
      local admin_ssh_dir="${home_dir}/.ssh"
      local admin_auth_file="${admin_ssh_dir}/authorized_keys"
      if [[ -L "${home_dir}" || ! -d "${home_dir}" ]]; then
        die "Dokploy metadata account home is missing or unsafe: ${home_dir}"
      fi
      if [[ -L "${admin_ssh_dir}" || ( -e "${admin_ssh_dir}" && ! -d "${admin_ssh_dir}" ) ]]; then
        die "Dokploy metadata account SSH directory is unsafe: ${admin_ssh_dir}"
      fi
      if [[ -e "${admin_auth_file}" || -L "${admin_auth_file}" ]]; then
        if [[ -L "${admin_auth_file}" || -f "${admin_auth_file}" ]]; then
          rm -f -- "${admin_auth_file}"
        else
          die "Dokploy metadata account authorized_keys is an unsupported file type: ${admin_auth_file}"
        fi
      fi
      log "Disabled SSH login for Dokploy metadata account ${ADMIN_USER}."
    fi
  elif is_true "${DRY_RUN}" && [[ "${user_exists}" == "false" ]]; then
    log "DRY-RUN: would create /home/${ADMIN_USER}/.ssh/authorized_keys with provided key."
  elif is_true "${DRY_RUN}"; then
    log "DRY-RUN: ensure ${home_dir}/.ssh/authorized_keys contains provided key."
  else
    install_admin_authorized_keys_no_follow "${home_dir}" "${ADMIN_USER}" "${ADMIN_PUBKEY}" \
      || die "Unable to install administrator authorized_keys safely."
  fi

  # Lock root password — root login is blocked by sshd config but a set
  # password is still a credential that could be leveraged via console or
  # a misconfigured PAM rule.
  if ! is_true "${DRY_RUN}"; then
    local root_pw_status
    root_pw_status="$(passwd -S root 2>/dev/null | awk '{print $2}')"
    if [[ "${root_pw_status}" == "P" ]]; then
      passwd -l root >/dev/null 2>&1
      log "Root password locked."
    fi
  else
    log "DRY-RUN: would lock root password."
  fi

  # Dokploy operators may need emergency root access, but only through the
  # Tailscale-only SSH listener and the key supplied for this deployment. Keep
  # exactly that key; never preserve provider-injected root credentials.
  if [[ "${PAAS}" == "dokploy" ]]; then
    if is_true "${DRY_RUN}"; then
      log "DRY-RUN: would install the admin public key as the sole root authorized key for Tailscale-only Dokploy access."
    else
      [[ -n "${ADMIN_PUBKEY}" ]] || die "Dokploy root Tailscale policy requires a non-empty admin public key."
      if [[ -L /root/.ssh || ( -e /root/.ssh && ! -d /root/.ssh ) ]]; then
        die "Root SSH directory is a symlink or unexpected file: /root/.ssh"
      fi
      install -d -m 0700 -o root -g root /root/.ssh
      local root_auth_file=/root/.ssh/authorized_keys
      if [[ -L "${root_auth_file}" || ( -e "${root_auth_file}" && ! -f "${root_auth_file}" ) ]]; then
        die "Root authorized_keys is a symlink or unexpected file: ${root_auth_file}"
      fi
      local root_auth_tmp
      root_auth_tmp="$(mktemp /root/.ssh/.authorized_keys.XXXXXX)" \
        || die "Unable to stage root authorized_keys safely."
      printf '%s\n' "${ADMIN_PUBKEY}" > "${root_auth_tmp}"
      chown root:root "${root_auth_tmp}"
      chmod 0600 "${root_auth_tmp}"
      mv -f "${root_auth_tmp}" "${root_auth_file}" \
        || { rm -f "${root_auth_tmp}"; die "Unable to install root authorized_keys atomically."; }
      chown root:root "${root_auth_file}"
      chmod 0600 "${root_auth_file}"
      log "Installed the admin public key as the sole root key for Tailscale-only Dokploy access."
    fi
  elif ! is_true "${DRY_RUN}"; then
    # Clear root authorized_keys — provisioning systems often inject keys
    # into /root/.ssh/authorized_keys that are unrelated to the admin user.
    if [[ -L /root/.ssh || ( -e /root/.ssh && ! -d /root/.ssh ) ]]; then
      die "Root SSH directory is a symlink or unexpected file: /root/.ssh"
    fi
    if [[ -f /root/.ssh/authorized_keys ]] && [[ -s /root/.ssh/authorized_keys ]]; then
      if [[ -L /root/.ssh/authorized_keys ]]; then
        die "Root authorized_keys is a symlink: /root/.ssh/authorized_keys"
      fi
      : > /root/.ssh/authorized_keys
      log "Cleared root authorized_keys."
    fi
  else
    log "DRY-RUN: would clear root authorized_keys."
  fi
}

restore_ssh_dropin() {
  local backup="$1"
  if is_true "${DRY_RUN}"; then
    return 0
  fi
  if [[ -n "${backup}" && -f "${backup}" ]]; then
    cp -a "${backup}" "${SSH_DROPIN_FILE}"
  else
    rm -f "${SSH_DROPIN_FILE}"
  fi
}

assert_sshd_effective() {
  local effective="$1"

  grep -qE "^port ${SSH_PORT}$" <<< "${effective}" || return 1
  grep -q "^permitrootlogin no$" <<< "${effective}" || return 1
  grep -q "^passwordauthentication no$" <<< "${effective}" || return 1
  grep -q "^kbdinteractiveauthentication no$" <<< "${effective}" || return 1
  grep -q "^pubkeyauthentication yes$" <<< "${effective}" || return 1
  grep -q "^authenticationmethods publickey$" <<< "${effective}" || return 1
  if [[ "${PAAS}" == "dokploy" ]]; then
    grep -qE '^allowusers .*\broot\b' <<< "${effective}" || return 1
    ! grep -qE "^allowusers .*\\b${ADMIN_USER}\\b" <<< "${effective}" || return 1
  else
    grep -qE "^allowusers .*\\b${ADMIN_USER}\\b" <<< "${effective}" || return 1
  fi
  grep -q "^permitemptypasswords no$" <<< "${effective}" || return 1
  grep -q "^compression no$" <<< "${effective}" || return 1
  grep -q "chacha20-poly1305@openssh.com" <<< "${effective}" || return 1
  grep -q "hmac-sha2-512-etm@openssh.com" <<< "${effective}" || return 1
  grep -q "sntrup761x25519-sha512@openssh.com" <<< "${effective}" || return 1
  grep -q "hostkeyalgorithms .*ssh-ed25519" <<< "${effective}" || return 1
}

assert_sshd_match_localhost() {
  local effective="$1"

  # OpenSSH outputs "prohibit-password" or its legacy synonym "without-password"
  grep -qE "^permitrootlogin (prohibit-password|without-password)$" <<< "${effective}" || return 1
  grep -qE "^allowusers .*\\broot\\b" <<< "${effective}" || return 1
  grep -qE "^allowusers .*\\b${ADMIN_USER}\\b" <<< "${effective}" || return 1
}

assert_sshd_match_tailscale() {
  local effective="$1"

  # OpenSSH outputs "prohibit-password" or its legacy synonym "without-password".
  grep -qE "^permitrootlogin (prohibit-password|without-password)$" <<< "${effective}" || return 1
  grep -qE "^allowusers .*\\broot\\b" <<< "${effective}" || return 1
  ! grep -qE "^allowusers .*\\b${ADMIN_USER}\\b" <<< "${effective}" || return 1
  grep -q "^passwordauthentication no$" <<< "${effective}" || return 1
  grep -q "^kbdinteractiveauthentication no$" <<< "${effective}" || return 1
  grep -q "^authenticationmethods publickey$" <<< "${effective}" || return 1
}

reload_ssh_service() {
  local units
  local has_ssh="false"
  local has_sshd="false"

  if ! systemctl list-unit-files --type=service --no-legend >/dev/null 2>&1; then
    return 1
  fi

  units="$(systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '{print $1}')"
  grep -qx "ssh.service" <<< "${units}" && has_ssh="true" || true
  grep -qx "sshd.service" <<< "${units}" && has_sshd="true" || true

  if [[ "${has_ssh}" == "true" ]]; then
    if ! systemctl is-active --quiet ssh; then
      systemctl start ssh || return 1
    fi
    systemctl reload ssh || systemctl restart ssh || return 1
    return 0
  fi

  if [[ "${has_sshd}" == "true" ]]; then
    if ! systemctl is-active --quiet sshd; then
      systemctl start sshd || return 1
    fi
    systemctl reload sshd || systemctl restart sshd || return 1
    return 0
  fi

  return 1
}

unit_available() {
  local unit_name="$1"
  command -v systemctl >/dev/null 2>&1 || return 1
  local load_state
  load_state="$(systemctl show --property=LoadState --value "${unit_name}" 2>/dev/null || true)"
  [[ -n "${load_state}" && "${load_state}" != "not-found" ]]
}

ifupdown_is_authoritative() {
  unit_available "networking.service" || return 1

  local path
  for path in /etc/network/interfaces /etc/network/interfaces.d/*; do
    [[ -f "${path}" ]] || continue
    if awk '
      /^[[:space:]]*#/ { next }
      /^[[:space:]]*iface[[:space:]]+/ {
        if ($2 != "lo") {
          found=1
          exit
        }
      }
      END { exit(found ? 0 : 1) }
    ' "${path}"; then
      return 0
    fi
  done

  return 1
}

configure_ssh() {
  local backup=""
  local effective=""
  local match_addresses="${TAILSCALE_CIDR:-100.64.0.0/10}"
  if [[ "${PAAS}" == "coolify" ]]; then
    local docker_match_addresses=""
    if declare -p DOCKER_SSH_CIDRS >/dev/null 2>&1 && (( ${#DOCKER_SSH_CIDRS[@]} > 0 )); then
      docker_match_addresses="$(IFS=,; printf '%s' "${DOCKER_SSH_CIDRS[*]}")"
    else
      docker_match_addresses="10.0.0.0/8,172.16.0.0/12"
    fi
    # Coolify's container-to-host SSH path is intentionally localhost plus
    # discovered Docker bridges.  The old implementation used only the
    # Tailscale CIDR, so its own localhost assertion validated a carve-out that
    # the generated sshd config never actually installed.
    match_addresses="127.0.0.1,::1,${docker_match_addresses}"
  fi

  if ! is_true "${DRY_RUN}" && [[ ! -d /run/sshd ]]; then
    install -d -m 0755 /run/sshd
  fi

  if [[ -f "${SSH_DROPIN_FILE}" ]] && ! is_true "${DRY_RUN}"; then
    backup="${SSH_DROPIN_FILE}.bak.$(date +%s)"
    cp -a "${SSH_DROPIN_FILE}" "${backup}"
  fi

  # Fix base sshd_config to not rely solely on drop-in overrides
  local base_config="/etc/ssh/sshd_config"
  if [[ -f "${base_config}" ]] && ! is_true "${DRY_RUN}"; then
    sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' "${base_config}"
    sed -i 's/^X11Forwarding yes/X11Forwarding no/' "${base_config}"
    log "Hardened base sshd_config (PermitRootLogin no, X11Forwarding no)."
  elif [[ -f "${base_config}" ]]; then
    log "DRY-RUN: would harden base sshd_config (PermitRootLogin no, X11Forwarding no)."
  fi

  # Neutralize cloud-init override that re-enables password auth
  local cloud_init_ssh="/etc/ssh/sshd_config.d/50-cloud-init.conf"
  local cloud_init_cfg="/etc/cloud/cloud.cfg.d/99-disable-ssh-password.cfg"
  if ! is_true "${DRY_RUN}"; then
    if [[ -f "${cloud_init_ssh}" ]]; then
      echo "PasswordAuthentication no" > "${cloud_init_ssh}"
      chmod 0644 "${cloud_init_ssh}"
      log "Neutralized ${cloud_init_ssh} (set PasswordAuthentication no)."
    fi
    mkdir -p "$(dirname "${cloud_init_cfg}")"
    echo "ssh_pwauth: false" > "${cloud_init_cfg}"
    log "Prevented cloud-init from re-enabling SSH password auth."
  else
    log "DRY-RUN: would neutralize cloud-init SSH password auth override."
  fi

  local match_block=""
  local global_allow_users="${ADMIN_USER}"
  if [[ "${PAAS}" == "coolify" ]]; then
    # Coolify connects to its own host as root via localhost / Docker bridge.
    # Compatibility mode uses broad RFC1918 ranges; strict mode uses discovered
    # Docker bridge CIDRs with safe fallback if discovery fails.
    # Other PaaS (dFlow, Dokploy) never SSH from containers to the host, so
    # they get no root Match carve-out at all.
    match_block="
# Coolify connects to its own host as root via localhost / Docker bridge.
# Compatibility mode uses broad RFC1918 ranges; strict mode uses discovered
# Docker bridge CIDRs with safe fallback if discovery fails.
Match Address ${match_addresses}
    PermitRootLogin prohibit-password
    AllowUsers ${ADMIN_USER} root"
  elif [[ "${PAAS}" == "dokploy" ]]; then
    # Dokploy does not need host SSH from containers, but the operator wants
    # an emergency root path. Permit root key auth only from the Tailscale
    # source range; the socket binding and UFW both keep WAN SSH closed.
    match_block="
# Dokploy root emergency access is Tailscale-only and key-only.
Match Address ${match_addresses}
    PermitRootLogin prohibit-password
    AllowUsers root"
    global_allow_users="root"
  fi

  write_file "${SSH_DROPIN_FILE}" "0644" "root" "root" <<EOF
# Managed by ${SCRIPT_NAME}
Port ${SSH_PORT}
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
AllowUsers ${global_allow_users}
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
Compression no
MaxAuthTries 3
MaxSessions 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
PerSourceMaxStartups 3
Ciphers ^chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs ^hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
KexAlgorithms ^sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org
HostKeyAlgorithms ^ssh-ed25519,rsa-sha2-512,rsa-sha2-256
Banner /etc/issue.net
${match_block}
EOF

  if is_true "${DRY_RUN}"; then
    return 0
  fi

  # Safety: normalize duplicate '^' operators if a partial manual edit occurred.
  if [[ -f "${SSH_DROPIN_FILE}" ]]; then
    sed -i -E \
      -e 's/^Ciphers \^+/Ciphers ^/' \
      -e 's/^MACs \^+/MACs ^/' \
      -e 's/^KexAlgorithms \^+/KexAlgorithms ^/' \
      -e 's/^HostKeyAlgorithms \^+/HostKeyAlgorithms ^/' \
      "${SSH_DROPIN_FILE}"
  fi

  # Migration: non-Coolify hosts must not keep the Docker-bridge root Match
  # dropin from an earlier Coolify-era run (docker-ssh-cidr-sync layout).
  if [[ "${PAAS}" != "coolify" && -f /etc/ssh/sshd_config.d/15-docker-ssh-match.conf ]]; then
    rm -f /etc/ssh/sshd_config.d/15-docker-ssh-match.conf
    log "Removed stale Docker-bridge SSH match dropin (not used for PAAS=${PAAS})."
  fi

  if ! sshd -t; then
    restore_ssh_dropin "${backup}"
    die "sshd -t failed after writing SSH hardening drop-in."
  fi

  effective="$(sshd -T 2>/dev/null || true)"
  if ! assert_sshd_effective "${effective}"; then
    restore_ssh_dropin "${backup}"
    die "sshd -T did not match expected hardened values."
  fi

  local match_effective
  match_effective="$(sshd -T -C addr=127.0.0.1,user=root,host=localhost,laddr=127.0.0.1 2>/dev/null || true)"
  if [[ "${PAAS}" == "coolify" ]]; then
    if ! assert_sshd_match_localhost "${match_effective}"; then
      restore_ssh_dropin "${backup}"
      die "sshd -T -C (localhost Match block) did not match expected values."
    fi
  elif [[ "${PAAS}" == "dokploy" ]]; then
    local tailscale_probe_ip="${DETECTED_TAILSCALE_IP:-}"
    if [[ -z "${tailscale_probe_ip}" ]] && command -v tailscale >/dev/null 2>&1; then
      tailscale_probe_ip="$(tailscale ip -4 2>/dev/null || true)"
    fi
    local match_tailscale
    match_tailscale="$(sshd -T -C "addr=${tailscale_probe_ip:-100.64.0.1},user=root,host=localhost,laddr=${tailscale_probe_ip:-100.64.0.1}" 2>/dev/null || true)"
    if ! assert_sshd_match_tailscale "${match_tailscale}"; then
      restore_ssh_dropin "${backup}"
      die "sshd -T -C (Tailscale Match block) did not match expected root-only-over-Tailscale values."
    fi
  else
    # dFlow and other non-Coolify/Dokploy PaaS must NOT allow root from localhost/bridges.
    if grep -qE "^permitrootlogin (prohibit-password|without-password|yes)$" <<< "${match_effective}"; then
      restore_ssh_dropin "${backup}"
      die "sshd -T -C (localhost) still permits root login — root Match carve-out must not exist for PAAS=${PAAS}."
    fi
  fi

  if ! reload_ssh_service; then
    restore_ssh_dropin "${backup}"
    die "Failed to reload SSH service."
  fi

  rm -f "${SSH_DROPIN_FILE}".bak.*

  # Migration: remove old combined dropin if present (pre-C3 layout)
  local old_dropin="/etc/ssh/sshd_config.d/00-coolify-hardening.conf"
  if [[ -f "${old_dropin}" && "${old_dropin}" != "${SSH_DROPIN_FILE}" ]]; then
    rm -f "${old_dropin}"
    log "Removed legacy SSH dropin ${old_dropin} (replaced by ${SSH_DROPIN_FILE})."
  fi

  # Remove weak DSA host key — deprecated in OpenSSH 7.0+, not negotiated
  # by our HostKeyAlgorithms list, but the key file should not exist.
  if [[ -f /etc/ssh/ssh_host_dsa_key ]] && ! is_true "${DRY_RUN}"; then
    rm -f /etc/ssh/ssh_host_dsa_key /etc/ssh/ssh_host_dsa_key.pub
    log "Removed deprecated DSA host key."
  elif [[ -f /etc/ssh/ssh_host_dsa_key ]]; then
    log "DRY-RUN: would remove deprecated DSA host key."
  fi
}
