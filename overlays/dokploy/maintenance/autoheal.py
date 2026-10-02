#!/usr/bin/env python3
"""Bounded recovery of the managed runtime; never deletes data or reboots."""
import fcntl, json, os, pathlib, re, subprocess, tempfile, time

os.umask(0o077)
ROOT = pathlib.Path('/var/lib/server-hardening/recovery')


def permitted(history, now):
    recent = [stamp for stamp in history if now - 86400 < stamp <= now]
    return len(recent) < 3 and (not recent or now - max(recent) >= 1800)


def output(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.DEVNULL, timeout=30).strip()


def main():
    subprocess.run(['python3', '/usr/local/sbin/paas-recovery-policy'], check=True, timeout=10)
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    locks = []
    for name in ('paas-autoheal', 'dokploy-auto-update', 'hermes-auto-update', 'controlplane-backup'):
        handle = open('/run/lock/' + name + '.lock', 'a')
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('Recovery deferred while an update/backup owns its lock')
            return
        locks.append(handle)
    if subprocess.run(['systemctl', 'is-active', '--quiet', 'apt-daily-upgrade.service']).returncode == 0:
        print('Recovery deferred during host package maintenance')
        return
    path = ROOT / 'health.json'
    state = json.loads(path.read_text()) if path.exists() else {'failures': {}, 'restarts': {}}
    now = int(time.time())
    actions = []

    def recover(name, healthy, command):
        failures = state['failures'][name] = 0 if healthy else state['failures'].get(name, 0) + 1
        history = state['restarts'].setdefault(name, [])
        state['restarts'][name] = history = [stamp for stamp in history if now - 86400 < stamp <= now]
        if failures < 3 or not permitted(history, now):
            return False
        # Persist an attempt before executing so a timeout cannot create a loop.
        history.append(now)
        save()
        subprocess.run(command, check=True, timeout=180, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        actions.append(name)
        state['failures'][name] = 0
        return True

    def save():
        state['checkedAt'] = now
        fd, temporary = tempfile.mkstemp(prefix='.health-', dir=ROOT)
        with os.fdopen(fd, 'w') as handle:
            json.dump(state, handle); handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, path)

    try:
        try:
            swarm = output('docker', 'info', '--format', '{{.Swarm.LocalNodeState}}')
            docker_ok = True
        except (subprocess.SubprocessError, OSError):
            docker_ok = False
            swarm = 'unavailable'
        state['swarmState'] = swarm
        restarted = recover('docker', docker_ok, ['systemctl', 'restart', 'docker.service'])
        if docker_ok and not restarted:
            config = pathlib.Path('/etc/dokploy/hermes-updater/config.json')
            if config.exists():
                import stat
                metadata = config.lstat()
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
                    raise RuntimeError('Unsafe scoped Hermes config')
                project = json.loads(config.read_text()).get('appName', '')
                if not re.fullmatch(r'[A-Za-z0-9_-]+', project):
                    raise RuntimeError('Invalid scoped Hermes project')
                ids = output('docker', 'ps', '-aq', '--filter', 'label=com.docker.compose.project=' + project,
                    '--filter', 'label=com.docker.compose.service=hermes').split()
                if len(ids) == 1:
                    status = output('docker', 'inspect', '--format',
                        '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}', ids[0])
                    # A stopped container may reflect an intentional operator stop.
                    recover('hermes', status != 'running unhealthy', ['docker', 'restart', ids[0]])
            for unit in ('docker-user-hardening.service', 'dokploy-tailnet-input-hardening.service',
                         'hermes-permissions.service', 'paas-config-permissions.service'):
                failed = subprocess.run(['systemctl', 'is-failed', '--quiet', unit]).returncode == 0
                recover(unit, not failed, ['systemctl', 'restart', unit])
        state['actions'] = actions
        state.pop('errorType', None)
    except Exception as error:
        state['errorType'] = type(error).__name__
        raise
    finally:
        save()
    print(json.dumps({'checkedAt': now, 'actions': actions, 'swarmState': swarm}))


if __name__ == '__main__':
    main()
