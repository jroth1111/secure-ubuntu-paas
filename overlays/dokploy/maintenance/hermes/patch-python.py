"""Explicit downstream security constraint; regenerate metadata from this source."""
from pathlib import Path
import re, subprocess, sys
from importlib.metadata import version
from packaging.version import Version
fixes={'PyJWT':'2.15.1','anyio':'4.15.1','httpcore2':'2.13.0','httpx2':'2.13.0','urllib3':'2.8.0','tornado':'6.5.10','msal':'1.39.0','typing-extensions':'4.16.0'}
chosen={name:str(max(Version(version(name)),Version(fixed))) for name,fixed in fixes.items()}
path=Path('/opt/hermes/pyproject.toml')
source=path.read_text()
# Upstream's exact JWT pin predates the advisory fixes. Change the dependency
# declaration, not the installed dist-info or the dependency checker.
source=re.sub(r'(?i)([\"\']pyjwt\[crypto\])==[0-9.]+([\"\'])',lambda m:m[1]+'=='+chosen['PyJWT']+m[2],source)
path.write_text(source)
subprocess.run(['uv','pip','install','--python',sys.executable,*[name+'=='+fixed for name,fixed in chosen.items()]],check=True)
# Keep private configuration owner-only after the upstream boot hook runs.
# The enclosing /opt/data directory remains owned by the fixed runtime UID.
startup=Path('/opt/hermes/docker/stage2-hook.sh')
boot=startup.read_text()
old='chmod 640 "$HERMES_HOME/config.yaml"'
new='chmod 600 "$HERMES_HOME/config.yaml"'
if old not in boot and new not in boot:
    raise RuntimeError('Upstream configuration permission hook needs review')
startup.write_text(boot.replace(old,new))
