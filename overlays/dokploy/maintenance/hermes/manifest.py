import json,subprocess
from importlib.metadata import distributions
packages=sorted((p.metadata['Name'],p.version) for p in distributions())
os_packages=subprocess.check_output(['dpkg-query','-W','-f=${Package}=${Version}\n'],text=True).splitlines()
print(json.dumps({'python':packages,'debian':sorted(os_packages),'uv':subprocess.check_output(['uv','--version'],text=True).strip()},sort_keys=True))
