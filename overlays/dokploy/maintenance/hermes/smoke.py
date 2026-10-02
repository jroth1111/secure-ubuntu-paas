import importlib, sqlite3, subprocess
from importlib.metadata import version
for name in ['jwt','anyio','httpcore2','httpx2','urllib3','tornado','msal','cryptography','hermes_cli.main','tools.mcp_tool']:
    importlib.import_module(name)
assert tuple(map(int,sqlite3.sqlite_version.split('.'))) >= (3,53,4)
db=sqlite3.connect(':memory:')
db.execute('create table security_probe(value text)')
db.execute("insert into security_probe values ('ok')")
assert db.execute('pragma integrity_check').fetchone()[0]=='ok'
subprocess.run(['/opt/hermes/.venv/bin/hermes','--version'],check=True,timeout=60)
print('Hermes import, CLI, and SQLite security smoke tests passed')
