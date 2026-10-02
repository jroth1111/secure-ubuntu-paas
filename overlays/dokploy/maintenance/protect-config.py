#!/usr/bin/env python3
"""Close the permission window for all app deployment logs, without reading them."""
import os,pathlib,stat
for folder in ['/etc/dokploy/logs','/etc/dokploy/compose','/etc/dokploy/paas-hardening']:
    root=pathlib.Path(folder)
    if not root.exists():continue
    if root.is_symlink() or not root.is_dir():raise SystemExit('Unsafe config root')
    for path in [root,*root.rglob('*')]:
        s=path.lstat()
        if stat.S_ISLNK(s.st_mode):raise SystemExit('Config symlink refused')
        if not (stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode)):raise SystemExit('Unexpected config file type')
        mode=0o700 if stat.S_ISDIR(s.st_mode) else 0o600
        if s.st_uid!=0 or s.st_gid!=0:os.chown(path,0,0,follow_symlinks=False)
        if stat.S_IMODE(s.st_mode)!=mode:os.chmod(path,mode,follow_symlinks=False)
