#!/usr/bin/env python3
import json,pathlib,re,stat,subprocess,sys
component,image=sys.argv[1:3]
try:
    if component not in ('dokploy','postgres'):raise ValueError()
    if not re.fullmatch('local/paas-'+component+r'-hardened:sha-[a-f0-9]{64}',image):raise ValueError()
    path=pathlib.Path('/var/lib/server-hardening/paas-images')/(component+'.json');s=path.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or stat.S_IMODE(s.st_mode)!=0o600:raise ValueError()
    data=json.loads(path.read_text());prefix='dokploy/dokploy:latest@' if component=='dokploy' else 'postgres:16@'
    if data['image']!=image or data.get('isolatedTestsPassed') is not True or not re.fullmatch(re.escape(prefix)+r'sha256:[a-f0-9]{64}',data['base']):raise ValueError()
    if data['imageId']!='sha256:'+image.split(':sha-')[1]:raise ValueError()
    if component=='dokploy' and not re.fullmatch(r'[a-f0-9]{40}',data['sourceCommit']):raise ValueError()
    actual=subprocess.check_output(['docker','image','inspect','--format','{{.Id}} {{index .Config.Labels "org.opencontainers.image.base.name"}}',image],text=True,stderr=subprocess.DEVNULL).strip()
    if actual!=data['imageId']+' '+data['base']:raise ValueError()
    print(data['base'])
except Exception:sys.exit(1)
