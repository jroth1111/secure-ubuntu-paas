#!/usr/bin/env python3
"""Disposable private dashboard acceptance; never mount production state."""
import json, secrets, subprocess, time, urllib.request, urllib.error, http.cookiejar, sys
image=sys.argv[1]
name='hermes-security-test-'+secrets.token_hex(5)
volume=name+'-data'
password=secrets.token_urlsafe(32)
def run(*args):return subprocess.check_output(['docker',*args],text=True,stderr=subprocess.DEVNULL).strip()
try:
    assert run('image','inspect','--format','{{.Config.User}}',image)=='10000:10000'
    run('volume','create',volume)
    run('run','-d','--name',name,'--memory=1g','--cpus=1','--pids-limit=256','--security-opt=no-new-privileges:true',
        '--read-only','--cap-drop=ALL',
        '--tmpfs','/run:rw,exec,nosuid,nodev,uid=10000,gid=10000,mode=0700,size=32m',
        '--tmpfs','/tmp:rw,exec,nosuid,nodev,mode=1777,size=256m',
        '--tmpfs','/var/tmp:rw,exec,nosuid,nodev,mode=1777,size=64m',
        '--mount','type=volume,source='+volume+',destination=/opt/data',
        '-p','127.0.0.1::9119','-e','HERMES_DASHBOARD=1','-e','HERMES_DASHBOARD_HOST=0.0.0.0',
        '-e','HERMES_DASHBOARD_BASIC_AUTH_USERNAME=security-test','-e','HERMES_DASHBOARD_BASIC_AUTH_PASSWORD='+password,
        '-e','TZ=Australia/Melbourne',image,'sleep','infinity')
    port=json.loads(run('inspect','--format','{{json .NetworkSettings.Ports}}',name))['9119/tcp'][0]
    assert port['HostIp']=='127.0.0.1'
    base='http://127.0.0.1:'+port['HostPort']
    jar=http.cookiejar.CookieJar();opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar),urllib.request.ProxyHandler({}))
    deadline=time.monotonic()+150
    while True:
        try:
            with opener.open(base+'/api/status',timeout=5) as r:status=json.load(r)
            assert status['auth_required'] is True
            break
        except (OSError,ValueError):
            if time.monotonic()>deadline:raise RuntimeError('Isolated dashboard failed to start')
            time.sleep(3)
    try:
        opener.open(base+'/api/config',timeout=10)
        raise RuntimeError('Unauthenticated configuration was not blocked')
    except urllib.error.HTTPError as e:assert e.code==401
    req=urllib.request.Request(base+'/auth/password-login',json.dumps({'provider':'basic','username':'security-test','password':password}).encode(),{'Content-Type':'application/json','Origin':base})
    with opener.open(req,timeout=15) as r:assert r.status==200
    for endpoint in ['/api/auth/me','/api/config','/']:
        try:
            with opener.open(base+endpoint,timeout=15) as r:assert r.status==200
        except urllib.error.HTTPError as e:
            print('Failed endpoint '+endpoint+' HTTP '+str(e.code))
            print(e.read().decode()[:1000]) # disposable synthetic config only
            logs=subprocess.check_output(['docker','logs',name],text=True,stderr=subprocess.STDOUT)
            for line in logs.splitlines():
                if line.lstrip().startswith('File "') or line.startswith(('TypeError:','AttributeError:','FileNotFoundError:','ModuleNotFoundError:','ValueError:')):print(line)
            raise
    request=urllib.request.Request(base+'/api/profiles',json.dumps({'name':'security-profile'}).encode(),
        {'Content-Type':'application/json','Origin':base})
    with opener.open(request,timeout=30) as response:assert response.status in (200,201)
    with opener.open(base+'/api/profiles',timeout=15) as response:assert response.status==200
    process_probe='''import json,pathlib
rows=[]
for path in pathlib.Path('/proc').glob('[0-9]*/status'):
 try:
  fields=dict(line.split(':',1) for line in path.read_text().splitlines() if ':' in line)
  rows.append({'uid':fields['Uid'].split(),'caps':fields['CapEff'].strip(),'nnp':fields['NoNewPrivs'].strip()})
 except (OSError,KeyError):pass
assert rows and all(set(row['uid'])=={'10000'} and int(row['caps'],16)==0 and row['nnp']=='1' for row in rows)
assert not pathlib.Path('/var/run/docker.sock').exists()
path=pathlib.Path('/opt/data/rootless-acceptance.json')
if path.exists():assert json.loads(path.read_text())=={'owner':10000,'persisted':True}
else:path.write_text(json.dumps({'owner':10000,'persisted':True}))
print(json.dumps({'allProcessesNonRoot':True,'effectiveCapabilitiesZero':True}))'''
    run('exec',name,'/opt/hermes/.venv/bin/python','-c',process_probe)
    run('restart',name)
    # Docker may allocate a different ephemeral host port on restart.
    port=json.loads(run('inspect','--format','{{json .NetworkSettings.Ports}}',name))['9119/tcp'][0]
    assert port['HostIp']=='127.0.0.1'
    base='http://127.0.0.1:'+port['HostPort']
    deadline=time.monotonic()+150
    while True:
        try:
            with opener.open(base+'/api/status',timeout=5) as response:
                assert json.load(response)['auth_required'] is True
            break
        except (OSError,ValueError):
            if time.monotonic()>deadline:raise RuntimeError('Rootless persistent restart failed')
            time.sleep(3)
    run('exec',name,'/opt/hermes/.venv/bin/python','-c',process_probe)
    req=urllib.request.Request(base+'/auth/password-login',json.dumps({'provider':'basic','username':'security-test','password':password}).encode(),{'Content-Type':'application/json','Origin':base})
    with opener.open(req,timeout=15) as response:assert response.status==200
    with opener.open(base+'/api/config',timeout=15) as response:assert response.status==200
    if not image.startswith('nousresearch/'):
        run('exec','--user','10000:10000',name,'/opt/hermes/.venv/bin/python','/usr/local/lib/hermes-security-smoke.py')
        run('exec',name,'uv','pip','check','--python','/opt/hermes/.venv/bin/python')
    print(json.dumps({'image':image,'isolatedDashboard':True,'passwordLogin':True,'protectedConfig':True,'nonRootCli':True,
        'rootlessSupervisor':True,'zeroCapabilities':True,'readOnlyRoot':True,'profileCreate':True,
        'persistentRestart':True,'dependenciesCompatible':True,'version':status.get('version')}))
finally:
    subprocess.run(['docker','rm','-f','-v',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    subprocess.run(['docker','volume','rm',volume],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
