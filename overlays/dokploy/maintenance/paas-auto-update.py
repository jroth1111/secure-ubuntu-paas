#!/usr/bin/env python3
"""Approved latest-source derivatives, encrypted recovery, and verified rollout."""
import fcntl,json,os,pathlib,re,stat,subprocess,tempfile,time,urllib.request,urllib.error,sys
os.umask(0o077)
root=pathlib.Path('/var/lib/server-hardening/paas-images');root.mkdir(mode=0o700,parents=True,exist_ok=True)
try:inherited=os.readlink('/proc/self/fd/9')=='/run/lock/dokploy-auto-update.lock'
except OSError:inherited=False
if not inherited:lock=open('/run/lock/dokploy-auto-update.lock','w');fcntl.flock(lock,fcntl.LOCK_EX)
state={'checkedAt':int(time.time()),'status':'checking'};changed=[];previous={}
def output(*args):return subprocess.check_output(args,text=True,stderr=subprocess.DEVNULL).strip()
def call(*args,**kwargs):return subprocess.run(args,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,**kwargs)
def atomic(path,data):
    fd,name=tempfile.mkstemp(prefix='.receipt-',dir=path.parent)
    with os.fdopen(fd,'w') as f:f.write(data);f.flush();os.fsync(f.fileno())
    os.replace(name,path)
def save():atomic(root/'update-state.json',json.dumps(state)+'\n')
def private(path):
    s=path.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or stat.S_IMODE(s.st_mode)!=0o600:raise RuntimeError('Unsafe protected configuration')
    return json.loads(path.read_text())
def official(channel):
    call('docker','pull','-q',channel)
    repo=channel.split(':')[0]
    refs=output('docker','image','inspect','--format','{{range .RepoDigests}}{{println .}}{{end}}',channel).splitlines()
    for ref in refs:
        if ref.split('@')[0]==repo and re.fullmatch(r'sha256:[a-f0-9]{64}',ref.split('@')[-1]):return channel+'@'+ref.split('@')[-1]
    raise RuntimeError('Official channel digest missing')
def live(service):return output('docker','service','inspect','--format','{{.Spec.TaskTemplate.ContainerSpec.Image}}',service)
def container(service):
    ids=output('docker','ps','-q','--filter','label=com.docker.swarm.service.name='+service).split()
    return ids[0] if len(ids)==1 else None
def ready(service,image,seconds=240):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        cid=container(service)
        if cid and live(service)==image:
            actual=output('docker','inspect','--format','{{.Image}}',cid)
            if ':sha-' in image and actual!='sha256:'+image.split(':sha-')[1]:raise RuntimeError('Live image identity mismatch')
            if service=='dokploy-postgres':
                if subprocess.run(['docker','exec',cid,'pg_isready','-U','dokploy','-d','dokploy'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:return True
            elif service=='dokploy':
                if output('docker','inspect','--format','{{if .State.Health}}{{.State.Health.Status}}{{end}}',cid)=='healthy':return True
            else:
                try:
                    req=urllib.request.Request('http://127.0.0.1:80',headers={'Host':'dokploy.docker.localhost'})
                    urllib.request.urlopen(req,timeout=5)
                except urllib.error.HTTPError as e:
                    if e.code==403:return True
                except OSError:pass
        time.sleep(5)
    return False
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise RuntimeError('Credential redirect refused')
def api_acceptance():
    config=private(pathlib.Path('/etc/dokploy/paas-hardening/api.json'))
    opener=urllib.request.build_opener(NoRedirect(),urllib.request.ProxyHandler({}))
    for endpoint in ['user.get','project.all']:
        req=urllib.request.Request('http://127.0.0.1:3000/api/trpc/'+endpoint,headers={'x-api-key':config['token']})
        with opener.open(req,timeout=20) as r:assert 'result' in json.load(r)
    try:
        opener.open('http://127.0.0.1:3000/api/trpc/project.all',timeout=10)
        raise RuntimeError('Protected API lost authentication')
    except urllib.error.HTTPError as e:assert e.code in (401,403)
try:
    policy=private(pathlib.Path('/etc/dokploy/security-image-policy.json'))
    if policy!={'dokploy':'tested-source-latest','postgresMajor':16,'briefApplicationRestartsApproved':True}:raise RuntimeError('Image policy changed')
    bases={'postgres':official('postgres:16'),'dokploy':official('dokploy/dokploy:latest')}
    targets={};provenance={}
    for component in ['postgres','dokploy']:
        build=json.loads(output('/usr/local/sbin/paas-build-image',component,bases[component]))
        if build.get('base')!=bases[component] or build.get('isolatedTestsPassed') is not True or not re.fullmatch('local/paas-'+component+r'-hardened:sha-[a-f0-9]{64}',build.get('image','')):raise RuntimeError('Tested derivative provenance missing')
        targets['dokploy-postgres' if component=='postgres' else 'dokploy']=build['image'];provenance[component]=build
    proxy=official('traefik:v3.7')
    version=output('docker','run','--rm','--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges:true','--entrypoint','traefik',proxy,'version')
    match=re.search(r'Version:\s*(3\.7\.(\d+))',version)
    if not match or int(match[2])<13:raise RuntimeError('Proxy channel security floor failed')
    targets['dokploy-traefik']=proxy
    # A paired restore/API drill must pass before either production service moves.
    call('python3','/usr/local/lib/paas-hardening/test-pair.py',targets['dokploy'],targets['dokploy-postgres'],timeout=360)
    full_backup=json.loads(output('/usr/local/sbin/controlplane-backup'))
    state['fullRecoveryBackup']=full_backup;state['builds']=provenance;save()
    # Keep the existing machine-readable encrypted SQL backup contract.
    backupdir=pathlib.Path('/var/lib/server-hardening/dokploy-backups');backupdir.mkdir(mode=0o700,exist_ok=True)
    backup=backupdir/('dokploy-'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())+'.sql.gz.age')
    pg=container('dokploy-postgres');assert pg
    recipient=pathlib.Path('/var/lib/server-hardening/backup-recipient').read_text().strip()
    fd,tmp=tempfile.mkstemp(prefix='.encrypted-',dir=backupdir)
    with os.fdopen(fd,'wb') as encrypted:
        dump=subprocess.Popen(['docker','exec',pg,'pg_dump','-U','dokploy','-d','dokploy','--no-owner','--no-acl'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        gzip=subprocess.Popen(['gzip','-c'],stdin=dump.stdout,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL);dump.stdout.close()
        age=subprocess.run(['age','-r',recipient],stdin=gzip.stdout,stdout=encrypted,stderr=subprocess.DEVNULL);gzip.stdout.close()
        if dump.wait()!=0 or gzip.wait()!=0 or age.returncode:raise RuntimeError('Encrypted database backup failed; no updates applied.')
    os.replace(tmp,backup);state['backup_file']=str(backup);save()
    previous={service:live(service) for service in targets};state['previousImages']=previous;save()
    for service,image in targets.items():
        if previous[service]!=image:
            changed.append(service)
            call('docker','service','update','--no-resolve-image','--image',image,'--update-order','stop-first','--update-failure-action','rollback','--detach=false','--quiet',service,timeout=300)
        if not ready(service,image):raise RuntimeError('Application rollout acceptance failed')
    api_acceptance()
    call('systemctl','restart','docker-user-hardening.service')
    call('systemctl','start','dokploy-tailnet-input-hardening.service')
    call('systemctl','start','hermes-permissions.service')
    call('systemctl','start','paas-config-permissions.service')
    now=int(time.time())
    fields={'last_check_epoch':now,'resolved_image':targets['dokploy'],'updated':str(bool(changed)).lower(),'traefik_resolved_image':proxy,'traefik_version':match[1],'postgres_resolved_image':targets['dokploy-postgres'],'backup_file':str(backup),'dokploy_official_base':bases['dokploy'],'postgres_official_base':bases['postgres']}
    atomic(pathlib.Path('/var/lib/server-hardening/dokploy-update-state'),''.join(str(k)+'='+str(v)+'\n' for k,v in fields.items()))
    state['status']='updated' if changed else 'no_change';state['verifiedAt']=now;state['currentImages']=targets;save()
    print('Tested Dokploy/PostgreSQL security derivatives and private authenticated boundary accepted; '+('application updates applied' if changed else 'no application restart'))
except Exception as error:
    state['status']='error';state['errorType']=type(error).__name__
    if changed:
        state['status']='rolled_back';state['rollbackVerified']=True
        for service in reversed(changed):
            try:
                call('docker','service','update','--no-resolve-image','--image',previous[service],'--detach=false','--quiet',service,timeout=300)
                state['rollbackVerified']=ready(service,previous[service],180) and state['rollbackVerified']
            except Exception:state['rollbackVerified']=False
        if not state['rollbackVerified']:state['status']='rollback_failed'
    save();print('PaaS patch not accepted; protected recovery receipt recorded',file=sys.stderr);sys.exit(1)
