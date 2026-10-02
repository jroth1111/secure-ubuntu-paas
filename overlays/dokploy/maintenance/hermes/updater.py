#!/usr/bin/env python3
"""Scoped Dokploy-managed Hermes updates with encrypted backup and rollback."""
import json,re,time,urllib.request,urllib.parse,urllib.error,subprocess,pathlib,fcntl,sys,os,stat,tempfile,ipaddress
os.umask(0o077)
ROOT=pathlib.Path('/var/lib/server-hardening/hermes');ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
lock=open('/run/lock/hermes-auto-update.lock','w');fcntl.flock(lock,fcntl.LOCK_EX)
state={'checked_at':int(time.time()),'status':'checking'}
def save():
    fd,name=tempfile.mkstemp(prefix='.update-',dir=ROOT)
    with os.fdopen(fd,'w') as output:json.dump(state,output);output.write('\n');output.flush();os.fsync(output.fileno())
    os.replace(name,ROOT/'update-state.json')
def private_config():
    path=pathlib.Path('/etc/dokploy/hermes-updater/config.json');info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o600:raise RuntimeError('Unsafe updater credential file')
    result=json.loads(path.read_text())
    if result.get('url')!='http://127.0.0.1:3000':raise RuntimeError('API credentials must remain on loopback')
    if not re.fullmatch(r'[A-Za-z0-9_-]+',result.get('composeId','')) or not re.fullmatch(r'[A-Za-z0-9_-]+',result.get('appName','')):raise RuntimeError('Invalid scoped target')
    address=result.get('tailscaleIp') or subprocess.check_output(['tailscale','ip','-4'],text=True).strip()
    if ipaddress.ip_address(address) not in ipaddress.ip_network('100.64.0.0/10'):raise RuntimeError('Hermes must bind to a Tailscale IPv4 address')
    result['tailscaleIp']=address
    result['dataVolume']=result.get('dataVolume','hermes-agent-private-data')
    if not re.fullmatch(r'[A-Za-z0-9_-]+',result['dataVolume']):raise RuntimeError('Invalid scoped data volume')
    return result
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise RuntimeError('Refusing credential-bearing API redirect')
opener=urllib.request.build_opener(NoRedirect(),urllib.request.ProxyHandler({}))
def api(endpoint,data=None):
    headers={'x-api-key':config['token'],'Content-Type':'application/json'}
    url=config['url']+'/api/trpc/'+endpoint
    if endpoint in ('compose.one','deployment.allByCompose'):
        url+='?'+urllib.parse.urlencode({'input':json.dumps({'json':data})});request=urllib.request.Request(url,headers=headers)
    else:request=urllib.request.Request(url,json.dumps({'json':data}).encode(),headers,method='POST')
    with opener.open(request,timeout=45) as response:body=json.load(response)
    if 'error' in body:raise RuntimeError('Dokploy rejected scoped operation')
    result=body.get('result',{}).get('data',{})
    return result.get('json',result)
def healthy(expected):
    ids=subprocess.check_output(['docker','ps','-q','--filter','label=com.docker.compose.project='+config['appName'],'--filter','label=com.docker.compose.service=hermes'],text=True).split()
    if len(ids)!=1:return False
    template='{"image":{{json .Config.Image}},"imageId":{{json .Image}},"health":{{if .State.Health}}{{json .State.Health.Status}}{{else}}null{{end}},"privileged":{{json .HostConfig.Privileged}},"ports":{{json .HostConfig.PortBindings}},"security":{{json .HostConfig.SecurityOpt}},"mounts":{{json .Mounts}}}'
    try:snapshot=json.loads(subprocess.check_output(['docker','inspect','--format',template,ids[0]],text=True,stderr=subprocess.DEVNULL))
    except (subprocess.CalledProcessError,json.JSONDecodeError):return False
    safe_ports=snapshot.get('ports')=={'9119/tcp':[{'HostIp':config['tailscaleIp'],'HostPort':'9119'}]}
    mounts=snapshot.get('mounts',[])
    safe_mounts=len(mounts)==1 and mounts[0].get('Type')=='volume' and mounts[0].get('Destination')=='/opt/data' and mounts[0].get('Name')==config['dataVolume']
    correct_id=not expected.startswith('local/hermes-hardened:sha-') or snapshot.get('imageId')=='sha256:'+expected.split(':sha-')[1]
    return snapshot.get('image')==expected and correct_id and snapshot.get('health')=='healthy' and snapshot.get('privileged') is False and safe_ports and safe_mounts and 'no-new-privileges:true' in (snapshot.get('security') or [])
def wait_healthy(image,seconds=900):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        if healthy(image):return True
        status=api('compose.one',{'composeId':config['composeId']}).get('composeStatus')
        if status=='error':return False
        time.sleep(15)
    return False
changed=False;previous=None;previous_image=None
try:
    config=private_config();state['composeId']=config['composeId']
    registry=urllib.request.Request('https://hub.docker.com/v2/repositories/nousresearch/hermes-agent/tags/latest',headers={'User-Agent':'Hermes-private-updater/2'})
    with urllib.request.urlopen(registry,timeout=30) as response:latest=json.load(response)
    digest=latest.get('digest','')
    if not re.fullmatch(r'sha256:[a-f0-9]{64}',digest):raise RuntimeError('Invalid official image digest')
    base='nousresearch/hermes-agent:latest@'+digest;state['latest_official_base']=base
    compose=api('compose.one',{'composeId':config['composeId']})
    if compose.get('appName')!=config['appName'] or compose.get('sourceType')!='raw':raise RuntimeError('Managed target configuration changed')
    previous=compose['composeFile'];match=re.search(r'(?m)^(\s*image:\s*)(nousresearch/hermes-agent:latest@sha256:[a-f0-9]{64}|local/hermes-hardened:sha-[a-f0-9]{64})\s*$',previous)
    if not match:raise RuntimeError('Scoped official or hardened image pin missing')
    previous_image=match.group(2)
    if compose.get('composeStatus')=='running':
        state['status']='deployment_in_progress';save();print('Existing deployment retained; no duplicate queued');sys.exit(0)
    build=subprocess.run(['/usr/local/sbin/hermes-build-image',base],capture_output=True,text=True,timeout=2100)
    if build.returncode!=0:raise RuntimeError('Isolated hardened image build failed; production retained')
    provenance=json.loads(build.stdout);target=provenance.get('image','')
    if not re.fullmatch(r'local/hermes-hardened:sha-[a-f0-9]{64}',target) or provenance.get('base')!=base or provenance.get('isolatedTestsPassed') is not True:raise RuntimeError('Invalid tested derivative provenance')
    state['build']=provenance;state['latest_image']=target
    if previous_image==target and healthy(target):
        state['status']='no_change';state['verified_at']=int(time.time());save();print('Hermes latest stable and private security boundary verified; no restart');sys.exit(0)
    if compose.get('composeStatus')=='running':
        state['status']='deployment_in_progress';save();print('Existing deployment retained; no duplicate queued');sys.exit(0)
    backup=subprocess.run(['/usr/local/sbin/hermes-backup'],capture_output=True,text=True,timeout=600)
    if backup.returncode!=0:raise RuntimeError('Backup failed; update not started')
    state['backup']=json.loads(backup.stdout);save()
    (ROOT/'previous-compose.yaml').write_text(previous);(ROOT/'previous-compose.yaml').chmod(0o600)
    updated=previous[:match.start(2)]+target+previous[match.end(2):]
    updated=re.sub(r'(?m)^(\s*pull_policy:\s*)always\s*$',r'\1never',updated)
    if previous_image!=target:api('compose.update',{'composeId':config['composeId'],'composeFile':updated});changed=True
    api('compose.deploy',{'composeId':config['composeId'],'title':'Automatic Hermes stable-image update','description':'Encrypted pre-update snapshot; private boundary and persistent volume preserved'})
    state['status']='deployment_requested';save()
    if not wait_healthy(target):raise RuntimeError('New image did not pass private authenticated health acceptance')
    state['status']='updated';state['verified_at']=int(time.time());save();print('Hermes latest stable update independently accepted');sys.exit(0)
except Exception as error:
    state['status']='error';state['error_type']=type(error).__name__
    if isinstance(error,urllib.error.HTTPError):state['http_status']=error.code
    if changed and previous and previous_image:
        try:
            api('compose.update',{'composeId':config['composeId'],'composeFile':previous})
            api('compose.deploy',{'composeId':config['composeId'],'title':'Rollback failed Hermes image update','description':'Restore previous image/config; retain data and encrypted recovery snapshot'})
            state['rollback_verified']=wait_healthy(previous_image,300)
            state['status']='rolled_back' if state['rollback_verified'] else 'rollback_failed'
        except Exception:state['status']='rollback_failed'
    save();print('Hermes update not accepted; protected receipt records recovery status',file=sys.stderr);sys.exit(1)
