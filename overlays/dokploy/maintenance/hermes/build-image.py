#!/usr/bin/env python3
"""Root-only scoped derivative builder. Failure never touches production compose."""
import hashlib,json,os,pathlib,re,secrets,shutil,stat,subprocess,sys,tempfile,time,fcntl
os.umask(0o077)
lock=open('/run/lock/hermes-build-image.lock','w');fcntl.flock(lock,fcntl.LOCK_EX)
root=pathlib.Path('/var/lib/server-hardening/hermes');source=pathlib.Path('/usr/local/lib/hermes-hardening/image')
base=sys.argv[1]
if not re.fullmatch(r'nousresearch/hermes-agent:latest@sha256:[a-f0-9]{64}',base):raise RuntimeError('Invalid official base pin')
if shutil.disk_usage('/var/lib/docker').free<8*1024**3:raise RuntimeError('Insufficient image-build headroom')
names=['Dockerfile','patch-python.py','patch-node.cjs','patch-uv.py','smoke.py','manifest.py','test-image.py']
digest=hashlib.sha256()
for name in names:
    p=source/name;s=p.lstat()
    if not p.is_file() or p.is_symlink() or s.st_uid!=0 or s.st_mode&0o022:raise RuntimeError('Unsafe build source')
    digest.update(name.encode());digest.update(p.read_bytes())
recipe=digest.hexdigest();day=time.strftime('%Y-%m-%d',time.gmtime())
receipt=root/'build-state.json'
old=json.loads(receipt.read_text()) if receipt.exists() else {}
def command(*args):return subprocess.check_output(args,text=True,stderr=subprocess.DEVNULL).strip()
def keep_image(image,image_id):
    name='hermes-security-pin-'+image_id.removeprefix('sha256:')[:20]+'-safe'
    try:
        observed=json.loads(command('docker','inspect','--format','{"image":{{json .Image}},"running":{{json .State.Running}},"pin":{{json (index .Config.Labels "local.hermes.update-pin")}}}',name))
        if observed['image']!=image_id:raise RuntimeError('Image keeper identity mismatch')
        if observed['pin']!='true':raise RuntimeError('Image keeper ownership mismatch')
        subprocess.run(['docker','update','--restart=unless-stopped',name],stdout=subprocess.DEVNULL,check=True)
        if not observed['running']:subprocess.run(['docker','start',name],stdout=subprocess.DEVNULL,check=True)
    except subprocess.CalledProcessError:
        subprocess.run(['docker','run','-d','--name',name,'--label','local.hermes.update-pin=true','--restart=unless-stopped','--no-healthcheck','--user','10000:10000','--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges:true','--memory=16m','--pids-limit=8','--tmpfs','/opt/data:rw,noexec,nosuid,size=1m','--entrypoint','sleep',image,'infinity'],stdout=subprocess.DEVNULL,check=True)
    return name
if old.get('base')==base and old.get('recipe')==recipe and old.get('day')==day:
    try:
        if command('docker','image','inspect','--format','{{.Id}}',old['image'])==old['imageId']:
            old['pin']=keep_image(old['image'],old['imageId'])
            fd,tmp=tempfile.mkstemp(prefix='.build-',dir=root)
            with os.fdopen(fd,'w') as output:json.dump(old,output);output.flush();os.fsync(output.fileno())
            os.replace(tmp,receipt)
            print(json.dumps(old));sys.exit(0)
    except subprocess.CalledProcessError:pass
tag='local/hermes-hardened:build-'+secrets.token_hex(8)
log=root/'last-build.log'
with log.open('w') as output:
    subprocess.run(['docker','build','--pull','--no-cache','--build-arg','BASE_IMAGE='+base,'-t',tag,str(source)],stdout=output,stderr=subprocess.STDOUT,check=True,timeout=1800)
image_id=command('docker','image','inspect','--format','{{.Id}}',tag)
target='local/hermes-hardened:sha-'+image_id.removeprefix('sha256:')
subprocess.run(['docker','tag',tag,target],check=True)
pin=keep_image(target,image_id)
assert command('docker','image','inspect','--format','{{index .Config.Labels "org.opencontainers.image.base.name"}}',target)==base
subprocess.run(['python3',str(source/'test-image.py'),target],stdout=subprocess.DEVNULL,check=True,timeout=240)
manifest=command('docker','run','--rm','--network=none','--entrypoint','/opt/hermes/.venv/bin/python',target,'/usr/local/lib/hermes-security-manifest.py')
fingerprint=hashlib.sha256((base+recipe+manifest).encode()).hexdigest()
if old.get('fingerprint')==fingerprint:
    try:
        if command('docker','image','inspect','--format','{{.Id}}',old['image'])==old['imageId']:
            if image_id!=old['imageId']:
                subprocess.run(['docker','rm','-f','-v',pin],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                subprocess.run(['docker','image','rm',target,tag],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            else:subprocess.run(['docker','image','rm',tag],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            target=old['image'];image_id=old['imageId']
            pin=old.get('pin')
    except subprocess.CalledProcessError:pass
else:subprocess.run(['docker','image','rm',tag],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
result={'base':base,'recipe':recipe,'day':day,'image':target,'imageId':image_id,'pin':pin,'fingerprint':fingerprint,'isolatedTestsPassed':True,'checkedAt':int(time.time())}
fd,name=tempfile.mkstemp(prefix='.build-',dir=root)
with os.fdopen(fd,'w') as output:json.dump(result,output);output.flush();os.fsync(output.fileno())
os.replace(name,receipt)
# Bound only our disposable keepers; never prune Dokploy or application containers.
pins=command('docker','ps','-a','--filter','label=local.hermes.update-pin=true','--format','{{.Names}}').splitlines()
configuration=pathlib.Path('/etc/dokploy/hermes-updater/config.json');metadata=configuration.lstat()
if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid!=0 or stat.S_IMODE(metadata.st_mode)!=0o600:raise RuntimeError('Unsafe scoped Hermes config')
project=json.loads(configuration.read_text()).get('appName','')
if not re.fullmatch(r'[A-Za-z0-9_-]+',project):raise RuntimeError('Invalid scoped Hermes project')
live=command('docker','ps','-q','--filter','label=com.docker.compose.project='+project,'--filter','label=com.docker.compose.service=hermes').splitlines()
protected={image_id,*[command('docker','inspect','--format','{{.Image}}',p) for p in live]}
previous=root/'previous-compose.yaml'
if previous.exists():
    match=re.search(r'local/hermes-hardened:sha-([a-f0-9]{64})',previous.read_text())
    if match:protected.add('sha256:'+match[1])
eligible=sorted((command('docker','inspect','--format','{{.Created}}',p),p,command('docker','inspect','--format','{{.Image}}',p)) for p in pins if re.fullmatch(r'hermes-security-pin-[a-f0-9]{20}(?:-safe)?',p))
for _,p,pinned_id in eligible[:-3]:
    if p!=pin and pinned_id not in protected:subprocess.run(['docker','rm','-f','-v',p],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
print(json.dumps(result))
