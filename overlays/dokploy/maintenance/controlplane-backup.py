#!/usr/bin/env python3
"""Encrypt the complete Dokploy recovery set; plaintext remains in RAM/pipes."""
import fcntl,hashlib,io,json,os,pathlib,secrets,stat,subprocess,tarfile,time,tempfile,shutil,re
os.umask(0o077)
root=pathlib.Path('/var/lib/server-hardening/controlplane-backups');root.mkdir(mode=0o700,parents=True,exist_ok=True)
lock=open('/run/lock/controlplane-backup.lock','w');fcntl.flock(lock,fcntl.LOCK_EX)
if shutil.disk_usage(root).free<5*1024**3:raise RuntimeError('Backup must preserve disk headroom')
recipient=pathlib.Path('/var/lib/server-hardening/backup-recipient')
info=recipient.lstat()
if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o600:raise RuntimeError('Unsafe recipient file')
def command(*args):return subprocess.check_output(args,stderr=subprocess.DEVNULL)
pg=command('docker','ps','-q','--filter','label=com.docker.swarm.service.name=dokploy-postgres').decode().split();assert len(pg)==1
dump=subprocess.Popen(['docker','exec',pg[0],'pg_dump','-U','dokploy','-d','dokploy','--no-owner','--no-acl'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
database=dump.stdout.read(64*1024**2+1)
if len(database)>64*1024**2:dump.terminate();raise RuntimeError('Control-plane dump exceeds bounded RAM policy')
assert dump.wait(timeout=120)==0
services=command('docker','service','inspect','dokploy','dokploy-postgres','dokploy-traefik')
secret_values={}
for service in json.loads(services):
    name=service['Spec']['Name']
    ids=command('docker','ps','-q','--filter','label=com.docker.swarm.service.name='+name).decode().split()
    if len(ids)!=1:raise RuntimeError('Recovery snapshot requires one live task per service')
    for secret in service['Spec']['TaskTemplate']['ContainerSpec'].get('Secrets',[]):
        target=secret.get('File',{}).get('Name','')
        if target.startswith('/run/secrets/'):target=target.removeprefix('/run/secrets/')
        if not re.fullmatch(r'[A-Za-z0-9_.-]+',target) or target in ('.','..'):raise RuntimeError('Unsafe secret target')
        value=command('docker','exec',ids[0],'cat','--','/run/secrets/'+target)
        if not value or len(value)>65536:raise RuntimeError('Unexpected recovery secret size')
        secret_values[secret['SecretName']]=value.decode()
docker_config=pathlib.Path(command('docker','volume','inspect','--format','{{.Mountpoint}}','dokploy').decode().strip())
assert docker_config==pathlib.Path('/var/lib/docker/volumes/dokploy/_data')
name='controlplane-'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())+'-'+secrets.token_hex(3)+'.tar.gz.age'
fd,tmp=tempfile.mkstemp(prefix='.encrypted-',dir=root)
count=0;total=0;encrypt=None
try:
    with os.fdopen(fd,'wb') as ciphertext:
        encrypt=subprocess.Popen(['age','-r',recipient.read_text().strip()],stdin=subprocess.PIPE,stdout=ciphertext,stderr=subprocess.DEVNULL)
        with tarfile.open(fileobj=encrypt.stdin,mode='w|gz') as archive:
            def memory(name,data):
                item=tarfile.TarInfo(name);item.size=len(data);item.mode=0o600;item.mtime=int(time.time());archive.addfile(item,io.BytesIO(data))
            memory('database.sql',database);memory('services.json',services)
            memory('swarm-secrets.json',json.dumps(secret_values).encode())
            for prefix,folder in [('config',pathlib.Path('/etc/dokploy')),('docker-config',docker_config)]:
                assert folder.is_dir() and not folder.is_symlink()
                for path in sorted(folder.rglob('*')):
                    if path.is_symlink() or not path.is_file():continue
                    if 'logs' in path.relative_to(folder).parts or '.git' in path.parts:continue
                    relative=path.relative_to(folder)
                    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
                    with os.fdopen(fd,'rb') as original:
                        before=os.fstat(original.fileno());item=tarfile.TarInfo(prefix+'/'+relative.as_posix())
                        total+=before.st_size
                        if total>128*1024**2:raise RuntimeError('Configuration exceeds bounded control-plane backup policy')
                        item.size=before.st_size;item.mode=stat.S_IMODE(before.st_mode);item.mtime=before.st_mtime
                        archive.addfile(item,original)
                        after=os.fstat(original.fileno())
                        if (before.st_size,before.st_mtime_ns)!=(after.st_size,after.st_mtime_ns):raise RuntimeError('Configuration changed during backup')
                        count+=1
            memory('manifest.json',json.dumps({'createdAt':int(time.time()),'configurationFiles':count,'postgresMajor':16}).encode())
        encrypt.stdin.close()
        assert encrypt.wait(timeout=120)==0
        ciphertext.flush();os.fsync(ciphertext.fileno())
    target=root/name;os.replace(tmp,target)
    digest=hashlib.sha256()
    with target.open('rb') as ciphertext:
        for block in iter(lambda:ciphertext.read(1048576),b''):digest.update(block)
    result={'archive':str(target),'sha256':digest.hexdigest(),'bytes':target.stat().st_size,'configurationFiles':count,'swarmSecrets':len(secret_values),'createdAt':int(time.time())}
    fd,record=tempfile.mkstemp(prefix='.receipt-',dir=root)
    with os.fdopen(fd,'w') as output:json.dump(result,output);output.flush();os.fsync(output.fileno())
    os.replace(record,root/'latest.json')
    print(json.dumps(result))
finally:
    if encrypt and encrypt.poll() is None:
        encrypt.terminate();encrypt.wait(timeout=10)
    pathlib.Path(tmp).unlink(missing_ok=True)
