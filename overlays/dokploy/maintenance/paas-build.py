#!/usr/bin/env python3
"""Scoped, source-rebuilt security images; fail closed on any acceptance error."""
import fcntl,hashlib,json,os,pathlib,re,secrets,shutil,subprocess,sys,tempfile,time,urllib.request
os.umask(0o077)
component,base=sys.argv[1:3]
prefix={'dokploy':'dokploy/dokploy:latest@','postgres':'postgres:16@'}
if component not in prefix or not re.fullmatch(re.escape(prefix[component])+r'sha256:[a-f0-9]{64}',base):raise RuntimeError('Invalid approved base')
lock=open('/run/lock/paas-image-build.lock','w');fcntl.flock(lock,fcntl.LOCK_EX)
root=pathlib.Path('/var/lib/server-hardening/paas-images');root.mkdir(mode=0o700,parents=True,exist_ok=True)
template=pathlib.Path('/usr/local/lib/paas-hardening');statefile=root/(component+'.json')
def output(*args):
    try:return subprocess.check_output(args,text=True,stderr=subprocess.DEVNULL).strip()
    except subprocess.CalledProcessError as error:
        operation=args[1] if len(args)>1 and re.fullmatch(r'[a-z][a-z0-9-]{0,30}',args[1]) else 'arguments-redacted'
        (root/(component+'-failed-command.json')).write_text(json.dumps({'program':pathlib.Path(args[0]).name,'operation':operation,'returnCode':error.returncode,'at':int(time.time())}))
        raise
def call(*args,**kwargs):
    try:return subprocess.run(args,check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,**kwargs)
    except subprocess.CalledProcessError as error:
        operation=args[1] if len(args)>1 and re.fullmatch(r'[a-z][a-z0-9-]{0,30}',args[1]) else 'arguments-redacted'
        (root/(component+'-failed-command.json')).write_text(json.dumps({'program':pathlib.Path(args[0]).name,'operation':operation,'returnCode':error.returncode,'at':int(time.time())}))
        raise
def save(data):
    fd,name=tempfile.mkstemp(prefix='.receipt-',dir=root)
    with os.fdopen(fd,'w') as f:json.dump(data,f);f.flush();os.fsync(f.fileno())
    os.replace(name,statefile)
def keeper(image,image_id):
    name='paas-image-pin-'+component+'-'+image_id[7:27]
    try:
        observed=json.loads(output('docker','inspect','--format','{"image":{{json .Image}},"running":{{json .State.Running}},"health":{{json .Config.Healthcheck}},"pin":{{json (index .Config.Labels "local.paas.update-pin")}}}',name))
        if observed['image']!=image_id:raise RuntimeError('Keeper identity mismatch')
        if observed['pin']!='true':raise RuntimeError('Keeper ownership mismatch')
        call('docker','update','--restart=unless-stopped',name)
        if (observed.get('health') or {}).get('Test') not in (None,['NONE']):
            # This is an inert image-retention container, not an application.
            # An inherited application healthcheck cannot succeed here.
            call('docker','rm','-f','-v',name)
            raise subprocess.CalledProcessError(1,['recreate-owned-pin'])
        if not observed['running']:call('docker','start',name)
    except subprocess.CalledProcessError:
        call('docker','run','-d','--name',name,'--label','local.paas.update-pin=true','--restart=unless-stopped','--no-healthcheck','--user','65534:65534','--network=none','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges:true','--memory=16m','--pids-limit=8','--tmpfs','/var/lib/postgresql/data:rw,noexec,nosuid,size=1m','--entrypoint','sleep',image,'infinity')
    return name
def bound_keepers(image_id):
    protected={image_id}
    service='dokploy' if component=='dokploy' else 'dokploy-postgres'
    ids=output('docker','ps','-q','--filter','label=com.docker.swarm.service.name='+service).split()
    protected.update(output('docker','inspect','--format','{{.Image}}',cid) for cid in ids)
    previous=root/'update-state.json'
    if previous.exists():
        try:
            ref=json.loads(previous.read_text()).get('previousImages',{}).get(service,'')
            if re.fullmatch('local/paas-'+component+r'-hardened:sha-[a-f0-9]{64}',ref):protected.add('sha256:'+ref.split(':sha-')[1])
        except (ValueError,TypeError):return
    names=output('docker','ps','-a','--filter','label=local.paas.update-pin=true','--format','{{.Names}}').split()
    candidates=[]
    for name in names:
        if not re.fullmatch('paas-image-pin-'+component+r'-[a-f0-9]{20}',name):continue
        created=output('docker','inspect','--format','{{.Created}}',name)
        candidate_id=output('docker','inspect','--format','{{.Image}}',name)
        candidates.append((created,name,candidate_id))
    for _,name,candidate_id in sorted(candidates)[:-3]:
        if candidate_id not in protected:call('docker','rm','-f','-v',name)
files=['Dockerfile.dokploy-source','Dockerfile.postgres','security-overrides.json','apply-overrides.cjs','verify-floors.cjs','rebuild-esbuild.py','test-pair.py','.dockerignore']
recipe_files=['Dockerfile.postgres'] if component=='postgres' else ['Dockerfile.dokploy-source','security-overrides.json','apply-overrides.cjs','verify-floors.cjs','rebuild-esbuild.py']
digest=hashlib.sha256()
for name in files:
    path=template/name;s=path.lstat()
    if path.is_symlink() or not path.is_file() or s.st_uid!=0 or s.st_mode&0o022:raise RuntimeError('Unsafe image recipe')
    if name in recipe_files:digest.update(name.encode());digest.update(path.read_bytes())
recipe=digest.hexdigest();day=time.strftime('%Y-%m-%d',time.gmtime())
old=json.loads(statefile.read_text()) if statefile.exists() else {}
if old.get('base')==base and old.get('recipe')==recipe and old.get('day')==day:
    try:
        if output('docker','image','inspect','--format','{{.Id}}',old['image'])==old['imageId']:
            old['pin']=keeper(old['image'],old['imageId']);save(old);print(json.dumps(old));sys.exit(0)
    except subprocess.CalledProcessError:pass
if shutil.disk_usage('/var/lib/docker').free<8*1024**3:raise RuntimeError('Insufficient build headroom')
context=root/('context-'+component);context.mkdir(mode=0o700,exist_ok=True)
for name in files:shutil.copyfile(template/name,context/name)
arguments=['--build-arg','BASE_IMAGE='+base]
source_commit=None;runtime_image=None
if component=='dokploy':
    version=output('docker','run','--rm','--network=none','--entrypoint','node',base,'-p','require("/app/package.json").version').removeprefix('v')
    if not re.fullmatch(r'\d+\.\d+\.\d+',version):raise RuntimeError('Non-stable application source version')
    version_file=context/'source-version'
    if not version_file.exists() or version_file.read_text()!=version:
        source=context/'source'
        if source.exists():
            # Preserve the old trusted source checkout; no recursive deletion.
            os.rename(source,context/('source-retired-'+secrets.token_hex(4)))
        call('git','clone','--depth','1','--branch','v'+version,'https://github.com/Dokploy/dokploy.git',str(source),timeout=180)
        version_file.write_text(version)
    source_commit=output('git','-C',str(context/'source'),'rev-parse','HEAD')
    if not re.fullmatch(r'[a-f0-9]{40}',source_commit):raise RuntimeError('Invalid source identity')
    node_major=output('docker','run','--rm','--network=none','--entrypoint','node',base,'-p','process.versions.node.split(".")[0]')
    if not re.fullmatch(r'[2-9][0-9]',node_major):raise RuntimeError('Unsupported Node major')
    node_channel='node:'+node_major+'-bookworm';call('docker','pull','-q',node_channel)
    runtime_image=output('docker','image','inspect','--format','{{index .RepoDigests 0}}',node_channel)
    arguments+=['--build-arg','NODE_IMAGE='+runtime_image,'--build-arg','SOURCE_COMMIT='+source_commit]
    pack_version=output('docker','run','--rm','--network=none','--entrypoint','pack',base,'--version').split('+')[0]
    railpack_version=output('docker','run','--rm','--network=none','--entrypoint','railpack',base,'--version').split()[-1]
    if not all(re.fullmatch(r'\d+\.\d+\.\d+',v) for v in [pack_version,railpack_version]):raise RuntimeError('Non-stable build helper version')
    call('docker','pull','-q','golang:bookworm')
    go_image=output('docker','image','inspect','--format','{{index .RepoDigests 0}}','golang:bookworm')
    with urllib.request.urlopen('https://registry.npmjs.org/pnpm',timeout=30) as response:pnpm=json.load(response)
    versions=[v for v in pnpm['versions'] if re.fullmatch(r'10\.\d+\.\d+',v)]
    if not versions:raise RuntimeError('No approved stable package-manager version')
    pnpm_version=max(versions,key=lambda v:tuple(map(int,v.split('.'))))
    npm_major=output('docker','run','--rm','--network=none','--entrypoint','npm',runtime_image,'--version').split('.')[0]
    if not re.fullmatch(r'\d+',npm_major):raise RuntimeError('Invalid npm major')
    with urllib.request.urlopen('https://registry.npmjs.org/npm',timeout=30) as response:npm=json.load(response)
    npm_versions=[v for v in npm['versions'] if re.fullmatch(re.escape(npm_major)+r'\.\d+\.\d+',v)]
    if not npm_versions:raise RuntimeError('No approved stable npm version')
    npm_version=max(npm_versions,key=lambda v:tuple(map(int,v.split('.'))))
    arguments+=['--build-arg','NPM_VERSION='+npm_version]
    arguments+=['--build-arg','GO_IMAGE='+go_image,'--build-arg','PACK_VERSION='+pack_version,'--build-arg','RAILPACK_VERSION='+railpack_version,'--build-arg','PNPM_VERSION='+pnpm_version]
    dockerfile='Dockerfile.dokploy-source'
else:
    gosu_version=output('docker','run','--rm','--network=none','--entrypoint','gosu',base,'--version').split()[0]
    if not re.fullmatch(r'\d+\.\d+',gosu_version):raise RuntimeError('Invalid privilege helper source version')
    call('docker','pull','-q','golang:bookworm')
    runtime_image=output('docker','image','inspect','--format','{{index .RepoDigests 0}}','golang:bookworm')
    arguments+=['--build-arg','GO_IMAGE='+runtime_image,'--build-arg','GOSU_VERSION='+gosu_version]
    dockerfile='Dockerfile.postgres'
tag='local/paas-'+component+'-hardened:build-'+secrets.token_hex(8)
with (root/(component+'-last-build.log')).open('w') as log:
    subprocess.run(['docker','buildx','build','--load','--pull','--no-cache-filter','hardened',*arguments,'-f',str(context/dockerfile),'-t',tag,str(context)],stdout=log,stderr=subprocess.STDOUT,check=True,timeout=2400)
image_id=output('docker','image','inspect','--format','{{.Id}}',tag);image='local/paas-'+component+'-hardened:sha-'+image_id[7:]
call('docker','tag',tag,image);pin=keeper(image,image_id)
assert output('docker','image','inspect','--format','{{index .Config.Labels "org.opencontainers.image.base.name"}}',image)==base
if component=='postgres':
    panel=output('docker','service','inspect','--format','{{.Spec.TaskTemplate.ContainerSpec.Image}}','dokploy');pg=image
else:
    panel=image;pg=output('docker','service','inspect','--format','{{.Spec.TaskTemplate.ContainerSpec.Image}}','dokploy-postgres')
call('python3',str(template/'test-pair.py'),panel,pg,timeout=360)
manifest=output('docker','run','--rm','--network=none','--entrypoint','sh',image,'-c','set -e; dpkg-query -W; if command -v node >/dev/null; then node --version; sha256sum /app/dist/server.mjs /usr/local/bin/pack /usr/local/bin/railpack /usr/local/lib/paas-source-lock.yaml /usr/local/lib/native-compilers.json; npm --version; corepack pnpm --version; fi; if command -v gosu >/dev/null; then gosu --version; sha256sum /usr/local/bin/gosu; fi')
fingerprint=hashlib.sha256((base+recipe+(source_commit or '')+manifest).encode()).hexdigest()
if old.get('fingerprint')==fingerprint:
    try:
        if output('docker','image','inspect','--format','{{.Id}}',old['image'])==old['imageId']:
            if image_id!=old['imageId']:
                call('docker','rm','-f','-v',pin);call('docker','image','rm',image,tag)
            else:call('docker','image','rm',tag)
            image=old['image'];image_id=old['imageId'];pin=old['pin']
    except subprocess.CalledProcessError:pass
else:call('docker','image','rm',tag)
result={'component':component,'base':base,'image':image,'imageId':image_id,'pin':pin,'day':day,'recipe':recipe,'sourceCommit':source_commit,'runtimeImage':runtime_image,'fingerprint':fingerprint,'isolatedTestsPassed':True,'testedAt':int(time.time())}
save(result);bound_keepers(image_id);print(json.dumps(result))
