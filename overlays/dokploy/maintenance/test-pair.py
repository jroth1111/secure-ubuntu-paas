#!/usr/bin/env python3
"""RAM-only cloned DB + isolated panel. Never expose the live Docker socket."""
import json,os,secrets,subprocess,sys,time,urllib.request,urllib.error,urllib.parse,traceback
os.umask(0o077)
panel_image,pg_image=sys.argv[1:3]
nonce=secrets.token_hex(5);network='paas-audit-'+nonce;pg='paas-audit-pg-'+nonce;panel='paas-audit-panel-'+nonce
def output(*args):return subprocess.check_output(['docker',*args],text=True,stderr=subprocess.DEVNULL).strip()
def execute(*args):return subprocess.run(['docker',*args],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True)
def query(container,sql):return output('exec',container,'psql','-U','dokploy','-d','dokploy','-Atc',sql)
def request(container,path,token=None):
    script="const fs=require('fs');const p=JSON.parse(fs.readFileSync(0));fetch('http://127.0.0.1:3000'+p.path,{headers:p.token?{'x-api-key':p.token}:{},redirect:'error',signal:AbortSignal.timeout(5000)}).then(async r=>{let result=false;try{result=Boolean((await r.json()).result)}catch{}console.log(JSON.stringify({status:r.status,result}))}).catch(()=>console.log(JSON.stringify({status:0,result:false})))"
    return json.loads(subprocess.check_output(['docker','exec','-i',container,'node','-e',script],input=json.dumps({'path':path,'token':token}),text=True,stderr=subprocess.DEVNULL))
created=[];variables=[]
try:
    output('network','create','--internal',network)
    output('run','-d','--name',pg,'--label','local.paas.restore-test=true','--network',network,'--memory=512m','--cpus=0.5','--pids-limit=128','--security-opt=no-new-privileges:true',
           '--tmpfs','/var/lib/postgresql/data:rw,nosuid,size=256m','-e','POSTGRES_HOST_AUTH_METHOD=trust','-e','POSTGRES_USER=dokploy','-e','POSTGRES_DB=dokploy',pg_image)
    created.append(pg)
    deadline=time.monotonic()+90
    while subprocess.run(['docker','exec',pg,'pg_isready','-U','dokploy','-d','dokploy'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode:
        if time.monotonic()>deadline:raise RuntimeError('Isolated PostgreSQL startup failed')
        time.sleep(3)
    assert query(pg,'SHOW server_version;').startswith('16.')
    live_pg=output('ps','-q','--filter','label=com.docker.swarm.service.name=dokploy-postgres').split()
    assert len(live_pg)==1
    dump=subprocess.Popen(['docker','exec',live_pg[0],'pg_dump','-U','dokploy','-d','dokploy','--no-owner','--no-acl'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    restore=subprocess.run(['docker','exec','-i',pg,'psql','-U','dokploy','-d','dokploy','-q','-v','ON_ERROR_STOP=1'],stdin=dump.stdout,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    dump.stdout.close();dump.wait(timeout=60)
    if dump.returncode or restore.returncode:raise RuntimeError('Isolated database restore failed')
    sql='SELECT count(*) FROM "user";SELECT count(*) FROM "user" WHERE two_factor_enabled=true;SELECT count(*) FROM compose;'
    expected=query(live_pg[0],sql);assert query(pg,sql)==expected
    live_panel=output('ps','-q','--filter','label=com.docker.swarm.service.name=dokploy').split();assert len(live_panel)==1
    # Only the cloned panel's private process gets these values; they are never
    # written to an artifact/log and no production mounts or Docker socket exist.
    variables=json.loads(output('inspect','--format','{{json .Config.Env}}',live_panel[0]))
    variables=[v for v in variables if not v.startswith(('DATABASE_URL=','POSTGRES_PASSWORD_FILE=','POSTGRES_HOST=','POSTGRES_PORT=','POSTGRES_USER=','POSTGRES_DB=','BETTER_AUTH_SECRET_FILE=','BETTER_AUTH_SECRET=','DOCKER_HOST=','PORT='))]
    variables+=['DATABASE_URL=postgres://dokploy@'+pg+':5432/dokploy','POSTGRES_HOST='+pg,'POSTGRES_USER=dokploy','POSTGRES_DB=dokploy','POSTGRES_PORT=5432','PORT=3000','BETTER_AUTH_SECRET='+secrets.token_hex(64)]
    args=['run','-d','--name',panel,'--label','local.paas.restore-test=true','--network',network,'--memory=2g','--cpus=2','--pids-limit=256','--security-opt=no-new-privileges:true',
          '--tmpfs','/etc/dokploy:rw,nosuid,size=16m','--tmpfs','/root/.docker:rw,nosuid,size=2m']
    for v in variables:args+=['-e',v]
    args.append(panel_image);output(*args);created.append(panel)
    assert not json.loads(output('inspect','--format','{{json .HostConfig.PortBindings}}',panel))
    deadline=time.monotonic()+180
    while True:
        try:
            assert request(panel,'/api/trpc/settings.health')['status']==200
            break
        except (OSError,AssertionError,subprocess.CalledProcessError):
            if output('inspect','--format','{{.State.Running}}',panel)=='false':raise RuntimeError('Isolated panel exited during startup')
            if time.monotonic()>deadline:raise RuntimeError('Isolated panel did not pass application health')
            time.sleep(3)
    credentials=json.load(open('/etc/dokploy/paas-hardening/api.json'));token=credentials['token']
    endpoints=[('user.get',None),('project.all',None)]
    if credentials.get('composeId'):endpoints.append(('compose.one',{'composeId':credentials['composeId']}))
    for endpoint,params in endpoints:
        target='/api/trpc/'+endpoint
        if params:target+='?'+urllib.parse.urlencode({'input':json.dumps({'json':params})})
        response=request(panel,target,token);assert response['status']==200 and response['result']
    assert request(panel,'/api/trpc/project.all')['status'] in (401,403)
    assert request(panel,'/')['status']==200
    assert query(pg,sql)==expected
    print(json.dumps({'panelImage':panel_image,'postgresImage':pg_image,'databaseRestore':True,'accountTotpAndComposeCountsPreserved':True,'health':True,'authenticatedApi':True,'unauthenticatedApiBlocked':True,'noProductionMounts':True,'ramOnlyDatabase':True}))
except Exception as error:
    print('Isolated pair acceptance failed: '+type(error).__name__,file=sys.stderr)
    for frame in traceback.extract_tb(error.__traceback__):print(frame.filename+':'+str(frame.lineno),file=sys.stderr)
    if panel in created:
        logs=subprocess.check_output(['docker','logs',panel],text=True,stderr=subprocess.STDOUT)
        for variable in variables:
            value=variable.partition('=')[2]
            if len(value)>6:logs=logs.replace(value,'[REDACTED]')
        for line in logs.splitlines():
            if any(word in line for word in ['Error:','ERR_','ECONN','Cannot find','MODULE_NOT_FOUND']) or line.lstrip().startswith('at '):print(line[:240],file=sys.stderr)
    sys.exit(1)
finally:
    for container in reversed(created):subprocess.run(['docker','rm','-f','-v',container],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    subprocess.run(['docker','network','rm',network],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
