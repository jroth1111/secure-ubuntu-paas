import pathlib,tempfile,json,urllib.parse,unittest.mock,contextlib,io,types,stat,os
source=(pathlib.Path(__file__).resolve().parents[4]/'overlays/dokploy/maintenance/hermes/updater.py').read_text()
old='nousresearch/hermes-agent:latest@sha256:'+'1'*64;new='local/hermes-hardened:sha-'+'2'*64
class Response(io.BytesIO):
    def __enter__(self):return self
    def __exit__(self,*args):self.close()
def scenario(failed=False,backup_failed=False,build_failed=False,unsafe_runtime=False):
    current={'appName':'hermes-test','sourceType':'raw','composeStatus':'done','composeFile':'services:\n  hermes:\n    image: '+old+'\n    volumes: [hermes_data:/opt/data]\n','env':'UNCHANGED'}
    calls=[];live={'image':old,'health':'healthy'}
    def request(req,timeout=None):
        if 'hub.docker.com' in req.full_url:return Response(json.dumps({'digest':'sha256:'+'2'*64}).encode())
        endpoint=urllib.parse.urlsplit(req.full_url).path.rsplit('/',1)[-1]
        data=json.loads(req.data)['json'] if req.data else None;calls.append((endpoint,data))
        if endpoint=='compose.one':result=dict(current)
        elif endpoint=='compose.update':current['composeFile']=data['composeFile'];result=dict(current)
        elif endpoint=='compose.deploy':
            if 'Rollback' in data['title']:live.update(image=old,health='healthy');current['composeStatus']='done'
            elif failed or unsafe_runtime:live.update(image=new,health='healthy' if unsafe_runtime else 'unhealthy');current['composeStatus']='error'
            else:live.update(image=new,health='healthy')
            result={}
        else:raise AssertionError('Unexpected endpoint')
        return Response(json.dumps({'result':{'data':{'json':result}}}).encode())
    def command(args,**kwargs):
        if args[1]=='ps':return 'test-container\n'
        return json.dumps({**live,'imageId':'sha256:'+'2'*64,'privileged':False,
            'user':'root' if unsafe_runtime or live['image']==old else '10000:10000',
            'readonly':True,'capadd':[],'capdrop':['ALL'],'tmpfs':{
                '/run':'rw,exec,nosuid,nodev,uid=10000,gid=10000,mode=0700,size=32m',
                '/tmp':'rw,exec,nosuid,nodev,mode=1777,size=256m',
                '/var/tmp':'rw,exec,nosuid,nodev,mode=1777,size=64m'},
            'ports':{'9119/tcp':[{'HostIp':'100.102.237.110','HostPort':'9119'}]},
            'security':['no-new-privileges:true'],
            'mounts':[{'Type':'volume','Destination':'/opt/data','Name':'hermes-agent-private-data'}]})
    with tempfile.TemporaryDirectory(prefix='hermes-hardening-test-') as directory:
        root=pathlib.Path(directory);configuration=root/'config.json'
        configuration.write_text(json.dumps({'url':'http://127.0.0.1:3000','token':'test-only','composeId':'test-id','appName':'hermes-test','tailscaleIp':'100.102.237.110'}))
        configuration.chmod(0o600)
        code=source.replace('/var/lib/server-hardening/hermes',str(root/'state')).replace('/run/lock/hermes-auto-update.lock',str(root/'lock')).replace('/etc/dokploy/hermes-updater/config.json',str(configuration))
        original_lstat=pathlib.Path.lstat
        def lstat(path):
            if path==configuration:return types.SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0)
            return original_lstat(path)
        backup=types.SimpleNamespace(returncode=1 if backup_failed else 0,stdout='{"archive":"encrypted-test.age"}')
        def execute(args,**kwargs):
            if args[0]=='/usr/local/sbin/hermes-build-image':return types.SimpleNamespace(returncode=1 if build_failed else 0,stdout=json.dumps({'base':'nousresearch/hermes-agent:latest@sha256:'+'2'*64,'image':new,'isolatedTestsPassed':True}))
            return backup
        opener=types.SimpleNamespace(open=request)
        with unittest.mock.patch('urllib.request.urlopen',request),unittest.mock.patch('urllib.request.build_opener',return_value=opener),unittest.mock.patch('subprocess.check_output',command),unittest.mock.patch('subprocess.run',side_effect=execute),unittest.mock.patch.object(pathlib.Path,'lstat',lstat),contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
            try:exec(compile(code,'updater-v2','exec'),{'__name__':'__main__'})
            except SystemExit:pass
        state=json.loads((root/'state/update-state.json').read_text())
        assert current['env']=='UNCHANGED'
        assert 'volumes: [hermes_data:/opt/data]' in current['composeFile']
        assert all('freshVolumes' not in (data or {}) for _,data in calls)
        if backup_failed or build_failed:assert state['status']=='error' and not any(name=='compose.deploy' for name,_ in calls)
        elif failed or unsafe_runtime:assert state['status']=='rolled_back' and state['rollback_verified'] is True and live['image']==old
        else:
            assert state['status']=='updated' and live['image']==new and state['runtimeRootless'] is True
            import yaml
            service=yaml.safe_load(current['composeFile'])['services']['hermes']
            assert service['user']=='10000:10000' and service['read_only'] is True
            assert service['cap_drop']==['ALL'] and not service['cap_add']
scenario();scenario(failed=True);scenario(backup_failed=True);scenario(build_failed=True);scenario(unsafe_runtime=True)
print('PASS: rootless acceptance, root-init refusal, failed-image rollback, backup/build refusal, private boundary and data preservation')
