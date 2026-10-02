// Patch only vulnerable installed modules; do not run npm lifecycle scripts.
const fs=require('fs'),path=require('path'),cp=require('child_process');
const semver=require('/usr/local/lib/node_modules/npm/node_modules/semver');
const targets=[
 ['/usr/local/lib/node_modules/npm/node_modules/brace-expansion','5.0.11'],
 ['/usr/local/lib/node_modules/npm/node_modules/ip-address','10.3.1'],
 ['/usr/local/lib/node_modules/npm/node_modules/tar','7.5.21'],
 ['/usr/local/lib/node_modules/npm/node_modules/undici','6.28.1'],
 ['/opt/hermes/node_modules/brace-expansion','5.0.11'],
 ['/opt/hermes/ui-tui/node_modules/undici','6.28.1'],
 ['/opt/hermes/plugins/platforms/photon/sidecar/node_modules/undici','7.29.1'],
 ['/opt/hermes/plugins/platforms/photon/sidecar/node_modules/@grpc/grpc-js','1.14.5']
];
function dependency(base,name){
 for(let dir=base;;dir=path.dirname(dir)){
  const candidate=path.join(dir,'node_modules',name,'package.json');
  if(fs.existsSync(candidate))return JSON.parse(fs.readFileSync(candidate));
  if(path.dirname(dir)===dir)throw Error('Missing dependency '+name);
 }
}
for(const [dir,fixed] of targets){
 if(!fs.existsSync(dir+'/package.json'))continue;
 const old=JSON.parse(fs.readFileSync(dir+'/package.json'));
 if(semver.gte(old.version,fixed))continue;
 const tmp=fs.mkdtempSync('/tmp/hermes-node-patch-');
 try{
  const packed=JSON.parse(cp.execFileSync('npm',['pack',old.name+'@'+fixed,'--json','--ignore-scripts','--pack-destination',tmp],{encoding:'utf8'}))[0];
  const archive=path.join(tmp,packed.filename);
  const names=cp.execFileSync('tar',['-tzf',archive],{encoding:'utf8'}).trim().split('\n');
  if(names.some(n=>!n.startsWith('package/')||n.split('/').includes('..')))throw Error('Unsafe package archive');
  cp.execFileSync('tar',['-xzf',archive,'-C',tmp]);
  const next=JSON.parse(fs.readFileSync(tmp+'/package/package.json'));
  if(next.name!==old.name||next.version!==fixed)throw Error('Package identity mismatch');
  for(const [name,range] of Object.entries(next.dependencies??{})){
   if(!semver.satisfies(dependency(dir,name).version,range))throw Error('Unsatisfied patched module dependency '+name);
  }
  // Preserve any nested dependencies already installed by the upstream lockfile.
  for(const entry of fs.readdirSync(dir)){if(entry!=='node_modules')fs.rmSync(path.join(dir,entry),{recursive:true,force:true});}
  fs.cpSync(tmp+'/package',dir,{recursive:true});
  console.log('Security patch '+old.name+' '+old.version+' -> '+fixed);
 }finally{fs.rmSync(tmp,{recursive:true,force:true});}
}
