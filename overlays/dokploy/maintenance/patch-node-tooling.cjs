// Patch reviewed same-major npm tooling dependencies without package lifecycle scripts.
const fs=require('fs'),path=require('path'),cp=require('child_process');
const semver=require('/usr/local/lib/node_modules/npm/node_modules/semver');
const targets=[
 ['/usr/local/lib/node_modules/npm/node_modules/brace-expansion','5.0.11'],
 ['/usr/local/lib/node_modules/npm/node_modules/undici','6.28.1']
];
function dependency(base,name){
 for(let directory=base;;directory=path.dirname(directory)){
  const file=path.join(directory,'node_modules',name,'package.json');
  if(fs.existsSync(file))return JSON.parse(fs.readFileSync(file));
  if(path.dirname(directory)===directory)throw Error('Missing module dependency');
 }
}
for(const [directory,fixed] of targets){
 if(!fs.existsSync(directory+'/package.json'))continue;
 const previous=JSON.parse(fs.readFileSync(directory+'/package.json'));
 if(semver.gte(previous.version,fixed))continue;
 if(semver.major(previous.version)!==semver.major(fixed))throw Error('Tooling module major change refused');
 const temporary=fs.mkdtempSync('/tmp/paas-node-tooling-');
 try{
  const packed=JSON.parse(cp.execFileSync('npm',['pack',previous.name+'@'+fixed,'--json','--ignore-scripts','--pack-destination',temporary],{encoding:'utf8'}))[0];
  const archive=path.join(temporary,packed.filename);
  const names=cp.execFileSync('tar',['-tzf',archive],{encoding:'utf8'}).trim().split('\n');
  if(names.some(name=>!name.startsWith('package/')||name.split('/').includes('..')))throw Error('Unsafe package archive');
  cp.execFileSync('tar',['-xzf',archive,'-C',temporary]);
  const next=JSON.parse(fs.readFileSync(temporary+'/package/package.json'));
  if(next.name!==previous.name||next.version!==fixed)throw Error('Tooling package identity mismatch');
  for(const [name,range] of Object.entries(next.dependencies??{}))
   if(!semver.satisfies(dependency(directory,name).version,range))throw Error('Unsatisfied tooling dependency');
  for(const entry of fs.readdirSync(directory))
   if(entry!=='node_modules')fs.rmSync(path.join(directory,entry),{recursive:true,force:true});
  fs.cpSync(temporary+'/package',directory,{recursive:true});
 }finally{fs.rmSync(temporary,{recursive:true,force:true});}
}
console.log('Reviewed npm tooling security floors applied');
