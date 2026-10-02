const fs=require('fs');
const pkg=JSON.parse(fs.readFileSync('package.json'));
const overrides=JSON.parse(fs.readFileSync('/tmp/security-overrides.json'));
pkg.pnpm??={};pkg.pnpm.overrides={...(pkg.pnpm.overrides??{}),...overrides};
const version=process.env.PNPM_VERSION;
if(!/^10\.\d+\.\d+$/.test(version??'')) throw Error('Approved stable pnpm version required');
const existing=/^pnpm@(\d+)\./.exec(pkg.packageManager??'');
if(existing && existing[1]!=='10') throw Error('Upstream package-manager major requires compatibility review');
pkg.packageManager='pnpm@'+version;
fs.writeFileSync('package.json',JSON.stringify(pkg,null,2)+'\n');
for(const parent of ['apps','packages']){
  if(!fs.existsSync(parent)) continue;
  for(const child of fs.readdirSync(parent)){
    const filename=parent+'/'+child+'/package.json';
    if(!fs.existsSync(filename)) continue;
    const project=JSON.parse(fs.readFileSync(filename));
    if(/^pnpm@10\./.test(project.packageManager??'')){
      project.packageManager=pkg.packageManager;
      fs.writeFileSync(filename,JSON.stringify(project,null,2)+'\n');
    }
  }
}
// Newer pnpm uses workspace settings as the authoritative override location.
// Merge rather than replace the upstream workspace configuration.
require('child_process').execFileSync('python3',['-c',`
import json,pathlib,yaml
p=pathlib.Path('pnpm-workspace.yaml')
data=yaml.safe_load(p.read_text()) or {}
pkg=json.loads(pathlib.Path('package.json').read_text())
data['overrides']={**data.get('overrides',{}),**pkg['pnpm']['overrides']}
p.write_text(yaml.safe_dump(data,sort_keys=False))
`]);
