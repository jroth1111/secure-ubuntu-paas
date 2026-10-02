const fs=require('fs'),path=require('path');
const [directory,manifest]=process.argv.slice(2);
if(!directory||!manifest) throw Error('Usage: verify-floors <modules> <manifest>');
const parse=v=>/^\d+\.\d+\.\d+$/.test(v)?v.split('.').map(Number):null;
const compare=(a,b)=>a[0]-b[0]||a[1]-b[1]||a[2]-b[2];
const floors=Object.entries(JSON.parse(fs.readFileSync(manifest))).map(([selector,floor])=>{
  const match=/^(.+)@>=(\d+\.\d+\.\d+) <(\d+\.\d+\.\d+)$/.exec(selector);
  if(!match||match[3]!==floor) throw Error('Unsupported security selector');
  return {name:match[1],lower:parse(match[2]),floor:parse(floor)};
});
let inspected=0;const violations=[];
function walk(folder){
  for(const item of fs.readdirSync(folder,{withFileTypes:true})){
    const filename=path.join(folder,item.name);
    if(item.isSymbolicLink()) continue;
    if(item.isDirectory()) walk(filename);
    else if(item.name==='package.json'){
      const pkg=JSON.parse(fs.readFileSync(filename));const version=parse(pkg.version??'');
      if(!version) continue;
      inspected++;
      for(const rule of floors)
        if(pkg.name===rule.name&&compare(version,rule.lower)>=0&&compare(version,rule.floor)<0)
          violations.push(pkg.name+'@'+pkg.version+' below '+rule.floor.join('.'));
    }
  }
}
walk(directory);
if(!inspected) throw Error('No package metadata inspected');
if(violations.length) throw Error([...new Set(violations)].join('; '));
console.log(JSON.stringify({dependencyFloorsVerified:true,packageMetadataInspected:inspected}));
