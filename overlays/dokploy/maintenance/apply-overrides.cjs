const fs=require('fs');
const pkg=JSON.parse(fs.readFileSync('package.json'));
const overrides=JSON.parse(fs.readFileSync('/tmp/security-overrides.json'));
pkg.pnpm??={};pkg.pnpm.overrides={...(pkg.pnpm.overrides??{}),...overrides};
fs.writeFileSync('package.json',JSON.stringify(pkg,null,2)+'\n');
