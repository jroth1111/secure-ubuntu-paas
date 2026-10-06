"""Reviewed Go module security floors; no prerelease, downgrade or import-major jump."""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess


def version(value):
    match=re.fullmatch(r'v(\d+)\.(\d+)\.(\d+)(-[^+]+)?(?:\+incompatible)?',value or '')
    if not match:raise RuntimeError('Unsupported Go module version')
    return tuple(map(int,match.group(1,2,3)))+(not bool(match.group(4)),)


def choose_updates(current,floors):
    updates={}
    blocked=[]
    for package,fixed in sorted(floors.items()):
        wanted=version(fixed)
        if not wanted[3]:raise RuntimeError('Prerelease security floor refused')
        old=current.get(package)
        if old is None:continue
        observed=version(old)
        if observed>=wanted:continue
        if observed[0]!=wanted[0]:
            blocked.append({'module':package,'installed':old,'floor':fixed,'reason':'import-major compatibility review required'})
            continue
        updates[package]=fixed
    return updates,blocked


def module_versions(floors=None):
    data=subprocess.check_output(['go','list','-m','-json','all'],text=True)
    decoder=json.JSONDecoder()
    versions={}
    while data.strip():
        row,offset=decoder.raw_decode(data.lstrip())
        data=data.lstrip()[offset:]
        if row.get('Version'):
            if row.get('Replace') and row['Path'] in (floors or {}):
                raise RuntimeError('Security-floor module replacement needs explicit review')
            versions[row['Path']]=row['Version']
    return versions


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('floors')
    parser.add_argument('receipt')
    args=parser.parse_args()
    floors=json.loads(pathlib.Path(args.floors).read_text())
    before=module_versions(floors)
    updates,blocked=choose_updates(before,floors)
    if updates:
        # These are lower bounds, not mutually contradictory exact pins. Go's
        # module-version selection may need a newer sibling (e.g. crypto's net
        # requirement or gRPC's telemetry requirement); tidy resolves that graph.
        subprocess.run(['go','mod','edit',*['-require='+name+'@'+fixed for name,fixed in updates.items()]],check=True)
        subprocess.run(['go','mod','tidy'],check=True)
    after=module_versions(floors)
    for package,old in before.items():
        if package in after and version(after[package])<version(old):
            raise RuntimeError('Transitive module downgrade refused')
        if package in after and version(after[package])[0]!=version(old)[0]:
            raise RuntimeError('Transitive import-major change needs compatibility review')
    for package,fixed in updates.items():
        if version(after.get(package,''))<version(fixed):raise RuntimeError('Go security-floor readback mismatch')
    receipt={'updated':updates,'blocked':blocked,'goVersion':subprocess.check_output(['go','version'],text=True).strip(),
        'goModSha256':hashlib.sha256(pathlib.Path('go.mod').read_bytes()).hexdigest(),
        'goSumSha256':hashlib.sha256(pathlib.Path('go.sum').read_bytes()).hexdigest()}
    pathlib.Path(args.receipt).write_text(json.dumps(receipt,sort_keys=True))
    print(json.dumps(receipt,sort_keys=True))


if __name__=='__main__':main()
