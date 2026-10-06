#!/usr/bin/env python3
"""Recompile exact upstream esbuild versions; never upgrade the JS/API version."""
import hashlib, json, pathlib, re, shutil, subprocess, tempfile


def discover(root):
    found = {}
    for binary in root.rglob('esbuild'):
        if binary.is_symlink() or not binary.is_file():
            continue
        with binary.open('rb') as handle:
            if handle.read(4) != b'\x7fELF':
                continue
        version = subprocess.check_output([str(binary), '--version'], text=True).strip()
        if not re.fullmatch(r'\d+\.\d+\.\d+', version):
            raise RuntimeError('Non-stable native esbuild version')
        found.setdefault(version, []).append(binary)
    return found


def transform(binary, source, loader):
    return subprocess.check_output([str(binary), '--loader=' + loader, '--format=cjs',
        '--target=es2020'], input=source, text=True, stderr=subprocess.DEVNULL)


def discover_typescript(root):
    found={}
    for binary in root.rglob('tsc'):
        if binary.is_symlink() or not binary.is_file():continue
        with binary.open('rb') as handle:
            if handle.read(4)!=b'\x7fELF':continue
        observed=subprocess.check_output([str(binary),'--version'],text=True).strip()
        match=re.fullmatch(r'Version (7\.\d+\.\d+)',observed)
        if not match:raise RuntimeError('Unsupported native TypeScript release')
        found.setdefault(match[1],[]).append(binary)
    return found


def typescript_output(binary,sample):
    with tempfile.TemporaryDirectory(prefix='typescript-security-parity-') as directory:
        folder=pathlib.Path(directory)
        (folder/'sample.ts').write_text(sample)
        (folder/'globals.d.ts').write_text('''interface Array<T> { length: number; [n: number]: T; }
interface ReadonlyArray<T> { readonly length: number; readonly [n: number]: T; }
interface Boolean {} interface Function {} interface CallableFunction {} interface NewableFunction {}
interface IArguments {} interface Number {} interface Object {} interface RegExp {} interface String {}
''')
        subprocess.run([str(binary),'--noLib','--strict','--target','es2020','--module','commonjs',
            '--declaration','--outDir',str(folder/'out'),str(folder/'globals.d.ts'),str(folder/'sample.ts')],
            check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        return {path.name:path.read_bytes() for path in (folder/'out').iterdir() if path.is_file()}


def main():
    root = pathlib.Path('/modules')
    output = pathlib.Path('/patched')
    output.mkdir()
    entries = []
    for version, binaries in sorted(discover(root).items()):
        source = pathlib.Path('/src/esbuild-' + version)
        subprocess.run(['git', 'clone', '--depth', '1', '--branch', 'v' + version,
            'https://github.com/evanw/esbuild.git', str(source)], check=True)
        candidate = pathlib.Path('/out/esbuild-' + version)
        candidate.parent.mkdir(exist_ok=True)
        subprocess.run(['go', 'build', '-trimpath', '-o', str(candidate), './cmd/esbuild'], cwd=source, check=True)
        subprocess.run(['go', 'test', './internal/logger', './internal/helpers'], cwd=source, check=True)
        observed = subprocess.check_output([str(candidate), '--version'], text=True).strip()
        if observed != version:
            raise RuntimeError('Native/JavaScript version mismatch')
        samples = [('export const answer: number = 42;', 'ts'),
                   ('export const f = (x) => x?.value ?? 7;', 'js'),
                   ('export const element = <div title="hello"/>;', 'tsx')]
        for original in binaries:
            for sample, loader in samples:
                if transform(original, sample, loader) != transform(candidate, sample, loader):
                    raise RuntimeError('Same-version transform regression')
            target = output / original.relative_to(root)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(candidate, target)
        entries.append({'version': version, 'copies': len(binaries),
            'commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip(),
            'sha256': hashlib.sha256(candidate.read_bytes()).hexdigest()})
    typescript=[]
    for version,binaries in sorted(discover_typescript(root).items()):
        source=pathlib.Path('/src/typescript-'+version)
        subprocess.run(['git','clone','--depth','1','--branch','typescript/v'+version,
            'https://github.com/microsoft/typescript-go.git',str(source)],check=True)
        subprocess.run(['python3','/usr/local/lib/patch-go-deps.py','/usr/local/lib/go-security-floors.json',
            '/out/typescript-security-'+version+'.json'],cwd=source,check=True)
        candidate=pathlib.Path('/out/tsc-'+version)
        subprocess.run(['go','build','-trimpath','-o',str(candidate),'./cmd/tsgo'],cwd=source,check=True)
        if subprocess.check_output([str(candidate),'--version'],text=True).strip()!='Version '+version:
            raise RuntimeError('Native TypeScript API version changed')
        subprocess.run(['go','test','./internal/core','./internal/tspath'],cwd=source,check=True)
        samples=['export const answer: number = 42;',
            'export function hello(value: string): string { return "世界 " + value; }',
            'export interface Value { key: string }; export const value: Value = { key: "stable" };']
        for original in binaries:
            for sample in samples:
                if typescript_output(original,sample)!=typescript_output(candidate,sample):
                    raise RuntimeError('Same-version TypeScript emit regression')
            target=output/original.relative_to(root)
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copy2(candidate,target)
        typescript.append({'version':version,'copies':len(binaries),
            'commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip(),
            'sha256':hashlib.sha256(candidate.read_bytes()).hexdigest(),
            'security':json.loads(pathlib.Path('/out/typescript-security-'+version+'.json').read_text())})
    if not entries:
        raise RuntimeError('No native esbuild binaries discovered')
    pathlib.Path('/out/native-compilers.json').write_text(json.dumps({
        'goVersion': subprocess.check_output(['go', 'version'], text=True).strip(),
        'esbuild': entries, 'typescript':typescript}, sort_keys=True))


if __name__ == '__main__':
    main()
