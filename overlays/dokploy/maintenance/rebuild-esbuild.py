#!/usr/bin/env python3
"""Recompile exact upstream esbuild versions; never upgrade the JS/API version."""
import hashlib, json, pathlib, re, shutil, subprocess


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
    if not entries:
        raise RuntimeError('No native esbuild binaries discovered')
    pathlib.Path('/out/native-compilers.json').write_text(json.dumps({
        'goVersion': subprocess.check_output(['go', 'version'], text=True).strip(),
        'esbuild': entries}, sort_keys=True))


if __name__ == '__main__':
    main()
