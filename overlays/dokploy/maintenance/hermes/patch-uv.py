import hashlib,pathlib,subprocess,tarfile,tempfile,urllib.request
from packaging.version import Version
current=subprocess.check_output(['uv','--version'],text=True).split()[1]
if Version(current)<Version('0.12.21'):
    with tempfile.TemporaryDirectory(prefix='hermes-uv-') as folder:
        archive=pathlib.Path(folder)/'uv.tar.gz'
        with urllib.request.urlopen('https://github.com/astral-sh/uv/releases/download/0.12.21/uv-x86_64-unknown-linux-musl.tar.gz',timeout=90) as r:archive.write_bytes(r.read())
        assert hashlib.sha256(archive.read_bytes()).hexdigest()=='d69d543a55ec9cdf9d3d9f2648b0a161847e3dbddc477e3be6b5813a6d46f639'
        with tarfile.open(archive) as tar:tar.extractall(folder,filter='data')
        for binary in ['uv','uvx']:
            subprocess.run(['install','-m','0755',folder+'/uv-x86_64-unknown-linux-musl/'+binary,'/usr/local/bin/'+binary],check=True)
