"""Pinned official Linux archives, bounded downloads, no archive path extraction."""
import gzip
import hashlib
import os
from pathlib import Path
import platform
import zipfile
import tarfile
import tempfile
import urllib.request

ASSETS={
 'rathole': ('rathole-org/rathole','v0.5.0','rathole-{arch}.zip',{'amd64':'3e7d0d0f365120cd3cd351d147d1a12ee960c8068b464d4dd533a3821873b80e','arm64':'fa4a6fc63d86f8f1faa7c103a845e4715ce79a048455c0eec897b27237576564'}),
 'chisel': ('jpillora/chisel','v1.12.0','chisel_1.12.0_linux_{arch}.gz',{
  'amd64':'f3f180f1d93aa72cce4e6386f98cc06569a0146fbd65eb4423cf83e6434bcfe6',
  'arm64':'2ec6152cd2c74fe0146d4d79e4e7aa174521368c56e433d55e023a92ea404ec3'}),
 'paqet': ('hanselime/paqet','v1.0.0-alpha.21','paqet-linux-{arch}-v1.0.0-alpha.21.tar.gz',{
  'amd64':'4f2f69e0493746726598485ef18df43372470a1514f8021594137e522f0f4fc7',
  'arm64':'be5c7b35a0a93832063e1dc7fddeb76d4597fb9de76abdfdf7b8574b775e3885'}),
}
ROOT=Path('/opt/tunnelguard-manager')


def ensure(name):
    folder=ROOT/'bin'; folder.mkdir(parents=True,exist_ok=True,mode=0o755)
    dest=folder/name
    record=folder/(name+'.sha256')
    if dest.exists():
        if not record.exists() or hashlib.sha256(dest.read_bytes()).hexdigest()!=record.read_text().strip():
            raise ValueError('Installed binary integrity mismatch')
        return dest
    arch={'x86_64':'amd64','aarch64':'arm64'}.get(platform.machine())
    if arch is None: raise ValueError('Linux amd64/arm64 required')
    with tempfile.TemporaryDirectory(dir=folder) as temp:
        stage=Path(temp)
        if name=='sing-box':
            import deploy
            binary=deploy.install_core(stage, (ROOT/'cache'/'sing-box.tar.gz') if (ROOT/'cache'/'sing-box.tar.gz').exists() else None)
        elif name=='spoof':
            import deploy_spoof
            binary=deploy_spoof.install_binary(stage, (ROOT/'cache'/'spoof') if (ROOT/'cache'/'spoof').exists() else None)
        else:
            repo,version,pattern,hashes=ASSETS[name]
            filename=pattern.format(arch=({'amd64':'x86_64-unknown-linux-gnu','arm64':'aarch64-unknown-linux-musl'}[arch] if name=='rathole' else arch))
            cached=ROOT/'cache'/filename
            archive=stage/filename
            if cached.exists():
                if cached.stat().st_size>100*1024*1024: raise ValueError('Oversized cache')
                archive.write_bytes(cached.read_bytes())
            else:
                with urllib.request.urlopen(f'https://github.com/{repo}/releases/download/{version}/{filename}',timeout=45) as src, archive.open('wb') as dst:
                    total=0
                    while chunk:=src.read(1024*1024):
                        total+=len(chunk)
                        if total>100*1024*1024: raise ValueError('Oversized download')
                        dst.write(chunk)
            if hashlib.sha256(archive.read_bytes()).hexdigest()!=hashes[arch]: raise ValueError('Archive SHA256 mismatch')
            binary=stage/name
            if filename.endswith('.zip'):
                with zipfile.ZipFile(archive) as z:
                    matches=[m for m in z.infolist() if not m.is_dir() and Path(m.filename).name==name]
                    if len(matches)!=1 or matches[0].file_size>150*1024*1024: raise ValueError('Unexpected ZIP archive')
                    binary.write_bytes(z.read(matches[0]))
            elif filename.endswith('.tar.gz'):
                with tarfile.open(archive) as tar:
                    matches=[m for m in tar.getmembers() if m.isfile() and Path(m.name).name.startswith('paqet') and not Path(m.name).suffix]
                    if len(matches)!=1 or matches[0].size>150*1024*1024: raise ValueError('Unexpected archive')
                    binary.write_bytes(tar.extractfile(matches[0]).read())
            else:
                with gzip.open(archive) as src:
                    data=src.read(150*1024*1024+1)
                    if len(data)>150*1024*1024: raise ValueError('Oversized binary')
                    binary.write_bytes(data)
        binary.chmod(0o755)
        os.replace(binary,dest)
        record.write_text(hashlib.sha256(dest.read_bytes()).hexdigest())
        record.chmod(0o600)
    return dest
