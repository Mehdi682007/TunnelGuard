"""Install paired tunnel management behind the existing authenticated HTTPS panel."""
import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess

import deploy
import tunnel_methods

ROOT=Path('/opt/tunnelguard-manager')
SOURCE=Path(__file__).resolve().parent


def bootstrap_guard(iran):
    """Fresh installations need no VMess/VLESS or other legacy proxy deployment."""
    prefix=Path('/opt/tunnelguard-node/client')
    unit=Path('/etc/systemd/system/tunnelguard-client-guard.service')
    if prefix.exists() or unit.exists(): raise ValueError('Partial guard installation exists; inspect it first')
    import manage
    cfg=manage.checked(dict(routes=[],profiles={'All':[]},default_profile='All',targets=[dict(url='https://cp.cloudflare.com/generate_204',status=[204])]))
    prefix.mkdir(parents=True,mode=0o755);(prefix/'app').mkdir(mode=0o755)
    deploy.write_private(prefix/'config.json',cfg)
    for name in ('tunnelguard.py','engines.py','dashboard.html'):
        shutil.copy2(SOURCE/name,prefix/'app'/name);(prefix/'app'/name).chmod(0o644)
    deploy.write_private(unit,deploy.unit_text(prefix,'guard',True));unit.chmod(0o644)
    subprocess.run(['systemctl','daemon-reload'],check=True)
    subprocess.run(['systemctl','enable','--now',unit.name],check=True)
    ROOT.mkdir(mode=0o700,exist_ok=True)
    subprocess.run(['/usr/bin/python3',str(SOURCE/'publish_panel.py'),'--address',iran,'--output',str(ROOT/'panel'),'--apply'],check=True)


def install(mode,bundle=None,iran=None,exit=None,output=None):
    if os.geteuid()!=0: raise ValueError('Linux root required')
    config=ROOT/('controller.json' if mode=='controller' else 'agent.json')
    if config.exists(): raise ValueError('Already paired; use upgrade to preserve configuration')
    if mode=='controller':
        tunnel_methods.ipv4(iran);tunnel_methods.ipv4(exit)
        if not Path('/opt/tunnelguard-node/client/config.json').exists(): bootstrap_guard(iran)
        cfg=json.loads(Path('/opt/tunnelguard-node/client/config.json').read_text())
        if not cfg.get('dashboard_tls') or not cfg.get('dashboard_auth_sha256'): raise ValueError('Publish authenticated HTTPS panel first')
        tunnel_methods.ipv4(iran);tunnel_methods.ipv4(exit)
        if cfg.get('dashboard_address')!=iran: raise ValueError('Panel certificate/address must match Iran IP')
        if output is None or output.exists(): raise ValueError('New output file required')
        token=secrets.token_urlsafe(32)
        data=dict(iran=iran,exit=exit,peer_token=token,iran_host_key=' '.join(Path('/etc/ssh/ssh_host_ed25519_key.pub').read_text().split()[:2]))
        export=dict(schema=1,url=f'https://{iran}:{cfg["dashboard_port"]}',peer_token=token,certificate=cfg['dashboard_tls']['certificate'])
    else:
        if bundle is None or bundle.stat().st_size>32768: raise ValueError('Pairing file required')
        data=json.loads(bundle.read_text())
        import urllib.parse,ssl
        url=urllib.parse.urlsplit(data['url'])
        if url.scheme!='https' or url.username or url.path: raise ValueError('HTTPS origin required')
        tunnel_methods.ipv4(url.hostname)
        if data.get('schema')!=1 or len(data['peer_token'])<40: raise ValueError('Invalid bundle')
        ssl.create_default_context(cadata=data['certificate'])
    ROOT.mkdir(mode=0o700,exist_ok=True)
    deploy.write_private(config,data)
    if mode=='controller': deploy.write_private(output,export)
    upgrade(mode)


def upgrade(mode):
    (ROOT/'app').mkdir(mode=0o755,exist_ok=True)
    for p in SOURCE.glob('*.py'):
        if p.resolve()!=(ROOT/'app'/p.name).resolve(): shutil.copy2(p,ROOT/'app'/p.name)
    if (SOURCE/'dashboard.html').resolve()!=(ROOT/'app'/'dashboard.html').resolve():
        shutil.copy2(SOURCE/'dashboard.html',ROOT/'app'/'dashboard.html')
    if mode=='controller':
        subprocess.run(['groupadd','--system','tunnelguard-control'],capture_output=True)
        drop=Path('/etc/systemd/system/tunnelguard-client-guard.service.d')
        drop.mkdir(exist_ok=True)
        if not (drop/'manager.conf').exists():
            deploy.write_private(drop/'manager.conf','[Service]\nSupplementaryGroups=tunnelguard-control\n')
    unit=Path('/etc/systemd/system')/f'tunnelguard-manager-{mode}.service'
    runtime='RuntimeDirectory=tunnelguard-manager\nRuntimeDirectoryMode=0750\nGroup=tunnelguard-control\n' if mode=='controller' else ''
    deploy.write_private(unit,f'''[Unit]
Description=TunnelGuard paired {mode}
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/usr/bin/python3 {ROOT}/app/tunnel_manager.py {'serve' if mode=='controller' else 'agent'}
Restart=always
RestartSec=5
UMask=0077
{runtime}[Install]
WantedBy=multi-user.target
''')
    unit.chmod(0o644)
    subprocess.run(['systemctl','daemon-reload'],check=True)
    subprocess.run(['systemctl','enable','--now',unit.name],check=True)
    subprocess.run(['systemctl','restart',unit.name],check=True)
    if mode=='controller':
        import maintenance
        with maintenance.locked(): maintenance.upgrade('client')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=['controller','agent'])
    parser.add_argument('--iran');parser.add_argument('--exit');parser.add_argument('--bundle',type=Path)
    parser.add_argument('--output',type=Path);parser.add_argument('--upgrade',action='store_true')
    args=parser.parse_args()
    if args.upgrade: upgrade(args.mode)
    else: install(args.mode,args.bundle,args.iran,args.exit,args.output)
    print('Manager installed. Pair the other node, then use the HTTPS panel. Keep pairing private.')
