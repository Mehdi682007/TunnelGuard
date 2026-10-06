"""Add VMess/WebSocket/TLS, VLESS/TLS, TUIC and AnyTLS to an existing standard pair."""
import argparse
import json
from pathlib import Path
import socket
import secrets
import subprocess
import uuid

import deploy
import maintenance as m
import manage


def free_ports(configs):
    sockets=[]
    try:
        for cfg in configs:
            for entry in cfg['inbounds']:
                host=entry['listen']
                s=socket.socket(socket.AF_INET6 if ':' in host else socket.AF_INET, socket.SOCK_DGRAM if entry['type']=='tuic' else socket.SOCK_STREAM)
                sockets.append(s)
                s.bind((host, entry['listen_port']))
    finally:
        for s in sockets: s.close()


def server(a):
    prefix=m.TARGETS['server'][0]
    cfg=json.loads((prefix/'server.json').read_text())
    if {i['type'] for i in cfg['inbounds']} != set(deploy.KINDS) or len(cfg['inbounds']) != 3:
        raise ValueError('Requires original three-transport server')
    entries={i['type']:i for i in cfg['inbounds']}
    b=dict(schema=1,core_version=deploy.VERSION,address=a.address,
           ports={k:i['listen_port'] for k,i in entries.items()},
           passwords={k:(i['password'] if k=='shadowsocks' else i['users'][0]['password']) for k,i in entries.items()},
           certificate='\n'.join(entries['trojan']['tls']['certificate'])+'\n',
           uuids={k:str(uuid.uuid4()) for k in deploy.EXTRAS}, extra_passwords={k:secrets.token_urlsafe(32) for k in ('tuic','anytls')})
    b['ports'].update(zip(deploy.EXTRAS,a.ports))
    generated,_,_=deploy.configs(b,'\n'.join(entries['trojan']['tls']['key']))
    additions=[i for i in generated['inbounds'] if i['type'] in deploy.EXTRAS]
    free_ports([dict(inbounds=additions)])
    cfg['inbounds'].extend(additions)
    a.output.mkdir(mode=0o700,parents=True)
    # Persist the pairing bundle before touching live service state.
    deploy.write_private(a.output/'pairing.json',b)
    deploy.write_private(a.output/'server.json',cfg)
    if a.apply:
        identity=m.transaction('server',{'server.json':json.dumps(cfg).encode()})
        print('Server snapshot:',identity)


def client(a):
    if a.bundle.stat().st_size > 32768: raise ValueError('Oversize bundle')
    b=json.loads(a.bundle.read_text())
    if 'vmess' not in b.get('ports',{}): raise ValueError('Bundle has no extra transports')
    _,clients,guard=deploy.configs(b,local_base=a.local_base)
    prefix=m.TARGETS['client'][0]
    for k in deploy.EXTRAS:
        if (prefix/f'{k}.json').exists() or (m.UNITS/f'tunnelguard-client-{k}.service').exists():
            raise ValueError('Extra transport already installed')
    # Prevent accidental pairing with a different existing exit.
    for k in deploy.KINDS:
        old=json.loads((prefix/f'{k}.json').read_text())['outbounds'][0]
        if old['server'] != b['address'] or old['server_port'] != b['ports'][k] or old['password'] != b['passwords'][k]:
            raise ValueError('Existing client does not match this pair')
    cfg=manage.attach(manage.load_config(manage.CONFIG),[r for r in guard['routes'] if r['name'] in deploy.EXTRAS],'Extra')
    free_ports([clients[k] for k in deploy.EXTRAS])
    a.output.mkdir(mode=0o700,parents=True)
    for k in deploy.EXTRAS:
        deploy.write_private(a.output/f'{k}.json',clients[k])
    deploy.write_private(a.output/'config.json',cfg)
    if not a.apply: return
    changes={f'{k}.json':json.dumps(clients[k]).encode() for k in deploy.EXTRAS}
    changes['config.json']=json.dumps(cfg).encode()
    identity=m.transaction('client',changes)
    try:
        for k in deploy.EXTRAS:
            unit=m.UNITS/f'tunnelguard-client-{k}.service'
            deploy.write_private(unit,deploy.unit_text(prefix,k))
            unit.chmod(0o644)
        m.run('systemctl','daemon-reload')
        for k in deploy.EXTRAS:
            m.run('systemctl','enable','--now',f'tunnelguard-client-{k}')
        m.restart([f'tunnelguard-client-{k}.service' for k in deploy.EXTRAS])
    except BaseException:
        m.restore(identity,'client')
        raise
    print('Client snapshot:',identity)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('role',choices=['server','client'])
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--address')
    p.add_argument('--bundle',type=Path)
    p.add_argument('--ports',type=int,nargs=4,default=[18446,18447,18448,18449])
    p.add_argument('--local-base',type=int,default=11001)
    p.add_argument('--apply',action='store_true')
    a=p.parse_args()
    if a.role=='server' and not a.address: p.error('--address required')
    if a.role=='client' and not a.bundle: p.error('--bundle required')
    try:
        if a.output.exists(): raise ValueError('Output already exists')
        with m.locked():
            (server if a.role=='server' else client)(a)
        print('Applied.' if a.apply else 'Generated only. Use a new output directory with --apply to install.')
        print('Application forwarding is TCP. Open configured TCP ports and TUIC UDP port; firewall unchanged.')
        return 0
    except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError):
        print('Extra transport deployment failed; inspect pairing, ports and service state. Secrets are not printed.')
        return 1


if __name__=='__main__': raise SystemExit(main())
