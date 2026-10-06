"""Paired userspace WireGuard through sing-box; no kernel routes, NAT or sysctl changes."""
import argparse
import base64
import ipaddress
import json
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile

import deploy
import maintenance as m
import manage


def keypair():
    private=subprocess.run(['openssl','genpkey','-algorithm','X25519','-outform','DER'],capture_output=True,check=True).stdout
    public=subprocess.run(['openssl','pkey','-inform','DER','-pubout','-outform','DER'],input=private,capture_output=True,check=True).stdout
    if len(private)!=48 or len(public)!=44:
        raise ValueError('Unexpected X25519 encoding')
    return base64.b64encode(private[-32:]).decode(),base64.b64encode(public[-32:]).decode()


def validate(b):
    if b.get('schema')!=1 or b.get('kind')!='wireguard' or b.get('core_version')!=deploy.VERSION:
        raise ValueError('Wrong WireGuard bundle')
    ipaddress.IPv4Address(b['address'])
    for k in ('port','socks_port','bridge_port'):
        if type(b[k]) is not int or not 1024<=b[k]<=65535 or b[k] in (1088,8787): raise ValueError('Invalid port')
    for k in ('client_private','client_public','server_public'):
        if len(base64.b64decode(b[k],validate=True))!=32: raise ValueError('Invalid key')
    return b


def configs(b, server_private=None):
    validate(b)
    server=dict(log={'level':'warn'},inbounds=[dict(type='socks',tag='bridge',listen='127.0.0.1',listen_port=b['bridge_port'])],endpoints=[dict(type='wireguard',tag='wg',system=False,mtu=1280,address=['10.77.0.1/30'],private_key=server_private or '',listen_port=b['port'],peers=[dict(public_key=b['client_public'],allowed_ips=['10.77.0.2/32'])])],outbounds=[dict(type='direct',tag='direct')],route={'rules':[dict(inbound=['wg'],action='route',outbound='direct',override_address='127.0.0.1',override_port=b['bridge_port'])],'final':'direct'})
    client=dict(log={'level':'warn'},inbounds=[dict(type='socks',listen='127.0.0.1',listen_port=b['socks_port'])],
        endpoints=[dict(type='wireguard',tag='wg',system=False,mtu=1280,address=['10.77.0.2/30'],private_key=b['client_private'],peers=[dict(address=b['address'],port=b['port'],public_key=b['server_public'],allowed_ips=['0.0.0.0/0'],persistent_keepalive_interval=20)])],
        outbounds=[dict(type='socks',tag='exit',server='10.77.0.1',server_port=b['bridge_port'],version='5',detour='wg')],route={'final':'exit'})
    return server,client


def apply(folder, role, b, archive=None):
    target='wireguard-'+role
    prefix=m.TARGETS[target][0]
    unit=m.UNITS/f'tunnelguard-{target}-core.service'
    if prefix.exists() or unit.exists(): raise ValueError('Existing installation; use maintenance')
    cfg=json.loads((folder/'core.json').read_text())
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM if role=='server' else socket.SOCK_STREAM) as probe:
        probe.bind(('0.0.0.0' if role=='server' else '127.0.0.1', b['port'] if role=='server' else b['socks_port']))
    if role=='server':
        with socket.socket() as probe: probe.bind(('127.0.0.1', b['bridge_port']))
    guard=None
    if role=='client':
        guard=manage.attach(manage.load_config(manage.CONFIG),[dict(name='wireguard',proxy=f'socks5h://127.0.0.1:{b["socks_port"]}',priority=90,layer='WireGuard-UDP')],'WireGuard')
    binary=deploy.install_core(folder,archive)
    m.run(str(binary),'check','-c',str(folder/'core.json'))
    prefix.parent.mkdir(mode=0o755,exist_ok=True)
    prefix.mkdir(mode=0o755)
    try:
        shutil.copy2(binary,prefix/'sing-box')
        shutil.copy2(folder/'core.json',prefix/'core.json')
        deploy.write_private(unit,deploy.unit_text(prefix,'core'))
        unit.chmod(0o644)
        m.run('systemctl','daemon-reload')
        m.run('systemctl','enable','--now',unit.name)
        m.restart([unit.name])
        if guard:
            m.transaction('client',{'config.json':json.dumps(guard).encode()})
    except BaseException:
        subprocess.run(['systemctl','disable','--now',unit.name],capture_output=True)
        unit.unlink(missing_ok=True)
        m.run('systemctl','daemon-reload')
        shutil.rmtree(prefix)  # Newly created fixed installation path only.
        raise


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('role',choices=['server','client'])
    p.add_argument('--address')
    p.add_argument('--port',type=int,default=18450)
    p.add_argument('--socks-port',type=int,default=11010)
    p.add_argument('--bridge-port',type=int,default=11011)
    p.add_argument('--bundle',type=Path)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--core-archive',type=Path)
    p.add_argument('--apply',action='store_true')
    a=p.parse_args()
    try:
        if a.output.exists(): raise ValueError('Output exists')
        if a.role=='server':
            if not a.address: p.error('--address required')
            server_private,server_public=keypair()
            client_private,client_public=keypair()
            b=validate(dict(schema=1,kind='wireguard',core_version=deploy.VERSION,address=a.address,port=a.port,socks_port=a.socks_port,bridge_port=a.bridge_port,server_public=server_public,client_private=client_private,client_public=client_public))
            server,client=configs(b,server_private)
        else:
            if not a.bundle: p.error('--bundle required')
            if a.bundle.stat().st_size>8192: raise ValueError('Oversize bundle')
            b=validate(json.loads(a.bundle.read_text()))
            server,client=configs(b)
        a.output.mkdir(mode=0o700,parents=True)
        deploy.write_private(a.output/'core.json',server if a.role=='server' else client)
        if a.role=='server': deploy.write_private(a.output/'pairing.json',b)
        if a.apply:
            with m.locked(): apply(a.output,a.role,b,a.core_archive)
        print('WireGuard configuration ready. Pairing contains a private client key; transfer only through trusted SSH.')
        print('Server requires configured UDP port. Firewall and OS routing unchanged. Validate end-to-end; UDP may be blocked.')
        return 0
    except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError):
        print('WireGuard deployment failed; inspect dependencies, pairing, ports and journal. Secrets are not printed.')
        return 1


if __name__=='__main__': raise SystemExit(main())
