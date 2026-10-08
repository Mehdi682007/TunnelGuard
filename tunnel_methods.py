"""Typed two-node transport plans. Proxy protocols are deliberately not catalog items."""
import base64
import hashlib
import ipaddress
import json
import re
import secrets
import subprocess
import tempfile
from pathlib import Path

METHODS = {
    'ssh': ('SSH', 'TCP / SSH', 'native'),
    'rathole': ('Rathole', 'TCP / Noise / Chisel channel', 'carrier'),
    'chisel': ('Chisel', 'HTTP / WebSocket / SSH', 'native'),
    'wireguard': ('WireGuard', 'L3 / UDP', 'carrier'),
    'paqet': ('Paqet', 'Raw TCP / KCP', 'carrier'),
    'spoof': ('Spoof', 'Raw TCP or UDP / encrypted overlay', 'carrier'),
    'ipip': ('IPIP', 'L3 / IP protocol 4', 'symmetric'),
    'gre': ('GRE', 'L3 / IP protocol 47', 'symmetric'),
    'vxlan': ('VXLAN', 'L2 / UDP', 'symmetric'),
}


def ipv4(value):
    address = ipaddress.IPv4Address(value)
    if address.is_unspecified or address.is_multicast or int(address) == 0xffffffff:
        raise ValueError('Unicast IPv4 required')
    return str(address)


def request(data):
    if not isinstance(data, dict): raise ValueError('Object required')
    name = data.get('name', '')
    if not isinstance(name, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,23}', name):
        raise ValueError('Name: lowercase letters, digits, hyphen; max 24')
    method, direction = data.get('method'), data.get('direction')
    if method not in METHODS or direction not in ('direct', 'reverse'):
        raise ValueError('Unsupported method or direction')
    mtu = data.get('mtu', 1280)
    if type(mtu) is not int or not 1000 <= mtu <= 1400: raise ValueError('MTU 1000..1400 required')
    result = dict(name=name, method=method, direction=direction, mtu=mtu)
    if method == 'spoof':
        result.update(iran_source=ipv4(data['iran_source']), exit_source=ipv4(data['exit_source']))
        for key in ('uplink', 'downlink'):
            if data.get(key, 'tcp') not in ('tcp', 'udp'): raise ValueError('TCP/UDP carrier required')
            result[key] = data.get(key, 'tcp')
    return result


def fingerprint(private):
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder)/'key'
        path.write_text(private); path.chmod(0o600)
        public = subprocess.run(['ssh-keygen','-y','-f',str(path)],check=True,capture_output=True).stdout.decode().split()
    return base64.b64encode(hashlib.sha256(base64.b64decode(public[1])).digest()).decode(), ' '.join(public[:2])


def make_plan(data, pair, slot):
    p = request(data)
    if type(slot) is not int or not 1 <= slot <= 199: raise ValueError('No free slots')
    p.update(schema=1, slot=slot, iran=ipv4(pair['iran']), exit=ipv4(pair['exit']),
             port=23000+slot*10, socks_port=30000+slot,
             interface='tg'+hashlib.sha256(p['name'].encode()).hexdigest()[:10],
             token=secrets.token_urlsafe(32))
    p['server_role'] = 'exit' if p['direction']=='direct' else 'iran'
    if p['method']=='ssh':
        with tempfile.TemporaryDirectory() as folder:
            key=Path(folder)/'key'
            subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True,capture_output=True)
            p['private_key']=key.read_text()
        p['fingerprint'],p['public_key']=fingerprint(p['private_key'])
        p['ssh_port']=pair.get('ssh_port',22)
    else:
        p['private_key']=subprocess.run(['openssl','ecparam','-name','prime256v1','-genkey','-noout'],check=True,capture_output=True).stdout.decode()
        p['fingerprint'],_=fingerprint(p['private_key'])
    if p['method']=='rathole':
        from deploy_wireguard import keypair
        p['noise_private'],p['noise_public']=keypair()
    if p['method']=='wireguard':
        import deploy_wireguard as wg
        p['wg_server_private'],p['wg_server_public']=wg.keypair()
        p['wg_client_private'],p['wg_client_public']=wg.keypair()
    if p['method']=='spoof':
        import deploy_spoof as spoof
        srv=p['server_role'];client='exit' if srv=='iran' else 'iran';b=p['port']
        settings=dict(version=spoof.VERSION,server_ip=p[srv],client_ip=p[client],server_source=p[srv+'_source'],client_source=p[client+'_source'],uplink=p['uplink'],downlink=p['downlink'],server_port=b+1,client_port=b+4,overlay_port=b+5,bridge_port=b+6,socks_port=b+2)
        with tempfile.TemporaryDirectory() as temp:
            server=Path(temp)/'server';client=Path(temp)/'client'
            spoof.generate_server(server,settings)
            spoof.generate_client(client,server/'pairing.json')
            p.update(spoof_settings=settings,spoof_server=json.loads((server/'overlay.json').read_text()),spoof_client=json.loads((client/'overlay.json').read_text()))
    return p


def validate_plan(p):
    normalized=request(p)
    if p.get('schema')!=1 or any(p[k]!=v for k,v in normalized.items()): raise ValueError('Invalid plan')
    slot=p['slot']
    if type(slot) is not int or not 1<=slot<=199: raise ValueError('Invalid slot')
    for k in ('iran','exit'): ipv4(p[k])
    if p['port']!=23000+slot*10 or p['socks_port']!=30000+slot: raise ValueError('Invalid allocated ports')
    if p['interface']!='tg'+hashlib.sha256(p['name'].encode()).hexdigest()[:10]: raise ValueError('Invalid interface')
    if p['server_role']!=('exit' if p['direction']=='direct' else 'iran'): raise ValueError('Invalid role')
    if not re.fullmatch(r'[A-Za-z0-9_-]{40,64}',p['token']): raise ValueError('Invalid token')
    if p['method']=='ssh' and (type(p['ssh_port']) is not int or not 1<=p['ssh_port']<=65535): raise ValueError('SSH port')
    if p['method']=='rathole':
        for key in ('noise_private','noise_public'):
            if len(base64.b64decode(p[key],validate=True))!=32: raise ValueError('Invalid Noise key')
    return p


def public_plan(p):
    return {k:p[k] for k in ('name','method','direction','mtu','socks_port','slot')}


def catalog():
    return [dict(id=k,name=v[0],layer=v[1],reverse=v[2],directions=['direct','reverse']) for k,v in METHODS.items()]
