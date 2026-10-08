"""Apply a validated transport plan on one Linux node; all commands use argv lists."""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time

import deploy
import tunnel_assets as assets
from tunnel_methods import validate_plan

ROOT=Path('/opt/tunnelguard-manager')
UNITS=Path('/etc/systemd/system')


def run(*args):
    return subprocess.run([str(a) for a in args],check=True,capture_output=True,timeout=45)


def paths(p):
    validate_plan(p)
    folder=ROOT/'tunnels'/p['name']
    return folder,UNITS/f'tunnelguard-link-{p["name"]}.service'


def netinfo(peer):
    route=json.loads(run('ip','-j','route','get',peer).stdout)[0]
    interface=route['dev']; gateway=route.get('gateway',peer)
    # A bounded UDP datagram triggers neighbour resolution without shell parsing.
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
        sock.sendto(b'\0',(gateway,9))
    for _ in range(15):
        entries=json.loads(run('ip','-j','neigh','show','to',gateway,'dev',interface).stdout)
        if entries and entries[0].get('lladdr'):
            return interface,route.get('prefsrc',route.get('src')),entries[0]['lladdr']
        time.sleep(.2)
    raise ValueError('Gateway MAC unresolved; check layer-2 connectivity')


def write(path,data):
    deploy.write_private(path,data)


def configure(p,role,folder):
    """Only writes this instance's files. Does not modify host networking."""
    server=role==p['server_role']; base=p['port']; method=p['method']
    peer=p['exit' if role=='iran' else 'iran']
    write(folder/'key',p['private_key'])
    allowed = [f'^R:127\\.0\\.0\\.1:{p["socks_port"]}$'] if p['direction']=='reverse' else ['^socks$']
    if method!='rathole': write(folder/'auth.json',{'tg:'+p['token']:allowed})
    if method=='rathole':
        import tunnel_rathole
        tunnel_rathole.configure(p,role,folder)
    if method=='wireguard':
        import deploy_wireguard as wg
        bundle=dict(schema=1,kind='wireguard',core_version=deploy.VERSION,address=p[p['server_role']],port=base+1,socks_port=base+2,bridge_port=base+3,
                    server_public=p['wg_server_public'],client_private=p['wg_client_private'],client_public=p['wg_client_public'])
        configs=wg.configs(bundle,p['wg_server_private'])
        write(folder/'core.json',configs[0 if server else 1])
    elif method=='spoof':
        import deploy_spoof as spoof
        # Generate once on the coordinator and ship the authenticated TLS overlay.
        s=p['spoof_settings']
        write(folder/'carrier.json',spoof.carrier(s,'server' if server else 'client'))
        write(folder/'core.json',p['spoof_server' if server else 'spoof_client'])
    elif method=='paqet':
        interface,local,mac=netinfo(peer)
        cfg=dict(role='server' if server else 'client',log={'level':'warn'},network=dict(interface=interface,ipv4=dict(addr=f'{local}:{base+1}',router_mac=mac)),
                 transport=dict(protocol='kcp',kcp=dict(mode='fast',block='aes',key=p['token'],mtu=min(p['mtu'],1350))))
        if server: cfg['listen']={'addr':f':{base+1}'}
        else: cfg.update(server={'addr':f'{peer}:{base+1}'},socks5=[{'listen':f'127.0.0.1:{base+2}'}])
        # JSON is a YAML subset and avoids interpolation of interface/address values.
        write(folder/'paqet.yaml',cfg)
    elif method=='ssh':
        if not server:
            host=peer if p['ssh_port']==22 else f'[{peer}]:{p["ssh_port"]}'
            write(folder/'known_hosts',host+' '+p['ssh_host_key']+'\n')
    if method in ('wireguard','spoof'):
        run(assets.ensure('sing-box'),'check','-c',folder/'core.json')


def ssh_receiver(p,role):
    if role!=p['server_role']: return
    account=p['interface']; home=Path('/var/lib')/account
    conf=Path('/etc/ssh/sshd_config.d')/f'80-{account}.conf'
    if conf.exists(): return  # Only reachable after manifest equality validation.
    if home.exists() or subprocess.run(['id',account],capture_output=True).returncode==0:
        raise ValueError('SSH account collision')
    run('useradd','--system','--create-home','--home-dir',home,'--shell','/usr/sbin/nologin',account)
    auth=home/'.ssh/authorized_keys'
    try:
        run('install','-d','-m','700','-o',account,'-g',account,auth.parent)
        write(auth,f'from="{p["exit" if role=="iran" else "iran"]}",restrict,port-forwarding,command="/usr/bin/false" {p["public_key"]}\n')
        run('chown',f'{account}:{account}',auth)
        direction='remote' if p['direction']=='reverse' else 'local'
        permit=f'    PermitListen 127.0.0.1:{p["socks_port"]}\n' if direction=='remote' else ''
        write(conf,f'Match User {account}\n    AuthenticationMethods publickey\n    PasswordAuthentication no\n    KbdInteractiveAuthentication no\n    AllowTcpForwarding {direction}\n    AllowStreamLocalForwarding no\n{permit}    GatewayPorts no\n    PermitTTY no\n    PermitTunnel no\n    AllowAgentForwarding no\n    X11Forwarding no\n    ClientAliveInterval 10\n    ClientAliveCountMax 3\n    ForceCommand /usr/bin/false\nMatch all\n')
        conf.chmod(0o644)
        run('/usr/sbin/sshd','-t');run('systemctl','reload','ssh')
    except BaseException:
        conf.unlink(missing_ok=True)
        subprocess.run(['userdel',account],capture_output=True)
        if home.exists(): shutil.rmtree(home)
        raise


def apply(p,role):
    folder,unit=paths(p)
    if role not in ('iran','exit'): raise ValueError('Invalid role')
    if folder.exists():
        if json.loads((folder/'plan.json').read_text())!=p: raise ValueError('Name already belongs to another plan')
        run('systemctl','start',unit.name)
        run('systemctl','is-active','--quiet',unit.name)
        return
    if unit.exists(): raise ValueError('Unit collision')
    method=p['method']
    if method in ('ipip','gre','vxlan') and subprocess.run(['ip','link','show',p['interface']],capture_output=True).returncode==0:
        raise ValueError('Network interface collision')
    binaries=['chisel'] if method!='ssh' else []
    if method=='rathole': binaries.append('rathole')
    if method=='paqet': binaries.append('paqet')
    if method in ('spoof','wireguard'): binaries.append('sing-box')
    if method=='spoof': binaries.append('spoof')
    for binary in binaries: assets.ensure(binary)
    # Check all listeners before creating services; never steal an existing port.
    checks=[]
    server=role==p['server_role']
    if method not in ('ssh','rathole') and server: checks.append(('127.0.0.1' if method in ('paqet','wireguard','spoof') else '0.0.0.0',p['port'],False))
    if method=='rathole':
        checks += [('0.0.0.0',p['port']+1,False),('127.0.0.1',p['port']+3,False)] if server else [('127.0.0.1',p['port'],False)]
    if role=='iran': checks.append(('127.0.0.1',p['socks_port'],False))
    if not server and method in ('paqet','wireguard','spoof'): checks.append(('127.0.0.1',p['port']+2,False))
    if method=='wireguard' and server: checks += [('0.0.0.0',p['port']+1,True),('127.0.0.1',p['port']+3,False)]
    for host,port,udp in checks:
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as s: s.bind((host,port))
    folder.mkdir(parents=True,mode=0o700)
    write(folder/'plan.json',p);write(folder/'role',role)
    try:
        configure(p,role,folder)
        if method=='ssh': ssh_receiver(p,role)
        text=f'''[Unit]
Description=TunnelGuard link {p['name']}
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0
[Service]
ExecStart=/usr/bin/python3 {ROOT}/app/tunnel_runtime.py {folder}
Restart=always
RestartSec=5
KillMode=control-group
TimeoutStopSec=15
UMask=0077
NoNewPrivileges=yes
ProtectHome=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths={folder}
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
[Install]
WantedBy=multi-user.target
'''
        write(unit,text);unit.chmod(0o644)
        run('systemd-analyze','verify',unit);run('systemctl','daemon-reload')
        run('systemctl','enable','--now',unit.name)
        time.sleep(2);run('systemctl','is-active','--quiet',unit.name)
    except BaseException:
        try: remove(p,role)
        except BaseException: pass  # Preserve the original exception and manifest for recovery.
        raise


def remove(p,role):
    folder,unit=paths(p)
    if not folder.exists(): return
    if json.loads((folder/'plan.json').read_text())!=p: raise ValueError('Manifest mismatch')
    subprocess.run(['systemctl','disable','--now',unit.name],capture_output=True)
    # Runtime cleanup normally runs on SIGTERM; recover leftovers after crashes too.
    from tunnel_runtime import cleanup
    cleanup(p,role)
    if p['method']=='ssh' and role==p['server_role']:
        conf=Path('/etc/ssh/sshd_config.d')/f'80-{p["interface"]}.conf'
        conf.unlink(missing_ok=True)
        run('/usr/sbin/sshd','-t');run('systemctl','reload','ssh')
        subprocess.run(['userdel',p['interface']],capture_output=True)
        home=Path('/var/lib')/p['interface']
        if home.exists(): shutil.rmtree(home)
    unit.unlink(missing_ok=True);run('systemctl','daemon-reload')
    shutil.rmtree(folder)


if __name__=='__main__':
    p=json.loads(Path(sys.argv[2]).read_text())
    (apply if sys.argv[1]=='apply' else remove)(p,sys.argv[3])
