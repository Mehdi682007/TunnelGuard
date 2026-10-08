"""Supervise an outer carrier and encrypted forward/reverse channel as one service."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from tunnel_methods import validate_plan

ROOT=Path('/opt/tunnelguard-manager')


def run(*args,check=True):
    return subprocess.run([str(a) for a in args],check=check,capture_output=True,timeout=15)


def firewall(p,role,operation):
    if p['method']!='paqet': return
    port=str(p['port']+1);peer=p['exit' if role=='iran' else 'iran']
    comment=['-m','comment','--comment','tunnelguard-'+p['name']]
    rules=[('raw','PREROUTING',['-s',peer,'-p','tcp','--dport',port],['-j','NOTRACK']),
           ('raw','OUTPUT',['-d',peer,'-p','tcp','--sport',port],['-j','NOTRACK']),
           ('mangle','OUTPUT',['-d',peer,'-p','tcp','--sport',port,'--tcp-flags','RST','RST'],['-j','DROP'])]
    for table,chain,match,target in rules:
        args=['iptables','-w','5','-t',table]
        present=run(*args,'-C',chain,*match,*comment,*target,check=False).returncode==0
        if (operation=='add' and not present) or (operation=='del' and present):
            run(*args,'-A' if operation=='add' else '-D',chain,*match,*comment,*target)


def kernel(p,role):
    method=p['method'];name=p['interface'];local=p[role];peer=p['exit' if role=='iran' else 'iran']
    if method in ('ipip','gre'):
        args=['ip','tunnel','add',name,'mode',method,'local',local,'remote',peer,'ttl','64']
        if method=='gre': args += ['key',str(p['slot'])]
        run(*args)
    else:
        run('ip','link','add',name,'type','vxlan','id',str(10000+p['slot']),'local',local,'remote',peer,'dstport',str(p['port']+1),'nolearning')
    run('ip','addr','add',f'10.203.{p["slot"]}.{1 if role=="iran" else 2}/30','dev',name)
    run('ip','link','set',name,'mtu',str(p['mtu']),'up')


def cleanup(p,role):
    if p['method'] in ('ipip','gre','vxlan'):
        run('ip','link','del',p['interface'],check=False)
    if p['method']=='paqet': firewall(p,role,'del')


def commands(p,role,folder):
    """Return commands and private environment; never emit either to the panel."""
    base=p['port'];method=p['method'];server=role==p['server_role']
    binary=lambda n:str(ROOT/'bin'/n)
    commands=[];env=dict(os.environ)
    if method=='ssh':
        if server: return [],env
        peer=p[p['server_role']]
        args=['/usr/bin/ssh','-F','/dev/null','-NT','-i',str(folder/'key'),'-o',f'UserKnownHostsFile={folder}/known_hosts','-o','StrictHostKeyChecking=yes','-o','IdentitiesOnly=yes','-o','BatchMode=yes','-o','ExitOnForwardFailure=yes','-o','ServerAliveInterval=10','-o','ServerAliveCountMax=3','-o','ConnectTimeout=10','-p',str(p['ssh_port']),'-D' if p['direction']=='direct' else '-R',f'127.0.0.1:{p["socks_port"]}',f'{p["interface"]}@{peer}']
        return [args],env
    if method=='rathole':
        import tunnel_rathole
        env['AUTH']='tg:'+p['token']
        return tunnel_rathole.commands(p,role,folder,ROOT),env
    if method=='paqet': commands.append([binary('paqet'),'run','-c',str(folder/'paqet.yaml')])
    if method=='spoof': commands.append([binary('spoof'),'run','-c',str(folder/'carrier.json')])
    if method in ('spoof','wireguard'): commands.append([binary('sing-box'),'run','-c',str(folder/'core.json')])
    host='0.0.0.0';endpoint=p[p['server_role']];proxy=[]
    if method in ('paqet','wireguard','spoof'):
        host=endpoint='127.0.0.1'
        proxy=['--proxy',f'socks5://127.0.0.1:{base+2}']
    elif method in ('ipip','gre','vxlan'):
        host=f'10.203.{p["slot"]}.{1 if role=="iran" else 2}'
        endpoint=f'10.203.{p["slot"]}.{1 if p["server_role"]=="iran" else 2}'
    env['AUTH']='tg:'+p['token']
    if server:
        args=[binary('chisel'),'server','--host',host,'--port',str(base),'--keyfile',str(folder/'key'),'--authfile',str(folder/'auth.json'),'--keepalive','10s']
        args+=['--reverse'] if p['direction']=='reverse' else ['--socks5']
    else:
        remote=('R:' if p['direction']=='reverse' else '')+f'127.0.0.1:{p["socks_port"]}:socks'
        args=[binary('chisel'),'client','--fingerprint',p['fingerprint'],'--keepalive','10s',*proxy,f'http://{endpoint}:{base}',remote]
    commands.append(args)
    return commands,env


def main(folder):
    p=validate_plan(json.loads((folder/'plan.json').read_text()));role=(folder/'role').read_text().strip()
    children=[];stopping=False
    def stop(*_):
        nonlocal stopping
        stopping=True
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    try:
        if p['method'] in ('ipip','gre','vxlan'):
            # Only our unique, manifest-owned interface can be removed on restart.
            cleanup(p,role);kernel(p,role)
        firewall(p,role,'add')
        argv,env=commands(p,role,folder)
        for args in argv:
            children.append(subprocess.Popen(args,env=env))
            time.sleep(.3)
        while not stopping:
            if any(c.poll() is not None for c in children):
                if p['method']=='ssh':
                    time.sleep(3)
                    if not stopping: children=[subprocess.Popen(argv[0],env=env)]
                else: raise RuntimeError('Transport process exited')
            time.sleep(.5)
    finally:
        for child in children:
            if child.poll() is None: child.terminate()
        for child in children:
            try: child.wait(timeout=3)
            except subprocess.TimeoutExpired: child.kill();child.wait()
        cleanup(p,role)


if __name__=='__main__': main(Path(sys.argv[1]))
