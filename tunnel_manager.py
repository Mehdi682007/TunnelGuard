"""Root-owned Unix control service and outbound-only paired node agent.

The dashboard stays unprivileged. Only typed operations cross the local socket.
Peer credentials authorize its own job channel, never dashboard/admin operations.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import socketserver
import ssl
import subprocess
import threading
import time
import urllib.request
import tempfile

import deploy
import manage
import tunnel_methods as methods
import tunnel_node as node

ROOT=Path('/opt/tunnelguard-manager')
SOCKET='/run/tunnelguard-manager/control.sock'
LOCK=threading.RLock()
CONFIG={}
STATE={}


def save():
    import maintenance
    maintenance.atomic(ROOT/'state.json',json.dumps(STATE).encode())


def probe(p):
    result=subprocess.run(['curl','-q','--noproxy','','--proxy',f'socks5h://127.0.0.1:{p["socks_port"]}','--connect-timeout','5','--max-time','10','--silent','--output','/dev/null','--write-out','%{http_code}','https://cp.cloudflare.com/generate_204'],capture_output=True,timeout=15)
    return result.returncode==0 and result.stdout==b'204'


def attach(p):
    cfg=manage.load_config(manage.CONFIG)
    if any(r['name']==p['name'] for r in cfg['routes']): raise ValueError('Existing route name')
    route=dict(name=p['name'],proxy=f'socks5h://127.0.0.1:{p["socks_port"]}',priority=50,layer=p['method']+'-'+p['direction'])
    import math
    cfg['stale_after']=max(cfg['stale_after'],math.ceil((len(cfg['routes'])+1)*len(cfg['targets'])/cfg['probe_concurrency'])*(cfg['timeout']+3)+2)
    merged=manage.attach(cfg,[route],'Tunnels')
    # The profile contains all managed links, not only the most recent one.
    merged['profiles']['Tunnels']=[r['name'] for r in merged['routes'] if r['name'] in STATE['links']]
    manage.save_managed(merged)


def detach(p):
    cfg=manage.load_config(manage.CONFIG)
    if not any(r['name']==p['name'] for r in cfg['routes']): return
    # Never silently destroy a user's forward when removing its only route.
    import maintenance
    if len(cfg['routes'])==1 and not cfg.get('tcp_forwards'):
        cfg.update(routes=[],profiles={'All':[]},default_profile='All')
        manage.save_managed(cfg)
    else: manage.save_managed(maintenance.remove_spoof_route(cfg,p['name']))


def details(error):
    # Private diagnostics may contain paths/config data; never returned via API.
    with (ROOT/'operations.log').open('a',encoding='utf-8') as log:
        log.write(time.strftime('%Y-%m-%d %H:%M:%S')+' '+repr(error)+'\n')
        if isinstance(error,subprocess.CalledProcessError):
            log.write((error.stderr or b'').decode(errors='replace') if isinstance(error.stderr,bytes) else (error.stderr or ''))
    (ROOT/'operations.log').chmod(0o600)


def local_step(name,operation,next_phase):
    try:
        p=STATE['links'][name]['plan']
        if operation=='apply': node.apply(p,'iran')
        else: node.remove(p,'iran')
        with LOCK:
            item=STATE['links'][name]
            item['phase']=next_phase
            save()
        if next_phase=='finish': finish(name)
    except BaseException as error:
        details(error)
        with LOCK:
            item=STATE['links'][name]
            item.update(phase='failed',error='Local operation failed; see private operations.log')
            save()


def finish(name):
    p=STATE['links'][name]['plan']
    try:
        with LOCK: attach(p)
        healthy=probe(p)
        with LOCK:
            STATE['links'][name].update(phase='ready',last_test=healthy,tested_at=time.time())
            save()
    except BaseException as error:
        details(error)
        with LOCK:
            STATE['links'][name].update(phase='failed',error='Attach/test failed; remove both sides before retry')
            save()


def launch(name,op,next_phase):
    threading.Thread(target=local_step,args=(name,op,next_phase),daemon=True).start()


def status():
    return dict(available=True,peer_online=time.time()-STATE.get('heartbeat',0)<30,
                methods=methods.catalog(),links=[dict(**methods.public_plan(v['plan']),phase=v['phase'],last_test=v.get('last_test'),tested_at=v.get('tested_at'),error=v.get('error','')) for v in STATE['links'].values()])


def create(data):
    spec=methods.request(data)
    if time.time()-STATE.get('heartbeat',0)>30: raise ValueError('Outside node offline; pair it first')
    if any(v['phase'] not in ('ready','failed') for v in STATE['links'].values()): raise ValueError('Another operation is running')
    if spec['name'] in STATE['links']: raise ValueError('Name exists; remove before replacing')
    cfg=manage.load_config(manage.CONFIG)
    if len(cfg['routes'])>=64: raise ValueError('Maximum 64 configured routes')
    if any(r['name']==spec['name'] for r in cfg['routes']): raise ValueError('Route name exists')
    occupied={v['plan']['slot'] for v in STATE['links'].values()}
    slot=next((i for i in range(1,200) if i not in occupied),None)
    p=methods.make_plan(spec,CONFIG,slot)
    if p['method']=='ssh':
        p['ssh_host_key']=CONFIG['iran_host_key'] if p['server_role']=='iran' else STATE['exit_host_key']
    local_first=p['server_role']=='iran'
    STATE['links'][p['name']]=dict(plan=p,phase='local-install' if local_first else 'peer-install',peer_job=secrets.token_hex(16))
    save()
    if local_first: launch(p['name'],'apply','peer-install')
    return {'ok':True,'name':p['name']}


def delete(name):
    if name not in STATE['links']: raise ValueError('Unknown link')
    item=STATE['links'][name]
    if item['phase'] not in ('ready','failed'): raise ValueError('Operation running')
    # Preflight and save before teardown. Explicitly keep the only forward target.
    detach(item['plan'])
    item.update(phase='local-remove',peer_job=secrets.token_hex(16))
    save();launch(name,'remove','peer-remove')
    return {'ok':True}


def peer(data,authorization):
    expected='Bearer '+CONFIG['peer_token']
    if not secrets.compare_digest(authorization,expected): raise PermissionError('Invalid peer credential')
    key=data.get('host_key','')
    parts=key.split()
    if len(parts)!=2 or parts[0]!='ssh-ed25519' or len(base64.b64decode(parts[1],validate=True))!=51: raise ValueError('Invalid peer host key')
    if STATE.get('exit_host_key') not in (None,key): raise ValueError('Peer SSH host key changed')
    STATE['exit_host_key']=key;STATE['heartbeat']=time.time()
    result=data.get('result')
    if result:
        for name,item in list(STATE['links'].items()):
            if result.get('id')!=item['peer_job'] or item['phase'] not in ('peer-install','peer-remove'): continue
            if not result.get('ok'):
                item.update(phase='failed',error='Outside operation failed; inspect outside node journal, then remove both sides')
            elif item['phase']=='peer-remove': del STATE['links'][name]
            elif item['plan']['server_role']=='exit':
                item['phase']='local-install';launch(name,'apply','finish')
            else:
                item['phase']='finish';threading.Thread(target=finish,args=(name,),daemon=True).start()
            break
    save()
    for item in STATE['links'].values():
        if item['phase'] in ('peer-install','peer-remove'):
            return dict(job=dict(id=item['peer_job'],operation='apply' if item['phase']=='peer-install' else 'remove',plan=item['plan']))
    return {'job':None}


def dispatch(message):
    with LOCK:
        op=message.get('op')
        if op=='peer': return peer(message['data'],message.get('authorization',''))
        if op=='status': return status()
        data=message.get('data',{})
        if op=='create': return create(data)
        if op=='delete': return delete(data.get('name'))
        if op=='test':
            name=data.get('name');item=STATE['links'].get(name)
            if not item or item['phase']!='ready': raise ValueError('Link is not ready')
            def check():
                try:
                    ok=probe(item['plan'])
                    with LOCK: item.update(last_test=ok,tested_at=time.time());save()
                except Exception as e: details(e)
            threading.Thread(target=check,daemon=True).start()
            return {'ok':True}
        if op=='forward':
            if any(v['phase'] not in ('ready','failed') for v in STATE['links'].values()): raise ValueError('Wait for the link operation to finish')
            cfg=manage.load_config(manage.CONFIG)
            manage.add_forward(cfg,data['name'],data['listen_host'],data['listen_port'],data['target_host'],data['target_port'],data.get('routes'),data.get('public') is True,data.get('replace') is True)
            # Restarting the guard can briefly call back into the manager, so
            # never perform it while the request handler holds LOCK. Validate
            # first, then commit in a worker and expose the result in state.
            def commit():
                try:
                    current=manage.load_config(manage.CONFIG)
                    current=manage.add_forward(current,data['name'],data['listen_host'],data['listen_port'],data['target_host'],data['target_port'],data.get('routes'),data.get('public') is True,data.get('replace') is True)
                    manage.save_managed(current)
                    with LOCK: STATE['forward_result']='applied';save()
                except Exception as e:
                    details(e)
                    with LOCK: STATE['forward_result']='failed';save()
            threading.Thread(target=commit,daemon=True).start()
            return {'ok':True,'status':'pending','name':data['name'],'note':'Forward is applying; check the live forward list'}
        raise ValueError('Unknown operation')


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(15)
        raw=self.rfile.readline(131073)
        try:
            if len(raw)>131072: raise ValueError('Request too large')
            result=dispatch(json.loads(raw))
        except PermissionError: result={'error':'Unauthorized','status':401}
        except (ValueError,KeyError,TypeError,OSError) as error:
            details(error);result={'error':str(error) if isinstance(error,ValueError) else 'Invalid operation','status':400}
        self.wfile.write(json.dumps(result).encode()+b'\n')


def serve():
    global CONFIG,STATE
    CONFIG=json.loads((ROOT/'controller.json').read_text())
    STATE=json.loads((ROOT/'state.json').read_text()) if (ROOT/'state.json').exists() else {'links':{}}
    # Never rerun interrupted local mutations blindly after a daemon crash.
    for item in STATE['links'].values():
        if item['phase'] in ('local-install','local-remove','finish'):
            item.update(phase='failed',error='Interrupted local operation; inspect and remove both sides')
    Path(SOCKET).unlink(missing_ok=True)
    with socketserver.ThreadingUnixStreamServer(SOCKET,Handler) as server:
        os.chmod(SOCKET,0o660)
        import grp
        os.chown(SOCKET,0,grp.getgrnam('tunnelguard-control').gr_gid)
        server.serve_forever()


def agent():
    cfg=json.loads((ROOT/'agent.json').read_text())
    ctx=ssl.create_default_context(cadata=cfg['certificate'])
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ctx))
    public=' '.join(Path('/etc/ssh/ssh_host_ed25519_key.pub').read_text().split()[:2])
    completed=ROOT/'last-peer-job.json'
    result=json.loads(completed.read_text()) if completed.exists() else None
    while True:
        try:
            data=json.dumps(dict(host_key=public,result=result)).encode()
            req=urllib.request.Request(cfg['url']+'/api/peer',data=data,headers={'Authorization':'Bearer '+cfg['peer_token'],'Content-Type':'application/json'})
            with opener.open(req,timeout=20) as response: job=json.load(response).get('job')
            if job and (not result or result['id']!=job['id']):
                try:
                    (node.apply if job['operation']=='apply' else node.remove)(job['plan'],'exit')
                    result=dict(id=job['id'],ok=True)
                except Exception as error:
                    details(error);result=dict(id=job['id'],ok=False)
                # This is a replaceable, local retry journal, not a credential bundle.
                completed.write_text(json.dumps(result),encoding='utf-8')
                completed.chmod(0o600)
        except Exception as error:
            # Connectivity failures are bounded and do not stop existing tunnel services.
            print(type(error).__name__,flush=True)
        time.sleep(3)


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('mode',choices=['serve','agent'])
    (serve if parser.parse_args().mode=='serve' else agent)()
