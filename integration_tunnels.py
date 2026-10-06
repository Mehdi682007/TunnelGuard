"""Real payloads through seven link families, both directions, in isolated namespaces.

Linux root only. No host route, SSH daemon or default firewall changes. Paqet rules
and kernel interfaces are created only inside the two temporary namespaces.
"""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

import deploy
import tunnel_assets
import tunnel_methods

ROOT=Path(__file__).resolve().parent


def run(*args,check=True,timeout=30):
    return subprocess.run([str(a) for a in args],check=check,capture_output=True,timeout=timeout)


def main():
    if os.geteuid()!=0: raise ValueError('Root required')
    for name in ('chisel','paqet','sing-box','spoof'): tunnel_assets.ensure(name)
    suffix=str(os.getpid())
    namespaces=['tgi'+suffix,'tge'+suffix];interfaces=['tvi'+suffix,'tve'+suffix]
    children=[];results=[]
    with tempfile.TemporaryDirectory(prefix='tg-links-') as temp:
        temp=Path(temp)
        try:
            for ns in namespaces: run('ip','netns','add',ns)
            run('ip','link','add',interfaces[0],'type','veth','peer','name',interfaces[1])
            for i,ns in enumerate(namespaces):
                run('ip','link','set',interfaces[i],'netns',ns)
                run('ip','-n',ns,'addr','add',f'198.18.50.{i+1}/24','dev',interfaces[i])
                run('ip','-n',ns,'link','set',interfaces[i],'up')
                # sing-box userspace WireGuard requires a default interface even
                # though this fixture keeps all packets inside the veth pair.
                run('ip','-n',ns,'route','add','default','dev',interfaces[i])
                run('ip','-n',ns,'link','set','lo','up')
            (temp/'payload').write_text('tunnelguard-real-link-payload')
            fixture=subprocess.Popen(['ip','netns','exec',namespaces[1],sys.executable,'-m','http.server','28880','--bind','127.0.0.1','--directory',str(temp)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            children.append(fixture)
            for index,(method,direction) in enumerate((m,d) for m in ('chisel','wireguard','paqet','spoof','ipip','gre','vxlan') for d in ('direct','reverse')):
                p=tunnel_methods.make_plan(dict(name=f'{method}-{direction}',method=method,direction=direction,iran_source='198.18.50.11',exit_source='198.18.50.12'),dict(iran='198.18.50.1',exit='198.18.50.2'),index+50)
                pair=[];logs=[]
                try:
                    for i,role in enumerate(('iran','exit')):
                        folder=temp/f'{method}-{direction}-{role}';folder.mkdir(mode=0o700)
                        deploy.write_private(folder/'plan.json',p);deploy.write_private(folder/'role',role)
                        code='import json,sys;from pathlib import Path;import tunnel_node;f=Path(sys.argv[1]);tunnel_node.configure(json.loads((f/"plan.json").read_text()),(f/"role").read_text().strip(),f)'
                        setup=run('ip','netns','exec',namespaces[i],sys.executable,'-c',code,folder)
                        log=(folder/'runtime.log').open('wb');logs.append(log)
                        process=subprocess.Popen(['ip','netns','exec',namespaces[i],sys.executable,str(ROOT/'tunnel_runtime.py'),str(folder)],stdout=log,stderr=log)
                        pair.append(process);children.append(process)
                    ok=False
                    for attempt in range(5):
                        time.sleep(1)
                        response=run('ip','netns','exec',namespaces[0],'curl','-q','--noproxy','','--proxy',f'socks5h://127.0.0.1:{p["socks_port"]}','--max-time','4','--silent','http://127.0.0.1:28880/payload',check=False,timeout=6)
                        if response.returncode==0 and response.stdout==b'tunnelguard-real-link-payload': ok=True;break
                    results.append(dict(method=method,direction=direction,ok=ok))
                    print(method,direction,'PAYLOAD PASS' if ok else 'FAIL',flush=True)
                    if not ok:
                        for folder in temp.glob(f'{method}-{direction}-*'):
                            print((folder/'runtime.log').read_text(errors='replace')[-3500:],flush=True)
                except Exception as error:
                    results.append(dict(method=method,direction=direction,ok=False,error=type(error).__name__))
                    print(method,direction,type(error).__name__,getattr(error,'stderr',b'').decode(errors='replace')[-1000:],flush=True)
                finally:
                    for process in pair:
                        process.terminate()
                        try: process.wait(timeout=8)
                        except subprocess.TimeoutExpired: process.kill();process.wait()
                        children.remove(process)
                    for log in logs: log.close()
            print(json.dumps(results),flush=True)
        finally:
            for child in children:
                child.terminate()
                try: child.wait(timeout=5)
                except subprocess.TimeoutExpired: child.kill();child.wait()
            for ns in namespaces: run('ip','netns','del',ns,check=False)
    return 0 if all(r['ok'] for r in results) and len(results)==14 else 1


if __name__=='__main__': raise SystemExit(main())
