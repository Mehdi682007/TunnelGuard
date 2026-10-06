"""Real pinned-core tests for all seven protocols and userspace WireGuard; loopback only."""
import argparse
import http.server
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time

import deploy
import deploy_wireguard as wg


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--core-archive',type=Path,required=True)
    a=parser.parse_args()
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body=b'tunnelguard-v24-real-core'
            self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        def log_message(self,*args): pass
    endpoint=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
    threading.Thread(target=endpoint.serve_forever,daemon=True).start()
    processes=[]
    logs=[]
    try:
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            server,client=root/'server',root/'client'
            deploy.generate_server(server,'127.0.0.1',[28443,28444,28445],[28446,28447,28448,28449])
            deploy.generate_client(client,server/'pairing.json',21001)
            binary=deploy.install_core(server,a.core_archive)
            def start(path):
                checked=subprocess.run([str(binary),'check','-c',str(path)],capture_output=True)
                if checked.returncode:
                    print('Validation failed:',path.name,checked.stderr.decode())
                    raise RuntimeError('core validation failed')
                log=tempfile.TemporaryFile();logs.append(log)
                processes.append(subprocess.Popen([str(binary),'run','-c',str(path)],stdout=log,stderr=log))
            start(server/'server.json')
            for k in deploy.ALL_KINDS: start(client/f'{k}.json')
            def fetch(port):
                url=f'http://127.0.0.1:{endpoint.server_port}/'
                for _ in range(15):
                    result=subprocess.run(['curl','-q','--noproxy','','--proxy',f'socks5h://127.0.0.1:{port}','--max-time','3','-sS',url],capture_output=True)
                    if result.returncode==0 and result.stdout==b'tunnelguard-v24-real-core': return
                    time.sleep(.3)
                raise RuntimeError('No payload on SOCKS port '+str(port))
            for k in deploy.ALL_KINDS:
                port=json.loads((client/f'{k}.json').read_text())['inbounds'][0]['listen_port']
                fetch(port);print(k,'payload PASS',flush=True)
            private,public=wg.keypair();cp,cu=wg.keypair()
            b=dict(schema=1,kind='wireguard',core_version=deploy.VERSION,address='127.0.0.1',port=28450,socks_port=21010,bridge_port=21011,server_public=public,client_private=cp,client_public=cu)
            ws,wc=wg.configs(b,private)
            for name,cfg in [('wg-server',ws),('wg-client',wc)]:
                path=root/(name+'.json');deploy.write_private(path,cfg);start(path)
            fetch(21010);print('wireguard payload PASS',flush=True)
    except BaseException:
        for log in logs[-2:]:
            log.seek(0)
            print(log.read().decode(errors='replace')[-3000:])
        raise
    finally:
        for p in reversed(processes):
            if p.poll() is None:
                p.terminate()
                try:p.wait(timeout=5)
                except subprocess.TimeoutExpired:p.kill();p.wait()
        for log in logs: log.close()
        endpoint.shutdown();endpoint.server_close()


if __name__=='__main__':main()
