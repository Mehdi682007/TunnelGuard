"""Rathole Noise carrier; a loopback Chisel channel supplies exit-side SOCKS.

Only Rathole initiates the inter-server connection. Chisel connects to its
loopback forwarded service, never directly to the other server.
"""
import json
from pathlib import Path
import deploy


def configure(p, role, folder):
    server=role==p['server_role'];base=p['port']
    side='server' if server else 'client'
    lines=[f'[{side}]',f'default_token = {json.dumps(p["token"])}']
    lines.append(f'bind_addr = "0.0.0.0:{base+1}"' if server else f'remote_addr = "{p[p["server_role"]]}:{base+1}"')
    lines += [f'[{side}.transport]','type = "noise"',f'[{side}.transport.noise]']
    lines.append(('local_private_key = ' if server else 'remote_public_key = ')+json.dumps(p['noise_private'] if server else p['noise_public']))
    lines += [f'[{side}.services.channel]',f'bind_addr = "127.0.0.1:{base+3}"' if server else f'local_addr = "127.0.0.1:{base}"']
    deploy.write_private(folder/'rathole.toml','\n'.join(lines)+'\n')
    allowed=[f'^R:127\\.0\\.0\\.1:{p["socks_port"]}$'] if p['direction']=='direct' else ['^socks$']
    deploy.write_private(folder/'auth.json',{'tg:'+p['token']:allowed})


def commands(p,role,folder,root):
    server=role==p['server_role'];base=p['port']
    args=[[str(root/'bin/rathole'),str(folder/'rathole.toml')]]
    if not server:
        channel=[str(root/'bin/chisel'),'server','--host','127.0.0.1','--port',str(base),'--keyfile',str(folder/'key'),'--authfile',str(folder/'auth.json'),'--keepalive','10s']
        channel+=['--reverse'] if p['direction']=='direct' else ['--socks5']
    else:
        remote=('R:' if p['direction']=='direct' else '')+f'127.0.0.1:{p["socks_port"]}:socks'
        channel=[str(root/'bin/chisel'),'client','--fingerprint',p['fingerprint'],'--keepalive','10s',f'http://127.0.0.1:{base+3}',remote]
    args.append(channel)
    return args
