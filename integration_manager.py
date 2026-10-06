"""Disposable runner: verify fresh management installation and API authorization."""
import base64
import json
from pathlib import Path
import re
import ssl
import time
import urllib.error
import urllib.request

root=Path('/opt/tunnelguard-manager')
login=dict(line.split(': ',1) for line in (root/'panel/login.txt').read_text().splitlines() if ': ' in line)
pair=json.loads((root/'agent.json').read_text())
ctx=ssl.create_default_context(cadata=pair['certificate'])
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=ctx))
auth='Basic '+base64.b64encode((login['Username']+':'+login['Password']).encode()).decode()
base=login['URL']


def get(path,credential=None,data=None,token=None):
    headers={'Authorization':credential or auth}
    if data is not None: headers.update({'Content-Type':'application/json','Origin':base,'X-TunnelGuard-Token':token or ''})
    req=urllib.request.Request(base+path,data=json.dumps(data).encode() if data is not None else None,headers=headers)
    with opener.open(req,timeout=10) as response: return response.read().decode()


for attempt in range(20):
    try:
        state=json.loads(get('/api/tunnels'))
        if state.get('peer_online'): break
    except OSError: pass
    time.sleep(1)
else: raise AssertionError('Paired agent never became online')
assert len(state['methods'])==8 and state['links']==[]
assert json.loads(get('/api/status'))['routes']==[]
token=json.loads(re.search(r'const controlToken=(.*?);',get('/')).group(1))
for path,credential,data,csrf,expected in [
    ('/api/tunnels','Bearer '+pair['peer_token'],None,None,401),
    ('/api/tunnels',auth,{'op':'create','data':{}},'bad-token',403),
    ('/api/peer','Bearer bad',{'host_key':'invalid'},None,401),
    ('/api/tunnels',auth,{'op':'peer','data':{}},token,400),
    ('/api/tunnels',auth,{'op':'create','data':{'name':'../escape','method':'paqet','direction':'reverse'}},token,400),
]:
    try: get(path,credential,data,csrf)
    except urllib.error.HTTPError as error: assert error.code==expected,(path,error.code)
    else: raise AssertionError('Unauthorized operation accepted')
assert pair['peer_token'] not in json.dumps(state)
print('Fresh zero-route HTTPS panel, peer pairing, CSRF, peer/admin separation and secret redaction PASS')
