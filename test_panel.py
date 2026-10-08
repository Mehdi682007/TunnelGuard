import asyncio
import base64
import copy
import hashlib
import json
import time
import unittest
from unittest.mock import patch
import tunnelguard as tg
import manage
import test_tunnelguard as fixtures

class PanelTests(unittest.TestCase):
    def test_sessions_expire_reject_tampering_and_rotate_with_credentials(self):
        g=tg.Guard(fixtures.config());g.cfg['dashboard_auth_sha256']='a'*64
        token=tg.session_cookie(g)
        self.assertTrue(tg.session_cookie(g,token))
        self.assertFalse(tg.session_cookie(g,token+'bad'))
        with patch.object(tg.time,'time',return_value=time.time()+28801):self.assertFalse(tg.session_cookie(g,token))
        g.cfg['dashboard_auth_sha256']='b'*64
        self.assertFalse(tg.session_cookie(g,token))

    def test_multiple_ports_keep_separate_routes_and_edit_preserves_other_port(self):
        cfg=fixtures.config();a,b=[r['name'] for r in cfg['routes']]
        cfg=manage.add_forward(cfg,'first','0.0.0.0',4748,'127.0.0.1',4748,[a],True)
        cfg=manage.add_forward(cfg,'second','0.0.0.0',7643,'127.0.0.1',7643,[b],True)
        original=copy.deepcopy(cfg['tcp_forwards'][1])
        cfg=manage.add_forward(cfg,'first','0.0.0.0',4748,'127.0.0.1',4748,[b],True,True)
        self.assertIn(original,cfg['tcp_forwards'])
        self.assertEqual(len(cfg['tcp_forwards']),2)

class CredentialTests(unittest.TestCase):
    def test_change_requires_current_password_and_persists_new_hash(self):
        import tunnel_manager as manager
        import threading
        old='Basic '+base64.b64encode(b'admin:old-test-password').decode()
        cfg={'dashboard_auth_sha256':hashlib.sha256(old.encode()).hexdigest()}
        threads=[];real=threading.Thread
        def launch(**kwargs):
            t=real(**kwargs);threads.append(t);return t
        with patch.object(manager,'STATE',{'links':{}}),patch.object(manager,'save'),patch.object(manager.manage,'load_config',side_effect=lambda _:dict(cfg)),patch.object(manager.manage,'checked'),patch.object(manager.manage,'save_managed') as saved,patch.object(manager.threading,'Thread',side_effect=launch):
            data={'current_username':'admin','current_password':'wrong','username':'new-user','password':'new-test-password'}
            with self.assertRaises(ValueError):manager.dispatch({'op':'credentials','data':data})
            saved.assert_not_called()
            data['current_password']='old-test-password'
            manager.dispatch({'op':'credentials','data':data})
            for t in threads:t.join(2)
            new='Basic '+base64.b64encode(b'new-user:new-test-password').decode()
            self.assertEqual(saved.call_args.args[0]['dashboard_auth_sha256'],hashlib.sha256(new.encode()).hexdigest())

class LoginNetworkTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp=fixtures.NetworkTests.asyncSetUp
    asyncTearDown=fixtures.NetworkTests.asyncTearDown
    server=fixtures.NetworkTests.server
    target=fixtures.NetworkTests.target
    http_proxy=fixtures.NetworkTests.http_proxy
    socks_proxy=fixtures.NetworkTests.socks_proxy

    async def test_login_cookie_and_cross_origin_rejection(self):
        auth='Basic '+base64.b64encode(b'admin:a-long-test-password').decode()
        self.g.cfg['dashboard_auth_sha256']=hashlib.sha256(auth.encode()).hexdigest()
        class TLSWriter:
            def __init__(self,w):self.w=w
            def __getattr__(self,k):return getattr(self.w,k)
            def get_extra_info(self,k,*a):return True if k=='ssl_object' else self.w.get_extra_info(k,*a)
        port=await self.server(lambda r,w:tg.dashboard(self.g,r,TLSWriter(w)))
        self.g.cfg['dashboard_port']=port
        async def request(path,method='GET',body=b'',headers=''):
            r,w=await asyncio.open_connection('127.0.0.1',port)
            w.write(f'{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: {len(body)}\r\n{headers}\r\n'.encode()+body);await w.drain()
            response=await r.read();await tg.close(w);return response
        body=json.dumps({'username':'admin','password':'a-long-test-password'}).encode()
        headers=f'Origin: https://127.0.0.1:{port}\r\nContent-Type: application/json\r\n'
        denied=await request('/api/login','POST',body,headers.replace('https://127.0.0.1','https://evil.invalid'))
        self.assertIn(b'403 Forbidden',denied)
        response=await request('/api/login','POST',body,headers)
        self.assertIn(b'200 OK',response);self.assertIn(b'HttpOnly; Secure; SameSite=Strict',response)
        cookie=response.split(b'Set-Cookie: ')[1].split(b';')[0].decode()
        self.assertIn(b'200 OK',await request('/api/status',headers='Cookie: '+cookie+'\r\n'))
        account=await request('/account',headers='Cookie: '+cookie+'\r\n')
        self.assertIn(b'200 OK',account)
        self.assertIn(b'id="account"',account)
        self.assertNotIn(b'/*TOKEN*/null',account)
        self.assertIn(b'401 Unauthorized',await request('/api/status'))
        self.assertIn(b'200 OK',await request('/api/logout','POST',b'{}',headers+'Cookie: '+cookie+'\r\n'))
        self.assertIn(b'401 Unauthorized',await request('/api/status',headers='Cookie: '+cookie+'\r\n'))
        self.assertNotIn(b'WWW-Authenticate',await request('/'))
        self.assertIn(b'<form',await request('/login'))
