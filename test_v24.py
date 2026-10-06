import asyncio
import base64
import copy
import hashlib
import json
import unittest
from unittest.mock import patch

import deploy
import deploy_reverse as reverse
import manage
import tunnelguard as tg
import test_tunnelguard as fixtures


class ConfigTests(unittest.TestCase):
    def test_public_forward_requires_explicit_opt_in_and_keeps_remote_loopback(self):
        cfg=fixtures.config()
        with self.assertRaises(ValueError):
            manage.add_forward(copy.deepcopy(cfg),'xui','0.0.0.0',4748,'127.0.0.1',4748,None)
        result=manage.add_forward(cfg,'xui','0.0.0.0',4748,'127.0.0.1',4748,None,True)
        self.assertTrue(all(t['via']=='proxy' for t in result['tcp_forwards'][0]['targets'].values()))
        with self.assertRaises(ValueError):
            manage.add_forward(result,'other','127.0.0.1',1088,'localhost',80,None)

    def test_public_dashboard_cannot_be_enabled_without_tls_and_auth(self):
        cfg=fixtures.config()
        cfg['dashboard_host']='0.0.0.0'
        cfg['dashboard_address']='192.0.2.1'
        with self.assertRaises(ValueError): manage.checked(cfg)

    def test_reverse_bundle_cannot_inject_ssh_options_and_unit_is_restricted(self):
        key='ssh-ed25519 '+base64.b64encode(b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20'+bytes(32)).decode()
        b=dict(schema=1,kind='reverse-ssh',receiver='192.0.2.1',sender='192.0.2.2',ssh_port=22,socks_port=11005,public_key=key,host_key=key)
        text=reverse.sender_unit(b)
        self.assertIn('StrictHostKeyChecking=yes',text)
        self.assertIn('ExitOnForwardFailure=yes',text)
        self.assertIn('ClientAliveInterval 10',reverse.receiver_config(11005))
        self.assertIn('AllowStreamLocalForwarding no',reverse.receiver_config(11005))
        b['receiver']='-oProxyCommand=bad'
        with self.assertRaises(ValueError): reverse.sender_unit(b)


class NetworkTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp=fixtures.NetworkTests.asyncSetUp
    asyncTearDown=fixtures.NetworkTests.asyncTearDown
    server=fixtures.NetworkTests.server
    target=fixtures.NetworkTests.target
    http_proxy=fixtures.NetworkTests.http_proxy
    socks_proxy=fixtures.NetworkTests.socks_proxy

    async def test_forward_uses_proxy_not_direct_and_fails_closed(self):
        for _ in range(2): await self.g.tick()
        self.proxy_hits=0
        # Deliberately unresolvable target; fixture HTTP proxy delivers the test payload.
        spec=dict(name='xui',targets={'Route-A':dict(host='exit-only.invalid',port=4748,via='proxy')})
        port=await self.server(lambda r,w:tg.tcp_forward(self.g,spec,r,w))
        r,w=await asyncio.open_connection('127.0.0.1',port)
        w.write(b'GET / HTTP/1.1\r\nHost: fixture\r\n\r\n');await w.drain()
        self.assertIn(b'hello-through-the-tunnel',await asyncio.wait_for(r.read(),3))
        await tg.close(w)
        self.assertEqual(self.proxy_hits,1)
        for route in self.g.routes: route.state='DOWN'
        with patch.object(tg,'upstream') as upstream:
            with self.assertRaises(OSError): await tg.dial(self.g,forward=spec)
            upstream.assert_not_called()

    async def test_dashboard_auth_protects_html_status_and_controls(self):
        auth='Basic '+base64.b64encode(b'admin:test-password').decode()
        self.g.cfg['dashboard_auth_sha256']=hashlib.sha256(auth.encode()).hexdigest()
        port=await self.server(lambda r,w:tg.dashboard(self.g,r,w))
        self.g.cfg['dashboard_port']=port
        for path in ('/','/api/status','/api/control'):
            r,w=await asyncio.open_connection('127.0.0.1',port)
            w.write(f'GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n'.encode());await w.drain()
            response=await r.read();await tg.close(w)
            self.assertIn(b'401 Unauthorized',response)
            self.assertNotIn(self.g.control_token.encode(),response)
        r,w=await asyncio.open_connection('127.0.0.1',port)
        w.write(f'GET /api/status HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: {auth}\r\n\r\n'.encode());await w.drain()
        response=await r.read();await tg.close(w)
        self.assertIn(b'200 OK',response)
        self.assertNotIn(auth.encode(),response)


if __name__=='__main__': unittest.main()
