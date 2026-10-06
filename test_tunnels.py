import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import tunnel_methods as methods
import tunnel_runtime as runtime


class TunnelPlanTests(unittest.TestCase):
    def test_fresh_guard_has_zero_routes_and_no_fake_proxy(self):
        import manage
        from tunnelguard import Guard
        cfg=manage.checked(dict(routes=[],targets=[dict(url='https://example.com',status=[200])]))
        guard=Guard(cfg)
        self.assertEqual(guard.snapshot()['routes'],[])
        self.assertIsNone(guard.snapshot()['active'])

    def test_catalog_is_transport_families_not_inbound_protocols(self):
        ids={item['id'] for item in methods.catalog()}
        self.assertTrue({'ssh','wireguard','paqet','spoof','ipip','gre','vxlan','chisel'}<=ids)
        self.assertTrue(ids.isdisjoint({'vmess','vless','trojan','tuic'}))
        self.assertTrue(all(x['directions']==['direct','reverse'] for x in methods.catalog()))

    def test_request_injection_and_source_validation(self):
        base=dict(name='link-one',method='spoof',direction='reverse',iran_source='192.0.2.1',exit_source='198.51.100.2')
        self.assertEqual(methods.request(base)['direction'],'reverse')
        for key,value in [('name','../bad'),('name','x;reboot'),('mtu',True),('mtu',9000),('exit_source','1.2.3.4;id'),('direction','fake'),('uplink','exec')]:
            with self.subTest(key=key,value=value),self.assertRaises((ValueError,TypeError)):
                methods.request(dict(base,**{key:value}))

    def plan(self,method,direction):
        import hashlib
        name=method+'-'+direction
        return dict(schema=1,name=name,method=method,direction=direction,mtu=1280,slot=1,port=23010,socks_port=30001,iran='192.0.2.1',exit='198.51.100.2',interface='tg'+hashlib.sha256(name.encode()).hexdigest()[:10],token='a'*43,server_role='exit' if direction=='direct' else 'iran',fingerprint='fingerprint',ssh_port=22)

    def test_reverse_carrier_has_no_direct_endpoint_fallback(self):
        for method in ('paqet','wireguard','spoof'):
            for direction in ('direct','reverse'):
                p=self.plan(method,direction)
                server=p['server_role'];client='iran' if server=='exit' else 'exit'
                argv,_=runtime.commands(p,client,Path('/opt/fixture'))
                chisel=argv[-1]
                self.assertIn('--proxy',chisel)
                self.assertIn('socks5://127.0.0.1:23012',chisel)
                self.assertIn('http://127.0.0.1:23010',chisel)
                self.assertEqual(chisel[-1],('R:' if direction=='reverse' else '')+'127.0.0.1:30001:socks')

    def test_kernel_channel_uses_only_inner_addresses(self):
        for method in ('ipip','gre','vxlan'):
            for direction in ('direct','reverse'):
                p=self.plan(method,direction)
                client='iran' if direction=='direct' else 'exit'
                argv,_=runtime.commands(p,client,Path('/opt/fixture'))
                self.assertIn('http://10.203.1.'+('2' if direction=='direct' else '1')+':23010',argv[-1])
                self.assertNotIn('--proxy',argv[-1])

    def test_paqet_firewall_is_peer_and_port_scoped_and_reversible(self):
        p=self.plan('paqet','direct')
        class Result: returncode=1
        with patch.object(runtime,'run',return_value=Result()) as run:
            runtime.firewall(p,'iran','add')
        additions=[call.args for call in run.call_args_list if '-A' in call.args]
        self.assertEqual(len(additions),3)
        for args in additions:
            self.assertIn('198.51.100.2',args);self.assertIn('23011',args)
            self.assertIn('tunnelguard-paqet-direct',args)
            self.assertNotIn('FORWARD',args)

    def test_allocated_ports_and_interface_cannot_be_overridden(self):
        p=self.plan('chisel','reverse')
        methods.validate_plan(p)
        for key,value in [('port',22),('interface','eth0'),('socks_port',8787),('slot',True)]:
            with self.assertRaises(ValueError): methods.validate_plan(dict(p,**{key:value}))

    def test_public_plan_omits_pair_secrets(self):
        p=self.plan('chisel','direct');p.update(private_key='PRIVATE',token='SECRET')
        self.assertNotIn('PRIVATE',json.dumps(methods.public_plan(p)))
        self.assertNotIn('SECRET',json.dumps(methods.public_plan(p)))


if __name__=='__main__': unittest.main()
