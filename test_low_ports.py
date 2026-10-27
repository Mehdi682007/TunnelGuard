import json
from pathlib import Path
import unittest

import deploy
import manage


class LowPortTests(unittest.TestCase):
    def test_forward_port_range(self):
        for port in (1, 80, 443, 1023, 65535):
            cfg = json.loads(Path(__file__).with_name('config.example.json').read_text())
            result = manage.add_forward(cfg, 'web', '0.0.0.0', port,
                                        '127.0.0.1', 443, None, public=True)
            self.assertEqual(result['tcp_forwards'][0]['listen_port'], port)
        for port in (0, 65536):
            cfg = json.loads(Path(__file__).with_name('config.example.json').read_text())
            with self.assertRaises(ValueError):
                manage.add_forward(cfg, 'web', '0.0.0.0', port,
                                   '127.0.0.1', 443, None, public=True)

    def test_guard_has_bind_capability_without_root(self):
        unit = deploy.unit_text(Path('/opt/tunnelguard-node/client'), 'guard', True)
        self.assertIn('DynamicUser=yes', unit)
        self.assertIn('NoNewPrivileges=yes', unit)
        self.assertIn('AmbientCapabilities=CAP_NET_BIND_SERVICE', unit)
        self.assertIn('CapabilityBoundingSet=CAP_NET_BIND_SERVICE', unit)
        self.assertNotIn('User=root', unit)

