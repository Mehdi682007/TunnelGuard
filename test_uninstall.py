import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uninstall as u
import test_tunnels

class UninstallTests(unittest.TestCase):
    def environment(self, stack, root):
        for name,relative in [('MANAGER','manager'),('UNITS','units'),('SSH','ssh')]:
            path=root/relative;path.mkdir();stack.enter_context(patch.object(u,name,path))
        stack.enter_context(patch.object(u,'TREES',(u.MANAGER,)))
        stack.enter_context(patch.object(u,'PAIRING',root/'pairing.json'))
        stack.enter_context(patch.object(u,'LAUNCHER',root/'launcher'))
        stack.enter_context(patch('sys.stdout',new=io.StringIO()))

    def test_preview_cancel_and_removal_are_local_and_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            root=Path(tmp).resolve();self.environment(stack,root)
            unit=u.UNITS/'tunnelguard-manager-agent.service';unit.write_text('Description=TunnelGuard agent')
            other=u.UNITS/'x-ui.service';other.write_text('Unrelated service')
            (u.MANAGER/'secret').write_text('private')
            fake=stack.enter_context(patch.object(u,'run',return_value=SimpleNamespace(returncode=0,stdout='',stderr='')))
            stack.enter_context(patch.dict(sys.modules,{'pwd':SimpleNamespace()}))
            u.preview();fake.assert_not_called()
            with patch('builtins.input',return_value='no'):self.assertFalse(u.interactive())
            self.assertTrue(unit.exists());fake.assert_not_called()
            u.apply();self.assertFalse(unit.exists());self.assertFalse(u.MANAGER.exists());self.assertTrue(other.exists())
            self.assertFalse(any('x-ui.service' in c.args for c in fake.call_args_list))
            u.apply();self.assertTrue(other.exists())

    def test_unrecognized_unit_and_invalid_manifest_block_removal(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            root=Path(tmp).resolve();self.environment(stack,root)
            unit=u.UNITS/'tunnelguard-custom.service';unit.write_text('Other software')
            with self.assertRaises(ValueError):u.inventory()
            unit.unlink()
            plan=test_tunnels.TunnelPlanTests().plan('gre','reverse');plan['interface']='eth0'
            folder=u.MANAGER/'tunnels'/plan['name'];folder.mkdir(parents=True)
            (folder/'plan.json').write_text(json.dumps(plan));(folder/'role').write_text('iran')
            with self.assertRaises(ValueError):u.inventory()

    def test_remaining_firewall_rules_preserve_installation(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
            root=Path(tmp).resolve();self.environment(stack,root)
            stack.enter_context(patch.dict(sys.modules,{'pwd':SimpleNamespace()}))
            stack.enter_context(patch.object(u,'run',return_value=SimpleNamespace(returncode=0,stdout='-A OUTPUT -m comment --comment "tunnelguard-link" -j DROP',stderr='')))
            with self.assertRaises(RuntimeError):u.apply()
            self.assertTrue(u.MANAGER.exists())
