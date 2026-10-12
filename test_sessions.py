import os
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
import tunnelguard as tg
import test_tunnelguard as fixtures

class PersistentSessionTests(unittest.TestCase):
    def test_restart_keeps_login_and_csrf_but_logout_and_rotation_revoke(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'TG_SESSION_FILE':str(Path(directory)/'sessions.json')}):
            cfg=fixtures.config();cfg['dashboard_auth_sha256']='a'*64
            first=tg.Guard(cfg);cookie=tg.session_cookie(first)
            restarted=tg.Guard(cfg)
            self.assertEqual(first.control_token,restarted.control_token)
            self.assertTrue(tg.session_cookie(restarted,cookie))
            self.assertFalse(tg.session_cookie(restarted,cookie+'x'))
            with patch.object(tg.time,'time',return_value=tg.time.time()+28801):
                self.assertFalse(tg.session_cookie(restarted,cookie))
            tg.revoke_session(restarted,cookie)
            self.assertFalse(tg.session_cookie(tg.Guard(cfg),cookie))
            cookie=tg.session_cookie(restarted)
            changed={**cfg,'dashboard_auth_sha256':'b'*64}
            rotated=tg.Guard(changed)
            self.assertNotEqual(restarted.control_token,rotated.control_token)
            self.assertFalse(tg.session_cookie(rotated,cookie))

    def test_bad_store_is_not_silently_replaced(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {'TG_SESSION_FILE':str(Path(directory)/'sessions.json')}):
            path=Path(directory)/'sessions.json';path.write_text('{"secret":"bad","sessions":{}}')
            with self.assertRaises(tg.ConfigError):tg.Guard(fixtures.config())
            self.assertIn('bad',path.read_text())
