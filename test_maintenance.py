import asyncio
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch, AsyncMock

import diagnostics
import maintenance as m
import pair_maintenance as pair


class LifecycleTests(unittest.TestCase):
    def test_transaction_rolls_back_after_restart_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prefix = root/"client"
            prefix.mkdir()
            (prefix/"app").mkdir()
            (prefix/"app/tunnelguard.py").write_text("old")
            state = root/"state"
            state.mkdir()
            units = root/"units"
            units.mkdir()
            with patch.dict(m.TARGETS, client=(prefix, [])), patch.object(m, "STATE", state), patch.object(m, "UNITS", units), \
                 patch.object(m, "run"), patch.object(m, "restart", side_effect=[RuntimeError("start failed"), None]):
                with self.assertRaises(RuntimeError):
                    m.transaction("client", {"app/tunnelguard.py": b"new"})
            self.assertEqual((prefix/"app/tunnelguard.py").read_text(), "old")

    def test_snapshot_tampering_and_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            prefix = root/"client"
            prefix.mkdir()
            (prefix/"config.json").write_text("{}")
            state = root/"state"
            state.mkdir()
            with patch.dict(m.TARGETS, client=(prefix, [])), patch.object(m, "STATE", state), patch.object(m, "unit_names", return_value=[]):
                identity = m.snapshot("client")
                (state/identity/"tree/config.json").write_text("tampered")
                with self.assertRaises(ValueError):
                    m.read_snapshot(identity, "client")
                with self.assertRaises(ValueError):
                    m.read_snapshot("../outside", "client")

    def test_detach_preserves_later_user_edits(self):
        cfg = dict(routes=[dict(name="Other", proxy="socks5h://127.0.0.1:7"), dict(name="Spoof", proxy="socks5h://127.0.0.1:8")],
                   profiles={"Emergency": ["Spoof"], "All": ["Other", "Spoof"]}, default_profile="Emergency", interval=17)
        result = m.remove_spoof_route(cfg)
        self.assertEqual(result["interval"], 17)
        self.assertEqual(result["default_profile"], "All")
        self.assertEqual(result["profiles"], {"All": ["Other"]})

    def test_coordinator_recovers_both_sides_on_client_failure_without_secret_report(self):
        calls = []
        def remote(host, checkout, args, payload=None):
            calls.append((host, args[0]))
            if args[0] == "prepare-rotation":
                return {"rotation": "a"*32}
            if args[0] == "rotation-bundle":
                return {"password": "private-value"}
            if args[0] == "commit-rotation" and host == "client":
                raise RuntimeError("failure")
            return {"snapshot": "b"*32}
        with tempfile.TemporaryDirectory() as temp, patch.object(pair, "remote", side_effect=remote):
            report = Path(temp)/"report.json"
            with self.assertRaises(RuntimeError):
                pair.rotate("server", "client", "/repo", "192.0.2.1", "base", report)
            self.assertIn(("server", "abort-rotation"), calls)
            self.assertIn(("client", "abort-rotation"), calls)
            self.assertNotIn("private-value", report.read_text())

    def test_ssh_alias_rejects_option_injection(self):
        with self.assertRaises(ValueError):
            pair.remote("-oProxyCommand=bad", "/repo", [])

    def test_soak_budget_and_report_redaction(self):
        cfg = dict(routes=[dict(name="route", proxy="socks5h://secret@127.0.0.1:1080")], targets=[dict(url="https://private.example", status=[200])], timeout=1)
        result = dict(ok=True, latency_ms=2, bytes=1, mbps=0, error="")
        with tempfile.TemporaryDirectory() as temp, patch.object(diagnostics, "measure", new=AsyncMock(return_value=result)) as probe:
            output = Path(temp)/"soak.json"
            report = asyncio.run(diagnostics.soak(cfg, 1, .25, 1, 1, output))
            self.assertGreater(probe.await_count, 0)
            self.assertLessEqual(probe.await_count, 16)
            self.assertNotIn("secret", output.read_text())
            self.assertNotIn("private.example", output.read_text())
            self.assertEqual(report["routes"][0]["success_pct"], 100)


if __name__ == "__main__":
    unittest.main()
