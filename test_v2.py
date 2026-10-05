import asyncio
import contextlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import engines
import tunnelguard as tg
import test_tunnelguard as fixtures
config = fixtures.config


class RoutingV2(unittest.TestCase):
    def ready(self):
        g = tg.Guard(config())
        now = time.monotonic()
        for r in g.routes:
            r.update(True, 30, "", g.cfg, now)
            r.update(True, 30, "", g.cfg, now)
        g.choose()
        return g

    def test_profile_never_escapes_to_excluded_route(self):
        g = self.ready()
        g.cfg["profiles"]["OnlyB"] = ["Route-B"]
        g.control({"action": "profile", "value": "OnlyB"})
        self.assertEqual(g.active.name, "Route-B")
        g.routes[1].state = "DOWN"
        self.assertIsNone(g.choose())

    def test_manual_preference_falls_back_and_disable_invalidates_samples(self):
        g = self.ready()
        g.control({"action": "prefer", "value": "Route-B"})
        self.assertEqual(g.active.name, "Route-B")
        g.routes[1].state = "DOWN"
        self.assertEqual(g.choose().name, "Route-A")
        with self.assertRaises(ValueError):
            g.control({"action": "prefer", "value": "Route-B"})
        g.control({"action": "enable", "route": "Route-A", "value": False})
        self.assertIsNone(g.active)
        g.control({"action": "enable", "route": "Route-A", "value": True})
        self.assertIsNone(g.active)
        self.assertEqual(g.routes[0].good, 0)

    def test_quality_requires_distinct_measurement_rounds(self):
        g = self.ready()
        g.cfg["cooldown"] = 0
        g.policy = "quality"
        g.routes[0].ewma, g.routes[1].ewma = 1000, 100
        for _ in range(20):
            g.choose()  # User traffic must not count as measurement rounds.
        self.assertEqual(g.active.name, "Route-A")
        for _ in range(2):
            g.choose(measurement_round=True)
        self.assertEqual(g.active.name, "Route-A")
        g.choose(measurement_round=True)
        self.assertEqual(g.active.name, "Route-B")

    def test_quarantine_increases_for_flapping_route(self):
        g = self.ready()
        r = g.routes[0]
        for now in (100, 101, 102):
            r.update(False, None, "Timeout", g.cfg, now)
        self.assertEqual(r.quarantine_until, 112)
        for now in (103, 104):
            r.update(True, 30, "", g.cfg, now)
        self.assertNotIn(r, g.eligible(105))
        self.assertIn(r, g.eligible(113))
        for now in (114, 115, 116):
            r.update(False, None, "Timeout", g.cfg, now)
        self.assertEqual(r.quarantine_until, 136)

    def test_report_excludes_control_token_and_engine_paths(self):
        g = self.ready()
        self.assertNotIn(g.control_token, json.dumps(g.snapshot()))
        self.assertNotIn(g.control_token, tg.dashboard_html(g.snapshot()))
        self.assertIn(g.control_token, tg.dashboard_html(token=g.control_token))

    def test_event_log_write_failure_does_not_stop_routing(self):
        g = self.ready()
        with tempfile.TemporaryDirectory() as temp:
            g.event_file = str(Path(temp) / "events.jsonl")
            g.event("Route-A: UP")
            row = json.loads(Path(g.event_file).read_text())
            self.assertIn("timestamp", row)
            self.assertFalse(g.event_log_error)
            g.event_file = str(Path(temp) / "missing" / "events.jsonl")
            g.event("Route-B: DOWN")
            self.assertTrue(g.event_log_error)
            self.assertIsNotNone(g.choose())

    def test_saved_choices_do_not_restore_stale_health_or_secrets(self):
        g = self.ready()
        with tempfile.TemporaryDirectory() as temp:
            path = str(Path(temp) / "state.json")
            g.restore_state(path)
            g.control({"action": "prefer", "value": "Route-B"})
            g.control({"action": "policy", "value": "quality"})
            saved = Path(path).read_text()
            self.assertNotIn(g.control_token, saved)
            self.assertNotIn("proxy", saved)
            fresh = tg.Guard(config())
            fresh.restore_state(path)
            self.assertEqual(fresh.preferred, "Route-B")
            self.assertEqual(fresh.policy, "quality")
            self.assertIsNone(fresh.choose())
            self.assertTrue(all(r.state == "WARMUP" for r in fresh.routes))
            broken = json.loads(saved)
            broken["profile"] = "does-not-exist"
            Path(path).write_text(json.dumps(broken))
            with self.assertRaises(tg.ConfigError):
                fresh.restore_state(path)


# Reuse only the fixture methods, not inherited tests.
class NetworkV2(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = fixtures.NetworkTests.asyncSetUp
    asyncTearDown = fixtures.NetworkTests.asyncTearDown
    server = fixtures.NetworkTests.server
    target = fixtures.NetworkTests.target
    http_proxy = fixtures.NetworkTests.http_proxy
    socks_proxy = fixtures.NetworkTests.socks_proxy
    request_via_gateway = fixtures.NetworkTests.request_via_gateway

    async def test_immediate_handshake_fallback_before_health_threshold(self):
        for _ in range(2):
            await self.g.tick()
        self.proxy_dead = True
        self.assertTrue((await self.request_via_gateway())["ok"])
        self.assertEqual(self.g.routes[0].connect_failures, 1)
        self.assertEqual(self.g.routes[0].state, "UP")

    async def test_tcp_forward_delivers_application_bytes(self):
        for _ in range(2):
            await self.g.tick()
        spec = {"name": "Test", "targets": {"Route-A": {"host": "127.0.0.1", "port": self.target_port}}}
        port = await self.server(lambda r, w: tg.tcp_forward(self.g, spec, r, w))
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(b"GET / HTTP/1.1\r\nHost: fixture\r\n\r\n")
        await w.drain()
        self.assertIn(b"hello-through-the-tunnel", await asyncio.wait_for(r.read(), 2))
        await tg.close(w)

    async def test_authenticated_controls_reject_cross_origin_and_bad_token(self):
        port = await self.server(lambda r, w: tg.dashboard(self.g, r, w))
        self.g.cfg["dashboard_port"] = port
        async def post(token, origin, payload):
            body = json.dumps(payload).encode()
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write((f"POST /api/control HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: {origin}\r\nX-TunnelGuard-Token: {token}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n").encode() + body)
            await w.drain()
            response = await r.read()
            await tg.close(w)
            return response
        payload = {"action": "enable", "route": "Route-A", "value": False}
        self.assertIn(b"403 Forbidden", await post("wrong", f"http://127.0.0.1:{port}", payload))
        self.assertIn(b"403 Forbidden", await post(self.g.control_token, "https://evil.example", payload))
        self.assertTrue(self.g.routes[0].enabled)
        self.assertIn(b"200 OK", await post(self.g.control_token, f"http://127.0.0.1:{port}", payload))
        self.assertFalse(self.g.routes[0].enabled)

    async def test_probe_concurrency_is_bounded_and_old_results_discarded(self):
        active, maximum = 0, 0
        started, release = asyncio.Event(), asyncio.Event()
        self.g.probe_slots = asyncio.Semaphore(1)
        async def fake(*args):
            nonlocal active, maximum
            active += 1
            maximum = max(maximum, active)
            started.set()
            await release.wait()
            active -= 1
            return dict(ok=True, latency_ms=10, error="")
        with patch.object(tg, "measure", fake):
            task = asyncio.create_task(self.g.tick())
            await started.wait()
            self.g.control({"action": "enable", "route": "Route-A", "value": False})
            self.g.control({"action": "enable", "route": "Route-A", "value": True})
            release.set()
            await task
        self.assertEqual(maximum, 1)
        self.assertEqual(self.g.routes[0].good, 0)


class EngineTests(unittest.IsolatedAsyncioTestCase):
    async def test_linux_templates_validate_without_launching_on_windows(self):
        example = Path(__file__).with_name("config.managed.example.json")
        c = tg.load_config(example)
        self.assertEqual(c["routes"][0]["engine"]["kind"], "sing-box")
        if os.name == "nt":
            with self.assertRaises(ValueError):
                engines.command(c["routes"][0]["engine"])

    async def test_ssh_host_cannot_inject_an_option(self):
        with tempfile.TemporaryDirectory() as temp:
            cfg = Path(temp) / "ssh config"
            cfg.write_text("Host backup\n")
            spec = dict(kind="ssh", binary=sys.executable, config=str(cfg), host="backup", local_port=11005)
            argv = engines.command(spec)
            self.assertIn("StrictHostKeyChecking=yes", argv)
            self.assertIn("127.0.0.1:11005", argv)
            self.assertEqual(argv[-1], "backup")
            spec["host"] = "-oProxyCommand=bad"
            with self.assertRaises(ValueError):
                engines.command(spec)

    async def test_launch_arguments_are_separate_and_hash_checked(self):
        with tempfile.TemporaryDirectory() as temp:
            cfg = Path(temp) / "config with spaces.json"
            cfg.write_text("{}")
            spec = dict(kind="sing-box", binary=sys.executable, config=str(cfg))
            self.assertEqual(engines.command(spec), [sys.executable, "run", "-c", str(cfg)])
            spec["sha256"] = "0" * 64
            with self.assertRaises(ValueError):
                engines.command(spec)

    async def test_owned_process_is_restarted_after_crash_and_stopped_on_cancel(self):
        events, exits = [], []
        with tempfile.TemporaryDirectory() as temp:
            marker = Path(temp) / "started"
            code = "import pathlib,time,sys; p=pathlib.Path(sys.argv[1]); existed=p.exists(); p.touch(); time.sleep(30) if existed else sys.exit(7)"
            spec = dict(kind="sing-box", binary=sys.executable, config=str(Path(temp) / "config.json"))
            sup = engines.Supervisor("fixture", spec, events.append, lambda: exits.append(True))
            with patch.object(engines, "command", return_value=[sys.executable, "-c", code, str(marker)]):
                task = asyncio.create_task(sup.run())
                try:
                    async with asyncio.timeout(6):
                        while not (sup.restarts >= 1 and sup.state == "RUNNING"):
                            await asyncio.sleep(.02)
                    process = sup.process
                    self.assertEqual(sup.exit_code, 7)
                finally:
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                self.assertIsNotNone(process.returncode)
                self.assertEqual(sup.state, "STOPPED")
                self.assertTrue(exits)


if __name__ == "__main__":
    unittest.main(verbosity=2)
