"""Offline tests: no public services, credentials, or real tunnels required."""
import asyncio
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import tunnelguard as tg


def config():
    return tg.load_config(Path(__file__).with_name("config.example.json"))


class PolicyTests(unittest.TestCase):
    def test_init_never_overwrites_and_uses_private_permissions(self):
        import stat
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "config.json"
            with contextlib.redirect_stdout(io.StringIO()):
                tg.initialize(path)
            self.assertEqual(len(tg.load_config(path)["routes"]), 2)
            original = path.read_bytes()
            with self.assertRaises(FileExistsError):
                tg.initialize(path)
            self.assertEqual(path.read_bytes(), original)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_personal_config_preferred_and_invalid_structures_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with patch.object(tg, "ROOT", root):
                self.assertEqual(tg.default_config(), str(root / "config.example.json"))
                (root / "config.json").write_text("{}")
                self.assertEqual(tg.default_config(), str(root / "config.json"))
            for value in ([], {**config(), "routes": [False]}, {**config(), "targets": [1]}, {**config(), "targets": [{"url": "https://example.com", "status": "200"}]}):
                path = root / "invalid.json"
                path.write_text(json.dumps(value))
                with self.assertRaises(tg.ConfigError):
                    tg.load_config(path)

    def test_report_replacement_leaves_no_temporary_files(self):
        with tempfile.TemporaryDirectory() as temp:
            g = tg.Guard(config())
            tg.save_report(g, temp)
            g.event("Route-A: DOWN")
            tg.save_report(g, temp)
            self.assertEqual(len(list(Path(temp).iterdir())), 2)
            data = json.loads((Path(temp) / "report.json").read_text())
            self.assertEqual(data["events"][-1]["message"], "Route-A: DOWN")

    def test_hysteresis_failover_and_optional_failback(self):
        c = config()
        g = tg.Guard(c)
        a, b = g.routes
        for n in range(2):
            for r in g.routes:
                r.update(True, 20, "", c, 100 + n)
            g.choose(100 + n)
        self.assertIs(g.active, a)
        for n in range(2):
            a.update(False, None, "Timeout", c, 102 + n)
            g.choose(102 + n)
            self.assertIs(g.active, a)
        a.update(False, None, "Timeout", c, 104)
        g.choose(104)
        self.assertIs(g.active, b)
        for n in range(2):
            a.update(True, 10, "", c, 105 + n)
        g.choose(106)
        self.assertIs(g.active, b)
        c["failback"] = True
        g.choose(107)
        self.assertIs(g.active, b)
        b.last = a.last = 125
        g.choose(125)
        self.assertIs(g.active, a)

    def test_no_route_and_stale_measurements_fail_closed(self):
        g = tg.Guard(config())
        self.assertIsNone(g.choose(100))
        for r in g.routes:
            r.state, r.last = "UP", 100
        self.assertIsNotNone(g.choose(100))
        self.assertIsNone(g.choose(200))

    def test_invalid_config_and_loop_rejected(self):
        c = config()
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / "config.json"
            c["routes"][0]["proxy"] = "socks5h://127.0.0.1:1088"
            p.write_text(json.dumps(c))
            with self.assertRaises(ValueError):
                tg.load_config(p)
            c["routes"][0]["proxy"] = "socks5h://127.0.0.1:1080"
            c["quorum"] = 3
            p.write_text(json.dumps(c))
            with self.assertRaises(ValueError):
                tg.load_config(p)

    def test_reports_omit_proxy_credentials(self):
        g = tg.Guard(config())
        g.routes[0].proxy = "http://secret-user:secret-password@10.20.30.40:8080"
        with tempfile.TemporaryDirectory() as temp:
            tg.save_report(g, temp)
            text = (Path(temp) / "report.html").read_text(encoding="utf-8")
            self.assertNotIn("secret-password", text)
            self.assertNotIn("10.20.30.40", text)
            self.assertIn('const frozen={', text)


class NetworkTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.servers = []
        self.tasks = set()
        self.proxy_dead = False
        self.proxy_hits = 0
        self.auth_seen = False
        self.g = tg.Guard(config())
        self.target_port = await self.server(self.target)
        self.http_port = await self.server(self.http_proxy)
        self.socks_port = await self.server(self.socks_proxy)
        self.g.routes[0].proxy = f"http://test:secret@127.0.0.1:{self.http_port}"
        self.g.routes[1].proxy = f"socks5h://127.0.0.1:{self.socks_port}"
        self.g.cfg["targets"] = [{"url": f"http://localhost:{self.target_port}/health", "status": [200]}]
        self.gateway_port = await self.server(lambda r, w: tg.gateway(self.g, r, w))

    async def server(self, handler):
        async def tracked(r, w):
            task = asyncio.current_task()
            self.tasks.add(task)
            try:
                await handler(r, w)
            except (OSError, asyncio.IncompleteReadError):
                pass
            finally:
                await tg.close(w)
                self.tasks.discard(task)
        server = await asyncio.start_server(tracked, "127.0.0.1", 0)
        self.servers.append(server)
        return server.sockets[0].getsockname()[1]

    async def target(self, r, w):
        await r.readuntil(b"\r\n\r\n")
        body = b"hello-through-the-tunnel"
        w.write(f"HTTP/1.1 200 OK\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body)
        await w.drain()

    async def http_proxy(self, r, w):
        if self.proxy_dead:
            return
        request = await r.readuntil(b"\r\n\r\n")
        self.proxy_hits += 1
        self.auth_seen |= b"Proxy-Authorization: Basic dGVzdDpzZWNyZXQ=" in request
        ur, uw = await asyncio.open_connection("127.0.0.1", self.target_port)
        try:
            w.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            await w.drain()
            await tg.relay(r, w, ur, uw, self.g)
        finally:
            await tg.close(uw)

    async def socks_proxy(self, r, w):
        ver, n = await r.readexactly(2)
        await r.readexactly(n)
        w.write(b"\x05\x00")
        await w.drain()
        await r.readexactly(3)
        host, port = await tg.socks_address(r)
        # The fixture listens on IPv4 only; avoid OS-specific ::1 fallback delays.
        ur, uw = await asyncio.open_connection("127.0.0.1" if host == "localhost" else host, port)
        try:
            w.write(b"\x05\x00\x00\x01" + b"\x00" * 6)
            await w.drain()
            await tg.relay(r, w, ur, uw, self.g)
        finally:
            await tg.close(uw)

    async def asyncTearDown(self):
        for s in self.servers:
            s.close()
            await s.wait_closed()
        tasks = list(self.tasks | self.g.tasks)
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    async def request_via_gateway(self):
        return await tg.measure(f"socks5h://127.0.0.1:{self.gateway_port}", self.g.cfg["targets"][0], 2)

    async def test_live_curl_probe_and_real_traffic_failover(self):
        with patch.dict(os.environ, {"NO_PROXY": "*", "ALL_PROXY": "http://127.0.0.1:1"}):
            for _ in range(2):
                await self.g.tick()
            self.assertEqual(self.g.active.name, "Route-A")
            self.assertTrue((await self.request_via_gateway())["ok"])
            self.assertTrue(self.auth_seen)
            self.proxy_dead = True
            for _ in range(3):
                await self.g.tick()
            self.assertEqual(self.g.active.name, "Route-B")
            self.assertTrue((await self.request_via_gateway())["ok"])
            self.assertEqual(self.g.switches, 1)

    async def test_all_down_never_connects_directly(self):
        result = await self.request_via_gateway()
        self.assertFalse(result["ok"])
        self.assertEqual(self.proxy_hits, 0)

    async def test_byte_cap_and_http_status(self):
        target = self.g.cfg["targets"][0]
        result = await tg.measure(self.g.routes[0].proxy, target, 2, byte_limit=4)
        self.assertFalse(result["ok"])
        result = await tg.measure(self.g.routes[0].proxy, {**target, "status": [204]}, 2)
        self.assertFalse(result["ok"])

    async def test_quorum_failure(self):
        self.g.cfg["targets"].append({**self.g.cfg["targets"][0], "status": [204]})
        self.g.cfg["quorum"] = 2
        for _ in range(3):
            await self.g.tick()
        self.assertIsNone(self.g.active)
        self.assertTrue(all(r.state == "DOWN" for r in self.g.routes))

    async def test_dashboard_host_validation(self):
        port = await self.server(lambda r, w: tg.dashboard(self.g, r, w))
        self.g.cfg["dashboard_port"] = port
        for host, expected in ((f"127.0.0.1:{port}", b"200 OK"), ("attacker.example", b"403 Forbidden")):
            r, w = await asyncio.open_connection("127.0.0.1", port)
            w.write(f"GET /api/status HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
            await w.drain()
            response = await r.read()
            self.assertIn(expected, response)
            self.assertNotIn(b"test:secret", response)
            await tg.close(w)

    async def test_socks_credentials_and_half_close(self):
        async def authenticated(r, w):
            self.assertEqual(await r.readexactly(3), b"\x05\x01\x02")
            w.write(b"\x05\x02")
            await w.drain()
            self.assertEqual(await r.readexactly(1), b"\x01")
            user = await r.readexactly((await r.readexactly(1))[0])
            password = await r.readexactly((await r.readexactly(1))[0])
            self.assertEqual((user, password), (b"user", b"p@ss"))
            w.write(b"\x01\x00")
            await w.drain()
            self.assertEqual(await r.readexactly(3), b"\x05\x01\x00")
            self.assertEqual(await tg.socks_address(r), ("example.com", 443))
            w.write(b"\x05\x00\x00\x01" + b"\x00" * 6)
            await w.drain()
            payload = await r.read()
            w.write(payload.upper())
            await w.drain()
        port = await self.server(authenticated)
        r, w = await tg.upstream(f"socks5h://user:p%40ss@127.0.0.1:{port}", "example.com", 443)
        w.write(b"half-close")
        await w.drain()
        w.write_eof()
        self.assertEqual(await asyncio.wait_for(r.read(), 2), b"HALF-CLOSE")
        await tg.close(w)


if __name__ == "__main__":
    unittest.main(verbosity=2)
