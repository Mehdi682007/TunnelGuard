import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import deploy


class DeploymentTests(unittest.TestCase):
    def bundle(self):
        return dict(schema=1, core_version=deploy.VERSION, address="192.0.2.1",
                    ports=dict(zip(deploy.KINDS, [18443, 18444, 18445])),
                    passwords={"shadowsocks": "AAAAAAAAAAAAAAAAAAAAAA==", "trojan": "a"*43, "hysteria2": "b"*43},
                    certificate="-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----")

    def test_pairing_generates_three_matching_routes_and_verifies_tls(self):
        b = self.bundle()
        server, clients, guard = deploy.configs(b, "PRIVATE")
        self.assertEqual(len(guard["routes"]), 3)
        for i, k in enumerate(deploy.KINDS):
            outbound = clients[k]["outbounds"][0]
            self.assertEqual(outbound["server_port"], server["inbounds"][i]["listen_port"])
            self.assertEqual(clients[k]["inbounds"][0]["listen"], "127.0.0.1")
            if k != "shadowsocks":
                self.assertNotIn("insecure", outbound["tls"])
                self.assertEqual(outbound["tls"]["certificate"], b["certificate"].splitlines())
            self.assertNotIn("PRIVATE", json.dumps(clients[k]))

    def test_reject_bad_pairing_and_port_collisions(self):
        b = self.bundle()
        for field, value in [("address", "host\nInjected"), ("core_version", "latest"), ("schema", 2)]:
            modified = copy.deepcopy(b)
            modified[field] = value
            with self.assertRaises(ValueError):
                deploy.configs(modified)
        for base in [1087, 8786, 65534]:
            with self.assertRaises(ValueError):
                deploy.configs(b, local_base=base)

    def test_private_files_never_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/"pairing.json"
            deploy.write_private(path, {"test": 1})
            with self.assertRaises(FileExistsError):
                deploy.write_private(path, {"test": 2})
            self.assertEqual(json.loads(path.read_text()), {"test": 1})
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_wrong_hash_and_archive_symlinks_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive, binary = Path(tmp)/"core.tar.gz", Path(tmp)/"binary"
            with tarfile.open(archive, "w:gz") as tf:
                info = tarfile.TarInfo(f"sing-box-{deploy.VERSION}-linux-amd64/sing-box")
                info.type, info.linkname = tarfile.SYMTYPE, "/etc/passwd"
                tf.addfile(info)
            with self.assertRaisesRegex(ValueError, "SHA256"):
                deploy.unpack_verified(archive, binary, "amd64")
            import hashlib
            with patch.dict(deploy.HASHES, amd64=hashlib.sha256(archive.read_bytes()).hexdigest()):
                with self.assertRaisesRegex(ValueError, "member"):
                    deploy.unpack_verified(archive, binary, "amd64")
            self.assertFalse(binary.exists())

    def test_unit_uses_credentials_and_unprivileged_account(self):
        text = deploy.unit_text(Path("/opt/tunnelguard-node/client"), "trojan")
        self.assertIn("DynamicUser=yes", text)
        self.assertIn("LoadCredential=config.json:", text)
        self.assertIn("-c %d/config.json", text)
        self.assertNotIn("User=root", text)
        self.assertIn("AF_NETLINK", text)
        self.assertNotIn("AF_NETLINK", deploy.unit_text(Path("/opt/tunnelguard-node/client"), "guard", True))

    def test_occupied_ports_detected_before_installation(self):
        import socket
        with tempfile.TemporaryDirectory() as tmp, socket.socket() as occupied:
            occupied.bind(("127.0.0.1", 0))
            occupied.listen()
            folder = Path(tmp)
            deploy.write_private(folder/"server.json", {"inbounds": [dict(type="trojan", listen="127.0.0.1", listen_port=occupied.getsockname()[1])]})
            with self.assertRaises(OSError):
                deploy.check_ports(folder, "server")


@unittest.skipUnless(os.environ.get("TG_CORE_TEST") == "1" and sys.platform == "linux", "Opt-in Linux real-core integration")
class RealCoreTests(unittest.TestCase):
    def test_three_protocols_and_gateway_fallback(self):
        import http.server
        import threading
        import time
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"tunnelguard-core-test")
            def log_message(self, *args):
                pass
        endpoint = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=endpoint.serve_forever, daemon=True).start()
        children, logs = [], []
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                server, client = root/"server", root/"client"
                deploy.generate_server(server, "127.0.0.1", [28443, 28444, 28445])
                deploy.generate_client(client, server/"pairing.json", 21001)
                binary = deploy.install_core(server)
                url = f"http://127.0.0.1:{endpoint.server_port}/"
                cfg = json.loads((client/"config.json").read_text())
                cfg.update(listen_port=21088, dashboard_port=28787, interval=1, failures=1, recovery=1,
                           targets=[dict(url=url, status=[200])])
                (client/"config.json").write_text(json.dumps(cfg))
                def start(argv):
                    log = tempfile.TemporaryFile()
                    logs.append(log)
                    p = subprocess.Popen(argv, stdout=log, stderr=log)
                    children.append(p)
                    return p
                def fetch(port):
                    return subprocess.run(["curl", "-q", "--silent", "--show-error", "--fail", "--max-time", "3",
                                           "--noproxy", "", "--proxy", f"socks5h://127.0.0.1:{port}", url], capture_output=True)
                def wait_fetch(port):
                    for _ in range(20):
                        response = fetch(port)
                        if response.returncode == 0 and response.stdout == b"tunnelguard-core-test":
                            return
                        time.sleep(0.5)
                    self.fail(f"Core transport did not deliver test payload on port {port}")
                for path in [server/"server.json", *(client/f"{k}.json" for k in deploy.KINDS)]:
                    subprocess.run([str(binary), "check", "-c", str(path)], check=True)
                    start([str(binary), "run", "-c", str(path)])
                for port in range(21001, 21004):
                    wait_fetch(port)
                start([sys.executable, str(deploy.ROOT/"tunnelguard.py"), "run", "--config", str(client/"config.json"), "--output", str(root/"reports")])
                wait_fetch(21088)
                children[1].terminate()  # stop local Shadowsocks core, retain TLS + QUIC
                children[1].wait(timeout=10)
                wait_fetch(21088)
        finally:
            for child in reversed(children):
                if child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait()
            for log in logs:
                log.close()
            endpoint.shutdown()
            endpoint.server_close()


if __name__ == "__main__":
    unittest.main()
