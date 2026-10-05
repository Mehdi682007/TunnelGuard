"""CI only: real deployment in an isolated, loopback-only network namespace.

Requires a disposable Ubuntu runner as root. Never run on a production host.
All network packets emitted by the tested services stay in the namespace.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

import deploy
import deploy_spoof as spoof
from test_spoof import settings

NAMESPACE = "tg-spoof-ci"
UNITS = ["tunnelguard-server-server", *[f"tunnelguard-client-{k}" for k in (*deploy.KINDS, "guard")],
         *[f"tunnelguard-spoof-{r}-{k}" for r in ("server", "client") for k in ("overlay", "carrier")]]


def run(*args, **kwargs):
    return subprocess.run(list(args), check=True, **kwargs)


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.geteuid() != 0:
        raise SystemExit("Run only in disposable GitHub Actions Linux runners as root")
    if Path("/opt/tunnelguard-node").exists() or spoof.PREFIX.exists():
        raise SystemExit("Refusing to touch an existing deployment")
    archive, raw = (Path(p).resolve() for p in sys.argv[1:3])
    # Verify before handing paths to offline installer and before any execution.
    for path, digest in [(archive, deploy.HASHES["amd64"]), (raw, spoof.HASHES["amd64"])]:
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise SystemExit("Downloaded fixture hash mismatch")
    saved_unit, saved_carrier = deploy.unit_text, spoof.carrier_unit
    def isolate(text):
        return text.replace("[Service]\n", f"[Service]\nNetworkNamespacePath=/run/netns/{NAMESPACE}\n")
    run("ip", "netns", "add", NAMESPACE)
    http = None
    try:
        run("ip", "-n", NAMESPACE, "link", "set", "lo", "up")
        # No veth, uplink, or default route is ever added.
        with tempfile.TemporaryDirectory() as temp, patch.object(deploy, "unit_text", side_effect=lambda *a, **kw: isolate(saved_unit(*a, **kw))), \
                patch.object(spoof, "carrier_unit", side_effect=lambda *a: isolate(saved_carrier(*a))):
            root = Path(temp)
            payload = b"spoof-encrypted-payload\n" * 12000
            (root/"fixture").mkdir()
            (root/"fixture/payload").write_bytes(payload)
            http = subprocess.Popen(["ip", "netns", "exec", NAMESPACE, "/usr/bin/python3", "-m", "http.server", "28880",
                                     "--bind", "127.0.0.1", "--directory", str(root/"fixture")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            server, client = root/"base-server", root/"base-client"
            deploy.generate_server(server, "127.0.0.2", [18443, 18444, 18445])
            deploy.generate_client(client, server/"pairing.json", 11001)
            cfg = json.loads((client/"config.json").read_text())
            cfg.update(targets=[dict(url="http://127.0.0.1:28880/", status=[200])], interval=1, failures=1, recovery=1)
            (client/"config.json").write_text(json.dumps(cfg))
            deploy.apply(server, "server", archive)
            deploy.apply(client, "client", archive)
            original = spoof.EXISTING_GUARD.read_bytes()
            ss, sc = root/"spoof-server", root/"spoof-client"
            s = settings()
            spoof.generate_server(ss, s)
            spoof.generate_client(sc, ss/"pairing.json")
            assert "PRIVATE KEY" not in (ss/"pairing.json").read_text()
            spoof.apply(ss, "server", s, archive, raw)
            spoof.apply(sc, "client", s, archive, raw)
            assert (spoof.PREFIX/"client/guard-backup.json").read_bytes() == original
            merged = json.loads(spoof.EXISTING_GUARD.read_text())
            assert len(merged["routes"]) == 4 and merged["profiles"]["Emergency"] == ["Spoof"]
            # Select only Spoof to prove the gateway cannot silently use a normal route.
            merged["default_profile"] = "Emergency"
            spoof.EXISTING_GUARD.write_text(json.dumps(merged))
            run("systemctl", "restart", "tunnelguard-client-guard")
            for port in (11004, 1088):
                for attempt in range(15):
                    result = subprocess.run(["ip", "netns", "exec", NAMESPACE, "curl", "-q", "--fail", "--silent", "--show-error",
                                             "--max-time", "5", "--noproxy", "", "--proxy", f"socks5h://127.0.0.1:{port}",
                                             "http://127.0.0.1:28880/payload"], capture_output=True)
                    if result.returncode == 0 and result.stdout == payload:
                        break
                    time.sleep(0.5)
                else:
                    raise RuntimeError(f"Spoof payload failed on {port}: curl code {result.returncode}")
            print("PASS: real raw TCP/UDP carrier + verified TLS overlay + payload + existing guard attachment + Emergency-only gateway")
    finally:
        subprocess.run(["journalctl", *[x for unit in UNITS for x in ("-u", unit)], "--no-pager", "-n", "100"])
        subprocess.run(["systemctl", "disable", "--now", *UNITS], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if http:
            http.terminate()
            http.wait(timeout=10)
        subprocess.run(["ip", "netns", "delete", NAMESPACE])


if __name__ == "__main__":
    main()
