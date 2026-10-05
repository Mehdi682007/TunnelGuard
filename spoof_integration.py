"""CI only: real deployment in an isolated, loopback-only network namespace.

Requires a disposable Ubuntu runner as root. Never run on a production host.
All network packets emitted by the tested services stay in the namespace.
"""
import hashlib
import json
import os
import platform
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

import deploy
import deploy_spoof as spoof
import maintenance
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
    arch = {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()]
    for path, digest in [(archive, deploy.HASHES[arch]), (raw, spoof.HASHES[arch])]:
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
            with maintenance.locked():
                upgrade = maintenance.upgrade("client")
                maintenance.restore(upgrade, "client")
                # Stage/commit one pair at a time. Both roles share this CI host;
                # move the client staging folder aside to simulate separate hosts.
                for server_target, client_target in (("server", "client"), ("spoof-server", "spoof-client")):
                    identity = maintenance.prepare_rotation(server_target, "127.0.0.2")
                    rotation = maintenance.rotation_folder(identity)
                    bundle = json.loads((rotation/"pairing.json").read_text())
                    saved = rotation.with_name(rotation.name+"-server")
                    rotation.rename(saved)
                    maintenance.stage_client(client_target, bundle)
                    client_saved = rotation.with_name(rotation.name+"-client")
                    rotation.rename(client_saved)
                    saved.rename(rotation)
                    maintenance.commit_rotation(server_target, identity)
                    rotation.rename(saved)
                    client_saved.rename(rotation)
                    maintenance.commit_rotation(client_target, identity)
                detached = maintenance.uninstall("spoof-client")
                assert "Spoof" not in [r["name"] for r in json.loads(spoof.EXISTING_GUARD.read_text())["routes"]]
                maintenance.restore(detached, "spoof-client")
                dependency = json.loads((maintenance.STATE/detached/"detached.json").read_text())["client_snapshot"]
                maintenance.restore(dependency, "client")
            # Sustained concurrent probes stay inside this namespace and leave a
            # bounded JSON report. Duration is controllable for manual CI soak runs.
            seconds = int(os.environ.get("TG_SOAK_SECONDS", "60"))
            for config in ("/opt/tunnelguard-spoof/client/config.json", "/opt/tunnelguard-node/client/config.json"):
                cfg = json.loads(Path(config).read_text())
                cfg["targets"] = [dict(url="http://127.0.0.1:28880/", status=[200])]
                Path(config).write_text(json.dumps(cfg))
            run("ip", "netns", "exec", NAMESPACE, "/usr/bin/python3", str(deploy.ROOT/"diagnostics.py"), "soak",
                "--config", "/opt/tunnelguard-node/client/config.json", "--seconds", str(seconds), "--interval", "0.25",
                "--concurrency", "4", "--max-mib", "10240", "--output", "/tmp/tg-soak.json")
            result = json.loads(Path("/tmp/tg-soak.json").read_text())
            assert all(r["success_pct"] >= 95 for r in result["routes"]), result
            print("PASS: upgrade, rollback, base/Spoof rotation, detach/restore and sustained probes", result["elapsed_s"])
            # Synthetic loss/delay affects only the namespace loopback, never the host.
            run("ip", "netns", "exec", NAMESPACE, "tc", "qdisc", "add", "dev", "lo", "root", "netem", "delay", "10ms", "3ms", "loss", "0.5%")
            try:
                run("ip", "netns", "exec", NAMESPACE, "/usr/bin/python3", str(deploy.ROOT/"diagnostics.py"), "soak",
                    "--config", "/opt/tunnelguard-node/client/config.json", "--seconds", "30", "--interval", "0.25",
                    "--concurrency", "4", "--max-mib", "1024", "--output", "/tmp/tg-loss.json")
                loss = json.loads(Path("/tmp/tg-loss.json").read_text())
                assert all(r["success_pct"] >= 80 for r in loss["routes"]), loss
                print("PASS: isolated 10ms jittered delay / 0.5% synthetic packet loss")
            finally:
                run("ip", "netns", "exec", NAMESPACE, "tc", "qdisc", "del", "dev", "lo", "root")
    finally:
        subprocess.run(["journalctl", *[x for unit in UNITS for x in ("-u", unit)], "--no-pager", "-n", "100"])
        subprocess.run(["systemctl", "disable", "--now", *UNITS], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if http:
            http.terminate()
            http.wait(timeout=10)
        subprocess.run(["ip", "netns", "delete", NAMESPACE])


if __name__ == "__main__":
    main()
