"""Coordinate certificate/password rotation over existing verified SSH aliases."""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import shutil

from diagnostics import save


def install_timer(a):
    if sys.platform != "linux" or os.geteuid() != 0:
        raise ValueError("Linux root required")
    if a.server == a.client:
        raise ValueError("Use two distinct SSH aliases")
    for host in (a.server, a.client):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", host):
            raise ValueError("Invalid SSH alias")
    if not a.checkout.startswith("/") or any(ord(c) < 32 for c in a.checkout):
        raise ValueError("Invalid remote checkout")
    folder = Path("/opt/tunnelguard-renewal-tools")
    unit = f"tunnelguard-renew-{a.family}"
    service, timer = [Path("/etc/systemd/system")/(unit+suffix) for suffix in (".service", ".timer")]
    if service.exists() or timer.exists() or folder.is_symlink():
        raise ValueError("Timer already exists or tools path is a symlink")
    folder.mkdir(mode=0o755, exist_ok=True)
    from maintenance import atomic
    from deploy import write_private
    for name in ("pair_maintenance.py", "diagnostics.py", "tunnelguard.py", "engines.py"):
        atomic(folder/name, (Path(__file__).parent/name).read_bytes(), 0o644)
    argv = ["/usr/bin/python3", str(folder/"pair_maintenance.py"), "--server", a.server, "--client", a.client,
            "--checkout", a.checkout, "--address", a.address, "--family", a.family, "--if-due-days", str(a.if_due_days or 30),
            "--output", f"/var/lib/tunnelguard-renewal/{a.family}.json"]
    command = " ".join(json.dumps(s, ensure_ascii=False).replace("%", "%%") for s in argv)
    try:
        write_private(service, f"[Unit]\nDescription=TunnelGuard coordinated renewal\nAfter=network-online.target\n[Service]\nType=oneshot\nUser=root\nStateDirectory=tunnelguard-renewal\nUMask=0077\nNoNewPrivileges=yes\nExecStart={command}\n")
        write_private(timer, f"[Unit]\nDescription=TunnelGuard daily expiry check\n[Timer]\nOnCalendar=daily\nRandomizedDelaySec=1800\nPersistent=true\nUnit={unit}.service\n[Install]\nWantedBy=timers.target\n")
        for path in (service, timer):
            path.chmod(0o644)
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "enable", "--now", unit+".timer"], check=True)
    except BaseException:
        subprocess.run(["systemctl", "disable", "--now", unit+".timer"], capture_output=True)
        service.unlink(missing_ok=True)
        timer.unlink(missing_ok=True)
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        raise
    return {"phase": "timer_installed"}


def remote(host, checkout, args, payload=None):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", host):
        raise ValueError("Use an SSH config Host alias")
    if not checkout.startswith("/") or any(ord(c) < 32 for c in checkout):
        raise ValueError("Remote checkout must be an absolute path")
    command = shlex.join(["sudo", "-n", "python3", checkout.rstrip("/")+"/maintenance.py", *args])
    result = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10",
                             host, command], input=payload, capture_output=True, timeout=180)
    if result.returncode:
        raise RuntimeError("Remote maintenance failed; raw output withheld to protect configuration")
    return json.loads(result.stdout)


def rotate(server, client, checkout, address, family, output, due_days=None):
    server_target, client_target = ("spoof-server", "spoof-client") if family == "spoof" else ("server", "client")
    if server == client:
        raise ValueError("Use two distinct SSH host aliases")
    report = dict(schema=1, operation="rotate", family=family, phase="preparing", rollback={})
    identity = None
    staged = False
    try:
        if due_days is not None:
            status = remote(server, checkout, ["certificate-status", "--target", server_target])
            if status["remaining_days"] and all(d is not None and d > due_days for d in status["remaining_days"]):
                report["phase"] = "not_due"
                save(output, report)
                return report
        identity = remote(server, checkout, ["prepare-rotation", "--target", server_target, "--address", address])["rotation"]
        report.update(rotation=identity, phase="server_prepared")
        save(output, report)
        bundle = remote(server, checkout, ["rotation-bundle", "--target", server_target, "--rotation", identity])
        remote(client, checkout, ["stage-rotation", "--target", client_target, "--bundle-stdin"], json.dumps(bundle).encode())
        staged = True
        report["phase"] = "both_staged"
        save(output, report)
        report["server_snapshot"] = remote(server, checkout, ["commit-rotation", "--target", server_target, "--rotation", identity])["snapshot"]
        report["phase"] = "server_committed"
        save(output, report)
        report["client_snapshot"] = remote(client, checkout, ["commit-rotation", "--target", client_target, "--rotation", identity])["snapshot"]
        report["phase"] = "complete"
        save(output, report)
        return report
    except BaseException:
        report["phase"] = "failed"
        if identity:
            for host, target in [(server, server_target), *([(client, client_target)] if staged else [])]:
                try:
                    remote(host, checkout, ["abort-rotation", "--target", target, "--rotation", identity])
                    report["rollback"][target] = "restored_or_unchanged"
                except Exception:
                    report["rollback"][target] = "unreachable_or_failed_manual_recovery_required"
        save(output, report)
        raise


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--server", required=True, help="Existing SSH Host alias")
    p.add_argument("--client", required=True)
    p.add_argument("--checkout", required=True, help="Absolute checkout path on both nodes")
    p.add_argument("--address", required=True, help="Existing exit server address")
    p.add_argument("--family", choices=["base", "spoof"], default="base")
    p.add_argument("--if-due-days", type=int)
    p.add_argument("--output", type=Path, default=Path("rotation-report.json"))
    p.add_argument("--install-timer", action="store_true", help="Install daily coordinator check using root's verified SSH setup")
    a = p.parse_args()
    if a.if_due_days is not None and not 1 <= a.if_due_days <= 90:
        p.error("--if-due-days must be 1..90")
    try:
        result = install_timer(a) if a.install_timer else rotate(a.server, a.client, a.checkout, a.address, a.family, a.output, a.if_due_days)
        print("وضعیت / Status:", result["phase"])
        return 0
    except (ValueError, KeyError, OSError, RuntimeError, subprocess.SubprocessError):
        print("گردش گواهی کامل نشد؛ گزارش بازیابی را بررسی کنید. / Rotation incomplete; inspect recovery report.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
