"""Run bounded measurements from the real client host over verified SSH."""
import argparse
import json
from pathlib import Path
import re
import shlex
import subprocess
import uuid

from diagnostics import save
from pair_maintenance import remote


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--server", required=True)
    p.add_argument("--client", required=True)
    p.add_argument("--checkout", required=True)
    p.add_argument("--seconds", type=int, default=300)
    p.add_argument("--max-mib", type=int, default=1024)
    p.add_argument("--family", choices=["base", "spoof"], default="base")
    p.add_argument("--output", type=Path, default=Path("field-report.json"))
    a = p.parse_args()
    if not 1 <= a.seconds <= 259200 or not 1 <= a.max_mib <= 10240:
        p.error("Duration 1..259200 seconds; byte budget 1..10240 MiB")
    if not all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", h) for h in (a.server, a.client)) or not a.checkout.startswith("/") or any(ord(c)<32 for c in a.checkout):
        p.error("Use SSH aliases and an absolute checkout path")
    config = "/opt/tunnelguard-node/client/config.json" if a.family == "base" else "/opt/tunnelguard-spoof/client/config.json"
    report = {"kind": "field", "status": "starting", "family": a.family}
    destination = "/var/lib/tunnelguard-maintenance/field-"+uuid.uuid4().hex+".json"
    def call(args, timeout):
        return subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=10", a.client,
                               shlex.join(["sudo", "-n", *args])], capture_output=True, timeout=timeout, check=True)
    try:
        report["server_certificate"] = remote(a.server, a.checkout, ["certificate-status", "--target", "server" if a.family == "base" else "spoof-server"])
        save(a.output, report)
        result = call(["python3", a.checkout.rstrip("/")+"/diagnostics.py", "soak", "--config", config,
                       "--seconds", str(a.seconds), "--max-mib", str(a.max_mib), "--output", destination], a.seconds+600)
        report["measurements"] = json.loads(call(["cat", destination], 30).stdout)
        report["status"] = "complete"
        save(a.output, report)
        print("گزارش آزمایش میدانی / Field report:", a.output)
        return 0
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError):
        report["status"] = "incomplete"
        report["remote_report"] = destination
        save(a.output, report)
        print("تست کامل نشد؛ گزارش باقی‌مانده روی کلاینت را بررسی کنید. / Test incomplete; inspect client report.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
