"""Bilingual, redacted diagnostics and bounded route soak/field measurements."""
import argparse
import asyncio
from collections import deque
import datetime as dt
import json
import math
import os
from pathlib import Path
import shutil
import socket
import statistics
import subprocess
import time
from urllib.parse import urlsplit

from tunnelguard import load_config, measure, url_check

ADVICE = {
    "Proxy connection failed": ("خروجی محلی هسته در دسترس نیست؛ سرویس و پورت آن را بررسی کنید.", "Proxy endpoint unavailable; inspect its service and port."),
    "Proxy handshake failed": ("هسته پاسخ داده ولی اتصال مقصد ساخته نشده؛ رمز، مسیر و لاگ هسته را بررسی کنید.", "Proxy handshake failed; check credentials, route and core log."),
    "TLS verification failed": ("اعتبار گواهی، ساعت سیستم و جفت‌سازی دو سمت را بررسی کنید؛ اعتبارسنجی TLS را خاموش نکنید.", "Check certificate expiry, clock and pairing; keep TLS verification enabled."),
    "TLS handshake failed": ("مذاکره TLS شکست خورد؛ تنظیمات دو سمت و دسترسی مقصد را بررسی کنید.", "TLS handshake failed; check peer configuration and destination reachability."),
    "Timeout": ("پاسخ به‌موقع نرسید؛ اختلال شبکه، فایروال یا مقصد ممکن است علت باشد و از این تست به‌تنهایی قطعی نیست.", "Timed out; network, firewall or destination may be responsible; this test cannot distinguish them."),
    "Proxy DNS failed": ("نام میزبان پروکسی resolve نشد.", "Proxy hostname DNS resolution failed."),
    "Target DNS failed": ("نام مقصد resolve نشد؛ DNS مسیر را بررسی کنید.", "Destination DNS resolution failed; inspect route DNS."),
    "Response exceeds byte cap": ("پاسخ از سقف آزمایش بزرگ‌تر است؛ یک مقصد کوچک انتخاب کنید.", "Response exceeds test cap; select a smaller target."),
}


def advice(error, lang="fa"):
    return ADVICE.get(error, ("جزئیات وضعیت سرویس و تنظیمات مقصد را بررسی کنید.", "Inspect service state and target configuration."))[lang == "en"]


def save(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    import tempfile
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tg-report-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def certificate_days(config):
    certs = []
    for section in ("inbounds", "outbounds"):
        for entry in config.get(section, []):
            cert = entry.get("tls", {}).get("certificate")
            if cert:
                certs.append("\n".join(cert) if isinstance(cert, list) else cert)
    result = []
    for cert in certs:
        proc = subprocess.run(["openssl", "x509", "-noout", "-enddate"], input=cert, text=True,
                              capture_output=True, timeout=5)
        if proc.returncode:
            result.append(None)
        else:
            value = proc.stdout.strip().split("=", 1)[1]
            expiry = dt.datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
            result.append(math.floor((expiry-dt.datetime.now(dt.timezone.utc)).total_seconds()/86400))
    return result


async def doctor(config, lang="fa"):
    cfg = load_config(config)
    results = []
    for route in cfg["routes"]:
        probe = await measure(route["proxy"], cfg["targets"][0], cfg["timeout"])
        results.append(dict(name=route["name"], ok=probe["ok"], latency_ms=probe["latency_ms"],
                            error=probe["error"], advice="" if probe["ok"] else advice(probe["error"], lang)))
    services = []
    if shutil.which("systemctl"):
        for family in ("tunnelguard-client", "tunnelguard-server", "tunnelguard-spoof-client", "tunnelguard-spoof-server"):
            for name in ("guard", "server", "shadowsocks", "trojan", "hysteria2", "overlay", "carrier"):
                unit = f"{family}-{name}.service"
                p = subprocess.run(["systemctl", "show", unit, "--property=LoadState,ActiveState,ExecMainStatus,NRestarts"],
                                   capture_output=True, text=True, timeout=5)
                state = dict(line.split("=", 1) for line in p.stdout.splitlines() if "=" in line)
                if state.get("LoadState") == "loaded":
                    services.append(dict(unit=unit, **state))
    certificates = []
    if shutil.which("openssl"):
        for path in Path(config).parent.glob("*.json"):
            if path.name in ("server.json", "trojan.json", "hysteria2.json", "overlay.json"):
                try:
                    days = certificate_days(json.loads(path.read_text()))
                    if days:
                        certificates.append(dict(file=path.name, remaining_days=days,
                                                 renewal_needed=any(d is None or d < 30 for d in days)))
                except (ValueError, OSError, subprocess.SubprocessError):
                    certificates.append(dict(file=path.name, unreadable=True))
    return dict(schema=1, kind="diagnostics", routes=results, services=services, certificates=certificates,
                note=("این گزارش علت قطعی فیلتر یا فایروال را اثبات نمی‌کند." if lang == "fa" else "This report cannot prove censorship or a firewall cause."))


async def soak(cfg, seconds, interval, concurrency, max_mib, output):
    if not 1 <= seconds <= 259200 or not .25 <= interval <= 300 or not 1 <= concurrency <= 16 or not 1 <= max_mib <= 10240:
        raise ValueError("Out-of-range soak limits")
    stats = {r["name"]: dict(attempts=0, success=0, bytes=0, current_failure_streak=0, max_failure_streak=0,
                             last_error="", latencies=deque(maxlen=1000)) for r in cfg["routes"]}
    started = time.monotonic()
    # Reserve the per-probe maximum before dispatch, so concurrency cannot overrun budget.
    remaining = int(max_mib * 1024 * 1024) // 65536
    sem = asyncio.Semaphore(concurrency)
    def report(reason):
        routes = []
        for name, value in stats.items():
            s = {k: v for k, v in value.items() if k != "latencies"}
            latencies = sorted(value["latencies"])
            s.update(name=name, success_pct=round(100*s["success"]/s["attempts"], 2) if s["attempts"] else None,
                     p95_ms=latencies[max(0, math.ceil(len(latencies)*.95)-1)] if latencies else None)
            routes.append(s)
        return dict(schema=1, kind="soak", elapsed_s=round(time.monotonic()-started, 2), reason=reason,
                    routes=routes, latency_window=1000, byte_cap_per_request=65536,
                    note="No proxy URLs, credentials or target URLs are included. Failure streaks are sample counts, not exact outage durations.")
    async def probe(route):
        async with sem:
            result = await measure(route["proxy"], cfg["targets"][0], cfg["timeout"])
        s = stats[route["name"]]
        s["attempts"] += 1
        s["bytes"] += result["bytes"]
        s["success"] += int(result["ok"])
        s["current_failure_streak"] = 0 if result["ok"] else s["current_failure_streak"]+1
        s["max_failure_streak"] = max(s["max_failure_streak"], s["current_failure_streak"])
        s["last_error"] = result["error"]
        if result["ok"]:
            s["latencies"].append(round(result["latency_ms"], 2))
    reason = "duration_complete"
    try:
        while time.monotonic()-started < seconds:
            if remaining < len(cfg["routes"]):
                reason = "byte_budget_exhausted"
                break
            remaining -= len(cfg["routes"])
            await asyncio.gather(*(probe(r) for r in cfg["routes"]))
            save(output, report("running"))
            await asyncio.sleep(min(interval, max(0, seconds-(time.monotonic()-started))))
    except asyncio.CancelledError:
        reason = "interrupted"
        raise
    finally:
        save(output, report(reason))
    return report(reason)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=["doctor", "soak"])
    p.add_argument("--config", required=True, type=Path)
    p.add_argument("--lang", choices=["fa", "en"], default="fa")
    p.add_argument("--output", type=Path, default=Path("diagnostic-report.json"))
    p.add_argument("--seconds", type=int, default=300)
    p.add_argument("--interval", type=float, default=5)
    p.add_argument("--concurrency", type=int, default=4)
    p.add_argument("--max-mib", type=int, default=1024)
    a = p.parse_args()
    try:
        if a.command == "doctor":
            result = asyncio.run(doctor(a.config, a.lang))
            save(a.output, result)
            for route in result["routes"]:
                print(route["name"], "OK" if route["ok"] else route["advice"])
        else:
            result = asyncio.run(soak(load_config(a.config), a.seconds, a.interval, a.concurrency, a.max_mib, a.output))
        print("گزارش / Report:", a.output)
        return 0 if all(r.get("ok", r.get("success", 0) > 0) for r in result["routes"]) else 1
    except KeyboardInterrupt:
        print("متوقف شد؛ گزارش آخر ذخیره شد. / Interrupted; last report saved.")
        return 130
    except (ValueError, OSError, subprocess.SubprocessError):
        print("تنظیمات، دسترسی فایل و نصب curl/openssl را بررسی کنید. / Check config, file permissions and curl/openssl.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
