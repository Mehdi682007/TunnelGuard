#!/usr/bin/env python3
"""TunnelGuard: bounded route measurements and a fail-closed SOCKS5 gateway.

Python 3.11+; curl 8.4+ for live measurements. No pip dependencies.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import getpass
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import statistics
import struct
import subprocess
import sys
import time
from collections import deque
from dataclasses import dataclass, field
from urllib.parse import urlsplit, unquote
from engines import ENGINES, Supervisor, validate_engine, command as engine_command

VERSION = "2.2.0"
ROOT = Path(__file__).resolve().parent
LANG = "fa"


def say(fa, en):
    return fa if LANG == "fa" else en


class ConfigError(ValueError):
    """A safe validation message, containing no config values or credentials."""


def default_config():
    local = ROOT / "config.json"
    return str(local if local.exists() else ROOT / "config.example.json")


def initialize(path, interactive=False):
    if Path(path).exists():
        raise FileExistsError("Configuration already exists")
    cfg = load_config(ROOT / "config.example.json")
    if interactive:
        print(say("تنظیم مسیرها؛ رمز و آدرس پروکسی در گزارش نمایش داده نمی‌شود.",
                  "Route setup; proxy addresses and credentials are omitted from reports."))
        count = int(input(say("تعداد مسیرها [2]: ", "Number of routes [2]: ")) or "2")
        if not 1 <= count <= 16:
            raise ConfigError("routes: 1..16")
        cfg["routes"] = []
        for i in range(count):
            name = input(say(f"نام انگلیسی مسیر {i+1} [Route-{i+1}]: ", f"Route {i+1} name [Route-{i+1}]: ")) or f"Route-{i+1}"
            proxy = getpass.getpass(say("آدرس پروکسی (ورودی مخفی؛ socks5h://host:port یا http://host:port): ",
                                      "Proxy URL (hidden input; socks5h://host:port or http://host:port): "))
            url_check(proxy, True)
            layer = input(say("برچسب لایه مثل TCP-TLS، QUIC یا SPOOF [unknown]: ", "Layer label, e.g. TCP-TLS, QUIC, SPOOF [unknown]: ")) or "unknown"
            route = dict(name=name, proxy=proxy, priority=(i+1)*10, layer=layer)
            kind = input(say("هسته قابل مدیریت، یا external برای اجرای جداگانه [external]: ", "Managed engine kind, or external [external]: ")) or "external"
            if kind != "external":
                route["engine"] = dict(kind=kind,
                    binary=input(say("مسیر کامل فایل اجرایی: ", "Absolute binary path: ")),
                    config=input(say("مسیر کامل تنظیمات هسته: ", "Absolute engine config path: ")))
                if kind == "ssh":
                    route["engine"]["host"] = input(say("نام Host در تنظیمات SSH: ", "SSH config Host alias: "))
                    route["engine"]["local_port"] = urlsplit(proxy).port
                validate_engine(route["engine"])
            cfg["routes"].append(route)
        cfg["profiles"] = {"All": [r["name"] for r in cfg["routes"]]}
        cfg["default_profile"] = "All"
    destination = Path(path)
    # Validate before creating the actual file; never overwrite an existing config.
    import tempfile
    with tempfile.TemporaryDirectory() as temp:
        candidate = Path(temp) / "config.json"
        fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        load_config(candidate)
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    print(say("فایل تنظیمات ساخته شد. آدرس مسیرها را بررسی و سپس فرمان check را اجرا کنید.",
              "Config created. Check route addresses, then run the check command."))


def url_check(value, proxy=False):
    if not isinstance(value, str) or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ConfigError("URLs must be strings without control characters")
    p = urlsplit(value)
    schemes = ("http", "socks5h") if proxy else ("https", "http")
    if p.scheme not in schemes or not p.hostname:
        raise ConfigError("Invalid proxy URL" if proxy else "Invalid measurement URL")
    if proxy and (not p.port or p.path not in ("", "/") or p.query or p.fragment):
        raise ConfigError("Proxy must include a port and no path/query/fragment")
    if not proxy and (p.username or p.password or p.fragment):
        raise ConfigError("Measurement URLs must not include credentials or fragments")
    for val in (p.username, p.password):
        if val and any(ord(c) < 32 or ord(c) == 127 for c in unquote(val)):
            raise ConfigError("Control characters in credentials are not supported")
    return p


def load_config(path):
    c = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(c, dict):
        raise ConfigError("Configuration must be a JSON object")
    defaults = dict(interval=5, timeout=4, failures=3, recovery=2,
                    cooldown=20, failback=False, listen_port=1088,
                    dashboard_port=8787, max_connections=256, quorum=1,
                    history=360, stale_after=30, quarantine=10, quarantine_max=120,
                    policy="priority", switch_margin=25, switch_rounds=3,
                    connect_attempts=3, probe_concurrency=8)
    for k, v in defaults.items():
        c.setdefault(k, v)
    bounds = dict(interval=(1, 3600), timeout=(1, 60), failures=(1, 20),
                  recovery=(1, 20), cooldown=(0, 3600), listen_port=(1, 65535),
                  dashboard_port=(1, 65535), max_connections=(1, 4096),
                  quorum=(1, 8), history=(10, 10000), stale_after=(5, 7200),
                  quarantine=(0, 600), quarantine_max=(0, 3600), switch_margin=(1, 90),
                  switch_rounds=(1, 20), connect_attempts=(1, 8), probe_concurrency=(1, 32))
    for k, (lo, hi) in bounds.items():
        if type(c[k]) is not int or not lo <= c[k] <= hi:
            raise ConfigError(f"{k} must be an integer in {lo}..{hi}")
    if type(c["failback"]) is not bool:
        raise ConfigError("failback must be true or false")
    if c["policy"] not in ("priority", "quality") or c["quarantine_max"] < c["quarantine"]:
        raise ConfigError("policy must be priority/quality; quarantine_max must be >= quarantine")
    if c["stale_after"] < c["interval"] + c["timeout"] + 2:
        raise ConfigError("stale_after must be >= interval + timeout + 2")
    if c["listen_port"] == c["dashboard_port"]:
        raise ConfigError("Gateway and dashboard ports must differ")
    routes = c.get("routes", [])
    if not isinstance(routes, list) or not 1 <= len(routes) <= 16:
        raise ConfigError("Configure 1..16 routes")
    names = set()
    for r in routes:
        if not isinstance(r, dict) or not isinstance(r.get("name"), str) or not isinstance(r.get("proxy"), str):
            raise ConfigError("Each route needs string name and proxy fields")
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,24}", r.get("name", "")):
            raise ConfigError("Route names: 1..24 letters, digits, dash or underscore")
        if r["name"] in names:
            raise ConfigError("Route names must be unique")
        names.add(r["name"])
        p = url_check(r["proxy"], True)
        if p.hostname in ("localhost", "127.0.0.1", "::1") and p.port in (c["listen_port"], c["dashboard_port"]):
            raise ConfigError("A route points back to TunnelGuard itself")
        r.setdefault("priority", 100)
        if type(r["priority"]) is not int or not 0 <= r["priority"] <= 10000:
            raise ConfigError("priority must be an integer in 0..10000")
        r.setdefault("layer", "unknown")
        r.setdefault("enabled", True)
        if not isinstance(r["layer"], str) or not re.fullmatch(r"[A-Za-z0-9_+.-]{1,40}", r["layer"]):
            raise ConfigError("route.layer must be a short technical label without spaces")
        if type(r["enabled"]) is not bool:
            raise ConfigError("route.enabled must be true or false")
        if "engine" in r:
            try:
                validate_engine(r["engine"])
            except ValueError as exc:
                raise ConfigError(str(exc)) from None
            if r["engine"]["kind"] == "ssh" and (p.scheme != "socks5h" or p.hostname != "127.0.0.1" or p.port != r["engine"]["local_port"]):
                raise ConfigError("SSH route proxy must match socks5h://127.0.0.1:engine.local_port")
    targets = c.get("targets", [])
    if not isinstance(targets, list) or not 1 <= len(targets) <= 8 or c["quorum"] > len(targets):
        raise ConfigError("Configure 1..8 targets and quorum <= target count")
    for t in targets:
        if not isinstance(t, dict) or not isinstance(t.get("url"), str):
            raise ConfigError("Each target needs a string url field")
        url_check(t["url"])
        codes = t.get("status", [200, 204])
        if not isinstance(codes, list) or not codes or any(type(x) is not int or not 100 <= x <= 599 for x in codes):
            raise ConfigError("Invalid expected HTTP status")
        t["status"] = codes
    c.setdefault("profiles", {"All": [r["name"] for r in routes]})
    profiles = c["profiles"]
    if not isinstance(profiles, dict) or not 1 <= len(profiles) <= 16:
        raise ConfigError("profiles must contain 1..16 named route lists")
    for name, members in profiles.items():
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,24}", name) or not isinstance(members, list) or not members or any(not isinstance(n, str) or n not in names for n in members):
            raise ConfigError("Invalid profile name or route member")
    c.setdefault("default_profile", next(iter(profiles)))
    if c["default_profile"] not in profiles:
        raise ConfigError("default_profile does not exist")
    # A round must fit inside freshness TTL even when probes are queued.
    slots = math.ceil(len(routes) * len(targets) / c["probe_concurrency"])
    if c["stale_after"] < max(c["interval"], slots * (c["timeout"] + 3)) + 2:
        raise ConfigError("stale_after is too short for the configured probe concurrency")
    c.setdefault("tcp_forwards", [])
    occupied = {c["listen_port"], c["dashboard_port"]}
    if not isinstance(c["tcp_forwards"], list) or len(c["tcp_forwards"]) > 16:
        raise ConfigError("tcp_forwards must contain at most 16 entries")
    for f in c["tcp_forwards"]:
        if not isinstance(f, dict) or not re.fullmatch(r"[A-Za-z0-9_-]{1,24}", str(f.get("name", ""))):
            raise ConfigError("Invalid forward name")
        port = f.get("listen_port")
        if type(port) is not int or not 1 <= port <= 65535 or port in occupied:
            raise ConfigError("Each TCP forward needs a unique listen_port")
        occupied.add(port)
        if not isinstance(f.get("targets"), dict) or not f["targets"]:
            raise ConfigError("Each TCP forward needs per-route targets")
        for name, target in f["targets"].items():
            if name not in names or not isinstance(target, dict):
                raise ConfigError("Invalid forwarding target route")
            host, port = target.get("host"), target.get("port")
            if not isinstance(host, str) or not host or not re.fullmatch(r"[A-Za-z0-9_.:-]+", host) or type(port) is not int or not 1 <= port <= 65535:
                raise ConfigError("Forward target requires host and port")
    for f in c["tcp_forwards"]:
        for target in f["targets"].values():
            if target["host"] in ("localhost", "127.0.0.1", "::1") and target["port"] in occupied:
                raise ConfigError("TCP forward points back to a TunnelGuard listener")
    for r in routes:
        p = url_check(r["proxy"], True)
        if p.hostname in ("localhost", "127.0.0.1", "::1") and p.port in occupied:
            raise ConfigError("Route proxy points back to a TunnelGuard listener")
    return c


@dataclass
class Route:
    name: str
    proxy: str
    priority: int
    state: str = "WARMUP"
    good: int = 0
    bad: int = 0
    samples: deque = field(default_factory=lambda: deque(maxlen=120))
    latency: float | None = None
    last: float = 0
    error: str = "Waiting for measurements"
    layer: str = "unknown"
    enabled: bool = True
    quarantine_until: float = 0
    outages: int = 0
    ewma: float | None = None
    connect_failures: int = 0
    target_results: list = field(default_factory=list)
    revision: int = 0

    def update(self, ok, latency, error, cfg, now):
        self.last = now
        self.samples.append((ok, latency))
        self.latency = latency if ok else self.latency
        if ok and latency is not None:
            self.ewma = latency if self.ewma is None else 0.3 * latency + 0.7 * self.ewma
        self.error = "" if ok else error
        if ok:
            self.good += 1
            self.bad = 0
            if self.good >= cfg["recovery"]:
                self.state = "UP"
        else:
            self.bad += 1
            self.good = 0
            if self.bad >= cfg["failures"]:
                if self.state != "DOWN":
                    self.outages = min(self.outages + 1, 10)
                    self.quarantine_until = now + min(cfg["quarantine_max"], cfg["quarantine"] * 2 ** (self.outages - 1))
                self.state = "DOWN"
        if self.good >= 30:
            self.outages = 0

    def score(self):
        failure_fraction = 1 - sum(ok for ok, _ in self.samples) / len(self.samples) if self.samples else 1
        return (self.ewma if self.ewma is not None else 10000) + 2000 * failure_fraction + 100 * self.bad

    def public(self):
        values = [v for ok, v in self.samples if ok and v is not None]
        jitter = statistics.mean(abs(b - a) for a, b in zip(values, values[1:])) if len(values) > 1 else 0
        return dict(name=self.name, state=self.state, priority=self.priority,
                    latency_ms=round(self.latency, 1) if self.latency is not None else None,
                    jitter_ms=round(jitter, 1),
                    success_pct=round(100 * sum(ok for ok, _ in self.samples) / len(self.samples), 1) if self.samples else None,
                    samples=len(self.samples), failures=self.bad, error=self.error,
                    layer=self.layer, enabled=self.enabled, score=round(self.score(), 1),
                    quarantine_s=max(0, math.ceil(self.quarantine_until - time.monotonic())),
                    connect_failures=self.connect_failures, targets=self.target_results)


def curl_quote(s):
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'


async def measure(proxy, target, timeout, byte_limit=65536):
    """Credentials go via stdin, never argv. Ignore curlrc and NO_PROXY."""
    config = "\n".join(f"{k} = {curl_quote(v)}" for k, v in (("proxy", proxy), ("url", target["url"])))
    args = [shutil.which("curl") or "curl", "-q", "--config", "-", "--silent",
            "--globoff", "--noproxy", "", "--proxytunnel", "--proto", "=http,https",
            "--connect-timeout", str(timeout), "--max-time", str(timeout),
            "--max-filesize", str(byte_limit), "--output", os.devnull,
            "--write-out", "%{http_code} %{time_total} %{size_download} %{speed_download}"]
    env = {k: v for k, v in os.environ.items() if k.lower() not in
           ("http_proxy", "https_proxy", "all_proxy", "no_proxy", "sslkeylogfile")}
    proc = await asyncio.create_subprocess_exec(*args, stdin=asyncio.subprocess.PIPE,
              stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, env=env)
    try:
        out, _ = await asyncio.wait_for(proc.communicate(config.encode()), timeout + 3)
    except (asyncio.TimeoutError, asyncio.CancelledError) as exc:
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
        await proc.communicate()
        if isinstance(exc, asyncio.CancelledError):
            raise
        return dict(ok=False, latency_ms=0, bytes=0, mbps=0, error="Probe process timeout")
    try:
        status, elapsed, size, speed = out.decode().strip().split()
        ok = proc.returncode == 0 and int(status) in target["status"]
        category = {5: "Proxy DNS failed", 6: "Target DNS failed", 7: "Proxy connection failed",
                    28: "Timeout", 35: "TLS handshake failed", 60: "TLS verification failed",
                    63: "Response exceeds byte cap", 97: "Proxy handshake failed"}
        error = "" if ok else category.get(proc.returncode, f"curl {proc.returncode}; HTTP {status}")
        return dict(ok=ok, latency_ms=float(elapsed) * 1000, bytes=int(float(size)),
                    mbps=float(speed) * 8 / 1_000_000, error=error)
    except (ValueError, UnicodeError):
        return dict(ok=False, latency_ms=0, bytes=0, mbps=0, error="Invalid curl result")


class Guard:
    def __init__(self, cfg, demo=False):
        self.cfg = cfg
        self.routes = [Route(r["name"], r["proxy"], r["priority"], layer=r.get("layer", "unknown"), enabled=r.get("enabled", True)) for r in cfg["routes"]]
        self.active = None
        self.events = deque(maxlen=100)
        self.history = deque(maxlen=cfg["history"])
        self.started = time.monotonic()
        self.last_switch = 0.0
        self.switches = 0
        self.connections = 0
        self.bytes = 0
        self.demo = demo
        self.tasks = set()
        self.profile = cfg["default_profile"]
        self.preferred = None
        self.policy = cfg["policy"]
        self.challenger = None
        self.challenger_rounds = 0
        self.control_token = secrets.token_urlsafe(32)
        self.probe_slots = asyncio.Semaphore(cfg["probe_concurrency"])
        self.supervisors = {}
        self.event_file = None
        self.event_log_error = False
        self.state_file = None
        self.state_error = False

    def restore_state(self, path):
        self.state_file = path
        source = Path(path)
        if not source.exists():
            return
        if source.stat().st_size > 65536:
            raise ConfigError("Saved control state exceeds 64 KiB")
        state = json.loads(source.read_text(encoding="utf-8"))
        names = {r.name for r in self.routes}
        if not isinstance(state, dict) or state.get("version") != 1:
            raise ConfigError("Invalid saved control state")
        profile, policy, preferred = state.get("profile"), state.get("policy"), state.get("preferred")
        enabled = state.get("enabled")
        if not isinstance(profile, str) or profile not in self.cfg["profiles"] or policy not in ("priority", "quality"):
            raise ConfigError("Saved profile or policy is incompatible with this configuration")
        if preferred is not None and (not isinstance(preferred, str) or preferred not in self.cfg["profiles"][profile]):
            raise ConfigError("Saved preferred route is incompatible with this configuration")
        if not isinstance(enabled, dict) or any(name not in names or type(value) is not bool for name, value in enabled.items()):
            raise ConfigError("Saved route toggles are incompatible with this configuration")
        self.profile, self.policy, self.preferred = profile, policy, preferred
        for route in self.routes:
            route.enabled = enabled.get(route.name, route.enabled)
        self.event("CONTROL_STATE: RESTORED")

    def persist_state(self):
        if not self.state_file:
            return
        state = dict(version=1, profile=self.profile, policy=self.policy, preferred=self.preferred,
                     enabled={r.name: r.enabled for r in self.routes})
        import tempfile
        temporary = None
        try:
            target = Path(self.state_file)
            fd, temporary = tempfile.mkstemp(prefix=".tg-state-", dir=target.parent)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(state, f)
            os.replace(temporary, target)
            self.state_error = False
        except OSError:
            self.state_error = True
        finally:
            if temporary:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(temporary)

    def eligible(self, now=None):
        now = time.monotonic() if now is None else now
        members = self.cfg["profiles"][self.profile]
        return [r for r in self.routes if r.enabled and r.name in members and r.state == "UP"
                and now - r.last <= self.cfg["stale_after"] and now >= r.quarantine_until
                and (r.name not in self.supervisors or self.supervisors[r.name].state == "RUNNING")]

    def ordered(self, now=None):
        candidates = self.eligible(now)
        if self.policy == "quality":
            candidates.sort(key=lambda r: (r.score(), r.priority))
        else:
            candidates.sort(key=lambda r: (r.priority, r.score()))
        return candidates

    def control(self, data):
        if not isinstance(data, dict):
            raise ValueError("Invalid control request")
        action = data.get("action")
        if action == "profile":
            if data.get("value") not in self.cfg["profiles"]:
                raise ValueError("Unknown profile")
            self.profile, self.preferred = data["value"], None
            self.event(f"PROFILE: {self.profile}")
        elif action == "policy":
            if data.get("value") not in ("priority", "quality"):
                raise ValueError("Unknown policy")
            self.policy = data["value"]
            self.event(f"POLICY: {self.policy}")
        elif action == "prefer":
            name = data.get("value")
            if name is not None and not any(r.name == name for r in self.eligible()):
                raise ValueError("Route must be healthy, enabled and in the selected profile")
            self.preferred = name
            self.event(f"PREFERRED: {name or 'AUTO'}")
        elif action == "enable":
            route = next((r for r in self.routes if r.name == data.get("route")), None)
            if route is None or type(data.get("value")) is not bool:
                raise ValueError("Invalid route toggle")
            if route.enabled != data["value"]:
                route.enabled = data["value"]
                route.revision += 1
                route.state, route.good, route.bad = "WARMUP", 0, 0
                route.last, route.quarantine_until = 0, 0
                if self.preferred == route.name:
                    self.preferred = None
                self.event(f"{route.name}: {'ENABLED' if route.enabled else 'DISABLED'}")
        else:
            raise ValueError("Unknown action")
        self.challenger, self.challenger_rounds = None, 0
        self.choose()
        self.persist_state()

    def event(self, message):
        entry = dict(time=time.strftime("%H:%M:%S"), timestamp=time.strftime("%Y-%m-%dT%H:%M:%S%z"), message=message)
        self.events.append(entry)
        if self.event_file:
            try:
                path = Path(self.event_file)
                if path.exists() and path.stat().st_size >= 10 * 1024 * 1024:
                    raise OSError("Event log full")
                fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                with os.fdopen(fd, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry) + "\n")
                self.event_log_error = False
            except OSError:
                self.event_log_error = True

    def choose(self, now=None, measurement_round=False):
        now = time.monotonic() if now is None else now
        for r in self.routes:
            if r.state == "UP" and now - r.last > self.cfg["stale_after"]:
                r.state, r.good = "DOWN", 0
                r.error = "Measurements expired"
        candidates = self.ordered(now)
        old = self.active
        preferred = next((r for r in candidates if r.name == self.preferred), None)
        if preferred:
            self.active = preferred
        elif old not in candidates:
            self.active = candidates[0] if candidates else None
        elif self.policy == "priority" and self.cfg["failback"] and candidates and candidates[0].priority < old.priority and now - self.last_switch >= self.cfg["cooldown"]:
            self.active = candidates[0]
        elif self.policy == "quality" and measurement_round and candidates:
            best = candidates[0]
            better = best is not old and best.score() < old.score() * (1 - self.cfg["switch_margin"] / 100)
            if better:
                self.challenger_rounds = self.challenger_rounds + 1 if self.challenger == best.name else 1
                self.challenger = best.name
                if self.challenger_rounds >= self.cfg["switch_rounds"] and now - self.last_switch >= self.cfg["cooldown"]:
                    self.active = best
            else:
                self.challenger, self.challenger_rounds = None, 0
        if old is not self.active:
            self.last_switch = now
            if old:
                self.switches += 1
            self.event(f"{old.name if old else 'NO ROUTE'} -> {self.active.name if self.active else 'NO ROUTE'}")
            self.challenger, self.challenger_rounds = None, 0
        return self.active

    def snapshot(self):
        return dict(version=VERSION, demo=self.demo, uptime_s=int(time.monotonic() - self.started),
                    active=self.active.name if self.active else None, switches=self.switches,
                    connections=self.connections, bytes=self.bytes,
                    event_log_error=self.event_log_error,
                    state_persistent=bool(self.state_file), state_error=self.state_error,
                    gateway=f"127.0.0.1:{self.cfg['listen_port']}",
                    profile=self.profile, profiles=self.cfg["profiles"], preferred=self.preferred,
                    policy=self.policy, engines={k: v.public() for k, v in self.supervisors.items()},
                    forwards=[dict(name=f["name"], listen_port=f["listen_port"]) for f in self.cfg["tcp_forwards"]],
                    routes=[r.public() for r in self.routes], events=list(self.events), history=list(self.history))

    async def tick(self):
        async def bounded(proxy, target):
            async with self.probe_slots:
                return await measure(proxy, target, self.cfg["timeout"])
        async def probe(r):
            if not r.enabled:
                return
            revision = r.revision
            results = await asyncio.gather(*(bounded(r.proxy, t) for t in self.cfg["targets"]))
            if not r.enabled or r.revision != revision:
                return
            if r.name in self.supervisors and self.supervisors[r.name].state != "RUNNING":
                results = [dict(ok=False, latency_ms=0, error="Engine stopped") for _ in results]
            r.target_results = [dict(target=f"T{i+1}", ok=x["ok"], latency_ms=round(x["latency_ms"], 1), error=x["error"]) for i, x in enumerate(results)]
            good = [x["latency_ms"] for x in results if x["ok"]]
            ok = len(good) >= self.cfg["quorum"]
            old_state = r.state
            r.update(ok, statistics.median(good) if good else None,
                     "; ".join(sorted(set(x["error"] for x in results if not x["ok"]))), self.cfg, time.monotonic())
            if r.state != old_state:
                self.event(f"{r.name}: {r.state}")
        await asyncio.gather(*(probe(r) for r in self.routes))
        self.choose(measurement_round=True)
        self.record()

    def record(self):
        self.history.append(dict(t=int(time.monotonic() - self.started),
                                 routes={r.name: r.latency if r.enabled and r.bad == 0 else None for r in self.routes}))

    async def monitor(self):
        while True:
            start = time.monotonic()
            await self.tick()
            await asyncio.sleep(max(0.1, self.cfg["interval"] - (time.monotonic() - start)))


async def close(writer):
    writer.close()
    with contextlib.suppress(Exception):
        await asyncio.wait_for(writer.wait_closed(), 2)


async def socks_address(reader):
    kind = (await reader.readexactly(1))[0]
    if kind == 1:
        host = str(ipaddress.ip_address(await reader.readexactly(4)))
    elif kind == 4:
        host = str(ipaddress.ip_address(await reader.readexactly(16)))
    elif kind == 3:
        n = (await reader.readexactly(1))[0]
        host = (await reader.readexactly(n)).decode("ascii")
        if not host or not re.fullmatch(r"[A-Za-z0-9_.-]+", host):
            raise ValueError("Invalid hostname")
    else:
        raise ValueError("Unsupported address type")
    port = struct.unpack("!H", await reader.readexactly(2))[0]
    if not port:
        raise ValueError("Invalid port")
    return host, port


def encode_address(host, port):
    try:
        ip = ipaddress.ip_address(host)
        address = bytes([1 if ip.version == 4 else 4]) + ip.packed
    except ValueError:
        raw = host.encode("idna")
        if not 1 <= len(raw) <= 255:
            raise ValueError("Invalid hostname length")
        address = b"\x03" + bytes([len(raw)]) + raw
    return address + struct.pack("!H", port)


async def upstream(proxy, host, port):
    p = urlsplit(proxy)
    reader, writer = await asyncio.open_connection(p.hostname, p.port, limit=16384, happy_eyeballs_delay=0.25)
    try:
        if p.scheme == "http":
            authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
            headers = f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n"
            if p.username is not None:
                token = base64.b64encode(f"{unquote(p.username)}:{unquote(p.password or '')}".encode()).decode()
                headers += f"Proxy-Authorization: Basic {token}\r\n"
            writer.write((headers + "\r\n").encode("ascii"))
            await writer.drain()
            response = await reader.readuntil(b"\r\n\r\n")
            first = response.split(b"\r\n", 1)[0].split()
            if len(first) < 2 or first[1] != b"200":
                raise OSError("HTTP proxy rejected CONNECT")
        else:
            auth = p.username is not None
            writer.write(b"\x05\x01\x02" if auth else b"\x05\x01\x00")
            await writer.drain()
            if await reader.readexactly(2) != (b"\x05\x02" if auth else b"\x05\x00"):
                raise OSError("SOCKS authentication negotiation failed")
            if auth:
                user, password = unquote(p.username).encode(), unquote(p.password or "").encode()
                if not 1 <= len(user) <= 255 or not 1 <= len(password) <= 255:
                    raise ValueError("SOCKS credentials must be 1..255 bytes")
                writer.write(b"\x01" + bytes([len(user)]) + user + bytes([len(password)]) + password)
                await writer.drain()
                if await reader.readexactly(2) != b"\x01\x00":
                    raise OSError("SOCKS authentication failed")
            writer.write(b"\x05\x01\x00" + encode_address(host, port))
            await writer.drain()
            head = await reader.readexactly(3)
            if head != b"\x05\x00\x00":
                raise OSError("SOCKS proxy rejected CONNECT")
            # BND.PORT may legally be zero.
            kind = (await reader.readexactly(1))[0]
            if kind == 1:
                await reader.readexactly(6)
            elif kind == 4:
                await reader.readexactly(18)
            elif kind == 3:
                await reader.readexactly((await reader.readexactly(1))[0] + 2)
            else:
                raise OSError("Invalid SOCKS reply")
        return reader, writer
    except BaseException:
        await close(writer)
        raise


async def relay(ar, aw, br, bw, guard):
    async def pump(reader, writer):
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
            guard.bytes += len(data)
        if writer.can_write_eof():
            writer.write_eof()
    tasks = [asyncio.create_task(pump(ar, bw)), asyncio.create_task(pump(br, aw))]
    try:
        await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def dial(guard, host=None, port=None, forward=None):
    active = guard.choose()
    candidates = guard.ordered()
    if active in candidates:
        candidates.remove(active)
        candidates.insert(0, active)
    if forward:
        candidates = [r for r in candidates if r.name in forward["targets"]]
    for route in candidates[:guard.cfg["connect_attempts"]]:
        if route not in guard.eligible():
            continue
        try:
            async with asyncio.timeout(guard.cfg["timeout"]):
                if forward:
                    target = forward["targets"][route.name]
                    result = await asyncio.open_connection(target["host"], target["port"], happy_eyeballs_delay=0.25)
                else:
                    result = await upstream(route.proxy, host, port)
            if route not in guard.eligible():
                await close(result[1])
                continue
            return result
        except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            route.connect_failures += 1
            # A single destination refusal does not prove the whole path is down.
    raise OSError("No eligible route completed the connection")


async def tcp_forward(guard, spec, reader, writer):
    task = asyncio.current_task()
    guard.tasks.add(task)
    remote = None
    if guard.connections >= guard.cfg["max_connections"]:
        guard.tasks.discard(task)
        await close(writer)
        return
    guard.connections += 1
    try:
        rr, remote = await dial(guard, forward=spec)
        await relay(reader, writer, rr, remote, guard)
    except (OSError, ValueError, asyncio.TimeoutError, asyncio.IncompleteReadError):
        pass
    finally:
        if remote:
            await close(remote)
        await close(writer)
        guard.connections -= 1
        guard.tasks.discard(task)


async def gateway(guard, reader, writer):
    task = asyncio.current_task()
    guard.tasks.add(task)
    upstream_writer = None
    accepted = False
    if guard.connections >= guard.cfg["max_connections"]:
        guard.tasks.discard(task)
        await close(writer)
        return
    guard.connections += 1
    try:
        async with asyncio.timeout(guard.cfg["timeout"] + 2):
            version, n = await reader.readexactly(2)
            methods = await reader.readexactly(n)
            if version != 5 or 0 not in methods:
                writer.write(b"\x05\xff")
                await writer.drain()
                return
            writer.write(b"\x05\x00")
            await writer.drain()
            ver, cmd, reserved = await reader.readexactly(3)
            if (ver, cmd, reserved) != (5, 1, 0):
                writer.write(b"\x05\x07\x00\x01" + b"\x00" * 6)
                await writer.drain()
                return
            host, port = await socks_address(reader)
        ur, upstream_writer = await dial(guard, host, port)
        async with asyncio.timeout(guard.cfg["timeout"]):
            writer.write(b"\x05\x00\x00\x01" + b"\x00" * 6)
            await writer.drain()
            accepted = True
        await relay(reader, writer, ur, upstream_writer, guard)
    except (OSError, ValueError, UnicodeError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
        if not accepted:
            with contextlib.suppress(Exception):
                writer.write(b"\x05\x01\x00\x01" + b"\x00" * 6)
                await writer.drain()
    finally:
        if upstream_writer:
            await close(upstream_writer)
        await close(writer)
        guard.connections -= 1
        guard.tasks.discard(task)


def dashboard_html(snapshot=None, token=None):
    html = (ROOT / "dashboard.html").read_text(encoding="utf-8")
    initial = json.dumps(snapshot, ensure_ascii=True).replace("<", "\\u003c") if snapshot is not None else "null"
    return html.replace("/*SNAPSHOT*/null", initial).replace("/*CONTROL*/null", json.dumps(token))


async def dashboard(guard, reader, writer):
    task = asyncio.current_task()
    guard.tasks.add(task)
    try:
        raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 3)
        request = raw.decode("ascii").split("\r\n")
        method, path, _ = request[0].split()
        headers = {}
        for line in request[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip().lower()
                if key in headers:
                    raise ValueError("Duplicate header")
                headers[key] = value.strip()
        host = headers.get("host", "")
        expected = {f"127.0.0.1:{guard.cfg['dashboard_port']}", f"localhost:{guard.cfg['dashboard_port']}"}
        if host not in expected:
            code, mime, body = "403 Forbidden", "text/plain", b"Forbidden"
        elif method == "POST" and path == "/api/control":
            valid_origin = headers.get("origin") == f"http://{host}"
            valid_token = secrets.compare_digest(headers.get("x-tunnelguard-token", ""), guard.control_token)
            length = headers.get("content-length", "")
            if not valid_origin or not valid_token or headers.get("content-type") != "application/json" or "transfer-encoding" in headers:
                code, mime, body = "403 Forbidden", "application/json", b'{"error":"Unauthorized control request"}'
            elif not length.isdigit() or not 1 <= int(length) <= 2048:
                code, mime, body = "413 Payload Too Large", "application/json", b'{"error":"Invalid request size"}'
            else:
                try:
                    payload = await asyncio.wait_for(reader.readexactly(int(length)), 3)
                    guard.control(json.loads(payload))
                    code, mime, body = "200 OK", "application/json", b'{"ok":true}'
                except (ValueError, TypeError, KeyError):
                    code, mime, body = "400 Bad Request", "application/json", b'{"error":"Invalid action or route not eligible"}'
        elif method == "GET" and path == "/api/status":
            code, mime, body = "200 OK", "application/json", json.dumps(guard.snapshot()).encode()
        elif method == "GET" and path == "/":
            code, mime, body = "200 OK", "text/html; charset=utf-8", dashboard_html(token=guard.control_token).encode()
        else:
            code, mime, body = "404 Not Found", "text/plain", b"Not found"
        writer.write((f"HTTP/1.1 {code}\r\nContent-Type: {mime}\r\nContent-Length: {len(body)}\r\n"
                      "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n"
                      "Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'\r\n"
                      "Connection: close\r\n\r\n").encode() + body)
        await writer.drain()
    except (OSError, ValueError, UnicodeError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
        pass
    finally:
        await close(writer)
        guard.tasks.discard(task)


def save_report(guard, output):
    folder = Path(output)
    folder.mkdir(parents=True, exist_ok=True)
    data = guard.snapshot()
    for name, content in (("report.json", json.dumps(data, indent=2)), ("report.html", dashboard_html(data))):
        # Replace each file atomically so browser refreshes never read a partial report.
        import tempfile
        fd, temporary = tempfile.mkstemp(prefix=".tunnelguard-", dir=folder)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(content)
            os.replace(temporary, folder / name)
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary)


async def demo_monitor(guard):
    guard.event(f"SIMULATION: {guard.routes[0].name} outage at 12s; recovery at 30s; cycle 48s")
    step = 0
    while True:
        for i, route in enumerate(guard.routes):
            if not route.enabled:
                continue
            ok = not (i == 0 and 12 <= step % 48 < 30)
            route.update(ok, 75 + i * 65 + 12 * math.sin(step / 3 + i), "Simulated timeout", guard.cfg, time.monotonic())
        guard.choose(measurement_round=True)
        guard.record()
        step += 1
        await asyncio.sleep(1)


async def serve(cfg, args):
    guard = Guard(cfg, args.command == "demo")
    protected = {Path(args.config).resolve(), ROOT / "tunnelguard.py", ROOT / "engines.py", ROOT / "dashboard.html"}
    if args.events_file and Path(args.events_file).resolve() in protected:
        raise ConfigError("Event log must not overwrite configuration or application files")
    guard.event_file = args.events_file
    if args.state_file:
        if guard.demo:
            raise ConfigError("State persistence is disabled in demo to avoid saving simulated choices")
        if Path(args.state_file).resolve() in protected or (args.events_file and Path(args.state_file).resolve() == Path(args.events_file).resolve()):
            raise ConfigError("State file must differ from configuration, source and event log files")
        guard.restore_state(args.state_file)
    servers = []
    tasks = []
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stop.set)
    try:
        if not guard.demo:
            servers.append(await asyncio.start_server(lambda r, w: gateway(guard, r, w), "127.0.0.1", cfg["listen_port"], limit=16384))
            for spec in cfg["tcp_forwards"]:
                servers.append(await asyncio.start_server(lambda r, w, s=spec: tcp_forward(guard, s, r, w), "127.0.0.1", spec["listen_port"], limit=16384))
        servers.append(await asyncio.start_server(lambda r, w: dashboard(guard, r, w), "127.0.0.1", cfg["dashboard_port"], limit=16384))
        if not guard.demo and args.manage_engines:
            for definition, route in zip(cfg["routes"], guard.routes):
                if "engine" not in definition:
                    continue
                def stopped(r=route):
                    r.revision += 1
                    r.state, r.good = "DOWN", 0
                    r.error = "Engine stopped"
                    guard.choose()
                supervisor = Supervisor(route.name, definition["engine"], guard.event, stopped)
                guard.supervisors[route.name] = supervisor
                tasks.append(asyncio.create_task(supervisor.run()))
        mode = say("شبیه‌سازی؛ پروکسی غیرفعال", "SIMULATION - no gateway") if guard.demo else 'LIVE - SOCKS5 127.0.0.1:' + str(cfg['listen_port'])
        print(f"TunnelGuard {VERSION} | {mode}", flush=True)
        print(say("داشبورد", "Dashboard") + f": http://127.0.0.1:{cfg['dashboard_port']} | Ctrl+C " + say("برای توقف", "to stop"), flush=True)
        monitor = asyncio.create_task(demo_monitor(guard) if guard.demo else guard.monitor())
        async def reporter():
            while True:
                await asyncio.sleep(5)
                print(f"[{time.strftime('%H:%M:%S')}] " + say("مسیر فعال", "active") + f"={guard.active.name if guard.active else 'NONE'} | " +
                      " | ".join(f"{r.name}:{r.state}" for r in guard.routes), flush=True)
                if args.output:
                    save_report(guard, args.output)
        tasks.extend([monitor, asyncio.create_task(reporter()), asyncio.create_task(stop.wait())])
        if args.duration:
            tasks.append(asyncio.create_task(asyncio.sleep(args.duration)))
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    finally:
        for server in servers:
            server.close()
            await server.wait_closed()
        for task in tasks + list(guard.tasks):
            task.cancel()
        await asyncio.gather(*tasks, *list(guard.tasks), return_exceptions=True)
        if args.output:
            save_report(guard, args.output)


async def lab(cfg, args):
    guard = Guard(cfg)
    for n in range(args.rounds):
        if n:
            await asyncio.sleep(cfg["interval"])
        await guard.tick()
    print(json.dumps(guard.snapshot(), indent=2))
    save_report(guard, args.output)
    return 0 if guard.active else 2


async def benchmark(cfg, args):
    url_check(args.url)
    results = []
    # Sequential: routes should not compete for the same access link.
    for route in cfg["routes"]:
        samples = [await measure(route["proxy"], {"url": args.url, "status": [200, 206]}, args.timeout, args.max_bytes) for _ in range(args.rounds)]
        good = [s["mbps"] for s in samples if s["ok"]]
        results.append(dict(name=route["name"], median_mbps=round(statistics.median(good), 2) if good else None, samples=samples))
        print(f"{route['name']}: {results[-1]['median_mbps']} Mbps; {len(good)}/{len(samples)} successful", flush=True)
    Path(args.output).mkdir(parents=True, exist_ok=True)
    (Path(args.output) / "benchmark.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    return 0 if all(any(s["ok"] for s in r["samples"]) for r in results) else 2


def main():
    global LANG
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    LANG = "en" if "--lang" in sys.argv and sys.argv[sys.argv.index("--lang")+1:][:1] == ["en"] else "fa"
    parser = argparse.ArgumentParser(description=say("TunnelGuard: آزمایشگاه مسیر و پروکسی محلی با پشتیبان خودکار", __doc__))
    parser.add_argument("--version", action="version", version=VERSION)
    subs = parser.add_subparsers(dest="command", required=True)
    descriptions = {"run":("اجرای نگهبان و داشبورد", "Run gateway and dashboard"), "lab":("آزمایش سلامت مسیرها", "Measure route health"), "demo":("دموی آفلاین با داده ساختگی", "Offline simulation"), "benchmark":("آزمایش سرعت دانلود", "Bounded download benchmark"), "check":("بررسی تنظیمات و وابستگی‌ها", "Validate configuration and dependencies"), "init":("ساخت تنظیمات بدون بازنویسی فایل موجود", "Create configuration without overwriting"), "adapters":("نمایش هسته‌های قابل مدیریت", "List supported engine launch adapters")}
    for cmd in descriptions:
        sub = subs.add_parser(cmd, help=say(*descriptions[cmd]))
        sub.add_argument("--lang", choices=("fa", "en"), default="fa", help="زبان پیام‌ها / Message language")
        sub.add_argument("--config", default=str(ROOT / "config.example.json") if cmd == "demo" else default_config(), help=say("مسیر فایل تنظیمات", "Configuration file path"))
        if cmd == "init":
            sub.add_argument("--output", default=str(ROOT / "config.json"), help=say("محل فایل جدید", "New configuration path"))
            sub.add_argument("--interactive", action="store_true", help=say("تنظیم مرحله‌به‌مرحله مسیرها", "Interactive route setup"))
        if cmd == "check":
            sub.add_argument("--check-engines", action="store_true", help=say("بررسی وجود فایل هسته و تنظیمات و هش اختیاری؛ بدون اجرا", "Check engine files and optional hashes without launching"))
        if cmd in ("run", "demo"):
            sub.add_argument("--duration", type=int, default=0, help="Stop after N seconds; 0 = continuous")
            sub.add_argument("--output", default=None, help="Optional report directory (overwritten every 5s)")
            sub.add_argument("--manage-engines", action="store_true", help=say("اجرای هسته‌های ثبت‌شده؛ در دمو نادیده گرفته می‌شود", "Launch configured cores; ignored in demo"))
            sub.add_argument("--events-file", default=None, help=say("ثبت رویداد JSONL تا سقف ۱۰ مگابایت", "Append event JSONL (10 MiB cap)"))
            sub.add_argument("--state-file", default=None, help=say("ذخیره انتخاب‌های داشبورد برای اجرای بعدی؛ فقط حالت واقعی", "Persist dashboard choices across live runs"))
        if cmd in ("lab", "benchmark"):
            sub.add_argument("--rounds", type=int, default=3)
            sub.add_argument("--output", default="reports")
        if cmd == "benchmark":
            sub.add_argument("--url", required=True, help="URL of a known-size static file you control")
            sub.add_argument("--max-bytes", type=int, default=5_242_880)
            sub.add_argument("--timeout", type=int, default=20)
    args = parser.parse_args()
    LANG = args.lang
    try:
        if args.command == "adapters":
            print(json.dumps(ENGINES, indent=2))
            return 0
        if args.command == "init":
            initialize(args.output, args.interactive)
            return 0
        cfg = load_config(args.config)
        if args.command != "demo":
            curl = shutil.which("curl")
            if not curl:
                print(say("curl نسخه 8.4 یا جدیدتر لازم است؛ آن را با مدیر بسته سیستم نصب کنید.", "curl 8.4+ is required. Install it with your OS package manager."), file=sys.stderr)
                return 1
            version = subprocess.run([curl, "-q", "--version"], capture_output=True, text=True, timeout=5)
            match = re.match(r"curl (\d+)\.(\d+)\.(\d+)", version.stdout)
            if not match or tuple(map(int, match.groups())) < (8, 4, 0):
                print(say("برای اعمال سقف حجم دانلود، curl نسخه 8.4 یا جدیدتر لازم است.", "curl 8.4+ is required to enforce limits on unknown-size downloads."), file=sys.stderr)
                return 1
        if hasattr(args, "rounds") and not 1 <= args.rounds <= 50:
            raise ValueError("rounds must be 1..50")
        if getattr(args, "duration", 0) < 0:
            raise ValueError("duration cannot be negative")
        if args.command == "benchmark" and not (1 <= args.max_bytes <= 104857600 and 1 <= args.timeout <= 120):
            raise ValueError("benchmark cap: 1..100 MiB; timeout: 1..120 seconds")
        if args.command == "check":
            if args.check_engines:
                for route in cfg["routes"]:
                    if "engine" in route:
                        try:
                            engine_command(route["engine"])
                        except ValueError as exc:
                            raise ConfigError(str(exc)) from None
            print(say(f"تنظیمات معتبر است: {len(cfg['routes'])} مسیر و {len(cfg['targets'])} هدف. درخواست شبکه ارسال نشد.", f"Configuration valid: {len(cfg['routes'])} routes, {len(cfg['targets'])} targets. No network requests made."))
            return 0
        if args.command == "demo":
            cfg["failback"], cfg["cooldown"] = True, 5
        if args.command in ("run", "demo"):
            asyncio.run(serve(cfg, args))
            return 0
        return asyncio.run(lab(cfg, args) if args.command == "lab" else benchmark(cfg, args))
    except KeyboardInterrupt:
        return 130
    except ConfigError as exc:
        print(say("خطای تنظیمات؛ جزئیات فیلد نامعتبر: ", "Configuration error: ") + str(exc), file=sys.stderr)
        return 1
    except EOFError:
        print(say("ورودی راه‌اندازی بسته شد؛ فایل تنظیمات ساخته نشد.", "Setup input closed; no configuration was created."), file=sys.stderr)
        return 1
    except FileExistsError:
        print(say("فایل از قبل وجود دارد؛ برای حفظ تنظیمات شما بازنویسی نشد. مسیر خروجی دیگری انتخاب کنید.", "File already exists; it was not overwritten. Choose another output path."), file=sys.stderr)
        return 1
    except FileNotFoundError:
        print(say("فایل تنظیمات یا یکی از فایل‌های برنامه پیدا نشد. مسیر --config و کامل بودن پوشه را بررسی کنید.", "Configuration or application file not found. Check --config and the package contents."), file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(say(f"ساختار JSON معتبر نیست؛ خط {exc.lineno}، ستون {exc.colno}.", f"Invalid JSON at line {exc.lineno}, column {exc.colno}."), file=sys.stderr)
        return 1
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as exc:
        # Do not echo URL-bearing exceptions or config content.
        print(say(f"خطا ({type(exc).__name__}): تنظیمات، وابستگی‌ها، آزاد بودن پورت‌ها و مجوز نوشتن پوشه خروجی را بررسی کنید.", f"Error: {type(exc).__name__}. Check configuration, dependencies, ports and writable output directory."), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
