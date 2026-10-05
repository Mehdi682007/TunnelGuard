"""Explicit, shell-free launch adapters for separately installed tunnel cores."""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import random
import re
import signal
import time

# Config files belong to their original projects; TunnelGuard does not invent schemas.
ENGINES = {
    "ssh": {"args": ["-F", "{config}", "-N", "-D", "{listen}", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ExitOnForwardFailure=yes", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=3", "{host}"], "source": "https://man.openbsd.org/ssh.1", "output": "Local SOCKS5 through an explicitly configured SSH host alias"},
    "sing-box": {"args": ["run", "-c", "{config}"], "source": "https://sing-box.sagernet.org/", "output": "SOCKS/HTTP inbound; multiple outbound transports"},
    "xray": {"args": ["run", "-config", "{config}"], "source": "https://github.com/XTLS/Xray-core", "output": "SOCKS/HTTP inbound; VLESS, REALITY and other configured transports"},
    "hysteria2": {"args": ["client", "-c", "{config}"], "source": "https://v2.hysteria.network/", "output": "SOCKS/HTTP client over QUIC"},
    "gost": {"args": ["-C", "{config}"], "source": "https://gost.run/", "output": "Configured proxy or forwarding service (GOST v3)"},
    "backhaul": {"args": ["-c", "{config}"], "source": "https://github.com/Musixal/Backhaul", "output": "Forwarded port; forward a remote proxy for health checks"},
    "rathole": {"args": ["{config}"], "source": "https://github.com/rathole-org/rathole", "output": "Forwarded TCP port; needs proxy bridge for health checks"},
    "frpc": {"args": ["-c", "{config}"], "source": "https://gofrp.org/", "output": "Configured forwarded service; needs proxy bridge"},
    "candy-spoof": {"args": ["--config", "{config}"], "source": "https://github.com/AmiRCandy/Candy-Spoof", "output": "SOCKS5 client; Linux raw-socket permissions required"},
    "parsa-spoof": {"args": ["run", "-c", "{config}"], "source": "https://github.com/ParsaKSH/spoof-tunnel", "output": "v3 UDP pipe only; requires encrypted overlay and SOCKS bridge"},
}


def validate_engine(spec):
    if not isinstance(spec, dict) or spec.get("kind") not in ENGINES:
        raise ValueError("engine.kind is not supported; use adapters to list choices")
    for field in ("binary", "config"):
        value = spec.get(field)
        if not isinstance(value, str) or any(ord(c) < 32 for c in value) or not (PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute()):
            raise ValueError("engine.binary and engine.config must be absolute paths")
    digest = spec.get("sha256")
    if digest is not None and (not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdefABCDEF" for c in digest)):
        raise ValueError("engine.sha256 must contain 64 hexadecimal characters")
    if spec["kind"] == "ssh":
        if not isinstance(spec.get("host"), str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", spec["host"]):
            raise ValueError("SSH engine needs a valid host alias")
        if type(spec.get("local_port")) is not int or not 1 <= spec["local_port"] <= 65535:
            raise ValueError("SSH engine needs local_port in 1..65535")


def command(spec):
    validate_engine(spec)
    binary, config = Path(spec["binary"]), Path(spec["config"])
    if not binary.is_absolute() or not config.is_absolute():
        raise ValueError("Engine paths must be absolute for the current operating system")
    if not binary.is_file() or not config.is_file():
        raise ValueError("Engine binary or configuration file is missing")
    if "sha256" in spec:
        with binary.open("rb") as f:
            actual = hashlib.file_digest(f, "sha256").hexdigest()
        if actual != spec["sha256"].lower():
            raise ValueError("Engine binary SHA256 mismatch")
    replacements = {"{config}": str(config), "{listen}": f"127.0.0.1:{spec.get('local_port', 0)}", "{host}": spec.get("host", "")}
    return [str(binary), *(replacements.get(arg, arg) for arg in ENGINES[spec["kind"]]["args"])]


class Supervisor:
    """Restart crashed owned foreground processes; never restart on censorship probes."""
    def __init__(self, name, spec, on_event, on_exit):
        self.name, self.spec = name, spec
        self.on_event, self.on_exit = on_event, on_exit
        self.process = None
        self.state = "STOPPED"
        self.restarts = 0
        self.exit_code = None
        self.delay = 0

    def public(self):
        return dict(kind=self.spec["kind"], state=self.state, restarts=self.restarts,
                    exit_code=self.exit_code, retry_seconds=round(self.delay, 1))

    async def stop(self):
        proc = self.process
        if proc:
            # Also clean up children of a foreground process that already exited on POSIX.
            with contextlib.suppress(ProcessLookupError):
                if os.name == "posix":
                    os.killpg(proc.pid, signal.SIGTERM)
                elif proc.returncode is None:
                    proc.terminate()
            if proc.returncode is None:
                try:
                    await asyncio.wait_for(proc.wait(), 3)
                except asyncio.TimeoutError:
                    with contextlib.suppress(ProcessLookupError):
                        if os.name == "posix":
                            os.killpg(proc.pid, signal.SIGKILL)
                        else:
                            proc.kill()
                    await proc.wait()
        self.process = None

    async def run(self):
        crashes = 0
        try:
            while True:
                started = time.monotonic()
                self.state = "STARTING"
                try:
                    argv = command(self.spec)
                    self.process = await asyncio.create_subprocess_exec(
                        *argv, stdin=asyncio.subprocess.DEVNULL,
                        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
                        cwd=str(Path(self.spec["config"]).parent),
                        start_new_session=os.name == "posix")
                    self.state = "RUNNING"
                    self.on_event(f"{self.name}: ENGINE_RUNNING")
                    self.exit_code = await self.process.wait()
                except (OSError, ValueError):
                    self.exit_code = -1
                finally:
                    await self.stop()
                self.on_exit()
                self.state = "BACKOFF"
                self.restarts += 1
                crashes = 1 if time.monotonic() - started >= 120 else min(crashes + 1, 7)
                self.delay = min(120, 2 ** crashes) + random.uniform(0, 1)
                self.on_event(f"{self.name}: ENGINE_BACKOFF")
                await asyncio.sleep(self.delay)
        finally:
            await self.stop()
            self.state = "STOPPED"
