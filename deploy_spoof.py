"""Optional paired Parsa UDP-pipe + authenticated Hysteria2 deployment."""
import argparse
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

import deploy

VERSION = "v3.1.0-beta.0"
HASHES = {
    "amd64": "4ba5597568607e864fb6d5ba4f13bac91a50456da5696d99463d6375ce2a3697",
    "arm64": "ab7e0a58aa37c63a36127feb99ef73cd498523c99d22146feb1a93dd97c9d97b",
}
PREFIX = Path("/opt/tunnelguard-spoof")
EXISTING_GUARD = Path("/opt/tunnelguard-node/client/config.json")


def validate(s):
    if s.get("version") != VERSION:
        raise ValueError("Unsupported Spoof version")
    for key in ("server_ip", "client_ip", "server_source", "client_source"):
        ip = ipaddress.IPv4Address(s[key])
        if ip.is_multicast or ip.is_unspecified or str(ip) == "255.255.255.255":
            raise ValueError("Use unicast IPv4 addresses")
    for direction in ("uplink", "downlink"):
        if s[direction] not in ("tcp", "udp"):
            raise ValueError("This installer supports TCP/UDP carriers only")
    ports = [s[k] for k in ("server_port", "client_port", "overlay_port", "bridge_port", "socks_port")]
    if any(type(p) is not int or not 1024 <= p <= 65535 for p in ports) or len(set(ports)) != len(ports):
        raise ValueError("Choose distinct ports in 1024..65535")
    if any(p in (1088, 8787) for p in ports):
        raise ValueError("Port conflicts with gateway/dashboard")


def carrier(s, role):
    validate(s)
    if role == "server":
        return dict(mode="remote", listen_port=s["server_port"], forward=f"127.0.0.1:{s['overlay_port']}",
                    client_ip=s["client_ip"], client_port=s["client_port"], spoof_ip=s["server_source"],
                    spoof_port=s["server_port"], peer_spoof_ip=s["client_source"],
                    send_transport=s["downlink"], recv_transport=s["uplink"])
    return dict(mode="local", listen=f"127.0.0.1:{s['bridge_port']}", remote=s["server_ip"],
                remote_port=s["server_port"], recv_port=s["client_port"], spoof_ip=s["client_source"],
                spoof_port=s["client_port"], peer_spoof_ip=s["server_source"],
                send_transport=s["uplink"], recv_transport=s["downlink"])


def generate_server(folder, s):
    validate(s)
    # Reuse the existing tested certificate/password generator without exposing a
    # public overlay listener or generating another certificate implementation.
    b = deploy.generate_server(folder, s["server_ip"], [18443, 18444, 18445])
    cfg = json.loads((folder/"server.json").read_text())
    hy = next(i for i in cfg["inbounds"] if i["type"] == "hysteria2")
    hy.update(listen="127.0.0.1", listen_port=s["overlay_port"], initial_packet_size=1200, disable_path_mtu_discovery=True)
    cfg["inbounds"] = [hy]
    (folder/"server.json").unlink()
    deploy.write_private(folder/"overlay.json", cfg)
    b["spoof"] = s
    (folder/"pairing.json").unlink()
    deploy.write_private(folder/"pairing.json", b)
    deploy.write_private(folder/"carrier.json", carrier(s, "server"))
    return b


def generate_client(folder, pairing):
    if pairing.stat().st_size > 32768:
        raise ValueError("Pairing file too large")
    b = json.loads(pairing.read_text(encoding="utf-8"))
    s = b["spoof"]
    validate(s)
    _, clients, guard = deploy.configs(b)
    hy = clients["hysteria2"]
    hy["inbounds"][0]["listen_port"] = s["socks_port"]
    hy["outbounds"][0].update(server="127.0.0.1", server_port=s["bridge_port"], initial_packet_size=1200,
                              disable_path_mtu_discovery=True)
    folder.mkdir(mode=0o700, parents=True, exist_ok=False)
    deploy.write_private(folder/"overlay.json", hy)
    deploy.write_private(folder/"carrier.json", carrier(s, "client"))
    route = dict(name="Spoof", proxy=f"socks5h://127.0.0.1:{s['socks_port']}", priority=40, layer="SPOOF-HY2-TLS")
    guard.update(routes=[route], profiles={"All": ["Spoof"], "Emergency": ["Spoof"]}, default_profile="All")
    deploy.write_private(folder/"config.json", guard)
    return s


def install_binary(folder, offline=None):
    arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    if platform.system() != "Linux" or arch not in HASHES:
        raise ValueError("Requires Linux amd64/arm64")
    with tempfile.TemporaryDirectory(dir=folder) as temp:
        candidate = Path(temp)/"spoof"
        if offline:
            if offline.stat().st_size > deploy.MAX_ARCHIVE:
                raise ValueError("Binary too large")
            shutil.copyfile(offline, candidate)
        else:
            url = f"https://github.com/ParsaKSH/spoof-tunnel/releases/download/{VERSION}/spoof-linux-{arch}"
            with urllib.request.urlopen(url, timeout=60) as response, candidate.open("wb") as f:
                size = 0
                while chunk := response.read(1024*1024):
                    size += len(chunk)
                    if size > deploy.MAX_ARCHIVE:
                        raise ValueError("Binary too large")
                    f.write(chunk)
        with candidate.open("rb") as f:
            if hashlib.file_digest(f, "sha256").hexdigest() != HASHES[arch]:
                raise ValueError("Spoof binary SHA256 mismatch")
        binary = folder/"spoof"
        with candidate.open("rb") as src, binary.open("xb") as dst:
            shutil.copyfileobj(src, dst)
        binary.chmod(0o755)
    return binary


def carrier_unit(prefix):
    # Upstream insists on UID 0. Limit its capability set to NET_RAW; no NET_ADMIN,
    # XDP, global ICMP settings or firewall modifications are needed for TCP/UDP.
    return f"""[Unit]
Description=TunnelGuard Parsa Spoof carrier (experimental)
After=network-online.target
Wants=network-online.target
[Service]
User=root
CapabilityBoundingSet=CAP_NET_RAW
AmbientCapabilities=CAP_NET_RAW
LoadCredential=config.json:{prefix}/carrier.json
ExecStart={prefix}/spoof run -c %d/config.json
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_UNIX AF_NETLINK
UMask=0077
[Install]
WantedBy=multi-user.target
"""


def merge_route(existing, addition):
    cfg = copy.deepcopy(existing)
    route = addition["routes"][0]
    if any(r["name"] == "Spoof" or r["proxy"] == route["proxy"] for r in cfg["routes"]):
        raise ValueError("Spoof route name or endpoint already exists")
    cfg["routes"].append(route)
    profiles = cfg.setdefault("profiles", {"All": [r["name"] for r in existing["routes"]]})
    for name in ("All", "Emergency"):
        profiles.setdefault(name, []).append("Spoof")
    return cfg


def check_network(s, role):
    validate(s)
    if platform.system() != "Linux" or os.geteuid() != 0:
        raise ValueError("Requires Linux root")
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW):
        pass
    peer = s["client_ip"] if role == "server" else s["server_ip"]
    subprocess.run(["ip", "route", "get", peer], check=True, capture_output=True)
    print("Local raw socket + peer route: OK. Upstream spoof reachability is NOT proven.")


def apply(folder, role, s, core_archive=None, spoof_binary=None):
    check_network(s, role)
    prefix = PREFIX/role
    if not Path("/run/systemd/system").exists() or prefix.exists():
        raise ValueError("Needs systemd and a new installation directory")
    attaching = role == "client" and EXISTING_GUARD.exists()
    names = ["overlay", "carrier"] + (["guard"] if role == "client" and not attaching else [])
    for name in names:
        unit = f"tunnelguard-spoof-{role}-{name}.service"
        found = subprocess.run(["systemctl", "show", "--property=LoadState", "--value", unit], capture_output=True, text=True, check=True)
        if found.stdout.strip() != "not-found":
            raise ValueError("Spoof service already exists")
    if attaching:
        from tunnelguard import load_config
        original = EXISTING_GUARD.read_bytes()
        merged = merge_route(json.loads(original), json.loads((folder/"config.json").read_text()))
        deploy.write_private(folder/"merged.json", merged)
        load_config(folder/"merged.json")
    # Check ordinary listeners. A raw TCP receive port is also reserved here to
    # avoid choosing an existing TCP service's port, though raw sockets do not bind it.
    listeners = [("127.0.0.1", s["overlay_port"], True)] if role == "server" else [
        ("127.0.0.1", s["bridge_port"], True), ("127.0.0.1", s["socks_port"], False)]
    listeners.append(("0.0.0.0", s["server_port"] if role == "server" else s["client_port"],
                      s["uplink" if role == "server" else "downlink"] == "udp"))
    if role == "client" and not attaching:
        listeners.extend([("127.0.0.1", 1088, False), ("127.0.0.1", 8787, False)])
    sockets = []
    try:
        for host, port, udp in listeners:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
            sockets.append(sock)
            sock.bind((host, port))
    finally:
        for sock in sockets:
            sock.close()
    core = deploy.install_core(folder, core_archive)
    raw = install_binary(folder, spoof_binary)
    subprocess.run([str(core), "check", "-c", str(folder/"overlay.json")], check=True, capture_output=True)
    PREFIX.mkdir(mode=0o755, exist_ok=True)
    PREFIX.chmod(0o755)
    prefix.mkdir(mode=0o755)
    prefix.chmod(0o755)
    units, started, changed = [], [], False
    try:
        for name in ("sing-box", "spoof", "overlay.json", "carrier.json"):
            shutil.copy2(folder/name, prefix/name)
        if role == "client":
            shutil.copy2(folder/"config.json", prefix/"config.json")
            if not attaching:
                (prefix/"app").mkdir(mode=0o755)
                for name in ("tunnelguard.py", "engines.py", "dashboard.html"):
                    shutil.copy2(deploy.ROOT/name, prefix/"app"/name)
                    (prefix/"app"/name).chmod(0o644)
        for name in names:
            unit = Path("/etc/systemd/system")/f"tunnelguard-spoof-{role}-{name}.service"
            text = carrier_unit(prefix) if name == "carrier" else deploy.unit_text(prefix, name, name == "guard")
            deploy.write_private(unit, text)
            units.append(unit)
            unit.chmod(0o644)
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        for unit in units:
            started.append(unit.name)
            subprocess.run(["systemctl", "enable", "--now", unit.name], check=True)
        time.sleep(2)
        for unit in units:
            subprocess.run(["systemctl", "is-active", "--quiet", unit.name], check=True)
        if attaching:
            # Preserve exact original bytes for rollback, including formatting.
            deploy.write_private(prefix/"guard-backup.json", original.decode("utf-8"))
            replacement = EXISTING_GUARD.with_name(".tg-spoof-config.json")
            if EXISTING_GUARD.read_bytes() != original:
                raise ValueError("Guard config changed during installation")
            deploy.write_private(replacement, merged)
            os.replace(replacement, EXISTING_GUARD)
            changed = True
            subprocess.run(["systemctl", "restart", "tunnelguard-client-guard"], check=True)
            time.sleep(2)
            subprocess.run(["systemctl", "is-active", "--quiet", "tunnelguard-client-guard"], check=True)
    except Exception:
        if changed:
            replacement = EXISTING_GUARD.with_name(".tg-spoof-restore.json")
            deploy.write_private(replacement, original.decode("utf-8"))
            os.replace(replacement, EXISTING_GUARD)
            subprocess.run(["systemctl", "restart", "tunnelguard-client-guard"], capture_output=True)
        for name in started:
            subprocess.run(["systemctl", "disable", "--now", name], capture_output=True)
        for unit in units:
            unit.unlink(missing_ok=True)
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        shutil.rmtree(prefix)
        raise


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("role", choices=["spoof-server", "spoof-client"])
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--address")
    p.add_argument("--client-address")
    p.add_argument("--server-source", help="Explicit authorized source IPv4")
    p.add_argument("--client-source", help="Explicit authorized source IPv4")
    p.add_argument("--uplink", choices=["tcp", "udp"], default="tcp")
    p.add_argument("--downlink", choices=["tcp", "udp"], default="udp")
    p.add_argument("--server-port", type=int, default=19443)
    p.add_argument("--client-port", type=int, default=19444)
    p.add_argument("--overlay-port", type=int, default=19445)
    p.add_argument("--bridge-port", type=int, default=19446)
    p.add_argument("--socks-port", type=int, default=11004)
    p.add_argument("--bundle", type=Path)
    p.add_argument("--apply", action="store_true")
    p.add_argument("--core-archive", type=Path)
    p.add_argument("--spoof-binary", type=Path)
    a = p.parse_args()
    role = a.role.split("-")[1]
    try:
        if role == "server":
            if not all((a.address, a.client_address, a.server_source, a.client_source)):
                p.error("server requires --address, --client-address, --server-source, --client-source")
            s = dict(version=VERSION, server_ip=a.address, client_ip=a.client_address, server_source=a.server_source,
                     client_source=a.client_source, uplink=a.uplink, downlink=a.downlink, server_port=a.server_port,
                     client_port=a.client_port, overlay_port=a.overlay_port, bridge_port=a.bridge_port, socks_port=a.socks_port)
            generate_server(a.output, s)
        else:
            if not a.bundle:
                p.error("client requires --bundle")
            s = generate_client(a.output, a.bundle)
        if a.apply:
            apply(a.output.resolve(), role, s, a.core_archive, a.spoof_binary)
        print("Spoof configuration ready / تنظیمات اسپوف آماده:", a.output.resolve())
        print("Experimental upstream beta. See SPOOF.fa.md / SPOOF.md for firewall and pairing requirements.")
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as e:
        print(f"Spoof deployment failed ({type(e).__name__}); inspect dependencies, ports and service journal. Existing installation is not overwritten.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
