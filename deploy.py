#!/usr/bin/env python3
"""Generate and install paired sing-box nodes. Ubuntu 24.04, systemd, Python 3.11+."""
from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parent
VERSION = "1.14.2"
HASHES = {
    "amd64": "a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6",
    "arm64": "b43a1fb1bda131c6653576741ce527eb2bdeab7c9308ca90ee8b972abb7e4a7f",
}
KINDS = ("shadowsocks", "trojan", "hysteria2")
EXTRAS = ("vmess", "vless", "tuic", "anytls")
ALL_KINDS = KINDS + EXTRAS
MAX_ARCHIVE = 100 * 1024 * 1024


def write_private(path, data):
    path = Path(path)
    with path.open("x", encoding="utf-8", newline="\n") as f:
        os.chmod(path, 0o600)
        f.write(data if isinstance(data, str) else json.dumps(data, indent=2) + "\n")


def validate_bundle(b):
    if not isinstance(b, dict) or b.get("schema") != 1:
        raise ValueError("Unsupported pairing bundle")
    # Numeric endpoint avoids bootstrap DNS dependence and ambiguous host strings.
    ipaddress.ip_address(b["address"])
    if b.get("core_version") != VERSION:
        raise ValueError("Pairing bundle requires another core version")
    ports = b["ports"]
    if set(ports) not in (set(KINDS), set(ALL_KINDS)) or any(type(p) is not int or not 1024 <= p <= 65535 for p in ports.values()):
        raise ValueError("Ports must be 1024..65535")
    if len(set(ports.values())) != len(ports):
        raise ValueError("Choose three distinct ports")
    if 'vmess' in ports:
        if set(b.get('uuids', {})) != set(EXTRAS):
            raise ValueError('Extra transports require UUIDs')
        for kind in ('tuic','anytls'):
            value=b.get('extra_passwords',{}).get(kind,'')
            if not isinstance(value,str) or not 32<=len(value)<=128 or not all(c.isalnum() or c in '_-' for c in value):
                raise ValueError('Invalid extra password')
        for value in b['uuids'].values():
            if str(uuid.UUID(value)) != value:
                raise ValueError('Invalid UUID')
    if len(base64.b64decode(b["passwords"]["shadowsocks"], validate=True)) != 16:
        raise ValueError("Invalid Shadowsocks key")
    for k in ("trojan", "hysteria2"):
        p = b["passwords"][k]
        if not isinstance(p, str) or not 32 <= len(p) <= 128 or not all(c.isalnum() or c in "_-" for c in p):
            raise ValueError("Invalid password")
    cert = b["certificate"]
    if not isinstance(cert, str) or len(cert) > 16384 or not cert.startswith("-----BEGIN CERTIFICATE-----"):
        raise ValueError("Invalid certificate")


def configs(b, key=None, local_base=11001):
    validate_bundle(b)
    if not 1024 <= local_base <= 65533 or any(p in (1088, 8787) for p in range(local_base, local_base + 3)):
        raise ValueError("Local ports collide with gateway/dashboard or are out of range")
    inbound, clients, routes = [], {}, []
    for i, kind in enumerate(KINDS):
        auth = {"method": "2022-blake3-aes-128-gcm", "password": b["passwords"][kind]} if kind == "shadowsocks" else {"users": [{"password": b["passwords"][kind]}]}
        server = dict(type=kind, listen="0.0.0.0", listen_port=b["ports"][kind], **auth)
        if ":" in b["address"]:
            server["listen"] = "::"
        out = dict(type=kind, server=b["address"], server_port=b["ports"][kind], password=b["passwords"][kind])
        if kind == "shadowsocks":
            server["network"] = "tcp"
            out.update(method="2022-blake3-aes-128-gcm", network="tcp")
        else:
            server["tls"] = dict(enabled=True, certificate=b["certificate"].splitlines(), key=(key or "").splitlines())
            out["tls"] = dict(enabled=True, server_name="tunnelguard.internal", certificate=b["certificate"].splitlines())
        inbound.append(server)
        clients[kind] = {"log": {"level": "warn"}, "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": local_base+i}], "outbounds": [out]}
        routes.append(dict(name=kind, proxy=f"socks5h://127.0.0.1:{local_base+i}", priority=(i+1)*10,
                           layer={"shadowsocks": "TCP-AEAD", "trojan": "TCP-TLS", "hysteria2": "QUIC"}[kind]))
    if 'vmess' in b['ports']:
        if local_base + 8 > 65535 or any(p in (1088, 8787) for p in range(local_base+5, local_base+9)):
            raise ValueError('Extra local port collision')
        for index, kind in enumerate(EXTRAS):
            tls = dict(enabled=True, certificate=b['certificate'].splitlines(), key=(key or '').splitlines())
            server = dict(type=kind, listen='::' if ':' in b['address'] else '0.0.0.0', listen_port=b['ports'][kind], users=[dict(uuid=b['uuids'][kind])], tls=tls)
            out = dict(type=kind, server=b['address'], server_port=b['ports'][kind], uuid=b['uuids'][kind], network='tcp', tls=dict(enabled=True, server_name='tunnelguard.internal', certificate=b['certificate'].splitlines()))
            if kind == 'vmess':
                server['transport'] = out['transport'] = dict(type='ws', path='/tunnelguard')
                out['security'] = 'auto'
            if kind in ('tuic','anytls'):
                out.pop('network',None)
                out['password']=b['extra_passwords'][kind]
                server['users'][0]['password']=b['extra_passwords'][kind]
                if kind=='anytls':
                    out.pop('uuid')
                    server['users'][0].pop('uuid')
                else:
                    server['tls']['alpn']=out['tls']['alpn']=['h3']
            inbound.append(server)
            port = local_base+5+index
            clients[kind] = dict(log={'level':'warn'}, inbounds=[dict(type='socks',listen='127.0.0.1',listen_port=port)], outbounds=[out])
            routes.append(dict(name=kind, proxy=f'socks5h://127.0.0.1:{port}',priority=50+index*10,layer={'vmess':'WS-TLS','vless':'VLESS-TLS','tuic':'TUIC-QUIC','anytls':'AnyTLS'}[kind]))
    guard = json.loads((ROOT / "config.example.json").read_text(encoding="utf-8"))
    guard.update(routes=routes, profiles={"All": list(KINDS), "TCP": list(KINDS[:2]), "QUIC": [KINDS[2]]}, default_profile="All")
    if 'vmess' in b['ports']:
        guard['profiles']['All'].extend(EXTRAS)
        guard['profiles']['TCP'].extend(k for k in EXTRAS if k!='tuic')
        guard['profiles']['QUIC'].append('tuic')
        guard['profiles']['WebSocket'] = ['vmess']
    return {"log": {"level": "warn"}, "inbounds": inbound, "outbounds": [{"type": "direct"}]}, clients, guard


def generate_server(folder, address, ports, extra_ports=None):
    ipaddress.ip_address(address)
    all_ports = list(ports) + list(extra_ports or [])
    if len(ports) != 3 or (extra_ports is not None and len(extra_ports) != len(EXTRAS)) or len(set(all_ports)) != len(all_ports) or any(not 1024 <= p <= 65535 for p in all_ports):
        raise ValueError("Choose distinct ports in 1024..65535")
    if not shutil.which("openssl"):
        raise ValueError("Install openssl first")
    folder.mkdir(mode=0o700, parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(dir=folder) as temp:
        cert, key = Path(temp)/"cert.pem", Path(temp)/"key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "365",
                        "-subj", "/CN=tunnelguard.internal", "-addext", "subjectAltName=DNS:tunnelguard.internal",
                        "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
        b = dict(schema=1, core_version=VERSION, address=address, ports=dict(zip(KINDS, ports)),
                 passwords={k: (base64.b64encode(secrets.token_bytes(16)).decode() if k == "shadowsocks" else secrets.token_urlsafe(32)) for k in KINDS},
                 certificate=cert.read_text())
        if extra_ports:
            b['ports'].update(zip(EXTRAS, extra_ports))
            b['uuids'] = {kind: str(uuid.uuid4()) for kind in EXTRAS}
            b['extra_passwords'] = {kind: secrets.token_urlsafe(32) for kind in ('tuic','anytls')}
        server, _, _ = configs(b, key.read_text())
        write_private(folder/"server.json", server)
        write_private(folder/"pairing.json", b)
    return b


def generate_client(folder, pairing, local_base):
    if pairing.stat().st_size > 32768:
        raise ValueError("Pairing bundle is too large")
    b = json.loads(pairing.read_text(encoding="utf-8"))
    _, clients, guard = configs(b, local_base=local_base)
    folder.mkdir(mode=0o700, parents=True, exist_ok=False)
    for kind, cfg in clients.items():
        write_private(folder/f"{kind}.json", cfg)
    write_private(folder/"config.json", guard)


def unpack_verified(archive, destination, arch):
    if archive.stat().st_size > MAX_ARCHIVE:
        raise ValueError("Core archive too large")
    with archive.open("rb") as f:
        if hashlib.file_digest(f, "sha256").hexdigest() != HASHES[arch]:
            raise ValueError("Core archive SHA256 mismatch")
    name = f"sing-box-{VERSION}-linux-{arch}/sing-box"
    with tarfile.open(archive, "r:gz") as tf:
        members = [m for m in tf.getmembers() if m.name == name]
        if len(members) != 1 or not members[0].isfile() or members[0].size > MAX_ARCHIVE:
            raise ValueError("Invalid core archive member")
        # Never extract archive paths or symlinks.
        with tf.extractfile(members[0]) as src, destination.open("xb") as dst:
            shutil.copyfileobj(src, dst)
    destination.chmod(0o755)


def install_core(folder, offline=None):
    arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    if platform.system() != "Linux" or arch not in HASHES:
        raise ValueError("Core installer supports Linux amd64/arm64 only")
    binary = folder/"sing-box"
    if binary.exists():
        raise ValueError("Core destination exists")
    if offline:
        unpack_verified(offline, binary, arch)
    else:
        url = f"https://github.com/SagerNet/sing-box/releases/download/v{VERSION}/sing-box-{VERSION}-linux-{arch}.tar.gz"
        with tempfile.TemporaryDirectory(dir=folder) as temp:
            archive = Path(temp)/"core.tar.gz"
            with urllib.request.urlopen(url, timeout=60) as response, archive.open("wb") as f:
                size = 0
                while chunk := response.read(1024 * 1024):
                    size += len(chunk)
                    if size > MAX_ARCHIVE:
                        raise ValueError("Core archive too large")
                    f.write(chunk)
            unpack_verified(archive, binary, arch)
    return binary


def preflight(role):
    if platform.system() != "Linux" or os.geteuid() != 0 or not Path("/run/systemd/system").exists():
        raise ValueError("--apply requires root on a Linux host running systemd")
    for program in ("systemctl", "python3", "curl"):
        if not shutil.which(program):
            raise ValueError(f"Install {program} first")
    prefix = Path("/opt/tunnelguard-node")/role
    names = ["server"] if role == "server" else [*ALL_KINDS, "guard"]
    for name in names:
        unit = f"tunnelguard-{role}-{name}.service"
        found = subprocess.run(["systemctl", "show", "--property=LoadState", "--value", unit], capture_output=True, text=True, check=True)
        if found.stdout.strip() != "not-found":
            raise ValueError("A deployment service already exists; preserve it and use the documented removal procedure first")
    if prefix.exists():
        raise ValueError("Deployment exists; this installer never overwrites it")
    return prefix


def unit_text(prefix, name, guard=False):
    config = "config.json" if guard else f"{name}.json"
    command = f"/usr/bin/python3 {prefix}/app/tunnelguard.py run --config %d/config.json" if guard else f"{prefix}/sing-box run -c %d/config.json"
    families = "AF_INET AF_INET6 AF_UNIX" + ("" if guard else " AF_NETLINK")
    return f"""[Unit]
Description=TunnelGuard managed {name}
After=network-online.target
Wants=network-online.target
[Service]
DynamicUser=yes
LoadCredential=config.json:{prefix}/{config}
ExecStart={command}
Restart=on-failure
RestartSec=5
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictAddressFamilies={families}
UMask=0077
[Install]
WantedBy=multi-user.target
"""


def check_ports(folder, role):
    listeners = []
    for name in (["server"] if role == "server" else [k for k in ALL_KINDS if (folder/f'{k}.json').is_file()]):
        cfg = json.loads((folder/f"{name}.json").read_text())
        for inbound in cfg["inbounds"]:
            listeners.append((inbound["listen"], inbound["listen_port"], inbound["type"] in ("hysteria2", "tuic")))
    if role == "client":
        cfg = json.loads((folder/"config.json").read_text())
        listeners.extend(("127.0.0.1", cfg[p], False) for p in ("listen_port", "dashboard_port"))
    sockets = []
    try:
        for host, port, udp in listeners:
            s = socket.socket(socket.AF_INET6 if ":" in host else socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
            sockets.append(s)
            s.bind((host, port))
    finally:
        for s in sockets:
            s.close()


def apply(folder, role, offline=None):
    prefix = preflight(role)
    check_ports(folder, role)
    binary = install_core(folder, offline)
    names = ["server"] if role == "server" else [k for k in ALL_KINDS if (folder/f'{k}.json').is_file()]
    for name in names:
        subprocess.run([str(binary), "check", "-c", str(folder/f"{name}.json")], check=True, capture_output=True)
    if not prefix.parent.exists():
        prefix.parent.mkdir(mode=0o755)
        prefix.parent.chmod(0o755)
    prefix.mkdir(mode=0o755)
    prefix.chmod(0o755)
    units, started = [], []
    try:
        shutil.copy2(binary, prefix/"sing-box")
        for name in names:
            shutil.copy2(folder/f"{name}.json", prefix/f"{name}.json")
        if role == "client":
            shutil.copy2(folder/"config.json", prefix/"config.json")
            (prefix/"app").mkdir(mode=0o755)
            for name in ("tunnelguard.py", "engines.py", "dashboard.html", "account.html"):
                shutil.copy2(ROOT/name, prefix/"app"/name)
                (prefix/"app"/name).chmod(0o644)
            names.append("guard")
        for name in names:
            unit = Path("/etc/systemd/system")/f"tunnelguard-{role}-{name}.service"
            write_private(unit, unit_text(prefix, name, name == "guard"))
            units.append(unit)
            unit.chmod(0o644)
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        for unit in units:
            started.append(unit.name)
            subprocess.run(["systemctl", "enable", "--now", unit.name], check=True)
        # Let immediate bind/config failures become visible.
        import time
        time.sleep(2)
        for unit in units:
            subprocess.run(["systemctl", "is-active", "--quiet", unit.name], check=True)
    except Exception:
        for name in started:
            subprocess.run(["systemctl", "disable", "--now", name], capture_output=True)
        for unit in units:
            unit.unlink(missing_ok=True)
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
        # prefix is a fixed, newly created directory owned by this attempt.
        shutil.rmtree(prefix)
        raise


def main():
    if len(sys.argv) > 1 and sys.argv[1] in ("spoof-server", "spoof-client"):
        from deploy_spoof import main as spoof_main
        return spoof_main()
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("role", choices=["server", "client"])
    p.add_argument("--output", type=Path, required=True, help="New private directory; never overwritten")
    p.add_argument("--address", help="Server public IPv4/IPv6 (server role)")
    p.add_argument("--ports", type=int, nargs=3, default=[18443, 18444, 18445], metavar=("SS", "TLS", "QUIC"))
    p.add_argument('--extra-ports', type=int, nargs=4, metavar=('VMESS_WS_TLS','VLESS_TLS','TUIC','ANYTLS'), help='Also install VMess/WS/TLS, VLESS/TLS, TUIC and AnyTLS')
    p.add_argument("--bundle", type=Path, help="Private pairing.json from server")
    p.add_argument("--local-base", type=int, default=11001)
    p.add_argument("--apply", action="store_true", help="Download verified core and install/start systemd services")
    p.add_argument("--core-archive", type=Path, help="Offline official tar.gz; same pinned hash is required")
    a = p.parse_args()
    if sys.version_info < (3, 11):
        p.error("Python 3.11+ required")
    if a.output.exists():
        p.error("Output already exists; choose a new private directory")
    try:
        if a.apply:
            preflight(a.role)
        if a.role == "server":
            if not a.address:
                p.error("server requires --address")
            generate_server(a.output, a.address, a.ports, a.extra_ports)
        else:
            if not a.bundle:
                p.error("client requires --bundle")
            generate_client(a.output, a.bundle, a.local_base)
        if a.apply:
            apply(a.output.resolve(), a.role, a.core_archive)
        print("Ready / آماده:", a.output.resolve())
        if a.role == "server":
            print("Private pairing.json contains passwords. Transfer only over a trusted channel.")
            print(f"Firewall required: TCP {a.ports[0]}, TCP {a.ports[1]}, UDP {a.ports[2]}. Firewall unchanged.")
            if a.extra_ports:
                print('Additional ports: VMess TCP, VLESS TCP, TUIC UDP, AnyTLS TCP:', *a.extra_ports)
        else:
            print("Gateway: 127.0.0.1:1088 | Dashboard: http://127.0.0.1:8787 (after --apply)")
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError, tarfile.TarError) as e:
        # Do not echo external core diagnostics, bundle contents or secrets.
        print(f"Deployment failed ({type(e).__name__}). No existing installation is overwritten. See DEPLOY.md / DEPLOY.fa.md.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
