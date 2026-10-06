"""Paired reverse SSH SOCKS installer. Ubuntu 24.04; no password storage."""
import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

import deploy

ACCOUNT = 'tunnelguard-relay'
PREFIX = Path('/opt/tunnelguard-reverse')
CONF = Path('/etc/ssh/sshd_config.d/90-tunnelguard-relay.conf')
UNIT = Path('/etc/systemd/system/tunnelguard-reverse-ssh.service')
HOME = Path('/var/lib/tunnelguard-relay')


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, timeout=45)


def validate(b, accepted=False):
    if b.get('schema') != 1 or b.get('kind') != 'reverse-ssh':
        raise ValueError('Wrong bundle type')
    for key in ('receiver', 'sender'):
        ipaddress.IPv4Address(b[key])
    for key in ('ssh_port', 'socks_port'):
        if type(b[key]) is not int or not (1 if key=='ssh_port' else 1024) <= b[key] <= 65535:
            raise ValueError('Invalid port')
    if b['socks_port'] in (1088, 8787, b['ssh_port']):
        raise ValueError('Listener collision')
    keys = ['public_key'] + (['host_key'] if accepted else [])
    for key in keys:
        parts = b[key].split()
        if len(parts) != 2 or parts[0] != 'ssh-ed25519':
            raise ValueError('Expected ed25519 public key without options')
        blob = base64.b64decode(parts[1], validate=True)
        if len(blob) != 51 or blob[:19] != b'\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20':
            raise ValueError('Invalid ed25519 public key')
    return b


def read_bundle(path, accepted=False):
    if path.stat().st_size > 8192:
        raise ValueError('Oversize bundle')
    return validate(json.loads(path.read_text()), accepted)


def receiver_config(port):
    return f'''Match User {ACCOUNT}
    AuthenticationMethods publickey
    PasswordAuthentication no
    KbdInteractiveAuthentication no
    AllowTcpForwarding remote
    AllowStreamLocalForwarding no
    PermitListen 127.0.0.1:{port}
    GatewayPorts no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTTY no
    PermitTunnel no
    ClientAliveInterval 10
    ClientAliveCountMax 3
    ForceCommand /usr/bin/false
Match all
'''


def sender_unit(b):
    validate(b, True)
    return f'''[Unit]
Description=TunnelGuard reverse SSH SOCKS path
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0
[Service]
DynamicUser=yes
LoadCredential=key:{PREFIX}/key
LoadCredential=known_hosts:{PREFIX}/known_hosts
ExecStart=/usr/bin/ssh -F /dev/null -NT -i %d/key -o UserKnownHostsFile=%d/known_hosts -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -o BatchMode=yes -o ExitOnForwardFailure=yes -o ConnectTimeout=10 -o ServerAliveInterval=10 -o ServerAliveCountMax=3 -p {b['ssh_port']} -R 127.0.0.1:{b['socks_port']} {ACCOUNT}@{b['receiver']}
Restart=always
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
UMask=0077
[Install]
WantedBy=multi-user.target
'''


def atomic(path, data, mode=0o600):
    import maintenance
    maintenance.atomic(path, data, mode)


def prepare(a):
    a.output.mkdir(mode=0o700, parents=True)
    key = a.output/'key'
    if a.key:
        shutil.copy2(a.key, key)
        key.chmod(0o600)
    else:
        run('ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key))
    public = ' '.join(run('ssh-keygen', '-y', '-f', str(key)).stdout.decode().split()[:2])
    b = validate(dict(schema=1, kind='reverse-ssh', receiver=a.receiver, sender=a.sender,
                      ssh_port=a.ssh_port, socks_port=a.socks_port, public_key=public))
    deploy.write_private(a.output/'offer.json', b)
    print('Transfer offer.json only to receiver. Keep key on sender.')


def accept(a, b):
    auth = HOME/'.ssh/authorized_keys'
    exists = subprocess.run(['id', ACCOUNT], capture_output=True).returncode == 0
    if exists and (not a.adopt_existing or not auth.is_file() or b['public_key'] not in auth.read_text()):
        raise ValueError('Existing account; only matching TunnelGuard deployment may be adopted')
    if (CONF.exists() or HOME.exists()) and not exists:
        raise ValueError('Conflicting receiver files')
    if exists and (not CONF.is_file() or f'Match User {ACCOUNT}' not in CONF.read_text()):
        raise ValueError('Account is not an existing managed relay')
    if not exists:
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', b['socks_port']))
    a.output.mkdir(mode=0o700, parents=True)
    originals = {p: p.read_bytes() if p.exists() else None for p in (CONF, auth)}
    for p, data in originals.items():
        if data is not None:
            deploy.write_private(a.output/(p.name+'.before'), data.decode())
    created = False
    try:
        if not exists:
            run('useradd', '--system', '--create-home', '--home-dir', str(HOME), '--shell', '/usr/sbin/nologin', ACCOUNT)
            created = True
        run('install', '-d', '-m', '700', '-o', ACCOUNT, '-g', ACCOUNT, str(auth.parent))
        atomic(auth, f'from="{b["sender"]}",restrict,port-forwarding,permitlisten="127.0.0.1:{b["socks_port"]}",command="/usr/bin/false" {b["public_key"]}\n')
        run('chown', f'{ACCOUNT}:{ACCOUNT}', str(auth))
        atomic(CONF, receiver_config(b['socks_port']), 0o644)
        run('/usr/sbin/sshd', '-t')
        run('systemctl', 'reload', 'ssh')
        b['host_key'] = ' '.join(Path('/etc/ssh/ssh_host_ed25519_key.pub').read_text().split()[:2])
        validate(b, True)
        deploy.write_private(a.output/'acceptance.json', b)
        if a.attach:
            import manage
            cfg = manage.load_config(manage.CONFIG)
            expected = f'socks5h://127.0.0.1:{b["socks_port"]}'
            match = [r for r in cfg['routes'] if r['name'] == 'reverse-ssh']
            if match:
                if not a.adopt_existing or match[0]['proxy'] != expected:
                    raise ValueError('Existing reverse route differs')
            else:
                import maintenance
                merged=manage.attach(cfg, [dict(name='reverse-ssh', proxy=expected, layer='SSH-Reverse-TCP', priority=40)], 'Reverse')
                maintenance.transaction('client', {'config.json':json.dumps(merged).encode()})
    except BaseException:
        for p, data in originals.items():
            if data is None:
                p.unlink(missing_ok=True)
            else:
                atomic(p, data, 0o644 if p == CONF else 0o600)
        run('/usr/sbin/sshd', '-t')
        run('systemctl', 'reload', 'ssh')
        if created:
            subprocess.run(['userdel', ACCOUNT], capture_output=True)
        raise
    fingerprint = base64.b64encode(hashlib.sha256(base64.b64decode(b['host_key'].split()[1])).digest()).decode().rstrip('=')
    print('Receiver ready. Verify through trusted channel: SHA256:'+fingerprint)
    print('Transfer acceptance.json back to sender. Existing sessions receive new heartbeat settings on reconnect.')


def connect(a, b):
    public = ' '.join(run('ssh-keygen', '-y', '-f', str(a.key)).stdout.decode().split()[:2])
    if public != b['public_key']:
        raise ValueError('Private key does not match accepted offer')
    existing = PREFIX.exists() or UNIT.exists()
    if existing and (not a.adopt_existing or not (PREFIX/'key').is_file() or not UNIT.is_file()
                     or ' '.join(run('ssh-keygen', '-y', '-f', str(PREFIX/'key')).stdout.decode().split()[:2]) != public):
        raise ValueError('Existing sender must have matching key and managed unit')
    if existing and 'TunnelGuard reverse SSH' not in UNIT.read_text():
        raise ValueError('Not a managed sender unit')
    a.output.mkdir(mode=0o700, parents=True)
    paths = [PREFIX/'key', PREFIX/'known_hosts', PREFIX/'manifest.json', UNIT]
    old = {p: p.read_bytes() if p.exists() else None for p in paths}
    for p, data in old.items():
        if data is not None:
            (a.output/(p.name+'.before')).write_bytes(data)
            (a.output/(p.name+'.before')).chmod(0o600)
    PREFIX.mkdir(mode=0o700, exist_ok=True)
    try:
        atomic(PREFIX/'key', a.key.read_bytes())
        host = b['receiver'] if b['ssh_port'] == 22 else f'[{b["receiver"]}]:{b["ssh_port"]}'
        atomic(PREFIX/'known_hosts', host+' '+b['host_key']+'\n')
        atomic(PREFIX/'manifest.json', json.dumps(b))
        atomic(UNIT, sender_unit(b), 0o644)
        run('systemd-analyze', 'verify', str(UNIT))
        run('systemctl', 'daemon-reload')
        run('systemctl', 'enable', UNIT.name)
        run('systemctl', 'restart', UNIT.name)
        time.sleep(3)
        run('systemctl', 'is-active', '--quiet', UNIT.name)
    except BaseException:
        subprocess.run(['systemctl','stop',UNIT.name],capture_output=True)
        for p, data in old.items():
            if data is None:
                p.unlink(missing_ok=True)
            else:
                atomic(p, data, 0o644 if p == UNIT else 0o600)
        if not existing:
            subprocess.run(['systemctl','disable',UNIT.name],capture_output=True)
        run('systemctl','daemon-reload')
        if existing:
            run('systemctl','start',UNIT.name)
        raise
    print('Sender service started. Verify end-to-end on receiver; active does not prove reachability.')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=['prepare','accept','connect'])
    p.add_argument('--output', type=Path, required=True, help='New private directory')
    p.add_argument('--receiver', help='Iran IPv4')
    p.add_argument('--sender', help='Exit IPv4')
    p.add_argument('--ssh-port', type=int, default=22)
    p.add_argument('--socks-port', type=int, default=11005)
    p.add_argument('--bundle', type=Path)
    p.add_argument('--key', type=Path)
    p.add_argument('--attach', action='store_true', help='Attach reverse route to existing managed guard on receiver')
    p.add_argument('--adopt-existing', action='store_true', help='Explicit migration of a matching field deployment; backup changed files')
    p.add_argument('--apply', action='store_true')
    a=p.parse_args()
    try:
        if a.output.exists():
            raise ValueError('Output exists')
        if a.command == 'prepare':
            if not a.receiver or not a.sender:
                p.error('--receiver and --sender required')
            prepare(a)
        else:
            if not a.bundle or (a.command == 'connect' and not a.key):
                p.error('--bundle required; connect also needs --key')
            b=read_bundle(a.bundle, a.command == 'connect')
            if not a.apply:
                print('Validated preview. Add --apply for service/account changes.')
                return 0
            if sys.platform != 'linux' or os.geteuid() != 0:
                raise ValueError('Linux root required')
            import maintenance
            with maintenance.locked():
                if a.command == 'connect':
                    connect(a,b)
                else:
                    accept(a,b)
        return 0
    except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError) as exc:
        print(str(exc) if isinstance(exc,ValueError) else type(exc).__name__,file=sys.stderr)
        print('Reverse deployment failed. Inspect ports, bundles, SSH and private backup output; credentials are not printed.',file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
