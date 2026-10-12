"""Remove the local managed TunnelGuard installation; preview before applying."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

MANAGER=Path('/opt/tunnelguard-manager')
UNITS=Path('/etc/systemd/system')
SSH=Path('/etc/ssh/sshd_config.d')
PAIRING=Path('/root/tg-agent-pairing.json')
LAUNCHER=Path('/usr/local/bin/tunnelguard')
TREES=tuple(map(Path,('/opt/tunnelguard-manager','/opt/tunnelguard-node','/opt/tunnelguard-spoof',
 '/opt/tunnelguard-wireguard','/opt/tunnelguard-reverse','/opt/tunnelguard',
 '/var/lib/tunnelguard-maintenance','/var/lib/tunnelguard-panel','/var/lib/private/tunnelguard-panel',
 '/run/tunnelguard-manager')))


def run(*args, optional=False):
    r=subprocess.run(list(map(str,args)),capture_output=True,text=True,timeout=120)
    if r.returncode and not optional:
        raise RuntimeError('Command failed: '+ ' '.join(map(str,args))+'; '+r.stderr.strip()[:300])
    return r


def remove_path(path):
    # Never traverse a redirected parent or follow a directory symlink.
    if path.parent.resolve()!=path.parent:
        raise ValueError('Refusing redirected parent: '+str(path))
    if path.is_symlink() or path.is_file():path.unlink()
    elif path.is_dir():shutil.rmtree(path)


def inventory():
    from tunnel_methods import validate_plan
    plans=[]
    for file in sorted((MANAGER/'tunnels').glob('*/plan.json')):
        if file.is_symlink() or file.parent.resolve()!=file.parent:
            raise ValueError('Redirected manifest: '+str(file))
        p=validate_plan(json.loads(file.read_text()))
        expected='tg'+hashlib.sha256(p['name'].encode()).hexdigest()[:10]
        if p['interface']!=expected or file.parent.name!=p['name']:
            raise ValueError('Unexpected link identity: '+str(file))
        role=(file.parent/'role').read_text().strip()
        if role not in ('iran','exit'):raise ValueError('Invalid installed role')
        plans.append((p,role))
    units=[]
    for file in sorted(UNITS.glob('tunnelguard*')):
        if file.suffix not in ('.service','.timer') or not re.fullmatch(r'tunnelguard(?:-[a-z0-9-]+)?\.(?:service|timer)',file.name):continue
        if file.is_symlink() or 'TunnelGuard' not in file.read_text():
            raise ValueError('Unrecognized unit; inspect before removal: '+str(file))
        units.append(file)
    configs=[]
    for file in SSH.glob('*.conf'):
        match=re.fullmatch(r'80-(tg[0-9a-f]{10})\.conf',file.name)
        account=match[1] if match else 'tunnelguard-relay' if file.name=='90-tunnelguard-relay.conf' else None
        if account:
            if file.is_symlink() or 'Match User '+account not in file.read_text():
                raise ValueError('Unrecognized SSH configuration: '+str(file))
            configs.append((file,account))
    return plans,units,configs


def preview():
    plans,units,configs=inventory()
    print('LOCAL uninstall: active tunnels, forwards and panel on this server will stop.')
    for file in units:print('  Service:',file.name)
    for p,role in plans:print('  Link:',p['name'],p['method'],role)
    for file,account in configs:print('  Restricted SSH account:',account)
    for path in TREES:
        if path.exists() or path.is_symlink():print('  Delete:',path)
    print('Managed keys, credentials, session files, caches and rollback snapshots are deleted.')
    print('Shared OS packages, OS journal/history and separately copied files/checkouts are retained.')
    print('Run uninstall separately on BOTH servers. No remote server is deleted automatically.')
    return plans,units,configs


def apply():
    import pwd
    from tunnel_runtime import cleanup
    plans,units,configs=inventory()
    # Preflight account ownership before stopping anything.
    for file,account in configs:
        try:entry=pwd.getpwnam(account)
        except KeyError:continue
        if entry.pw_dir!='/var/lib/'+account or entry.pw_uid==0:
            raise ValueError('Account ownership mismatch: '+account)
    # Stop coordinators/timers first so they cannot recreate a removed link.
    ordered=sorted(units,key=lambda p:(not(p.suffix=='.timer' or 'manager-' in p.name),p.name))
    for file in ordered:run('systemctl','disable','--now',file.name)
    for p,role in plans:
        cleanup(p,role)
        if p['method'] in ('ipip','gre','vxlan'):
            if run('ip','link','show',p['interface'],optional=True).returncode==0:
                raise RuntimeError('Interface still exists: '+p['interface'])
    # Verify all tagged rules are gone; retain manifests if cleanup failed.
    rules=run('iptables-save',optional=True)
    if rules.returncode==0 and any(re.search(r'--comment [\"\']?tunnelguard-', line) for line in rules.stdout.splitlines()):
        raise RuntimeError('TunnelGuard firewall rules remain; installation files preserved for recovery')
    for file,account in configs:
        original=file.read_bytes();file.unlink()
        try:run('/usr/sbin/sshd','-t')
        except Exception:
            file.write_bytes(original);file.chmod(0o644);raise
        run('systemctl','reload','ssh')
        try:pwd.getpwnam(account)
        except KeyError:pass
        else:run('userdel',account)
        remove_path(Path('/var/lib')/account)
        # userdel may already remove the matching private group.
        run('groupdel',account,optional=True)
    for file in units:
        remove_path(file)
        remove_path(UNITS/(file.name+'.d'))
    for path in TREES:remove_path(path)
    pairing=PAIRING
    if pairing.is_file() and not pairing.is_symlink():
        try:data=json.loads(pairing.read_text())
        except (ValueError,OSError):data={}
        if data.get('schema')==1 and 'peer_token' in data and 'certificate' in data:pairing.unlink()
    launcher=LAUNCHER
    if launcher.is_file() and not launcher.is_symlink():
        if '/opt/tunnelguard/tunnelguard.py' in launcher.read_text():launcher.unlink()
    run('groupdel','tunnelguard-control',optional=True)
    run('systemctl','daemon-reload')
    for file in units:run('systemctl','reset-failed',file.name,optional=True)
    print('Local managed installation removed. Shared packages and OS logs were not modified.')


def interactive():
    preview()
    if input('Type UNINSTALL to permanently remove this local installation: ').strip()!='UNINSTALL':
        print('Cancelled.');return False
    apply();return True


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply',action='store_true',help='Show preview and require typed confirmation')
    args=parser.parse_args()
    if sys.platform!='linux' or os.geteuid()!=0:raise SystemExit('Run as root on Linux')
    if args.apply:interactive()
    else:preview()

if __name__=='__main__':main()
