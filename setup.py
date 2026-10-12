"""Interactive TunnelGuard installer and maintenance menu (Linux/systemd)."""
import argparse
import getpass
import base64
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys

import install_manager
import manage
from branding import banner, display
from tunnelguard import VERSION


def role(prompt=input):
    choice=prompt('1) 🇮🇷 Iran   2) 🌍 Outside: ').strip()
    if choice not in ('1','2'): raise ValueError('Choose 1 or 2')
    return 'controller' if choice=='1' else 'agent'


def credentials():
    username=input('New username: ').strip()
    password=getpass.getpass('New password (12+ chars): ')
    if password!=getpass.getpass('Repeat: '): raise ValueError('Passwords do not match')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}',username) or not 12<=len(password)<=256:
        raise ValueError('Invalid username or password length')
    cfg=manage.load_config(manage.CONFIG)
    auth='Basic '+base64.b64encode((username+':'+password).encode()).decode()
    cfg['dashboard_auth_sha256']=hashlib.sha256(auth.encode()).hexdigest()
    manage.save_managed(cfg)
    print('Credentials changed; previous sessions expire')


def main():
    if sys.platform!='linux' or os.geteuid()!=0:
        print('Run with sudo on a Linux server');return 1
    while True:
        display(banner())
        display('1) 📦 Install\n2) 🔄 Upgrade from this checkout\n3) 🔐 Change panel login (Iran)\n4) 📊 Service status\n5) 🧰 Install prerequisites (apt)\n6) 🗑 Uninstall this server\n0) 🚪 Exit')
        try:
            choice=input('> ').strip()
            if choice=='0': return 0
            if choice=='1':
                selected=role()
                if selected=='controller':
                    iran=input('Iran IPv4: ').strip()
                    outside=input('Outside IPv4: ').strip()
                    output=Path(input('New pairing file [/root/tg-agent-pairing.json]: ').strip() or '/root/tg-agent-pairing.json')
                    install_manager.install('controller',iran=iran,exit=outside,output=output)
                    print('Transfer pairing file privately to outside',output)
                    print('Panel login: /opt/tunnelguard-manager/panel/login.txt')
                else:
                    bundle=Path(input('Pairing file from Iran: ').strip())
                    install_manager.install('agent',bundle=bundle)
            elif choice=='2': install_manager.upgrade(role())
            elif choice=='3': credentials()
            elif choice=='4': subprocess.run(['systemctl','--no-pager','status','tunnelguard-client-guard','tunnelguard-manager-controller','tunnelguard-manager-agent'])
            elif choice=='5':
                subprocess.run(['apt-get','update'],check=True)
                subprocess.run(['apt-get','install','-y','python3','curl','openssl','openssh-client','openssh-server','iproute2','iptables'],check=True)
            elif choice=='6':
                import uninstall
                if uninstall.interactive():return 0
            else: print('Unknown option')
        except (ValueError,OSError,RuntimeError,subprocess.SubprocessError) as error:
            print('Operation failed',type(error).__name__,str(error))
        except (EOFError,KeyboardInterrupt):return 0

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version',action='version',version=VERSION)
    parser.add_argument('--banner',action='store_true',help='Show the full supplied block-art banner')
    args=parser.parse_args()
    if args.banner: display(banner(full=True))
    else: raise SystemExit(main())
