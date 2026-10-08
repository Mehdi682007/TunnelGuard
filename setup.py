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


def role(prompt=input):
    choice=prompt('1) Iran / ایران   2) Outside / خارج: ').strip()
    if choice not in ('1','2'): raise ValueError('Choose 1 or 2 / گزینه ۱ یا ۲')
    return 'controller' if choice=='1' else 'agent'


def credentials():
    username=input('New username / نام کاربری جدید: ').strip()
    password=getpass.getpass('New password (12+ chars) / رمز جدید: ')
    if password!=getpass.getpass('Repeat / تکرار: '): raise ValueError('Passwords do not match')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}',username) or not 12<=len(password)<=256:
        raise ValueError('Invalid username or password length')
    cfg=manage.load_config(manage.CONFIG)
    auth='Basic '+base64.b64encode((username+':'+password).encode()).decode()
    cfg['dashboard_auth_sha256']=hashlib.sha256(auth.encode()).hexdigest()
    manage.save_managed(cfg)
    print('Credentials changed; previous sessions expire / اطلاعات ورود تغییر کرد')


def main():
    if sys.platform!='linux' or os.geteuid()!=0:
        print('Run with sudo on a Linux server / روی سرور لینوکس با sudo اجرا کنید');return 1
    while True:
        print('\nTunnelGuard\n1) Install / نصب\n2) Upgrade from this checkout / ارتقا\n3) Change panel login (Iran) / تغییر ورود پنل ایران\n4) Service status / وضعیت\n5) Install prerequisites (apt) / نصب پیش‌نیازها\n0) Exit / خروج')
        try:
            choice=input('> ').strip()
            if choice=='0': return 0
            if choice=='1':
                selected=role()
                if selected=='controller':
                    iran=input('Iran IPv4 / آی‌پی ایران: ').strip()
                    outside=input('Outside IPv4 / آی‌پی خارج: ').strip()
                    output=Path(input('New pairing file [/root/tg-agent-pairing.json]: ').strip() or '/root/tg-agent-pairing.json')
                    install_manager.install('controller',iran=iran,exit=outside,output=output)
                    print('Transfer pairing file privately to outside / فایل جفت‌سازی را خصوصی به خارج منتقل کنید:',output)
                    print('Panel login / اطلاعات اولیه ورود: /opt/tunnelguard-manager/panel/login.txt')
                else:
                    bundle=Path(input('Pairing file from Iran / مسیر فایل جفت‌سازی ایران: ').strip())
                    install_manager.install('agent',bundle=bundle)
            elif choice=='2': install_manager.upgrade(role())
            elif choice=='3': credentials()
            elif choice=='4': subprocess.run(['systemctl','--no-pager','status','tunnelguard-client-guard','tunnelguard-manager-controller','tunnelguard-manager-agent'])
            elif choice=='5':
                subprocess.run(['apt-get','update'],check=True)
                subprocess.run(['apt-get','install','-y','python3','curl','openssl','openssh-client','openssh-server','iproute2','iptables'],check=True)
            else: print('Unknown option / گزینه نامعتبر')
        except (ValueError,OSError,subprocess.SubprocessError) as error:
            print('Operation failed / عملیات ناموفق:',type(error).__name__,str(error))
        except (EOFError,KeyboardInterrupt):return 0

if __name__=='__main__': raise SystemExit(main())
