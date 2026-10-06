"""Publish the managed dashboard with mandatory HTTPS and a random admin password."""
import argparse
import base64
import hashlib
import ipaddress
from pathlib import Path
import secrets
import subprocess

import deploy
import manage


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--address',required=True,help='Public server IP, used in certificate SAN and Host validation')
    p.add_argument('--port',type=int,default=8787)
    p.add_argument('--output',type=Path,required=True,help='New private directory for credentials and certificate')
    p.add_argument('--apply',action='store_true')
    a=p.parse_args()
    try:
        address=ipaddress.ip_address(a.address)
        if not 1024<=a.port<=65535: raise ValueError('Invalid port')
        cfg=manage.load_config(manage.CONFIG)
        a.output.mkdir(mode=0o700,parents=True)
        cert,key=a.output/'certificate.pem',a.output/'key.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:3072','-nodes','-days','365','-subj','/CN=TunnelGuard','-addext',f'subjectAltName=IP:{address}','-keyout',str(key),'-out',str(cert)],check=True,capture_output=True)
        key.chmod(0o600)
        password=secrets.token_urlsafe(32)
        auth='Basic '+base64.b64encode(('admin:'+password).encode()).decode()
        url=f'https://[{address}]:{a.port}' if address.version==6 else f'https://{address}:{a.port}'
        deploy.write_private(a.output/'login.txt',f'URL: {url}\nUsername: admin\nPassword: {password}\n')
        cfg.update(dashboard_host='::' if address.version==6 else '0.0.0.0',dashboard_address=str(address),dashboard_port=a.port,
                   dashboard_auth_sha256=hashlib.sha256(auth.encode()).hexdigest(),dashboard_tls=dict(certificate=cert.read_text(),key=key.read_text()))
        manage.checked(cfg)
        if a.apply:
            print('Snapshot:',manage.save_managed(cfg))
            print('Published:',url)
        else:
            print('Generated only; no live changes. Use a new output directory with --apply to publish.')
        print('Credentials saved privately:',a.output/'login.txt')
        print('Self-signed certificate: verify certificate fingerprint before accepting in browser. Firewall unchanged.')
        print(subprocess.run(['openssl','x509','-in',str(cert),'-noout','-fingerprint','-sha256'],capture_output=True,text=True,check=True).stdout.strip())
        return 0
    except (ValueError,OSError,KeyError,subprocess.SubprocessError):
        print('Publication failed; inspect configuration, output directory and service state. Password is never printed.')
        return 1


if __name__=='__main__': raise SystemExit(main())
