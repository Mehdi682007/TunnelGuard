"""Configure managed routes and TCP service forwarding; preview by default."""
import argparse
import json
from pathlib import Path
import tempfile
import subprocess

from tunnelguard import load_config

CONFIG = Path('/opt/tunnelguard-node/client/config.json')


def checked(cfg):
    with tempfile.TemporaryDirectory() as temp:
        path = Path(temp)/'config.json'
        path.write_text(json.dumps(cfg), encoding='utf-8')
        return load_config(path)


def add_forward(cfg, name, listen_host, listen_port, host, port, routes, public=False, replace=False):
    names = {r['name'] for r in cfg['routes']}
    selected = set(routes or names)
    if not selected or not selected <= names:
        raise ValueError('Unknown route')
    forwards = cfg.setdefault('tcp_forwards', [])
    if any(f['name'] == name for f in forwards) and not replace:
        raise ValueError('Forward exists; use --replace after reviewing it')
    cfg['tcp_forwards'] = [f for f in forwards if f['name'] != name]
    cfg['tcp_forwards'].append(dict(name=name, listen_host=listen_host, listen_port=listen_port,
        allow_public=public, targets={r: dict(host=host, port=port, via='proxy') for r in sorted(selected)}))
    return checked(cfg)


def attach(cfg, routes, profile):
    existing = {r['name'] for r in cfg['routes']}
    if existing & {r['name'] for r in routes}:
        raise ValueError('Route already exists')
    cfg['routes'].extend(routes)
    names = [r['name'] for r in routes]
    cfg['profiles'].setdefault('All', []).extend(names)
    cfg['profiles'][profile] = names
    return checked(cfg)


def save_managed(cfg):
    import maintenance
    with maintenance.locked():
        return maintenance.transaction('client', {'config.json': json.dumps(checked(cfg), indent=2).encode()})


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=['forward-add', 'forward-remove', 'route-add', 'list'])
    p.add_argument('--config', type=Path, default=CONFIG)
    p.add_argument('--name')
    p.add_argument('--listen', default='127.0.0.1')
    p.add_argument('--port', type=int)
    p.add_argument('--target-host', default='127.0.0.1', help='Resolved/reached by the exit proxy, not the Iran host')
    p.add_argument('--target-port', type=int)
    p.add_argument('--route', action='append', help='Repeat for each route; default all installed routes')
    p.add_argument('--public', action='store_true', help='Explicitly allow a non-loopback TCP listener')
    p.add_argument('--replace', action='store_true')
    p.add_argument('--proxy', help='SOCKS5/HTTP CONNECT endpoint for an already installed transport')
    p.add_argument('--layer', default='External')
    p.add_argument('--apply', action='store_true', help='Snapshot, update managed config, restart guard; rollback on failure')
    a = p.parse_args()
    try:
        cfg = load_config(a.config)
        if a.command == 'list':
            print(json.dumps(dict(routes=[r['name'] for r in cfg['routes']], forwards=cfg['tcp_forwards']), indent=2))
            return 0
        if not a.name:
            p.error('--name required')
        if a.command == 'forward-add':
            if not a.port or not a.target_port:
                p.error('--port and --target-port required; TCP only')
            cfg = add_forward(cfg, a.name, a.listen, a.port, a.target_host, a.target_port, a.route, a.public, a.replace)
        elif a.command == 'forward-remove':
            if not any(f['name'] == a.name for f in cfg['tcp_forwards']):
                raise ValueError('Forward does not exist')
            cfg['tcp_forwards'] = [f for f in cfg['tcp_forwards'] if f['name'] != a.name]
        else:
            if not a.proxy:
                p.error('--proxy required')
            cfg = attach(cfg, [dict(name=a.name, proxy=a.proxy, priority=50, layer=a.layer)], a.name)
        checked(cfg)
        if a.apply:
            if a.config.resolve() != CONFIG:
                raise ValueError('--apply supports the managed client config only')
            identity = save_managed(cfg)
            print('Applied / اعمال شد. Rollback snapshot:', identity)
        else:
            print('Valid preview / پیش‌نمایش معتبر. Add --apply to save and restart the guard.')
            print(json.dumps(dict(routes=[r['name'] for r in cfg['routes']], forwards=cfg['tcp_forwards']), indent=2))
        return 0
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as exc:
        print('Configuration rejected / تنظیمات رد شد:', type(exc).__name__)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
