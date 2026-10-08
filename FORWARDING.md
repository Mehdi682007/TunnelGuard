# TCP service forwarding and HTTPS dashboard

[فارسی](FORWARDING.fa.md)

The installers deploy tunnel cores; the guard selects healthy routes. SOCKS on 1088 serves proxy-aware applications. To publish an Xray **user inbound**, not the x-ui management panel, run on Iran from the project checkout:

```bash
sudo python3 manage.py forward-add --name xui-4748 \
  --listen 0.0.0.0 --port 4748 --public \
  --target-host 127.0.0.1 --target-port 4748
```

This previews the configuration. Repeat with `--apply` to snapshot, validate, save and restart the guard; restart failure restores the snapshot. Use `--replace` to update an existing forward. Use unprivileged listen ports (1024+).

Here `127.0.0.1` means loopback **at the exit proxy**, not at Iran. Traffic travels `user → Iran:4748 → healthy proxy route → exit:127.0.0.1:4748 → Xray`. Set the client connection address to Iran's IP and port 4748, retaining the UUID, transport, SNI, Reality keys and other values required by the real Xray inbound. TCP/TLS bytes pass through unchanged. Application UDP is not supported; established connections cannot migrate.

Repeat `--route NAME` to restrict destinations to selected routes. Default: all routes configured at command time. After adding routes, repeat with `--replace` if they should carry this service. Each exit must actually reach the same service; do not assume separate exit hosts have the same loopback service. An unavailable destination never triggers direct Internet fallback.

Host/provider firewalls must allow the chosen inbound port; the tool never resets or enables a firewall. Without explicit `--listen 0.0.0.0 --public`, forwards remain loopback-only. SOCKS and dashboard are not made public automatically.

```bash
sudo python3 manage.py list
sudo python3 manage.py forward-remove --name xui-4748 --apply
```

New JSON forwarding targets use `via: "proxy"`. Legacy targets without `via` retain their old behavior: connecting directly to the local endpoint of an independently configured tunnel.

## Public dashboard

Default: `http://127.0.0.1:8787`. To publish with mandatory TLS and random Basic authentication:

```bash
sudo python3 publish_panel.py --address YOUR_IRAN_IP \
  --port 8787 --output /root/tg-panel --apply
sudo cat /root/tg-panel/login.txt
```

Visit `https://YOUR_IRAN_IP:8787`; username is `admin`, password is in the private file. Never publish that file. The self-signed certificate lasts 365 days: verify its printed SHA256 fingerprint before trusting it in the browser. To renew/change the password, rerun with a new output directory. Plain HTTP no longer works. Restore the printed maintenance snapshot to revert. Allow the port in your provider firewall if necessary.

TunnelGuard does not install x-ui or create the destination service on 4748. Create the Xray inbound on the outside server first and verify it with `ss -ltnp | grep 4748`. In Tunnel Manager, apply a public listener on `0.0.0.0:4748` with target `127.0.0.1:4748`; the panel updates an existing forward with the same name. Applying returns pending; the manager exposes applied or failed after the background restart. Applied means configuration saved, not an end-to-end Xray test. Select all desired tunnel routes for failover; selecting a preferred route only affects forwards that include it.
