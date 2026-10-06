# Userspace WireGuard

[فارسی](WIREGUARD.fa.md)

Uses the WireGuard endpoint in pinned sing-box 1.14.2. No kernel interface, default route, global IP forwarding or NAT changes. A local SOCKS endpoint integrates with the guard; application gateway/forwarding remains TCP-only. This is not a system-wide VPN or general UDP port forwarder.

On exit:

```bash
sudo python3 deploy_wireguard.py server --address YOUR_EXIT_IP \
  --output /root/tg-wg-server --apply
```

Allow UDP/18450 in host/provider firewall; override using `--port`. Pairing includes the private **client** key, never the server private key. Transfer only through trusted SSH. On Iran after base installation:

```bash
sudo python3 deploy_wireguard.py client --bundle /root/wg-pairing.json \
  --output /root/tg-wg-client --apply
```

Adds route `wireguard` on local SOCKS 11010 to All/WireGuard profiles. Override it with `server --socks-port` when generating the pair. Internal addresses 10.77.0.1/30 and 10.77.0.2/30 exist only in userspace. A SOCKS bridge on exit loopback (11011, configurable with --bridge-port) runs inside WireGuard; destinations are resolved at exit. WireGuard packets target the internal address, supporting loopback application destinations without invalid loopback IP packets.

Offline installs accept `--core-archive` with the same mandatory pinned hash. Key generation requires openssl. Firewalls are unchanged; blocked UDP may make this path unusable.

```bash
sudo systemctl status tunnelguard-wireguard-client-core
sudo python3 maintenance.py upgrade --target wireguard-client --cores
sudo python3 maintenance.py uninstall --target wireguard-client
```

Exit target: `wireguard-server`. Remove the attached client before removing the base guard. Snapshots contain private keys. WireGuard has no expiring TLS certificate; automatic base paired key rotation does not apply to this target.

Reference: [sing-box WireGuard endpoint](https://sing-box.sagernet.org/configuration/endpoint/wireguard/).

## Reverse initiation

Generate the exit side with `--direction reverse --client-address YOUR_IRAN_IP` to have exit initiate the WireGuard handshake to Iran UDP/18451 (override with `--client-port`). Allow this UDP port on Iran. This is a direction option for the same WireGuard route, not another independent healthy path.

For an existing installation, use these server options plus `--replace` and a fresh output directory, transfer the new pairing, then run client with another fresh output and `--replace --apply`. Both sides create snapshots. Keys change; the route is unavailable until both sides are paired again. Keep the existing SOCKS port. Reverse initiation still cannot guarantee UDP reachability.
