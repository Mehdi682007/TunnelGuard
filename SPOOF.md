# Automatic Spoof deployment (experimental)

[فارسی](SPOOF.fa.md) · [Base deployment](DEPLOY.md)

TunnelGuard 2.2 installs **Parsa spoof-tunnel v3.1.0-beta.0** and **sing-box 1.14.2**,
generates both sides and creates the services. The raw carrier transports a
TLS-authenticated Hysteria2 connection, which exposes a loopback SOCKS5 endpoint.
There is no separate manual core installation. Both downloads have pinned SHA256
hashes; offline files undergo identical verification.

```
Application → TunnelGuard → SOCKS5 :11004 → Hysteria2/TLS
            → local UDP bridge → raw Spoof carrier → peer carrier
            → loopback Hysteria2/TLS server → destination
```

This integrates the upstream beta, not a newly invented Spoof protocol. The source
was checked at commit `ba29f0c8e22da5a905a74a8137e01a22f0443e60`.
[Upstream source/license](https://github.com/ParsaKSH/spoof-tunnel/tree/v3.1.0-beta.0)
and [QUIC packet sizing](https://sing-box.sagernet.org/configuration/shared/quic/).

## Requirements

- Ubuntu 24.04 amd64/arm64, Python 3.11+, systemd, openssl, curl, iproute2.
- Known real IPv4 addresses for the two endpoints; one explicitly supplied,
  authorized source IPv4 address per direction. The installer does not discover
  working source IPs or scan third-party networks.
- Both provider networks must permit the required source addressing. A local raw
  socket/route check cannot prove that an upstream provider forwards those packets.
- TCP and UDP carriers are selectable per direction. ICMP/ICMPv6 and XDP are not
  exposed by this installer because their host/network requirements differ.

The TLS overlay is always enabled and verified. Only its public certificate and
credentials go in the private pairing file. The 365-day certificate requires
coordinated re-pairing before expiration, as in the base deployment.

## Exit server

Update your checkout (`git pull --ff-only`) or clone the repository, then install
prerequisites on **both** nodes:

```bash
sudo apt update
sudo apt install -y python3 curl openssl ca-certificates iproute2
```

Replace all four documentation-only addresses with your actual deployment values:

```bash
sudo python3 deploy.py spoof-server \
  --address 203.0.113.10 --client-address 198.51.100.20 \
  --server-source 192.0.2.10 --client-source 192.0.2.20 \
  --uplink tcp --downlink udp \
  --output /root/deployment-spoof-server --apply
```

`--uplink` means client → server; `--downlink` means server → client. Both can be
`tcp` or `udp`. Defaults: external server receive **19443**, client receive **19444**,
private server overlay **19445/UDP**, client bridge **19446/UDP**, client SOCKS **11004/TCP**.
You can set `--server-port`, `--client-port`, `--overlay-port`, `--bridge-port`,
`--socks-port` on the server command; they are carried in the pairing file.

## Client node

Transfer `/root/deployment-spoof-server/pairing.json` securely using SSH/SCP. Keep it
private and retain SSH host-key verification. Then, in the client checkout:

```bash
sudo python3 deploy.py spoof-client --bundle /root/pairing-spoof.json \
  --output /root/deployment-spoof-client --apply
```

If the 2.1 automatic deployment exists at `/opt/tunnelguard-node/client/config.json`,
the installer adds a **Spoof** route to it and the **All/Emergency** profiles, preserves
other routes/profiles, backs up the original file and restarts its guard service.
That restart interrupts existing gateway connections. Existing Spoof names/endpoints
cause an error instead of overwriting. A non-All active profile remains selected;
choose **All** or **Emergency** to allow this route.

If no base deployment exists, it installs a standalone guard with only the Spoof route.
Gateway/dashboard ports remain 1088/8787 on loopback. A custom independently installed
guard is not auto-modified; stop it before standalone installation or add the generated
SOCKS route to your own config and run only the two core services.

## Firewall and network diagnostics

For default TCP upload / UDP download, allow inbound **TCP 19443** on the exit server
from the configured client source, and **UDP 19444** on the client from the configured
server source, in both host and provider firewalls. Change protocols when changing
the two transport options. Do not expose private overlay/bridge/SOCKS/dashboard ports.

The raw TCP carrier is not a normal TCP connection; a stateful firewall may need an
explicit rule for the selected source/protocol/port. Source filtering, NAT, reverse-path
filtering and provider anti-spoofing can prevent delivery. The installer checks local
raw-socket permission and the route to the peer; it does not disable firewall rules,
rp_filter, or host ICMP handling and cannot bypass provider restrictions.

```bash
sudo systemctl status 'tunnelguard-spoof-*'
sudo journalctl -u tunnelguard-spoof-client-carrier -n 50 --no-pager
curl --noproxy '' --proxy socks5h://127.0.0.1:11004 https://example.com
```

The raw core insists on UID 0. Its service therefore uses root with only
**CAP_NET_RAW** in its capability bounding set; it has no CAP_NET_ADMIN and cannot
change firewall/kernel tunables. The TLS core and guard use DynamicUser. Upstream
carrier packet counts alone do not prove successful TLS or Internet connectivity.

## Offline installation

Download the matching architecture from the official pinned releases elsewhere and
add both options to either install command:

```bash
--core-archive /root/sing-box-1.14.2-linux-amd64.tar.gz \
--spoof-binary /root/spoof-linux-amd64
```

Sources: [sing-box](https://github.com/SagerNet/sing-box/releases/tag/v1.14.2),
[Parsa](https://github.com/ParsaKSH/spoof-tunnel/releases/tag/v3.1.0-beta.0).
No panel, third-party install script, IP pool, scanner or global network change is installed.

## Removal / reinstall

Back up your private settings first. On each side replace `ROLE` below with
`server` or `client`:

```bash
sudo systemctl disable --now tunnelguard-spoof-ROLE-overlay tunnelguard-spoof-ROLE-carrier
```

For a standalone client also stop `tunnelguard-spoof-client-guard`. For an attached
client, first remove Spoof from its config's routes/profiles and restart
`tunnelguard-client-guard`. The exact pre-install backup is
`/opt/tunnelguard-spoof/client/guard-backup.json`; restore it only if no later config
changes need preserving. This restarts the gateway and interrupts sessions.

Remove the corresponding exact `.service` files under `/etc/systemd/system/`, run
`sudo systemctl daemon-reload`, and remove `/opt/tunnelguard-spoof/ROLE` after backing
it up. Keep or securely remove generated output and pairing files as appropriate.
Existing deployments/output directories are refused, not upgraded in place.

One carrier/overlay instance supports one paired client node. Multiple applications
share the encrypted overlay; multiple independent client nodes need separate deployments.
No Iranian ISP connectivity, ARM runtime, censorship resistance or production load
guarantee is implied. See [TESTING.md](TESTING.md) for the actual tested scope.
