# Automatic two-node deployment (2.1)

[فارسی](DEPLOY.fa.md) · [Project guide](README.md)

`deploy.py` installs a pinned **sing-box 1.14.2** core and configures both ends of
Shadowsocks 2022 (TCP), Trojan (TLS/TCP), and Hysteria2 (QUIC/UDP). It creates
random credentials, a private TLS certificate, local SOCKS endpoints, TunnelGuard
routes and systemd services. It supports **Ubuntu 24.04, amd64/arm64**, Python 3.11+.
Other Linux distributions have not been qualified. `--apply` requires root and systemd.

The server is the exit node, usually outside Iran. The client node, usually in Iran,
connects outward to it. All three protocols on one exit IP provide transport
diversity, **not protection against loss/blocking of that IP**. This is not a reverse
tunnel. [Spoof now has its own automatic paired installer](SPOOF.md); Backhaul and other adapters still require their own deployment.

## 1. Prepare both servers

Run on each host:

```bash
sudo apt update
sudo apt install -y git python3 curl openssl ca-certificates
git clone https://github.com/Mehdi682007/TunnelGuard.git
cd TunnelGuard
```

## 2. Install the exit server

Replace `203.0.113.10` with its actual public IP (IPv4 or IPv6):

```bash
sudo python3 deploy.py server --address 203.0.113.10 \
  --output /root/deployment-server --apply
```

This installs `/opt/tunnelguard-node/server` and starts
`tunnelguard-server-server.service`. Open **TCP 18443, TCP 18444, UDP 18445**
in your provider firewall and host firewall. If using an already configured UFW:

```bash
sudo ufw allow 18443/tcp
sudo ufw allow 18444/tcp
sudo ufw allow 18445/udp
```

The installer never enables/resets a firewall. Do not enable UFW without preserving
your SSH access. Custom ports: `--ports 19443 19444 19445` (three distinct ports above 1023).
The installed core cannot bind privileged ports because it runs with a restricted account.

## 3. Pair and install the client node

The server creates `/root/deployment-server/pairing.json`. It includes shared
passwords and the public certificate, **not the TLS private key**. Transfer this
file over SSH/SCP using an account that can read it. For example, from the client
when root SSH login on the exit server is already allowed:

```bash
sudo scp root@203.0.113.10:/root/deployment-server/pairing.json /root/pairing.json
sudo chmod 600 /root/pairing.json
sudo python3 deploy.py client --bundle /root/pairing.json \
  --output /root/deployment-client --apply
```

Keep SSH host-key checking enabled and verify the host fingerprint through a trusted
channel. For a non-root SSH account use your existing secure file-transfer procedure;
do not enable root login just for this tool. Never paste the pairing file into a
public issue, video, repository or chat.

The client installs three local cores on **127.0.0.1:11001–11003**, and TunnelGuard
on **127.0.0.1:1088** with dashboard **127.0.0.1:8787**. `--local-base 12001` moves
the three core ports. Stop an older TunnelGuard instance first if its gateway or
dashboard occupies those ports. Choose the All, TCP or QUIC profile on the dashboard.

From your personal computer, forward the dashboard and gateway:

```bash
ssh -N -L 8787:127.0.0.1:8787 -L 1088:127.0.0.1:1088 user@IRAN_SERVER
```

Then open http://127.0.0.1:8787 and configure your app to use SOCKS5 at
127.0.0.1:1088 with remote DNS. Test on the client node:

```bash
curl --noproxy "" --proxy socks5h://127.0.0.1:1088 https://example.com
sudo systemctl status 'tunnelguard-client-*'
sudo journalctl -u tunnelguard-client-hysteria2 -n 50 --no-pager
```

## Download verification and offline installation

Binaries are fetched directly from the official upstream release, verified against
architecture-specific SHA256 values pinned in `deploy.py`, then extracted without
archive path traversal or symlink extraction. No `curl | bash`, remote shell script,
or floating `latest` binary is executed. Source/license: [sing-box upstream](https://github.com/SagerNet/sing-box).

If GitHub is inaccessible on a node, download the matching official
[v1.14.2 release archive](https://github.com/SagerNet/sing-box/releases/tag/v1.14.2)
elsewhere, transfer it securely, and add this option to the server/client command:

```bash
--core-archive /root/sing-box-1.14.2-linux-amd64.tar.gz
```

Use `arm64` for ARM servers. The same hash verification is mandatory offline.
OS packages must also be installed beforehand. Upstream binaries are downloaded
at deployment time, not redistributed in the TunnelGuard ZIP.

## Review, operation and removal

Omit `--apply` to generate private configuration files only, without downloading
or changing services. Use a **new output directory** for every invocation. A new
server generation creates new credentials; pair clients with the bundle belonging
to the actually installed server. Existing output directories and installations
are never overwritten by the initial installer. Use the [operations toolkit](OPERATIONS.md)
for in-place upgrades, rollback, uninstall and coordinated credential/certificate rotation.

Services use systemd DynamicUser and private LoadCredential configuration. Server
TLS keys never leave the server; client verification remains enabled using the
generated certificate and fixed internal certificate name. The certificate expires
after **365 days**. Plan a coordinated re-pairing of both nodes before expiration;
do not regenerate only one side. These certificates do not impersonate another site.

If service installation/start fails, newly created units and the new installation
are removed; the private generated output remains for troubleshooting. This is an
initial installation rollback, not a guarantee that the route reaches the Internet.
Use the dashboard to verify health after allowing firewall traffic.

To remove a deployment, first back up its private files. On the client:

```bash
sudo systemctl disable --now tunnelguard-client-shadowsocks tunnelguard-client-trojan tunnelguard-client-hysteria2 tunnelguard-client-guard
sudo rm /etc/systemd/system/tunnelguard-client-{shadowsocks,trojan,hysteria2,guard}.service
sudo rm -r /opt/tunnelguard-node/client
sudo systemctl daemon-reload
sudo systemctl reset-failed
```

On the exit server:

```bash
sudo systemctl disable --now tunnelguard-server-server
sudo rm /etc/systemd/system/tunnelguard-server-server.service
sudo rm -r /opt/tunnelguard-node/server
sudo systemctl daemon-reload
sudo systemctl reset-failed
```

This does not delete your generated output/bundle backups or firewall rules.
Remove those separately when no longer needed. Reinstallation interrupts sessions.

Hysteria2 uses UDP as transport, but TunnelGuard's gateway still carries TCP
applications only. No deployment guarantees connectivity through Iranian ISPs.
See [TESTING.md](TESTING.md) for tested scope.

Protocol schemas follow upstream [Shadowsocks](https://sing-box.sagernet.org/configuration/inbound/shadowsocks/),
[Trojan](https://sing-box.sagernet.org/configuration/outbound/trojan/),
[Hysteria2](https://sing-box.sagernet.org/configuration/inbound/hysteria2/) and
[TLS](https://sing-box.sagernet.org/configuration/shared/tls/) documentation.
