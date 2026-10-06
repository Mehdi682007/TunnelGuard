# Additional tunnel installers

[فارسی](TRANSPORTS.fa.md)

Ten installer options: Shadowsocks 2022, Trojan/TLS, Hysteria2/QUIC, reverse SSH, VMess/WebSocket/TLS, VLESS/TLS, TUIC/QUIC, AnyTLS, WireGuard and Spoof with a Hysteria2 overlay. These do not guarantee a minimum success ratio: an unreachable IP can affect several protocols simultaneously.

The dashboard separates available installers, configured routes and measured health. Spoof appears as a live route only after [pairing](SPOOF.md). [Reverse SSH](REVERSE.md) and [WireGuard](WIREGUARD.md) have their own installers in this repository. Downloaded cores remain pinned and verified.

Fresh seven-protocol sing-box installation on exit:

```bash
sudo python3 deploy.py server --address YOUR_EXIT_IP \
  --extra-ports 18446 18447 18448 18449 \
  --output /root/tg-server --apply
```

Transfer private `pairing.json` and install the client following [DEPLOY](DEPLOY.md). Base ports are TCP/18443, TCP/18444, UDP/18445. Extra ports are respectively TCP/18446, TCP/18447, UDP/18448, TCP/18449. Default local SOCKS ports: 11001–11003 and 11006–11009; 11004 and 11005 are reserved for Spoof and reverse SSH.

For an existing three-protocol pair, update the code checkout, then on exit:

```bash
sudo python3 deploy_extra.py server --address YOUR_EXIT_IP \
  --output /root/tg-extra-server --apply
```

Securely transfer its `pairing.json` to Iran:

```bash
sudo python3 deploy_extra.py client --bundle /root/extra-pairing.json \
  --output /root/tg-extra-client --apply
```

This reuses the installed base core and keeps existing base credentials/configuration. Each side gets a maintenance snapshot; activation failures roll back. Guard restart may interrupt active connections. Override extra ports using four `--ports` values, and local ports using `--local-base`. Firewall rules remain unchanged.

Updated coordinated base credential/certificate rotation supports all seven transports, provided both maintenance checkouts are updated. The certificate lasts 365 days. WebSocket here connects directly to the exit IP; it does not automatically provision a CDN or public domain certificate.

Backhaul, Rathole, FRP, GOST and ordinary SSH have adapters, not automatic paired installers. Configure their actual core and SOCKS/HTTP endpoint before registering it:

```bash
sudo python3 manage.py route-add --name MyBackhaul \
  --proxy socks5h://127.0.0.1:12001 --layer Backhaul --apply
```

That command does not install an external core. See [TCP/x-ui forwarding](FORWARDING.md).
