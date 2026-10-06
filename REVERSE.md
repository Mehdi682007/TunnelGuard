# Reverse SSH installer

[فارسی](REVERSE.fa.md)

The exit connects to Iran's SSH server, creating a loopback SOCKS endpoint on Iran. This may work when Iran cannot initiate a connection to the exit. It is TCP-only and not a universal censorship workaround. The dedicated account has no shell, local forwarding, Unix sockets, PTY, agent, X11 or TUN access. Both ends use keepalives; systemd reconnects automatically.

On exit:

```bash
sudo python3 deploy_reverse.py prepare --receiver YOUR_IRAN_IP \
  --sender YOUR_EXIT_IP --output /root/tg-reverse-offer
```

Transfer **only offer.json** to Iran over trusted SSH. Keep `key` on exit. After base installation, on Iran:

```bash
sudo python3 deploy_reverse.py accept --bundle /root/offer.json \
  --output /root/tg-reverse-accept --attach --apply
```

This creates the restricted `tunnelguard-relay` account and a per-user sshd fragment, validates sshd before reload, and attaches the route. Root login settings remain unchanged. Verify the printed Iran host-key fingerprint through a trusted channel. Transfer `acceptance.json` back to exit:

```bash
sudo python3 deploy_reverse.py connect --bundle /root/acceptance.json \
  --key /root/tg-reverse-offer/key --output /root/tg-reverse-start --apply
```

On Iran:

```bash
curl --noproxy '' --proxy socks5h://127.0.0.1:11005 https://www.gstatic.com/generate_204 -I
```

Defaults: SSH 22, SOCKS 11005. Override with `prepare --ssh-port` / `--socks-port`. Paired addresses currently require IPv4. Omitting `--apply` validates only; prepare creates private files. Running a service is not evidence of successful traffic delivery.

For an earlier matching field deployment, use `prepare --key /root/tunnelguard-field/reverse_ed25519` and `--adopt-existing` with accept/connect. Always choose new output directories. Existing keys must match; changed files are backed up privately. Reconnect existing sessions after changing keepalive settings.

Exit service: `tunnelguard-reverse-ssh`; files: `/opt/tunnelguard-reverse`. Iran SSH fragment: `/etc/ssh/sshd_config.d/90-tunnelguard-relay.conf`. These account/unit changes are maintained through this installer, not generic maintenance targets. To stop, disable the exit service and remove the reverse route/dependent forward targets. Account deletion is manual after its sessions stop and other uses are ruled out; the installer does not silently delete retained files.

Reference: [OpenSSH remote dynamic forwarding](https://man.openbsd.org/ssh#R).
