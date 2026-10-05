# Client templates

[فارسی](README.fa.md)

These are **incomplete templates**, not working credentials. Replace `YOUR_*` and `REPLACE_*` values, remove the `.example` suffix, and validate with the installed core before enabling supervision.

- `sing-box-reality.json.example`: mixed local inbound on 11001 with a VLESS/REALITY outbound. Validate the completed file with `sing-box check -c FILE`.
- `hysteria-client.yaml.example`: local SOCKS5 on 11002, certificate verification enabled, fastOpen disabled to preserve initial connection error semantics.
- `ssh_config.example`: the `tg-backup` host alias. Supply your server, key and a previously verified known_hosts entry. TunnelGuard's SSH adapter creates the SOCKS listener.

Backhaul/Rathole forwards need a compatible proxy carried through the tunnel for health checks. Parsa v3 needs an encrypted overlay and proxy bridge. See [the multi-layer guide](../MULTILAYER.md).

References: [sing-box VLESS](https://sing-box.sagernet.org/configuration/outbound/vless/), [TLS](https://sing-box.sagernet.org/configuration/shared/tls/), [Hysteria client](https://v2.hysteria.network/docs/advanced/Full-Client-Config/), [SSH](https://man.openbsd.org/ssh.1).
