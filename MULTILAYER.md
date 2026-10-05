# Multi-layer integration

New in 2.2: [automatic paired Spoof installation with a TLS overlay](SPOOF.md).
The adapter instructions below also apply to externally installed cores.

[فارسی](MULTILAYER.fa.md) · [Main README](README.md)

TunnelGuard manages **independent ready-made paths**. A route's proxy endpoint is the common interface used for measurements and SOCKS gateway traffic. The `layer` field is a user-supplied label, not protocol detection. A profile restricts selection to explicitly named routes; it does not change their transports.

## Integration map

| Family | Endpoint to provide | Launch adapter |
|---|---|---|
| sing-box | Dedicated SOCKS/HTTP inbound for each configured outbound | `sing-box` |
| Xray | Dedicated SOCKS/HTTP inbound | `xray` |
| Hysteria 2 | SOCKS/HTTP client endpoint over its configured transport | `hysteria2` |
| GOST v3 | SOCKS/HTTP endpoint for its configured chain | `gost` |
| Backhaul | Forward a remote proxy port through the reverse tunnel | `backhaul` |
| Rathole / FRP | Forward a remote proxy port | `rathole`, `frpc` |
| SSH | Local dynamic SOCKS5 forward | `ssh` |
| Candy-Spoof | Existing client SOCKS5 endpoint | `candy-spoof` |
| Parsa spoof-tunnel v3 | UDP carrier → encrypted overlay → proxy bridge | `parsa-spoof` launches only the carrier |
| WireGuard / AmneziaWG / GRE / IPIP / ICMP / DNS carriers | A compatible proxy reached through the already prepared path | External management |

External management is also available for other tools exposing or transporting a compatible endpoint. The manager does not install these products or configure both ends of their connections. A raw forwarded service port is not automatically a SOCKS proxy.

## Six-route example

`config.multilayer.example.json` expects independently configured endpoints at localhost ports 11001–11006. The sample profiles are:

- `All`: Reality, Hysteria, Backhaul, Spoof, SSH, DNS.
- `TCP`: Reality, Backhaul, SSH.
- `QUIC`: Hysteria.
- `Emergency`: Spoof, DNS.

These names are examples, not claims that a route works during a particular outage. Unprepared endpoints will fail health checks. Remove unused routes and their profile references, or set `enabled: false`. If every member of a profile fails, the manager **does not escape the profile**; choose another profile to use other paths.

## Core supervision

Use an absolute executable path and the core's own configuration file:

```json
{
  "name": "Reality",
  "proxy": "socks5h://127.0.0.1:11001",
  "priority": 10,
  "layer": "TCP-TLS",
  "engine": {
    "kind": "sing-box",
    "binary": "/usr/local/bin/sing-box",
    "config": "/etc/tunnelguard/reality.json"
  }
}
```

Add an optional `sha256` field to pin the binary's digest. Structural checks can inspect Linux templates on Windows, but launching requires paths valid on the current OS and actual files.

```bash
python3 tunnelguard.py check --lang en --config config.json --check-engines
python3 tunnelguard.py run --lang en --config config.json --manage-engines
```

Without `--manage-engines`, the program launches no cores. The adapter builds a fixed argument list without shell evaluation. Cores must stay in the foreground. Exited processes are restarted with increasing delays of approximately 2–120 seconds plus jitter. Two minutes of stable execution resets the delay. A failed Internet probe does not cause a restart storm. Core stdout/stderr is discarded; diagnose a core's own configuration by running it separately.

On shutdown, the manager stops the processes it owns. It never invokes sudo or grants raw-socket permissions. Prefer separate system services for privileged overlays and raw-packet cores, while TunnelGuard consumes their ready-made endpoints. The supplied service is designed for that externally managed mode.

### SSH

The SSH adapter additionally needs `host` (an alias in the SSH config) and `local_port`. Its route proxy must be `socks5h://127.0.0.1:LOCAL_PORT`. See `recipes/ssh_config.example`. Prepare the key and trusted known_hosts entry first. Batch mode and strict host-key checking remain enabled; an unknown host key is not silently accepted.

## Spoof integration and limits

The current [Parsa spoof-tunnel documentation](https://github.com/ParsaKSH/spoof-tunnel) describes a UDP pipe; the old integrated SOCKS and encryption layers were removed. Run an independently configured encrypted overlay over that carrier, then expose a proxy reached through the overlay. Do not enter the carrier's UDP listening port as a SOCKS route. Both ends and their upstream networks must permit the required packet behavior.

[Candy-Spoof](https://github.com/AmiRCandy/Candy-Spoof) documents a local SOCKS5 endpoint and Linux raw-socket requirements. Its ready endpoint can be registered as a route. A packet-authentication PSK alone is not evidence of full content encryption; assess confidentiality independently.

No third-party source-address pools, range scanners or new raw-packet implementation are included. The adapters do not demonstrate that spoofing is available on your provider or that either project is more stable than another. No spoofed packets or host firewall changes were used to test this repository.

## Selection policy

Priority mode uses the smaller configured `priority`, with route cost breaking ties. Quality mode uses:

```text
cost = exponentially smoothed HTTP response time in milliseconds
     + 2000 × recent failed-round fraction
     + 100 × current consecutive failures
```

Lower is better. This is a documented heuristic, not packet loss or a standard quality score. A healthy route changes to a better candidate only after `switch_margin` percent improvement for `switch_rounds` independent probe rounds, and after `cooldown`. User connection attempts do not increment the probe-round counter. Failure of the active route does not wait for cooldown.

`quarantine` sets a stabilization period after a route becomes DOWN. Repeated outages double it up to `quarantine_max`; probes continue during the wait. After 30 successful rounds, the outage counter resets. A reused route must both pass recovery checks and finish the stabilization wait.

A manually preferred route falls back to another healthy member of the profile when unavailable, and can return after recovery. Excluding a route prevents new selections and probes without stopping its core or existing connections. Re-enabling it requires fresh health checks.

`connect_attempts` caps attempts across eligible paths during initial connection establishment. Each attempt has the configured `timeout`. Application bytes are sent only after connection establishment; already-sent requests are not replayed. A single destination refusal does not prove that the entire route is down.

## Fixed TCP forwarding

Add per-route endpoints which are **already forwarded to the same application service**:

```json
"tcp_forwards": [
  {
    "name": "PanelTCP",
    "listen_port": 18080,
    "targets": {
      "Reality": {"host": "127.0.0.1", "port": 21001},
      "Backhaul": {"host": "127.0.0.1", "port": 21003}
    }
  }
]
```

The consuming application connects to 127.0.0.1:18080. Target ports here are application forwards, **not SOCKS endpoints**. Ensure the proxy used for route health and its application forward really traverse the same path. An HTTP probe does not verify every service.

All listeners remain loopback-only. Application UDP, SOCKS UDP ASSOCIATE and live session migration are not implemented. Carrying TCP over a QUIC/UDP-based core does not add those features.

## Persistence, reporting and diagnostics

```bash
python3 tunnelguard.py run --config config.json --lang en \
  --output reports --events-file events.jsonl --state-file control-state.json
```

- `--state-file`: atomically saves profile, policy, preferred route and enabled flags. It stores no proxy credentials or old health. Renamed/removed profiles may make old state incompatible; omit the option or choose a fresh state file to start anew. Demo does not persist choices.
- `--events-file`: appends timestamped events up to 10 MiB. Logging errors or reaching the cap do not stop routing; the dashboard shows the issue. Use different files for different running instances.
- `--output`: exports HTML and JSON snapshots. Exports have no live control token. Route names are visible; choose neutral names if recording video.
- T1, T2, etc. refer to configured probe targets in order. DNS errors, TLS errors, HTTP status failures and timeouts are observations; a timeout is not proof that an IP has been filtered.

Source references and protocol-specific templates are linked in the [main README](README.md) and [recipes guide](recipes/README.md). Real-world ISP and core interoperability testing remains necessary.
