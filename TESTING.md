# TunnelGuard validation record

## 2.1 automatic deployment

[GitHub Actions validation](https://github.com/Mehdi682007/TunnelGuard/actions/runs/37307542088)
passed all four Ubuntu 24.04 / Windows and Python 3.11 / 3.12 jobs.
The default suite has 34 passing tests plus one opt-in integration test skipped.
Both Linux jobs explicitly enabled that integration test, downloaded the pinned
official sing-box 1.14.2 amd64 archive, checked its SHA256 and generated server/client
configs, transferred an HTTP payload over Shadowsocks 2022, Trojan/TLS and Hysteria2/QUIC,
and verified that the TunnelGuard gateway still transfers data after stopping the
local Shadowsocks process.

The Ubuntu / Python 3.12 job additionally ran the real root installer for both nodes,
started all five systemd services with DynamicUser/LoadCredential, checked their active
state and transferred a known local HTTP payload through all three installed core services.
The service restriction now permits AF_NETLINK for core interface discovery; the guard
does not need that address family. A failed installation during development exercised
rollback of newly created service/install files.

Additional unit coverage: generated credentials/TLS mapping, loopback client listeners,
invalid bundles and port collisions, refusal to overwrite files, Unix private file
permissions, bad archive hashes and symlinks, and occupied-port detection.

These are local loopback tests on hosted Ubuntu amd64 runners, not a two-country field
trial. ARM64 hashes/download support are present but ARM execution has not been tested.
Offline download selection, long-term certificate renewal, host/provider firewall setup,
Internet censorship resistance and production load have not been qualified. Certificate
rotation and in-place deployment upgrades are not automated. Xray/Spoof/other adapter
binaries remain untested by this integration suite.

## 2.0 historical validation

Environment: Windows, Python 3.12.10, curl 8.9.1. Date: 2026-10-05.

`python -m unittest discover -v`: **28 unique tests passed**, local publication run 9.245 seconds.

GitHub Actions [publication validation](https://github.com/Mehdi682007/TunnelGuard/actions/runs/37305166870)
passed all four jobs: Ubuntu 24.04 and Windows, each with Python 3.11 and 3.12.
Each job ran all 28 tests and validated the multi-layer example configuration.
Both Linux jobs also installed into paths containing spaces, executed the installed launcher,
and confirmed that reinstalling preserves an existing config.json.

Validated with local fixtures:
- Actual curl traffic through HTTP CONNECT and SOCKS5, credential handling and half-close.
- Health-threshold failover and immediate connection-establishment fallback before application bytes.
- No direct fallback when no route is eligible; profile boundaries; preference and maintenance toggles.
- Quality improvement over distinct probe rounds; increasing stabilization wait after repeated outages.
- Bounded probe concurrency and discarding stale in-flight results after disabling/re-enabling a route.
- TCP forwarding of real HTTP application bytes to a local endpoint.
- Control API rejects invalid tokens and cross-origin requests; report exports omit control tokens.
- Config creation never overwrites; malformed structures and forwarding loops are rejected.
- Atomic report replacement; persistent choices restore no old health and contain no proxy credentials.
- Event-file failures do not stop route selection.
- Native path validation, shell-free argument construction, SHA256 mismatch rejection and SSH option validation.
- Real owned test process exits with code 7, is restarted after backoff, and is stopped on cancellation.

The managed Linux template and six-route template both passed structural `check` on Windows.
`--check-engines` additionally requires actual local binaries/configs and native OS paths.

Browser QA: live Persian RTL dashboard rendered; manual preference changed the active simulated
route; selecting Emergency restricted choices to Spoof/DNS; selecting quality succeeded.
English/Persian switching was verified in preceding versions. Offline exports contain both languages
and no live control token. Direct file-URL browser inspection was unavailable due to browser policy;
no browser verification of the final offline report is claimed.

In the 2.0 validation, external cores were NOT downloaded or executed. Launch lifecycle was verified with an owned Python
fixture, not production sing-box/Xray/Spoof binaries. Protocol-specific config templates contain
placeholders and require validation with the installed core after completion.

Not validated: production VPS/systemd deployment, raw-packet spoofing, actual Iranian ISP paths, third-party
core interoperability, sustained production load, UDP applications or migration of existing sessions.
The saved six-route report contains synthetic demo data only.
