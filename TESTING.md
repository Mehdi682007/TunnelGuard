# TunnelGuard validation record

## 2.5 paired tunnels and account page — 2026-10-08

The local Windows suite discovers 68 tests: 67 pass and one real-core test is
opt-in. Authenticated access to the separate `/account` page and unauthenticated
redirects are covered. JavaScript syntax and referenced element IDs were checked
for the dashboard and account page; no new visual browser QA is claimed here.

Rathole v0.5.0 with Noise passed real payload transfer in both directions in
isolated amd64 Linux network namespaces. It also passed HTTPS requests through
each direction between the authorized Iran/outside VPS pair, returning HTTP 204
with normal TLS certificate verification. The existing VLESS TCP forward passed
an HTTPS application request after the deployment upgrade. These are bounded
connectivity checks, not throughput, long-term uptime, or all-ISP guarantees.
Rathole arm64 archives are pinned but have not been executed in this field run.

Both server roles were upgraded in place, preserving pairing and credentials.
Repeated manager installation now replaces its existing systemd unit rather
than failing with `FileExistsError`. Earlier validation records below describe
the code and limitations at their respective dates.

## 2.4 transport, forwarding and public panel validation

The [initial 2.4 run](https://github.com/Mehdi682007/TunnelGuard/actions/runs/37400704220)
passed all six Windows/Linux and native amd64/ARM64 jobs. The default suite discovers
52 tests (51 pass, one real-core test is opt-in). Native integration transfers actual
HTTP payloads through Shadowsocks, Trojan, Hysteria2, VMess, VLESS, TUIC, AnyTLS and
the userspace WireGuard SOCKS bridge. Follow-up CI also exercises reverse WireGuard
initiation, seven-protocol credential rotation and fresh restricted reverse SSH installation.

An authorized two-VPS field trial on 2026-10-06 installed nine routes. In a bounded
120-second probe run, reverse SSH succeeded in 9/9 samples; the other eight routes
failed in 9/9 samples each. Both WireGuard initiation directions failed on that path.
This is a short connectivity measurement, not a throughput or long-term availability result.
Spoof is visible in the catalog but was not configured in this field trial. Its raw
transport tests remain isolated network-namespace tests, not proof of ISP compatibility.

A temporary public TCP listener on the receiving VPS delivered an exact HTTP fixture
from the sending VPS's loopback address through reverse SSH. The listener and fixture
were removed afterwards. No x-ui installation or real user inbound was present.
The public HTTPS dashboard returned 401 without authentication and 200 with it;
certificate chain/IP verification succeeded using its exported self-signed certificate.
Reports were checked for absence of dashboard TLS keys and authentication secrets.

The records below describe earlier releases and their limitations at the time.
No release promises that a particular number of transports will work on every filtered IP.

## 2.3 operations and native ARM64 validation

[Final functional run](https://github.com/Mehdi682007/TunnelGuard/actions/runs/37340018201)
passed all six jobs: Windows/Ubuntu with Python 3.11/3.12 and native Ubuntu amd64/ARM64
deployment jobs. The default suite discovered 47 tests, passed 46 and skipped the opt-in
real-core test; Linux jobs ran that test separately.

Both native architectures completed real service upgrade/rollback, certificate and password
rotation on the normal and Spoof pairs, Spoof detach/uninstall/restore, expiry extraction
from the real certificate, and syntax verification of generated renewal timer/service units.
The timer was not activated against fake SSH hosts. The coordinator's failed-client recovery
and secret-free reporting are unit-tested; no real two-host SSH renewal has been run yet.

Each native job then probed all four routes concurrently for 60 seconds, followed by
30 seconds with isolated loopback netem delay 10ms ±3ms and 0.5% synthetic packet loss.
All requests succeeded in these recorded runs: 224+61 requests per route on amd64 and
225+60 on ARM64. This is request success, not absence of dropped/retransmitted packets.
Reports with latency percentiles are printed in the CI logs.

A separate [600-second run](https://github.com/Mehdi682007/TunnelGuard/actions/runs/37339101697)
also passed on both native architectures (600.01s amd64, 600.00s ARM64). That run preceded
the final recovery-journal refinements and synthetic loss step; it validates the same
transport stack for ten minutes, not multi-day stability.

No user Iran/outside servers were supplied. Actual ISP field measurements, independent SSH
coordination and multi-day production/load validation remain pending until those servers
are available. The field/soak commands are implemented and documented. Do not infer a
connectivity or throughput guarantee from the isolated loopback tests.

## 2.2 automatic Spoof deployment

[GitHub Actions validation](https://github.com/Mehdi682007/TunnelGuard/actions/runs/37329940744)
passed all five jobs: four OS/Python combinations plus a dedicated Ubuntu amd64 Spoof job.
The default suite passed 39 tests with the separate real-core test skipped; Linux jobs
also ran that real-core test explicitly. Local Windows run: 40 discovered, 39 passed,
one opt-in skip, 9.146 seconds.

The Spoof job verified pinned downloads, then deployed the real Parsa v3.1.0-beta.0
and sing-box 1.14.2 binaries as systemd services inside a loopback-only network namespace.
The namespace had no uplink, veth or default route. Endpoint/source addresses were
127.0.0.1–127.0.0.4; no raw packet was sent to any external network.

Validated: raw TCP upload / raw UDP download, TLS overlay config validation and handshake,
288,000-byte payload equality through both the Spoof SOCKS endpoint and the guard,
automatic attachment to an existing three-route deployment, exact backup of the original
configuration, and selection of the Emergency profile so normal routes could not mask a
Spoof failure. The pairing file did not contain the server private key. Actual root carrier
services ran with a CAP_NET_RAW-only capability bounding set; TLS/guard used DynamicUser.

Unit tests additionally cover direction/peer source matching, malformed network settings,
duplicate ports, refused unsupported carriers, corrupted offline binary hashes, route/profile
preservation and duplicate route rejection.

Not tested: alternative TCP/UDP direction combinations, ARM64 execution, multiple independent
client nodes, NAT/provider filtering, Iranian ISP paths, censorship resistance, packet loss/load
soak tests or long-term upstream beta stability. The installation and the isolated tested path
work; this is not evidence that a particular provider allows source spoofing. ICMP/ICMPv6/XDP
deployment is not exposed. Certificate rotation remains manual.

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
