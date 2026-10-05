# Operations: diagnostics, lifecycle, renewal and field tests

[فارسی](OPERATIONS.fa.md)

These commands run from a trusted updated checkout (`git pull --ff-only`). They manage
the standard installer paths, not arbitrary third-party deployments. Changes to services
interrupt existing connections; plan a maintenance window. Snapshots contain secrets and
are retained under root-only `/var/lib/tunnelguard-maintenance` until you remove them.

## 1. Diagnose

```bash
sudo python3 diagnostics.py doctor --config /opt/tunnelguard-node/client/config.json --lang en --output diagnostic-report.json
```

Default language is Persian. Includes per-route live probes, categorized advice, systemd
state/restart counts and certificate expiry where readable. Reports omit proxy/target URLs,
credentials and raw journals. Route names remain visible. A timeout cannot establish whether
a firewall, provider filter or target outage is responsible. Run `journalctl` locally when
you need core-specific detail. For a standalone Spoof install use
`/opt/tunnelguard-spoof/client/config.json`.

## 2. Upgrade / rollback / uninstall

Targets: `server`, `client`, `spoof-server`, `spoof-client`.

```bash
sudo python3 maintenance.py upgrade --target client
sudo python3 maintenance.py upgrade --target server --cores
sudo python3 maintenance.py rollback --target client --snapshot SNAPSHOT_ID
sudo python3 maintenance.py uninstall --target spoof-client
sudo python3 maintenance.py snapshots --target client
sudo python3 maintenance.py recover --target client
```

Upgrade uses the current trusted checkout for the guard app; configs and ports are retained.
`--cores` downloads the versions pinned in this checkout and validates existing configs
against the candidate sing-box before replacement. It does not blindly fetch `latest`.
Each mutation prints a snapshot ID. Files are replaced atomically, services restarted and
checked; a failed restart triggers restoration. Snapshot hashes reject altered tree contents.
Upgrade/rotation transactions leave a pending recovery record if interrupted by a kill/power
failure; `recover` restores that record before a later transaction may proceed. The snapshots
command lists IDs and timestamps. Uninstall recovery uses its retained snapshot explicitly.
This is process/config validation, not a proof of end-to-end Internet access. Run doctor next.

Uninstall stops/disables owned units and removes their exact install directory. An attached
Spoof route is removed from the existing guard while preserving later unrelated edits; empty
profiles are removed and a valid default selected. Remove attached Spoof before removing its
base client. Rollback of an uninstall restores its dependent client snapshot too; this also
reverts any edits made after that snapshot. Generated pairing/output files are not deleted.
Firewall rules are never removed automatically. Backup storage has no automatic pruning.

## 3. Coordinated certificate and password rotation

Use two verified SSH `Host` aliases with key authentication, `BatchMode`, host-key checking
and noninteractive `sudo` for the maintenance commands. Both nodes must have this updated
checkout at the same absolute path. Use SSH transport independent of the tunnel being rotated.
The coordinator stages both sides before switching, rotates TLS key/certificate and passwords,
then restarts both. It requests rollback on both if a step fails. A lost SSH connection can
prevent rollback; the local report identifies the side requiring manual recovery.

```bash
python3 pair_maintenance.py --server exit-node --client iran-node \
  --checkout /opt/TunnelGuard --address YOUR_EXIT_IP --family base \
  --output rotation-report.json
```

Use `--family spoof` for the encrypted Spoof overlay. Carrier addresses/settings are preserved.
Only standard one-client deployments are supported. No private TLS key leaves the server;
new passwords/certificate are transferred over SSH stdin and are excluded from the coordinator
report. `maintenance.py rotation-bundle` is an explicit secret-export operation used internally;
do not run it in a recorded terminal.

For daily automated expiry checking on a Linux coordinator whose **root account** already has
the verified SSH setup, add `--install-timer --if-due-days 30` to the command above. It installs
`tunnelguard-renew-base.timer` (or `spoof`) and runs daily with a randomized delay. This checks
the certificate and rotates only when due. This is not an ACME/public-CA certificate. Reports
are `/var/lib/tunnelguard-renewal/base.json` or `spoof.json`; failures appear in the service journal.

```bash
sudo systemctl list-timers 'tunnelguard-renew-*'
sudo journalctl -u tunnelguard-renew-base --no-pager -n 30
```

Install the timer with `sudo python3 pair_maintenance.py ... --install-timer`; the one-off
coordinator can run as your normal account. Stop/remove a timer explicitly with
`sudo systemctl disable --now tunnelguard-renew-base.timer`, then remove that exact timer and
service file under `/etc/systemd/system` and run `sudo systemctl daemon-reload`. Renewal tools
are copied to `/opt/tunnelguard-renewal-tools`; retain them if another renewal timer uses them.

For manual recovery, use the snapshot IDs in `rotation-report.json`, or run
`sudo python3 maintenance.py abort-rotation --target TARGET --rotation ROTATION_ID` on each
reachable node. If the coordinator process is killed or its host loses power, inspect this
report and the root-only `rotation-ID/committed.json` on both nodes before rerunning.

## 4. Bounded soak tests

```bash
sudo python3 diagnostics.py soak --config /opt/tunnelguard-node/client/config.json \
  --seconds 86400 --interval 5 --concurrency 4 --max-mib 6144 --output soak-report.json
```

Reports success rate, request failure streaks, transferred bytes and p95 latency over the
last 1000 successful samples. It probes the first configured health target on each route;
choose a small endpoint you control for sustained testing. Limits: 72 hours, concurrency 16,
64 KiB per request, conservative total byte reservation. It stops on the time or budget limit.
Reports are updated after each round and on Ctrl+C. This measures request behavior, not packet
loss or raw tunnel bandwidth. Only the measurement generator's resources are bounded; it does
not assert production capacity. The JSON `reason` tells whether duration or budget ended the run.

## 5. Real Iran–outside field test

```bash
python3 field_test.py --server exit-node --client iran-node --checkout /opt/TunnelGuard \
  --seconds 300 --max-mib 1024 --family base --output field-report.json
```

This runs measurements on the actual client over SSH and retrieves a redacted report, alongside
the exit certificate's status. It does not install servers or invent credentials. `--family spoof`
probes the generated Spoof route. For a 24-hour run keep the coordinator running and use
`--seconds 86400 --max-mib 6144`. Remote reports remain under `/var/lib/tunnelguard-maintenance`;
an interrupted SSH run may leave the remote measurement running until its own time/budget limit.
No real geography/ISP is inferred: ensure the selected aliases point to the intended hosts.

## CI scope

CI runs native Ubuntu amd64 and ARM64 deployments, plus Windows/Python compatibility tests.
The raw Spoof test is isolated in a namespace with no external network interface. It exercises
upgrade, rollback, certificate/password rotation on both pairs, uninstall/restore and sustained
probes. In Actions → Tests → Run workflow, `soak_seconds` accepts 60–7200 seconds. Ordinary pushes
use 60 seconds. See TESTING.md for actual completed runs; adding a test is not evidence it passed.
