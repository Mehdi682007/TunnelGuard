# TunnelGuard

**2.5: [two-server tunnel management from the panel](TUNNELS.md)** — SSH, Chisel, WireGuard, Paqet, Spoof, IPIP, GRE and VXLAN, direct/reverse channels, Spoof source inputs, paired exit agent and forwarding for existing 3x-ui inbounds. Fresh installation needs no VMess/VLESS deployment. The 2.4 proxy installers below remain for compatibility and are not counted as independent network tunnel methods.

**New in 2.4:** [ten installer options](TRANSPORTS.md), [reverse SSH](REVERSE.md), [userspace WireGuard](WIREGUARD.md), [TCP/x-ui forwarding and authenticated HTTPS dashboard](FORWARDING.md). Available installers are shown separately from configured/healthy routes. No minimum number of working protocols is guaranteed.

**[فارسی — راهنمای کامل](README.fa.md)** · **English** · [Multi-layer guide (English)](MULTILAYER.md) · [راهنمای چندلایه و Spoof](MULTILAYER.fa.md)

Local tunnel monitoring, route selection and TCP failover, with a Persian/English dashboard.

**New in 2.3: [operations toolkit](OPERATIONS.md)** — bilingual diagnostics, snapshot-based upgrades/rollback/uninstall, coordinated certificate/password rotation with an optional daily timer, bounded soak and SSH field tests, and native ARM64 CI.

**New in 2.2: [automatic Spoof installation](SPOOF.md)** — pinned Parsa carrier + verified TLS overlay, paired server/client setup and automatic attachment to the existing gateway. Experimental upstream beta; explicit source IPs and a compatible provider network are required.

TunnelGuard measures existing HTTP CONNECT or SOCKS5 routes, exposes a stable local SOCKS5 gateway, and selects a healthy route for **new TCP connections**. It includes manual controls, network profiles, quality-based selection, bounded download benchmarks and optional supervision of separately installed tunnel cores.

**New in 2.1: [automatic two-node deployment](DEPLOY.md)** for Shadowsocks 2022, Trojan/TLS and Hysteria2/QUIC, including verified core downloads, paired configurations and systemd services. [راهنمای نصب دو سمت](DEPLOY.fa.md)

Other adapters require separately configured cores. TunnelGuard does not implement a new spoofing protocol or guarantee connectivity on any ISP. Existing sessions are not migrated, and application UDP / SOCKS UDP ASSOCIATE is not supported.

## Requirements

- Python **3.11+**.
- curl **8.4+** for live measurements; the offline demo needs no curl or Internet access.
- No pip dependencies.
- For live use: at least one working SOCKS5 or HTTP CONNECT endpoint; two independent routes are recommended for failover.

## Download and run

On Ubuntu 24.04:

```bash
sudo apt update
sudo apt install -y git python3 curl
git clone https://github.com/Mehdi682007/TunnelGuard.git
cd TunnelGuard
python3 tunnelguard.py demo --config config.multilayer.example.json
```

Open **http://127.0.0.1:8787**. The demo is explicitly marked as simulated and starts **no proxy gateway**. Switch language with the button at the top.

On Windows, install Python 3.11+ and Git, clone the repository, and replace `python3` with `python`. A sufficiently recent `curl.exe` must be on PATH for live mode. All examples use the same Python program; the optional installer below is for Linux/macOS.

You can also download a versioned ZIP from [Releases](https://github.com/Mehdi682007/TunnelGuard/releases), extract it, and run commands inside its `tunnelguard` directory.

## Optional local installation — no root

After cloning or extracting:

```bash
python3 install.py
export PATH="$HOME/.local/bin:$PATH"
tunnelguard demo
```

This copies program files to `~/.local/share/tunnelguard` and creates `~/.local/bin/tunnelguard`. It does not change shell startup files, firewall rules or system routing, download cores, or start services. Add that PATH setting to your shell profile if you want it to persist. Existing `config.json` is preserved on upgrade.

For custom locations:

```bash
python3 install.py --prefix /YOUR/INSTALL/DIRECTORY --bin-dir /YOUR/BIN/DIRECTORY
```

Run `python3 install.py` again from an updated checkout to upgrade program files. To uninstall, remove the launcher and installed directory after backing up your private configuration and reports. The installer prints the exact two paths.

## Configure real routes

When running from a checkout, use the following. With a local installation, replace `python3 tunnelguard.py` with `tunnelguard`.

```bash
python3 tunnelguard.py init --interactive
python3 tunnelguard.py check --lang en
python3 tunnelguard.py run --lang en --output reports \
  --events-file events.jsonl --state-file control-state.json
```

The setup asks for each route's name, proxy URL, declared layer and optional engine. Select `external` for already running cores. Proxy URL input is hidden to avoid displaying credentials. `init` never overwrites an existing configuration.

A minimal route definition:

```json
{"name":"Primary","proxy":"socks5h://127.0.0.1:11001","priority":10,"layer":"TCP-TLS"}
```

Configure the consuming application to use SOCKS5 **127.0.0.1:1088**, with remote DNS resolution. Test it with:

```bash
curl --noproxy "" --proxy socks5h://127.0.0.1:1088 https://example.com
```

Only applications using this gateway are routed by TunnelGuard. By default, both gateway and dashboard bind to loopback. The optional HTTPS publisher and explicit public TCP forwards are documented in [FORWARDING](FORWARDING.md). To access an instance on your VPS, run this on your own computer:

```bash
ssh -N -L 8787:127.0.0.1:8787 -L 1088:127.0.0.1:1088 user@YOUR_SERVER
```

Keep configuration files private (`chmod 600 config.json` on Linux). Credentials in proxy URLs must be percent-encoded where necessary. Check proxy and port values before use: the examples are placeholders, not working public services.

## Commands

| Command | Purpose |
|---|---|
| `demo` | Synthetic route outage/recovery demonstration; no gateway or external cores |
| `init --interactive` | Create a private configuration without overwriting |
| `check` | Validate configuration and local curl dependency |
| `check --check-engines` | Also verify core files and optional binary SHA256 values |
| `run` | Start live probes, local SOCKS5 gateway and dashboard |
| `run --manage-engines` | Additionally launch configured foreground cores |
| `lab --rounds 5 --output reports` | Spaced health measurements and HTML/JSON report |
| `benchmark --url URL --rounds 3 --output reports` | Sequential bounded download measurements |
| `adapters` | List supported launch adapters and upstream project links |

Add `--config FILE` to choose a configuration explicitly. Live commands otherwise prefer `config.json` beside the program and fall back to `config.example.json`. Demo defaults to the example. Add `--lang en` for English console messages; dashboard language is independently selectable.

Example download benchmark against a known-size file **on a server you control**:

```bash
python3 tunnelguard.py benchmark --lang en --config config.json \
  --url https://YOUR_DOMAIN/test-5MiB.bin \
  --max-bytes 5242880 --timeout 20 --rounds 3 --output reports
```

Timeouts, oversized responses and incomplete downloads are failures, not successful speed samples. The result is `reports/benchmark.json`. Small-file speed is not a guarantee of sustained link capacity.

## Dashboard and failover

- Choose a profile, selection policy, preferred route, or temporarily exclude a route.
- A failed preferred route falls back only to healthy members of the selected profile.
- No eligible route means new connections are rejected; there is no direct-Internet fallback.
- Disabling a route does not terminate existing sessions or stop its core.
- Priority mode uses configured priorities. Quality mode uses a documented cost heuristic with an improvement margin, consecutive probe rounds and cooldown.
- A flapping path receives an increasing stabilization wait before reuse.
- Connection-establishment failures can try another eligible route **before application bytes are forwarded**. Requests already sent are never replayed.
- `--state-file` persists choices, not stale health or proxy credentials. Each restart rechecks health.

The displayed HTTP time is **not ICMP ping**. Variation is variation of successful HTTP response times, not packet-level jitter. Success is the fraction of successful probe rounds, not measured packet loss. See the [multi-layer guide](MULTILAYER.md) for policy details and protocol integration.

## Core adapters

SSH, sing-box, Xray, Hysteria 2, GOST v3, Backhaul, Rathole, FRP client, Candy-Spoof and Parsa spoof-tunnel have explicit launch adapters. **Adapter support means launching and supervising an already installed core using its own config**, not bundling its binary or proving interoperability with all versions.

Parsa's current UDP-pipe architecture needs an encrypted overlay and a proxy bridge; its raw UDP port cannot be entered as a SOCKS endpoint. Other ready-made tunnels can be used whenever they expose or carry a compatible proxy endpoint. See [MULTILAYER.md](MULTILAYER.md), [config.managed.example.json](config.managed.example.json) and [recipes](recipes/).

## Linux system service

The supplied service runs TunnelGuard without managing privileged cores. After configuring and testing `config.json` in your checkout:

```bash
sudo mkdir -p /opt/tunnelguard
sudo cp tunnelguard.py engines.py dashboard.html config.json /opt/tunnelguard/
sudo chmod 600 /opt/tunnelguard/config.json
sudo cp tunnelguard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tunnelguard
sudo journalctl -u tunnelguard -f
```

The unit uses systemd `LoadCredential` and a dynamic user. It needs a compatible systemd version and Python 3.11+ at `/usr/bin/python3` (Ubuntu 24.04 is the documented baseline). Existing engine services remain separate. It does not enable persistent report files by default. Stop it with `sudo systemctl disable --now tunnelguard`.

## Validation and reporting problems

```bash
python3 -m unittest discover -v
```

See [TESTING.md](TESTING.md) for the validation record. Local tests cover real traffic through fixture proxies, failover, profile boundaries, control authentication, process restart and persistence. They do not demonstrate raw spoofing or connectivity through an Iranian ISP. Linux/Windows CI results are visible in [Actions](https://github.com/Mehdi682007/TunnelGuard/actions).

When filing a problem, include OS, Python/curl versions, engine name/version, command and sanitized error. Do not publish passwords, UUIDs, tokens, keys, real proxy URLs or private configuration files. Dashboard exports intentionally omit proxy addresses and credentials; route names remain visible.

External projects retain their own licenses. This repository does not include their source code or binaries.

## Interactive server installation and panel login

```bash
sudo apt update && sudo apt install -y git python3
git clone https://github.com/Mehdi682007/TunnelGuard.git
cd TunnelGuard
sudo python3 setup.py
```

Menu: **1 Install**, **2 Upgrade**, **3 Change panel credentials**, **4 Status**, **5 Install prerequisites**, **0 Exit**. Choose prerequisites first on a fresh host. Install asks for **1 Iran / 2 Outside**. Iran creates the HTTPS panel and a private pairing file; transfer that file to outside and select outside installation there. Update the checkout (`git pull --ff-only`) before selecting Upgrade. Existing pairing is preserved.

Open `https://IRAN_IP:8787/login`. Initial credentials remain in `/opt/tunnelguard-manager/panel/login.txt`. Use the panel account form to change username/password (current credentials required), or menu option 3 on Iran to recover access as root. Restart/credential changes expire browser sessions. The initial login file is not updated when credentials change; retain your new password.

Each TCP forward has a name, public/local listener, destination, and routing mode. Add as many distinct listener ports as needed. For example, select **fixed** and only WireGuard for 4748, then add a second named forward for 7643 selecting only Paqet. Both destination inbounds must already exist in 3x-ui on outside. Fixed routes are independent of global selection/profile; unhealthy fixed routes fail closed. Alternatively choose **follow global selection** for automatic managed-tunnel switching. Existing forwards can be edited/deleted from their cards. Applying configuration restarts the guard and briefly interrupts traffic; ordinary tunnel selection does not restart it.
