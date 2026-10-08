# Two-server links and 3x-ui forwarding (2.5)

[فارسی](TUNNELS.fa.md)

Workflow: install a link between Iran and exit, test it, select a healthy route, then forward an existing 3x-ui user inbound port. VMess/VLESS settings stay in 3x-ui; they are not counted as tunnel families.

Eight families: **SSH, Chisel, WireGuard, Paqet, Spoof, IPIP, GRE and VXLAN**. Each offers direct and reverse channel initiation. SSH and Chisel have native reverse forwarding. WireGuard/Paqet/Spoof carry an encrypted Chisel return channel entirely inside the selected carrier, with no direct fallback. IPIP/GRE/VXLAN are symmetric kernel links; direction selects the initiator of their encrypted inner channel. Sixteen modes are not sixteen independent protocols.

## Pair the management agents

Both nodes require Ubuntu 24.04/systemd, root, Python 3.11+, curl, OpenSSL, OpenSSH, iproute2 and iptables. Supported binary architectures: Linux amd64/arm64. Official core downloads have pinned hashes. Paqet is an alpha release; Spoof is beta.

```bash
sudo apt update
sudo apt install -y git python3 curl openssl openssh-client openssh-server iproute2 iptables
git clone https://github.com/Mehdi682007/TunnelGuard.git
cd TunnelGuard
```

Existing checkouts: `git pull --ff-only`. On a fresh Iran node, the controller installer creates a guard with **zero routes** and an authenticated HTTPS panel; no legacy proxy cores are installed. Its login is saved privately at `/opt/tunnelguard-manager/panel/login.txt`. On existing deployments, publish HTTPS first if needed; see [panel publishing](FORWARDING.md). Existing configurations are preserved.

On Iran, substitute your actual IPs:

```bash
sudo python3 install_manager.py controller --iran IRAN_IP --exit EXIT_IP --output /root/tg-agent-pairing.json
```

Transfer that private file over a trusted channel to exit, then run there:

```bash
sudo python3 install_manager.py agent --bundle /root/tg-agent-pairing.json
```

The pairing contains a bearer credential for this node's job channel. Protect it like a password. No exit root password is stored in the panel. Exit polls Iran's HTTPS panel with certificate verification; this management path must be reachable independently. If it is blocked, the agent cannot receive jobs.

In the panel, wait for the exit agent to become online, choose a unique link name, method and direction, then install/test. Installed does not mean reachable. Consult live health and the last bounded test. Private diagnostics are in `/opt/tunnelguard-manager/operations.log` on each side and each service's journal.

## Spoof and forwarding

Select Spoof and enter both permitted source IPv4 addresses (Iran egress and exit egress). Choose TCP/UDP independently for each carrier direction. The panel applies both configurations. A syntactically valid source is not proof that the provider permits it. Do not use placeholder addresses.

For an existing exit inbound on 4748, choose Iran port 4748, target `127.0.0.1:4748`, select tunnel routes, enable public listening and apply. Verify the forward appears after the guard restart. This forwards **TCP**, not application UDP. Select the user inbound, not the 3x-ui administration port. Keep the user's UUID, transport and TLS settings; change the client connection address to Iran's IP. Existing sessions do not migrate after failure.

Removing the only route used by a forward is rejected. Use [manage.py](FORWARDING.md) to remove/remap an existing forward before deleting that link. The panel supports multiple named TCP forwards with edit/delete controls and fixed per-port or global-follow routing. See the interactive menu and login instructions in README.md.

## Network and lifecycle

Each instance has `tunnelguard-link-NAME.service`, base port `23000+slot*10`, and local SOCKS port `30000+slot`. WireGuard/Paqet/VXLAN use carrier port `base+1`; Spoof uses `base+1` and `base+4`. Kernel inner addresses use `10.203.slot.1/30` and `.2/30`; check for conflicts first. IPIP requires IP protocol 4, GRE protocol 47, and VXLAN its allocated UDP port. Provider firewall rules are not automatically opened.

Paqet adds three peer-IP/port-scoped NOTRACK/RST rules and removes them on stop. No default route, global NAT, global sysctl or 3x-ui service changes are made. Kernel link payloads are protected by the authenticated Chisel inner channel; the outer kernel tunnel itself is unencrypted.

Failed/partial installs remain visibly failed. Remove both sides, wait for peer cleanup, then retry. Agent restart does not remove established link services. Upgrade the installed controller with `sudo python3 install_manager.py controller --upgrade` and exit with `sudo python3 install_manager.py agent --upgrade` after updating the checkout; guard upgrade may interrupt current forwarded connections. Existing private pairing/configuration is preserved.

Upstream: [Paqet](https://github.com/hanselime/paqet), [Chisel](https://github.com/jpillora/chisel), [Spoof](https://github.com/ParsaKSH/spoof-tunnel). No claim of supporting every tunneling method or a guaranteed number of working links on a filtered address.
