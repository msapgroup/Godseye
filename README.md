# GODSEYE

GODSEYE is a local-first Raspberry Pi 4 network monitoring, discovery, diagnostics, and troubleshooting appliance inspired by Pi.Alert and the feature set of NetAlertX.

## This working copy

This distribution keeps the existing GODSEYE authentication, MFA, device inventory, event history, alert rules, notifications, scanner health, and privilege separation, and adds the foundation for broader NetAlertX-style functionality without Docker.

### Included now

- ARP discovery with `arp-scan`
- Reverse DNS enrichment
- ICMP cross-checks
- Persistent SQLite/WAL inventory
- New/disconnect/reconnect/IP-change events
- Device classification
- Alert rules
- ntfy/email/webhook notifications
- Session authentication and TOTP MFA
- Admin/read-only roles
- CSRF/security headers/account lockout
- Privilege-separated web and scanner systemd services
- Native plugin registry and scheduler
- Nmap local-network discovery
- IPv4/IPv6 neighbor discovery
- Local hostname lookup
- Read-only gateway and Internet diagnostics
- Host troubleshooting and evidence-based recommendations
- Authenticated `/tools` diagnostics page
- Feature-parity manifest for planned integrations
- Basic automated tests

## Screenshots

![GODSEYE UI overview](docs/screenshots/godseye-ui-overview.png)

See [docs/SCREENSHOTS.md](docs/SCREENSHOTS.md) for the walkthrough.

## Fresh Raspberry Pi installation

```bash
sudo apt update
sudo apt install -y git
git clone https://github.com/msapgroup/Godseye.git /tmp/godseye-install
cd /tmp/godseye-install
sudo bash install.sh
```

The installer installs the required Raspberry Pi packages, copies the checked-out release into `/opt/godseye` (it does not clone the repository a second time), creates the `godseye` service account, installs the web/scanner systemd services, validates the application import before starting services, and creates a random initial admin password if one was not supplied. Optional tools are installed when available. Use `sudo bash install.sh --doctor` for diagnostics.

After installation:

```bash
sudo systemctl status godseye-web
sudo systemctl status godseye-scanner
```

Open the Pi's web address on your LAN. The exact listener/port is defined by the systemd configuration in this release.

## Diagnostics

After logging in, open:

```text
/tools
```

Available read-only tools include:

- Host ping and packet-loss diagnosis
- DNS resolution
- Gateway test
- Internet connectivity test
- IPv4/IPv6 neighbor discovery
- Nmap discovery of private/link-local networks

Nmap targets are deliberately restricted to private/link-local networks by the API.

## Development and testing

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
PYTHONPATH=. pytest -q
python -m compileall app
```

The working copy was locally verified with Python compilation, application import, and three smoke tests.

## Security model

The web service runs as the unprivileged `godseye` account. Only the scanner service runs as root because ARP scanning requires elevated privileges. The application is intended for trusted LAN/VPN access and should not be exposed directly to the public Internet.

## Documentation

- `docs/USAGE.md` — installation and how-to guide
- `docs/netalertx-parity.md` — feature parity roadmap
- `docs/screenshots/` — current UI documentation images

## Roadmap

The plugin architecture is prepared for additional native integrations including DHCP, Pi-hole, UniFi, SNMP, router APIs, mDNS/NetBIOS enrichment, website/service monitoring, Wake-on-LAN, workflows, MQTT, Prometheus, reports, and additional notification providers.

These are tracked as implementation work; they are not represented as complete merely because they appear in the capability manifest. The screenshot walkthrough is a product/UI presentation aid and is labeled accordingly.

## Native network tools and integrations

The working build is Docker-free and includes authenticated endpoints for Nmap LAN discovery, IPv4/IPv6 neighbor discovery, host/gateway/Internet diagnostics, website monitoring, Pi-hole testing, UniFi testing, SNMP testing, and Wake-on-LAN. See `docs/GITHUB_RELEASE.md` and `docs/USAGE.md` for deployment and usage.
