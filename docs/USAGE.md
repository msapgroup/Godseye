# GODSEYE Usage Guide

GODSEYE is a local-first network monitoring and troubleshooting appliance for Raspberry Pi 4 and compatible Linux systems.

## 1. Install

On Raspberry Pi OS 64-bit:

```bash
sudo apt update
sudo apt install -y git
sudo git clone https://github.com/msapgroup/Godseye.git /opt/godseye-src
cd /opt/godseye-src
sudo bash install.sh
```

The installer creates a dedicated `godseye` service account, a web service, and a privileged scanner service. It generates a unique initial administrator password when one is not supplied through the environment.

## 2. Open GODSEYE

Use the Pi's LAN address and the port configured by the web service. Complete the initial password change and enable TOTP MFA from **Security**.

## 3. Overview

The Overview screen shows discovered devices, online/offline state, devices needing review, recent events, and scanner health. Use **Scan Now** for an immediate discovery request.

## 4. Tools

Open `/tools` while authenticated for the diagnostic toolkit:

- Host ping and packet-loss diagnosis
- DNS resolution
- Gateway test
- Internet connectivity test
- IPv4/IPv6 neighbor discovery
- Nmap local-network discovery

Diagnostics are read-only. GODSEYE does not change router, DHCP, DNS, or device configuration without a future explicit fix action.

## 5. Troubleshooting workflow

1. Identify the affected device/event.
2. Run host diagnostics.
3. Check packet loss and latency.
4. Test the gateway.
5. Test Internet/DNS separately.
6. Review related device events.
7. Follow the evidence-based recommendation.

## 6. Nmap

Nmap must be installed on the Pi. The built-in GODSEYE endpoint only accepts private or link-local networks. Example: `192.168.1.0/24`.

## 7. Service health

```bash
sudo systemctl status godseye-web
sudo systemctl status godseye-scanner
sudo journalctl -u godseye-web -f
sudo journalctl -u godseye-scanner -f
```

## 8. Screenshots

The screenshots under `docs/screenshots/` document the shipped UI. Replace them with captures from your running Pi once deployment is available.

## Native integrations and tools

GODSEYE is designed to run directly on Raspberry Pi OS without Docker. The current working build exposes authenticated APIs for:

- Nmap private-network discovery
- IPv4/IPv6 neighbor discovery
- Hostname/reverse lookup
- Host diagnostics, gateway checks, and Internet checks
- Website/HTTP monitoring
- Pi-hole API connectivity testing
- UniFi controller login testing
- SNMP device testing
- Wake-on-LAN

Integration credentials are not written to the database by these test endpoints. Administrator-only integration tests should be used over a trusted LAN/VPN.

### Useful endpoints

- `GET /api/v1/discovery/nmap?target=192.168.1.0/24`
- `GET /api/v1/discovery/neighbors`
- `GET /api/v1/diagnostics/gateway`
- `GET /api/v1/diagnostics/internet`
- `POST /api/v1/diagnostics/host`
- `POST /api/v1/monitor/website`
- `POST /api/v1/integrations/pihole/test`
- `POST /api/v1/integrations/unifi/test`
- `POST /api/v1/integrations/snmp/test`
- `POST /api/v1/tools/wol`
