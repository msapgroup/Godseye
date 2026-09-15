# GODSEYE Scan Now and Add Device

## Discover Network
The **Scan Now** / **Discover Network** action queues a scan in SQLite. The privileged `godseye-scanner` service polls the queue every second between scheduled scans, runs `arp-scan --localnet`, updates the shared database, and marks the request complete.

The dashboard polls `/api/v1/scan/status` and reports completion, device count, or the scanner error.

## Add Device
**Add Device** opens a real form. It sends `POST /api/v1/devices` and validates the MAC address. Duplicate MAC addresses are rejected.

## Troubleshooting
```bash
sudo systemctl status godseye-scanner --no-pager
sudo journalctl -u godseye-scanner -n 100 --no-pager
sudo bash install.sh --doctor
```
