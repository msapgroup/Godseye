# GODSEYE scan troubleshooting

The web UI and privileged scanner must share the same database and scan trigger directory.

Database:
`/var/lib/godseye/godseye.db`

Manual scan flag:
`/var/lib/godseye/scan-now`

Check the scanner:
```bash
sudo systemctl status godseye-scanner --no-pager
sudo journalctl -u godseye-scanner -n 100 --no-pager
```

Check tools:
```bash
sudo command -v arp-scan
sudo ip -4 route
sudo arp-scan --localnet --retry=2
```

A manual scan is requested by the web service and then executed by the privileged scanner service.
