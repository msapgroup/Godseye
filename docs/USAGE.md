# GODSEYE usage

## Install

Extract the release ZIP and run:

```bash
sudo bash ./install.sh --fresh
```

For an existing installation:

```bash
sudo bash ./install.sh --upgrade
```

Then open `http://<raspberry-pi-address>:8080/` unless HTTPS/reverse-proxy settings use a different URL.

Use the sidebar for Dashboard, Devices, Network Map, Monitoring, Findings, Network Tools, Integrations, Management features, Remote Access, Windows Event Findings, Ticket Portal, reports, users, security, and audit history.

For Windows event collection, prefer the permanent x64 Windows Agent documented in `WINDOWS_AGENT.md`.
