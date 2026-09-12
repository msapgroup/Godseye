# GODSEYE 1.5.0 — Dashboard Visualization & Appliance Hardening

- Live Raspberry Pi interface traffic sampling and dashboard RX/TX graph.
- Client activity visualization with explicit evidence labeling when true per-client byte counters are unavailable.
- PDF and CSV export for generated reports.
- Prometheus `/metrics` protected by authenticated browser session or rotatable API key.
- Fernet encryption at rest for Pi-hole, UniFi, SNMP and SMTP credentials, including migration of legacy plaintext values.
- Online SQLite backup, inventory, integrity checking, and restore with automatic pre-restore safety backup.
- Configurable retention policies with automatic hourly pruning.
- Raspberry Pi health page covering load, temperature, RAM, storage, DB integrity, systemd services and active network interface.
- The metrics API key is shown once on generation; only its SHA-256 digest is stored.
