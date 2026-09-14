# GODSEYE v3.8 — Per-Device Traffic Collector & Reporting Infrastructure

GODSEYE now has a normalized per-device traffic data plane and explicit collection-mode selection.

Modes:
- UniFi / Controller: automatic client-counter ingestion when the controller exposes recognized cumulative byte counters.
- SNMP: per-device counter ingestion through explicit OID mappings; GODSEYE does not assume a universal client-byte MIB.
- SPAN / Mirror: normalized sensor ingestion path and source configuration for a privileged mirror-port sensor.
- Inline / Gateway: normalized sensor ingestion path and source configuration for traffic that actually traverses the Raspberry Pi.

The web service remains unprivileged. SPAN/inline raw-packet capture is intentionally separated from the web process; this release establishes the database, API, source selection, status model, retention, reporting and sensor-ingestion contract before enabling privileged packet capture.

Traffic Usage reports now use only normalized per-device measurements. They never relabel appliance-interface totals as client usage.

A protected `/api/v1/traffic/ingest` contract accepts normalized cumulative or interval-delta samples. In v3.8 it is admin-authenticated; a dedicated least-privilege local sensor credential can be added when the privileged sensor service is enabled.
