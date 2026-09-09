# Persistent Intelligence

GODSEYE now has a SQLite-backed intelligence store for devices, observations, findings, and topology links.

Collectors submit observations through `IntelligenceService.ingest(source, observations)`.
MAC addresses are the preferred stable identity; IPs and hostnames are retained as observations/history.
