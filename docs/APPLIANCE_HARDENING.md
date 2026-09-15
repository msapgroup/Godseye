# Appliance Hardening

GODSEYE 1.5 introduces encrypted local credentials, authenticated Prometheus metrics, SQLite online backup/restore, retention management and Raspberry Pi self diagnostics.

## Secret key
The appliance creates `/var/lib/godseye/secret.key` with mode `0600`. Integration and SMTP secrets are stored as Fernet ciphertext prefixed `enc:v1:`. GODSEYE copies this key beside each local database backup as a mode-0600 sidecar so encrypted credentials remain portable to replacement hardware. Protect the backup directory because the key sidecar can decrypt credentials in its paired database.

## Prometheus
Generate or rotate a key from **System Health**. Prometheus can send `Authorization: Bearer <key>` or `X-API-Key: <key>`. The key is shown once and only a SHA-256 digest is stored. A valid GODSEYE browser session may also access `/metrics`.

## Backups and restore
Backups are online SQLite backups written below `/var/lib/godseye/backups`. Each backup is integrity checked. Restore accepts only an existing GODSEYE backup filename and creates a safety backup immediately before replacing the live DB. Restarting GODSEYE services after a restore is recommended.

## Retention
Traffic, event, audit, report, integration-sync and notification history have independently configurable day limits. Policies are applied on save and automatically by the background manager at most once per hour.

## Traffic data
The web service samples Linux `/proc/net/dev` for the default route interface. These are appliance-interface counters. Per-client activity is shown separately and is clearly labeled; GODSEYE does not invent per-client bandwidth when a controller has not supplied byte counters.
