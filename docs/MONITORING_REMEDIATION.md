# Monitoring + Findings Remediation

## Monitor lifecycle

From **Monitoring**, administrators can add, edit, delete, run one monitor, or run all enabled monitors. Supported monitor types remain Website/HTTP, DHCP leases, Public IP, Pi-hole, UniFi, and SNMP.

Each check records status, response time, details, and the monitor ID in SQLite. Two consecutive service failures create a `service_failure` finding. A later healthy check automatically resolves that health finding.

## Automatic findings

GODSEYE creates explainable findings for:

- device offline transitions from the scanner;
- device IP changes;
- two consecutive reachability failures;
- two consecutive packet-loss results of 10% or greater;
- two consecutive DNS failures when a hostname is available;
- two consecutive service-monitor failures.

Transient single failures do not immediately create packet-loss, DNS, or service-failure findings.

## Remediation actions

**Suggested Fix** returns an ordered operator checklist based on the finding type.

**Recheck** repeats a safe diagnostic or monitor check and records the result.

**Resolve** marks the finding resolved and writes the action to the audit log.

GODSEYE does not automatically make destructive network configuration changes.
