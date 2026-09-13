# Windows Event Findings

GODSEYE can pull selected Windows Event Log entries from 64-bit Windows workstations and Windows Server through **WinRM over HTTPS**.

## What GODSEYE pulls

The collector requests only Windows event levels:

- Critical (`Level=1`)
- Error (`Level=2`)
- Warning (`Level=3`)

Each configured channel has its own Event Record ID bookmark. After the first poll, later polls request only records newer than the saved bookmark. The default channels are `System` and `Application`; additional channels can be configured per host.

GODSEYE classifies useful Windows events into Event Findings such as Storage, Hardware/WHEA, Power/Shutdown, Service, Windows Update, Defender/Security, Backup/VSS, and Application failures.

## Recommended Windows configuration

Use a dedicated Windows account for GODSEYE and grant it only the permissions needed to read the required event logs. Add that account to the local **Event Log Readers** group. Configure WinRM HTTPS with a certificate trusted by the Raspberry Pi running GODSEYE.

The included helper is:

`windows/GODSEYE-WinRM-EventLog-Setup.ps1`

Run it in an elevated 64-bit PowerShell session. It does not disable certificate validation, change TrustedHosts, or intentionally expose WinRM to public networks.

## Security guidance

- Prefer WinRM HTTPS on TCP 5986.
- Keep **Verify TLS certificate** enabled in GODSEYE.
- Restrict the Windows firewall rule to trusted management networks where practical.
- Use a dedicated least-privilege account instead of an administrator account.
- Do not expose WinRM directly to the Internet.
- GODSEYE encrypts stored WinRM passwords at rest using the appliance secret key.

## Workflow

Windows source → filtered Event Log pull → Event Finding → Suggested Fix / Recheck → Create Ticket → Schedule on Calendar → Work Notes → Resolve / Close.

Repeated events update the same Event Finding and increase its occurrence count instead of creating an endless stream of duplicate findings. If a resolved condition occurs again, GODSEYE reopens the finding.

## Recheck behavior

Recheck performs a fresh pull from the source associated with the finding. GODSEYE reports whether another matching event occurred. It does not automatically claim a hardware problem is repaired merely because no event appeared during one poll; the operator chooses when to resolve the finding.
