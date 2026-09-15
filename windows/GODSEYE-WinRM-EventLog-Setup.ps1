# GODSEYE Windows Event Log WinRM HTTPS preparation helper
# Run in an elevated 64-bit PowerShell session on the Windows computer/server.
# This script does NOT disable certificate validation, enable TrustedHosts, or open WinRM to the Internet.

[CmdletBinding(SupportsShouldProcess=$true)]
param(
    [Parameter(Mandatory=$true)]
    [string]$ReaderUser,

    [string]$CertificateThumbprint = "",

    [switch]$CreateHttpsListener,

    [int]$Port = 5986
)

$ErrorActionPreference = "Stop"

Write-Host "GODSEYE Windows Event Log preparation" -ForegroundColor Cyan
Write-Host "Reader account: $ReaderUser"

# Ensure the existing account can read Windows Event Logs.
$group = [ADSI]"WinNT://./Event Log Readers,group"
try {
    $group.Add("WinNT://$ReaderUser")
    Write-Host "Added $ReaderUser to Event Log Readers." -ForegroundColor Green
} catch {
    if ($_.Exception.Message -match "already a member") {
        Write-Host "$ReaderUser is already in Event Log Readers." -ForegroundColor Yellow
    } else {
        Write-Warning "Could not add the account automatically: $($_.Exception.Message)"
        Write-Host "Add the account manually to the local 'Event Log Readers' group if needed."
    }
}

Set-Service -Name WinRM -StartupType Automatic
Start-Service -Name WinRM

if ($CreateHttpsListener) {
    if (-not $CertificateThumbprint) {
        throw "-CertificateThumbprint is required with -CreateHttpsListener."
    }
    $cert = Get-Item "Cert:\LocalMachine\My\$CertificateThumbprint" -ErrorAction Stop
    if ($cert.NotAfter -lt (Get-Date)) {
        throw "The supplied certificate is expired."
    }

    $existing = Get-ChildItem WSMan:\localhost\Listener | Where-Object {
        (Get-Item "$($_.PSPath)\Transport").Value -eq "HTTPS"
    }
    if (-not $existing) {
        $hostname = [System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName
        New-WSManInstance -ResourceURI winrm/config/Listener `
            -SelectorSet @{Address="*";Transport="HTTPS"} `
            -ValueSet @{Hostname=$hostname;CertificateThumbprint=$CertificateThumbprint;Port="$Port"}
        Write-Host "Created WinRM HTTPS listener on port $Port." -ForegroundColor Green
    } else {
        Write-Host "An HTTPS WinRM listener already exists; leaving it unchanged." -ForegroundColor Yellow
    }
}

$ruleName = "GODSEYE WinRM HTTPS $Port"
if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow -Protocol TCP -LocalPort $Port -Profile Domain,Private
    Write-Host "Created Domain/Private firewall rule for TCP $Port." -ForegroundColor Green
} else {
    Write-Host "Firewall rule already exists." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Validation:" -ForegroundColor Cyan
winrm enumerate winrm/config/listener
Write-Host ""
Write-Host "GODSEYE should connect using WinRM HTTPS, NTLM, and TLS certificate verification."
Write-Host "Do not expose TCP $Port directly to the public Internet."
