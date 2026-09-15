[CmdletBinding()]
param(
    [string]$ServerUrl = "",
    [string]$EnrollmentToken = "",
    [switch]$SkipTlsVerify,
    [switch]$AllowHttp
)

$ErrorActionPreference='Stop'

function Assert-Administrator {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    $p=New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run PowerShell as Administrator, then run the GODSEYE agent installer again.'
    }
}

function Wait-ServiceStopped([string]$Name,[int]$TimeoutSeconds=30) {
    $deadline=(Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $svc=Get-Service -Name $Name -ErrorAction SilentlyContinue
        if (-not $svc -or $svc.Status -eq 'Stopped') {
            $wmi=Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
            if (-not $wmi -or [int]$wmi.ProcessId -eq 0) { return }
        }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    throw "Timed out waiting for service '$Name' to stop. Reboot the Windows host or stop the service manually, then retry."
}

function Replace-AgentBinary([string]$Staged,[string]$Target,[string]$Backup) {
    if (Test-Path $Backup) { Remove-Item $Backup -Force -ErrorAction SilentlyContinue }
    if (Test-Path $Target) { Copy-Item $Target $Backup -Force }
    $last=$null
    for($i=0;$i -lt 20;$i++) {
        try {
            Copy-Item $Staged $Target -Force
            Remove-Item $Staged -Force -ErrorAction SilentlyContinue
            return
        } catch {
            $last=$_
            Start-Sleep -Milliseconds 500
        }
    }
    if ((Test-Path $Backup) -and -not (Test-Path $Target)) {
        Copy-Item $Backup $Target -Force -ErrorAction SilentlyContinue
    }
    throw "Could not replace the existing agent executable after stopping the service. $($last.Exception.Message)"
}

Assert-Administrator

if (-not [Environment]::Is64BitOperatingSystem) {
    throw 'GODSEYE Windows Agent requires 64-bit Windows.'
}

$base = Join-Path $env:ProgramData 'GODSEYE\Agent'
$bin = Join-Path $base 'GODSEYE.WindowsAgent.exe'
$stagedBin = Join-Path $base 'GODSEYE.WindowsAgent.exe.new'
$backupBin = Join-Path $base 'GODSEYE.WindowsAgent.exe.bak'
$src = Join-Path $PSScriptRoot 'src\GodseyeAgentService.cs'
$configPath = Join-Path $base 'agent.json'
$keyPath = Join-Path $base 'agent.key'
$svc='GODSEYEWindowsAgent'

New-Item -ItemType Directory -Path $base -Force | Out-Null

$existingService = Get-Service -Name $svc -ErrorAction SilentlyContinue
$existingConfig = $null
if (Test-Path $configPath) {
    try { $existingConfig = Get-Content $configPath -Raw | ConvertFrom-Json } catch {
        throw "Existing agent configuration is unreadable: $configPath. $($_.Exception.Message)"
    }
}
$existingEnrollment = ($null -ne $existingConfig) -and (Test-Path $keyPath)

if ($existingEnrollment) {
    if ([string]::IsNullOrWhiteSpace($ServerUrl)) {
        $ServerUrl = [string]$existingConfig.ServerUrl
    }
    if ([string]::IsNullOrWhiteSpace($ServerUrl)) {
        throw 'Existing agent configuration does not contain ServerUrl. Supply -ServerUrl during upgrade.'
    }
} else {
    if ([string]::IsNullOrWhiteSpace($ServerUrl)) {
        throw 'ServerUrl is required for a new installation.'
    }
    if ([string]::IsNullOrWhiteSpace($EnrollmentToken)) {
        throw 'EnrollmentToken is required for a new installation. Existing enrolled agents can be upgraded without a new token.'
    }
}

$ServerUrl=$ServerUrl.TrimEnd('/')
if (-not $AllowHttp -and -not $ServerUrl.StartsWith('https://',[StringComparison]::OrdinalIgnoreCase)) {
    throw 'Use an HTTPS GODSEYE URL. For isolated lab testing only, explicitly add -AllowHttp.'
}

if ($existingService) {
    Write-Host 'Stopping existing GODSEYE Windows Agent for upgrade...' -ForegroundColor Cyan
    Stop-Service $svc -Force -ErrorAction Stop
    Wait-ServiceStopped $svc 30
}

$csc = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path $csc)) {
    throw "64-bit .NET Framework C# compiler not found at $csc"
}
if (-not (Test-Path $src)) {
    throw "Agent source file is missing: $src"
}

Write-Host 'Compiling GODSEYE Windows Agent v1.1.1 to a staging file...' -ForegroundColor Cyan
if (Test-Path $stagedBin) { Remove-Item $stagedBin -Force }
& $csc /nologo /target:exe /optimize+ /out:$stagedBin `
    /reference:System.ServiceProcess.dll `
    /reference:System.Web.Extensions.dll `
    /reference:System.Security.dll `
    $src

if ($LASTEXITCODE -ne 0 -or -not (Test-Path $stagedBin)) {
    if ($existingService) { Start-Service $svc -ErrorAction SilentlyContinue }
    throw 'Agent compilation failed. The previous agent executable was left unchanged.'
}

Replace-AgentBinary $stagedBin $bin $backupBin

if ($existingEnrollment) {
    $config = $existingConfig
    $config.ServerUrl = $ServerUrl

    # Preserve the existing TLS setting unless the caller explicitly supplied
    # -SkipTlsVerify. This prevents an upgrade from silently changing trust mode.
    if ($PSBoundParameters.ContainsKey('SkipTlsVerify')) {
        $config.SkipTlsVerify = [bool]$SkipTlsVerify
    }

    if (-not $config.PollIntervalSeconds) {
        $config | Add-Member -NotePropertyName PollIntervalSeconds -NotePropertyValue 60 -Force
    }
    if (-not $config.Channels) {
        $config | Add-Member -NotePropertyName Channels -NotePropertyValue @('System','Application') -Force
    }
    $config.EnrollmentToken = ''
    $config | ConvertTo-Json -Depth 6 | Set-Content -Path $configPath -Encoding UTF8
    Write-Host 'Existing enrollment, agent UUID, config, and DPAPI-protected API key preserved.' -ForegroundColor Green
} else {
    $config = [ordered]@{
        ServerUrl = $ServerUrl
        EnrollmentToken = $EnrollmentToken
        AgentUuid = [guid]::NewGuid().ToString()
        SkipTlsVerify = [bool]$SkipTlsVerify
        PollIntervalSeconds = 60
        Channels = @('System','Application')
    }
    $config | ConvertTo-Json -Depth 4 | Set-Content -Path $configPath -Encoding UTF8
}

& icacls $base /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null

if (-not $existingService) {
    & sc.exe create $svc binPath= ('"' + $bin + '"') start= auto DisplayName= 'GODSEYE Windows Agent' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Could not create Windows service '$svc'." }
    & sc.exe description $svc 'Read-only GODSEYE Windows Event Log agent. Sends selected Critical, Error, and Warning events outbound to GODSEYE.' | Out-Null
    & sc.exe failure $svc reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
}

try {
    Start-Service $svc -ErrorAction Stop
    Start-Sleep -Seconds 3
    $service=Get-Service $svc
    if ($service.Status -ne 'Running') {
        throw "Service status is $($service.Status)"
    }
} catch {
    Write-Warning "The upgraded executable was installed, but the service did not start: $($_.Exception.Message)"
    if (Test-Path (Join-Path $base 'agent.log')) {
        Write-Host 'Recent agent log:' -ForegroundColor Yellow
        Get-Content (Join-Path $base 'agent.log') -Tail 30
    }
    throw
}

Write-Host "GODSEYE Windows Agent installed/upgraded successfully. Service status: $($service.Status)" -ForegroundColor Green
Write-Host "Agent data: $base"

if ($existingEnrollment) {
    Write-Host 'Upgrade mode: existing enrollment retained. No new enrollment token was required.' -ForegroundColor Green
} else {
    Write-Host 'After successful enrollment, the one-time token is removed from agent.json; the long-term API key is protected with Windows DPAPI LocalMachine.'
}

Write-Host 'Agent v1.1.1 checks GODSEYE for Pull Events Now / recheck commands every 10 seconds.'
if ($PSBoundParameters.ContainsKey('SkipTlsVerify') -and $SkipTlsVerify) {
    Write-Warning 'TLS certificate verification is disabled. Use only for temporary testing and enable proper HTTPS trust for production.'
}
