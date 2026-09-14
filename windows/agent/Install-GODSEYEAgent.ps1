[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ServerUrl,
    [string]$EnrollmentToken = "",
    [switch]$SkipTlsVerify,
    [switch]$AllowHttp
)
$ErrorActionPreference='Stop'
if (-not [Environment]::Is64BitOperatingSystem) { throw 'GODSEYE Windows Agent requires 64-bit Windows.' }
if (-not $AllowHttp -and -not $ServerUrl.StartsWith('https://',[StringComparison]::OrdinalIgnoreCase)) {
    throw 'Use an HTTPS GODSEYE URL. For isolated lab testing only, explicitly add -AllowHttp.'
}
$base = Join-Path $env:ProgramData 'GODSEYE\Agent'
$bin = Join-Path $base 'GODSEYE.WindowsAgent.exe'
$src = Join-Path $PSScriptRoot 'src\GodseyeAgentService.cs'
$configPath = Join-Path $base 'agent.json'
$keyPath = Join-Path $base 'agent.key'
$svc='GODSEYEWindowsAgent'
New-Item -ItemType Directory -Path $base -Force | Out-Null

$existingService = Get-Service -Name $svc -ErrorAction SilentlyContinue
$existingEnrollment = (Test-Path $configPath) -and (Test-Path $keyPath)
if ($existingService) {
    Write-Host 'Stopping existing GODSEYE Windows Agent for upgrade...' -ForegroundColor Cyan
    Stop-Service $svc -Force -ErrorAction SilentlyContinue
    $existingService.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(20))
}

$csc = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path $csc)) { throw "64-bit .NET Framework C# compiler not found at $csc" }
Write-Host 'Compiling GODSEYE Windows Agent v1.1...' -ForegroundColor Cyan
& $csc /nologo /target:exe /optimize+ /out:$bin `
    /reference:System.ServiceProcess.dll `
    /reference:System.Web.Extensions.dll `
    /reference:System.Security.dll `
    $src
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $bin)) { throw 'Agent compilation failed.' }

if ($existingEnrollment) {
    $config = Get-Content $configPath -Raw | ConvertFrom-Json
    $config.ServerUrl = $ServerUrl.TrimEnd('/')
    $config.SkipTlsVerify = [bool]$SkipTlsVerify
    if (-not $config.PollIntervalSeconds) { $config | Add-Member -NotePropertyName PollIntervalSeconds -NotePropertyValue 60 -Force }
    if (-not $config.Channels) { $config | Add-Member -NotePropertyName Channels -NotePropertyValue @('System','Application') -Force }
    $config.EnrollmentToken = ''
    $config | ConvertTo-Json -Depth 6 | Set-Content -Path $configPath -Encoding UTF8
    Write-Host 'Existing enrollment and DPAPI-protected API key preserved.' -ForegroundColor Green
} else {
    if ([string]::IsNullOrWhiteSpace($EnrollmentToken)) {
        throw 'EnrollmentToken is required for a new installation. Existing enrolled agents can be upgraded without a new token.'
    }
    $config = [ordered]@{
        ServerUrl = $ServerUrl.TrimEnd('/')
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
    & sc.exe description $svc 'Read-only GODSEYE Windows Event Log agent. Sends selected Critical, Error, and Warning events outbound to GODSEYE.' | Out-Null
    & sc.exe failure $svc reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
}
Start-Service $svc
Start-Sleep -Seconds 3
$service=Get-Service $svc
Write-Host "GODSEYE Windows Agent installed/upgraded. Service status: $($service.Status)" -ForegroundColor Green
Write-Host "Agent data: $base"
if (-not $existingEnrollment) {
    Write-Host 'After successful enrollment, the one-time token is removed from agent.json; the long-term API key is protected with Windows DPAPI LocalMachine.'
}
Write-Host 'Agent v1.1 checks GODSEYE for Pull Events Now / recheck commands every 10 seconds while keeping the configured event collection interval.'
if ($SkipTlsVerify) { Write-Warning 'TLS certificate verification is disabled. Use only for temporary testing and enable proper HTTPS trust for production.' }
