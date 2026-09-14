[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$ServerUrl,
    [Parameter(Mandatory=$true)][string]$EnrollmentToken,
    [switch]$SkipTlsVerify,
    [switch]$AllowHttp
)
$ErrorActionPreference='Stop'
if (-not [Environment]::Is64BitOperatingSystem) { throw 'GODSEYE Windows Agent v1 requires 64-bit Windows.' }
if (-not $AllowHttp -and -not $ServerUrl.StartsWith('https://',[StringComparison]::OrdinalIgnoreCase)) {
    throw 'Use an HTTPS GODSEYE URL. For isolated lab testing only, explicitly add -AllowHttp.'
}
$base = Join-Path $env:ProgramData 'GODSEYE\Agent'
$bin = Join-Path $base 'GODSEYE.WindowsAgent.exe'
$src = Join-Path $PSScriptRoot 'src\GodseyeAgentService.cs'
New-Item -ItemType Directory -Path $base -Force | Out-Null
$csc = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if (-not (Test-Path $csc)) { throw "64-bit .NET Framework C# compiler not found at $csc" }
Write-Host 'Compiling GODSEYE Windows Agent...' -ForegroundColor Cyan
& $csc /nologo /target:exe /optimize+ /out:$bin `
    /reference:System.ServiceProcess.dll `
    /reference:System.Web.Extensions.dll `
    /reference:System.Security.dll `
    $src
if ($LASTEXITCODE -ne 0 -or -not (Test-Path $bin)) { throw 'Agent compilation failed.' }
$config = [ordered]@{
    ServerUrl = $ServerUrl.TrimEnd('/')
    EnrollmentToken = $EnrollmentToken
    AgentUuid = [guid]::NewGuid().ToString()
    SkipTlsVerify = [bool]$SkipTlsVerify
    PollIntervalSeconds = 60
    Channels = @('System','Application')
}
$config | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $base 'agent.json') -Encoding UTF8
# Lock configuration and DPAPI key directory to SYSTEM and local Administrators.
& icacls $base /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
$svc='GODSEYEWindowsAgent'
if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
    Stop-Service $svc -Force -ErrorAction SilentlyContinue
    & sc.exe delete $svc | Out-Null
    Start-Sleep -Seconds 2
}
& sc.exe create $svc binPath= ('"' + $bin + '"') start= auto DisplayName= 'GODSEYE Windows Agent' | Out-Null
& sc.exe description $svc 'Read-only GODSEYE Windows Event Log agent. Sends selected Critical, Error, and Warning events outbound to GODSEYE.' | Out-Null
& sc.exe failure $svc reset= 86400 actions= restart/5000/restart/15000/restart/60000 | Out-Null
Start-Service $svc
Start-Sleep -Seconds 3
$service=Get-Service $svc
Write-Host "GODSEYE Windows Agent installed. Service status: $($service.Status)" -ForegroundColor Green
Write-Host "Agent data: $base"
Write-Host 'The enrollment token is removed from agent.json after successful enrollment; the long-term agent API key is protected with Windows DPAPI LocalMachine.'
if ($SkipTlsVerify) { Write-Warning 'TLS certificate verification is disabled. Use only for temporary testing and enable proper HTTPS trust for production.' }
