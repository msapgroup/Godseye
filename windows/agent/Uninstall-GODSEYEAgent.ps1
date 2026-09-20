[CmdletBinding()]
param([switch]$RemoveData)
$ErrorActionPreference='Stop'
$svc='GODSEYEWindowsAgent'
if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
    Stop-Service $svc -Force -ErrorAction SilentlyContinue
    & sc.exe delete $svc | Out-Null
    Write-Host 'GODSEYE Windows Agent service removed.' -ForegroundColor Green
}
if ($RemoveData) {
    $base=Join-Path $env:ProgramData 'GODSEYE\Agent'
    if (Test-Path $base) { Remove-Item $base -Recurse -Force }
    Write-Host 'Agent configuration, state, queue, and logs removed.' -ForegroundColor Yellow
}
