# Run in PowerShell as the Windows user who will approve Remote Access.
# This starts the original Agent 2.4.5 tray and restores its startup at sign-in.
$agent = Join-Path $env:ProgramFiles 'GODSEYE Agent\GODSEYE.Agent.exe'
if (-not (Test-Path $agent)) { throw "GODSEYE Agent is not installed at $agent." }
$version = (Get-Item $agent).VersionInfo.FileVersion
if ($version -notlike '2.4.5*') {
    throw "Installed agent is $version. This repair is for the verified 2.4.5 agent; it does not replace the executable."
}
if (-not (Get-Service GODSEYEWindowsAgent -ErrorAction SilentlyContinue)) {
    throw 'The GODSEYE Windows Agent service is not installed.'
}
$runPath = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$command = '"' + $agent + '" --tray'
New-ItemProperty -Path $runPath -Name 'GODSEYE Windows Agent Tray' -PropertyType String -Value $command -Force | Out-Null
Start-Process -FilePath $agent -ArgumentList '--tray'
Write-Host "Started the Agent $version tray and registered sign-in startup for $env:USERNAME. Check the notification area's hidden icons."
