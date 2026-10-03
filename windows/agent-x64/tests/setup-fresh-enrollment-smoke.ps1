param([Parameter(Mandatory=$true)][string]$SetupPath)
$ErrorActionPreference='Stop'
$folder=Join-Path $env:ProgramData 'GODSEYE\Agent'
$exe=Join-Path $env:ProgramFiles 'GODSEYE Agent\GODSEYE.Agent.exe'
$setup=(Resolve-Path $SetupPath).Path
$state=Join-Path $env:RUNNER_TEMP 'fresh-enrollment-state.json'
# Prior tests can leave an installed executable behind and mask an early tray
# launch. This case must begin with no installed service executable at all.
Stop-Service GODSEYEWindowsAgent -ErrorAction Ignore
& taskkill.exe /IM GODSEYE.Agent.exe /T /F 2>$null | Out-Null
$msi=(Resolve-Path 'windows/agent-x64/GODSEYE-Windows-Agent-x64.msi').Path
$remove=Start-Process msiexec.exe -ArgumentList @('/x',"`"$msi`"",'/qn','/norestart') -Wait -PassThru
if ($remove.ExitCode -notin @(0,3010,1605)) { throw "Could not prepare a genuinely fresh install: $($remove.ExitCode)" }
if (Test-Path $exe) { throw 'Fresh Setup regression requires the installed executable to be absent.' }
Write-Host 'Fresh-install precondition verified: installed executable is absent.'

foreach ($name in @('agent.json','agent.json.bak','agent.key')) { Remove-Item (Join-Path $folder $name) -ErrorAction Ignore }
Remove-Item $state -ErrorAction Ignore
$server=Start-Process python -ArgumentList @('windows/agent-x64/tests/enrollment-fixture.py',"`"$state`"") -PassThru
function Run-Setup {
  $log=Join-Path $env:RUNNER_TEMP 'godseye-setup-fresh.log'
  $p=Start-Process $setup -ArgumentList "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SERVERURL=http://127.0.0.1:8087 /ALLOWHTTP=1 /TOKEN=CI-ENROLLMENT /CHECKTRAY=1 /LOG=`"$log`"" -PassThru
  if (-not $p.WaitForExit(180000)) {
    Get-Content $log -Tail 100 -ErrorAction Continue | Write-Host
    Get-Content (Join-Path $folder 'agent.log') -Tail 40 -ErrorAction Continue | Write-Host
    & taskkill.exe /PID $p.Id /T /F | Out-Null
    throw 'Fresh guided Setup timed out.'
  }
  if ($p.ExitCode -notin @(0,3010)) { Get-Content (Join-Path $folder 'setup-msi.log') -Tail 60; throw "Guided Setup failed: $($p.ExitCode)" }
  if (-not (Test-Path $exe)) { throw 'Setup did not retain the executable at the tray launch path.' }
  if ((Get-Service GODSEYEWindowsAgent).Status -ne 'Running') { throw 'Service is not running.' }
  $tray=Start-Process $exe -ArgumentList '--check-tray' -Wait -PassThru
  if ($tray.ExitCode -ne 0) { throw 'Tray readiness handshake failed in the installing session.' }
}
try {
  Start-Sleep -Seconds 1
  Run-Setup
  for ($i=0;$i -lt 45;$i++) {
    if ((Test-Path $state) -and (Test-Path (Join-Path $folder 'agent.key'))) {
      $result=Get-Content $state -Raw | ConvertFrom-Json
      if ($result.heartbeats -gt 0) { break }
    }
    Start-Sleep -Seconds 1
  }
  if ($result.enrollments -ne 1 -or $result.heartbeats -lt 1 -or $result.version -ne '2.4.5') { throw 'Fresh Setup did not complete authenticated enrollment and a current-version heartbeat.' }
  $cfg=Get-Content (Join-Path $folder 'agent.json') -Raw | ConvertFrom-Json
  if ($cfg.EnrollmentToken -or $cfg.SkipTlsVerify) { throw 'Enrollment token was not cleared, or certificate checks were disabled by default.' }
  $uuid=$cfg.AgentUuid
  $hash=(Get-FileHash (Join-Path $folder 'agent.key')).Hash
  Run-Setup
  $after=Get-Content (Join-Path $folder 'agent.json') -Raw | ConvertFrom-Json
  if ($after.AgentUuid -ne $uuid -or (Get-FileHash (Join-Path $folder 'agent.key')).Hash -ne $hash) { throw 'Enrolled repair changed identity or key.' }
  $result=Get-Content $state -Raw | ConvertFrom-Json
  if ($result.enrollments -ne 1) { throw 'Existing enrollment was repeated instead of preserved.' }
  Write-Host 'Fresh Setup configuration, enrollment, heartbeat, final tray launch/readiness, and enrolled repair passed.'
} finally {
  Stop-Service GODSEYEWindowsAgent -ErrorAction Ignore
  & taskkill.exe /IM GODSEYE.Agent.exe /T /F 2>$null | Out-Null
  $msi=(Resolve-Path 'windows/agent-x64/GODSEYE-Windows-Agent-x64.msi').Path
  Start-Process msiexec.exe -ArgumentList @('/x',"`"$msi`"",'/qn','/norestart') -Wait | Out-Null
  Stop-Process $server.Id -ErrorAction Ignore
  foreach ($name in @('agent.json','agent.json.bak','agent.key')) { Remove-Item (Join-Path $folder $name) -ErrorAction Ignore }
}
