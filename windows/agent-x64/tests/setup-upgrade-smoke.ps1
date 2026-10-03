param([Parameter(Mandatory=$true)][string]$SetupPath)
$ErrorActionPreference='Stop'
$setup=(Resolve-Path $SetupPath).Path
$folder=Join-Path $env:ProgramData 'GODSEYE\Agent'
$exe=Join-Path $env:ProgramFiles 'GODSEYE Agent\GODSEYE.Agent.exe'
New-Item -ItemType Directory $folder -Force | Out-Null
Add-Type -AssemblyName System.Security
$key=[Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes('CI-NONSECRET-KEY'),$null,[Security.Cryptography.DataProtectionScope]::LocalMachine)
[IO.File]::WriteAllBytes((Join-Path $folder 'agent.key'),$key)
$config='{"ServerUrl":"http://127.0.0.1:9","AgentUuid":"upgrade-preserved-uuid","EnrollmentToken":"","Channels":["System"],"PollIntervalSeconds":60}'
[IO.File]::WriteAllText((Join-Path $folder 'agent.json'),$config)
[IO.File]::WriteAllText((Join-Path $folder 'agent.json.bak'),$config)
[IO.File]::WriteAllText((Join-Path $folder 'upgrade-state.sentinel'),'preserve-this-state')
$keyHash=(Get-FileHash (Join-Path $folder 'agent.key')).Hash
function Run-Setup {
  $p=Start-Process $setup -ArgumentList '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART' -PassThru
  if (-not $p.WaitForExit(180000)) { Stop-Process $p.Id -Force; throw 'Guided Setup upgrade timed out.' }
  if ($p.ExitCode -notin @(0,3010)) { Get-Content (Join-Path $folder 'setup-msi.log') -Tail 100; throw "Guided Setup failed: $($p.ExitCode)" }
  if ((Get-Item $exe).VersionInfo.FileVersion -notlike '2.4.5*') { throw 'Installed executable version is incorrect.' }
  $cfg=Get-Content (Join-Path $folder 'agent.json') -Raw | ConvertFrom-Json
  if ($cfg.AgentUuid -ne 'upgrade-preserved-uuid' -or $cfg.ServerUrl -ne 'http://127.0.0.1:9') { throw 'Upgrade changed enrollment settings.' }
  if ((Get-FileHash (Join-Path $folder 'agent.key')).Hash -ne $keyHash) { throw 'Upgrade changed the protected enrollment key.' }
  if (-not (Test-Path (Join-Path $folder 'upgrade-state.sentinel'))) { throw 'Upgrade removed persistent state.' }
  if ((Get-Service GODSEYEWindowsAgent).Status -ne 'Running') { throw 'Upgrade did not restart the service.' }
  $versions=@(Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction Ignore | Where-Object DisplayName -eq 'GODSEYE Windows Agent' | Select-Object -ExpandProperty DisplayVersion)
  if ($versions.Count -ne 1 -or $versions[0] -ne '2.4.5') { throw "Installed app versions disagree: $versions" }
}
# Build an isolated related-product fixture at 2.5.1 to test the MSI downgrade
# migration. This is a CI fixture, never a published agent or release asset.
$wxs='windows/agent-x64/installer/msi/Package.wxs'
$original=[IO.File]::ReadAllText($wxs)
try {
  [IO.File]::WriteAllText($wxs,$original.Replace('Version="2.4.5"','Version="2.5.1"'))
  dotnet build 'windows/agent-x64/installer/msi/GODSEYE.Agent.Installer.wixproj' -c Release -p:InstallerPlatform=x64
  if ($LASTEXITCODE -ne 0) { throw 'Could not build related-product upgrade fixture.' }
  $fixture=Get-ChildItem 'windows/agent-x64/installer/msi/bin' -Filter 'GODSEYE-Windows-Agent-x64.msi' -Recurse | Select-Object -First 1
  $p=Start-Process msiexec.exe -ArgumentList @('/i',"`"$($fixture.FullName)`"",'/qn','/norestart') -Wait -PassThru
  if ($p.ExitCode -notin @(0,3010)) { throw 'Related-product fixture install failed.' }
  Run-Setup
  Run-Setup # Running the exact same Setup again must repair successfully too.
  Write-Host 'Guided Setup replaced related 2.5.1 and repaired 2.4.5; settings, key, state, registry, and running service verified.'
} finally {
  [IO.File]::WriteAllText($wxs,$original)
  Stop-Service GODSEYEWindowsAgent -ErrorAction Ignore
  & taskkill.exe /IM GODSEYE.Agent.exe /T /F 2>$null | Out-Null
  $msi=(Resolve-Path 'windows/agent-x64/GODSEYE-Windows-Agent-x64.msi').Path
  Start-Process msiexec.exe -ArgumentList @('/x',"`"$msi`"",'/qn','/norestart') -Wait | Out-Null
  foreach ($name in @('agent.key','agent.json','agent.json.bak','upgrade-state.sentinel')) { Remove-Item (Join-Path $folder $name) -ErrorAction Ignore }
}
