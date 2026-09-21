[CmdletBinding()]
param(
  [switch]$SkipInstallSmoke
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if (-not $IsWindows) { throw 'GODSEYE Windows Agent packages must be built on Windows x64.' }

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Resolve-Path (Join-Path $Root '..\..')
$Project = Join-Path $Root 'src\Godseye.WindowsAgent\Godseye.WindowsAgent.csproj'
$Publish = Join-Path $Root 'publish'
$MsiProject = Join-Path $Root 'installer\msi\GODSEYE.Agent.Installer.wixproj'
$MsiOut = Join-Path $Root 'GODSEYE-Windows-Agent-x64.msi'
$SetupOut = Join-Path $Root 'GODSEYE-Windows-Agent-x64-Setup.exe'
$Manifest = Join-Path $Root 'update-manifest.json'
$AgentOut = Join-Path $Root 'GODSEYE.Agent.exe'

function Require-Command([string]$Name) {
  $cmd = Get-Command $Name -ErrorAction SilentlyContinue
  if (-not $cmd) { throw "Required build command '$Name' was not found." }
  return $cmd
}

$dotnet = Require-Command 'dotnet'
$dotnetInfo = & $dotnet --version
if ($LASTEXITCODE -ne 0 -or $dotnetInfo -notmatch '^8\.') {
  throw "GODSEYE Agent 2.4.3 requires the .NET 8 SDK. Found: $dotnetInfo"
}

[xml]$projectXml = Get-Content $Project
$AgentVersion = [string]$projectXml.Project.PropertyGroup.Version
if ($AgentVersion -ne '2.4.3') { throw "Expected Agent 2.4.3, found '$AgentVersion'." }

Write-Host "Publishing GODSEYE Agent $AgentVersion (win-x64)..." -ForegroundColor Cyan
Remove-Item $Publish -Recurse -Force -ErrorAction SilentlyContinue
& $dotnet publish $Project -c Release -r win-x64 --self-contained true -o $Publish
if ($LASTEXITCODE -ne 0) { throw 'dotnet publish failed.' }
$PublishedAgent = Join-Path $Publish 'GODSEYE.Agent.exe'
if (-not (Test-Path $PublishedAgent)) { throw 'GODSEYE.Agent.exe was not produced.' }
$fileVersion = (Get-Item $PublishedAgent).VersionInfo.FileVersion
if ($fileVersion -notlike '2.4.3*') { throw "Unexpected Agent file version: $fileVersion" }
Copy-Item $PublishedAgent $AgentOut -Force

Write-Host 'Building native WiX MSI...' -ForegroundColor Cyan
& $dotnet build $MsiProject -c Release -p:InstallerPlatform=x64
if ($LASTEXITCODE -ne 0) { throw 'WiX MSI build failed.' }
$BuiltMsi = Get-ChildItem (Join-Path $Root 'installer\msi\bin') -Filter 'GODSEYE-Windows-Agent-x64.msi' -Recurse | Select-Object -First 1
if (-not $BuiltMsi) { throw 'WiX did not create GODSEYE-Windows-Agent-x64.msi.' }
Copy-Item $BuiltMsi.FullName $MsiOut -Force
$MsiHash = (Get-FileHash $MsiOut -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content -Path "$MsiOut.sha256" -Value "$MsiHash  GODSEYE-Windows-Agent-x64.msi" -Encoding ascii

if (-not $SkipInstallSmoke) {
  Write-Host 'Smoke testing MSI install / uninstall...' -ForegroundColor Cyan
  $installLog = Join-Path $env:TEMP 'godseye-agent-msi-install.log'
  $uninstallLog = Join-Path $env:TEMP 'godseye-agent-msi-uninstall.log'
  $install = Start-Process msiexec.exe -ArgumentList @('/i', "`"$MsiOut`"", '/qn', '/norestart', '/l*v', "`"$installLog`"") -Wait -PassThru
  if ($install.ExitCode -notin @(0,3010)) { throw "MSI install failed with exit code $($install.ExitCode). Log: $installLog" }
  $svc = Get-CimInstance Win32_Service -Filter "Name='GODSEYEWindowsAgent'"
  if (-not $svc) { throw 'MSI did not create GODSEYEWindowsAgent.' }
  if ($svc.StartMode -ne 'Auto') { throw "Service start mode is $($svc.StartMode), expected Auto." }
  if ($svc.StartName -ne 'LocalSystem') { throw "Service account is $($svc.StartName), expected LocalSystem." }
  if ($svc.PathName -notlike '*\GODSEYE Agent\GODSEYE.Agent.exe*') { throw "Unexpected service path: $($svc.PathName)" }

  $sentinel = Join-Path $env:ProgramData 'GODSEYE\Agent\build-preserve-test.txt'
  New-Item -ItemType Directory -Path (Split-Path $sentinel) -Force | Out-Null
  Set-Content -Path $sentinel -Value 'preserve-me' -Encoding ascii
  $uninstall = Start-Process msiexec.exe -ArgumentList @('/x', "`"$MsiOut`"", '/qn', '/norestart', '/l*v', "`"$uninstallLog`"") -Wait -PassThru
  if ($uninstall.ExitCode -notin @(0,3010)) { throw "MSI uninstall failed with exit code $($uninstall.ExitCode). Log: $uninstallLog" }
  for ($i=0; $i -lt 10; $i++) {
    if (-not (Get-Service GODSEYEWindowsAgent -ErrorAction SilentlyContinue)) { break }
    Start-Sleep -Seconds 1
  }
  if (Get-Service GODSEYEWindowsAgent -ErrorAction SilentlyContinue) { throw 'Agent service still exists after MSI uninstall.' }
  if (-not (Test-Path $sentinel)) { throw 'ProgramData state was removed; enrollment must survive an upgrade/uninstall.' }
  Remove-Item $sentinel -Force
}

$Iscc = 'C:\Program Files (x86)\Inno Setup 6\ISCC.exe'
if (-not (Test-Path $Iscc)) {
  throw 'Inno Setup 6 is required to build GODSEYE-Windows-Agent-x64-Setup.exe. Install it, then rerun this script.'
}
Write-Host 'Building guided Setup EXE...' -ForegroundColor Cyan
& $Iscc (Join-Path $Root 'installer\GODSEYE-Agent-x64.iss')
if ($LASTEXITCODE -ne 0) { throw 'Inno Setup build failed.' }
$BuiltSetup = Join-Path $Root 'installer\output\GODSEYE-Windows-Agent-x64-Setup.exe'
if (-not (Test-Path $BuiltSetup)) { throw 'Guided Setup EXE was not created.' }
Copy-Item $BuiltSetup $SetupOut -Force
$SetupHash = (Get-FileHash $SetupOut -Algorithm SHA256).Hash.ToLowerInvariant()
Set-Content -Path "$SetupOut.sha256" -Value "$SetupHash  GODSEYE-Windows-Agent-x64-Setup.exe" -Encoding ascii

$readyManifest = [ordered]@{
  status = 'ready'
  version = $AgentVersion
  filename = 'GODSEYE-Windows-Agent-x64.msi'
  sha256 = $MsiHash
} | ConvertTo-Json
Set-Content -Path $Manifest -Value $readyManifest -Encoding utf8

Write-Host ''
Write-Host 'GODSEYE Windows Agent 2.4.3 build complete.' -ForegroundColor Green
Write-Host "Agent: $AgentOut"
Write-Host "MSI:   $MsiOut"
Write-Host "Setup: $SetupOut"
Write-Host "MSI SHA-256:   $MsiHash"
Write-Host "Setup SHA-256: $SetupHash"
