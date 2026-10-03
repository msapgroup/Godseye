param([Parameter(Mandatory=$true)][string]$AgentPath)
$ErrorActionPreference='Stop'
$exe=(Resolve-Path $AgentPath).Path
function Invoke-Agent([string[]]$Arguments, [int]$ExpectedExit = 0) {
  $out=Join-Path $env:RUNNER_TEMP 'godseye-config-test.out'
  $err=Join-Path $env:RUNNER_TEMP 'godseye-config-test.err'
  # WinExe processes are asynchronous when invoked directly from PowerShell.
  $process=Start-Process $exe -ArgumentList $Arguments -Wait -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
  $result=(Get-Content $out -Raw -ErrorAction Ignore) + (Get-Content $err -Raw -ErrorAction Ignore)
  if ($process.ExitCode -ne $ExpectedExit) { throw "Agent config command returned $($process.ExitCode), expected $ExpectedExit. $result" }
  return $result
}
$folder=Join-Path $env:ProgramData 'GODSEYE\Agent'
New-Item -ItemType Directory $folder -Force | Out-Null
$config=Join-Path $folder 'agent.json'
if (Test-Path $config) { throw 'Configuration recovery test requires a clean CI agent folder.' }
try {
  Invoke-Agent @('--configure','--server-url','http://127.0.0.1:9','--enrollment-token','CI-NONSECRET-TOKEN') | Write-Host
  $before=Get-Content $config -Raw | ConvertFrom-Json
  if (-not (Test-Path ($config+'.bak'))) { throw 'First configuration save has no valid recovery backup.' }
  Invoke-Agent @('--configure','--server-url','http://127.0.0.1:9','--enrollment-token','CI-NONSECRET-TOKEN') | Write-Host
  [IO.File]::WriteAllBytes($config,[byte[]]@(0,0,0,0))
  Invoke-Agent @('--check-config') | Write-Host
  $after=Get-Content $config -Raw | ConvertFrom-Json
  if ($after.AgentUuid -ne $before.AgentUuid -or $after.ServerUrl -ne $before.ServerUrl) { throw 'Configuration recovery changed enrollment identity.' }
  $corrupt=Get-ChildItem $folder -Filter 'agent.json.corrupt-*'
  if (-not $corrupt) { throw 'Damaged configuration was not preserved for diagnosis.' }
  Remove-Item ($config+'.bak')
  [IO.File]::WriteAllBytes($config,[byte[]]@(0,0,0,0))
  $result=Invoke-Agent @('--check-config') 2
  if ($result -notmatch 'No valid backup is available') { throw 'Invalid configuration without a backup was not reported clearly.' }
  if (([IO.File]::ReadAllBytes($config))[0] -ne 0) { throw 'Unrecoverable configuration was silently overwritten.' }
  Add-Type -AssemblyName System.Security
  $keyPath=Join-Path $folder 'agent.key'
  $protected=[Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes('CI-NONSECRET-KEY'),$null,[Security.Cryptography.DataProtectionScope]::LocalMachine)
  [IO.File]::WriteAllBytes($keyPath,$protected)
  $keyHash=(Get-FileHash $keyPath).Hash
  Invoke-Agent @('--configure','--repair-config','--server-url','http://127.0.0.1:9') | Write-Host
  if ((Get-FileHash $keyPath).Hash -ne $keyHash) { throw 'Repair changed the protected enrollment key.' }
  Invoke-Agent @('--check-config') | Write-Host
  Write-Host 'Atomic saves, null-byte recovery, identity preservation, and unrecoverable-file diagnostics passed.'
} finally {
  Get-ChildItem $folder -Filter 'agent.json*' | Remove-Item -Force
  Remove-Item (Join-Path $folder 'agent.key') -ErrorAction Ignore
}
