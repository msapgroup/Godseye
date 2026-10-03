param([Parameter(Mandatory=$true)][string]$AgentPath)
$ErrorActionPreference='Stop'
$exe=(Resolve-Path $AgentPath).Path
$folder=Join-Path $env:ProgramData 'GODSEYE\Agent'
New-Item -ItemType Directory $folder -Force | Out-Null
$config=Join-Path $folder 'agent.json'
if (Test-Path $config) { throw 'Configuration recovery test requires a clean CI agent folder.' }
try {
  & $exe --configure --server-url http://127.0.0.1:9 --enrollment-token CI-NONSECRET-TOKEN
  if ($LASTEXITCODE -ne 0) { throw 'CI configuration could not be created.' }
  $before=Get-Content $config -Raw | ConvertFrom-Json
  if (-not (Test-Path ($config+'.bak'))) { throw 'First configuration save has no valid recovery backup.' }
  & $exe --configure --server-url http://127.0.0.1:9 --enrollment-token CI-NONSECRET-TOKEN
  if ($LASTEXITCODE -ne 0) { throw 'Atomic configuration replacement failed.' }
  [IO.File]::WriteAllBytes($config,[byte[]]@(0,0,0,0))
  & $exe --check-config
  if ($LASTEXITCODE -ne 0) { throw 'Null-byte configuration did not recover from its valid backup.' }
  $after=Get-Content $config -Raw | ConvertFrom-Json
  if ($after.AgentUuid -ne $before.AgentUuid -or $after.ServerUrl -ne $before.ServerUrl) { throw 'Configuration recovery changed enrollment identity.' }
  $corrupt=Get-ChildItem $folder -Filter 'agent.json.corrupt-*'
  if (-not $corrupt) { throw 'Damaged configuration was not preserved for diagnosis.' }
  Remove-Item ($config+'.bak')
  [IO.File]::WriteAllBytes($config,[byte[]]@(0,0,0,0))
  $result=& $exe --check-config 2>&1
  if ($LASTEXITCODE -ne 2 -or ($result -join ' ') -notmatch 'No valid backup is available') { throw 'Invalid configuration without a backup was not reported clearly.' }
  if (([IO.File]::ReadAllBytes($config))[0] -ne 0) { throw 'Unrecoverable configuration was silently overwritten.' }
  Write-Host 'Atomic saves, null-byte recovery, identity preservation, and unrecoverable-file diagnostics passed.'
} finally {
  Get-ChildItem $folder -Filter 'agent.json*' | Remove-Item -Force
}
