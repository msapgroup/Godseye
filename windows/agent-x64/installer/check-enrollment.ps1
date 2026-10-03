# Local installer probe. Never print tokens, keys, or configuration contents.
param([switch]$CheckServiceRunning)
$ErrorActionPreference = 'Stop'
if ($CheckServiceRunning) {
  for ($i=0; $i -lt 10; $i++) {
    if ((Get-Service GODSEYEWindowsAgent -ErrorAction SilentlyContinue).Status -eq 'Running') { exit 0 }
    Start-Sleep -Seconds 1
  }
  exit 12
}
$folder = Join-Path $env:ProgramData 'GODSEYE\Agent'
$hasKey = $false
try {
  Add-Type -AssemblyName System.Security
  $keyPath = Join-Path $folder 'agent.key'
  if (Test-Path $keyPath) {
    $plain = [Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($keyPath), $null, [Security.Cryptography.DataProtectionScope]::LocalMachine)
    $hasKey = -not [string]::IsNullOrWhiteSpace([Text.Encoding]::UTF8.GetString($plain))
    [Array]::Clear($plain, 0, $plain.Length)
  }
} catch { $hasKey = $false }
foreach ($name in @('agent.json', 'agent.json.bak')) {
  try {
    $cfg = [IO.File]::ReadAllText((Join-Path $folder $name)) | ConvertFrom-Json
    $url = [Uri]$cfg.ServerUrl
    if ($url.IsAbsoluteUri -and $url.Scheme -in @('http','https') -and -not [string]::IsNullOrWhiteSpace($cfg.AgentUuid) -and
        ($hasKey -or -not [string]::IsNullOrWhiteSpace($cfg.EnrollmentToken))) { exit 0 }
  } catch { }
}
if ($hasKey) { exit 10 } # Existing enrollment key; connection settings need repair.
exit 11 # No usable enrollment: ask for server and token.
