[CmdletBinding()]
param([string]$Destination = (Join-Path $PSScriptRoot 'publish\EDR'))
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Pin the release tag and its published SHA-256 so builds do not depend on
# anonymous GitHub API rate limits or a mutable "latest" release.
$tag = 'v1.21.0'
$assetName = 'yara-x-v1.21.0-x86_64-pc-windows-msvc.zip'
$expected = '0e2fc4d2f64df3eaa22129ad5bd074c968a5d80766ddec6183b73175e5c9da25'
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('godseye-yarax-' + [guid]::NewGuid().ToString('N'))
New-Item -Path $scratch -ItemType Directory -Force | Out-Null
try {
  $archive = Join-Path $scratch $assetName
  Invoke-WebRequest -Uri "https://github.com/VirusTotal/yara-x/releases/download/$tag/$assetName" -OutFile $archive -TimeoutSec 180
  $actual = (Get-FileHash -Path $archive -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($actual -ne $expected) { throw "YARA-X SHA-256 mismatch: $actual" }
  $unpacked = Join-Path $scratch 'unpacked'
  Expand-Archive -LiteralPath $archive -DestinationPath $unpacked
  $engine = @(Get-ChildItem -Path $unpacked -Filter 'yr.exe' -File -Recurse)
  if ($engine.Count -ne 1) { throw 'Expected exactly one yr.exe in YARA-X archive.' }
  New-Item -Path $Destination -ItemType Directory -Force | Out-Null
  Copy-Item -LiteralPath $engine[0].FullName -Destination (Join-Path $Destination 'yr.exe') -Force
  $license = @(Get-ChildItem -Path $unpacked -File -Recurse | Where-Object Name -Match '^(LICENSE|COPYING)(\.txt|\.md)?$' | Select-Object -First 1)
  if ($license.Count) { Copy-Item -LiteralPath $license[0].FullName -Destination (Join-Path $Destination 'YARA-X-LICENSE.txt') -Force }
  else {
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/VirusTotal/yara-x/$tag/LICENSE" -OutFile (Join-Path $Destination 'YARA-X-LICENSE.txt')
  }
  Write-Host "Verified YARA-X $tag archive SHA-256 $actual"
} finally {
  Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}
