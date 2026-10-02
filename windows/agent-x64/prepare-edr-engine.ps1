[CmdletBinding()]
param([string]$Destination = (Join-Path $PSScriptRoot 'publish\EDR'))
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Pin the release tag and verify the downloaded asset against the digest in
# GitHub's release metadata before it can enter the MSI.
$tag = 'v1.21.0'
$assetName = 'yara-x-v1.21.0-x86_64-pc-windows-msvc.zip'
$release = Invoke-RestMethod -Uri "https://api.github.com/repos/VirusTotal/yara-x/releases/tags/$tag" -Headers @{ 'User-Agent' = 'GODSEYE-build' }
$asset = @($release.assets | Where-Object name -eq $assetName)
if ($asset.Count -ne 1 -or $asset[0].digest -notmatch '^sha256:[0-9a-fA-F]{64}$') {
  throw 'YARA-X release asset or verified SHA-256 digest is unavailable.'
}
$scratch = Join-Path ([IO.Path]::GetTempPath()) ('godseye-yarax-' + [guid]::NewGuid().ToString('N'))
New-Item -Path $scratch -ItemType Directory -Force | Out-Null
try {
  $archive = Join-Path $scratch $assetName
  Invoke-WebRequest -Uri $asset[0].browser_download_url -OutFile $archive
  $actual = (Get-FileHash -Path $archive -Algorithm SHA256).Hash.ToLowerInvariant()
  $expected = $asset[0].digest.Substring(7).ToLowerInvariant()
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
