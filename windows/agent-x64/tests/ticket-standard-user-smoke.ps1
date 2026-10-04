$ErrorActionPreference='Stop'
$stage=Join-Path $env:ProgramFiles 'GODSEYE Ticket Storage Test'
$account='GeTicketTest'
$process=$null
try {
  dotnet publish 'windows/agent-x64/tests/ticket-smoke/TicketSmoke.csproj' -c Release -r win-x64 --self-contained true -o $stage
  if ($LASTEXITCODE -ne 0) { throw 'Could not publish storage regression harness.' }
  $password=ConvertTo-SecureString ('Aa1!'+[Guid]::NewGuid().ToString('N')) -AsPlainText -Force
  New-LocalUser -Name $account -Password $password -Description 'Disposable non-admin ticket storage regression account' | Out-Null
  Add-LocalGroupMember -Group 'Users' -Member $account
  Start-Service seclogon
  $credential=[PSCredential]::new("$env:COMPUTERNAME\$account",$password)
  $stdout=Join-Path $env:RUNNER_TEMP 'godseye-standard-user-ticket.out'
  $stderr=Join-Path $env:RUNNER_TEMP 'godseye-standard-user-ticket.err'
  $process=Start-Process (Join-Path $stage 'TicketSmoke.exe') -ArgumentList '--ticket-storage-only' -Credential $credential -LoadUserProfile -WorkingDirectory $env:ProgramFiles -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
  if (-not $process.WaitForExit(30000)) { Stop-Process $process.Id -Force; throw 'Standard-user ticket storage test exceeded 30 seconds.' }
  Get-Content $stdout -ErrorAction Ignore | Out-Host
  Get-Content $stderr -ErrorAction Ignore | Out-Host
  if ($process.ExitCode -ne 0) { throw "Standard-user ticket storage failed: $($process.ExitCode)" }
} finally {
  if ($process -and -not $process.HasExited) { Stop-Process $process.Id -Force -ErrorAction Ignore }
  Remove-LocalUser -Name $account -ErrorAction Ignore
  Remove-Item $stage -Recurse -Force -ErrorAction Ignore
}
