param([Parameter(Mandatory=$true)][string]$SetupPath)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
Add-Type @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class SetupUi {
  public delegate bool EnumProc(IntPtr h, IntPtr p);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr p);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc cb, IntPtr p);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessage(IntPtr h, uint m, IntPtr w, StringBuilder l);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left,Top,Right,Bottom; }
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr dc, uint flags);
}
'@
function Get-Controls([IntPtr]$Window) {
  $items = [System.Collections.Generic.List[object]]::new()
  $cb = [SetupUi+EnumProc]{ param($h,$p)
    if ([SetupUi]::IsWindowVisible($h)) {
      $s = [Text.StringBuilder]::new(2048); $c = [Text.StringBuilder]::new(256)
      [void][SetupUi]::GetWindowText($h,$s,$s.Capacity)
      [void][SetupUi]::GetClassName($h,$c,$c.Capacity)
      $items.Add([pscustomobject]@{Handle=$h;Text=$s.ToString();Class=$c.ToString()})
    }
    return $true
  }
  [void][SetupUi]::EnumChildWindows($Window,$cb,[IntPtr]::Zero)
  return $items
}
function Find-SetupWindow {
  $windows = [System.Collections.Generic.List[IntPtr]]::new()
  $cb = [SetupUi+EnumProc]{param($h,$p)
    $s=[Text.StringBuilder]::new(512)
    [void][SetupUi]::GetWindowText($h,$s,$s.Capacity)
    if ([SetupUi]::IsWindowVisible($h) -and $s.ToString() -like 'Setup - GODSEYE Windows Agent*') { $windows.Add($h) }
    return $true
  }
  [void][SetupUi]::EnumWindows($cb,[IntPtr]::Zero)
  if ($windows.Count) { return $windows[0] }
  return [IntPtr]::Zero
}
$config=Join-Path $env:ProgramData 'GODSEYE\Agent\agent.json'
$backup=$null
if (Test-Path $config) { $backup=[IO.File]::ReadAllBytes($config); Remove-Item $config }
try {
  foreach ($mode in @('fresh','enrolled')) {
    if ($mode -eq 'enrolled') {
      New-Item -ItemType Directory (Split-Path $config) -Force | Out-Null
      [IO.File]::WriteAllText($config,'{}')
    }
    $process=Start-Process (Resolve-Path $SetupPath).Path -ArgumentList '/NORESTART' -PassThru
    try {
      $window=[IntPtr]::Zero
      for ($i=0;$i -lt 60;$i++) {
        $window=Find-SetupWindow
        if ($window -ne [IntPtr]::Zero) { break }
        Start-Sleep -Milliseconds 500
      }
      if ($window -eq [IntPtr]::Zero) { throw "$mode Setup window did not appear." }
      $next=$null
      for ($i=0;$i -lt 60;$i++) {
        $next=Get-Controls $window | Where-Object { ($_.Text -replace '&','').Trim() -match '^Next\b' } | Select-Object -First 1
        if ($next) { break }
        Start-Sleep -Milliseconds 500
      }
      if (-not $next) { Get-Controls $window | Format-Table | Out-String | Write-Host; throw "$mode Setup welcome page has no Next button." }
      [void][SetupUi]::SendMessage($next.Handle,0x00F5,[IntPtr]::Zero,[IntPtr]::Zero)
      for ($i=0;$i -lt 60;$i++) {
        $controls=Get-Controls $window
        if ($controls | Where-Object Text -eq 'Optional Godseye EDR') { break }
        Start-Sleep -Milliseconds 500
      }
      if (-not ($controls | Where-Object Text -eq 'Optional Godseye EDR')) { throw "$mode Setup did not show EDR as its first choice page." }
      $list=$controls | Where-Object Class -eq 'TNewCheckListBox' | Select-Object -First 1
      if (-not $list) { throw "$mode Setup has no component selection list." }
      $count=[SetupUi]::SendMessage($list.Handle,0x018B,[IntPtr]::Zero,[IntPtr]::Zero).ToInt32()
      $labels=@()
      for ($i=0;$i -lt $count;$i++) {
        $label=[Text.StringBuilder]::new(2048)
        [void][SetupUi]::SendMessage($list.Handle,0x0189,[IntPtr]$i,$label)
        $labels += $label.ToString()
      }
      if ($labels.Count -ne 2 -or $labels[0] -ne 'Install Godseye EDR scanner (YARA-X)' -or $labels[1] -ne 'Agent only (skip Godseye EDR scanner)') {
        throw "$mode Setup component choices are incorrect: $($labels -join '; ')"
      }
      $rect=[SetupUi+RECT]::new(); [void][SetupUi]::GetWindowRect($window,[ref]$rect)
      $bitmap=[Drawing.Bitmap]::new($rect.Right-$rect.Left,$rect.Bottom-$rect.Top)
      $graphics=[Drawing.Graphics]::FromImage($bitmap); $dc=$graphics.GetHdc()
      try { [void][SetupUi]::PrintWindow($window,$dc,0) } finally { $graphics.ReleaseHdc($dc) }
      $bitmap.Save((Join-Path $env:RUNNER_TEMP "godseye-setup-edr-$mode.png"))
      $graphics.Dispose(); $bitmap.Dispose()
      Write-Host "$mode Setup.exe displays both EDR choices before enrollment."
    } finally {
      # No Install button is pressed. End only this bootstrapper's process tree.
      & taskkill.exe /PID $process.Id /T /F | Out-Null
    }
    if (Test-Path $config) { Remove-Item $config }
  }
} finally {
  if ($null -ne $backup) { [IO.File]::WriteAllBytes($config,$backup) }
  elseif (Test-Path $config) { Remove-Item $config }
}
