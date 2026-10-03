#define MyAppName "GODSEYE Windows Agent"
#define MyAppVersion "2.4.5"
#define MyAppPublisher "MSAPGROUP LLC"
#define MyAppExeName "GODSEYE.Agent.exe"
#define MyMsiName "GODSEYE-Windows-Agent-x64.msi"

[Setup]
AppId={{E3BB8C4D-52AF-44D2-A6A9-4E6418F04D2F}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
CreateAppDir=no
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
DisableWelcomePage=no
OutputDir=output
OutputBaseFilename=GODSEYE-Windows-Agent-x64-Setup-2.4.5
SetupLogging=yes
CloseApplications=no
RestartApplications=no
Uninstallable=no

[Files]
Source: "..\{#MyMsiName}"; Flags: dontcopy
Source: "check-enrollment.ps1"; Flags: dontcopy

[Run]
; The MSI owns the service and sign-in startup. Launch the tray now in the
; signed-in user's session so it appears without requiring a sign-out.
Filename: "{autopf64}\GODSEYE Agent\{#MyAppExeName}"; Parameters: "--tray"; Flags: nowait runasoriginaluser; Check: NeedsTrayLaunch

[Code]
var
  ConfigPage: TInputQueryWizardPage;
  TlsPage: TInputOptionWizardPage;
  EdrPage: TInputOptionWizardPage;
  ConnectionPage: TInputOptionWizardPage;
  ExistingConfig: Boolean;
  ExistingKey: Boolean;

function DataDir(): String;
begin
  Result := ExpandConstant('{commonappdata}\GODSEYE\Agent');
end;

function ConfigPath(): String;
begin
  Result := DataDir() + '\agent.json';
end;

function AgentExePath(): String;
begin
  Result := ExpandConstant('{autopf64}\GODSEYE Agent\{#MyAppExeName}');
end;

procedure InitializeWizard;
var
  ProbeResult: Integer;
begin
  ExtractTemporaryFile('check-enrollment.ps1');
  if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + ExpandConstant('{tmp}\check-enrollment.ps1') + '"',
    '', SW_HIDE, ewWaitUntilTerminated, ProbeResult) then
    RaiseException('Could not check the existing GODSEYE enrollment. Setup did not change it.');
  if (ProbeResult <> 0) and (ProbeResult <> 10) and (ProbeResult <> 11) then
    RaiseException('GODSEYE enrollment check failed. Setup did not change the existing connection.');
  ExistingConfig := ProbeResult = 0;
  ExistingKey := (ProbeResult = 0) or (ProbeResult = 10);

  { Always show the component choice first, including enrolled upgrades.
    Two radio choices make skipping EDR explicit and reversible. }
  EdrPage := CreateInputOptionPage(wpWelcome,
    'Optional Godseye EDR', 'Choose endpoint scan components',
    'Choose whether to install the optional Godseye EDR scanner. Both choices include the core Agent, Cyber Tools integration, and user-approved remote support.',
    True, False);
  EdrPage.Add('Install Godseye EDR scanner (YARA-X)');
  EdrPage.Add('Agent only (skip Godseye EDR scanner)');
  if FileExists(ExpandConstant('{autopf64}\GODSEYE Agent\EDR\yr.exe')) then
    EdrPage.SelectedValueIndex := 0
  else
    EdrPage.SelectedValueIndex := 1;

  ConnectionPage := CreateInputOptionPage(EdrPage.ID,
    'Existing GODSEYE enrollment', 'Keep or repair connection settings',
    'Keep the existing enrollment, or change the server URL and certificate settings without removing the protected enrollment key.', True, False);
  ConnectionPage.Add('Keep existing enrollment and connection settings (recommended)');
  ConnectionPage.Add('Change server connection or TLS settings (keep enrollment key)');
  ConnectionPage.SelectedValueIndex := 0;
  if ExpandConstant('{param:RECONFIGURE|0}') = '1' then ConnectionPage.SelectedValueIndex := 1;

  ConfigPage := CreateInputQueryPage(ConnectionPage.ID,
    'Connect to GODSEYE',
    'Enroll this Windows computer with GODSEYE',
    'Enter the GODSEYE server URL and enrollment token. Usable existing settings are kept automatically. If an existing enrollment key was found, the token may be left blank to keep that enrollment.');
  ConfigPage.Add('GODSEYE URL:', False);
  ConfigPage.Add('Enrollment token:', True);
  ConfigPage.Values[0] := ExpandConstant('{param:SERVERURL|https://}');
  ConfigPage.Values[1] := ExpandConstant('{param:TOKEN|}');

  TlsPage := CreateInputOptionPage(ConfigPage.ID,
    'TLS verification',
    'Certificate validation',
    'Keep TLS certificate verification enabled for production.',
    True, False);
  TlsPage.Add('Verify the GODSEYE HTTPS certificate (recommended)');
  TlsPage.Add('Use a self-signed certificate on a trusted LAN (skip certificate validation)');
  TlsPage.SelectedValueIndex := 0;
  if ExpandConstant('{param:TLSVERIFY|1}') = '0' then TlsPage.SelectedValueIndex := 1;

end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := ((PageID = ConnectionPage.ID) and (not ExistingConfig)) or
    (ExistingConfig and (ConnectionPage.SelectedValueIndex = 0) and ((PageID = ConfigPage.ID) or (PageID = TlsPage.ID)));
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if ((not ExistingConfig) or (ConnectionPage.SelectedValueIndex = 1)) and (CurPageID = ConfigPage.ID) then
  begin
    if Trim(ConfigPage.Values[0]) = '' then
    begin
      MsgBox('Enter the GODSEYE server URL.', mbError, MB_OK);
      Result := False;
      exit;
    end;

    if (Pos('https://', Lowercase(Trim(ConfigPage.Values[0]))) <> 1) and
       (Pos('http://', Lowercase(Trim(ConfigPage.Values[0]))) <> 1) then
    begin
      MsgBox('Enter a GODSEYE URL beginning with https:// or http://.', mbError, MB_OK);
      Result := False;
      exit;
    end;

    if Pos('http://', Lowercase(Trim(ConfigPage.Values[0]))) = 1 then
    begin
      if MsgBox('This GODSEYE URL uses unencrypted HTTP. Use this only on a trusted LAN. Continue?', mbConfirmation, MB_YESNO) <> IDYES then
      begin
        Result := False;
        exit;
      end;
    end;

    if (not ExistingKey) and (Trim(ConfigPage.Values[1]) = '') then
    begin
      MsgBox('Enter a one-time Windows Agent enrollment token from GODSEYE.', mbError, MB_OK);
      Result := False;
      exit;
    end;
  end;
end;

function TrayCheckRequired(): Boolean;
begin
  Result := (not WizardSilent()) or (ExpandConstant('{param:CHECKTRAY|0}') = '1');
end;

function NeedsTrayLaunch(): Boolean;
var
  ExitCode: Integer;
begin
  Result := False;
  if not TrayCheckRequired() then exit;
  if not FileExists(AgentExePath()) then
    RaiseException('The installed GODSEYE executable is missing before tray startup: ' + AgentExePath() + '. Keep setup-msi.log and check Windows protection history for a removed file.');
  if Exec(AgentExePath(), '--check-tray', '', SW_HIDE, ewWaitUntilTerminated, ExitCode) and (ExitCode = 0) then exit;
  Result := True;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
  MsiResultCode: Integer;
  ServiceResultCode: Integer;
  MsiPath: String;
  Params: String;
  ExePath: String;
  InstalledVersion: String;
  InstallLog: String;
  Attempt: Integer;
begin
  if (CurStep = ssDone) and TrayCheckRequired() then
  begin
    for Attempt := 1 to 15 do
    begin
      if Exec(AgentExePath(), '--check-tray', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0) then exit;
      Sleep(500);
    end;
    RaiseException('The agent service is installed, but the tray did not complete its readiness check in this Windows session. Keep agent.log and setup-msi.log for diagnosis.');
  end;
  if CurStep <> ssPostInstall then exit;

  ExtractTemporaryFile('{#MyMsiName}');
  MsiPath := ExpandConstant('{tmp}\{#MyMsiName}');

  { The MSI is the sole owner of files, service registration, repair, upgrades,
    and uninstall. This bootstrapper only supplies first-install enrollment UI. }
  ForceDirectories(DataDir());
  InstallLog := DataDir() + '\setup-msi.log';
  { A running old tray can keep the old executable loaded after file replacement.
    Stop the service normally first so its recovery policy cannot relaunch it. }
  if RegKeyExists(HKLM, 'SYSTEM\CurrentControlSet\Services\GODSEYEWindowsAgent') then
  begin
    if not Exec(ExpandConstant('{sys}\net.exe'), 'stop GODSEYEWindowsAgent /y', '', SW_HIDE, ewWaitUntilTerminated, ServiceResultCode) or
      ((ServiceResultCode <> 0) and (ServiceResultCode <> 2)) then
      RaiseException('Could not stop the existing GODSEYE service for upgrade. Existing enrollment was preserved.');
  end;
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/IM GODSEYE.Agent.exe /T /F', '', SW_HIDE, ewWaitUntilTerminated, ServiceResultCode);
  Params := '/i "' + MsiPath + '" /qn /norestart /l*v "' + InstallLog + '"';
  if EdrPage.SelectedValueIndex = 0 then
    Params := Params + ' ADDLOCAL=MainFeature,EdrFeature'
  else
    Params := Params + ' ADDLOCAL=MainFeature REMOVE=EdrFeature';
  if not Exec(ExpandConstant('{sys}\msiexec.exe'), Params, '', SW_SHOW, ewWaitUntilTerminated, MsiResultCode) or
     ((MsiResultCode <> 0) and (MsiResultCode <> 3010)) then
  begin
    Exec(ExpandConstant('{sys}\net.exe'), 'start GODSEYEWindowsAgent', '', SW_HIDE, ewWaitUntilTerminated, ServiceResultCode);
    RaiseException('Windows Installer could not install GODSEYE Windows Agent. msiexec exit code: ' + IntToStr(MsiResultCode) + #13#10 +
      'Details were saved to: ' + InstallLog + #13#10 +
      'If Windows requests a restart, restart before trying again. Send setup-msi.log to your administrator to diagnose the failure.');
  end;

  if (not ExistingConfig) or (ConnectionPage.SelectedValueIndex = 1) then
  begin
    ExePath := AgentExePath();
    if not FileExists(ExePath) then
      RaiseException('GODSEYE Windows Agent was installed, but the service executable was not found at ' + ExePath);

    { The MSI starts the service automatically. Stop it while writing the first-time
      enrollment configuration, then restart it so enrollment happens immediately. }
    Exec(ExpandConstant('{sys}\net.exe'), 'stop GODSEYEWindowsAgent /y', '', SW_HIDE, ewWaitUntilTerminated, ServiceResultCode);

    Params := '--configure --repair-config --server-url "' + Trim(ConfigPage.Values[0]) + '" --enrollment-token "' + Trim(ConfigPage.Values[1]) + '" --skip-tls-verify ';
    if TlsPage.SelectedValueIndex = 0 then
      Params := Params + 'false'
    else
      Params := Params + 'true';

    if not Exec(ExePath, Params, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) or (ResultCode <> 0) then
      RaiseException('The Windows Agent MSI installed successfully, but first-time GODSEYE configuration failed. Agent exit code: ' + IntToStr(ResultCode));

  end;

  { Re-running the same MSI may be maintenance rather than a file upgrade.
    Explicitly restart and verify the service in either case. }
  Exec(ExpandConstant('{sys}\net.exe'), 'start GODSEYEWindowsAgent', '', SW_HIDE, ewWaitUntilTerminated, ServiceResultCode);
  if not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
    '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + ExpandConstant('{tmp}\check-enrollment.ps1') + '" -CheckServiceRunning',
    '', SW_HIDE, ewWaitUntilTerminated, ServiceResultCode) or (ServiceResultCode <> 0) then
    RaiseException('GODSEYE Windows Agent files were installed, but the service is not running. Check agent.log and setup-msi.log in ' + DataDir());

  if MsiResultCode = 3010 then
    SuppressibleMsgBox('GODSEYE Windows Agent was installed successfully. Windows requested a restart to complete installation.', mbInformation, MB_OK, IDOK);

  ExePath := AgentExePath();
  if not GetVersionNumbersString(ExePath, InstalledVersion) then
    RaiseException('GODSEYE Windows Agent was installed, but its version could not be verified.');
  if Pos('2.4.5', InstalledVersion) <> 1 then
    RaiseException('The installer expected GODSEYE Windows Agent 2.4.5, but Windows reports version ' + InstalledVersion + '.');

  if MsiResultCode <> 3010 then
    SuppressibleMsgBox('GODSEYE Windows Agent 2.4.5 was installed and verified successfully.', mbInformation, MB_OK, IDOK);
end;
