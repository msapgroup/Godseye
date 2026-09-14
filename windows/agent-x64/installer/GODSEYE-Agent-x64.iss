#define MyAppName "GODSEYE Windows Agent"
#define MyAppVersion "2.2.6"
#define MyAppPublisher "MSAPGROUP LLC"
#define MyAppExeName "GODSEYE.WindowsAgent.exe"
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
OutputDir=output
OutputBaseFilename=GODSEYE-Windows-Agent-x64-Setup
SetupLogging=yes
CloseApplications=no
RestartApplications=no
Uninstallable=no

[Files]
Source: "..\{#MyMsiName}"; Flags: dontcopy

[Code]
var
  ModePage: TInputOptionWizardPage;
  ConfigPage: TInputQueryWizardPage;
  TlsPage: TInputOptionWizardPage;
  ExistingConfig: Boolean;

function DataDir(): String;
begin
  Result := ExpandConstant('{commonappdata}\GODSEYE\Agent');
end;

function ConfigPath(): String;
begin
  Result := DataDir() + '\agent.json';
end;

function KeyPath(): String;
begin
  Result := DataDir() + '\agent.key';
end;

function LogPath(): String;
begin
  Result := DataDir() + '\agent.log';
end;

function AgentExePath(): String;
begin
  Result := ExpandConstant('{autopf64}\GODSEYE Agent\{#MyAppExeName}');
end;

function IsRepairMode(): Boolean;
begin
  Result := ExistingConfig and (ModePage.SelectedValueIndex = 1);
end;

function IsResetMode(): Boolean;
begin
  Result := ExistingConfig and (ModePage.SelectedValueIndex = 2);
end;

function NeedsConfiguration(): Boolean;
begin
  Result := (not ExistingConfig) or IsRepairMode() or IsResetMode();
end;

procedure StopAgentService;
var
  Code: Integer;
begin
  Exec(ExpandConstant('{sys}\sc.exe'), 'stop GODSEYEWindowsAgent', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Sleep(1500);
end;

procedure StartAgentService;
var
  Code: Integer;
begin
  if not Exec(ExpandConstant('{sys}\sc.exe'), 'start GODSEYEWindowsAgent', '', SW_HIDE, ewWaitUntilTerminated, Code) then
    RaiseException('GODSEYE Windows Agent could not be started.');
  if (Code <> 0) and (Code <> 1056) then
    RaiseException('GODSEYE Windows Agent could not be started. sc.exe exit code: ' + IntToStr(Code));
end;

procedure BackupFileIfPresent(Path: String);
begin
  if FileExists(Path) then
    FileCopy(Path, Path + '.before-repair.bak', False);
end;

procedure PrepareEnrollmentState;
begin
  if IsRepairMode() then
  begin
    BackupFileIfPresent(KeyPath());
    DeleteFile(KeyPath());
  end
  else if IsResetMode() then
  begin
    BackupFileIfPresent(KeyPath());
    BackupFileIfPresent(ConfigPath());
    DeleteFile(KeyPath());
    DeleteFile(ConfigPath());
  end;
end;

function WaitForEnrollment(Seconds: Integer): Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 1 to Seconds do
  begin
    if FileExists(KeyPath()) then
    begin
      Result := True;
      exit;
    end;
    Sleep(1000);
  end;
end;

procedure ShowEnrollmentFailure;
var
  LogText: AnsiString;
  Msg: String;
begin
  Msg := 'The Windows service installed, but it did not complete GODSEYE enrollment.' + #13#10 + #13#10;
  if LoadStringFromFile(LogPath(), LogText) and
     (Pos('already enrolled', Lowercase(String(LogText))) > 0) then
  begin
    Msg := Msg + 'This computer identity is still active in GODSEYE.' + #13#10 +
      'In GODSEYE > Event Findings > Windows Agents, revoke the old offline agent, then run this Setup again and choose Repair / re-enroll.';
  end
  else
  begin
    Msg := Msg + 'Check the GODSEYE URL, enrollment token, TLS setting, and network access.' + #13#10 +
      'Agent log: ' + LogPath();
  end;
  MsgBox(Msg, mbError, MB_OK);
end;

procedure InitializeWizard;
begin
  ExistingConfig := FileExists(ConfigPath());

  ModePage := CreateInputOptionPage(wpWelcome,
    'Existing GODSEYE Agent state detected',
    'Choose how Setup should handle the existing enrollment',
    'Keep enrollment for a normal upgrade. If this computer is offline or the old enrollment is broken, use Repair / re-enroll. Reset as new creates a new GODSEYE agent identity and keeps Event Log bookmarks/queue data.',
    True, False);
  ModePage.Add('Keep existing enrollment (normal upgrade)');
  ModePage.Add('Repair / re-enroll this computer (same agent identity)');
  ModePage.Add('Reset enrollment and register as a new agent identity');
  ModePage.SelectedValueIndex := 0;

  ConfigPage := CreateInputQueryPage(ModePage.ID,
    'Connect to GODSEYE',
    'Enroll this Windows computer with GODSEYE',
    'Enter the GODSEYE server URL and a fresh one-time Windows Agent enrollment token. For Repair / re-enroll, revoke the old offline agent in GODSEYE first so the same identity can be re-keyed.');
  ConfigPage.Add('GODSEYE URL:', False);
  ConfigPage.Add('Enrollment token:', True);
  ConfigPage.Values[0] := 'https://';

  TlsPage := CreateInputOptionPage(ConfigPage.ID,
    'TLS verification',
    'Certificate validation',
    'Choose how the agent validates the GODSEYE HTTPS certificate.',
    True, False);
  TlsPage.Add('Verify the GODSEYE HTTPS certificate (recommended)');
  TlsPage.Add('Allow an untrusted/self-signed certificate (trusted LAN testing only)');
  TlsPage.SelectedValueIndex := 0;
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := False;
  if (PageID = ModePage.ID) and (not ExistingConfig) then
    Result := True
  else if ExistingConfig and (ModePage.SelectedValueIndex = 0) and
          ((PageID = ConfigPage.ID) or (PageID = TlsPage.ID)) then
    Result := True;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;

  if ExistingConfig and (CurPageID = ModePage.ID) and IsRepairMode() then
  begin
    if MsgBox('Repair / re-enroll keeps this computer''s existing agent identity. Before continuing, revoke the old offline Windows Agent entry in GODSEYE so the one-time token can rotate its API key. Continue?', mbConfirmation, MB_YESNO) <> IDYES then
    begin
      Result := False;
      exit;
    end;
  end;

  if NeedsConfiguration() and (CurPageID = ConfigPage.ID) then
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

    if Trim(ConfigPage.Values[1]) = '' then
    begin
      MsgBox('Enter a fresh one-time Windows Agent enrollment token from GODSEYE.', mbError, MB_OK);
      Result := False;
      exit;
    end;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
  MsiResultCode: Integer;
  MsiPath: String;
  Params: String;
  ExePath: String;
begin
  if CurStep <> ssPostInstall then
    exit;

  ExtractTemporaryFile('{#MyMsiName}');
  MsiPath := ExpandConstant('{tmp}\{#MyMsiName}');

  Params := '/i "' + MsiPath + '" /qn /norestart';
  if not Exec(ExpandConstant('{sys}\msiexec.exe'), Params, '', SW_SHOW, ewWaitUntilTerminated, MsiResultCode) or
     ((MsiResultCode <> 0) and (MsiResultCode <> 3010)) then
    RaiseException('Windows Installer could not install GODSEYE Windows Agent. msiexec exit code: ' + IntToStr(MsiResultCode));

  if NeedsConfiguration() then
  begin
    ExePath := AgentExePath();
    if not FileExists(ExePath) then
      RaiseException('GODSEYE Windows Agent was installed, but the service executable was not found at ' + ExePath);

    StopAgentService();
    PrepareEnrollmentState();

    Params := '--configure --server-url "' + Trim(ConfigPage.Values[0]) + '" --enrollment-token "' + Trim(ConfigPage.Values[1]) + '" --skip-tls-verify ';
    if TlsPage.SelectedValueIndex = 0 then
      Params := Params + 'false'
    else
      Params := Params + 'true';

    if not Exec(ExePath, Params, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) or (ResultCode <> 0) then
      RaiseException('The Windows Agent MSI installed successfully, but GODSEYE configuration failed. Agent exit code: ' + IntToStr(ResultCode));

    StartAgentService();

    if not WaitForEnrollment(45) then
      ShowEnrollmentFailure();
  end;

  if MsiResultCode = 3010 then
    MsgBox('GODSEYE Windows Agent was installed successfully. Windows requested a restart to complete installation.', mbInformation, MB_OK);
end;
