#define MyAppName "GODSEYE Windows Agent"
#define MyAppVersion "2.2.7"
#define MyAppPublisher "MSAPGROUP LLC"
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
  ConfigPage: TInputQueryWizardPage;
  TlsPage: TInputOptionWizardPage;
  ExistingEnrollment: Boolean;
  ConfigWrittenBySetup: Boolean;

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

function JsonEscape(Value: String): String;
begin
  Result := Value;
  StringChangeEx(Result, '\', '\\', True);
  StringChangeEx(Result, '"', '\"', True);
  StringChangeEx(Result, #13, '\r', True);
  StringChangeEx(Result, #10, '\n', True);
  StringChangeEx(Result, #9, '\t', True);
end;

function WriteFirstInstallConfig(): Boolean;
var
  Json: String;
  SkipTls: String;
  AgentUuid: String;
begin
  Result := False;
  if not ForceDirectories(DataDir()) then
  begin
    MsgBox('Setup could not create the GODSEYE Agent data folder:' + #13#10 + DataDir(), mbError, MB_OK);
    exit;
  end;

  if TlsPage.SelectedValueIndex = 0 then
    SkipTls := 'false'
  else
    SkipTls := 'true';

  AgentUuid := GetMD5OfString(ExpandConstant('{computername}') + '|' +
    ExpandConstant('{username}') + '|' +
    GetDateTimeString('yyyy-mm-dd hh:nn:ss.zzz', '-', ':'));

  Json := '{' + #13#10 +
    '  "ServerUrl": "' + JsonEscape(Trim(ConfigPage.Values[0])) + '",' + #13#10 +
    '  "EnrollmentToken": "' + JsonEscape(Trim(ConfigPage.Values[1])) + '",' + #13#10 +
    '  "AgentUuid": "' + AgentUuid + '",' + #13#10 +
    '  "SkipTlsVerify": ' + SkipTls + ',' + #13#10 +
    '  "PollIntervalSeconds": 60,' + #13#10 +
    '  "Channels": ["System", "Application"]' + #13#10 +
    '}' + #13#10;

  if not SaveStringToFile(ConfigPath(), Json, False) then
  begin
    MsgBox('Setup could not write the GODSEYE Agent configuration:' + #13#10 + ConfigPath(), mbError, MB_OK);
    exit;
  end;

  ConfigWrittenBySetup := True;
  Result := True;
end;

procedure InitializeWizard;
begin
  { A real existing enrollment requires both config and the DPAPI-protected API key.
    A stale config left by an interrupted/failed first install must not suppress the wizard. }
  ExistingEnrollment := FileExists(ConfigPath()) and FileExists(KeyPath());
  ConfigWrittenBySetup := False;

  ConfigPage := CreateInputQueryPage(wpWelcome,
    'Connect to GODSEYE',
    'Enroll this Windows computer with GODSEYE',
    'Enter the GODSEYE server URL and a one-time Windows Agent enrollment token. Existing enrolled installations keep their current enrollment automatically.');
  ConfigPage.Add('GODSEYE URL:', False);
  ConfigPage.Add('Enrollment token:', True);
  ConfigPage.Values[0] := 'https://';

  TlsPage := CreateInputOptionPage(ConfigPage.ID,
    'TLS verification',
    'Certificate validation',
    'Keep TLS certificate verification enabled for production.',
    True, False);
  TlsPage.Add('Verify the GODSEYE HTTPS certificate (recommended)');
  TlsPage.SelectedValueIndex := 0;
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := ExistingEnrollment and ((PageID = ConfigPage.ID) or (PageID = TlsPage.ID));
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if (not ExistingEnrollment) and (CurPageID = ConfigPage.ID) then
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
      MsgBox('Enter a one-time Windows Agent enrollment token from GODSEYE.', mbError, MB_OK);
      Result := False;
      exit;
    end;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  MsiResultCode: Integer;
  MsiPath: String;
  Params: String;
begin
  if CurStep <> ssPostInstall then
    exit;

  { IMPORTANT: first-install configuration is written BEFORE the MSI starts the
    Windows service. We intentionally do not launch the service executable as a
    post-install configuration helper. This removes the CLR bootstrap failure
    path and gives the service a valid configuration on its very first start. }
  if (not ExistingEnrollment) and (not WriteFirstInstallConfig()) then
    RaiseException('GODSEYE Windows Agent configuration could not be prepared.');

  ExtractTemporaryFile('{#MyMsiName}');
  MsiPath := ExpandConstant('{tmp}\{#MyMsiName}');

  Params := '/i "' + MsiPath + '" /qn /norestart';
  if not Exec(ExpandConstant('{sys}\msiexec.exe'), Params, '', SW_SHOW, ewWaitUntilTerminated, MsiResultCode) or
     ((MsiResultCode <> 0) and (MsiResultCode <> 3010)) then
  begin
    if ConfigWrittenBySetup then
      DeleteFile(ConfigPath());
    RaiseException('Windows Installer could not install GODSEYE Windows Agent. msiexec exit code: ' + IntToStr(MsiResultCode));
  end;

  if MsiResultCode = 3010 then
    MsgBox('GODSEYE Windows Agent was installed successfully. Windows requested a restart to complete installation.', mbInformation, MB_OK);
end;
