#define MyAppName "GODSEYE Windows Agent"
#define MyAppVersion "2.2.3"
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

function AgentExePath(): String;
begin
  Result := ExpandConstant('{autopf64}\GODSEYE Agent\{#MyAppExeName}');
end;

procedure InitializeWizard;
begin
  ExistingConfig := FileExists(ConfigPath());

  ConfigPage := CreateInputQueryPage(wpWelcome,
    'Connect to GODSEYE',
    'Enroll this Windows computer with GODSEYE',
    'Enter the GODSEYE server URL and a one-time Windows Agent enrollment token. Existing installations keep their current enrollment automatically.');
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
  Result := ExistingConfig and ((PageID = ConfigPage.ID) or (PageID = TlsPage.ID));
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if (not ExistingConfig) and (CurPageID = ConfigPage.ID) then
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

  { The MSI is the sole owner of files, service registration, repair, upgrades,
    and uninstall. This bootstrapper only supplies first-install enrollment UI. }
  Params := '/i "' + MsiPath + '" /qn /norestart';
  if not Exec(ExpandConstant('{sys}\msiexec.exe'), Params, '', SW_SHOW, ewWaitUntilTerminated, MsiResultCode) or
     ((MsiResultCode <> 0) and (MsiResultCode <> 3010)) then
    RaiseException('Windows Installer could not install GODSEYE Windows Agent. msiexec exit code: ' + IntToStr(MsiResultCode));

  if not ExistingConfig then
  begin
    ExePath := AgentExePath();
    if not FileExists(ExePath) then
      RaiseException('GODSEYE Windows Agent was installed, but the service executable was not found at ' + ExePath);

    Params := '--configure --server-url "' + Trim(ConfigPage.Values[0]) + '" --enrollment-token "' + Trim(ConfigPage.Values[1]) + '" --skip-tls-verify ';
    if TlsPage.SelectedValueIndex = 0 then
      Params := Params + 'false'
    else
      Params := Params + 'true';

    if not Exec(ExePath, Params, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) or (ResultCode <> 0) then
      RaiseException('The Windows Agent MSI installed successfully, but first-time GODSEYE configuration failed. Agent exit code: ' + IntToStr(ResultCode));
  end;

  if MsiResultCode = 3010 then
    MsgBox('GODSEYE Windows Agent was installed successfully. Windows requested a restart to complete installation.', mbInformation, MB_OK);
end;
