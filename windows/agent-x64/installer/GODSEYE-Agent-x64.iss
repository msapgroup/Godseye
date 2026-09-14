#define MyAppName "GODSEYE Windows Agent"
#define MyAppVersion "2.0.0"
#define MyAppPublisher "MSAPGROUP LLC"
#define MyAppExeName "GODSEYE.WindowsAgent.exe"

[Setup]
AppId={{E3BB8C4D-52AF-44D2-A6A9-4E6418F04D2F}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf64}\GODSEYE\Windows Agent
DefaultGroupName=GODSEYE
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
OutputDir=output
OutputBaseFilename=GODSEYE-Windows-Agent-x64-Setup
UninstallDisplayName={#MyAppName}
SetupLogging=yes
CloseApplications=no
RestartApplications=no
UsePreviousAppDir=yes

[Files]
Source: "..\publish\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\GODSEYE Agent Log"; Filename: "notepad.exe"; Parameters: """{commonappdata}\GODSEYE\Agent\agent.log"""

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

function ServiceExists(): Boolean;
var
  ResultCode: Integer;
begin
  Result := Exec(ExpandConstant('{sys}\sc.exe'), 'query GODSEYEWindowsAgent', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) and (ResultCode = 0);
end;

procedure InitializeWizard;
begin
  ExistingConfig := FileExists(ConfigPath());
  ConfigPage := CreateInputQueryPage(wpSelectDir,
    'Connect to GODSEYE',
    'Enroll this Windows computer with GODSEYE',
    'Enter the GODSEYE server URL and a one-time Windows Agent enrollment token.');
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

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Result := '';
  if ServiceExists() then
  begin
    Exec(ExpandConstant('{sys}\sc.exe'), 'stop GODSEYEWindowsAgent', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(2500);
    Exec(ExpandConstant('{sys}\sc.exe'), 'delete GODSEYEWindowsAgent', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(1000);
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
  Params: String;
  ExePath: String;
begin
  if CurStep <> ssPostInstall then exit;

  ForceDirectories(DataDir());
  ExePath := ExpandConstant('{app}\{#MyAppExeName}');

  if not ExistingConfig then
  begin
    Params := '--configure --server-url "' + Trim(ConfigPage.Values[0]) + '" --enrollment-token "' + Trim(ConfigPage.Values[1]) + '" --skip-tls-verify ';
    if TlsPage.SelectedValueIndex = 0 then
      Params := Params + 'false'
    else
      Params := Params + 'true';
    if not Exec(ExePath, Params, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) or (ResultCode <> 0) then
      RaiseException('Could not configure the GODSEYE Windows Agent. Installer exit code: ' + IntToStr(ResultCode));
  end;

  Exec(ExpandConstant('{sys}\icacls.exe'), '"' + DataDir() + '" /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  { Exec passes Params directly to CreateProcess. sc.exe needs the service binary path
    quoted exactly once because the default install directory contains spaces. }
  Params := 'create GODSEYEWindowsAgent binPath= "' + ExePath + '" start= auto DisplayName= "GODSEYE Windows Agent"';
  if not Exec(ExpandConstant('{sys}\sc.exe'), Params, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) or (ResultCode <> 0) then
    RaiseException('Could not create GODSEYE Windows Agent service. sc.exe exit code: ' + IntToStr(ResultCode));

  Exec(ExpandConstant('{sys}\sc.exe'), 'description GODSEYEWindowsAgent "Read-only GODSEYE Windows Event Log agent"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\sc.exe'), 'failure GODSEYEWindowsAgent reset= 86400 actions= restart/5000/restart/15000/restart/60000', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  if not Exec(ExpandConstant('{sys}\sc.exe'), 'start GODSEYEWindowsAgent', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) or (ResultCode <> 0) then
    MsgBox('The agent was installed, but Windows did not start the service. Review ' + DataDir() + '\agent.log and Windows Event Viewer.', mbError, MB_OK);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultCode: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    Exec(ExpandConstant('{sys}\sc.exe'), 'stop GODSEYEWindowsAgent', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Sleep(1500);
    Exec(ExpandConstant('{sys}\sc.exe'), 'delete GODSEYEWindowsAgent', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;
