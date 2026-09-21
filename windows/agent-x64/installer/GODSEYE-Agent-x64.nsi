Unicode True
RequestExecutionLevel admin
ManifestDPIAware true

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "nsDialogs.nsh"
!include "x64.nsh"

!define APP_NAME "GODSEYE Windows Agent"
!define APP_VERSION "2.4.4"
!define PUBLISHER "MSAPGROUP LLC"
!define SERVICE_NAME "GODSEYEWindowsAgent"
!define PRODUCT_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\GODSEYEWindowsAgent"

Name "${APP_NAME} ${APP_VERSION}"
OutFile "..\GODSEYE-Windows-Agent-x64-Setup.exe"
InstallDir "$PROGRAMFILES64\GODSEYE Agent"
InstallDirRegKey HKLM "${PRODUCT_KEY}" "InstallLocation"
BrandingText "Powered By: MSAPGROUP.LLC"
VIProductVersion "2.4.4.0"
VIAddVersionKey "ProductName" "${APP_NAME}"
VIAddVersionKey "ProductVersion" "${APP_VERSION}"
VIAddVersionKey "CompanyName" "${PUBLISHER}"
VIAddVersionKey "FileDescription" "GODSEYE Windows Agent x64 Setup"
VIAddVersionKey "FileVersion" "2.4.4.0"

Var ServerUrl
Var EnrollmentToken
Var VerifyTls
Var ExistingConfig
Var KeepExisting
Var ServerInput
Var TokenInput
Var TlsCheckbox
Var KeepCheckbox

!insertmacro MUI_PAGE_WELCOME
Page custom EnrollmentPageCreate EnrollmentPageLeave
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_LANGUAGE "English"

Function .onInit
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP|MB_OK "GODSEYE Windows Agent 2.4.4 requires 64-bit Windows."
    Abort
  ${EndIf}
  SetRegView 64
  SetShellVarContext all
  StrCpy $ServerUrl "https://"
  StrCpy $VerifyTls "1"
  StrCpy $KeepExisting "0"
  IfFileExists "$APPDATA\GODSEYE\Agent\agent.json" 0 +2
    StrCpy $ExistingConfig "1"
FunctionEnd

Function EnrollmentPageCreate
  nsDialogs::Create 1018
  Pop $0
  ${If} $0 == error
    Abort
  ${EndIf}
  ${If} $ExistingConfig == "1"
    ${NSD_CreateLabel} 0 0 100% 22u "An existing GODSEYE enrollment was found. Keep it, or clear the option below and enter a new URL and token."
    Pop $0
    ${NSD_CreateCheckbox} 0 24u 100% 13u "Keep existing GODSEYE enrollment"
    Pop $KeepCheckbox
    ${NSD_Check} $KeepCheckbox
  ${Else}
    ${NSD_CreateLabel} 0 0 100% 24u "Connect this Windows computer to GODSEYE using a one-time Windows Agent enrollment token."
    Pop $0
  ${EndIf}
  ${NSD_CreateLabel} 0 43u 100% 12u "GODSEYE server URL"
  Pop $0
  ${NSD_CreateText} 0 57u 100% 13u "$ServerUrl"
  Pop $ServerInput
  ${NSD_CreateLabel} 0 80u 100% 12u "Enrollment token"
  Pop $0
  ${NSD_CreatePassword} 0 94u 100% 13u ""
  Pop $TokenInput
  ${NSD_CreateCheckbox} 0 121u 100% 13u "Verify the GODSEYE HTTPS certificate (recommended)"
  Pop $TlsCheckbox
  ${NSD_Check} $TlsCheckbox
  nsDialogs::Show
FunctionEnd

Function EnrollmentPageLeave
  ${If} $ExistingConfig == "1"
    ${NSD_GetState} $KeepCheckbox $KeepExisting
    ${If} $KeepExisting == ${BST_CHECKED}
      Return
    ${EndIf}
  ${EndIf}
  ${NSD_GetText} $ServerInput $ServerUrl
  ${NSD_GetText} $TokenInput $EnrollmentToken
  ${NSD_GetState} $TlsCheckbox $VerifyTls
  ${If} $ServerUrl == ""
    MessageBox MB_ICONSTOP|MB_OK "Enter the GODSEYE server URL."
    Abort
  ${EndIf}
  ${If} $EnrollmentToken == ""
    MessageBox MB_ICONSTOP|MB_OK "Enter a one-time Windows Agent enrollment token."
    Abort
  ${EndIf}
FunctionEnd

Section "GODSEYE Windows Agent" SEC_AGENT
  SetRegView 64
  SetShellVarContext all
  SetOutPath "$INSTDIR"

  File /oname=GODSEYE.Agent.exe "..\publish\GODSEYE.Agent.exe"
  CreateDirectory "$APPDATA\GODSEYE\Agent"

  ${If} $KeepExisting != ${BST_CHECKED}
    ; The user explicitly chose a new enrollment. Remove only the prior identity
    ; and protected API key; event bookmarks, logs, and queued diagnostics remain.
    Delete "$APPDATA\GODSEYE\Agent\agent.json"
    Delete "$APPDATA\GODSEYE\Agent\agent.key"
    ${If} $VerifyTls == ${BST_CHECKED}
      StrCpy $1 "false"
    ${Else}
      StrCpy $1 "true"
    ${EndIf}
    nsExec::ExecToLog '"$INSTDIR\GODSEYE.Agent.exe" --configure --server-url "$ServerUrl" --enrollment-token "$EnrollmentToken" --skip-tls-verify $1'
    Pop $0
    ${If} $0 != 0
      MessageBox MB_ICONSTOP|MB_OK "The agent files were installed, but GODSEYE enrollment configuration failed (exit code $0)."
      Abort
    ${EndIf}
  ${EndIf}

  ; Keep service creation arguments deliberately minimal. Passing nested quotes to
  ; sc.exe through an installer produced Windows error 1639 on clean systems.
  ; sc.exe first receives the executable path as one argument; ImagePath is then
  ; written with explicit quotes so the Program Files path is stored securely.
  nsExec::ExecToLog '"$SYSDIR\sc.exe" query ${SERVICE_NAME}'
  Pop $0
  ${If} $0 == 0
    nsExec::ExecToLog '"$SYSDIR\sc.exe" stop ${SERVICE_NAME}'
    Pop $0
    nsExec::ExecToLog '"$SYSDIR\sc.exe" config ${SERVICE_NAME} binPath= "$INSTDIR\GODSEYE.Agent.exe" start= auto'
    Pop $0
  ${Else}
    nsExec::ExecToLog '"$SYSDIR\sc.exe" create ${SERVICE_NAME} binPath= "$INSTDIR\GODSEYE.Agent.exe" start= auto'
    Pop $0
  ${EndIf}
  ${If} $0 != 0
    MessageBox MB_ICONSTOP|MB_OK "Windows could not register the GODSEYE service (exit code $0)."
    Abort
  ${EndIf}
  WriteRegStr HKLM "SYSTEM\CurrentControlSet\Services\${SERVICE_NAME}" "ImagePath" '$\"$INSTDIR\GODSEYE.Agent.exe$\"'
  WriteRegStr HKLM "SYSTEM\CurrentControlSet\Services\${SERVICE_NAME}" "DisplayName" "GODSEYE Windows Agent"
  nsExec::ExecToLog '"$SYSDIR\sc.exe" description "${SERVICE_NAME}" "GODSEYE monitoring and user-approved remote support agent"'
  Pop $0
  nsExec::ExecToLog '"$SYSDIR\sc.exe" failure "${SERVICE_NAME}" reset= 86400 actions= restart/5000/restart/5000/restart/5000'
  Pop $0
  nsExec::ExecToLog '"$SYSDIR\sc.exe" start "${SERVICE_NAME}"'
  Pop $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP|MB_OK "The agent was installed, but the GODSEYE service did not start (exit code $0). Check the server URL, token, and Windows Event Log."
    Abort
  ${EndIf}

  WriteUninstaller "$INSTDIR\Uninstall.exe"
  WriteRegStr HKLM "${PRODUCT_KEY}" "DisplayName" "${APP_NAME}"
  WriteRegStr HKLM "${PRODUCT_KEY}" "DisplayVersion" "${APP_VERSION}"
  WriteRegStr HKLM "${PRODUCT_KEY}" "Publisher" "${PUBLISHER}"
  WriteRegStr HKLM "${PRODUCT_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${PRODUCT_KEY}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegDWORD HKLM "${PRODUCT_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${PRODUCT_KEY}" "NoRepair" 1
SectionEnd

Section "Uninstall"
  SetRegView 64
  nsExec::ExecToLog '"$SYSDIR\sc.exe" stop "${SERVICE_NAME}"'
  Pop $0
  nsExec::ExecToLog '"$SYSDIR\sc.exe" delete "${SERVICE_NAME}"'
  Pop $0
  Delete "$INSTDIR\GODSEYE.Agent.exe"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKLM "${PRODUCT_KEY}"
  ; Enrollment identity and event bookmarks in ProgramData intentionally survive uninstall.
SectionEnd
