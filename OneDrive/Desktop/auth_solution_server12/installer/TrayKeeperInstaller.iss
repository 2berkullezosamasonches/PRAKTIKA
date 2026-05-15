#define MyAppName "TrayKeeper Antivirus"
#define MyAppPublisher "TrayKeeper"
#define MyAppExeName "TrayKeeper.exe"
#define MyServiceExeName "TrayKeeperService.exe"
#define MyServiceName "TrayKeeperService"
#define MyAppVersion "1.0.0"
#ifndef SourceDir
#define SourceDir "..\\build\\installer-payload"
#endif
#ifndef OutputDir
#define OutputDir "..\\build\\installer"
#endif

[Setup]
AppId={{0D06F98B-3F26-4D8B-9B31-B4742F97F24E}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\TrayKeeper Antivirus
DefaultGroupName=TrayKeeper Antivirus
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutputDir}
OutputBaseFilename=TrayKeeperAntivirusSetup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\{#MyAppExeName}
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\\Russian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; The CI pipeline prepares SourceDir with every runtime artifact required to start the app:
; executables, optional DLL/config/resource files, and the default antivirus database.
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "*.pdb,*.ilk,*.log,.ninja_*,CMakeCache.txt,CMakeFiles\*"

[Icons]
Name: "{group}\TrayKeeper Antivirus"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"
Name: "{autodesktop}\TrayKeeper Antivirus"; Filename: "{app}\{#MyAppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
; Register the freshly installed service for automatic startup and start it immediately.
Filename: "{app}\{#MyServiceExeName}"; Parameters: "install"; StatusMsg: "Регистрация Windows-службы..."; Flags: runhidden waituntilterminated
Filename: "{cmd}"; Parameters: "/C sc start {#MyServiceName}"; StatusMsg: "Запуск Windows-службы..."; Flags: runhidden waituntilterminated
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Stop and remove the service from the Service Control Manager before deleting files.
Filename: "{cmd}"; Parameters: "/C sc stop {#MyServiceName} >nul 2>nul"; Flags: runhidden waituntilterminated
Filename: "{cmd}"; Parameters: "/C sc delete {#MyServiceName} >nul 2>nul"; Flags: runhidden waituntilterminated

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Code]
function InitializeSetup(): Boolean;
begin
  if not IsAdminInstallMode then begin
    MsgBox('Для установки TrayKeeper Antivirus требуются права администратора.', mbError, MB_OK);
    Result := False;
    exit;
  end;

  Result := True;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  { Stop and unregister the previous service before files are copied. This avoids
    locked executable files during upgrade and keeps reinstall/update scenarios safe. }
  Exec(ExpandConstant('{cmd}'), '/C sc stop {#MyServiceName} >nul 2>nul', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{cmd}'), '/C timeout /T 2 /NOBREAK >nul 2>nul', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{cmd}'), '/C sc delete {#MyServiceName} >nul 2>nul', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{cmd}'), '/C timeout /T 2 /NOBREAK >nul 2>nul', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := '';
end;
