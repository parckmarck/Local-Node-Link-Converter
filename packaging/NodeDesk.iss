; Node Desk 安装包脚本（由 scripts/build_windows.py 调用；也可用 Inno Setup 6 手动编译）
; 可传入的定义: AppVersion / SourceDir / OutputDir / ProjectRoot / ChineseIsl

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SourceDir
  #define SourceDir AddBackslash(SourcePath) + "..\dist\NodeDesk"
#endif
#ifndef OutputDir
  #define OutputDir AddBackslash(SourcePath) + "..\dist"
#endif
#ifndef ProjectRoot
  #define ProjectRoot AddBackslash(SourcePath) + ".."
#endif

#define AppName "Node Desk"
#define AppExeName "NodeDesk.exe"

[Setup]
AppId={{7E6C9B2A-3F4D-4A8E-9B1C-5D2E8F0A6C31}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppName}
DefaultDirName={autopf}\NodeDesk
DisableProgramGroupPage=yes
DefaultGroupName={#AppName}
UninstallDisplayIcon={app}\{#AppExeName}
OutputDir={#OutputDir}
OutputBaseFilename=NodeDesk-{#AppVersion}-setup
SetupIconFile={#ProjectRoot}\assets\app.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
CloseApplications=yes
RestartApplications=no
MinVersion=10.0
#if VER >= EncodeVer(6,3,0)
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
#else
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
#endif

; Inno Setup 默认不附带中文语言文件。仅当打包脚本找到可用文件时才会定义
; ChineseIsl（值为其完整路径），否则编译为英文安装向导。
#ifdef ChineseIsl
[Languages]
Name: "chinesesimplified"; MessagesFile: "{#ChineseIsl}"
#endif

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExeName}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent

[Code]
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    MsgBox('Node Desk 已卸载。' + #13#10 + #13#10 +
           '你的本地节点数据仍保留在：' + #13#10 +
           ExpandConstant('{localappdata}') + '\NodeDesk' + #13#10 + #13#10 +
           '如需彻底清理，可手动删除该文件夹；删除前建议先在程序中导出备份。',
           mbInformation, MB_OK);
end;
