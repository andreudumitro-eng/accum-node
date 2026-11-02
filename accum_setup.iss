[Setup]
AppName=ACCUM Node
AppVersion=1.0
DefaultDirName={autopf}\ACCUM Node
DefaultGroupName=ACCUM Node
UninstallDisplayIcon={app}\accum-node.exe
Compression=lzma2
SolidCompression=yes
OutputDir=C:\ACCUM\accum-node\installer
OutputBaseFilename=ACCUM_Setup
ArchitecturesInstallIn64BitMode=x64

[Files]
Source: "C:\ACCUM\accum-node\target\release\accum-node.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "C:\ACCUM\accum-node\accum-wallet.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "C:\ACCUM\accum-node\start.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "C:\ACCUM\accum-node\stop.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "C:\ACCUM\accum-node\src\logo.svg"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Start ACCUM Node"; Filename: "{app}\start.bat"
Name: "{autodesktop}\ACCUM Node"; Filename: "{app}\start.bat"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop icon"; GroupDescription: "Additional icons:"