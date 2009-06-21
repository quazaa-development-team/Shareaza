; Uncomment the next line to compile a debug build without any files.
;#define debug

#if VER < 0x05010700
  #error Inno Setup version 5.1.7 or higher is needed for this script
#endif
#if PREPROCVER < 0x05010000
  #error PreProcessor version 5.1.2 or higher is needed for this script
#endif

#ifdef debug
  #define name "Shareaza debug build"
#else
  #define name "Shareaza"
#endif

#define version GetFileVersion("..\builds\Shareaza.exe")

[Setup]
AppComments=Shareaza Ultimate File Sharing
AppId=Shareaza
AppName={#name}
AppPublisher=Shareaza Development Team
AppVersion={#version}
AppVerName={#name} {#version}
VersionInfoVersion={#version}
DefaultDirName={ini:{param:SETTINGS|},Locations,Path|{reg:HKLM\SOFTWARE\Shareaza,|{pf}\Shareaza}}
DirExistsWarning=no
DefaultGroupName=Shareaza
AllowNoIcons=yes
OutputDir=setup\builds
OutputBaseFilename=Shareaza_{#version}
SolidCompression=yes
Compression=lzma/max
InternalCompressLevel=max
VersionInfoCompany=Shareaza Development Team
VersionInfoDescription=Shareaza Ultimate File Sharing
PrivilegesRequired=poweruser
ShowLanguageDialog=yes
ShowUndisplayableLanguages=yes
LanguageDetectionMethod=locale
UninstallDisplayIcon={app}\Uninstall\setup.exe
UninstallDisplayName={cm:NameAndVersion,Shareaza,{#version}}
UninstallFilesDir={app}\Uninstall
SetupIconFile=setup\misc\install.ico
ShowComponentSizes=no
WizardImageFile=setup\misc\sidebar.bmp
WizardSmallImageFile=setup\misc\corner.bmp
;AppModifyPath="{app}\Uninstall\repair.exe"
ChangesAssociations=yes
ChangesEnvironment=yes
OutputManifestFile=Manifest.txt
MinVersion=4.0,4.0sp6

; Set the CVS root as source dir (up 2 levels)
SourceDir=..\..

; links to website for software panel
AppPublisherURL=http://www.shareaza.com/?id=home
AppSupportURL=http://www.shareaza.com/?id=support
AppUpdatesURL=http://www.shareaza.com/?id=download

[Components]
; Ask user wich components to install
Name: "language"; Description: "{cm:components_languages}"; Types: full; Flags: disablenouninstallwarning

[Tasks]
Name: "multiuser"; Description: "{cm:tasks_multisetup}"
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"
Name: "quicklaunch"; Description: "{cm:CreateQuickLaunchIcon}"
;Name: "firewall"; Description: "{cm:tasks_firewall}"; MinVersion: 0,5.01sp2
Name: "upnp"; Description: "{cm:tasks_upnp}"; MinVersion: 0,5.01; Check: CanUserModifyServices
Name: "deleteoldsetup"; Description: "{cm:tasks_deleteoldsetup}"; Check: EnableDeleteOldSetup

[Files]
#ifndef debug
; Install unicows.dll on Win 9X
Source: "setup\builds\unicows.dll"; DestDir: "{app}"; Flags: overwritereadonly replacesameversion restartreplace uninsremovereadonly sortfilesbyextension; MinVersion: 4.0,0
Source: "setup\builds\unicows.dll"; DestDir: "{app}\Plugins"; Flags: overwritereadonly replacesameversion restartreplace uninsremovereadonly sortfilesbyextension; MinVersion: 4.0,0

; Main files
Source: "setup\builds\zlibwapi.dll"; DestDir: "{app}\Plugins"; Flags: overwritereadonly replacesameversion uninsremovereadonly sortfilesbyextension deleteafterinstall
Source: "setup\builds\zlibwapi.dll"; DestDir: "{app}"; Flags: overwritereadonly replacesameversion restartreplace uninsremovereadonly sortfilesbyextension
Source: "setup\plugins\libgfl254.dll"; DestDir: "{app}\Plugins"; Flags: overwritereadonly replacesameversion uninsremovereadonly sortfilesbyextension deleteafterinstall
Source: "setup\plugins\libgfl254.dll"; DestDir: "{app}"; Flags: overwritereadonly replacesameversion restartreplace uninsremovereadonly sortfilesbyextension
Source: "setup\builds\Shareaza.exe"; DestDir: "{app}"; Flags: overwritereadonly replacesameversion restartreplace uninsremovereadonly sortfilesbyextension
#endif
Source: "setup\builds\skin.exe"; DestDir: "{app}"; Flags: overwritereadonly replacesameversion restartreplace uninsremovereadonly sortfilesbyextension
Source: "setup\builds\Shareaza.pdb"; DestDir: "{app}"; Flags: skipifsourcedoesntexist overwritereadonly replacesameversion restartreplace uninsremovereadonly sortfilesbyextension
#ifndef debug
Source: "Schemas\*"; DestDir: "{app}\Schemas"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension

; Set up data dir in {app}
Source: "Data\*.*"; DestDir: "{app}\Data"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Excludes: "*.bak"

; Copy repair installer
;Source: "setup\builds\repair.exe"; DestDir: "{app}\Uninstall"; Flags: overwritereadonly replacesameversion uninsremovereadonly sortfilesbyextension; Check: not WizardSilent

; Plugins
; Don't register RazaWebHook.dll since it will setup Shareaza as download manager
Source: "setup\plugins\*.dll"; DestDir: "{app}\Plugins"; Flags: overwritereadonly replacesameversion restartreplace uninsremovereadonly sortfilesbyextension regserver; Excludes: "RazaWebHook.dll,libgfl*.dll"; MinVersion: 0,4.0
Source: "setup\plugins\*.dll"; DestDir: "{app}\Plugins"; Flags: overwritereadonly replacesameversion uninsremovereadonly sortfilesbyextension regserver; Excludes: "RazaWebHook.dll,libgfl*.dll"; MinVersion: 4.0,0
Source: "setup\plugins\RazaWebHook.dll"; DestDir: "{app}\Plugins"; Flags: overwritereadonly replacesameversion restartreplace uninsremovereadonly sortfilesbyextension; MinVersion: 0,4.0
Source: "setup\plugins\RazaWebHook.dll"; DestDir: "{app}\Plugins"; Flags: overwritereadonly replacesameversion uninsremovereadonly sortfilesbyextension; MinVersion: 4.0,0
;Source: "setup\plugins\libgfl254.dll"; DestDir: "{app}\Plugins"; Flags: overwritereadonly replacesameversion restartreplace uninsremovereadonly sortfilesbyextension; MinVersion: 0,4.0
;Source: "setup\plugins\libgfl254.dll"; DestDir: "{app}\Plugins"; Flags: overwritereadonly replacesameversion uninsremovereadonly sortfilesbyextension; MinVersion: 4.0,0

; Uninstall icon for software panel
Source: "setup\misc\uninstall.ico"; DestDir: "{app}\Uninstall"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension

; Skins
Source: "Skins\Corona\*"; DestDir: "{app}\Skins\Corona"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension recursesubdirs; Excludes: ".svn"
Source: "Skins\Shareaza2\*"; DestDir: "{app}\Skins\Shareaza2"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension recursesubdirs; Excludes: ".svn"
Source: "Skins\ShareazaOS\*"; DestDir: "{app}\Skins\ShareazaOS"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension recursesubdirs; Excludes: ".svn"
Source: "Skins\BlueStreak\*"; DestDir: "{app}\Skins\BlueStreak"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension recursesubdirs; Excludes: ".svn"
Source: "Skins\Skin+\*"; DestDir: "{app}\Skins\Skin+"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension recursesubdirs; Excludes: ".svn"

; Templates
Source: "Templates\Audio Collection\*"; DestDir: "{app}\Templates\Audio Collection"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension recursesubdirs; Excludes: ".svn"
Source: "Templates\Basic Collection\*"; DestDir: "{app}\Templates\Basic Collection"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension recursesubdirs; Excludes: ".svn"
Source: "Templates\General Purple Collection\*"; DestDir: "{app}\Templates\General Purple Collection"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension recursesubdirs; Excludes: ".svn"
Source: "Templates\Video Collection\*"; DestDir: "{app}\Templates\Video Collection"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension recursesubdirs; Excludes: ".svn"

; Languages
Source: "Languages\*"; DestDir: "{app}\Skins\Languages"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension; Components: "language"; Excludes: "default-en.xml,*.bak"

; Copy skins back from {userappdata}\Shareaza\Skins
Source: "{userappdata}\Shareaza\Skins\*"; DestDir: "{app}\Skins"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist recursesubdirs; AfterInstall: DeleteFolder('{userappdata}\Shareaza\Skins')

; Copy templates back from {userappdata}\Shareaza\Templates
Source: "{userappdata}\Shareaza\Templates\*"; DestDir: "{app}\Templates"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist recursesubdirs; AfterInstall: DeleteFolder('{userappdata}\Shareaza\Templates')

; Switch user data between locations
Source: "{ini:{param:SETTINGS|},Locations,UserPath|{reg:HKCU\Software\Shareaza\Shareaza,UserPath|{userappdata}\Shareaza}}\Data\Library1.dat"; DestDir: "{userappdata}\Shareaza\Data"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist; Tasks: multiuser
Source: "{ini:{param:SETTINGS|},Locations,UserPath|{reg:HKCU\Software\Shareaza\Shareaza,UserPath|{userappdata}\Shareaza}}\Data\Library2.dat"; DestDir: "{userappdata}\Shareaza\Data"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist; Tasks: multiuser
Source: "{ini:{param:SETTINGS|},Locations,UserPath|{reg:HKCU\Software\Shareaza\Shareaza,UserPath|{userappdata}\Shareaza}}\Data\DownloadGroups.dat"; DestDir: "{userappdata}\Shareaza\Data"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist; Tasks: multiuser
Source: "{ini:{param:SETTINGS|},Locations,UserPath|{reg:HKCU\Software\Shareaza\Shareaza,UserPath|{userappdata}\Shareaza}}\Data\TigerTree.dat"; DestDir: "{userappdata}\Shareaza\Data"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist; Tasks: multiuser
Source: "{ini:{param:SETTINGS|},Locations,UserPath|{reg:HKCU\Software\Shareaza\Shareaza,UserPath|{userappdata}\Shareaza}}\Data\Security.dat"; DestDir: "{userappdata}\Shareaza\Data"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist; Tasks: multiuser
Source: "{ini:{param:SETTINGS|},Locations,UserPath|{reg:HKCU\Software\Shareaza\Shareaza,UserPath|{userappdata}\Shareaza}}\Data\UploadQueues.dat"; DestDir: "{userappdata}\Shareaza\Data"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist; Tasks: multiuser
Source: "{ini:{param:SETTINGS|},Locations,UserPath|{reg:HKCU\Software\Shareaza\Shareaza,UserPath|{userappdata}\Shareaza}}\Data\Searches.dat"; DestDir: "{userappdata}\Shareaza\Data"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist; Tasks: multiuser
Source: "{ini:{param:SETTINGS|},Locations,UserPath|{reg:HKCU\Software\Shareaza\Shareaza,UserPath|{userappdata}\Shareaza}}\Data\Schedule.dat"; DestDir: "{userappdata}\Shareaza\Data"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist; Tasks: multiuser
Source: "{ini:{param:SETTINGS|},Locations,UserPath|{reg:HKCU\Software\Shareaza\Shareaza,UserPath|{userappdata}\Shareaza}}\Data\Profile.xml"; DestDir: "{userappdata}\Shareaza\Data"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist; Tasks: multiuser
Source: "{ini:{param:SETTINGS|},Locations,Path|{reg:HKCU\Software\Shareaza\Shareaza,Path|{app}}}\Data\Library1.dat"; DestDir: "{userappdata}\Shareaza\Data"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist; Tasks: multiuser
Source: "{ini:{param:SETTINGS|},Locations,Path|{reg:HKCU\Software\Shareaza\Shareaza,Path|{app}}}\Data\Library2.dat"; DestDir: "{userappdata}\Shareaza\Data"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist; Tasks: multiuser
Source: "{ini:{param:SETTINGS|},Locations,Path|{reg:HKCU\Software\Shareaza\Shareaza,Path|{app}}}\Data\DownloadGroups.dat"; DestDir: "{userappdata}\Shareaza\Data"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist; Tasks: multiuser
Source: "{ini:{param:SETTINGS|},Locations,Path|{reg:HKCU\Software\Shareaza\Shareaza,Path|{app}}}\Data\TigerTree.dat"; DestDir: "{userappdata}\Shareaza\Data"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist; Tasks: multiuser
Source: "{ini:{param:SETTINGS|},Locations,Path|{reg:HKCU\Software\Shareaza\Shareaza,Path|{app}}}\Data\Security.dat"; DestDir: "{userappdata}\Shareaza\Data"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist; Tasks: multiuser
Source: "{ini:{param:SETTINGS|},Locations,Path|{reg:HKCU\Software\Shareaza\Shareaza,Path|{app}}}\Data\UploadQueues.dat"; DestDir: "{userappdata}\Shareaza\Data"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist; Tasks: multiuser
Source: "{ini:{param:SETTINGS|},Locations,Path|{reg:HKCU\Software\Shareaza\Shareaza,Path|{app}}}\Data\Searches.dat"; DestDir: "{userappdata}\Shareaza\Data"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist; Tasks: multiuser
Source: "{ini:{param:SETTINGS|},Locations,Path|{reg:HKCU\Software\Shareaza\Shareaza,Path|{app}}}\Data\Schedule.dat"; DestDir: "{userappdata}\Shareaza\Data"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist; Tasks: multiuser
Source: "{ini:{param:SETTINGS|},Locations,Path|{reg:HKCU\Software\Shareaza\Shareaza,Path|{app}}}\Data\Profile.xml"; DestDir: "{userappdata}\Shareaza\Data"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist; Tasks: multiuser

Source: "{ini:{param:SETTINGS|},Locations,Path|{reg:HKCU\Software\Shareaza\Shareaza,Path|{app}}}\Data\Library1.dat"; DestDir: "{app}\Data"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist; Tasks: not multiuser
Source: "{ini:{param:SETTINGS|},Locations,Path|{reg:HKCU\Software\Shareaza\Shareaza,Path|{app}}}\Data\Library2.dat"; DestDir: "{app}\Data"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist; Tasks: not multiuser
Source: "{ini:{param:SETTINGS|},Locations,Path|{reg:HKCU\Software\Shareaza\Shareaza,Path|{app}}}\Data\DownloadGroups.dat"; DestDir: "{app}\Data"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist; Tasks: not multiuser
Source: "{ini:{param:SETTINGS|},Locations,Path|{reg:HKCU\Software\Shareaza\Shareaza,Path|{app}}}\Data\TigerTree.dat"; DestDir: "{app}\Data"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist; Tasks: not multiuser
Source: "{ini:{param:SETTINGS|},Locations,Path|{reg:HKCU\Software\Shareaza\Shareaza,Path|{app}}}\Data\Security.dat"; DestDir: "{app}\Data"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist; Tasks: not multiuser
Source: "{ini:{param:SETTINGS|},Locations,Path|{reg:HKCU\Software\Shareaza\Shareaza,Path|{app}}}\Data\UploadQueues.dat"; DestDir: "{app}\Data"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist; Tasks: not multiuser
Source: "{ini:{param:SETTINGS|},Locations,Path|{reg:HKCU\Software\Shareaza\Shareaza,Path|{app}}}\Data\Searches.dat"; DestDir: "{app}\Data"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist; Tasks: not multiuser
Source: "{ini:{param:SETTINGS|},Locations,Path|{reg:HKCU\Software\Shareaza\Shareaza,Path|{app}}}\Data\Schedule.dat"; DestDir: "{app}\Data"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist; Tasks: not multiuser
Source: "{ini:{param:SETTINGS|},Locations,Path|{reg:HKCU\Software\Shareaza\Shareaza,Path|{app}}}\Data\Profile.xml"; DestDir: "{app}\Data"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist; Tasks: not multiuser
Source: "{ini:{param:SETTINGS|},Locations,UserPath|{reg:HKCU\Software\Shareaza\Shareaza,UserPath|{userappdata}\Shareaza}}\Data\Library1.dat"; DestDir: "{app}\Data"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist; Tasks: not multiuser
Source: "{ini:{param:SETTINGS|},Locations,UserPath|{reg:HKCU\Software\Shareaza\Shareaza,UserPath|{userappdata}\Shareaza}}\Data\Library2.dat"; DestDir: "{app}\Data"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist; Tasks: not multiuser
Source: "{ini:{param:SETTINGS|},Locations,UserPath|{reg:HKCU\Software\Shareaza\Shareaza,UserPath|{userappdata}\Shareaza}}\Data\DownloadGroups.dat"; DestDir: "{app}\Data"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist; Tasks: not multiuser
Source: "{ini:{param:SETTINGS|},Locations,UserPath|{reg:HKCU\Software\Shareaza\Shareaza,UserPath|{userappdata}\Shareaza}}\Data\TigerTree.dat"; DestDir: "{app}\Data"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist; Tasks: not multiuser
Source: "{ini:{param:SETTINGS|},Locations,UserPath|{reg:HKCU\Software\Shareaza\Shareaza,UserPath|{userappdata}\Shareaza}}\Data\Security.dat"; DestDir: "{app}\Data"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist; Tasks: not multiuser
Source: "{ini:{param:SETTINGS|},Locations,UserPath|{reg:HKCU\Software\Shareaza\Shareaza,UserPath|{userappdata}\Shareaza}}\Data\UploadQueues.dat"; DestDir: "{app}\Data"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist; Tasks: not multiuser
Source: "{ini:{param:SETTINGS|},Locations,UserPath|{reg:HKCU\Software\Shareaza\Shareaza,UserPath|{userappdata}\Shareaza}}\Data\Searches.dat"; DestDir: "{app}\Data"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist; Tasks: not multiuser
Source: "{ini:{param:SETTINGS|},Locations,UserPath|{reg:HKCU\Software\Shareaza\Shareaza,UserPath|{userappdata}\Shareaza}}\Data\Schedule.dat"; DestDir: "{app}\Data"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist; Tasks: not multiuser
Source: "{ini:{param:SETTINGS|},Locations,UserPath|{reg:HKCU\Software\Shareaza\Shareaza,UserPath|{userappdata}\Shareaza}}\Data\Profile.xml"; DestDir: "{app}\Data"; Flags: ignoreversion uninsremovereadonly sortfilesbyextension external onlyifdoesntexist skipifsourcedoesntexist; Tasks: not multiuser
#endif

; Copy installer into download and uninstall dir
;Source: "{srcexe}"; DestDir: "{ini:{param:SETTINGS|},Locations,CompletePath|{reg:HKCU\Software\Shareaza\Shareaza\Downloads,CompletePath|{userdocs}\Downloads}}"; DestName: "Shareaza_{#version}.exe"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension external onlyifdoesntexist; Tasks: multiuser
;Source: "{srcexe}"; DestDir: "{ini:{param:SETTINGS|},Locations,CompletePath|{reg:HKCU\Software\Shareaza\Shareaza\Downloads,CompletePath|{app}\Downloads}}"; DestName: "Shareaza_{#version}.exe"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension external onlyifdoesntexist; Tasks: not multiuser
Source: "{srcexe}"; DestDir: "{app}\Uninstall"; DestName: "setup.exe"; Flags: ignoreversion overwritereadonly uninsremovereadonly sortfilesbyextension external

[Icons]
; Shareaza icons
Name: "{userprograms}\{groupname}\Shareaza ({cm:icons_basicmode})"; Filename: "{app}\Shareaza.exe"; Parameters: "-basic"; WorkingDir: "{app}"; Comment: "{cm:reg_apptitle}"
Name: "{userprograms}\{groupname}\Shareaza ({cm:icons_tabbedmode})"; Filename: "{app}\Shareaza.exe"; Parameters: "-tabbed"; WorkingDir: "{app}"; Comment: "{cm:reg_apptitle}"
Name: "{userprograms}\{groupname}\Shareaza ({cm:icons_windowedmode})"; Filename: "{app}\Shareaza.exe"; Parameters: "-windowed"; WorkingDir: "{app}"; Comment: "{cm:reg_apptitle}"
Name: "{userdesktop}\Shareaza"; Filename: "{app}\Shareaza.exe"; WorkingDir: "{app}"; Comment: "{cm:reg_apptitle}"; Tasks: desktopicon
Name: "{userappdata}\Microsoft\Internet Explorer\Quick Launch\Shareaza"; Filename: "{app}\Shareaza.exe"; WorkingDir: "{app}"; Comment: "{cm:reg_apptitle}"; Tasks: quicklaunch

; Other icons in user language
Name: "{userprograms}\{groupname}\{cm:icons_license}"; Filename: "{app}\Uninstall\license.rtf"; WorkingDir: "{app}\Uninstall"; Comment: "{cm:icons_license}"
Name: "{userprograms}\{groupname}\{cm:icons_uninstall}"; Filename: "{uninstallexe}"; WorkingDir: "{app}\Uninstall"; Comment: "{cm:UninstallProgram,Shareaza}"; IconFilename: "{app}\Uninstall\uninstall.ico"
;Name: "{userprograms}\{groupname}\{cm:icons_downloads}"; Filename: "{ini:{param:SETTINGS|},Locations,CompletePath|{reg:HKCU\Software\Shareaza\Shareaza\Downloads,CompletePath|{userdocs}\Downloads}}"; WorkingDir: "{ini:{param:SETTINGS|},Locations,CompletePath|{reg:HKCU\Software\Shareaza\Shareaza\Downloads,CompletePath|{userappdata}\Shareaza\Downloads}}"; Comment: "{cm:icons_downloads}"; Tasks: multiuser; Check: not WizardNoIcons
;Name: "{userprograms}\{groupname}\{cm:icons_downloads}"; Filename: "{ini:{param:SETTINGS|},Locations,CompletePath|{reg:HKCU\Software\Shareaza\Shareaza\Downloads,CompletePath|{app}\Downloads}}"; WorkingDir: "{ini:{param:SETTINGS|},Locations,CompletePath|{reg:HKCU\Software\Shareaza\Shareaza\Downloads,CompletePath|{app}\Downloads}}"; Comment: "{cm:icons_downloads}"; Tasks: not multiuser; Check: not WizardNoIcons

[Messages]
; Overwrite standard ISL entries
; DO NOT use for localized messages
BeveledLabel=Shareaza Development Team
SetupAppTitle=Setup - Shareaza

[Run]
; Run the skin installer at end of installation
Filename: "{app}\skin.exe"; Parameters: "/installsilent"; WorkingDir: "{app}"; StatusMsg: "{cm:run_skinexe}"
; Run Shareaza at end of installation
Filename: "{app}\Shareaza.exe"; Description: "{cm:LaunchProgram,Shareaza}"; WorkingDir: "{app}"; Flags: postinstall skipifsilent nowait

[UninstallRun]
; Run the skin installer at start of uninstallation and make sure it only runs once
Filename: "{app}\skin.exe"; Parameters: "/uninstallsilent"; WorkingDir: "{app}"; StatusMsg: "{cm:run_skinexe}"; RunOnceId: "uninstallskinexe"

[Registry]
; Write installation path to registry
Root: HKLM; Subkey: "SOFTWARE\Shareaza"; ValueType: string; ValueName: ; ValueData: "{app}"; Flags: uninsdeletekey deletevalue
Root: HKCU; Subkey: "Software\Shareaza\Shareaza"; ValueType: string; ValueName: "Path" ; ValueData: "{app}"; Flags: uninsdeletekey deletevalue
Root: HKCU; Subkey: "Software\Shareaza\Shareaza"; ValueType: string; ValueName: "UserPath" ; ValueData: "{ini:{param:SETTINGS|},Locations,UserPath|{userappdata}\Shareaza}"; Flags: uninsdeletekey deletevalue ; Tasks: multiuser
Root: HKCU; Subkey: "Software\Shareaza\Shareaza"; ValueType: string; ValueName: "UserPath" ; ValueData: "{ini:{param:SETTINGS|},Locations,UserPath|{app}}"; Flags: uninsdeletekey deletevalue; Tasks: not multiuser
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Shareaza.exe"; ValueType: string; ValueName: ; ValueData: "{app}\Shareaza.exe"; Flags: uninsdeletekey deletevalue
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Shareaza.exe"; ValueType: string; ValueName: "Path"; ValueData: "{app}"; Flags: uninsdeletekey deletevalue

; Install chat notify sound
Root: HKCU; Subkey: "AppEvents\EventLabels\RAZA_IncomingChat"; ValueType: string; ValueName: ; ValueData: "{cm:reg_incomingchat}"; Flags: uninsdeletekey
Root: HKCU; Subkey: "AppEvents\Schemes\Apps\Shareaza"; ValueType: string; ValueName: ; ValueData: "{cm:reg_apptitle}"; Flags: uninsdeletekey
Root: HKCU; Subkey: "AppEvents\Schemes\Apps\Shareaza\RAZA_IncomingChat\.current"; ValueType: string; ValueName: ; ValueData: "%SystemRoot%\media\notify.wav"; Flags: uninsdeletekey
Root: HKCU; Subkey: "AppEvents\Schemes\Apps\Shareaza\RAZA_IncomingChat\.default"; ValueType: string; ValueName: ; ValueData: "%SystemRoot%\media\notify.wav"; Flags: uninsdeletekey

; Set directory locations
Root: HKCU; Subkey: "Software\Shareaza\Shareaza\Downloads"; ValueType: string; ValueName: "CompletePath"; ValueData: "{ini:{param:SETTINGS|},Locations,CompletePath|{userdocs}\Downloads}"; Flags: uninsdeletekey createvalueifdoesntexist; Tasks: multiuser
Root: HKCU; Subkey: "Software\Shareaza\Shareaza\Downloads"; ValueType: string; ValueName: "IncompletePath"; ValueData: "{ini:{param:SETTINGS|},Locations,IncompletePath|{localappdata}\Shareaza\Incomplete}"; Flags: uninsdeletekey createvalueifdoesntexist; Tasks: multiuser
Root: HKCU; Subkey: "Software\Shareaza\Shareaza\Downloads"; ValueType: string; ValueName: "TorrentPath"; ValueData: "{ini:{param:SETTINGS|},Locations,TorrentPath|{userappdata}\Shareaza\Torrents}"; Flags: uninsdeletekey createvalueifdoesntexist; Tasks: multiuser
Root: HKCU; Subkey: "Software\Shareaza\Shareaza\Downloads"; ValueType: string; ValueName: "CollectionPath"; ValueData: "{ini:{param:SETTINGS|},Locations,CollectionPath|{userappdata}\Shareaza\Collections}"; Flags: uninsdeletekey createvalueifdoesntexist; Tasks: multiuser
Root: HKCU; Subkey: "Software\Shareaza\Shareaza\Downloads"; ValueType: string; ValueName: "CompletePath"; ValueData: "{ini:{param:SETTINGS|},Locations,CompletePath|{app}\Downloads}"; Flags: uninsdeletekey createvalueifdoesntexist; Tasks: not multiuser
Root: HKCU; Subkey: "Software\Shareaza\Shareaza\Downloads"; ValueType: string; ValueName: "IncompletePath"; ValueData: "{ini:{param:SETTINGS|},Locations,IncompletePath|{app}\Incomplete}"; Flags: uninsdeletekey createvalueifdoesntexist; Tasks: not multiuser
Root: HKCU; Subkey: "Software\Shareaza\Shareaza\Downloads"; ValueType: string; ValueName: "TorrentPath"; ValueData: "{ini:{param:SETTINGS|},Locations,TorrentPath|{app}\Torrents}"; Flags: uninsdeletekey createvalueifdoesntexist; Tasks: not multiuser
Root: HKCU; Subkey: "Software\Shareaza\Shareaza\Downloads"; ValueType: string; ValueName: "CollectionPath"; ValueData: "{ini:{param:SETTINGS|},Locations,CollectionPath|{app}\Collections}"; Flags: uninsdeletekey createvalueifdoesntexist; Tasks: not multiuser

; Delete keys at uninstall
Root: HKLM; Subkey: "SOFTWARE\Shareaza"; Flags: dontcreatekey uninsdeletekey
Root: HKCU; Subkey: "Software\Shareaza"; Flags: dontcreatekey uninsdeletekey
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueName: "Shareaza"; Flags: dontcreatekey uninsdeletevalue
Root: HKCR; Subkey: ".co"; Flags: dontcreatekey uninsdeletekey
Root: HKCR; Subkey: ".collection"; Flags: dontcreatekey uninsdeletekey
Root: HKCR; Subkey: ".sks"; Flags: dontcreatekey uninsdeletekey
Root: HKCR; Subkey: "ed2k"; Flags: dontcreatekey uninsdeletekey
Root: HKCR; Subkey: "gnet"; Flags: dontcreatekey uninsdeletekey
Root: HKCR; Subkey: "gnutella"; Flags: dontcreatekey uninsdeletekey
Root: HKCR; Subkey: "magnet"; Flags: dontcreatekey uninsdeletekey
Root: HKCR; Subkey: "mp2p"; Flags: dontcreatekey uninsdeletekey
Root: HKCR; Subkey: "shareaza"; Flags: dontcreatekey uninsdeletekey
Root: HKCR; Subkey: "Shareaza.*"; Flags: dontcreatekey uninsdeletekey
Root: HKCR; Subkey: "Applications\shareaza.exe"; Flags: dontcreatekey uninsdeletekey
Root: HKCR; Subkey: "Applications\skin.exe"; Flags: dontcreatekey uninsdeletekey
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.sks"; Flags: dontcreatekey uninsdeletekey
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.torrent"; Flags: dontcreatekey uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\App Management\ARPCache\Shareaza_is1"; Flags: dontcreatekey uninsdeletekey
Root: HKCU; Subkey: "Software\Microsoft\Windows\ShellNoRoam\MUICache"; ValueName:"{app}\Shareaza.exe"; Flags: dontcreatekey uninsdeletevalue
Root: HKLM; Subkey: "SOFTWARE\Classes\.co"; Flags: dontcreatekey uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\Classes\.collection"; Flags: dontcreatekey uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\Classes\.sks"; Flags: dontcreatekey uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\Classes\bittorrent"; Flags: dontcreatekey uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\Classes\ed2k"; Flags: dontcreatekey uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\Classes\gnet"; Flags: dontcreatekey uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\Classes\gnutella"; Flags: dontcreatekey uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\Classes\magnet"; Flags: dontcreatekey uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\Classes\mp2p"; Flags: dontcreatekey uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\Classes\shareaza"; Flags: dontcreatekey uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\Classes\Applications\Shareaza.exe"; Flags: dontcreatekey uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\Classes\Applications\skin.exe"; Flags: dontcreatekey uninsdeletekey
Root: HKLM; Subkey: "SOFTWARE\Magnet"; Flags: dontcreatekey uninsdeletekey
Root: HKU; Subkey: ".DEFAULT\Software\Shareaza"; Flags: dontcreatekey uninsdeletekey
; How did we end up inhere?
Root: HKCU; Subkey: "Software\Intervideo\Common\AudioDec\Shareaza"; Flags: dontcreatekey uninsdeletekey

; Delete NSIS entry on software panel
Root: HKLM; Subkey: "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Shareaza"; Flags: dontcreatekey deletekey

; Clear version check key
Root: HKCU; Subkey: "Software\Shareaza\Shareaza\VersionCheck"; Flags: dontcreatekey deletekey
Root: HKLM; Subkey: "Software\Shareaza\Shareaza\VersionCheck"; Flags: dontcreatekey deletekey

; Delete Generic Video thumbnailer plugin
Root: HKCU; Subkey: "Software\Shareaza\Shareaza\Plugins"; ValueName: "{{17BF74FD-69AF-4BD5-A982-EA6DE6F3449C}"; Flags: dontcreatekey deletevalue
Root: HKCR; Subkey: "Shareaza.AVIThumb"; Flags: dontcreatekey deletekey
Root: HKCR; Subkey: "Shareaza.AVIThumb.1"; Flags: dontcreatekey deletekey
Root: HKCR; Subkey: "CLSID\{{17BF74FD-69AF-4BD5-A982-EA6DE6F3449C}"; Flags: dontcreatekey deletekey

; Create TorrentAid default dir locations
Root: HKCU; Subkey: "Software\TorrentAid\TorrentWizard\Folders"; ValueType: string; ValueName: "001.Path"; ValueData: "{userappdata}\Shareaza\Torrents"; Flags: createvalueifdoesntexist; Tasks: multiuser
Root: HKCU; Subkey: "Software\TorrentAid\TorrentWizard\Folders"; ValueType: string; ValueName: "Last"; ValueData: "{userappdata}\Shareaza\Torrents"; Flags: createvalueifdoesntexist; Tasks: multiuser
Root: HKCU; Subkey: "Software\TorrentAid\TorrentWizard\Folders"; ValueType: string; ValueName: "001.Path"; ValueData: "{app}\Torrents"; Flags: createvalueifdoesntexist; Tasks: not multiuser
Root: HKCU; Subkey: "Software\TorrentAid\TorrentWizard\Folders"; ValueType: string; ValueName: "Last"; ValueData: "{app}\Torrents"; Flags: createvalueifdoesntexist; Tasks: not multiuser

[Dirs]
; Make incomplete, torrent and collection dir
; Note: download dir will be created when installer is copied
Name: "{ini:{param:SETTINGS|},Locations,IncompletePath|{reg:HKCU\Software\Shareaza\Shareaza\Downloads,IncompletePath|{localappdata}\Shareaza\Incomplete}}"; Flags: uninsalwaysuninstall; Tasks: multiuser
Name: "{ini:{param:SETTINGS|},Locations,TorrentPath|{reg:HKCU\Software\Shareaza\Shareaza\Downloads,TorrentPath|{userappdata}\Shareaza\Torrents}}"; Flags: uninsalwaysuninstall; Tasks: multiuser
Name: "{ini:{param:SETTINGS|},Locations,CollectionPath|{reg:HKCU\Software\Shareaza\Shareaza\Downloads,CollectionPath|{userappdata}\Shareaza\Collections}}"; Flags: uninsalwaysuninstall; Tasks: multiuser
Name: "{ini:{param:SETTINGS|},Locations,IncompletePath|{reg:HKCU\Software\Shareaza\Shareaza\Downloads,IncompletePath|{app}\Incomplete}}"; Flags: uninsalwaysuninstall; Tasks: not multiuser
Name: "{ini:{param:SETTINGS|},Locations,TorrentPath|{reg:HKCU\Software\Shareaza\Shareaza\Downloads,TorrentPath|{app}\Torrents}}"; Flags: uninsalwaysuninstall; Tasks: not multiuser
Name: "{ini:{param:SETTINGS|},Locations,CollectionPath|{reg:HKCU\Software\Shareaza\Shareaza\Downloads,CollectionPath|{app}\Collections}}"; Flags: uninsalwaysuninstall; Tasks: not multiuser
Name: "{userappdata}\Shareaza\Data"; Flags: uninsalwaysuninstall; Tasks: multiuser


[InstallDelete]
; Clean up old files from Shareaza
Type: files; Name: "{app}\Shareaza.pdb"
Type: files; Name: "{app}\zlib.dll"
Type: files; Name: "{app}\zlib1.dll"
Type: files; Name: "{app}\Plugins\zlib.dll"
Type: files; Name: "{app}\Plugins\zlib1.dll"
Type: files; Name: "{app}\LICENSE.txt"
Type: files; Name: "{app}\uninstall.exe"
Type: files; Name: "{app}\Uninstall\repair.exe"
Type: files; Name: "{app}\Plugins\DivFix.dll"
Type: files; Name: "{app}\Plugins\libgfl240.dll"
Type: files; Name: "{app}\Skins\skin.exe"
Type: files; Name: "{app}\*.dat"
Type: files; Name: "{app}\*.xml"
Type: files; Name: "{app}\*.png"
Type: files; Name: "{app}\*.bmp"
Type: filesandordirs; Name: "{userappdata}\Shareaza\Remote"
Type: filesandordirs; Name: "{userappdata}\Shareaza\Schemas"
Type: files; Name: "{userappdata}\Shareaza\Data\DefaultAvatar.png"
Type: files; Name: "{app}\Skins\Languages\default-es-mx.xml"
Type: files; Name: "{app}\Skins\Languages\default-es-mx.ico"
Type: files; Name: "{app}\Skins\Languages\default-en.xml"

; Old japanese Translation code used to be "jp" but now it is "ja"
Type: files; Name: "{app}\Skins\Languages\default-jp.ico"
Type: files; Name: "{app}\Skins\Languages\default-jp.xml"

; Clean up old Shareaza icons
Type: files; Name: "{userdesktop}\Start Shareaza.lnk"; Check: NSISUsed
Type: files; Name: "{userdesktop}\Shareaza.lnk"; Tasks: not desktopicon
Type: filesandordirs; Name: "{userprograms}\Shareaza"; Check: NSISUsed
Type: filesandordirs; Name: "{userprograms}\{reg:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Shareaza_is1,Inno Setup: Icon Group|{groupname}}"; Check: InnoSetupUsed
Type: files; Name: "{userappdata}\Microsoft\Internet Explorer\Quick Launch\Shareaza.lnk"; Tasks: not quicklaunch

; Delete extra components so installer can "uninstall" them
Type: filesandordirs; Name: "{app}\Remote"
Type: filesandordirs; Name: "{app}\Skins\Languages"; Components: not language
Type: filesandordirs; Name: "{userappdata}\Shareaza\Skins\Languages"; Components: not language

; Delete old Shareaza installers
;Type: files; Name: "{ini:{param:SETTINGS|},Locations,CompletePath|{reg:HKCU\Software\Shareaza\Shareaza\Downloads,CompletePath|{userdocs}\Downloads}}\Shareaza*.exe"; Tasks: deleteoldsetup and multiuser
;Type: files; Name: "{ini:{param:SETTINGS|},Locations,CompletePath|{reg:HKCU\Software\Shareaza\Shareaza\Downloads,CompletePath|{app}\Downloads}}\Shareaza*.exe"; Tasks: deleteoldsetup and not multiuser

; Delete Discovery.dat because of G1 problems (remove in some future)
Type: files; Name: "{app}\Data\Discovery.dat"
Type: files; Name: "{userappdata}\Shareaza\Data\Discovery.dat"; Tasks: multiuser

[UninstallDelete]
; Clean up files created after installation
Type: filesandordirs; Name: "{app}\Data"
Type: filesandordirs; Name: "{userappdata}\Shareaza\Data"
Type: filesandordirs; Name: "{app}\Skins"
Type: filesandordirs; Name: "{app}\Templates"

; Pull in languages and localized files
#include "languages.iss"
; Pull in Shareaza settings to write to registry
#include "settings.iss"

; Code sections need to be the last section in a script or the compiler will get confused
[Code]
type
  SERVICE_STATUS = record
    dwServiceType: cardinal;
    dwCurrentState: cardinal;
    dwControlsAccepted: cardinal;
    dwWin32ExitCode: cardinal;
    dwServiceSpecificExitCode: cardinal;
    dwCheckPoint: cardinal;
    dwWaitHint: cardinal;
  end;
  HANDLE = cardinal;
const
  WM_CLOSE = $0010;
  KeyLoc1 = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Shareaza_is1';
  KeyLoc2 = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Shareaza';
  KeyName = 'UninstallString';
  NET_FW_SCOPE_ALL = 0;
  NET_FW_IP_VERSION_ANY       = 2;
  SERVICE_QUERY_CONFIG        = $1;
  SERVICE_CHANGE_CONFIG       = $2;
  SERVICE_QUERY_STATUS        = $4;
  SERVICE_START               = $10;
  SERVICE_STOP                = $20;
  SERVICE_ALL_ACCESS          = $f01ff;
  SC_MANAGER_ALL_ACCESS       = $f003f;
  SERVICE_AUTO_START          = $2;
  SERVICE_DEMAND_START        = $3;
  SERVICE_RUNNING             = $4;
  SERVICE_NO_CHANGE           = $ffffffff;
var
  CurrentPath: string;
  Installed: Boolean;
  FirewallFailed: string;
  HasUserPrivileges: Boolean;

// NT API functions for services
Function OpenSCManager(lpMachineName, lpDatabaseName: string; dwDesiredAccess: cardinal): HANDLE;
external 'OpenSCManagerA@advapi32.dll stdcall setuponly';

Function OpenService(hSCManager: HANDLE; lpServiceName: string; dwDesiredAccess: cardinal): HANDLE;
external 'OpenServiceA@advapi32.dll stdcall setuponly';

Function CloseServiceHandle(hSCObject: HANDLE): Boolean;
external 'CloseServiceHandle@advapi32.dll stdcall setuponly';

Function StartNTService(hService: HANDLE; dwNumServiceArgs: cardinal; lpServiceArgVectors: cardinal): Boolean;
external 'StartServiceA@advapi32.dll stdcall setuponly';

Function QueryServiceStatus(hService: HANDLE; var ServiceStatus: SERVICE_STATUS): Boolean;
external 'QueryServiceStatus@advapi32.dll stdcall setuponly';

Function ChangeServiceConfig(hService: HANDLE; dwServiceType, dwStartType, dwErrorControl: cardinal;
                             lpBinaryPathName, lpLoadOrderGroup: string; lpdwTagId: cardinal;
                             lpDependencies, lpServiceStartName, lpPassword, lpDisplayName: string): Boolean;
external 'ChangeServiceConfigA@advapi32.dll stdcall setuponly';

Function InnoSetupUsed(): boolean;
Begin
    Result := RegKeyExists(HKEY_LOCAL_MACHINE, KeyLoc1);
End;

Function NSISUsed(): boolean;
Begin
    Result := RegKeyExists(HKEY_LOCAL_MACHINE, KeyLoc2);
End;

// check if the current install path exists
Function DoesPathExist(): boolean;
Begin
    if RegQueryStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Shareaza','', CurrentPath) then
        Result := DirExists(CurrentPath)
    else
        Result := False;

End;

Function OpenServiceManager(): HANDLE;
begin
  Result := 0;
  if (InstallOnThisVersion('0,5.01', '0,0') = irInstall) then
    Result := OpenSCManager('', 'ServicesActive', SC_MANAGER_ALL_ACCESS);
end;

Function CanUserModifyServices(): Boolean;
var
 hSCManager: HANDLE;
begin
  hSCManager := 0;
  Result := false;
  HasUserPrivileges := false;
  if (InstallOnThisVersion('0,5.01', '0,0') = irInstall) then begin
    hSCManager := OpenSCManager('', 'ServicesActive', SC_MANAGER_ALL_ACCESS);
    if (hSCManager <> 0) then begin
      HasUserPrivileges := true;
      Result := true;
      CloseServiceHandle(hSCManager);
    end;
  end;
end;

Function IsServiceInstalled(ServiceName: string): boolean;
var
 hSCManager: HANDLE;
 hService: HANDLE;
begin
  hSCManager := OpenServiceManager();
  Result := false;
  if (hSCManager <> 0) then begin
    hService := OpenService(hSCManager, ServiceName, SERVICE_QUERY_CONFIG);
    if (hService <> 0) then begin
      Result := true;
      CloseServiceHandle(hService);
    end;
    CloseServiceHandle(hSCManager);
  end;
end;

Function StartService(ServiceName: string): boolean;
var
  hSCManager: HANDLE;
  hService: HANDLE;
begin
  hSCManager := OpenServiceManager();
  Result := false;
  if (hSCManager <> 0) then begin
    hService := OpenService(hSCManager, ServiceName, SERVICE_START);
    if (hService <> 0) then begin
      Result := StartNTService(hService, 0, 0);
      CloseServiceHandle(hService);
    end;
    CloseServiceHandle(hSCManager);
  end;
end;

Function IsServiceRunning(ServiceName: string): boolean;
var
  hSCManager: HANDLE;
  hService: HANDLE;
  sStatus: SERVICE_STATUS;
begin
  hSCManager := OpenServiceManager();
  Result := false;
  if (hSCManager <> 0) then begin
    hService := OpenService(hSCManager, ServiceName, SERVICE_QUERY_STATUS);
    if (hService <> 0) then begin
      if (QueryServiceStatus(hService, sStatus)) then
        Result := (sStatus.dwCurrentState = SERVICE_RUNNING)
      CloseServiceHandle(hService);
    end;
    CloseServiceHandle(hSCManager);
 end;
end;

Function ChangeServiceStartup(ServiceName: string; dwStartType: cardinal): boolean;
var
  hSCManager: HANDLE;
  hService: HANDLE;
begin
  hSCManager := OpenServiceManager();
  Result := false;
  if (hSCManager <> 0) then begin
    hService := OpenService(hSCManager, ServiceName, SERVICE_CHANGE_CONFIG);
    if (hService <> 0) then begin
       Result := ChangeServiceConfig(hService, SERVICE_NO_CHANGE, dwStartType, SERVICE_NO_CHANGE, '','',0,'','','','');
       CloseServiceHandle(hService);
    end;
    CloseServiceHandle(hSCManager);
  end;
end;

Function NextButtonClick(CurPageID: integer): Boolean;
var
  Wnd: HWND;
  Shutdownmessage: string;
begin
  Result := True;
  if (CurPageID = wpWelcome) then begin
    Wnd := FindWindowByClassName('ShareazaMainWnd');
    if Wnd <> 0 then begin
      Shutdownmessage := ExpandConstant('{cm:dialog_shutdown,Shareaza}');
      if MsgBox(Shutdownmessage, mbConfirmation, MB_OKCANCEL) = IDOK then begin
        SendMessage(Wnd, WM_CLOSE, 0, 0);
        while Wnd <> 0 do begin
          Sleep(100);
          Wnd := FindWindowByClassName('ShareazaMainWnd');
        end;
      end else Result := False;
    end;
  end;
end;

Function InitializeSetup: Boolean;
Begin
  Result := True;
  Installed := (RegValueExists(HKEY_LOCAL_MACHINE, KeyLoc1, KeyName) or RegValueExists(HKEY_LOCAL_MACHINE, KeyLoc2, KeyName)) and DoesPathExist();
End;

Function EnableDeleteOldSetup: Boolean;
Begin
  Result := Installed;
End;

Function WeOwnTorrentAssoc: boolean;
var
  CommandString: string;
  Position: Integer;
Begin
  Result := False;
  if RegQueryStringValue(HKEY_CLASSES_ROOT, 'bittorrent\shell\open\command','', CommandString) then
    Begin
      Position := Pos('shareaza.exe', LowerCase(CommandString));
      Result := (Position > 0);
    End
End;

Function ShouldSkipPage(PageID: Integer): Boolean;
Begin
  Result := False;
  if PageID = wpSelectDir then Result := Installed;
End;

Procedure DeleteFolder(Param: String);
var
  Foldername: string;
Begin
  Foldername := ExpandConstant(Param);
  DelTree(Foldername, True, True, True);
End;

Procedure DeleteFile(Param: String);
var
  Filename: string;
Begin
  Filename := ExpandConstant(Param);
  DelayDeleteFile(Filename,3);
End;

Procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  InstallFolder: string;
  FirewallManager: Variant;
  FirewallProfile: Variant;
  Wnd: HWND;
Begin
  if CurUninstallStep = usUninstall then begin
    if InstallOnThisVersion('0,5.01sp2','0,0') = irInstall then begin
      try
        InstallFolder := ExpandConstant('{app}\Shareaza.exe');
        FirewallManager := CreateOleObject('HNetCfg.FwMgr');
        FirewallProfile := FirewallManager.LocalPolicy.CurrentProfile;
        FirewallProfile.AuthorizedApplications.Remove(InstallFolder);
      except
      End;
    End;
    Wnd := FindWindowByClassName('ShareazaMainWnd');
    if Wnd <> 0 then begin
      SendMessage(Wnd, WM_CLOSE, 0, 0);
      while Wnd <> 0 do
        begin
          Sleep(100);
          Wnd := FindWindowByClassName('ShareazaMainWnd');
        End;
    End;
    if WeOwnTorrentAssoc then begin
      RegDeleteKeyIncludingSubkeys(HKEY_CLASSES_ROOT,'.torrent');
      RegDeleteKeyIncludingSubkeys(HKEY_CLASSES_ROOT,'bittorrent');
    End;
  End;
End;

Function IsLanguageRTL(LangCode: String): String;
Begin
  if ( (LangCode = 'heb') or (LangCode = 'ar') ) then
    Result := '1'
  else
    Result := '0';
End;

Function GetRelFilePath(LangCode: String): String;
Begin
  if ( (LangCode = 'br') or (LangCode = 'pt') ) then
    Result := 'Languages\default-pt-br.xml'
  else if ( LangCode = 'sl' ) then
    Result := 'Languages\default-sl-SI.xml'
  else
    Result := 'Languages\default-' + LangCode + '.xml';
End;

Function ResetLanguages: boolean;
var
  Names: TArrayOfString;
  I: Integer;
  S: String;
  Value: String;
begin
  if RegGetValueNames(HKEY_CURRENT_USER, 'Software\Shareaza\Shareaza\Skins', Names) then
  begin
    S := '';
    Value := LowerCase(GetRelFilePath(ExpandConstant('{language}')));
    for I := 0 to GetArrayLength(Names)-1 do
    begin
      S := LowerCase(Names[I]);
      if Pos('languages', S) <> 0 then
        if Value <> S then
          RegWriteDWordValue(HKEY_CURRENT_USER, 'Software\Shareaza\Shareaza\Skins', S, 0);
    end;
    RegWriteDWordValue(HKEY_CURRENT_USER, 'Software\Shareaza\Shareaza\Skins', Value, 1);
    Value := IsLanguageRTL(ExpandConstant('{language}'));
    RegWriteDWordValue(HKEY_CURRENT_USER, 'Software\Shareaza\Shareaza\Settings', 'LanguageRTL', StrToInt(Value));
    RegWriteStringValue(HKEY_CURRENT_USER, 'Software\Shareaza\Shareaza\Settings', 'Language', ExpandConstant('{language}'));
  end;
  Result := True;
end;

Procedure CurStepChanged(CurStep: TSetupStep);
var
  InstallFolder: string;
  FirewallObject: Variant;
  FirewallManager: Variant;
  FirewallProfile: Variant;
  Reset: boolean;
  Success: boolean;
Begin
  if CurStep=ssPostInstall then begin
    if IsTaskSelected('firewall') then begin
      if WizardSilent = True then begin
        try
          FirewallObject := CreateOleObject('HNetCfg.FwAuthorizedApplication');
          InstallFolder := ExpandConstant('{app}\Shareaza.exe');
          FirewallObject.ProcessImageFileName := InstallFolder;
          FirewallObject.Name := 'Shareaza';
          FirewallObject.Scope := NET_FW_SCOPE_ALL;
          FirewallObject.IpVersion := NET_FW_IP_VERSION_ANY;
          FirewallObject.Enabled := True;
          FirewallManager := CreateOleObject('HNetCfg.FwMgr');
          FirewallProfile := FirewallManager.LocalPolicy.CurrentProfile;
          FirewallProfile.AuthorizedApplications.Add(FirewallObject);
        except
        End;
      End else begin
        FirewallFailed := ExpandConstant('{cm:dialog_firewall}')
        try
          FirewallObject := CreateOleObject('HNetCfg.FwAuthorizedApplication');
          InstallFolder := ExpandConstant('{app}\Shareaza.exe');
          FirewallObject.ProcessImageFileName := InstallFolder;
          FirewallObject.Name := 'Shareaza';
          FirewallObject.Scope := NET_FW_SCOPE_ALL;
          FirewallObject.IpVersion := NET_FW_IP_VERSION_ANY;
          FirewallObject.Enabled := True;
          FirewallManager := CreateOleObject('HNetCfg.FwMgr');
          FirewallProfile := FirewallManager.LocalPolicy.CurrentProfile;
          FirewallProfile.AuthorizedApplications.Add(FirewallObject);
        except
          MsgBox(FirewallFailed, mbInformation, MB_OK);
        End;
      End;
    End;
    if IsTaskSelected('upnp') then begin
      if (HasUserPrivileges) then begin
        Success := false;
        if (IsServiceInstalled('SSDPSRV') and IsServiceInstalled('upnphost')) then begin
          if (not IsServiceRunning('SSDPSRV')) then begin
            // change the startup type to manual if it was disabled;
            // we don't need to start it since UPnP Device Host service depends on it;
            // assuming that user didn't modify the dependencies manually.
            // Note: probably, we could elevate user rights with AdjustTokenPrivileges(?)
            Success := ChangeServiceStartup('SSDPSRV', SERVICE_DEMAND_START);
          end else
            Success := true;
          if (Success) then begin
            // We succeeded to change the startup type, so we will change another service
            Success := ChangeServiceStartup('upnphost', SERVICE_AUTO_START);
            if (Success and not IsServiceRunning('upnphost')) then
              StartService('upnphost');
          end;
        end;
      end;
    end;
  End;
  if CurStep=ssInstall then begin
    if not IsTaskSelected('firewall') then begin
      if InstallOnThisVersion('0,5.01sp2','0,0') = irInstall then begin
        try
          InstallFolder := ExpandConstant('{app}\Shareaza.exe');
          FirewallManager := CreateOleObject('HNetCfg.FwMgr');
          FirewallProfile := FirewallManager.LocalPolicy.CurrentProfile;
          FirewallProfile.AuthorizedApplications.Remove(InstallFolder);
        except
        End;
      End;
    End;
  End;
  if CurStep=ssDone then Reset := ResetLanguages;
End;

{ Pull in custom wizard pages }
#include "pages.iss"

#expr SaveToFile("..\builds\Preprocessed.iss")