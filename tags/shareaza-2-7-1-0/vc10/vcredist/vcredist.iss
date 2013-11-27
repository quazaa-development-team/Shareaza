; Installing Visual Studio 2010 C++ CRT Libraries
; http://download.microsoft.com/download/C/6/D/C6D0FD4E-9E53-4897-9B91-836EBA2AACD3/vcredist_x86.exe
; http://download.microsoft.com/download/A/8/0/A80747C3-41BD-45DF-B505-E9710D2744E0/vcredist_x64.exe

[Files]
#if PlatformName == "Win32"
  Source: "vc10\vcredist\vcredist_x86.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall; AfterInstall: ExecTemp( 'vcredist_x86.exe', '/passive /promptrestart' );
#else
  Source: "vc10\vcredist\vcredist_x64.exe"; DestDir: "{tmp}"; Flags: deleteafterinstall; AfterInstall: ExecTemp( 'vcredist_x64.exe', '/passive /promptrestart' );
#endif

[Code]
procedure ExecTemp(File, Params : String);
var
	nCode: Integer;
begin
	Exec( ExpandConstant( '{tmp}' ) + '\' + File, Params, ExpandConstant( '{tmp}' ), SW_SHOW, ewWaitUntilTerminated, nCode );
end;
