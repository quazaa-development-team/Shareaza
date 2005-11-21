/*
This software is released into the public domain.  You are free to 
redistribute and modify without any restrictions with the exception of
the following:

The Zlib library is Copyright (C) 1995-2002 Jean-loup Gailly and Mark Adler.
The Unzip library is Copyright (C) 1998-2003 Gilles Vollant.
*/
#include "skin.h"

// globals
int   skinType;
TCHAR* szName;
TCHAR* szVersion;
TCHAR* szAuthor;
TCHAR* szXML;
TCHAR* prefix[MAX_PATH];
BOOL  bRunningOnNT;

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE hPrevInst, LPCTSTR cmdParam, int cmdShow) {
	InitCommonControls();

	// globals
	skinType  = 0;
	szName    = NULL;
	szVersion = NULL;
	szAuthor  = NULL;
	szXML     = NULL;
	bRunningOnNT = ( ( GetVersion() & 0x80000000 ) != 0x80000000 );
    
	if (wcslen(cmdParam)==0) MessageBox(NULL,L"Shareaza Skin Installer " VERSION L"\n\nDouble-click on a Shareaza Skin File to use the Shareaza Skin Installer.",L"Shareaza Skin Installer",MB_OK | MB_ICONINFORMATION);
	else if (!wcscmp(cmdParam, L"/install") || !wcscmp(cmdParam, L"/installsilent")) CreateSkinKeys();
	else if (!wcscmp(cmdParam, L"/uninstall") || !wcscmp(cmdParam, L"/uninstallsilent")) DeleteSkinKeys();
	else ExtractSkinFile(cmdParam);
	
	// free up memory from globals
	if (szName) free(szName);
	if (szVersion) free(szVersion);
	if (szAuthor) free(szAuthor);
	if (szXML) free(szXML);
	return 0;
}
