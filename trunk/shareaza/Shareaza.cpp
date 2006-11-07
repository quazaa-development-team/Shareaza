//
// Shareaza.cpp
//
// Copyright (c) Shareaza Development Team, 2002-2006.
// This file is part of SHAREAZA (www.shareaza.com)
//
// Shareaza is free software; you can redistribute it
// and/or modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2 of
// the License, or (at your option) any later version.
//
// Shareaza is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Shareaza; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
//

#include "StdAfx.h"
#include "Shareaza.h"
#include "Settings.h"
#include "CoolInterface.h"
#include "Network.h"
#include "Firewall.h"
#include "UPnPFinder.h"
#include "Security.h"
#include "HostCache.h"
#include "DiscoveryServices.h"
#include "VersionChecker.h"
#include "SchemaCache.h"
#include "VendorCache.h"
#include "EDClients.h"
#include "BTClients.h"
#include "Library.h"
#include "Transfers.h"
#include "DownloadGroups.h"
#include "Downloads.h"
#include "Uploads.h"
#include "UploadQueues.h"
#include "QueryHashMaster.h"
#include "DDEServer.h"
#include "IEProtocol.h"
#include "ShareazaURL.h"
#include "GProfile.h"
#include "SharedFile.h"
#include "Emoticons.h"
#include "ShellIcons.h"
#include "Skin.h"
#include "Scheduler.h"
#include "FileExecutor.h"

#include "WndMain.h"
#include "WndSystem.h"
#include "DlgSplash.h"
#include "DlgHelp.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

BEGIN_MESSAGE_MAP(CShareazaApp, CWinApp)
	//{{AFX_MSG_MAP(CShareazaApp)
	//}}AFX_MSG
END_MESSAGE_MAP()

CShareazaApp theApp;

/////////////////////////////////////////////////////////////////////////////
// CShareazaApp construction

CShareazaApp::CShareazaApp()
{
	m_pMutex = NULL;
	m_pSafeWnd	= NULL;
	m_bLive		= FALSE;
	m_bUPnPPortsForwarded = TS_UNKNOWN;
	m_bUPnPDeviceConnected = TS_UNKNOWN;
}

/////////////////////////////////////////////////////////////////////////////
// CShareazaApp initialization

BOOL CShareazaApp::InitInstance()
{
	CWaitCursor pCursor;

	SetRegistryKey( _T("Shareaza") );
	GetVersionNumber();
	InitResources();

	EnableShellOpen();

	AfxOleInit();
	AfxEnableControlContainer();

	m_pMutex = CreateMutex( NULL, FALSE,
		( m_dwWindowsVersion < 5 ) ? _T("Shareaza") : _T("Global\\Shareaza") );
	if ( m_pMutex != NULL )
	{
		if ( GetLastError() == ERROR_ALREADY_EXISTS )
		{
			CloseHandle( m_pMutex );
			m_pMutex = NULL;

			// Popup first instance
			if ( CWnd* pWnd = CWnd::FindWindow( _T("ShareazaMainWnd"), NULL ) )
			{
				pWnd->SendMessage( WM_SYSCOMMAND, SC_RESTORE );
				pWnd->ShowWindow( SW_SHOWNORMAL );
				pWnd->BringWindowToTop();
				pWnd->SetForegroundWindow();
			}
			else
			{
				// Probably window created in another user's session
			}
			return FALSE;
		}
		// We are first!
	}
	else
	{
		// Probably mutex created in another user's session
		return FALSE;
	}

	DDEServer.Create();
	IEProtocol.Create();

	// Set Build Date
	COleDateTime tCompileTime; 
	tCompileTime.ParseDateTime( _T(__DATE__), LOCALE_NOUSEROVERRIDE, 1033 );
	m_sBuildDate = tCompileTime.Format( _T("%Y%m%d") );
	
	// ***********
	// Beta expiry. Remember to re-compile to update the time, and remove this 
	// section for final releases and public betas.
	COleDateTime tCurrent = COleDateTime::GetCurrentTime();
	COleDateTimeSpan tTimeOut( 28, 0, 0, 0);
	if ( ( tCompileTime + tTimeOut )  < tCurrent )
	{
		CString strMessage;
		LoadString( strMessage, IDS_BETA_EXPIRED);
		AfxMessageBox( strMessage, MB_SYSTEMMODAL|MB_ICONQUESTION|MB_OK );
		//return FALSE;
	}

	// Alpha warning. Remember to remove this section for final releases and public betas.
	if ( AfxMessageBox( 
		L"WARNING: This is an ALPHA TEST version of Shareaza.\n\n"
		L"It is NOT FOR GENERAL USE, and is only for testing specific features in a controlled "
		L"environment. It will frequently stop running, or display debug information to assist testing.\n\n"
		L"If you wish to actually use this software, you should download "
		L"the current stable release from www.shareaza.com\n"
		L"If you continue past this point, you may experience system instability, lose downloads, "
		L"or corrupt system files. Corrupted downloads/files may not be recoverable. "
		L"Do you wish to continue?", MB_SYSTEMMODAL|MB_ICONEXCLAMATION|MB_YESNO ) == IDNO )
		return FALSE;

	// ***********
	
	BOOL bSilentTray = ( m_lpCmdLine && _tcsistr( m_lpCmdLine, _T("-tray") ) != NULL );
	
	CSplashDlg* dlgSplash = new CSplashDlg( 18, bSilentTray );

	dlgSplash->Step( _T("Winsock") );
		WSADATA wsaData;
		if ( WSAStartup( 0x0101, &wsaData ) ) return FALSE;
	
	dlgSplash->Step( _T("Settings Database") );
		Settings.Load();

	if ( m_lpCmdLine )
	{
		if ( _tcsistr( m_lpCmdLine, _T("-basic") ) != NULL )
			Settings.General.GUIMode = GUI_BASIC;
		else if ( _tcsistr( m_lpCmdLine, _T("-tabbed") ) != NULL )
			Settings.General.GUIMode = GUI_TABBED;
		else if ( _tcsistr( m_lpCmdLine, _T("-windowed") ) != NULL )
			Settings.General.GUIMode = GUI_WINDOWED;
	}

	dlgSplash->Step( _T("Firewall/Router Setup") );
	{
		CFirewall firewall;
		if ( firewall.AccessWindowsFirewall() && firewall.AreExceptionsAllowed() )
		{
			// Add to firewall exception list if necessary
			// and enable UPnP Framework if disabled
			CString strBinaryPath;
			GetModuleFileName( NULL, strBinaryPath.GetBuffer( MAX_PATH ), MAX_PATH );
			strBinaryPath.ReleaseBuffer( MAX_PATH );
			firewall.SetupService( NET_FW_SERVICE_UPNP );
			firewall.SetupProgram( strBinaryPath, theApp.m_pszAppName );
		}
	}
	// We will run the UPnP discovery in the QuickStart Wizard
	if ( Settings.Connection.EnableUPnP && !Settings.Live.FirstRun )
	{
		try
		{
			m_pUPnPFinder.reset( new CUPnPFinder );
			if ( m_pUPnPFinder->AreServicesHealthy() )
				m_pUPnPFinder->StartDiscovery();
		}
		catch ( CUPnPFinder::UPnPError& ) {}
		catch ( CException* e ) { e->Delete(); }
	}

	dlgSplash->Step( _T("P2P URIs") );
		CShareazaURL::Register( TRUE );
	dlgSplash->Step( _T("Shell Icons") );
		ShellIcons.Clear();
	dlgSplash->Step( _T("Metadata Schemas") );
		SchemaCache.Load();
	dlgSplash->Step( _T("Vendor Data") );
		VendorCache.Load();
	dlgSplash->Step( _T("Profile") );
		MyProfile.Load();
	dlgSplash->Step( _T("Library") );
		Library.Load();
	dlgSplash->Step( _T("Query Manager") );
		QueryHashMaster.Create();
	dlgSplash->Step( _T("Host Cache") );
		HostCache.Load();
	dlgSplash->Step( _T("Discovery Services") );
		DiscoveryServices.Load();
	dlgSplash->Step( _T("Security Services") );
		Security.Load();
		AdultFilter.Load();
		MessageFilter.Load();
	dlgSplash->Step( _T("Scheduler") );
		Schedule.Load();
	dlgSplash->Step( _T("Rich Documents") );
		Emoticons.Load();
	dlgSplash->Step( _T("GUI") );
	
	if ( bSilentTray ) WriteProfileInt( _T("Windows"), _T("CMainWnd.ShowCmd"), 0 );
	
	m_pMainWnd = new CMainWnd();
	CoolMenu.EnableHook();
	
	if ( bSilentTray )
	{
		((CMainWnd*)m_pMainWnd)->CloseToTray();
	}
	else
	{
		dlgSplash->Topmost();
		m_pMainWnd->ShowWindow( SW_SHOW );
		m_pMainWnd->UpdateWindow();
	}
	// From this point translations are available and LoadString returns correct strings
	dlgSplash->Step( _T("Download Manager") ); 
		Downloads.Load();
	dlgSplash->Step( _T("Upload Manager") );
		UploadQueues.Load();

	dlgSplash->Step( _T("Upgrade Manager") );
	if ( VersionChecker.NeedToCheck() ) VersionChecker.Start( m_pMainWnd->GetSafeHwnd() );

	pCursor.Restore();

	dlgSplash->Hide();
	m_bLive = TRUE;

	return TRUE;
}

/////////////////////////////////////////////////////////////////////////////
// CShareazaApp termination

int CShareazaApp::ExitInstance() 
{
	CWaitCursor pCursor;
	
	DDEServer.Close();
	IEProtocol.Close();
	VersionChecker.Stop();
	DiscoveryServices.Stop();
	Network.Disconnect();
	Library.StopThread();
	
	Transfers.StopThread();
	Downloads.CloseTransfers();
	Uploads.Clear( FALSE );
	EDClients.Clear();
	BTClients.Clear();

	{
		CFirewall firewall;
		if ( firewall.AccessWindowsFirewall() )
		{
			// Remove application from the firewall exception list
			CString strBinaryPath;
			GetModuleFileName( NULL, strBinaryPath.GetBuffer( MAX_PATH ), MAX_PATH );
			strBinaryPath.ReleaseBuffer( MAX_PATH );
			firewall.SetupProgram( strBinaryPath, theApp.m_pszAppName, TRUE );
		}
	}
	if ( m_pUPnPFinder )
	{
		m_pUPnPFinder->StopAsyncFind();
		if ( Settings.Connection.DeleteUPnPPorts )
			m_pUPnPFinder->DeletePorts();
		m_pUPnPFinder.reset();
	}

	if ( m_bLive )
	{
		Downloads.Save();
		DownloadGroups.Save();
		Library.Save();
		Security.Save();
		HostCache.Save();
		UploadQueues.Save();
		DiscoveryServices.Save();
	}
	
	Downloads.Clear( TRUE );
	Library.Clear();
	Skin.Clear();
	
	if ( m_bLive ) Settings.Save( TRUE );

	if ( m_hUser32 != NULL ) FreeLibrary( m_hUser32 );

	WSACleanup();

	if ( m_pMutex != NULL ) CloseHandle( m_pMutex );

	return CWinApp::ExitInstance();
}

/////////////////////////////////////////////////////////////////////////////
// CShareazaApp help (suppress F1)

void CShareazaApp::WinHelp(DWORD /*dwData*/, UINT /*nCmd*/) 
{
}

/////////////////////////////////////////////////////////////////////////////
// CShareazaApp version

void CShareazaApp::GetVersionNumber()
{
	TCHAR szPath[MAX_PATH];
	DWORD dwSize;

	m_nVersion[0] = m_nVersion[1] = m_nVersion[2] = m_nVersion[3] = 0;

	GetModuleFileName( NULL, szPath, MAX_PATH );
	dwSize = GetFileVersionInfoSize( szPath, &dwSize );

	if ( dwSize )
	{
		BYTE* pBuffer = new BYTE[ dwSize ];

		if ( GetFileVersionInfo( szPath, NULL, dwSize, pBuffer ) )
		{
			VS_FIXEDFILEINFO* pTable;

			if ( VerQueryValue( pBuffer, _T("\\"), (VOID**)&pTable, (UINT*)&dwSize ) )
			{
				m_nVersion[0] = (WORD)( pTable->dwFileVersionMS >> 16 );
				m_nVersion[1] = (WORD)( pTable->dwFileVersionMS & 0xFFFF );
				m_nVersion[2] = (WORD)( pTable->dwFileVersionLS >> 16 );
				m_nVersion[3] = (WORD)( pTable->dwFileVersionLS & 0xFFFF );
			}
		}

		delete [] pBuffer;
	}

	m_sVersion.Format( _T("%i.%i.%i.%i"),
		m_nVersion[0], m_nVersion[1],
		m_nVersion[2], m_nVersion[3] );
}

/////////////////////////////////////////////////////////////////////////////
// CShareazaApp resources

void CShareazaApp::InitResources()
{
	//Determine the version of Windows
	OSVERSIONINFOEX pVersion;
	pVersion.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	GetVersionEx( (OSVERSIONINFO*)&pVersion );
	
	//Networking is poor under Win9x based operating systems. (95/98/Me)
	m_bNT = ( pVersion.dwPlatformId == VER_PLATFORM_WIN32_NT );

	// Determine if it's a server
	m_bServer = m_bNT && pVersion.wProductType != VER_NT_WORKSTATION;

	//Win 95/98/Me/NT (<5) do not support some functions
	m_dwWindowsVersion = pVersion.dwMajorVersion;

	//Win2000 = 0 WinXP = 1
	m_dwWindowsVersionMinor = pVersion.dwMinorVersion; 

	// Detect Windows ME
	m_bWinME = ( m_dwWindowsVersion == 4 && m_dwWindowsVersionMinor == 90 );

	m_bLimitedConnections = FALSE;
	VER_PLATFORM_WIN32s;
	VER_PLATFORM_WIN32_WINDOWS;
	VER_PLATFORM_WIN32_NT;

	if ( m_dwWindowsVersion == 5 && m_dwWindowsVersionMinor == 1 )
	{	//Windows XP - Test for SP2
		TCHAR* sp = _tcsstr( pVersion.szCSDVersion, _T("Service Pack ") );
		if( sp && sp[ 13 ] >= '2' )
		{	//XP SP2 - Limit the networking.
			//AfxMessageBox(_T("Warning - Windows XP Service Pack 2 detected. Performance may be reduced."), MB_OK );
			m_bLimitedConnections = TRUE;
		}
	}
	else if ( m_dwWindowsVersion == 5 && m_dwWindowsVersionMinor == 2
		&& _tcsstr( pVersion.szCSDVersion, _T("Service Pack") ) )
	{
		// Windows 2003 or Win XP x64
		m_bLimitedConnections = TRUE;
	}
	else if ( m_dwWindowsVersion == 6 && m_dwWindowsVersionMinor == 0 )
	{
		// Windows Vista
		m_bLimitedConnections = TRUE;
	}

	//Get the amount of installed memory.
	m_nPhysicalMemory = 0;
	if ( ( m_hUser32 = LoadLibrary( _T("User32.dll") ) ) != 0 )
	{	//Use GlobalMemoryStatusEx if possible (WinXP)
		void (WINAPI *m_pfnGlobalMemoryStatus)( LPMEMORYSTATUSEX );
		MEMORYSTATUSEX pMemory;

		(FARPROC&)m_pfnGlobalMemoryStatus = GetProcAddress(
			m_hUser32, "GlobalMemoryStatusEx" );

		if ( m_pfnGlobalMemoryStatus )
		{
			m_pfnGlobalMemoryStatus( &pMemory ); 
			m_nPhysicalMemory = pMemory.ullTotalPhys;
		}
	}

	if ( m_nPhysicalMemory == 0 )
	{	//Fall back to GlobalMemoryStatusEx (always available)
		MEMORYSTATUS pMemory;
		GlobalMemoryStatus( &pMemory ); 
		m_nPhysicalMemory = pMemory.dwTotalPhys;
	}
	
	//Get pointers to some functions that don't exist under 95/NT
	if ( ( m_hUser32 = LoadLibrary( _T("User32.dll") ) ) != 0 )
	{
		(FARPROC&)m_pfnSetLayeredWindowAttributes = GetProcAddress(
			m_hUser32, "SetLayeredWindowAttributes" );
		   
		(FARPROC&)m_pfnGetMonitorInfoA = GetProcAddress( 
			m_hUser32, "GetMonitorInfoA" ); 
    
		(FARPROC&)m_pfnMonitorFromRect = GetProcAddress( 
			m_hUser32, "MonitorFromRect" ); 

		(FARPROC&)m_pfnMonitorFromWindow = GetProcAddress( 
			m_hUser32, "MonitorFromWindow" ); 
	}
	else
	{
		m_pfnSetLayeredWindowAttributes = NULL;
		m_pfnGetMonitorInfoA = NULL; 
        m_pfnMonitorFromRect = NULL; 
		m_pfnMonitorFromWindow = NULL;
	}

	if ( ( m_hGDI32 = LoadLibrary( _T("gdi32.dll") ) ) != 0 )
		(FARPROC&)m_pfnSetLayout = GetProcAddress( m_hGDI32, "SetLayout" );
	else
		m_pfnSetLayout = NULL;

	// Get the fonts from the registry
	theApp.m_sDefaultFont		= theApp.GetProfileString( _T("Fonts"), _T("DefaultFont"), _T("Tahoma") );
	theApp.m_sPacketDumpFont	= theApp.GetProfileString( _T("Fonts"), _T("PacketDumpFont"), _T("Lucida Console") );
	theApp.m_sSystemLogFont		= theApp.GetProfileString( _T("Fonts"), _T("SystemLogFont"), _T("Tahoma") );
	theApp.m_nDefaultFontSize	= theApp.GetProfileInt( _T("Fonts"), _T("FontSize"), 11 );
	
	// Set up the default font
	m_gdiFont.CreateFontW( -theApp.m_nDefaultFontSize, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
		DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
		DEFAULT_PITCH|FF_DONTCARE, theApp.m_sDefaultFont );
	
	m_gdiFontBold.CreateFontW( -theApp.m_nDefaultFontSize, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
		DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
		DEFAULT_PITCH|FF_DONTCARE, theApp.m_sDefaultFont );
	
	m_gdiFontLine.CreateFontW( -theApp.m_nDefaultFontSize, 0, 0, 0, FW_NORMAL, FALSE, TRUE, FALSE,
		DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
		DEFAULT_PITCH|FF_DONTCARE, theApp.m_sDefaultFont );

	theApp.m_bRTL = theApp.GetProfileInt( _T("Settings"), _T("LanguageRTL"), 0 );

	srand( GetTickCount() );
}

/////////////////////////////////////////////////////////////////////////////
// CShareazaApp safe main window

CMainWnd* CShareazaApp::SafeMainWnd()
{
	CMainWnd* pMainWnd = (CMainWnd*)theApp.m_pSafeWnd;
	if ( pMainWnd == NULL ) return NULL;
	ASSERT_KINDOF( CMainWnd, pMainWnd );
	return IsWindow( pMainWnd->m_hWnd ) ? pMainWnd : NULL;
}

/////////////////////////////////////////////////////////////////////////////
// CShareazaApp message

TCHAR CShareazaApp::szMessageBuffer[16384];

void CShareazaApp::Message(int nType, UINT nID, ...) throw()
{
	if ( nType == MSG_DEBUG && ! Settings.General.Debug ) return;
	if ( nType == MSG_TEMP && ! Settings.General.DebugLog ) return;
	
	CSingleLock pLock( &m_csMessage, TRUE );
	CString strFormat;
	va_list pArgs;
	
	LoadString( strFormat, nID );
	va_start( pArgs, nID );
	
	if ( strFormat.Find( _T("%1") ) >= 0 )
	{
		LPTSTR lpszTemp;
		if ( ::FormatMessage( FORMAT_MESSAGE_FROM_STRING|FORMAT_MESSAGE_ALLOCATE_BUFFER,
			strFormat, 0, 0, (LPTSTR)&lpszTemp, 0, &pArgs ) != 0 && lpszTemp != NULL )
		{
			PrintMessage( nType, lpszTemp );
			if ( Settings.General.DebugLog ) LogMessage( lpszTemp );
			LocalFree( lpszTemp );
		}
	}
	else
	{
		_vsntprintf( szMessageBuffer, 16380, strFormat, pArgs );
		PrintMessage( nType, szMessageBuffer );
		if ( Settings.General.DebugLog ) LogMessage( szMessageBuffer );
	}

	va_end( pArgs );
}

void CShareazaApp::Message(int nType, LPCTSTR pszFormat, ...) throw()
{
	if ( nType == MSG_DEBUG && ! Settings.General.Debug ) return;
	if ( nType == MSG_TEMP && ! Settings.General.DebugLog ) return;
	
	CSingleLock pLock( &m_csMessage, TRUE );
	CString strFormat;
	va_list pArgs;
	
	va_start( pArgs, pszFormat );
	_vsntprintf( szMessageBuffer, 16380, pszFormat, pArgs );
	va_end( pArgs );
	
	PrintMessage( nType, szMessageBuffer );
	if ( Settings.General.DebugLog ) LogMessage( szMessageBuffer );
}

void CShareazaApp::PrintMessage(int nType, LPCTSTR pszLog)
{
	if ( HWND hWnd = m_pSafeWnd->GetSafeHwnd() )
	{
		PostMessage( hWnd, WM_LOG, nType, (LPARAM)_tcsdup( pszLog ) );
	}
}

void CShareazaApp::LogMessage(LPCTSTR pszLog)
{
	CFile pFile;
	
	if ( pFile.Open( Settings.General.UserPath + _T("\\Data\\Shareaza.log"), CFile::modeReadWrite ) )
	{
		if ( ( Settings.General.MaxDebugLogSize ) &&					// If log rotation is on 
			( pFile.GetLength() > Settings.General.MaxDebugLogSize ) )	// and file is too long...
		{	
			// Close the file
			pFile.Close();				
			// Rotate the logs 
			DeleteFile( Settings.General.UserPath + _T("\\Data\\Shareaza.old.log") );
			MoveFile( Settings.General.UserPath + _T("\\Data\\Shareaza.log"), 
				Settings.General.UserPath + _T("\\Data\\Shareaza.old.log") );
			// Start a new log
			if ( ! pFile.Open( Settings.General.UserPath + _T("\\Data\\Shareaza.log"), 
				CFile::modeWrite|CFile::modeCreate ) ) return;
			// Unicode marker
			WORD nByteOrder = 0xFEFF;
			pFile.Write( &nByteOrder, 2 );
		}
		else
		{
			pFile.Seek( 0, CFile::end ); // Otherwise, go to the end of the file to add entires.
		}
	}
	else
	{
		if ( ! pFile.Open( Settings.General.UserPath + _T("\\Data\\Shareaza.log"), 
			CFile::modeWrite|CFile::modeCreate ) ) return;

		// Unicode marker
		WORD nByteOrder = 0xFEFF;
		pFile.Write( &nByteOrder, 2 );
	}
	
	if ( Settings.General.ShowTimestamp )
	{
		CTime pNow = CTime::GetCurrentTime();
		CString strLine;
		
		strLine.Format( _T("[%.2i:%.2i:%.2i] %s\r\n"),
			pNow.GetHour(), pNow.GetMinute(), pNow.GetSecond(), pszLog );
		
		pFile.Write( (LPCTSTR)strLine, sizeof(TCHAR) * strLine.GetLength() );
	}
	else
	{
		pFile.Write( pszLog, static_cast< UINT >( sizeof(TCHAR) * _tcslen(pszLog) ) );
		pFile.Write( _T("\r\n"), sizeof(TCHAR) * 2 );
	}
	
	pFile.Close();
}

/////////////////////////////////////////////////////////////////////////////
// CShareazaApp get error string

CString CShareazaApp::GetErrorString()
{
	LPTSTR pszMessage = NULL;
	CString strMessage;
	
	FormatMessage( FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_ALLOCATE_BUFFER,
		NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&pszMessage, 0, NULL );
	
	if ( pszMessage != NULL )
	{
		strMessage = pszMessage;
		LocalFree( pszMessage );
	}
	
	return strMessage;
}

/////////////////////////////////////////////////////////////////////////////
// CShareazaApp process an internal URI

BOOL CShareazaApp::InternalURI(LPCTSTR pszURI)
{
	if ( m_pSafeWnd == NULL ) return FALSE;
	CMainWnd* pMainWnd = (CMainWnd*)m_pSafeWnd;
	
	CString strURI( pszURI );
	
	if ( strURI.Find( _T("raza:command:") ) == 0 )
	{
		if ( UINT nCmdID = CoolInterface.NameToID( pszURI + 13 ) )
		{
			pMainWnd->PostMessage( WM_COMMAND, nCmdID );
		}
	}
	else if ( strURI.Find( _T("raza:windowptr:") ) == 0 )
	{
		CChildWnd* pChild = NULL;
		_stscanf( (LPCTSTR)strURI + 15, _T("%lu"), &pChild );
		if ( pMainWnd->m_pWindows.Check( pChild ) ) pChild->MDIActivate();
	}
	else if ( strURI.Find( _T("raza:launch:") ) == 0 )
	{
		DWORD nIndex = 0;
		_stscanf( (LPCTSTR)strURI + 12, _T("%lu"), &nIndex );

		CSingleLock oLock( &Library.m_pSection, TRUE );
		if ( CLibraryFile* pFile = Library.LookupFile( nIndex ) )
		{
			if ( pFile->m_pFolder )
			{
				CString strPath = pFile->GetPath();
				oLock.Unlock();
				CFileExecutor::Execute( strPath, FALSE );
			}
		}
	}
	else if (	strURI.Find( _T("http://") ) == 0 ||
				strURI.Find( _T("ftp://") ) == 0 ||
				strURI.Find( _T("mailto:") ) == 0 ||
				strURI.Find( _T("aim:") ) == 0 ||
				strURI.Find( _T("magnet:") ) == 0 ||
				strURI.Find( _T("gnutella:") ) == 0 ||
				strURI.Find( _T("shareaza:") ) == 0 ||
				strURI.Find( _T("gnet:") ) == 0 ||
				strURI.Find( _T("ed2k:") ) == 0 ||
				strURI.Find( _T("sig2dat:") ) == 0 )
	{
		ShellExecute( pMainWnd->GetSafeHwnd(), _T("open"), strURI,
			NULL, NULL, SW_SHOWNORMAL );
	}
	else if ( strURI == _T("raza:connect") )
	{
		pMainWnd->PostMessage( WM_COMMAND, ID_NETWORK_CONNECT );
	}
	else if ( strURI == _T("raza:disconnect") )
	{
		pMainWnd->PostMessage( WM_COMMAND, ID_NETWORK_DISCONNECT );
	}
	else if ( strURI == _T("raza:search") )
	{
		pMainWnd->PostMessage( WM_COMMAND, ID_TAB_SEARCH );
	}
	else if ( strURI == _T("raza:neighbours") )
	{
		pMainWnd->PostMessage( WM_COMMAND, ID_VIEW_NEIGHBOURS );
	}
	else if ( strURI == _T("raza:downloads") )
	{
		pMainWnd->PostMessage( WM_COMMAND, ID_VIEW_DOWNLOADS );
	}
	else if ( strURI == _T("raza:uploads") )
	{
		pMainWnd->PostMessage( WM_COMMAND, ID_VIEW_UPLOADS );
	}
	else if ( strURI == _T("raza:shell:downloads") )
	{
		ShellExecute( pMainWnd->GetSafeHwnd(), _T("open"),
			Settings.Downloads.CompletePath, NULL, NULL, SW_SHOWNORMAL );
	}
	else if ( strURI == _T("raza:upgrade") )
	{
		pMainWnd->PostMessage( WM_VERSIONCHECK, 1 );
	}
	else if ( strURI == _T("raza:options") )
	{
		pMainWnd->PostMessage( WM_COMMAND, ID_TOOLS_SETTINGS );
	}
	else if ( strURI == _T("raza:options:skins") )
	{
		pMainWnd->PostMessage( WM_COMMAND, ID_TOOLS_SKIN );
	}
	else if ( strURI == _T("raza:wizard") )
	{
		pMainWnd->PostMessage( WM_COMMAND, ID_TOOLS_WIZARD );
	}
	else if ( strURI == _T("raza:library") )
	{
		pMainWnd->PostMessage( WM_COMMAND, ID_VIEW_LIBRARY );
	}
	else if ( strURI == _T("raza:library:downloads") )
	{
		pMainWnd->PostMessage( WM_COMMAND, ID_VIEW_LIBRARY );
	}
	else if ( strURI == _T("raza:library:history") )
	{
		pMainWnd->PostMessage( WM_COMMAND, ID_VIEW_LIBRARY );
		pMainWnd->PostMessage( WM_COMMAND, ID_LIBRARY_TREE_VIRTUAL );
	}
	else if ( strURI.Find( _T("raza:library:/") ) == 0 )
	{
		pMainWnd->PostMessage( WM_COMMAND, ID_VIEW_LIBRARY );
		pMainWnd->PostMessage( WM_COMMAND, ID_LIBRARY_TREE_VIRTUAL );
	}
	else
	{
		return FALSE;
	}

	return TRUE;
}

/////////////////////////////////////////////////////////////////////////////
// Runtime class lookup

void AFXAPI AfxLockGlobals(int nLockType);
void AFXAPI AfxUnlockGlobals(int nLockType);

CRuntimeClass* AfxClassForName(LPCTSTR pszClass)
{
	AFX_MODULE_STATE* pModuleState = AfxGetModuleState();

	AfxLockGlobals( 0 );

	for ( CRuntimeClass* pClass = pModuleState->m_classList ; pClass != NULL ; pClass = pClass->m_pNextClass )
	{
		if ( CString( pClass->m_lpszClassName ).CompareNoCase( pszClass ) == 0 )
		{
			AfxUnlockGlobals( 0 );
			return pClass;
		}
	}

	AfxUnlockGlobals( 0 );

	return NULL;
}

/////////////////////////////////////////////////////////////////////////////
// String functions

void Split(CString strSource, LPCTSTR pszDelimiter, CArray< CString >& pAddIt, BOOL bAddFirstEmpty)
{
	CString		strNew = strSource;
	CString		strTemp = strSource;
	CString		strAdd;
	BOOL		bFirstChecked = FALSE;

	int nPos1;
	int nPos = 0;

	if ( ! _tcslen( pszDelimiter ) )
		pszDelimiter = _T("|"); 

	do
	{
		nPos1 = 0;
		nPos = strNew.Find( pszDelimiter, nPos1 );
		if ( nPos != -1 ) 
		{
			CString strAdd = strTemp = strNew.Left( nPos );
			if ( ! strAdd.IsEmpty() && ! strTemp.Trim().IsEmpty() ) 
			{
				pAddIt.Add( strAdd );
			}
			else if ( bAddFirstEmpty && ! bFirstChecked ) 
			{
				pAddIt.Add( strAdd.Trim() );
			}
			strNew = strTemp = strNew.Mid( nPos + static_cast< int >( _tcslen( pszDelimiter ) ) );
		}
		bFirstChecked = TRUE; // Allow only the first item empty and ignore trailing empty items 
	} while ( nPos != -1 );
	
	if ( ! strTemp.Trim().IsEmpty() )
		pAddIt.Add( strNew );
}

BOOL LoadString(CString& str, UINT nID)
{
	return Skin.LoadString( str, nID );
}

void Replace(CString& strBuffer, LPCTSTR pszFind, LPCTSTR pszReplace)
{
	while ( TRUE )
	{
		int nPos = strBuffer.Find( pszFind );
		if ( nPos < 0 ) break;

		strBuffer = strBuffer.Left( nPos ) + pszReplace + strBuffer.Mid( nPos + static_cast< int >( _tcslen( pszFind ) ) );
	}
}

BOOL LoadSourcesString(CString& str, DWORD num)
{
	if (num == 0)
	{
		return Skin.LoadString( str, IDS_STATUS_NOSOURCES );
	}
	else if (num == 1)
	{
		return Skin.LoadString( str, IDS_STATUS_SOURCE );
	}
	else if ( ( (num % 100) > 10) && ( (num % 100) < 20) )
	{
		return Skin.LoadString( str, IDS_STATUS_SOURCES11TO19 );
	}
	else
	{
		switch (num % 10)
		{
			case 0: 
				return Skin.LoadString( str, IDS_STATUS_SOURCESTENS );
			case 1:
				return Skin.LoadString( str, IDS_STATUS_SOURCES );				
			case 2:
			case 3:
			case 4:
				return Skin.LoadString( str, IDS_STATUS_SOURCES2TO4 );
			default:
				return Skin.LoadString( str, IDS_STATUS_SOURCES5TO9 );
		}
	}
}

/////////////////////////////////////////////////////////////////////////////
// Case independent string search

LPCTSTR _tcsistr(LPCTSTR pszString, LPCTSTR pszPattern)
{
	if ( !*pszString || !*pszPattern ) return NULL;

	const TCHAR cFirstPatternChar = ToLower( *pszPattern );

	for ( ; ; ++pszString )
	{
		while ( *pszString && ToLower( *pszString ) != cFirstPatternChar ) ++pszString;

		if ( !*pszString ) return NULL;

		int i = 0;
		while ( const TCHAR cPatternChar = ToLower( pszPattern[ ++i ] ) )
		{
			if ( const TCHAR cStringChar = ToLower( pszString[ i ] ) )
			{
				if ( cStringChar != cPatternChar ) break;
			}
			else
			{
				return NULL;
			}
		}

		if ( !pszPattern[ i ] ) return pszString;
	}
}

LPCTSTR _tcsnistr(LPCTSTR pszString, LPCTSTR pszPattern, size_t plen)
{
	if ( !*pszString || !*pszPattern || !plen ) return NULL;

	const TCHAR cFirstPatternChar = ToLower( *pszPattern );

	for ( ; ; ++pszString )
	{
		while ( *pszString && ToLower( *pszString ) != cFirstPatternChar ) ++pszString;

		if ( !*pszString ) return NULL;

		DWORD i = 0;
		while ( ++i < plen )
		{
			if ( const TCHAR cStringChar = ToLower( pszString[ i ] ) )
			{
				if ( cStringChar != ToLower( pszPattern[ i ] ) ) break;
			}
			else
			{
				return NULL;
			}
		}

		if ( i == plen ) return pszString;
	}
}

/////////////////////////////////////////////////////////////////////////////
// Time Management Functions (C-runtime)

DWORD TimeFromString(LPCTSTR pszTime)
{
	// 2002-04-30T08:30Z
	
	if ( _tcslen( pszTime ) != 17 ) return 0;
	if ( pszTime[4] != '-' || pszTime[7] != '-' ) return 0;
	if ( pszTime[10] != 'T' || pszTime[13] != ':' || pszTime[16] != 'Z' ) return 0;
	
	LPCTSTR psz;
	int nTemp;
	
	tm pTime = {};

	if ( _stscanf( pszTime, _T("%i"), &nTemp ) != 1 ) return 0;
	pTime.tm_year = nTemp - 1900;
	for ( psz = pszTime + 5 ; *psz == '0' ; psz++ );
	if ( _stscanf( psz, _T("%i"), &nTemp ) != 1 ) return 0;
	pTime.tm_mon = nTemp - 1;
	for ( psz = pszTime + 8 ; *psz == '0' ; psz++ );
	if ( _stscanf( psz, _T("%i"), &nTemp ) != 1 ) return 0;
	pTime.tm_mday = nTemp;
	for ( psz = pszTime + 11 ; *psz == '0' ; psz++ );
	if ( _stscanf( psz, _T("%i"), &nTemp ) != 1 ) return 0;
	pTime.tm_hour = nTemp;
	for ( psz = pszTime + 14 ; *psz == '0' ; psz++ );
	if ( _stscanf( psz, _T("%i"), &nTemp ) != 1 ) return 0;
	pTime.tm_min = nTemp;
	
	time_t tGMT = mktime( &pTime );
	// check for invalid dates
	if (tGMT == -1) 
	{
		theApp.Message( MSG_ERROR, _T("Invalid Date/Time"), pszTime );
		return 0;
	}
	struct tm* pGM = gmtime( &tGMT );
	time_t tSub = mktime( pGM );
	
	if (tSub == -1) 
	{
		theApp.Message( MSG_ERROR, _T("Invalid Date/Time"), pszTime );
		return 0;
	}
	
	return DWORD( 2 * tGMT - tSub );
}

CString TimeToString(time_t tVal)
{
	tm* pTime = gmtime( &tVal );
	CString str;

	str.Format( _T("%.4i-%.2i-%.2iT%.2i:%.2iZ"),
		pTime->tm_year + 1900, pTime->tm_mon + 1, pTime->tm_mday,
		pTime->tm_hour, pTime->tm_min );

	return str;
}

/////////////////////////////////////////////////////////////////////////////
// Time Management Functions (FILETIME)

BOOL TimeFromString(LPCTSTR pszTime, FILETIME* pTime)
{
	// 2002-04-30T08:30Z
	
	if ( _tcslen( pszTime ) != 17 ) return FALSE;
	if ( pszTime[4] != '-' || pszTime[7] != '-' ) return FALSE;
	if ( pszTime[10] != 'T' || pszTime[13] != ':' || pszTime[16] != 'Z' ) return FALSE;
	
	LPCTSTR psz;
	int nTemp;

	SYSTEMTIME pOut = {};

	if ( _stscanf( pszTime, _T("%i"), &nTemp ) != 1 ) return FALSE;
	pOut.wYear = WORD( nTemp );
	for ( psz = pszTime + 5 ; *psz == '0' ; psz++ );
	if ( _stscanf( psz, _T("%i"), &nTemp ) != 1 ) return FALSE;
	pOut.wMonth = WORD( nTemp );
	for ( psz = pszTime + 8 ; *psz == '0' ; psz++ );
	if ( _stscanf( psz, _T("%i"), &nTemp ) != 1 ) return FALSE;
	pOut.wDay = WORD( nTemp );
	for ( psz = pszTime + 11 ; *psz == '0' ; psz++ );
	if ( _stscanf( psz, _T("%i"), &nTemp ) != 1 ) return FALSE;
	pOut.wHour = WORD( nTemp );
	for ( psz = pszTime + 14 ; *psz == '0' ; psz++ );
	if ( _stscanf( psz, _T("%i"), &nTemp ) != 1 ) return FALSE;
	pOut.wMinute = WORD( nTemp );

	return SystemTimeToFileTime( &pOut, pTime );
}

CString	TimeToString(FILETIME* pTime)
{
	SYSTEMTIME pOut;
	CString str;

	FileTimeToSystemTime( pTime, &pOut );

	str.Format( _T("%.4i-%.2i-%.2iT%.2i:%.2iZ"),
		pOut.wYear, pOut.wMonth, pOut.wDay,
		pOut.wHour, pOut.wMinute );

	return str;
}

/////////////////////////////////////////////////////////////////////////////
// Automatic dropdown list width adjustment (to fit translations)
// Use in ON_CBN_DROPDOWN events

void RecalcDropWidth(CComboBox* pWnd)
{
    // Reset the dropped width
    int nNumEntries = pWnd->GetCount();
    int nWidth = 0;
    CString str;

    CClientDC dc( pWnd );
    int nSave = dc.SaveDC();
    dc.SelectObject( pWnd->GetFont() );

    int nScrollWidth = GetSystemMetrics( SM_CXVSCROLL );
    for ( int nEntry = 0; nEntry < nNumEntries; nEntry++ )
    {
        pWnd->GetLBText( nEntry, str );
        int nLength = dc.GetTextExtent( str ).cx + nScrollWidth;
        nWidth = max( nWidth, nLength );
    }
    
    // Add margin space to the calculations
    nWidth += dc.GetTextExtent( _T("0") ).cx;

    dc.RestoreDC( nSave );
    pWnd->SetDroppedWidth( nWidth );
}

HICON CreateMirroredIcon(HICON hIconOrig)
{
	HDC hdcScreen, hdcBitmap, hdcMask = NULL;
	HBITMAP hbm, hbmMask, hbmOld,hbmOldMask;
	BITMAP bm;
	ICONINFO ii;
	HICON hIcon = NULL;
	hdcBitmap = CreateCompatibleDC( NULL );
	if ( hdcBitmap )
	{
		hdcMask = CreateCompatibleDC( NULL );
		if( hdcMask )
		{
			theApp.m_pfnSetLayout( hdcBitmap, LAYOUT_RTL );
			theApp.m_pfnSetLayout( hdcMask, LAYOUT_RTL );
		}
		else
		{
			DeleteDC( hdcBitmap );
			hdcBitmap = NULL;
		}
	}
	hdcScreen = GetDC( NULL );
	if ( hdcScreen )
	{
		if ( hdcBitmap && hdcMask )
		{
			if ( hIconOrig )
			{
				if ( GetIconInfo( hIconOrig, &ii ) && GetObject( ii.hbmColor, sizeof(BITMAP), &bm ) )
				{
					// Do the cleanup for the bitmaps.
					DeleteObject( ii.hbmMask );
					DeleteObject( ii.hbmColor );
					ii.hbmMask = ii.hbmColor = NULL;
					hbm = CreateCompatibleBitmap( hdcScreen, bm.bmWidth, bm.bmHeight );
					hbmMask = CreateBitmap( bm.bmWidth, bm.bmHeight, 1, 1, NULL );
					hbmOld = (HBITMAP)SelectObject( hdcBitmap, hbm );
					hbmOldMask = (HBITMAP)SelectObject( hdcMask,hbmMask );
					DrawIconEx( hdcBitmap, 0, 0, hIconOrig, bm.bmWidth, bm.bmHeight, 0, NULL, DI_IMAGE );
					DrawIconEx( hdcMask, 0, 0, hIconOrig, bm.bmWidth, bm.bmHeight, 0, NULL, DI_MASK );
					SelectObject( hdcBitmap, hbmOld );
					SelectObject( hdcMask, hbmOldMask );
					// Create the new mirrored icon and delete bitmaps

					ii.hbmMask = hbmMask;
					ii.hbmColor = hbm;
					hIcon = CreateIconIndirect( &ii );
					DeleteObject( hbm );
					DeleteObject( hbmMask );
				}
			}
		}
	}
	ReleaseDC( NULL, hdcScreen );

	if ( hdcBitmap ) DeleteDC( hdcBitmap );
	if ( hdcMask ) DeleteDC( hdcMask );
	return hIcon;
}

HBITMAP CreateMirroredBitmap(HBITMAP hbmOrig)
{
	HDC hdc, hdcMem1, hdcMem2;
	HBITMAP hbm = NULL, hOld_bm1, hOld_bm2;
	BITMAP bm;
	if ( !hbmOrig ) return NULL;
	if ( !GetObject( hbmOrig, sizeof(BITMAP), &bm ) ) return NULL;

	hdc = GetDC( NULL );
	if ( hdc )
	{
		hdcMem1 = CreateCompatibleDC( hdc );
		if ( !hdcMem1 )
		{
			ReleaseDC( NULL, hdc );
			return NULL;
		}
		hdcMem2 = CreateCompatibleDC( hdc );
		if ( !hdcMem2 )
		{
			DeleteDC( hdcMem1 );
			ReleaseDC( NULL, hdc );
			return NULL;
		}
		hbm = CreateCompatibleBitmap( hdc, bm.bmWidth, bm.bmHeight );
		if (!hbm)
		{
			ReleaseDC( NULL, hdc );
			DeleteDC( hdcMem1 );
			DeleteDC( hdcMem2 );
			return NULL;
		}
		// Flip the bitmap.
		hOld_bm1 = (HBITMAP)SelectObject( hdcMem1, hbmOrig );
		hOld_bm2 = (HBITMAP)SelectObject( hdcMem2, hbm );
		theApp.m_pfnSetLayout( hdcMem2, LAYOUT_RTL );
		BitBlt( hdcMem2, 0, 0, bm.bmWidth, bm.bmHeight, hdcMem1, 0, 0, SRCCOPY );
		SelectObject( hdcMem1, hOld_bm1 );
		SelectObject( hdcMem1, hOld_bm2 );
		DeleteDC( hdcMem1 );
		DeleteDC( hdcMem2 );
		ReleaseDC( NULL, hdc );
	}
	return hbm;
}