//
// Shareaza.h
//
// Copyright (c) Shareaza Development Team, 2002-2005.
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

#pragma once

#include "Resource.h"
#include "ComObject.h"
#include "ShareazaOM.h"

class CUPnPFinder;
class CMainWnd;
class CSplashDlg;

class CShareazaCommandLineInfo : public CCommandLineInfo
{
public:
	CShareazaCommandLineInfo();

	virtual void ParseParam(const TCHAR* pszParam, BOOL bFlag, BOOL bLast);

	BOOL m_bSilentTray;
	BOOL m_bNoSplash;
	BOOL m_bNoAlphaWarning;
};

class CShareazaApp : public CWinApp
{
public:
	CShareazaApp();

	HANDLE				m_pMutex;
	CMutex				m_pSection;
	WORD				m_nVersion[4];
	CString				m_sVersion;
	CString				m_sBuildDate;
	CFont				m_gdiFont;
	CFont				m_gdiFontBold;
	CFont				m_gdiFontLine;
	CWnd*				m_pSafeWnd;
	BOOL				m_bLive;
	BOOL				m_bNT;						// NT based core. (NT, 2000, XP, etc)
	BOOL				m_bServer;					// Server version
	BOOL				m_bWinME;					// Windows Millennium
	BOOL				m_bLimitedConnections;		// Networking is limited (XP SP2)
	DWORD				m_dwWindowsVersion;			// Windows version
	DWORD				m_dwWindowsVersionMinor;	// Windows minor version
	QWORD				m_nPhysicalMemory;			// Physical RAM installed
	BOOL				m_bRTL;						// Right-to-Left GUI (2000, XP only)
	BOOL                m_bMenuWasVisible;          // For the menus in media player window
	int					m_nDefaultFontSize;			// The basic font size. (11)
	CString				m_sDefaultFont;				// Main font. (Tahoma)
	CString				m_sPacketDumpFont;			// Packet Window. (Lucida Console)
	CString				m_sSystemLogFont;			// System Window. (Courier New)
	boost::scoped_ptr< CUPnPFinder > m_pUPnPFinder;
	TRISTATE			m_bUPnPPortsForwarded;		// UPnP values are assigned when the discovery is complete
	TRISTATE			m_bUPnPDeviceConnected;		// or when the service notifies
	CString				m_sUPnPExternalIP;

	// GDI and display monitor functions
	HINSTANCE	m_hUser32;
	BOOL		(WINAPI *m_pfnSetLayeredWindowAttributes)(HWND, COLORREF, BYTE, DWORD);
	BOOL		(WINAPI *m_pfnGetMonitorInfoA)(HMONITOR, LPMONITORINFO);
	HMONITOR	(WINAPI *m_pfnMonitorFromRect)(LPCRECT, DWORD);
	HMONITOR	(WINAPI *m_pfnMonitorFromWindow)(HWND, DWORD);

	// For RTL layout support
	HINSTANCE	m_hGDI32;
	DWORD		(WINAPI *m_pfnSetLayout)(HDC, DWORD);

	// Power schemes management
	HINSTANCE	m_hPowrProf;
	BOOLEAN		(WINAPI *m_pfnGetActivePwrScheme)(PUINT);
	BOOLEAN		(WINAPI *m_pfnGetCurrentPowerPolicies)(PGLOBAL_POWER_POLICY, PPOWER_POLICY);
	BOOLEAN		(WINAPI *m_pfnSetActivePwrScheme)(UINT, PGLOBAL_POWER_POLICY, PPOWER_POLICY);
	
public:
	static CMainWnd*	SafeMainWnd();
	void				Message(int nType, UINT nID, ...) throw();
	void				Message(int nType, LPCTSTR pszFormat, ...) throw();
	CString				GetErrorString();
	BOOL				InternalURI(LPCTSTR pszURI);
	void				PrintMessage(int nType, LPCTSTR pszLog);
	void				LogMessage(LPCTSTR pszLog);
	void				DebugState(BOOL bState);

	virtual BOOL		InitInstance();
	virtual int			ExitInstance();
	virtual void		WinHelp(DWORD dwData, UINT nCmd = HELP_CONTEXT);
	virtual CDocument*	OpenDocumentFile(LPCTSTR lpszFileName);

	static BOOL			Open(LPCTSTR lpszFileName, BOOL bDoIt);
	static BOOL			OpenTorrent(LPCTSTR lpszFileName, BOOL bDoIt);
	static BOOL			OpenCollection(LPCTSTR lpszFileName, BOOL bDoIt);
	static BOOL			OpenURL(LPCTSTR lpszFileName, BOOL bDoIt);

protected:
	CCriticalSection			m_csMessage;
	static TCHAR				szMessageBuffer[16384];
	CShareazaCommandLineInfo	m_ocmdInfo;

	void				GetVersionNumber();
	void				InitResources();
	void				SplashStep(CSplashDlg*& dlg, LPCTSTR pszMessage);

	DECLARE_MESSAGE_MAP()
};

extern CShareazaApp theApp;

//
// Utility Functions
//

CRuntimeClass* AfxClassForName(LPCTSTR pszClass);

BOOL LoadString(CString& str, UINT nID);
LPCTSTR _tcsistr(LPCTSTR pszString, LPCTSTR pszPattern);
LPCTSTR _tcsnistr(LPCTSTR pszString, LPCTSTR pszPattern, size_t plen);
void Replace(CString& strBuffer, LPCTSTR pszFind, LPCTSTR pszReplace);
void Split(CString strSource, LPCTSTR strDelimiter, CArray< CString >& pAddIt, BOOL bAddFirstEmpty);
BOOL LoadSourcesString(CString& str, DWORD num, bool bFraction=false);

DWORD	TimeFromString(LPCTSTR psz);
CString	TimeToString(time_t tVal);
BOOL	TimeFromString(LPCTSTR psz, FILETIME* pTime);
CString	TimeToString(FILETIME* pTime);

void	RecalcDropWidth(CComboBox* pWnd);
HICON	CreateMirroredIcon(HICON hIconOrig);
HBITMAP	CreateMirroredBitmap(HBITMAP hbmOrig);

#ifdef _DEBUG
#define MLOG(x) theApp.Message( MSG_DEBUG, x )
#else
#define MLOG(x)
#endif

typedef enum
{
	sNone = 0,
	sNumeric = 1,
	sRegular = 2,
	sKanji = 4,
	sHiragana = 8,
	sKatakana = 16
} ScriptType;

struct CompareNums
{
	inline bool operator()(WORD lhs, WORD rhs) const
	{
		return lhs > rhs;
	}
};

inline bool IsCharacter(TCHAR nChar)
{
    WORD nCharType = 0;
	
	if ( GetStringTypeExW( LOCALE_NEUTRAL, CT_CTYPE3, &nChar, 1, &nCharType ) )
		return ( ( nCharType & C3_ALPHA ) == C3_ALPHA ||
				 ( ( nCharType & C3_KATAKANA ) == C3_KATAKANA ||
				   ( nCharType & C3_HIRAGANA ) == C3_HIRAGANA ) && 
				   !( ( nCharType & C3_SYMBOL ) == C3_SYMBOL )  ||
				 ( nCharType & C3_IDEOGRAPH ) == C3_IDEOGRAPH ||
				 _istdigit( nChar ) );

	return false;
}

inline bool IsHiragana(TCHAR nChar)
{
	WORD nCharType = 0;
	
	if ( GetStringTypeExW( LOCALE_NEUTRAL, CT_CTYPE3, &nChar, 1, &nCharType ) )
		return ( ( nCharType & C3_HIRAGANA ) == C3_HIRAGANA );
	return false;
}

inline bool IsKatakana(TCHAR nChar)
{
	WORD nCharType = 0;
	
	if ( GetStringTypeExW( LOCALE_NEUTRAL, CT_CTYPE3, &nChar, 1, &nCharType ) )
		return ( ( nCharType & C3_KATAKANA ) == C3_KATAKANA );
	return false;
}

inline bool IsKanji(TCHAR nChar)
{
	WORD nCharType = 0;
	
	if ( GetStringTypeExW( LOCALE_NEUTRAL, CT_CTYPE3, &nChar, 1, &nCharType ) )
		return ( ( nCharType & C3_IDEOGRAPH ) == C3_IDEOGRAPH );
	return false;
}

inline bool IsWord(LPCTSTR pszString, size_t nStart, size_t nLength)
{
	for ( pszString += nStart ; *pszString && nLength ; pszString++, nLength-- )
	{
		if ( ! _istdigit( *pszString ) ) return true;
	}
	return false;
}

#define MSG_DEFAULT		0
#define MSG_SYSTEM		1
#define MSG_ERROR		2
#define MSG_DEBUG		3
#define MSG_TEMP		4
#define MSG_DOWNLOAD	1

#define WM_WINSOCK		(WM_USER+101)
#define WM_VERSIONCHECK	(WM_USER+102)
#define WM_OPENCHAT		(WM_USER+103)
#define WM_TRAY			(WM_USER+104)
#define WM_URL			(WM_USER+105)
#define WM_SKINCHANGED	(WM_USER+106)
#define WM_COLLECTION	(WM_USER+107)
#define WM_OPENSEARCH	(WM_USER+108)
#define WM_LOG			(WM_USER+109)
#define WM_LIBRARYSEARCH (WM_USER+110)

#define WM_AFX_SETMESSAGESTRING 0x0362
#define WM_AFX_POPMESSAGESTRING 0x0375
#define WM_IDLEUPDATECMDUI		0x0363

#define ID_PLUGIN_FIRST	27000
#define ID_PLUGIN_LAST	27999

#undef ON_NOTIFY
#define ON_NOTIFY(wNotifyCode, id, memberFxn) \
	{ WM_NOTIFY, (WORD)(int)wNotifyCode, (WORD)id, (WORD)id, AfxSigNotify_v, \
		(AFX_PMSG) \
		(reinterpret_cast< void (AFX_MSG_CALL CCmdTarget::*)(NMHDR*, LRESULT*) > \
		(memberFxn)) },

#undef ON_NOTIFY_RANGE
#define ON_NOTIFY_RANGE(wNotifyCode, id, idLast, memberFxn) \
	{ WM_NOTIFY, (WORD)(int)wNotifyCode, (WORD)id, (WORD)idLast, AfxSigNotify_RANGE, \
		(AFX_PMSG) \
		(reinterpret_cast< void (AFX_MSG_CALL CCmdTarget::*)(UINT, NMHDR*, LRESULT*) > \
		(memberFxn)) },

#undef ON_NOTIFY_EX
#define ON_NOTIFY_EX(wNotifyCode, id, memberFxn) \
	{ WM_NOTIFY, (WORD)(int)wNotifyCode, (WORD)id, (WORD)id, AfxSigNotify_EX, \
		(AFX_PMSG) \
		(reinterpret_cast< BOOL (AFX_MSG_CALL CCmdTarget::*)(UINT, NMHDR*, LRESULT*) > \
		(memberFxn)) },

#undef ON_NOTIFY_EX_RANGE
#define ON_NOTIFY_EX_RANGE(wNotifyCode, id, idLast, memberFxn) \
	{ WM_NOTIFY, (WORD)(int)wNotifyCode, (WORD)id, (WORD)idLast, AfxSigNotify_EX, \
		(AFX_PMSG) \
		(reinterpret_cast< BOOL (AFX_MSG_CALL CCmdTarget::*)(UINT, NMHDR*, LRESULT*) > \
		(memberFxn)) },

#undef ON_NOTIFY_REFLECT
#define ON_NOTIFY_REFLECT(wNotifyCode, memberFxn) \
	{ WM_NOTIFY+WM_REFLECT_BASE, (WORD)(int)wNotifyCode, 0, 0, AfxSigNotify_v, \
		(AFX_PMSG) \
		(reinterpret_cast<void (AFX_MSG_CALL CCmdTarget::*)(NMHDR*, LRESULT*) > \
		(memberFxn)) },

#undef ON_NOTIFY_REFLECT_EX
#define ON_NOTIFY_REFLECT_EX(wNotifyCode, memberFxn) \
	{ WM_NOTIFY+WM_REFLECT_BASE, (WORD)(int)wNotifyCode, 0, 0, AfxSigNotify_b, \
		(AFX_PMSG) \
		(reinterpret_cast<BOOL (AFX_MSG_CALL CCmdTarget::*)(NMHDR*, LRESULT*) > \
		(memberFxn)) },


// Client's name
#define CLIENT_NAME			"Shareaza"


// Network ID stuff

// 4 Character vendor code (used on G1, G2)
// BEAR, LIME, RAZA, etc
#define VENDOR_CODE			"RAZB"

// ed2k client ID number.
// 0 = eMule, 1 - cDonkey, 4 = Shareaza mod/fork/etc, 28 = Raza.
#define ED2K_CLIENT_ID		4

// 2 Character BT peer-id code
// SZ = Raza, AZ = Azerus, etc
#define BT_ID1				'S'
#define BT_ID2				'~'

