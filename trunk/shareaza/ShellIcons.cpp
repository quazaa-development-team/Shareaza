//
// ShellIcons.cpp
//
// Copyright (c) Shareaza Development Team, 2002-2004.
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
#include "ShellIcons.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

CShellIcons ShellIcons;


//////////////////////////////////////////////////////////////////////
// CShellIcons construction

CShellIcons::CShellIcons()
{
	m_hUser			= LoadLibrary( _T("User32.dll") );
	m_pfnPrivate	= NULL;

	if ( m_hUser != NULL )
	{
#ifdef UNICODE
		(FARPROC&)m_pfnPrivate = GetProcAddress( m_hUser, "PrivateExtractIconsW" );
#else
		(FARPROC&)m_pfnPrivate = GetProcAddress( m_hUser, "PrivateExtractIconsA" );
#endif
	}
}

CShellIcons::~CShellIcons()
{
	if ( m_hUser ) FreeLibrary( m_hUser );
}

//////////////////////////////////////////////////////////////////////
// CShellIcons clear

void CShellIcons::Clear()
{
	if ( m_i16.m_hImageList ) m_i16.DeleteImageList();
	if ( m_i32.m_hImageList ) m_i32.DeleteImageList();
	if ( m_i48.m_hImageList ) m_i48.DeleteImageList();
	
	m_i16.Create( 16, 16, ILC_COLOR32|ILC_MASK, SHI_MAX, 4 );
	m_i32.Create( 32, 32, ILC_COLOR32|ILC_MASK, 1, 4 );
	m_i48.Create( 48, 48, ILC_COLOR32|ILC_MASK, 1, 4 );
	
	CBitmap bmBase;
	HICON hTemp;
	
	bmBase.LoadBitmap( IDB_SHELL_BASE );
	m_i16.Add( &bmBase, RGB( 0, 255, 0 ) );
	m_i16.SetOverlayImage( SHI_LOCKED, SHI_O_LOCKED );
	m_i16.SetOverlayImage( SHI_PARTIAL, SHI_O_PARTIAL );
	m_i16.SetOverlayImage( SHI_COLLECTION, SHI_O_COLLECTION );
	m_i16.SetOverlayImage( SHI_COMMERCIAL, SHI_O_COMMERCIAL );
	
	hTemp = (HICON)LoadImage( AfxGetResourceHandle(), MAKEINTRESOURCE(IDI_FILE), IMAGE_ICON, 32, 32, 0 );
	m_i32.Add( hTemp );
	DestroyIcon( hTemp );
	hTemp = (HICON)LoadImage( AfxGetResourceHandle(), MAKEINTRESOURCE(IDI_FILE), IMAGE_ICON, 48, 48, 0 );
	m_i48.Add( hTemp );
	DestroyIcon( hTemp );
	
	hTemp = (HICON)LoadImage( AfxGetResourceHandle(), MAKEINTRESOURCE(IDI_EXECUTABLE), IMAGE_ICON, 32, 32, 0 );
	m_i32.Add( hTemp );
	DestroyIcon( hTemp );
	hTemp = (HICON)LoadImage( AfxGetResourceHandle(), MAKEINTRESOURCE(IDI_EXECUTABLE), IMAGE_ICON, 48, 48, 0 );
	m_i48.Add( hTemp );
	DestroyIcon( hTemp );
	
	hTemp = (HICON)LoadImage( AfxGetResourceHandle(), MAKEINTRESOURCE(IDI_COLLECTION_MASK), IMAGE_ICON, 32, 32, 0 );
	m_i32.SetOverlayImage( m_i32.Add( hTemp ), SHI_O_COLLECTION );
	DestroyIcon( hTemp );
	hTemp = (HICON)LoadImage( AfxGetResourceHandle(), MAKEINTRESOURCE(IDI_COLLECTION_MASK), IMAGE_ICON, 48, 48, 0 );
	m_i48.SetOverlayImage( m_i48.Add( hTemp ), SHI_O_COLLECTION );
	DestroyIcon( hTemp );
	
	m_m16.RemoveAll();
	m_m32.RemoveAll();
	m_m48.RemoveAll();
	
	m_m16.SetAt( _T(".exe"), (LPVOID)SHI_EXECUTABLE );
	m_m32.SetAt( _T(".exe"), (LPVOID)1 );
	m_m48.SetAt( _T(".exe"), (LPVOID)1 );
}

//////////////////////////////////////////////////////////////////////
// CShellIcons get

int CShellIcons::Get(LPCTSTR pszFile, int nSize)
{
	LPCTSTR pszType = _tcsrchr( pszFile, '.' );
	if ( pszType == NULL ) return 0;
	
	if ( m_i16.m_hImageList == NULL ) Clear();

	CString strType( pszType );
	strType = CharLower( strType.GetBuffer() );

	HICON hIcon = NULL;
	int nIndex;

	switch ( nSize )
	{
	case 16:
		if ( m_m16.Lookup( strType, (void*&)nIndex ) ) return nIndex;
		Lookup( pszType, &hIcon, NULL, NULL, NULL );
		nIndex = hIcon ? m_i16.Add( hIcon ) : 0;
		m_m16.SetAt( strType, (LPVOID)nIndex );
		break;
	case 32:
		if ( m_m32.Lookup( strType, (void*&)nIndex ) ) return nIndex;
		Lookup( pszType, NULL, &hIcon, NULL, NULL );
		nIndex = hIcon ? m_i32.Add( hIcon ) : 0;
		m_m32.SetAt( strType, (LPVOID)nIndex );
		break;
	case 48:
		if ( m_m48.Lookup( strType, (void*&)nIndex ) ) return nIndex;
		Lookup( pszType, NULL, NULL, NULL, NULL, &hIcon );
		nIndex = hIcon ? m_i48.Add( hIcon ) : 0;
		m_m48.SetAt( strType, (LPVOID)nIndex );
		break;
	}
	
	if ( hIcon ) DestroyIcon( hIcon );

	return nIndex;
}

//////////////////////////////////////////////////////////////////////
// CShellIcons add icon

int CShellIcons::Add(HICON hIcon, int nSize)
{
	if ( m_i16.m_hImageList == NULL ) Clear();

	switch ( nSize )
	{
	case 16:
		return m_i16.Add( hIcon );
	case 32:
		return m_i32.Add( hIcon );
	case 48:
		return m_i48.Add( hIcon );
	default:
		return -1;
	}
}

//////////////////////////////////////////////////////////////////////
// CShellIcons icon extractor

HICON CShellIcons::ExtractIcon(int nIndex, int nSize)
{
	switch ( nSize )
	{
	case 16:
		return m_i16.ExtractIcon( nIndex );
	case 32:
		return m_i32.ExtractIcon( nIndex );
	case 48:
		return m_i48.ExtractIcon( nIndex );
	default:
		return NULL;
	}
}

//////////////////////////////////////////////////////////////////////
// CShellIcons common type string

CString	CShellIcons::GetTypeString(LPCTSTR pszFile)
{
	CString strOutput;

	LPCTSTR pszType = _tcsrchr( pszFile, '.' );
	if ( ! pszType ) return strOutput;

	CString strName, strMime;
	Lookup( pszType, NULL, NULL, &strName, &strMime );

	if ( strName.GetLength() )
	{
		strOutput = strName;
		if ( strMime.GetLength() ) strOutput += _T(" (") + strMime + _T(")");
	}
	else
	{
		strOutput = pszType + 1;
	}

	return strOutput;
}

//////////////////////////////////////////////////////////////////////
// CShellIcons lookup

BOOL CShellIcons::Lookup(LPCTSTR pszType, HICON* phSmallIcon, HICON* phLargeIcon, CString* psName, CString* psMIME, HICON* phHugeIcon)
{
	DWORD nType, nResult;
	TCHAR szResult[128];
	HKEY hKey, hSub;

	if ( phSmallIcon ) *phSmallIcon = NULL;
	if ( phLargeIcon ) *phLargeIcon = NULL;
	if ( psName ) *psName = pszType + 1;
	if ( psMIME ) psMIME->Empty();

	if ( pszType == NULL || *pszType == 0 ) return FALSE;

	if ( RegOpenKeyEx( HKEY_CLASSES_ROOT, pszType, 0, KEY_READ, &hKey ) != ERROR_SUCCESS ) return FALSE;

	if ( psMIME )
	{
		nResult = sizeof(TCHAR) * 128; nType = REG_SZ;
		if ( RegQueryValueEx( hKey, _T("Content Type"), NULL, &nType, (LPBYTE)szResult, &nResult ) == ERROR_SUCCESS )
		{
			szResult[ nResult / sizeof(TCHAR) ] = 0;
			*psMIME = szResult;
		}
	}

	nResult = sizeof(TCHAR) * 128; nType = REG_SZ;
	if ( RegQueryValueEx( hKey, _T(""), NULL, &nType, (LPBYTE)szResult, &nResult ) != ERROR_SUCCESS )
	{
		RegCloseKey( hKey );
		return FALSE;
	}

	RegCloseKey( hKey );
	szResult[ nResult / sizeof(TCHAR) ] = 0;

	if ( RegOpenKeyEx( HKEY_CLASSES_ROOT, szResult, 0, KEY_READ, &hKey ) != ERROR_SUCCESS ) return 0;

	if ( psName )
	{
		nResult = sizeof(TCHAR) * 128; nType = REG_SZ;
		if ( RegQueryValueEx( hKey, _T(""), NULL, &nType, (LPBYTE)szResult, &nResult ) == ERROR_SUCCESS )
		{
			szResult[ nResult / sizeof(TCHAR) ] = 0;
			*psName = szResult;
		}
	}

	if ( RegOpenKeyEx( hKey, _T("DefaultIcon"), 0, KEY_READ, &hSub ) != ERROR_SUCCESS )
	{
		RegCloseKey( hKey );
		return FALSE;
	}

	nResult = sizeof(TCHAR) * 128; nType = REG_SZ;
	if ( RegQueryValueEx( hSub, _T(""), NULL, &nType, (LPBYTE)szResult, &nResult ) != ERROR_SUCCESS )
	{
		RegCloseKey( hSub );
		RegCloseKey( hKey );
		return FALSE;
	}
	
	RegCloseKey( hSub );
	RegCloseKey( hKey );
	szResult[ nResult / sizeof(TCHAR) ] = 0;

	CString strIcon( szResult );

	int nIcon, nIndex = strIcon.ReverseFind( ',' );
	if ( nIndex < 0 ) return 0;

	if ( _stscanf( strIcon.Mid( nIndex + 1 ), _T("%i"), &nIcon ) != 1 ) return FALSE;
	strIcon = strIcon.Left( nIndex );

	if ( strIcon.GetLength() < 3 ) return FALSE;

	if ( strIcon.GetAt( 0 ) == '\"' && strIcon.GetAt( strIcon.GetLength() - 1 ) == '\"' )
		strIcon = strIcon.Mid( 1, strIcon.GetLength() - 2 );

	BOOL bSuccess = FALSE;

	if ( phLargeIcon || phSmallIcon )
	{
		if ( ExtractIconEx( strIcon, nIcon, phLargeIcon, phSmallIcon, 1 ) )
		{
			bSuccess |= ( phLargeIcon && *phLargeIcon ) || ( phSmallIcon && *phSmallIcon );
		}
	}

	if ( m_pfnPrivate && phHugeIcon )
	{
		UINT nLoadedID;

		if ( (*m_pfnPrivate)( strIcon, nIcon, 48, 48, phHugeIcon, &nLoadedID, 1, 0 ) )
		{
			bSuccess = TRUE;
		}
	}

	return bSuccess != 0;
}

//////////////////////////////////////////////////////////////////////
// CShellIcons drawing

void CShellIcons::Draw(CDC* pDC, int nIcon, int nSize, int nX, int nY, COLORREF crBack, BOOL bSelected)
{
	ImageList_DrawEx( ShellIcons.GetHandle( nSize ), nIcon, pDC->GetSafeHdc(),
		nX, nY, nSize, nSize, crBack, CLR_DEFAULT, bSelected ? ILD_SELECTED : ILD_NORMAL );
	
	if ( crBack != CLR_NONE ) pDC->ExcludeClipRect( nX, nY, nX + nSize, nY + nSize );
}
