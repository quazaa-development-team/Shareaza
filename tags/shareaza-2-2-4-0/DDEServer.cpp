//
// DDEServer.cpp
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

#include "StdAfx.h"
#include "Shareaza.h"
#include "Settings.h"
#include "DDEServer.h"

#include "ShareazaURL.h"
#include "BTInfo.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

CDDEServer DDEServer( _T("Shareaza") );


//////////////////////////////////////////////////////////////////////
// CDDEServer construction

CDDEServer* CDDEServer::m_pServer = NULL;


CDDEServer::CDDEServer(LPCTSTR pszService)
{
	m_pServer		= this;
	m_hInstance		= NULL;
	m_hszService	= NULL;
	m_sService		= pszService;
}

CDDEServer::~CDDEServer()
{
	Close();
	m_pServer = NULL;
}

//////////////////////////////////////////////////////////////////////
// CDDEServer create

BOOL CDDEServer::Create()
{
	USES_CONVERSION;
	DWORD dwFilterFlags = 0;
	UINT uiResult;

	uiResult = DdeInitialize( &m_hInstance, DDECallback, dwFilterFlags, 0 );
	if ( uiResult != DMLERR_NO_ERROR ) return FALSE;

	m_hszService = DdeCreateStringHandle( m_hInstance, (LPCTSTR)m_sService, CP_WINUNICODE );


    DdeNameService( m_hInstance, m_hszService, NULL, DNS_REGISTER );

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CDDEServer close

void CDDEServer::Close()
{
	if ( m_hInstance == NULL ) return;

	DdeNameService( m_hInstance, m_hszService, NULL, DNS_UNREGISTER );

	DdeFreeStringHandle( m_hInstance, m_hszService );

	DdeUninitialize( m_hInstance );
	m_hInstance = NULL;
}

//////////////////////////////////////////////////////////////////////
// CDDEServer static callback

HDDEDATA CALLBACK CDDEServer::DDECallback(UINT wType, UINT /*wFmt*/, HCONV /*hConv*/, HSZ hsz1, HSZ /*hsz2*/, HDDEDATA hData, ULONG_PTR /*dwData1*/, ULONG_PTR /*dwData2*/)
{
	HDDEDATA hResult = NULL;

	if ( ! m_pServer ) return hResult;

	switch ( wType )
	{
	case XTYP_CONNECT:

		hResult = m_pServer->CheckAccept( m_pServer->StringFromHsz( hsz1 ) ) ?
			(HDDEDATA)TRUE : (HDDEDATA)FALSE;
		break;

	case XTYP_CONNECT_CONFIRM:

		// m_pServer->AddConversation( hConv, hsz1 );
		break;

	case XTYP_DISCONNECT:

		// m_pServer->RemoveConversation( hConv );
		break;

	case XTYP_EXECUTE:

		m_pServer->Execute( m_pServer->StringFromHsz( hsz1 ), hData, &hResult );
		break;

	}

	return hResult;
}

//////////////////////////////////////////////////////////////////////
// CDDEServer HSZ to string helper

CString CDDEServer::StringFromHsz(HSZ hsz)
{
	CString str;

	DWORD nLen = DdeQueryString( m_hInstance, hsz, NULL, 0, CP_WINUNICODE );
	if ( nLen == 0 ) return str;

	LPTSTR pBuf = new TCHAR[ nLen + 1 ];
	DdeQueryString( m_hInstance, hsz, pBuf, nLen + 1, CP_WINUNICODE );
	pBuf[nLen] = 0;

	str = pBuf;
	delete [] pBuf;

	return str;
}

//////////////////////////////////////////////////////////////////////
// CDDEServer argument helper

CString CDDEServer::ReadArgument(LPCTSTR& pszMessage)
{
	BOOL bEscape = FALSE;
	CString strPath;

	for ( pszMessage += 7 ; *pszMessage ; pszMessage++ )
	{
		if ( bEscape )
		{
			strPath += *pszMessage;
			bEscape = FALSE;
		}
		else if ( *pszMessage == '\"' )
		{
			if ( pszMessage[1] == '\"' )
			{
				strPath += '\"';
				pszMessage++;
			}
			else
			{
				break;
			}
		}
		else if ( *pszMessage == '\\' )
		{
			bEscape = TRUE;
		}
		else
		{
			strPath += *pszMessage;
		}
	}

	return strPath;
}

//////////////////////////////////////////////////////////////////////
// CDDEServer check accept

BOOL CDDEServer::CheckAccept(LPCTSTR pszTopic)
{
	return	_tcsicmp( pszTopic, _T("URL") ) == 0 ||
			_tcsicmp( pszTopic, _T("TORRENT") ) == 0 ||
			_tcsicmp( pszTopic, _T("COLLECTION") ) == 0;
}

//////////////////////////////////////////////////////////////////////
// CDDEServer execute HDDEDATA mode

BOOL CDDEServer::Execute(LPCTSTR pszTopic, HDDEDATA hData, HDDEDATA* phResult)
{
	DWORD nLength	= 0;
	LPVOID pData	= DdeAccessData( hData, &nLength );

	BOOL bResult = Execute( pszTopic, pData, nLength );

	DdeUnaccessData( hData );

	*phResult = (HDDEDATA)static_cast< DWORD_PTR >( bResult ? DDE_FACK : DDE_FNOTPROCESSED );

	return bResult;
}

//////////////////////////////////////////////////////////////////////
// CDDEServer execute LPCVOID mode

BOOL CDDEServer::Execute(LPCTSTR pszTopic, LPCVOID pData, DWORD nLength)
{
	CString str;

	if ( theApp.m_bNT )
	{
		// Copy data info a buffer
		LPWSTR pszData = new WCHAR[ nLength + 1 ];
		CopyMemory( pszData, pData, nLength * sizeof( WCHAR ) );
		// Ensure it has a null terminator
		pszData[ nLength ] = 0;
		// Assign it to the Cstring and remove buffer
		str = pszData;
		delete [] pszData;
	}
	else
	{
		// Windows 9x will return the data as an ASCII string. (even though UNICODE was specified)
		int nWide = MultiByteToWideChar( CP_ACP, 0, (LPCSTR)pData, (int)nLength, NULL, 0 );
		MultiByteToWideChar( CP_ACP, 0, (LPCSTR)pData, (int)nLength, str.GetBuffer( nWide ), nWide );
		str.ReleaseBuffer( nWide );
	}

	return Execute( pszTopic, str );
}

//////////////////////////////////////////////////////////////////////
// CDDEServer execute string mode

BOOL CDDEServer::Execute(LPCTSTR pszTopic, LPCTSTR pszMessage)
{
	if ( _tcscmp( pszTopic, _T("URL") ) == 0 )
	{
		return CShareazaApp::OpenURL( pszMessage, TRUE );
	}
	else if ( _tcscmp( pszTopic, _T("TORRENT") ) == 0 )
	{
		return CShareazaApp::OpenTorrent( pszMessage, TRUE );
	}
	else if ( _tcscmp( pszTopic, _T("COLLECTION") ) == 0 )
	{
		return CShareazaApp::OpenCollection( pszMessage, TRUE );
	}

	return FALSE;
}

