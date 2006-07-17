//
// Transfer.cpp
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
#include "Transfers.h"
#include "Transfer.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif


//////////////////////////////////////////////////////////////////////
// CTransfer construction

CTransfer::CTransfer()
{
	m_nRunCookie = 0;
}

CTransfer::~CTransfer()
{
	ASSERT( m_hSocket == INVALID_SOCKET );
	if ( m_hSocket != INVALID_SOCKET ) Close();
}

//////////////////////////////////////////////////////////////////////
// CTransfer operations

BOOL CTransfer::ConnectTo(IN_ADDR* pAddress, WORD nPort)
{
	if ( CConnection::ConnectTo( pAddress, nPort ) )
	{
		Transfers.Add( this );
		return TRUE;
	}

	return FALSE;
}

void CTransfer::AttachTo(CConnection* pConnection)
{
	CConnection::AttachTo( pConnection );
	Transfers.Add( this );
}

void CTransfer::Close()
{
	Transfers.Remove( this );
	CConnection::Close();
}

//////////////////////////////////////////////////////////////////////
// CTransfer HTTP headers

void CTransfer::ClearHeaders()
{
	m_pHeaderName.RemoveAll();
	m_pHeaderValue.RemoveAll();
}

BOOL CTransfer::OnHeaderLine(CString& strHeader, CString& strValue)
{
	m_pHeaderName.Add( strHeader );
	m_pHeaderValue.Add( strValue );

	return CConnection::OnHeaderLine( strHeader, strValue );
}

BOOL CTransfer::StrToSockaddr( LPCTSTR pszHost, SOCKADDR_IN & pHost )
{
	CString strHost( pszHost );
	int nPort = 0;

	strHost.TrimLeft();
	strHost.TrimRight();

	int nPos = strHost.Find( ':' );
	if ( nPos < 0 )
	{
		nPort = GNUTELLA_DEFAULT_PORT;
	}
	else
	{
		if ( _stscanf( strHost.Mid( nPos + 1 ), _T("%i"), &nPort ) != 1 ) return FALSE;
	}

	strHost = strHost.Left( nPos );

	USES_CONVERSION;
	DWORD nAddress = inet_addr( T2CA( (LPCTSTR)strHost ) );

	// Don't add invalid addresses
	if ( ! nPort ) return FALSE;
	if ( ! nAddress )  return FALSE;

	pHost.sin_addr.S_un.S_addr = nAddress;
	pHost.sin_port = htons((WORD)nPort);

	return TRUE;
}
