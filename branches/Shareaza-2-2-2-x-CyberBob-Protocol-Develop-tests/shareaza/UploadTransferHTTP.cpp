//
// UploadTransferHTTP.cpp
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
#include "Uploads.h"
#include "UploadFile.h"
#include "UploadFiles.h"
#include "UploadQueue.h"
#include "UploadQueues.h"
#include "UploadTransferHTTP.h"
#include "TransferFile.h"
#include "Transfers.h"
#include "Remote.h"
#include "ShellIcons.h"
#include "Statistics.h"
#include "Buffer.h"
#include "Schema.h"
#include "XML.h"

#include "Network.h"
#include "Library.h"
#include "SharedFile.h"
#include "Downloads.h"
#include "Download.h"

#include "LocalSearch.h"
#include "ImageServices.h"
#include "ThumbCache.h"
#include "Neighbours.h"
#include "G2Neighbour.h"
#include "G2Packet.h"
#include "GProfile.h"
#include "Security.h"

#include "SHA.h"
#include "ED2K.h"
#include "TigerTree.h"
#include "MD5.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif


//////////////////////////////////////////////////////////////////////
// CUploadTransferHTTP construction

CUploadTransferHTTP::CUploadTransferHTTP() : CUploadTransfer( PROTOCOL_HTTP )
{
	m_bKeepAlive		= FALSE;
	m_nGnutella			= 0;
	m_nReaskMultiplier	= 1;
	m_bNotShareaza		= FALSE;
	m_nTimeoutTraffic	= Settings.Connection.TimeoutTraffic;
}

CUploadTransferHTTP::~CUploadTransferHTTP()
{
}

//////////////////////////////////////////////////////////////////////
// CUploadTransferHTTP attach to connection

void CUploadTransferHTTP::AttachTo(CConnection* pConnection)
{
	CUploadTransfer::AttachTo( pConnection );

	theApp.Message( MSG_DEFAULT, IDS_UPLOAD_ACCEPTED, (LPCTSTR)m_sAddress );

	m_mInput.pLimit		= &Settings.Bandwidth.Request;
	m_mOutput.pLimit	= &m_nBandwidth;

	m_nState	= upsRequest;
	m_tRequest	= m_tConnected;
	m_nTimeoutTraffic	= Settings.Connection.TimeoutTraffic;

	OnRead();
}

//////////////////////////////////////////////////////////////////////
// CUploadTransferHTTP read handler

BOOL CUploadTransferHTTP::OnRead()
{
	CUploadTransfer::OnRead();

	switch ( m_nState )
	{
	case upsRequest:
	case upsQueued:
		if ( ! ReadRequest() ) return FALSE;
		if ( m_nState != upsHeaders ) break;

	case upsHeaders:
		return ReadHeaders();

	}

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CUploadTransferHTTP read : request line

BOOL CUploadTransferHTTP::ReadRequest()
{
	CString strLine;

	if ( ! m_pInput->ReadLine( strLine ) ) return TRUE;
	if ( strLine.GetLength() > 512 ) strLine = _T("#LINE_TOO_LONG#");

	if ( m_nState == upsQueued && m_pQueue != NULL )
	{
		DWORD tLimit = Settings.Uploads.QueuePollMin;

		tLimit *= m_nReaskMultiplier;

		if ( GetTickCount() - m_tRequest < tLimit )
		{
			theApp.Message( MSG_ERROR, IDS_UPLOAD_BUSY_FAST, (LPCTSTR)m_sAddress );
			Close();
			return FALSE;
		}
	}

	int nChar = strLine.Find( _T(" HTTP/") );

	if ( strLine.GetLength() < 14 || nChar < 5 ||
		( strLine.Left( 4 ) != _T("GET ") && strLine.Left( 5 ) != _T("HEAD ") ) )
	{
		theApp.Message( MSG_ERROR, IDS_UPLOAD_NOHTTP, (LPCTSTR)m_sAddress );
		Close();
		return FALSE;
	}

	theApp.Message( MSG_SYSTEM, _T("Recieved HTTP request: %s "),strLine);

	ClearRequest();

	m_bHead			= ( strLine.Left( 5 ) == _T("HEAD ") );
	m_bConnectHdr	= FALSE;
	m_bHostBrowse	= FALSE;
	m_bDeflate		= FALSE;
	m_bBackwards	= FALSE;
	m_bRange		= FALSE;
	m_bQueueMe		= FALSE;
	m_bNotShareaza  = FALSE;

	m_bMetadata		= FALSE;
	m_bTigerTree	= FALSE;
	m_bHttp11		= _tcsistr( strLine.Mid(nChar), _T(" HTTP/1.1") ) != NULL;
	m_bKeepAlive	= m_bHttp11;

	m_sAltG1Locations.Empty();
	m_sXAlt.Empty();
	m_sXNAlt.Empty();
	m_sAltLocations.Empty();
	m_sXG2Alt.Empty();
	m_sRanges.Empty();

	CString strRequest = strLine.Mid( m_bHead ? 5 : 4, nChar - ( m_bHead ? 5 : 4 ) );

	if ( strRequest.GetLength() > 5 && strRequest.Right( 1 ) == _T("/") )
	{
		strRequest = strRequest.Left( strRequest.GetLength() - 1 );
	}

	strRequest = URLDecode( strRequest );

	if ( strRequest != m_sRequest )
	{
		if ( m_sRequest.Find( _T("/gnutella/tigertree/") ) < 0 &&
			strRequest.Find( _T("/gnutella/tigertree/") ) < 0 &&
			m_sRequest.Find( _T("/gnutella/thex/") ) < 0 &&
			strRequest.Find( _T("/gnutella/thex/") ) < 0 &&
			m_sRequest.Find( _T("/gnutella/metadata/") ) < 0 &&
			strRequest.Find( _T("/gnutella/metadata/") ) < 0 )
		{
			UploadQueues.Dequeue( this );
		}

		m_sRequest = strRequest;
	}

	theApp.Message( MSG_DEBUG, _T("%s: UPLOAD PATH: %s"), (LPCTSTR)m_sAddress, (LPCTSTR)m_sRequest );

	m_nState	= upsHeaders;
	m_tRequest	= GetTickCount();
	m_nTimeoutTraffic	= Settings.Connection.TimeoutTraffic;

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CUploadTransferHTTP read : headers

BOOL CUploadTransferHTTP::OnHeaderLine(CString& strHeader, CString& strValue)
{
	theApp.Message( MSG_DEBUG, _T("%s: UPLOAD HEADER: %s: %s"), (LPCTSTR)m_sAddress, (LPCTSTR)strHeader, strValue );

	if ( strHeader.CompareNoCase( _T("Connection") ) == 0 )
	{
		if ( strValue.CompareNoCase( _T("close") ) == 0 ) m_bKeepAlive = FALSE;
		if ( strValue.CompareNoCase( _T("keep-alive") ) == 0 ) m_bKeepAlive = TRUE;
		m_bConnectHdr = TRUE;
	}
	else if ( strHeader.CompareNoCase( _T("Accept") ) == 0 )
	{
		CharLower( strValue.GetBuffer() );
		strValue.ReleaseBuffer();
		if ( strValue.Find( _T("application/x-gnutella-packets") ) >= 0 ) m_bHostBrowse = 1;
		if ( strValue.Find( _T("application/x-gnutella2") ) >= 0 ) m_bHostBrowse = 2;
		if ( strValue.Find( _T("application/x-shareaza") ) >= 0 ) m_bHostBrowse = 2;
	}
	else if ( strHeader.CompareNoCase( _T("Accept-Encoding") ) == 0 )
	{
		if ( _tcsistr( strValue, _T("deflate") ) ) m_bDeflate = TRUE;
		if ( Settings.Uploads.AllowBackwards && _tcsistr( strValue, _T("backwards") ) ) m_bBackwards = TRUE;
	}
	else if ( strHeader.CompareNoCase( _T("Range") ) == 0 )
	{
		QWORD nFrom = 0, nTo = 0;

		if ( _stscanf( strValue, _T("bytes=%I64i-%I64i"), &nFrom, &nTo ) == 2 )
		{
			m_nOffset	= nFrom;
			m_nLength	= nTo + 1 - nFrom;
			m_bRange	= TRUE;
		}
		else if ( _stscanf( strValue, _T("bytes=%I64i-"), &nFrom ) == 1 )
		{
			m_nOffset	= nFrom;
			m_nLength	= SIZE_UNKNOWN;
			m_bRange	= TRUE;
		}
	}
	else if (	strHeader.CompareNoCase( _T("X-Gnutella-Content-URN") ) == 0 ||
				strHeader.CompareNoCase( _T("Content-URN") ) == 0 )
	{
		HashesFromURN( strValue );
		m_nGnutella |= 1;
	}
	else if ( strHeader.CompareNoCase( _T("X-Content-URN") ) == 0 )
	{
		HashesFromURN( strValue );
		m_nGnutella |= 2;
	}
	else if (	strHeader.CompareNoCase( _T("X-Gnutella-Alternate-Location") ) == 0 )
	{
		if ( Settings.Library.SourceMesh )
		{
			if ( strValue.Find( _T("Zhttp://") ) < 0 ) m_sAltG1Locations = strValue;
		}
		m_nGnutella |= 1;
	}
	else if ( strHeader.CompareNoCase( _T("X-Alt") ) == 0 )
	{
		if ( Settings.Library.SourceMesh )
		{
			if ( strValue.Find( _T("Zhttp://") ) < 0 ) m_sXAlt = strValue;
		}
		m_nGnutella |= 1;
	}
	else if ( strHeader.CompareNoCase( _T("Alt-Location") ) == 0 )
	{
		if ( Settings.Library.SourceMesh )
		{
			if ( strValue.Find( _T("Zhttp://") ) < 0 ) m_sAltLocations = strValue;
		}
		m_nGnutella |= 2;
	}
	else if ( strHeader.CompareNoCase( _T("X-G2Alt") ) == 0 )
	{
		if ( Settings.Library.SourceMesh )
		{
			if ( strValue.Find( _T("Zhttp://") ) < 0 ) m_sXG2Alt = strValue;
		}
		m_nGnutella |= 2;
	}
	else if ( strHeader.CompareNoCase( _T("X-NAlt") ) == 0 )
	{
		if ( Settings.Library.SourceMesh )
		{
			if ( strValue.Find( _T("Zhttp://") ) < 0 ) m_sXNAlt = strValue;
		}
		m_nGnutella |= 1;
		/*
			// Dead alt-sources
			LPCTSTR pszURN = (LPCTSTR)m_sRequest + 13;
			CSingleLock oLock( &Library.m_pSection );

			if ( CDownload* pDownload = Downloads.FindByURN( pszURN ) )
			{
				if ( Settings.Library.SourceMesh )
				{
					if ( strValue.Find( _T("://") ) < 0 )
					{
						pDownload->AddSourceURLs( strValue, TRUE, TRUE );
					}
				}
			}
			m_nGnutella |= 1;
		*/
	}
	else if ( strHeader.CompareNoCase( _T("X-Node") ) == 0 )
	{
		m_bNotShareaza = TRUE; // Shareaza doesn't send this header
		m_nGnutella |= 1;
	}
	else if ( strHeader.CompareNoCase( _T("X-Queue") ) == 0 )
	{
		m_bQueueMe = TRUE;
		m_nGnutella |= 1;
		if ( strValue == _T("1.0") ) m_bNotShareaza = TRUE;			// Shareaza doesn't send this value
	}
	else if (	strHeader.CompareNoCase( _T("X-Nick") ) == 0 ||
				strHeader.CompareNoCase( _T("X-Name") ) == 0 ||
				strHeader.CompareNoCase( _T("X-UserName") ) == 0 )
	{
		m_sNick = URLDecode( strValue );
	}
	else if ( strHeader.CompareNoCase( _T("X-Features") ) == 0 )
	{
		if ( _tcsistr( strValue, _T("g2/") ) != NULL ) m_nGnutella |= 2;
		if ( _tcsistr( strValue, _T("gnet2/") ) != NULL ) m_nGnutella |= 2;
		if ( _tcsistr( strValue, _T("gnutella2/") ) != NULL ) m_nGnutella |= 2;
		if ( m_nGnutella == 0 ) m_nGnutella = 1;
	}
	else if ( strHeader.CompareNoCase( _T("X-PAlt") ) == 0 ||
			  strHeader.CompareNoCase( _T("FP-1a") ) == 0 ||
			  strHeader.CompareNoCase( _T("FP-Auth-Challenge") ) == 0 )
	{
		m_nGnutella |= 1;
	}
	else if ( strHeader.CompareNoCase( _T("X-MyGUID") ) == 0 )
	{
		strValue.Trim();
		for ( int nByte = 0 ; nByte < 16 ; nByte++ )
		{
			int nValue;
			_stscanf( strValue.Mid( nByte * 2, 2 ), _T("%X"), &nValue );
			m_oGUID[ nByte ] = (BYTE)nValue;
		}
		m_oGUID.validate();
	}
	else if ( strHeader.CompareNoCase( _T("X-G2NH") ) == 0 )
	{
		// The remote computer is giving us a list of G2 hubs the remote node is connected to
		// Not really Useful here because there is no way to find/store both Hub address and
		// GUID to PUSH connect to remote node at this time... but might be useful in future.
		int nCount = 0;
		HubList oHubList;
		CString sHublist(strValue);
		for ( sHublist += ',' ; ; ) 
		{
			int nPos = sHublist.Find( ',' );		// Set nPos to the distance in characters from the start to the comma
			if ( nPos < 0 ) break;					// If no comma was found, leave the loop
			CString sHub = sHublist.Left( nPos );	// Copy the text up to the comma into strHost
			sHublist = sHublist.Mid( nPos + 1 );    // Clip that text and the comma off the start of strValue

			SOCKADDR_IN pHub;
			if ( StrToSockaddr( sHub, pHub ) )
			{
				nCount++;
				oHubList.push_back(pHub);
			}
		}
		if ( nCount > 0 ) m_oHubList = oHubList;
		m_nGnutella |= 2;
	}

	return CUploadTransfer::OnHeaderLine( strHeader, strValue );
}

//////////////////////////////////////////////////////////////////////
// CUploadTransferHTTP process request

BOOL CUploadTransferHTTP::OnHeadersComplete()
{
	if ( Uploads.EnforcePerHostLimit( this, TRUE ) ) return FALSE;

	if ( _tcsistr( m_sUserAgent, _T("shareaza") ) != NULL )
	{
		// Assume certain capabilitites for various Shareaza versions
		m_nGnutella |= 3;
		if ( m_sUserAgent == _T("Shareaza 1.4.0.0") ) m_bQueueMe = TRUE;

		// Check for non-shareaza clients spoofing a Shareaza user agent
		if ( m_bNotShareaza )
		{
			SendResponse( IDR_HTML_FILENOTFOUND );
			theApp.Message( MSG_ERROR, _T("Client %s has a spoofed user agent, banning"), (LPCTSTR)m_sAddress );

			Security.Ban( &m_pHost.sin_addr, banWeek, FALSE );
			Remove( FALSE );
			return FALSE;
		}
	}
	else if ( _tcsistr( m_sUserAgent, _T("trustyfiles") ) != NULL ||
			  _tcsistr( m_sUserAgent, _T("gnucdna") ) != NULL ||
			  _tcsistr( m_sUserAgent, _T("adagio") ) != NULL )
	{
		// Assume Gnutella2 capability for certain user-agents
		m_nGnutella |= 3;
	}
	else if ( m_nGnutella & 2 )
	{
		// Check for clients spoofing a G2 header
		if ( _tcsistr( m_sUserAgent, _T("phex") ) != NULL ||
			_tcsistr( m_sUserAgent, _T("limewire") ) != NULL ||
			_tcsistr( m_sUserAgent, _T("gtk-gnutella") ) != NULL )
		{
			// This is actually a G1-only client sending a fake header, so they can download 
			// from (but not upload to) clients that are only connected to G2. 
			m_nGnutella = 1;

			if ( ! Settings.Gnutella1.EnableToday )
			{
				// Terminate the connection and do not try to download from them.
				SendResponse( IDR_HTML_FILENOTFOUND );
				theApp.Message( MSG_ERROR, _T("Client %s has a fake G2 header, banning"), (LPCTSTR)m_sAddress );

				Security.Ban( &m_pHost.sin_addr, banWeek, FALSE );
				Remove( FALSE );
				return FALSE;
			}
		}
	}

	if ( m_sRequest == _T("/") || StartsWith( m_sRequest, _T("/gnutella/browse/v1") ) )
	{
		// Requests for "/" or the browse path are handled the same way

		if ( ( m_bHostBrowse == 1 && ! Settings.Community.ServeFiles ) ||
			 ( m_bHostBrowse == 2 && ! Settings.Community.ServeProfile && ! Settings.Community.ServeFiles ) )
		{
			theApp.Message( MSG_ERROR, IDS_UPLOAD_BROWSE_DENIED, (LPCTSTR)m_sAddress );
			m_bHostBrowse = FALSE;
		}

		if ( m_bHostBrowse )
		{
			RequestHostBrowse();
		}
		else
		{
			theApp.Message( MSG_DEFAULT, IDS_UPLOAD_ABOUT, (LPCTSTR)m_sAddress, (LPCTSTR)m_sUserAgent );
			SendResponse( IDR_HTML_ABOUT );
		}

		return TRUE;
	}
	else if ( StartsWith( m_sRequest, _T("/remote") ) || StartsWith( m_sRequest, _T("/favicon.ico") ) )
	{
		// A web client can start requesting remote pages on the same keep-alive
		// connection after previously requesting other system objects

		if ( Settings.Remote.Enable )
		{
			m_pInput->Prefix( "GET /remote/ HTTP/1.0\r\n\r\n" );
			new CRemote( this );
			Remove( FALSE );
			return FALSE;
		}
	}
	else if ( IsAgentBlocked() )
	{
		if ( m_sFileName.IsEmpty() ) m_sFileName = _T("file");
		SendResponse( IDR_HTML_BROWSER );
		theApp.Message( MSG_ERROR, IDS_UPLOAD_BROWSER, (LPCTSTR)m_sAddress, (LPCTSTR)m_sFileName );
		Security.Ban( &m_pHost.sin_addr, ban5Mins, FALSE ); // Anti-hammer protection if client doesn't understand 403 (Don't bother re-sending HTML every 5 seconds)
		if ( m_sUserAgent.Find( _T("Mozilla") ) >= 0 ) return TRUE;
		Remove( FALSE );
		return FALSE;
	}
	else if ( IsNetworkDisabled() )
	{
		// Network isn't active- Check if we should send 404 or 403

		if ( StartsWith( m_sRequest, _T("/uri-res/N2R?urn:") ) )
		{
			LPCTSTR pszURN = (LPCTSTR)m_sRequest + 13;

			CSingleLock oLock( &Library.m_pSection );

			if ( oLock.Lock( 50 ) )
			{
				if ( CLibraryFile* pFile = LibraryMaps.LookupFileByURN( pszURN, TRUE, TRUE ) )
				{
					if ( UploadQueues.CanUpload( PROTOCOL_HTTP, pFile, TRUE ) )
					{
						// Have the file, but the network is disabled (503 Service Unavailable response).
						// We handle them in CDownloadTransferHTTP::ReadResponseLine.
						// Adjust Retry-After header in SendDefaultHeaders() if you change the ban period 
						SendResponse( IDR_HTML_DISABLED );
						theApp.Message( MSG_ERROR, IDS_UPLOAD_DISABLED, (LPCTSTR)m_sAddress, (LPCTSTR)m_sUserAgent );
						Security.Ban( &m_pHost.sin_addr, ban2Hours, FALSE ); // Anti-hammer protection if client doesn't understand 403
						Remove( FALSE );
						return FALSE;
					}
				}
			}
			// Network is disabled, but we don't have the file anyway.
			SendResponse( IDR_HTML_FILENOTFOUND );
		}
		else
		{
			SendResponse( IDR_HTML_DISABLED );
		}
		theApp.Message( MSG_ERROR, IDS_UPLOAD_DISABLED, (LPCTSTR)m_sAddress, (LPCTSTR)m_sUserAgent );
		Security.Ban( &m_pHost.sin_addr, ban2Hours, FALSE ); // Anti-hammer protection if client doesn't understand 403
		Remove( FALSE );
		return FALSE;
	}
	else if ( StartsWith( m_sRequest, _T("/gnutella/metadata/v1?urn:") ) && Settings.Uploads.ShareMetadata )
	{
		LPCTSTR pszURN = (LPCTSTR)m_sRequest + 22;
		CXMLElement* pMetadata = NULL;

		CSingleLock oLock( &Library.m_pSection, TRUE );
		if ( CLibraryFile* pShared = LibraryMaps.LookupFileByURN( pszURN, TRUE, TRUE ) )
		{
			if ( pShared->m_pMetadata != NULL )
			{
				m_sFileName	= pShared->m_sName;
				pMetadata	= pShared->m_pSchema->Instantiate( TRUE );
				pMetadata->AddElement( pShared->m_pMetadata->Clone() );
			}
			oLock.Unlock();
		}
		else
		{
			oLock.Unlock();
			if ( CDownload* pDownload = Downloads.FindByURN( pszURN ) )
			{
				if ( pDownload->m_pXML != NULL )
				{
					m_sFileName	= pDownload->m_sDisplayName;
					pMetadata	= pDownload->m_pXML->Clone();
				}
			}
		}

		if ( pMetadata != NULL ) return RequestMetadata( pMetadata );
	}
	else if ( StartsWith( m_sRequest, _T("/gnutella/tigertree/v3?urn:") ) && Settings.Uploads.ShareTiger )
	{
		LPCTSTR pszURN = (LPCTSTR)m_sRequest + 23;

		{
			CQuickLock oLock( Library.m_pSection );
			if ( CLibraryFile* pShared = LibraryMaps.LookupFileByURN( pszURN, TRUE, TRUE ) )
			{
				CTigerTree* pTigerTree = pShared->GetTigerTree();
				m_sFileName = pShared->m_sName;
				return RequestTigerTreeRaw( pTigerTree, TRUE );
			}
		}
		if ( CDownload* pDownload = Downloads.FindByURN( pszURN ) )
		{
			if ( pDownload->GetTigerTree() != NULL )
			{
				m_sFileName = pDownload->m_sDisplayName;
				return RequestTigerTreeRaw( pDownload->GetTigerTree(), FALSE );
			}
		}
	}
	else if ( StartsWith( m_sRequest, _T("/gnutella/thex/v1?urn:") ) && Settings.Uploads.ShareTiger )
	{
		LPCTSTR pszURN	= (LPCTSTR)m_sRequest + 18;
		DWORD nDepth	= 0;

		if ( LPCTSTR pszDepth = _tcsistr( m_sRequest, _T("depth=") ) )
		{
			_stscanf( pszDepth + 6, _T("%i"), &nDepth );
		}

		BOOL bHashset = ( _tcsistr( m_sRequest, _T("ed2k=1") ) != NULL );

		{
			CQuickLock oLock( Library.m_pSection );
			if ( CLibraryFile* pShared = LibraryMaps.LookupFileByURN( pszURN, TRUE, TRUE ) )
			{
				CTigerTree* pTigerTree	= pShared->GetTigerTree();
				CED2K* pHashset			= bHashset ? pShared->GetED2K() : NULL;
				m_sFileName = pShared->m_sName;
				m_nFileSize = pShared->GetSize();
				return RequestTigerTreeDIME( pTigerTree, nDepth, pHashset, TRUE );
			}
		}
		if ( CDownload* pDownload = Downloads.FindByURN( pszURN ) )
		{
			if ( pDownload->GetTigerTree() != NULL )
			{
				m_sFileName = pDownload->m_sDisplayName;
				m_nFileSize = pDownload->m_nSize;
				return RequestTigerTreeDIME( pDownload->GetTigerTree(), nDepth,
					bHashset ? pDownload->GetHashset() : NULL, FALSE );
			}
		}
	}
	else if ( StartsWith( m_sRequest, _T("/gnutella/preview/v1?urn:") ) && Settings.Uploads.SharePreviews )
	{
		LPCTSTR pszURN = (LPCTSTR)m_sRequest + 21;
		CSingleLock oLock( &Library.m_pSection, TRUE );
		CLibraryFile* pShared = LibraryMaps.LookupFileByURN( pszURN, TRUE, TRUE );
		if ( pShared != NULL ) return RequestPreview( pShared, oLock );
	}
	else if ( StartsWith( m_sRequest, _T("/uri-res/N2R?urn:") ) )
	{
		LPCTSTR pszURN = (LPCTSTR)m_sRequest + 13;

		{
			CSingleLock oLock( &Library.m_pSection, TRUE );

			if ( CLibraryFile* pShared = LibraryMaps.LookupFileByURN( pszURN, TRUE, TRUE ) )
			{
				return RequestSharedFile( pShared, oLock );
			}
		}

		CDownload* pDownload = Downloads.FindByURN( pszURN );

		if ( pDownload != NULL && pDownload->IsShared() && pDownload->IsStarted() )
		{
			return RequestPartialFile( pDownload );
		}
	}
	else if ( StartsWith( m_sRequest, _T("/get/") ) )
	{
		DWORD nIndex = 0;

		CString strFile	= m_sRequest.Mid( 5 );
		int nChar		= strFile.Find( '/' );

		if ( _stscanf( strFile, _T("%lu/"), &nIndex ) == 1 && nChar > 0 && nChar < strFile.GetLength() - 1 )
		{
			strFile = strFile.Mid( nChar + 1 );

			{
				CSingleLock oLock( &Library.m_pSection, TRUE );

				CLibraryFile* pFile = Library.LookupFile( nIndex, TRUE, TRUE );

				if ( pFile != NULL && pFile->m_sName.CompareNoCase( strFile ) )
				{
					pFile = NULL;
				}

				if ( pFile == NULL )
				{
					pFile = LibraryMaps.LookupFileByName( strFile, TRUE, TRUE );
				}

				if ( pFile != NULL ) return RequestSharedFile( pFile, oLock );
			}
		}
		else
		{
			strFile = strFile.Mid( nChar + 1 );
			CSingleLock oLock( &Library.m_pSection, TRUE );
			CLibraryFile* pFile = LibraryMaps.LookupFileByName( strFile, TRUE, TRUE );
			if ( pFile != NULL ) return RequestSharedFile( pFile, oLock );
		}
	}
	else
	{
		CString strFile = m_sRequest.Mid( 1 );
		CSingleLock oLock( &Library.m_pSection, TRUE );
		CLibraryFile* pFile = LibraryMaps.LookupFileByName( strFile, TRUE, TRUE );
		if ( pFile != NULL ) return RequestSharedFile( pFile, oLock );
	}

	if ( m_sFileName.IsEmpty() )
	{
		if ( m_oSHA1 ) m_sFileName = m_oSHA1.toUrn();
		else m_sFileName = m_sRequest;
	}

	SendResponse( IDR_HTML_FILENOTFOUND );
	theApp.Message( MSG_ERROR, IDS_UPLOAD_FILENOTFOUND, (LPCTSTR)m_sAddress, (LPCTSTR)m_sFileName );

	return TRUE;
}

BOOL CUploadTransferHTTP::IsNetworkDisabled()
{
	if ( !Network.IsConnected() ) return TRUE;
	if ( Settings.Connection.RequireForTransfers == FALSE ) return FALSE;

	if ( m_nGnutella & 2 )
	{
		if ( Settings.Gnutella2.EnableToday ) return FALSE;
	}
	else if ( m_nGnutella & 1 )
	{
		if ( Settings.Gnutella1.EnableToday ) return FALSE;
	}
	else
	{
		if ( ! Settings.Gnutella1.EnableToday &&
			 ! Settings.Gnutella2.EnableToday ) return TRUE;
	}

	return FALSE;
}

//////////////////////////////////////////////////////////////////////
// CUploadTransferHTTP request a shared file

BOOL CUploadTransferHTTP::RequestSharedFile(CLibraryFile* pFile, CSingleLock& oLibraryLock)
{
	ASSERT( pFile != NULL );

	if ( ! RequestComplete( pFile ) )
	{
		oLibraryLock.Unlock();
		SendResponse( IDR_HTML_HASHMISMATCH );
		theApp.Message( MSG_ERROR, IDS_UPLOAD_HASH_MISMATCH, (LPCTSTR)m_sAddress, (LPCTSTR)m_sFileName );
		return TRUE;
	}

	if ( IsNetworkDisabled() )
	{
		oLibraryLock.Unlock();
		SendResponse( IDR_HTML_DISABLED );
		theApp.Message( MSG_ERROR, IDS_UPLOAD_DISABLED, (LPCTSTR)m_sAddress, (LPCTSTR)m_sFileName );
		return TRUE;
	}

	if ( ! UploadQueues.CanUpload( PROTOCOL_HTTP, pFile ) )
	{
		// File is not uploadable. (No queue, is a ghost, etc)
		if ( m_sFileName.IsEmpty() ) m_sFileName = m_oSHA1.toUrn();

		oLibraryLock.Unlock();
		SendResponse( IDR_HTML_FILENOTFOUND );
		theApp.Message( MSG_ERROR, IDS_UPLOAD_FILENOTFOUND, (LPCTSTR)m_sAddress, (LPCTSTR)m_sFileName );
		return TRUE;
	}

	m_bTigerTree	= bool( m_oTiger );
	m_bMetadata		= ( pFile->m_pMetadata != NULL && ( pFile->m_bMetadataAuto == FALSE || pFile->m_nVirtualSize > 0 ) );

	if ( ! m_oSHA1 && ! m_oTiger && ! m_oED2K && ! m_oMD5 ) m_sAltG1Locations.Empty();
	if ( ! m_oSHA1 ) m_sXAlt.Empty();
	if ( ! m_oSHA1 ) m_sXNAlt.Empty();
	if ( ! m_oSHA1 && ! m_oTiger && ! m_oED2K && ! m_oMD5 ) m_sAltLocations.Empty();
	if ( ! m_oSHA1 && ! m_oTiger && ! m_oED2K && ! m_oMD5 ) m_sXG2Alt.Empty();

	if ( m_nLength == SIZE_UNKNOWN ) m_nLength = m_nFileSize - m_nOffset;

	if ( m_nOffset >= m_nFileSize || m_nOffset + m_nLength > m_nFileSize )
	{
		oLibraryLock.Unlock();
		SendResponse( IDR_HTML_BADRANGE );
		theApp.Message( MSG_ERROR, IDS_UPLOAD_BAD_RANGE, (LPCTSTR)m_sAddress, (LPCTSTR)m_sFileName );
		return TRUE;
	}

	if ( Settings.Library.SourceMesh )
	{
		CString strLocations;

		strLocations = pFile->GetAlternateSources( &m_pSourcesSent, 15, PROTOCOL_G1 );
		if ( m_sXAlt.GetLength() ) pFile->AddAlternateSources( m_sXAlt );
		m_sXAlt = strLocations;

		strLocations = pFile->GetAlternateSources( &m_pSourcesSent, 15, PROTOCOL_HTTP );
		if ( m_sAltG1Locations.GetLength() ) pFile->AddAlternateSources( m_sAltG1Locations );
		m_sAltG1Locations = strLocations;

		strLocations = pFile->GetAlternateSources( &m_pSourcesSent, 15, PROTOCOL_G2 );
		if ( m_sAltLocations.GetLength() ) pFile->AddAlternateSources( m_sAltLocations );
		m_sAltLocations = strLocations;

		strLocations = pFile->GetAlternateSources( &m_pSourcesSent, 15, PROTOCOL_HTTP );
		if ( m_sXG2Alt.GetLength() ) pFile->AddAlternateSources( m_sXG2Alt );
		m_sXG2Alt = strLocations;
	}

	oLibraryLock.Unlock();

	return QueueRequest();
}

//////////////////////////////////////////////////////////////////////
// CUploadTransferHTTP request a partial file

BOOL CUploadTransferHTTP::RequestPartialFile(CDownload* pDownload)
{
	ASSERT( pDownload != NULL );
	ASSERT( pDownload->IsStarted() );

	if ( ! RequestPartial( pDownload ) )
	{
		SendResponse( IDR_HTML_HASHMISMATCH );
		theApp.Message( MSG_ERROR, IDS_UPLOAD_HASH_MISMATCH, (LPCTSTR)m_sAddress, (LPCTSTR)m_sFileName );
		return TRUE;
	}

	ASSERT( m_nFileBase == 0 );

	m_bTigerTree	= ( m_oTiger && pDownload->GetTigerTree() != NULL );
	m_bMetadata		= ( pDownload->m_pXML != NULL );

	if ( m_sAltG1Locations.GetLength() ) pDownload->AddSourceURLs( m_sAltG1Locations, TRUE, FALSE, PROTOCOL_HTTP );
	if ( m_sXAlt.GetLength() ) pDownload->AddSourceURLs( m_sXAlt, TRUE, FALSE, PROTOCOL_G1 );
	if ( m_sAltLocations.GetLength() ) pDownload->AddSourceURLs( m_sAltLocations, TRUE, FALSE, PROTOCOL_HTTP );
	if ( m_sXG2Alt.GetLength() ) pDownload->AddSourceURLs( m_sXG2Alt, TRUE, FALSE, PROTOCOL_G2 );
	// if ( Settings.Library.SourceMesh ) m_sLocations = pDownload->GetSourceURLs( &m_pSourcesSent, 15, PROTOCOL_HTTP, NULL );
	if ( Settings.Library.SourceMesh ) 
	{
		BOOL bXG1AltLoc = FALSE, bXAlt = FALSE, bAltLoc = FALSE, bXG2Alt = FALSE;
		if ( m_sAltG1Locations.GetLength() )
		{
			bXG1AltLoc = TRUE;
			m_sAltG1Locations.Empty();
		}
		if ( m_sXAlt.GetLength() )
		{
			bXAlt = TRUE;
			m_sXAlt.Empty();
		}
		if ( m_sAltLocations.GetLength() )
		{
			bAltLoc = TRUE;
			m_sAltLocations.Empty();
		}
		if ( m_sXG2Alt.GetLength() )
		{
			bXG2Alt = TRUE;
			m_sXG2Alt.Empty();
		}

		if ( m_nGnutella == 1 )
		{
			if ( bXAlt )
			{
				m_sXAlt = pDownload->GetSourceURLs( &m_pSourcesSent, 15, PROTOCOL_G1, NULL );
			}
			else if ( bXG1AltLoc )
			{
				m_sAltG1Locations = pDownload->GetSourceURLs( &m_pSourcesSent, 15, PROTOCOL_HTTP, NULL );
			}
		}
		if ( m_nGnutella == 2 )
		{
			if ( bXG2Alt )
			{
				m_sXG2Alt = pDownload->GetSourceURLs( &m_pSourcesSent, 15, PROTOCOL_G2, NULL );
			}
			else if ( bAltLoc )
			{
				m_sAltLocations = pDownload->GetSourceURLs( &m_pSourcesSent, 15, PROTOCOL_HTTP, NULL );
			}
		}
	}

	m_sRanges = pDownload->GetAvailableRanges();

	if ( m_bRange && m_nOffset == 0 && m_nLength == SIZE_UNKNOWN )
	{
		pDownload->GetRandomRange( m_nOffset, m_nLength );
	}

	if ( m_nLength == SIZE_UNKNOWN ) m_nLength = m_nFileSize - m_nOffset;

	if ( pDownload->ClipUploadRange( m_nOffset, m_nLength ) )
	{
		return QueueRequest();
	}

	if ( pDownload->IsMoving() )
	{
		if ( GetTickCount() - pDownload->m_tCompleted < 30000 )
		{
			m_pOutput->Print( "HTTP/1.1 503 Range Temporarily Unavailable\r\n" );
		}
		else
		{
			SendResponse( IDR_HTML_FILENOTFOUND );
			theApp.Message( MSG_ERROR, IDS_UPLOAD_FILENOTFOUND, (LPCTSTR)m_sAddress, (LPCTSTR)m_sFileName );
			return TRUE;
		}
	}
	else if ( pDownload->GetTransferCount() )
	{
		m_pOutput->Print( "HTTP/1.1 503 Range Temporarily Unavailable\r\n" );
	}
	else
	{
		m_pOutput->Print( "HTTP/1.1 416 Requested Range Unavailable\r\n" );
	}

	SendDefaultHeaders();
	SendFileHeaders();

	m_pOutput->Print( "Content-Length: 0\r\n" );
	m_pOutput->Print( "\r\n" );

	StartSending( upsResponse );

	theApp.Message( MSG_DEFAULT, IDS_UPLOAD_BAD_RANGE, (LPCTSTR)m_sAddress, (LPCTSTR)m_sFileName );

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CUploadTransferHTTP queue the request if necessary

BOOL CUploadTransferHTTP::QueueRequest()
{
	if ( m_bHead ) return OpenFileSendHeaders();

	AllocateBaseFile();

	UINT nError		= 0;
	int nPosition	= 0;

	if ( m_bStopTransfer )
	{

		m_tRotateTime = 0;
		m_bStopTransfer	= FALSE;

		CUploadQueue* pQueue = m_pQueue;
		if ( pQueue ) pQueue->Dequeue( this );
	}


	if ( Uploads.CanUploadFileTo( &m_pHost.sin_addr, m_oSHA1 ) )
	{
		if ( ( nPosition = UploadQueues.GetPosition( this, TRUE ) ) >= 0 )
		{
			ASSERT( m_pQueue != NULL );

			// If the queue can't accept this file
			if ( ! m_pQueue->CanAccept( m_nProtocol, m_sFileName, m_nFileSize, 
				( m_bFilePartial ? CUploadQueue::ulqPartial: CUploadQueue::ulqLibrary ), m_sFileTags ) )
			{	// This is probably a partial that has completed
				theApp.Message( MSG_DEBUG, _T("File queue error- Partial may have recently completed") );

				// Might as well allow the upload... so don't do anything.
				//ASSERT( FALSE );
			}


			if ( nPosition == 0 )
			{
				// Queued, and ready to send
				return OpenFileSendHeaders();
			}
			else
			{
				// Queued, but must wait
			}
		}
		else if ( UploadQueues.Enqueue( this ) )
		{
			ASSERT( m_pQueue != NULL );
			ASSERT( m_pQueue->CanAccept( m_nProtocol, m_sFileName, m_nFileSize, 
				( m_bFilePartial ? CUploadQueue::ulqPartial : CUploadQueue::ulqLibrary ), m_sFileTags ) );

			nPosition = UploadQueues.GetPosition( this, TRUE );
			ASSERT( nPosition >= 0 );

			if ( nPosition == 0 )
			{
				// Queued, and ready to send
				return OpenFileSendHeaders();
			}
			else if ( m_bQueueMe )
			{
				// Queued, but must wait
			}
			else
			{
				// Client can't queue, so dequeue and return busy
				UploadQueues.Dequeue( this );
				ASSERT( m_pQueue == NULL );
			}
		}
		else
		{
			// Unable to queue anywhere
		}
	}
	else
	{
		// Too many from this host

		UploadQueues.Dequeue( this );
		ASSERT( m_pQueue == NULL );

		nError = IDS_UPLOAD_BUSY_HOST;
	}

	if ( m_pQueue != NULL )
	{
		CString strHeader, strName;

		m_pOutput->Print( "HTTP/1.1 503 Busy Queued\r\n" );

		SendDefaultHeaders();
		SendFileHeaders();

		m_nReaskMultiplier=( nPosition <= 9 ) ? ( (nPosition+1) / 2 ) : 5;
		DWORD nTimeScale = 1000 / m_nReaskMultiplier;

		CSingleLock pLock( &UploadQueues.m_pSection, TRUE );

		if ( UploadQueues.Check( m_pQueue ) )
		{
			strName = m_pQueue->m_sName;
			Replace( strName, _T("\""), _T("'") );

			strHeader.Format( _T("X-Queue: position=%i,length=%i,limit=%i,pollMin=%lu,pollMax=%lu,id=\"%s\"\r\n"),
				nPosition,
				m_pQueue->GetQueuedCount(),
				m_pQueue->GetTransferCount( TRUE ),
				Settings.Uploads.QueuePollMin / nTimeScale,
				Settings.Uploads.QueuePollMax / nTimeScale,
				(LPCTSTR)strName );

			theApp.Message( MSG_DEFAULT, IDS_UPLOAD_QUEUED, (LPCTSTR)m_sFileName,
				(LPCTSTR)m_sAddress, nPosition, m_pQueue->GetQueuedCount(),
				(LPCTSTR)strName );

			m_nTimeoutTraffic	= DWORD( Settings.Uploads.QueuePollMax * m_nReaskMultiplier );
		}

		pLock.Unlock();

		m_pOutput->Print( strHeader );

		m_pOutput->Print( "Content-Length: 0\r\n" );
		m_pOutput->Print( "\r\n" );

		StartSending( upsPreQueue );
	}
	else
	{
		SendResponse( IDR_HTML_BUSY, TRUE );

		if ( ! nError ) nError = m_bQueueMe ? IDS_UPLOAD_BUSY_QUEUE : IDS_UPLOAD_BUSY_OLD;
		theApp.Message( MSG_ERROR, nError, (LPCTSTR)m_sFileName, (LPCTSTR)m_sAddress, (LPCTSTR)m_sUserAgent );
	}

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CUploadTransferHTTP default response headers

void CUploadTransferHTTP::SendDefaultHeaders()
{
	CString strLine = Settings.SmartAgent();

	if ( strLine.GetLength() )
	{
		strLine = _T("Server: ") + strLine + _T("\r\n");
		m_pOutput->Print( strLine );
	}

	if ( ! m_bInitiated )
	{
		strLine.Format( _T("Remote-IP: %s\r\n"),
			(LPCTSTR)CString( inet_ntoa( m_pHost.sin_addr ) ) );
		m_pOutput->Print( strLine );
	}
	else if ( Network.m_bEnabled && m_bInitiated && Settings.Gnutella2.EnableToday )
	{
		CG2Neighbour * NHubs;
		CString strPort;
		int nHubCount = 0;
		strLine = "X-G2NH: ";

		CSingleLock pNetLock( &Network.m_pSection );
		if ( pNetLock.Lock( 50 ) )
		{
			std::list<CG2Neighbour*>::iterator iIndex = Neighbours.m_oG2Hubs.begin();
			std::list<CG2Neighbour*>::iterator iEnd = Neighbours.m_oG2Hubs.end();
			for (;iIndex != iEnd; iIndex++ )
			{
				NHubs = *iIndex;
				if ( nHubCount ) strLine	+= _T(",");
				strLine	+= CString( inet_ntoa( NHubs->m_pHost.sin_addr ) ) + _T(':');
				strPort.Format( _T("%hu") ,ntohs( NHubs->m_pHost.sin_port ) );
				strLine += strPort;
				nHubCount++;
			}
		}

		if (nHubCount)
		{
			strLine += "\r\n";
			m_pOutput->Print( strLine );
		}
	}

	if ( IsNetworkDisabled() )
	{
		// Ask to retry after some delay in seconds
		strLine.Format( L"Retry-After: %lu", 
			m_nGnutella == 1 ? Settings.Gnutella1.RequeryDelay * 60 
							 : Settings.Gnutella2.RequeryDelay * 3600 );
		m_pOutput->Print( strLine + _T("\r\n") );
	}
	else if ( m_bKeepAlive )
	{
		m_pOutput->Print( "Connection: Keep-Alive\r\n" );
	}

	m_pOutput->Print( "Accept-Ranges: bytes\r\n" );

	if ( m_nRequests <= 1 )
	{
		if ( m_bInitiated ) SendMyAddress();
		strLine.Format( _T("X-PerHost: %lu\r\n"), Settings.Uploads.MaxPerHost );
		m_pOutput->Print( strLine );

		strLine = MyProfile.GetNick().Left( 255 );

		if ( strLine.GetLength() > 0 )
		{
			strLine = _T("X-Nick: ") + URLEncode( strLine ) + _T("\r\n");
			m_pOutput->Print( strLine );
		}
	}
}

//////////////////////////////////////////////////////////////////////
// CUploadTransferHTTP file response headers

void CUploadTransferHTTP::SendFileHeaders()
{
	CString strHeader;

	if ( m_oSHA1 )
	{
		if ( m_oTiger )
		{
			strHeader	= _T("X-Content-URN: urn:bitprint:")
						+ m_oSHA1.toString() + '.'
						+ m_oTiger.toString() + _T("\r\n");
		}
		else
		{
			strHeader = _T("X-Content-URN: ") + m_oSHA1.toUrn() + _T("\r\n");
		}

		m_pOutput->Print( strHeader );
	}
	else if ( m_oTiger )
	{
		strHeader = _T("X-Content-URN: ") + m_oTiger.toUrn() + _T("\r\n");
		m_pOutput->Print( strHeader );
	}

	if ( m_oED2K )
	{
		strHeader = _T("X-Content-URN: ") + m_oED2K.toUrn()
			+ _T("\r\n");
		m_pOutput->Print( strHeader );
	}

	if ( m_oMD5 )
	{
		strHeader = _T("X-Content-URN: ") + m_oMD5.toUrn()
			+ _T("\r\n");
		m_pOutput->Print( strHeader );
	}

	if ( m_bTigerTree && Settings.Uploads.ShareTiger )
	{
		strHeader	= _T("X-Thex-URI: /gnutella/thex/v1?")
			+ m_oTiger.toUrn()
			+ _T("&depth=9&ed2k=0;") 
			+ m_oTiger.toString()
			+ _T("\r\n");
		m_pOutput->Print( strHeader );
	}

	if ( m_bMetadata )
	{
		strHeader	= _T("X-Metadata-Path: /gnutella/metadata/v1?")
					+ m_oTiger.toUrn()
					+ _T("\r\n");
		m_pOutput->Print( strHeader );
	}

	if ( m_sRanges.GetLength() )
	{
		strHeader = _T("X-Available-Ranges: ") + m_sRanges + _T("\r\n");
		m_pOutput->Print( strHeader );
	}

	if ( m_sAltLocations.GetLength() )
	{
		strHeader = _T("X-Gnutella-Alternate-Location: ") + m_sAltLocations + _T("\r\n");
		m_pOutput->Print( strHeader );
	}

	if ( m_sXAlt.GetLength() )
	{
		strHeader = _T("X-Alt: ") + m_sXAlt + _T("\r\n");
		m_pOutput->Print( strHeader );
	}

	if ( m_sAltLocations.GetLength() )
	{
		strHeader = _T("Alt-Location: ") + m_sAltLocations + _T("\r\n");
		m_pOutput->Print( strHeader );
	}

	if ( m_sXG2Alt.GetLength() )
	{
		strHeader = _T("X-G2Alt: ") + m_sXG2Alt + _T("\r\n");
		m_pOutput->Print( strHeader );
	}

	if ( m_pQueue == NULL && !m_bHead )
	{
		// Ask to retry after some delay in seconds
		strHeader.Format( L"Retry-After: %lu", 
			m_nGnutella == 1 ? Settings.Gnutella1.RequeryDelay * 60 
							: Settings.Gnutella2.RequeryDelay * 3600 );
		m_pOutput->Print( strHeader + _T("\r\n") );
	}

	if ( m_nGnutella & 1 )
	{
		LPCTSTR pszURN = (LPCTSTR)m_sRequest + 13;
		CSingleLock oLock( &Library.m_pSection );

		// Send X-NAlt for partial transfers only
		if ( CDownload* pDownload = Downloads.FindByURN( pszURN ) )
		{
			strHeader = pDownload->GetTopFailedSources( 15, PROTOCOL_G1 ) + _T("\r\n");
			if ( strHeader.GetLength() ) m_pOutput->Print( _T("X-NAlt: ") + strHeader );
		}
	}
}

//////////////////////////////////////////////////////////////////////
// CUploadTransferHTTP open file and send headers

BOOL CUploadTransferHTTP::OpenFileSendHeaders()
{
	ASSERT( m_pDiskFile == NULL );

	m_pDiskFile = TransferFiles.Open( m_sFilePath, FALSE, FALSE );

	// If there's an error reading the file from disk
	if ( m_pDiskFile == NULL )
	{
		SendResponse( IDR_HTML_FILENOTFOUND );
		theApp.Message( MSG_ERROR, IDS_UPLOAD_CANTOPEN, (LPCTSTR)m_sFileName, (LPCTSTR)m_sAddress );
		return TRUE;
	}

	CSingleLock pLock( &UploadQueues.m_pSection, TRUE );

	if ( m_pQueue != NULL && UploadQueues.Check( m_pQueue ) && m_pQueue->m_bRotate )
	{
		DWORD nLimit = m_pQueue->m_nRotateChunk;
		if ( nLimit == 0 ) nLimit = Settings.Uploads.RotateChunkLimit;
		if ( nLimit > 0 ) m_nLength = min( m_nLength, nLimit );
	}

	pLock.Unlock();

	if ( m_nLength != m_nFileSize )
		m_pOutput->Print( "HTTP/1.1 206 OK\r\n" );
	else
		m_pOutput->Print( "HTTP/1.1 200 OK\r\n" );

	SendDefaultHeaders();

	CString strExt, strResponse;

	int nType = m_sFileName.ReverseFind( '.' );
	if ( nType > 0 ) strExt = m_sFileName.Mid( nType );
	ShellIcons.Lookup( strExt, NULL, NULL, NULL, &strResponse );

	if ( strResponse.IsEmpty() )
	{
		m_pOutput->Print( "Content-Type: application/x-binary\r\n" );
	}
	else
	{
		strResponse = _T("Content-Type: ") + strResponse + _T("\r\n");
		m_pOutput->Print( strResponse );
	}

	strResponse.Format( _T("Content-Length: %I64i\r\n"), m_nLength );
	m_pOutput->Print( strResponse );

	if ( m_nLength != m_nFileSize )
	{
		strResponse.Format( _T("Content-Range: bytes=%I64i-%I64i/%I64i\r\n"), m_nOffset, m_nOffset + m_nLength - 1, m_nFileSize );
		m_pOutput->Print( strResponse );
	}

	if ( ! m_bHead && m_bBackwards )
	{
		m_pOutput->Print( "Content-Encoding: backwards\r\n" );
	}

	if ( m_oSHA1 || m_oTiger || m_oED2K ) SendFileHeaders();

	m_pOutput->Print( "\r\n" );

	if ( m_bHead )
	{
		m_pDiskFile->Release( FALSE );
		m_pDiskFile = NULL;

		theApp.Message( MSG_DEFAULT, IDS_UPLOAD_HEADERS, (LPCTSTR)m_sFileName,
			(LPCTSTR)m_sAddress, (LPCTSTR)m_sUserAgent );

		StartSending( upsResponse );
	}
	else
	{
		if ( m_pBaseFile->m_nRequests++ == 0 )
		{
			theApp.Message( MSG_SYSTEM, IDS_UPLOAD_FILE,
				(LPCTSTR)m_sFileName, (LPCTSTR)m_sAddress );

			CQuickLock oLock( Library.m_pSection );
			if ( CLibraryFile* pFile = LibraryMaps.LookupFileByPath( m_sFilePath, TRUE, TRUE ) )
			{
				pFile->m_nUploadsToday++;
				pFile->m_nUploadsTotal++;
			}
		}

		theApp.Message( MSG_DEFAULT,
			m_sRanges.GetLength() ? IDS_UPLOAD_PARTIAL_CONTENT : IDS_UPLOAD_CONTENT,
			m_nOffset, m_nOffset + m_nLength - 1, (LPCTSTR)m_sFileName,
			(LPCTSTR)m_sAddress, (LPCTSTR)m_sUserAgent );

		StartSending( upsUploading );
	}

	OnWrite();

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CUploadTransferHTTP write handler

BOOL CUploadTransferHTTP::OnWrite()
{
	if ( m_nState == upsUploading && m_pDiskFile != NULL && m_pOutput->m_nLength == 0 )
	{
		if ( m_nPosition >= m_nLength )
		{
			OnCompleted();
			CUploadTransfer::OnWrite();
			return TRUE;
		}

		QWORD nPacket = min( m_nLength - m_nPosition, Transfers.m_nBuffer );
		BYTE* pBuffer = Transfers.m_pBuffer;

		if ( m_bBackwards )
		{
			QWORD nRead = 0;
			m_pDiskFile->Read( m_nFileBase + m_nOffset + m_nLength - m_nPosition - nPacket, pBuffer, nPacket, &nRead );
			if ( nRead != nPacket ) return TRUE;
			m_pOutput->AddReversed( pBuffer, (DWORD)nPacket );
		}
		else
		{
			m_pDiskFile->Read( m_nFileBase + m_nOffset + m_nPosition, pBuffer, nPacket, &nPacket );
			if ( nPacket == 0 ) return TRUE;
			m_pOutput->Add( pBuffer, (DWORD)nPacket );
		}

		m_nPosition += nPacket;
		m_nUploaded += nPacket;

		Statistics.Current.Uploads.Volume += ( nPacket / 1024 );
	}

	CUploadTransfer::OnWrite();

	if ( m_nState >= upsResponse && m_pOutput->m_nLength == 0 )
	{
		m_nState	= ( m_nState == upsPreQueue ) ? upsQueued : upsRequest;
		m_tRequest	= GetTickCount();
	}

	return TRUE;
}

void CUploadTransferHTTP::OnCompleted()
{
	Uploads.SetStable( GetAverageSpeed() );

	m_pDiskFile->Release( FALSE );
	m_pDiskFile	= NULL;
	m_nState	= upsRequest;
	m_tRequest	= GetTickCount();

	m_pBaseFile->AddFragment( m_nOffset, m_nLength );
	// m_pBaseFile = NULL;

	theApp.Message( MSG_DEFAULT, IDS_UPLOAD_FINISHED, (LPCTSTR)m_sFileName, (LPCTSTR)m_sAddress );
}

//////////////////////////////////////////////////////////////////////
// CUploadTransferHTTP run handler

BOOL CUploadTransferHTTP::OnRun()
{
	CUploadTransfer::OnRun();

	DWORD tNow = GetTickCount();

	switch ( m_nState )
	{
	case upsRequest:
		if ( ! m_bKeepAlive && m_pOutput->m_nLength == 0 )
		{
			theApp.Message( MSG_DEFAULT, IDS_UPLOAD_DROPPED, (LPCTSTR)m_sAddress );
			Close();
			return FALSE;
		}

	case upsHeaders:
		if ( tNow - m_tRequest > Settings.Connection.TimeoutHandshake )
		{
			theApp.Message( MSG_ERROR, IDS_UPLOAD_REQUEST_TIMEOUT, (LPCTSTR)m_sAddress );
			Close();
			return FALSE;
		}
		break;

	case upsQueued:
		switch ( m_nGnutella )
		{
		case 1:
			if ( !Settings.IsG1Allowed() )
			{
				Remove( FALSE );
				return FALSE;
			}
			break;
		case 2:
			if ( !Settings.IsG2Allowed() )
			{
				Remove( FALSE );
				return FALSE;
			}
			break;
		default:
			if ( !Settings.IsG1Allowed() || !Settings.IsG2Allowed() )
			{
				Remove( FALSE );
				return FALSE;
			}
			break;
		}
		if ( tNow - m_tRequest > m_nTimeoutTraffic )
		{
			theApp.Message( MSG_ERROR, IDS_UPLOAD_REQUEST_TIMEOUT, (LPCTSTR)m_sAddress );
			Close();
			return FALSE;
		}
		break;

	case upsUploading:
	case upsResponse:
	case upsBrowse:
	case upsTigerTree:
	case upsMetadata:
	case upsPreview:
	case upsPreQueue:
		switch ( m_nGnutella )
		{
		case 1:
			if ( !Settings.IsG1Allowed() )
			{
				Remove( FALSE );
				return FALSE;
			}
			break;
		case 2:
			if ( !Settings.IsG2Allowed() )
			{
				Remove( FALSE );
				return FALSE;
			}
			break;
		default:
			if ( !Settings.IsG1Allowed() || !Settings.IsG2Allowed() )
			{
				Remove( FALSE );
				return FALSE;
			}
			break;
		}
		if ( tNow - m_mOutput.tLast > Settings.Connection.TimeoutTraffic )
		{
			if ( tNow - m_tRequest > m_nTimeoutTraffic )
			{
				theApp.Message( MSG_SYSTEM, IDS_UPLOAD_TRAFFIC_TIMEOUT, (LPCTSTR)m_sAddress );
				Remove( FALSE );
				return FALSE;
			}
		}
		break;

	}

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CUploadTransferHTTP dropped handler

void CUploadTransferHTTP::OnDropped(BOOL /*bError*/)
{
	theApp.Message( MSG_DEFAULT, IDS_UPLOAD_DROPPED, (LPCTSTR)m_sAddress );

	if ( m_nState == upsUploading && m_pBaseFile != NULL )
	{
		if ( m_bBackwards )
		{
			m_pBaseFile->AddFragment( m_nOffset + m_nLength - m_nPosition, m_nPosition );
		}
		else
		{
			m_pBaseFile->AddFragment( m_nOffset, m_nPosition );
		}

		m_pBaseFile = NULL;
	}

	Close();
}

//////////////////////////////////////////////////////////////////////
// CUploadTransferHTTP request metadata

BOOL CUploadTransferHTTP::RequestMetadata(CXMLElement* pMetadata)
{
	ASSERT( pMetadata != NULL );
	CString strXML = pMetadata->ToString( TRUE, TRUE );
	delete pMetadata;

	int nXML = WideCharToMultiByte( CP_UTF8, 0, strXML, strXML.GetLength(), NULL, 0, NULL, NULL );
	LPSTR pszXML = new CHAR[ nXML ];
	WideCharToMultiByte( CP_UTF8, 0, strXML, strXML.GetLength(), pszXML, nXML, NULL, NULL );

	m_pOutput->Print( "HTTP/1.1 200 OK\r\n" );
	SendDefaultHeaders();
	m_pOutput->Print( "Content-Type: text/xml\r\n" );

	CString strHeader;
	strHeader.Format( _T("Content-Length: %lu\r\n"), nXML );
	m_pOutput->Print( strHeader );
	m_pOutput->Print( "\r\n" );

	if ( ! m_bHead ) m_pOutput->Add( pszXML, nXML );
	delete [] pszXML;

	StartSending( upsMetadata );

	theApp.Message( MSG_DEFAULT, IDS_UPLOAD_METADATA_SEND,
		(LPCTSTR)m_sFileName, (LPCTSTR)m_sAddress );

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CUploadTransferHTTP request a tiger tree hash, raw format

BOOL CUploadTransferHTTP::RequestTigerTreeRaw(CTigerTree* pTigerTree, BOOL bDelete)
{
	if ( pTigerTree == NULL )
	{
		ClearHashes();
		m_sAltG1Locations.Empty();
		m_sXAlt.Empty();
		m_sXNAlt.Empty();
		m_sAltLocations.Empty();
		m_sXG2Alt.Empty();

		SendResponse( IDR_HTML_FILENOTFOUND, TRUE );
		theApp.Message( MSG_ERROR, IDS_UPLOAD_FILENOTFOUND, (LPCTSTR)m_sAddress, (LPCTSTR)m_sFileName );

		return TRUE;
	}

	BYTE* pSerialTree;
	DWORD nSerialTree;

	pTigerTree->ToBytes( &pSerialTree, &nSerialTree );
	if ( bDelete ) delete pTigerTree;

	if ( m_bRange )
	{
		if ( m_nOffset >= nSerialTree ) m_nLength = SIZE_UNKNOWN;
		else m_nLength = min( m_nLength, nSerialTree - m_nOffset );
	}
	else
	{
		m_nOffset = 0;
		m_nLength = nSerialTree;
	}

	if ( m_nLength <= nSerialTree )
	{
		CString strHeader;

		if ( m_nLength != nSerialTree )
			m_pOutput->Print( "HTTP/1.1 206 OK\r\n" );
		else
			m_pOutput->Print( "HTTP/1.1 200 OK\r\n" );

		SendDefaultHeaders();

		m_pOutput->Print( "Content-Type: application/tigertree-breadthfirst\r\n" );
		strHeader.Format( _T("Content-Length: %I64i\r\n"), m_nLength );
		m_pOutput->Print( strHeader );

		if ( m_nLength != nSerialTree )
		{
			strHeader.Format( _T("Content-Range: %I64i-%I64i\r\n"), m_nOffset, m_nOffset + m_nLength - 1 );
			m_pOutput->Print( strHeader );
		}

		m_pOutput->Print( "\r\n" );

		if ( ! m_bHead ) m_pOutput->Add( pSerialTree + m_nOffset, (DWORD)m_nLength );

		StartSending( upsTigerTree );

		theApp.Message( MSG_DEFAULT, IDS_UPLOAD_TIGER_SEND,
			(LPCTSTR)m_sFileName, (LPCTSTR)m_sAddress );
	}
	else
	{
		m_sRanges.Format( _T("0-%I64i"), (QWORD)nSerialTree - 1 );
		ClearHashes();
		m_sAltG1Locations.Empty();
		m_sXAlt.Empty();
		m_sXNAlt.Empty();
		m_sAltLocations.Empty();
		m_sXG2Alt.Empty();

		SendResponse( IDR_HTML_BADRANGE, TRUE );
		theApp.Message( MSG_ERROR, IDS_UPLOAD_BAD_RANGE, (LPCTSTR)m_sAddress, (LPCTSTR)m_sFileName );
	}

	delete [] pSerialTree;

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CUploadTransferHTTP request a tiger tree hash, DIME format

BOOL CUploadTransferHTTP::RequestTigerTreeDIME(CTigerTree* pTigerTree, int nDepth, CED2K* pHashset, BOOL bDelete)
{
	if ( pTigerTree == NULL )
	{
		ClearHashes();
		m_sAltG1Locations.Empty();
		m_sXAlt.Empty();
		m_sXNAlt.Empty();
		m_sAltLocations.Empty();
		m_sXG2Alt.Empty();

		SendResponse( IDR_HTML_FILENOTFOUND, TRUE );
		theApp.Message( MSG_ERROR, IDS_UPLOAD_FILENOTFOUND, (LPCTSTR)m_sAddress, (LPCTSTR)m_sFileName );

		if ( pHashset != NULL && bDelete ) delete pHashset;

		return TRUE;
	}

	DWORD nSerialTree;
	BYTE* pSerialTree;
	CBuffer pDIME;

	if ( nDepth < 1 ) nDepth = pTigerTree->GetHeight();
	else if ( nDepth > (int)pTigerTree->GetHeight() ) nDepth = pTigerTree->GetHeight();

	pTigerTree->ToBytes( &pSerialTree, &nSerialTree, nDepth );
	if ( bDelete ) delete pTigerTree;

	CString strUUID, strXML;

	Hashes::Guid oGUID;

	Network.CreateID( oGUID );
	GUID pUUID;
	std::memcpy( &pUUID, &oGUID[ 0 ], sizeof( pUUID ) );
	strUUID.Format( _T("uuid:%.8x-%.4x-%.4x-%.2x%.2x-%.2x%.2x%.2x%.2x%.2x%.2x"),
		pUUID.Data1, pUUID.Data2, pUUID.Data3,
		pUUID.Data4[0], pUUID.Data4[1], pUUID.Data4[2], pUUID.Data4[3],
		pUUID.Data4[4], pUUID.Data4[5], pUUID.Data4[6], pUUID.Data4[7] );

	strXML.Format(	_T("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n")
					_T("<!DOCTYPE hashtree SYSTEM \"http://open-content.net/spec/thex/thex.dtd\">\r\n")
					_T("<hashtree>\r\n")
					_T("\t<file size=\"%I64i\" segmentsize=\"1024\"/>\r\n")
					_T("\t<digest algorithm=\"http://open-content.net/spec/digest/tiger\" outputsize=\"24\"/>\r\n")
					_T("\t<serializedtree depth=\"%i\" type=\"http://open-content.net/spec/thex/breadthfirst\" uri=\"%s\"/>\r\n")
					_T("</hashtree>"),
					m_nFileSize, nDepth, (LPCTSTR)strUUID );

					//test code for put additional hash info in XML/DIME
/*
	strXML.Format(	_T("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n")
					_T("<!DOCTYPE hashtree SYSTEM \"http://open-content.net/spec/thex/thex.dtd\">\r\n")
					_T("<hashtree>\r\n")
					_T("\t<file size=\"%I64i\" segmentsize=\"1024\">\r\n")
					_T("\t\t<hash SHA1=\"%s\"/>\r\n")
					_T("\t\t<hash TTH=\"%s\"/>\r\n")
					_T("\t\t<hash ED2K=\"%s\"/>\r\n")
					_T("\t\t<hash MD5=\"%s\"/>\r\n")
					_T("\t</file>\r\n")
					_T("\t<digest algorithm=\"http://open-content.net/spec/digest/tiger\" outputsize=\"24\"/>\r\n")
					_T("\t<serializedtree depth=\"%i\" type=\"http://open-content.net/spec/thex/breadthfirst\" uri=\"%s\"/>\r\n")
					_T("</hashtree>"),
					m_nFileSize, pFile->m_oSHA1->toString, pFile->m_oTiger->toString, pFile->m_oED2K->toString, pFile->m_oMD5->toString, nDepth, (LPCTSTR)strUUID );
*/
	
	int nXML = WideCharToMultiByte( CP_UTF8, 0, strXML, -1, NULL, 0, NULL, NULL );
	LPSTR pszXML = new CHAR[ nXML ];
	WideCharToMultiByte( CP_UTF8, 0, strXML, -1, pszXML, nXML, NULL, NULL );
	int nUUID = WideCharToMultiByte( CP_ACP, 0, strUUID, -1, NULL, 0, NULL, NULL );
	LPSTR pszUUID = new CHAR[ nUUID ];
	WideCharToMultiByte( CP_ACP, 0, strUUID, -1, pszUUID, nUUID, NULL, NULL );

	pDIME.WriteDIME( 1, "", "text/xml", pszXML, strlen(pszXML) );
	pDIME.WriteDIME( pHashset ? 0 : 2, pszUUID, "http://open-content.net/spec/thex/breadthfirst", pSerialTree, nSerialTree );
	delete [] pSerialTree;

	delete [] pszUUID;
	delete [] pszXML;

	if ( pHashset != NULL )
	{
		pHashset->ToBytes( &pSerialTree, &nSerialTree );
		if ( bDelete ) delete pHashset;

		pDIME.WriteDIME( 2, "", "http://edonkey2000.com/spec/md4-hashset", pSerialTree, nSerialTree );
		delete [] pSerialTree;
	}

	if ( m_bRange )
	{
		if ( m_nOffset >= (QWORD)pDIME.m_nLength ) m_nLength = SIZE_UNKNOWN;
		else m_nLength = min( m_nLength, pDIME.m_nLength - m_nOffset );
	}
	else
	{
		m_nOffset = 0;
		m_nLength = (QWORD)pDIME.m_nLength;
	}

	if ( m_nLength <= pDIME.m_nLength )
	{
		CString strHeader;

		if ( m_nLength != pDIME.m_nLength )
			m_pOutput->Print( "HTTP/1.1 206 OK\r\n" );
		else
			m_pOutput->Print( "HTTP/1.1 200 OK\r\n" );

		SendDefaultHeaders();

		m_pOutput->Print( "Content-Type: application/dime\r\n" );
		strHeader.Format( _T("Content-Length: %I64i\r\n"), m_nLength );
		m_pOutput->Print( strHeader );

		if ( m_nLength != pDIME.m_nLength )
		{
			strHeader.Format( _T("Content-Range: %I64i-%I64i\r\n"), m_nOffset, m_nOffset + m_nLength - 1 );
			m_pOutput->Print( strHeader );
		}

		m_pOutput->Print( "\r\n" );

		if ( ! m_bHead )
		{
			m_pOutput->Add( pDIME.m_pBuffer + m_nOffset, (DWORD)m_nLength );
		}

		StartSending( upsTigerTree );

		theApp.Message( MSG_DEFAULT, IDS_UPLOAD_TIGER_SEND,
			(LPCTSTR)m_sFileName, (LPCTSTR)m_sAddress );
	}
	else
	{
		m_sRanges.Format( _T("0-%I64i"), (QWORD)pDIME.m_nLength - 1 );
		ClearHashes();
		m_sAltG1Locations.Empty();
		m_sXAlt.Empty();
		m_sXNAlt.Empty();
		m_sAltLocations.Empty();
		m_sXG2Alt.Empty();

		SendResponse( IDR_HTML_BADRANGE, TRUE );
		theApp.Message( MSG_ERROR, IDS_UPLOAD_BAD_RANGE, (LPCTSTR)m_sAddress, (LPCTSTR)m_sFileName );
	}

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CUploadTransferHTTP request preview

BOOL CUploadTransferHTTP::RequestPreview(CLibraryFile* pFile, CSingleLock& oLibraryLock)
{
	ASSERT( pFile != NULL );

	m_sFileName		= pFile->m_sName;
	m_sFilePath		= pFile->GetPath();
	m_oSHA1			= pFile->m_oSHA1;
	m_oTiger		= pFile->m_oTiger;
	m_oED2K			= pFile->m_oED2K;
	m_oMD5			= pFile->m_oMD5;
	DWORD nIndex	= pFile->m_nIndex;
	BOOL bCached	= pFile->m_bCachedPreview;

	oLibraryLock.Unlock();

	DWORD nExisting = static_cast< DWORD >( Uploads.GetCount( this, upsPreview ) );

	if ( nExisting >= Settings.Uploads.PreviewTransfers )
	{
		theApp.Message( MSG_ERROR, IDS_UPLOAD_PREVIEW_BUSY, (LPCTSTR)m_sFileName, (LPCTSTR)m_sAddress );
		m_pOutput->Print( "HTTP/1.1 503 Busy\r\n" );
		SendDefaultHeaders();
		StartSending( upsResponse );
		return TRUE;
	}

	CImageServices pServices;
	CImageFile pImage( &pServices );
	CThumbCache pCache;
	CSize szThumb( 0, 0 );

	if ( pCache.Load( m_sFilePath, &szThumb, nIndex, &pImage ) )
	{
		// Got a cached copy
	}
	else if ( Settings.Uploads.DynamicPreviews && pImage.LoadFromFile( m_sFilePath, FALSE, TRUE ) && pImage.EnsureRGB() )
	{
		theApp.Message( MSG_DEFAULT, IDS_UPLOAD_PREVIEW_DYNAMIC, (LPCTSTR)m_sFileName, (LPCTSTR)m_sAddress );

		int nSize = szThumb.cy * pImage.m_nWidth / pImage.m_nHeight;

		if ( nSize > szThumb.cx )
		{
			nSize = szThumb.cx * pImage.m_nHeight / pImage.m_nWidth;
			pImage.Resample( szThumb.cx, nSize );
		}
		else
		{
			pImage.Resample( nSize, szThumb.cy );
		}

		pCache.Store( m_sFilePath, &szThumb, nIndex, &pImage );
	}
	else
	{
		theApp.Message( MSG_ERROR, IDS_UPLOAD_PREVIEW_EMPTY, (LPCTSTR)m_sAddress, (LPCTSTR)m_sFileName );
		SendResponse( IDR_HTML_FILENOTFOUND );
		return TRUE;
	}

	if ( ! bCached )
	{
		CQuickLock oLock( Library.m_pSection );
		if ( ( pFile = Library.LookupFile( nIndex ) ) != NULL )
		{
			pFile->m_bCachedPreview = TRUE;
			Library.Update();
		}
	}

	BYTE* pBuffer = NULL;
	DWORD nLength = 0;

	int nQuality = Settings.Uploads.PreviewQuality;

	if ( LPCTSTR pszQuality = _tcsistr( m_sRequest, _T("&quality=") ) )
	{
		_stscanf( pszQuality + 9, _T("%i"), &nQuality );
		nQuality = max( 1, min( 100, nQuality ) );
	}

	if ( ! pImage.SaveToMemory( _T(".jpg"), nQuality, &pBuffer, &nLength ) )
	{
		theApp.Message( MSG_ERROR, IDS_UPLOAD_PREVIEW_EMPTY, (LPCTSTR)m_sAddress, (LPCTSTR)m_sFileName );
		SendResponse( IDR_HTML_FILENOTFOUND );
		return TRUE;
	}

	pServices.Cleanup();

	m_pOutput->Print( "HTTP/1.1 200 OK\r\n" );
	SendDefaultHeaders();

	CString strHeader;

	if ( m_oSHA1 )
	{
		strHeader.Format( _T("X-Previewed-URN: %s\r\n"),
			(LPCTSTR)m_oSHA1.toUrn() );
	}
	else if ( m_oTiger )
	{
		strHeader.Format( _T("X-Previewed-URN: %s\r\n"),
			(LPCTSTR)m_oTiger.toUrn() );
	}
	else if ( m_oED2K )
	{
		strHeader.Format( _T("X-Previewed-URN: %s\r\n"),
			(LPCTSTR)m_oED2K.toUrn() );
	}
	else if ( m_oMD5 )
	{
		strHeader.Format( _T("X-Previewed-URN: %s\r\n"),
			(LPCTSTR)m_oMD5.toUrn() );
	}

	m_pOutput->Print( strHeader );

	m_pOutput->Print( "Content-Type: image/jpeg\r\n" );

	strHeader.Format( _T("Content-Length: %lu\r\n"), nLength );
	m_pOutput->Print( strHeader );

	m_pOutput->Print( "\r\n" );

	if ( ! m_bHead )
	{
		m_pOutput->Add( pBuffer, nLength );
	}

	delete [] pBuffer;

	StartSending( upsPreview );

	theApp.Message( MSG_SYSTEM, IDS_UPLOAD_PREVIEW_SEND, (LPCTSTR)m_sFileName,
		(LPCTSTR)m_sAddress );

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CUploadTransferHTTP request host browse

BOOL CUploadTransferHTTP::RequestHostBrowse()
{
	CBuffer pBuffer;

	DWORD nExisting = static_cast< DWORD >( Uploads.GetCount( this, upsBrowse ) );

	if ( nExisting >= Settings.Uploads.PreviewTransfers )
	{
		theApp.Message( MSG_ERROR, IDS_UPLOAD_BROWSE_BUSY, (LPCTSTR)m_sAddress );
		m_pOutput->Print( "HTTP/1.1 503 Busy\r\n" );
		SendDefaultHeaders();
		StartSending( upsResponse );
		return TRUE;
	}

	if ( m_bHostBrowse < 2 )
	{
		if ( Settings.Community.ServeFiles )
		{
			CLocalSearch pSearch( NULL, &pBuffer, PROTOCOL_G1 );
			pSearch.Execute( 0 );
		}
	}
	else
	{
		if ( Settings.Community.ServeProfile && MyProfile.IsValid() )
		{
			CG2Packet* pProfile = CG2Packet::New( G2_PACKET_PROFILE_DELIVERY, TRUE );
			CString strXML = MyProfile.GetXML()->ToString( TRUE );
			pProfile->WritePacket( G2_PACKET_XML, pProfile->GetStringLen( strXML ) );
			pProfile->WriteString( strXML, FALSE );
			pProfile->ToBuffer( &pBuffer );
			pProfile->Release();
		}

		if ( Settings.Community.ServeFiles )
		{
			CLocalSearch pSearch( NULL, &pBuffer, PROTOCOL_G2 );
			pSearch.Execute( 0 );
			pSearch.WriteVirtualTree();
		}

		if ( Settings.Community.ServeProfile && MyProfile.IsValid() )
		{
			if ( CG2Packet* pAvatar = MyProfile.CreateAvatar() )
			{
				pAvatar->ToBuffer( &pBuffer );
				pAvatar->Release();
			}
		}
	}

	m_pOutput->Print( "HTTP/1.1 200 OK\r\n" );
	SendDefaultHeaders();

	if ( m_bHostBrowse < 2 )
	{
		m_pOutput->Print( "Content-Type: application/x-gnutella-packets\r\n" );
	}
	else
	{
		m_pOutput->Print( "Content-Type: application/x-gnutella2\r\n" );
	}

	m_bDeflate = m_bDeflate && pBuffer.Deflate( TRUE );

	if ( m_bDeflate ) m_pOutput->Print( "Content-Encoding: deflate\r\n" );

	CString strLength;
	strLength.Format( _T("Content-Length: %lu\r\n\r\n"), pBuffer.m_nLength );
	m_pOutput->Print( strLength );

	if ( ! m_bHead ) m_pOutput->AddBuffer( &pBuffer );

	StartSending( upsBrowse );

	theApp.Message( MSG_SYSTEM, IDS_UPLOAD_BROWSE, (LPCTSTR)m_sAddress, (LPCTSTR)m_sUserAgent );

	CTransfer::OnWrite();

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CUploadTransferHTTP formatted response

void CUploadTransferHTTP::SendResponse(UINT nResourceID, BOOL bFileHeaders)
{
	CString strBody, strResponse;

	HMODULE hModule = GetModuleHandle( NULL );
	HRSRC hRes = FindResource( hModule, MAKEINTRESOURCE( nResourceID ), MAKEINTRESOURCE( 23 ) );

	if ( hRes != NULL )
	{
		DWORD nSize			= SizeofResource( hModule, hRes );
		HGLOBAL hMemory		= LoadResource( hModule, hRes );
		LPTSTR pszOutput	= strBody.GetBuffer( nSize + 1 );
		LPCSTR pszInput		= (LPCSTR)LockResource( hMemory );

		while ( nSize-- ) *pszOutput++ = *pszInput++;
		*pszOutput++ = 0;

		strBody.ReleaseBuffer();
	}

	int nBreak	= strBody.Find( _T("\r\n") );
	bool bWindowsEOL = true;

	if ( nBreak == -1 )
	{
		nBreak	= strBody.Find( _T("\n") );
		bWindowsEOL = false;
	}
	strResponse	= strBody.Left( nBreak + ( bWindowsEOL ? 2 : 1 ) );
	strBody		= strBody.Mid( nBreak + ( bWindowsEOL ? 2 : 1 ) );

	while ( TRUE )
	{
		int nStart = strBody.Find( _T("<%") );
		if ( nStart < 0 ) break;

		int nEnd = strBody.Find( _T("%>") );
		if ( nEnd < nStart ) break;

		CString strReplace = strBody.Mid( nStart + 2, nEnd - nStart - 2 );

		strReplace.TrimLeft();
		strReplace.TrimRight();

		if ( strReplace.CompareNoCase( _T("Name") ) == 0 )
			strReplace = m_sFileName;
		else if ( strReplace.CompareNoCase( _T("SHA1") ) == 0 )
			strReplace = m_oSHA1.toString();
		else if ( strReplace.CompareNoCase( _T("URN") ) == 0 )
			strReplace = m_oSHA1.toUrn();
		else if ( strReplace.CompareNoCase( _T("Version") ) == 0 )
			strReplace = theApp.m_sVersion;
		else if ( strReplace.CompareNoCase( _T("Neighbours") ) == 0 )
			GetNeighbourList( strReplace );
		else if ( strReplace.CompareNoCase( _T("ListenIP") ) == 0 )
		{
			if ( Network.IsListening() )
			{
				strReplace.Format( _T("%s:%i"),
					(LPCTSTR)CString( inet_ntoa( Network.m_pHost.sin_addr ) ),
					htons( Network.m_pHost.sin_port ) );
			}
			else strReplace.Empty();
		}

		strBody = strBody.Left( nStart ) + strReplace + strBody.Mid( nEnd + 2 );
	}

	m_pOutput->Print( _T("HTTP/1.1 ") + strResponse );
	SendDefaultHeaders();
	if ( bFileHeaders ) SendFileHeaders();
	m_pOutput->Print( "Content-Type: text/html\r\n" );

	int nBody = WideCharToMultiByte( CP_UTF8, 0, strBody, strBody.GetLength(), NULL, 0, NULL, NULL );
	LPSTR pszBody = new CHAR[ nBody ];
	WideCharToMultiByte( CP_UTF8, 0, strBody, strBody.GetLength(), pszBody, nBody, NULL, NULL );

	strResponse.Format( _T("Content-Length: %lu\r\n\r\n"), nBody );
	m_pOutput->Print( strResponse );

	if ( ! m_bHead ) m_pOutput->Add( pszBody, nBody );

	delete [] pszBody;

	StartSending( upsResponse );
}

void CUploadTransferHTTP::GetNeighbourList(CString& strOutput)
{
	static LPCTSTR pszModes[4][5] =
	{
		{ _T("Handshake"), _T("Handshake"), _T("Handshake"), _T("Handshake"), _T("Handshake") },
		{ _T("Unknown"), _T("G1 Peer"), _T("G1 Ultrapeer"), _T("G1 Leaf"), _T("Unknown") },
		{ _T("Unknown"), _T("G2 Peer"), _T("G2 Hub"), _T("G2 Leaf"), _T("Unknown") },
		{ _T("Unknown"), _T("eDonkey2000"), _T("Unknown"), _T("Unknown"), _T("Unknown") }
	};

	strOutput.Empty();

	CSingleLock pLock( &Network.m_pSection );
	if ( ! pLock.Lock( 100 ) ) return;

	DWORD tNow = GetTickCount();

	for ( POSITION pos = Neighbours.GetIterator() ; pos ; )
	{
		CNeighbour* pNeighbour = Neighbours.GetNext( pos );

		if ( pNeighbour->m_nState == nrsConnected )
		{
			CString strNode;

			DWORD nTime = ( tNow - pNeighbour->m_tConnected ) / 1000;

			strNode.Format( _T("<tr><td class=\"fi\"><a href=\"gnutella:host:%s:%lu\">%s:%lu</a></td><td class=\"fi\" align=\"center\">%i:%.2i:%.2i</td><td class=\"fi\">%s</td><td class=\"fi\">%s</td><td class=\"fi\"><a href=\"http://%s:%lu/\">Browse</a></td></tr>\r\n"),
				(LPCTSTR)pNeighbour->m_sAddress, htons( pNeighbour->m_pHost.sin_port ),
				(LPCTSTR)pNeighbour->m_sAddress, htons( pNeighbour->m_pHost.sin_port ),
				nTime / 3600, ( nTime % 3600 ) / 60, nTime % 60,
				pszModes[ pNeighbour->m_nProtocol ][ pNeighbour->m_nNodeType ],
				(LPCTSTR)pNeighbour->m_sUserAgent,
				(LPCTSTR)pNeighbour->m_sAddress, htons( pNeighbour->m_pHost.sin_port ) );

			strOutput += strNode;
		}
	}
}
