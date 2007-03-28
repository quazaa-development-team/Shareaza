//
// DownloadTransferHTTP.cpp
//
//	Date:			"$Date: 2006/04/04 23:33:36 $"
//	Revision:		"$Revision: 1.24 $"
//  Last change by:	"$Author: rolandas $"
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
#include "Download.h"
#include "Downloads.h"
#include "DownloadSource.h"
#include "Transfer.h"
#include "Transfers.h"
#include "DownloadTransfer.h"
#include "DownloadTransferHTTP.h"
#include "FragmentedFile.h"
#include "Network.h"
#include "G2Neighbour.h"
#include "Neighbours.h"
#include "Buffer.h"
#include "SourceURL.h"
#include "GProfile.h"
#include "SHA.h"
#include "ED2K.h"
#include "TigerTree.h"
#include "XML.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif


//////////////////////////////////////////////////////////////////////
// CDownloadTransferHTTP construction

CDownloadTransferHTTP::CDownloadTransferHTTP(CDownloadSource* pSource) : CDownloadTransfer( pSource, PROTOCOL_HTTP )
{
	m_nRequests		= 0;
	m_tContent		= 0;

	m_bBadResponse	= FALSE;
	m_bBusyFault	= FALSE;
	m_bRangeFault	= FALSE;
	m_bHashMatch	= FALSE;
	m_bTigerFetch	= FALSE;
	m_bTigerIgnore	= FALSE;
	m_bTigerFailed	= FALSE;
	m_bMetaFetch	= FALSE;
	m_bMetaIgnore	= FALSE;
	m_bRedirect		= FALSE;
	m_bHeadRequest	= !( m_pSource->m_bCloseConn && m_pSource->m_bReConnect );

	m_nRetryDelay	= Settings.Downloads.RetryDelay;
	m_nRetryAfter	= 0;
	m_bGUIDSent		= FALSE;
	m_bPushWaiting	= FALSE;
}

CDownloadTransferHTTP::~CDownloadTransferHTTP()
{
}

//////////////////////////////////////////////////////////////////////
// CDownloadTransferHTTP initiate connection

BOOL CDownloadTransferHTTP::Initiate()
{
	theApp.Message( MSG_DEFAULT, IDS_DOWNLOAD_CONNECTING,
		(LPCTSTR)CString( inet_ntoa( m_pSource->m_pAddress ) ), m_pSource->m_nPort,
		(LPCTSTR)m_pDownload->GetDisplayName() );

	m_pSource->m_bReConnect = FALSE;

	if ( m_pSource->m_bCloseConn )
	{
		m_bHeadRequest = FALSE;
		m_pSource->m_bCloseConn = FALSE;
	}
	else if ( m_pDownload->m_nSize == SIZE_UNKNOWN )
	{
		m_bHeadRequest = TRUE;
	}

	if ( m_pSource->m_bPushOnly && m_pSource->PushRequest() ) // This is PushOnly Source and Push succeed.
	{
		m_bPushWaiting = TRUE;			// Set flag to indicate this is waiting for PUSH connection to come.
		m_tConnected = GetTickCount();	// Set Connect time for Timeout calculation
		CTransfer::AttachTo( NULL );	// Add this CTransfer derived object to CTransfers.
		m_sAddress.Format( _T("Attempting PUSH") );			// Set Message in Address field (Quick hack for GUI)
		m_pHost.sin_port = htons( (WORD)m_pSource->m_nPushAttempted );	// Set attempt count to Port number(Quick hack for GUI)
	}
	else if ( ConnectTo( &m_pSource->m_pAddress, m_pSource->m_nPort ) )
	{
		m_bPushWaiting = FALSE;	// this is not PUSH connection.

		if ( ! m_pDownload->IsBoosted() )
			m_mInput.pLimit = m_mOutput.pLimit = &m_nBandwidth;
	}
	else
	{
		/* ??????? don't get this. at this point, no one can get Offline/online status. only thing it can get
					is initiation success or failed. including the case the source was on security list,
					when socket creation is failed with Running out of handles(not rare on Win9x) thus it
					is totally not good at all to add the source to failed list.*/
		// Couldn't connect, keep the source but add to the m_pFailedSources
		// Mark it as an offline source, it might be good later...
		//m_pDownload->AddFailedSource( m_pSource, true, true );
		theApp.Message( MSG_ERROR, IDS_DOWNLOAD_CONNECT_ERROR, (LPCTSTR)m_sAddress );
		Close( TS_UNKNOWN );
		return FALSE;
	}

	SetState( dtsConnecting );
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CDownloadTransferHTTP accept push

BOOL CDownloadTransferHTTP::AcceptPush(CConnection* pConnection)
{
	m_bPushWaiting = FALSE;					// this connection is no longer waiting for PUSH connection.
	CConnection::AttachTo( pConnection );	// Attach CConnection object parsed from CHandshakes

	theApp.Message( MSG_DEFAULT, IDS_DOWNLOAD_PUSHED, (LPCTSTR)m_sAddress,
		(LPCTSTR)m_pDownload->GetDisplayName() );
	m_pSource->m_nPushAttempted = 0;		// PUSH succeed, so reset Attempt count.

	if ( ! m_pDownload->IsBoosted() )
		m_mInput.pLimit = m_mOutput.pLimit = &m_nBandwidth;

	if ( m_pSource->m_bCloseConn )
	{
		m_bHeadRequest = FALSE;
		m_pSource->m_bCloseConn = FALSE;
	}
	else if ( m_pDownload->m_nSize == SIZE_UNKNOWN )
	{
		m_bHeadRequest = TRUE;
	}

	m_pSource->m_sCountry = m_sCountry;
	m_pSource->m_sCountryName = m_sCountryName;
	m_pSource->m_pAddress.S_un.S_addr = m_pHost.sin_addr.S_un.S_addr;

	m_pSource->m_bReConnect = FALSE;
	if ( StartNextFragment() ) return TRUE;

	return FALSE;
}

//////////////////////////////////////////////////////////////////////
// CDownloadTransferHTTP close

void CDownloadTransferHTTP::Close( TRISTATE bKeepSource, DWORD nRetryAfter )
{
	if ( m_pDownload->IsDownloading() && m_pSource != NULL && m_nState == dtsDownloading && m_nPosition )
	{
		if ( m_bRecvBackwards )
		{
			m_pSource->AddFragment( m_nOffset + m_nLength - m_nPosition, m_nPosition );
		}
		else
		{
			m_pSource->AddFragment( m_nOffset, m_nPosition );
		}
	}
	
	CDownloadTransfer::Close( bKeepSource, nRetryAfter );
}

//////////////////////////////////////////////////////////////////////
// CDownloadTransferHTTP speed controls

void CDownloadTransferHTTP::Boost()
{
	m_mInput.pLimit = m_mOutput.pLimit = NULL;
}

DWORD CDownloadTransferHTTP::GetAverageSpeed()
{
	if ( m_nState == dtsDownloading )
	{
		DWORD nTime = ( GetTickCount() - m_tContent ) / 1000;
		if ( nTime > 0 ) m_pSource->m_nSpeed = (DWORD)( m_nPosition / nTime );
	}

	return m_pSource->m_nSpeed;
}

//////////////////////////////////////////////////////////////////////
// CDownloadTransferHTTP connection handler

BOOL CDownloadTransferHTTP::OnConnected()
{
	theApp.Message( MSG_DEFAULT, IDS_DOWNLOAD_CONNECTED, (LPCTSTR)m_sAddress );

	m_tConnected = GetTickCount();

	return StartNextFragment();
}

//////////////////////////////////////////////////////////////////////
// CDownloadTransferHTTP fragment allocation

BOOL CDownloadTransferHTTP::StartNextFragment()
{
	ASSERT( this != NULL );
	if ( this == NULL ) return FALSE;

	m_nOffset			= SIZE_UNKNOWN;
	m_nPosition			= 0;
	m_bWantBackwards	= FALSE;
	m_bRecvBackwards	= FALSE;
	m_bTigerFetch		= FALSE;
	m_bMetaFetch		= FALSE;

	if ( m_pInput == NULL || m_pOutput == NULL /* ||
		 m_pDownload->GetTransferCount( dtsDownloading ) >= Settings.Downloads.MaxFileTransfers */ )
	{
		theApp.Message( MSG_DEFAULT, IDS_DOWNLOAD_CLOSING_EXTRA, (LPCTSTR)m_sAddress );
		Close( TS_TRUE );
		return FALSE;
	}

	// this needs to go for pipeline

	if ( m_pInput->m_nLength > 0 && m_nRequests > 0 )
	{
		theApp.Message( MSG_ERROR, IDS_DOWNLOAD_CLOSING_OVERFLOW, (LPCTSTR)m_sAddress );
		Close( TS_TRUE );
		return FALSE;
	}

	if ( m_bHeadRequest && !m_bTigerFetch )
	{
		m_bHeadRequest = TRUE;
		return SendRequest();
	}
	else if ( m_pDownload->NeedTigerTree() && m_sTigerTree.GetLength() )
	{
		theApp.Message( MSG_DEFAULT, IDS_DOWNLOAD_TIGER_REQUEST,
			(LPCTSTR)m_pDownload->GetDisplayName(), (LPCTSTR)m_sAddress );

		m_bTigerFetch	= TRUE;
		m_bTigerIgnore	= TRUE;

		return SendRequest();
	}
	else if ( m_pDownload->m_pXML == NULL && m_sMetadata.GetLength() )
	{
		theApp.Message( MSG_DEFAULT, IDS_DOWNLOAD_METADATA_REQUEST,
			(LPCTSTR)m_pDownload->GetDisplayName(), (LPCTSTR)m_sAddress );

		m_bMetaFetch	= TRUE;
		m_bMetaIgnore	= TRUE;

		return SendRequest();
	}
	else if ( m_pDownload->GetFragment( this ) || m_nRequests == 0 )
	{
		ChunkifyRequest( &m_nOffset, &m_nLength, Settings.Downloads.ChunkSize, TRUE );

		theApp.Message( MSG_DEFAULT, IDS_DOWNLOAD_FRAGMENT_REQUEST,
			m_nOffset, m_nOffset + m_nLength - 1,
			(LPCTSTR)m_pDownload->GetDisplayName(), (LPCTSTR)m_sAddress );

		return SendRequest();
	}
	else
	{
		// Line Below cause Shareaza to forget Available range on Source, which might cause User to think the source have either full range
		// Available or else, no range. thus it is better to have it left drawn on Range graph.
        //if ( m_pSource != NULL ) m_pSource->SetAvailableRanges( NULL );

		theApp.Message( MSG_DEFAULT, IDS_DOWNLOAD_FRAGMENT_END, (LPCTSTR)m_sAddress );
		Close( TS_TRUE );

		return FALSE;
	}
}

//////////////////////////////////////////////////////////////////////
// CDownloadTransferHTTP subtract pending requests

BOOL CDownloadTransferHTTP::SubtractRequested(Fragments::List& ppFragments)
{
	if ( m_nOffset < SIZE_UNKNOWN && m_nLength < SIZE_UNKNOWN )
	{
		if ( m_nState == dtsRequesting || m_nState == dtsDownloading )
		{
			ppFragments.erase( Fragments::Fragment( m_nOffset, m_nOffset + m_nLength ) );
			return TRUE;
		}
	}

	return FALSE;
}

//////////////////////////////////////////////////////////////////////
// CDownloadTransferHTTP send request

BOOL CDownloadTransferHTTP::SendRequest()
{
	CString strLine;

	CSourceURL pURL;
	if ( ! pURL.ParseHTTP( m_pSource->m_sURL, FALSE ) ) return FALSE;

	if ( m_bTigerFetch )
	{
		pURL.m_sPath = m_sTigerTree;
		m_sTigerTree.Empty();
	}
	else if ( m_bMetaFetch )
	{
		pURL.m_sPath = m_sMetadata;
		m_sMetadata.Empty();
	}

	if (m_bHeadRequest)
	{
		if ( Settings.Downloads.RequestHTTP11 )
		{
			strLine.Format( _T("HEAD %s HTTP/1.1\r\n"), (LPCTSTR)pURL.m_sPath );
			m_pOutput->Print( strLine );

			strLine.Format( _T("Host: %s\r\n"), (LPCTSTR)pURL.m_sAddress );
			m_pOutput->Print( strLine );
		}
		else
		{
			strLine.Format( _T("HEAD %s HTTP/1.0\r\n"), (LPCTSTR)pURL.m_sPath );
		}
	}
	else
	{
		if ( Settings.Downloads.RequestHTTP11 )
		{
			strLine.Format( _T("GET %s HTTP/1.1\r\n"), (LPCTSTR)pURL.m_sPath );
			m_pOutput->Print( strLine );

			strLine.Format( _T("Host: %s\r\n"), (LPCTSTR)pURL.m_sAddress );
			m_pOutput->Print( strLine );
		}
		else
		{
			strLine.Format( _T("GET %s HTTP/1.0\r\n"), (LPCTSTR)pURL.m_sPath );
		}
	}

	theApp.Message( MSG_DEBUG, _T("%s: DOWNLOAD REQUEST: %s"),
		(LPCTSTR)m_sAddress, (LPCTSTR)pURL.m_sPath );

	strLine = Settings.SmartAgent();

	if ( strLine.GetLength() )
	{
		strLine = _T("User-Agent: ") + strLine + _T("\r\n");
		m_pOutput->Print( strLine );
	}

	if ( m_nRequests == 0 )
	{
		if ( m_bInitiated ) SendMyAddress();

		strLine = MyProfile.GetNick().Left( 255 );

		if ( strLine.GetLength() > 0 )
		{
			strLine = _T("X-Nick: ") + URLEncode( strLine ) + _T("\r\n");
			m_pOutput->Print( strLine );
		}
	}


	if ( Network.m_bEnabled && m_bInitiated && Settings.Gnutella2.EnableToday )
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

			if ( m_bGUIDSent == FALSE )
			{
				// copy Profile's GUID
				Hashes::Guid oID( MyProfile.oGUID );
				// Compose the X-MyGUID string, which is like "X-MyGUID: " with two newlines at the end (do)
				CString strGUID;
				// MFC's CString::Format is like sprintf, "%.2X" formats a byte into 2 hexidecimal characters like "ff"
				strGUID.Format(	_T("X-MyGUID: %.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X\r\n"),
					int( oID[0] ),  int( oID[1] ),  int( oID[2] ),  int( oID[3] ),		// Our GUID
					int( oID[4] ),  int( oID[5] ),  int( oID[6] ),  int( oID[7] ),
					int( oID[8] ),  int( oID[9] ),  int( oID[10] ), int( oID[11] ),
					int( oID[12] ), int( oID[13] ), int( oID[14] ), int( oID[15] ) );

				// Print the string into the output buffer, and write the output buffer to the remote computer
				m_pOutput->Print( strGUID );
				m_bGUIDSent = TRUE;
			}
		}
	}

	m_pOutput->Print( "Connection: Keep-Alive\r\n" ); //BearShare assumes close

	if ( Settings.Gnutella2.EnableToday ) m_pOutput->Print( "X-Features: g2/1.0\r\n" );

	if ( m_bTigerFetch )
	{
		m_pOutput->Print( "Accept: application/dime, application/tigertree-breadthfirst\r\n" );
	}
	else if ( m_bMetaFetch )
	{
		m_pOutput->Print( "Accept: text/xml\r\n" );
	}

	if ( !m_bHeadRequest && m_nOffset != SIZE_UNKNOWN && ! m_bTigerFetch && ! m_bMetaFetch )
	{
		if ( m_nOffset + m_nLength == m_pDownload->m_nSize )
		{
			strLine.Format( _T("Range: bytes=%I64i-\r\n"), m_nOffset );
		}
		else
		{
			strLine.Format( _T("Range: bytes=%I64i-%I64i\r\n"), m_nOffset, m_nOffset + m_nLength - 1 );
		}
		m_pOutput->Print( strLine );
	}
	else if ( !m_bHeadRequest )
	{
		m_pOutput->Print( "Range: bytes=0-\r\n" );
	}

	if ( m_bWantBackwards && Settings.Downloads.AllowBackwards )
	{
		m_pOutput->Print( "Accept-Encoding: backwards\r\n" );
	}

	if ( m_pSource->m_nPort == INTERNET_DEFAULT_HTTP_PORT )
	{
		int nSlash = m_pSource->m_sURL.ReverseFind( '/' );
		if ( nSlash > 0 )
		{
			strLine = _T("Referrer: ") + m_pSource->m_sURL.Left( nSlash + 1 ) + _T("\r\n");
			m_pOutput->Print( strLine );
		}
	}

    // m_pOutput->Print( "X-Queue: 0.1\r\n" );
    if ( !m_bHeadRequest ) m_pOutput->Print( "X-Queue: 0.1\r\n" );

	if ( m_pDownload->m_oSHA1 )
	{
		CString strURN = m_pDownload->m_oSHA1.toUrn();

		m_pOutput->Print( "X-Content-URN: " );
		m_pOutput->Print( strURN + _T("\r\n") );
	}

	if ( m_pDownload->m_oTiger )
	{
		CString strURN = m_pDownload->m_oTiger.toUrn();
		m_pOutput->Print( "X-Content-URN: " );
		m_pOutput->Print( strURN + _T("\r\n") );
	}

	if ( m_pDownload->m_oED2K )
	{
		CString strURN = m_pDownload->m_oED2K.toUrn();
		m_pOutput->Print( "X-Content-URN: " );
		m_pOutput->Print( strURN + _T("\r\n") );
	}

	if ( m_pDownload->m_oMD5 )
	{
		CString strURN = m_pDownload->m_oMD5.toUrn();
		m_pOutput->Print( "X-Content-URN: " );
		m_pOutput->Print( strURN + _T("\r\n") );
	}

	if ( ( m_pDownload->m_oSHA1 || m_pDownload->m_oTiger || m_pDownload->m_oED2K || m_pDownload->m_oMD5 ) && 
			Settings.Library.SourceMesh && ! m_bTigerFetch && ! m_bMetaFetch )
	{
		CString strURN;

		if ( m_pDownload->m_oSHA1 && m_pDownload->m_oTiger )
		{
			strURN = _T("urn:bitprint:")
					+ m_pDownload->m_oSHA1.toString() + '.'
					+ m_pDownload->m_oTiger.toString();
		}
		else if ( m_pDownload->m_oSHA1 )
		{
			strURN = m_pDownload->m_oSHA1.toUrn();
		}
		else if ( m_pDownload->m_oTiger )
		{
			strURN = m_pDownload->m_oTiger.toUrn();
		}
		else if ( m_pDownload->m_oED2K )
		{
			strURN = m_pDownload->m_oED2K.toUrn();
		}
		else if ( m_pDownload->m_oMD5 )
		{
			strURN = m_pDownload->m_oMD5.toUrn();
		}

		if ( m_pDownload->IsShared() && !m_pDownload->IsPaused() && Network.IsFirewalled(CHECK_TCP) != TS_TRUE && m_nRequests > 0)
		{
			if ( strURN.GetLength() )
			{
				strLine.Format( _T("http://%s:%i/uri-res/N2R?%s "),
					(LPCTSTR)CString( inet_ntoa( Network.m_pHost.sin_addr ) ),
					htons( Network.m_pHost.sin_port ), (LPCTSTR)strURN );
					strLine += TimeToString( static_cast< DWORD >( time( NULL ) - 180 ) );
					m_pOutput->Print( "Alt-Location: " );
				m_pOutput->Print( strLine + _T("\r\n") );
			}

			if ( m_pSource->m_nGnutella < 2 && Settings.IsG1Allowed() )
			{
				strLine = m_pDownload->GetSourceURLs( &m_pSourcesSent, 15, PROTOCOL_G1, m_pSource );
				if ( strLine.GetLength() )
				{
					m_pOutput->Print( "X-Alt: " );
					strLine.Format( _T("%s:%i"), (LPCTSTR)CString( inet_ntoa( Network.m_pHost.sin_addr ) ),
					htons( Network.m_pHost.sin_port ) );
					m_pOutput->Print( strLine + _T("\r\n") );
				}
			}
			else
			{
				strLine = m_pDownload->GetSourceURLs( &m_pSourcesSent, 15, PROTOCOL_G1, m_pSource );
				if ( strLine.GetLength() )
				{
					m_pOutput->Print( "X-Alt: " );
					strLine.Format( _T("%s:%i"), (LPCTSTR)CString( inet_ntoa( Network.m_pHost.sin_addr ) ),
						htons( Network.m_pHost.sin_port ) );
					m_pOutput->Print( strLine + _T("\r\n") );
				}

				strLine = m_pDownload->GetSourceURLs( &m_pSourcesSent, 15, PROTOCOL_G2, m_pSource );
				if ( strLine.GetLength() )
				{
					m_pOutput->Print( "X-G2Alt: " );
					strLine.Format( _T("%s:%i"), (LPCTSTR)CString( inet_ntoa( Network.m_pHost.sin_addr ) ),
						htons( Network.m_pHost.sin_port ) );
					m_pOutput->Print( strLine + _T("\r\n") );
				}

				strLine = m_pDownload->GetSourceURLs( &m_pSourcesSent, 15, PROTOCOL_HTTP, m_pSource );
				if ( strLine.GetLength() )
				{
					m_pOutput->Print( "Alt-Location: " );
					m_pOutput->Print( strLine + _T("\r\n") );
				}
			}

			if ( m_pSource->m_nGnutella < 2 )
			{
				strLine = m_pDownload->GetTopFailedSources( 15, PROTOCOL_G1 );
				if ( strLine.GetLength() )
				{
					m_pOutput->Print( "X-NAlt: " + strLine );
					m_pOutput->Print( _T("\r\n") );
				}
			}

			if ( m_pSource->m_nGnutella >= 2 )
			{
				strLine = m_pDownload->GetTopFailedSources( 15, PROTOCOL_G2 );
				if ( strLine.GetLength() )
				{
					m_pOutput->Print( "X-G2NAlt: " + strLine );
					m_pOutput->Print( _T("\r\n") );
				}
			}
		}
	}

	m_pOutput->Print( "\r\n" );

	m_bBadResponse		= FALSE;
	m_bBusyFault		= FALSE;
	m_bRangeFault		= FALSE;
	m_bKeepAlive		= FALSE;
	m_bHashMatch		= FALSE;
	m_bGotRange			= FALSE;
	m_bGotRanges		= FALSE;
	m_bQueueFlag		= FALSE;
	m_nContentLength	= SIZE_UNKNOWN;
	m_sContentType.Empty();

	m_sTigerTree.Empty();
	m_nRequests++;

	m_pSource->SetLastSeen();

	CDownloadTransfer::OnWrite();
	SetState( dtsRequesting );
	m_tRequest	= GetTickCount();

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CDownloadTransferHTTP run handler

BOOL CDownloadTransferHTTP::OnRun()
{
	if ( !CDownloadTransfer::OnRun() )
	{
		return FALSE;
	}

	DWORD tNow = GetTickCount();

	switch ( m_nState )
	{
	case dtsConnecting:
		if ( m_bPushWaiting )	// Trying to connect with PUSH method
		{
			if ( tNow - m_tConnected > Settings.Downloads.PushTimeout )	// if time of the trial is longer than PUSH timeout.
			{
				theApp.Message( MSG_ERROR, IDS_CONNECTION_TIMEOUT_CONNECT, (LPCTSTR)m_sAddress );
				m_pSource->m_bCloseConn = FALSE;	// Reset CloseConnection flag.

				if ( m_pSource->m_bPushOnly )		// This is PUSH only source
					Close( TS_TRUE );
				else								// Not PUSH only source
					Close( TS_UNKNOWN );			// Close connection with AttemptTime/FailureCount increased.

				return FALSE;
			}
		}
		else	// this is not PUSH connection
		{
			if ( tNow - m_tConnected > Settings.Connection.TimeoutConnect )	// if time of trial is loger than Connection Timeout
			{
				theApp.Message( MSG_ERROR, IDS_CONNECTION_TIMEOUT_CONNECT, (LPCTSTR)m_sAddress );
				m_pSource->m_bCloseConn = FALSE;									// Reset CloseConnection flag
				if ( Network.IsListening() && m_pSource->PushRequest() )			// Try PUSH if Network core is ready for it
				{
					CConnection::Close();											// Close Socket
					m_bPushWaiting = TRUE;											// Set PUSH flag
					m_tConnected  = tNow;											// Reset Connection time for Timeout
					m_sAddress.Format( _T("Attempting PUSH") );						// Set Message in Address field (Quick hack for GUI)
					m_pHost.sin_port = htons( (WORD)m_pSource->m_nPushAttempted );	// Set attempt count to Port number(Quick hack for GUI)
					return TRUE;
				}
				else	// PUSH is not option this time
				{
					Close( TS_UNKNOWN );	// Close connection with AttemptTime/FailureCount increased.
					return FALSE;
				}
			}
		}
		break;

	case dtsRequesting:
	case dtsHeaders:
		if ( tNow - m_tRequest > Settings.Connection.TimeoutHandshake )
		{
			theApp.Message( MSG_ERROR, IDS_DOWNLOAD_REQUEST_TIMEOUT, (LPCTSTR)m_sAddress );
			Close( m_bBusyFault || m_bQueueFlag ? TS_TRUE : TS_UNKNOWN );
			return FALSE;
		}
		break;

	case dtsDownloading:
	case dtsFlushing:
	case dtsTiger:
	case dtsMetadata:
		if ( tNow - m_mInput.tLast > Settings.Connection.TimeoutTraffic * 2 )
		{
			theApp.Message( MSG_ERROR, IDS_DOWNLOAD_TRAFFIC_TIMEOUT, (LPCTSTR)m_sAddress );
			Close( TS_TRUE );
			return FALSE;
		}
		break;

	case dtsBusy:
		if ( tNow - m_tRequest > 1000 )
		{
			theApp.Message( MSG_ERROR, IDS_DOWNLOAD_BUSY, (LPCTSTR)m_sAddress, Settings.Downloads.RetryDelay / 1000 );
			Close( TS_TRUE, m_nRetryAfter );
			return FALSE;
		}
		break;

	case dtsQueued:
		if ( tNow >= m_tRequest )
		{
			return StartNextFragment();
		}
		break;

	}

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CDownloadTransferHTTP read handler

BOOL CDownloadTransferHTTP::OnRead()
{
	CDownloadTransfer::OnRead();

	switch ( m_nState )
	{
	case dtsRequesting:
		if ( ! ReadResponseLine() ) return FALSE;
		if ( m_nState != dtsHeaders ) break;

	case dtsHeaders:
		if ( ! ReadHeaders() ) return FALSE;
		if ( m_nState != dtsDownloading ) break;

	case dtsDownloading:
		return ReadContent();

	case dtsTiger:
		return ReadTiger();

	case dtsMetadata:
		return ReadMetadata();

	case dtsFlushing:
		return ReadFlush();

	}

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CDownloadTransferHTTP read response line

BOOL CDownloadTransferHTTP::ReadResponseLine()
{
	CString strLine, strCode, strMessage;

	if ( ! m_pInput->ReadLine( strLine ) ) return TRUE;
	if ( strLine.IsEmpty() ) return TRUE;

	if ( strLine.GetLength() > 512 ) strLine = _T("#LINE_TOO_LONG#");

	theApp.Message( MSG_DEBUG, _T("%s: DOWNLOAD RESPONSE: %s"), (LPCTSTR)m_sAddress, (LPCTSTR)strLine );

	if ( strLine.GetLength() >= 12 && strLine.Left( 9 ) == _T("HTTP/1.1 ") )
	{
		strCode		= strLine.Mid( 9, 3 );
		strMessage	= strLine.Mid( 12 );
		m_bKeepAlive = TRUE;
	}
	else if ( strLine.GetLength() >= 12 && strLine.Left( 9 ) == _T("HTTP/1.0 ") )
	{
		strCode		= strLine.Mid( 9, 3 );
		strMessage	= strLine.Mid( 12 );
		m_bKeepAlive = FALSE;
	}
	else if ( strLine.GetLength() >= 8 && strLine.Left( 4 ) == _T("HTTP") )
	{
		strCode		= strLine.Mid( 5, 3 );
		strMessage	= strLine.Mid( 8 );
	}
	else
	{
		theApp.Message( MSG_ERROR, IDS_DOWNLOAD_NOHTTP, (LPCTSTR)m_sAddress );
		Close( TS_FALSE );
		return FALSE;
	}

	if ( strCode == _T("200") || strCode == _T("206") )
	{
		m_bBadResponse = FALSE;
		m_pSource->m_nFailures = 0;
		if ( !m_bHeadRequest ) m_pSource->m_nBusyCount = 0;
	}
	else if ( strCode == _T("503") )
	{
		// 503 response without an X-Available-Ranges header means the complete file is available
		if ( _tcsistr( strMessage, _T("range") ) != NULL )
		{
			m_bRangeFault = TRUE;
			m_pSource->m_bReConnect = FALSE;
		}
		else
		{
			m_bBusyFault = TRUE;
			m_pSource->m_nFailures = 0;
		}
		m_pSource->m_bReConnect = FALSE;
		theApp.Message( MSG_ERROR, IDS_DOWNLOAD_HTTPCODE, (LPCTSTR)m_sAddress,
			(LPCTSTR)strCode, (LPCTSTR)strMessage );
	}
	else if ( strCode == _T("416") )
	{
		m_bRangeFault = TRUE;
		m_pSource->m_bReConnect = FALSE;
		theApp.Message( MSG_ERROR, IDS_DOWNLOAD_HTTPCODE, (LPCTSTR)m_sAddress,
			(LPCTSTR)strCode, (LPCTSTR)strMessage );
	}
	else if ( strCode == _T("301") || strCode == _T("302") )
	{
		m_bRedirect = TRUE;
		m_pSource->m_bReConnect = FALSE;
		theApp.Message( MSG_ERROR, IDS_DOWNLOAD_HTTPCODE, (LPCTSTR)m_sAddress,
			(LPCTSTR)strCode, (LPCTSTR)strMessage );
	}
	else if ( strCode == _T("404") )
	{
		m_bBadResponse = TRUE;
		m_pSource->m_bReConnect = FALSE;
		theApp.Message( MSG_ERROR, IDS_DOWNLOAD_HTTPCODE, (LPCTSTR)m_sAddress,
			(LPCTSTR)strCode, (LPCTSTR)strMessage );
	}
	else
	{
		strMessage.TrimLeft();
		if ( strMessage.GetLength() > 128 ) strMessage = _T("No Message");
		theApp.Message( MSG_ERROR, IDS_DOWNLOAD_HTTPCODE, (LPCTSTR)m_sAddress,
			(LPCTSTR)strCode, (LPCTSTR)strMessage );
		m_bBadResponse = TRUE;
		m_pSource->m_bReConnect = FALSE;

	}

	SetState( dtsHeaders );

	m_pHeaderName.RemoveAll();
	m_pHeaderValue.RemoveAll();

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CDownloadTransferHTTP read header lines

BOOL CDownloadTransferHTTP::OnHeaderLine(CString& strHeader, CString& strValue)
{
	theApp.Message( MSG_DEBUG, _T("%s: DOWNLOAD HEADER: %s: %s"), (LPCTSTR)m_sAddress, (LPCTSTR)strHeader, (LPCTSTR)strValue );

	if ( strHeader.CompareNoCase( _T("Server") ) == 0 )
	{
		m_sUserAgent = strValue;

		// Agent Block should not be checked here, because it might be able to give out Valid Sources with Source exchange
		//if ( IsAgentBlocked() )
		//{
		//	Close( TS_FALSE );
		//	return FALSE;
		//}

		m_pSource->m_sServer = strValue;
		if ( strValue.GetLength() > 64 ) strValue = strValue.Left( 64 );

		if ( _tcsistr( m_sUserAgent, _T("shareaza") ) != NULL ) m_pSource->SetGnutella( 3 );
		if ( _tcsistr( m_sUserAgent, _T("trustyfiles") ) != NULL ) m_pSource->SetGnutella( 3 );
		if ( _tcsistr( m_sUserAgent, _T("gnucdna") ) != NULL ) m_pSource->SetGnutella( 3 );
		if ( _tcsistr( m_sUserAgent, _T("vagaa") ) != NULL ) m_pSource->SetGnutella( 3 );
		if ( _tcsistr( m_sUserAgent, _T("mxie") ) != NULL ) m_pSource->SetGnutella( 3 );
		if ( _tcsistr( m_sUserAgent, _T("adagio") ) != NULL ) m_pSource->SetGnutella( 2 );
	}
	else if ( strHeader.CompareNoCase( _T("Connection") ) == 0 )
	{
		if ( strValue.CompareNoCase( _T("Keep-Alive") ) == 0 ) 
		{
			m_bKeepAlive = TRUE;
			m_pSource->m_bCloseConn = FALSE;
		}
		if ( strValue.CompareNoCase( _T("close") ) == 0 ) 
		{
			m_bKeepAlive = FALSE;
			if ( !m_bBadResponse && !m_bRangeFault && !m_bBusyFault ) 
			{
				m_pSource->m_bCloseConn = TRUE;
			}
			else
			{
				m_pSource->m_bCloseConn = FALSE;
			}
		}
	}
	else if ( strHeader.CompareNoCase( _T("Content-Length") ) == 0 )
	{
		_stscanf( strValue, _T("%I64i"), &m_nContentLength );
	}
	else if ( strHeader.CompareNoCase( _T("Content-Range") ) == 0 )
	{
		QWORD nFirst = 0, nLast = 0, nTotal = 0;

		if ( _stscanf( strValue, _T("bytes %I64i-%I64i/%I64i"), &nFirst, &nLast, &nTotal ) != 3 )
			_stscanf( strValue, _T("bytes=%I64i-%I64i/%I64i"), &nFirst, &nLast, &nTotal );

		if ( m_pDownload->m_nSize == SIZE_UNKNOWN )
		{
			m_pDownload->m_nSize = nTotal;
		}
		else if ( m_bTigerFetch || m_bMetaFetch )
		{
			m_nOffset = nFirst;
			m_nLength = nLast + 1 - nFirst;
			if ( m_nContentLength == SIZE_UNKNOWN ) m_nContentLength = m_nLength;
			return TRUE;
		}
		else if ( m_pDownload->m_nSize != nTotal )
		{
			theApp.Message( MSG_ERROR, IDS_DOWNLOAD_WRONG_SIZE, (LPCTSTR)m_sAddress,
				(LPCTSTR)m_pDownload->GetDisplayName() );
			Close( TS_FALSE );
			return FALSE;
		}

		if ( m_nOffset == SIZE_UNKNOWN && ! m_pDownload->GetFragment( this ) )
		{
			Close( TS_TRUE );
			return FALSE;
		}

		BOOL bUseful = m_pDownload->IsPositionEmpty( nFirst );
		// BOOL bUseful = m_pDownload->IsRangeUseful( nFirst, nLast - nFirst + 1 );

		if ( nFirst == m_nOffset && nLast == m_nOffset + m_nLength - 1 && bUseful )
		{
			// Perfect match, good
		}
		else if ( nFirst >= m_nOffset && nFirst < m_nOffset + m_nLength && bUseful )
		{
			m_nOffset = nFirst;
			m_nLength = nLast - nFirst + 1;

			theApp.Message( MSG_DEFAULT, IDS_DOWNLOAD_USEFUL_RANGE, (LPCTSTR)m_sAddress,
				m_nOffset, m_nOffset + m_nLength - 1, (LPCTSTR)m_pDownload->GetDisplayName() );
		}
		else
		{
			theApp.Message( MSG_ERROR, IDS_DOWNLOAD_WRONG_RANGE, (LPCTSTR)m_sAddress,
				(LPCTSTR)m_pDownload->GetDisplayName() );
			Close( TS_TRUE );

			return FALSE;
		}

		if ( m_nContentLength == SIZE_UNKNOWN ) m_nContentLength = m_nLength;
		m_bGotRange = TRUE;
	}
	else if ( strHeader.CompareNoCase( _T("Content-Type") ) == 0 )
	{
		m_sContentType = strValue;
	}
	else if ( strHeader.CompareNoCase( _T("Content-Encoding") ) == 0 )
	{
		if ( Settings.Downloads.AllowBackwards && _tcsistr( strValue, _T("backwards") ) ) m_bRecvBackwards = TRUE;
	}
	else if (	strHeader.CompareNoCase( _T("X-Gnutella-Content-URN") ) == 0 ||
				strHeader.CompareNoCase( _T("X-Content-URN") ) == 0 ||
				strHeader.CompareNoCase( _T("Content-URN") ) == 0 )
	{
		Hashes::Sha1Hash oSHA1;
		Hashes::TigerHash oTiger;
		Hashes::Ed2kHash oED2K;
		Hashes::Ed2kHash oMD5;
		CString strURNs = strValue + ',';
		for ( int nPos = strURNs.Find( ',' ); nPos >= 0; nPos = strURNs.Find( ',' ) )
		{
			strValue = strURNs.Left( nPos ).TrimLeft();
			strURNs = strURNs.Mid( nPos + 1 );

			if (   ( !oSHA1.fromUrn( strValue ) || m_pSource->CheckHash( oSHA1  ) )
				&& ( !oTiger.fromUrn( strValue ) || m_pSource->CheckHash( oTiger ) )
				&& ( !oED2K.fromUrn( strValue ) || m_pSource->CheckHash( oED2K ) )
				&& ( !oMD5.fromUrn( strValue ) || m_pSource->CheckHash( oMD5  ) ) )
			{
				if ( !m_bTigerFailed && oTiger && Settings.Downloads.VerifyTiger && !m_bTigerIgnore && oTiger && m_sTigerTree.IsEmpty()
					&& (  ( _tcsistr( m_sUserAgent, L"Shareaza 2.1" ) != NULL
						&&	_tcsistr( m_sUserAgent, L"2.1.0.0" ) == NULL )
						||	_tcsistr( m_sUserAgent, L"Shareaza 2.2.0" ) != NULL ) )
				{
					// Converting urn containing tiger tree root to
					// "/gnutella/thex/v1?urn:tree:tiger/:{TIGER_ROOT}&depth={TIGER_HEIGHT}&ed2k={0/1}"
					// in case if "X-Thex-URI" and "X-TigerTree-Path" headers
					// will be absent (perfect workaround for "silent" Sareaza 2.2.0.0)
					m_sTigerTree.Format( L"/gnutella/thex/v1?%s&depth=%d&ed2k=%d",
						oTiger.toUrn(),
						Settings.Library.TigerHeight,
						Settings.Downloads.VerifyED2K );
				}
				m_bHashMatch = m_bHashMatch || oSHA1 || oTiger || oED2K || oMD5;
				continue;
			}
			theApp.Message( MSG_ERROR, IDS_DOWNLOAD_WRONG_HASH, (LPCTSTR)m_sAddress,
				(LPCTSTR)m_pDownload->GetDisplayName() );
			Close( TS_FALSE );
			return FALSE;
		}
		m_pSource->SetGnutella( 1 );
	}
	else if ( strHeader.CompareNoCase( _T("X-Metadata-Path") ) == 0 )
	{
		if ( ! m_bMetaIgnore && Settings.Downloads.Metadata ) m_sMetadata = strValue;
	}
	else if ( strHeader.CompareNoCase( _T("X-TigerTree-Path") ) == 0 )
	{
		if ( Settings.Downloads.VerifyTiger && ! m_bTigerIgnore && m_sTigerTree.IsEmpty() )
		{
			if ( strValue.Find( _T("tigertree/v1") ) < 0 &&
				 strValue.Find( _T("tigertree/v2") ) < 0 )
			{
				m_sTigerTree = strValue;
			}
		}
	}
	else if ( strHeader.CompareNoCase( _T("X-Thex-URI") ) == 0 )
	{
		if ( Settings.Downloads.VerifyTiger && ! m_bTigerIgnore )
		{
			if ( StartsWith( strValue, _T("/") ) )
			{
				m_sTigerTree = strValue.SpanExcluding( _T("; ") );
				Replace( m_sTigerTree, _T("ed2k=0"), _T("ed2k=1") );

				int nPos = m_sTigerTree.GetLength() + 1;
				Hashes::TigerHash oTiger;
				oTiger.fromString( strValue.Mid( nPos ) );
				if ( oTiger && !m_pSource->CheckHash(oTiger) )
				{
					theApp.Message( MSG_ERROR, IDS_DOWNLOAD_WRONG_HASH, (LPCTSTR)m_sAddress,
						(LPCTSTR)m_pDownload->GetDisplayName() );
					Close( TS_FALSE );
					return FALSE;
				}
			}
		}
		m_pSource->SetGnutella( 1 );
	}
	else if (	strHeader.CompareNoCase( _T("X-Gnutella-Alternate-Location") ) == 0 )
	{
		if ( Settings.Library.SourceMesh )
		{
			if ( strValue.Find( _T("Zhttp://") ) < 0 )
			{
				m_pDownload->AddSourceURLs( strValue, m_bHashMatch, FALSE, PROTOCOL_HTTP );
			}
		}
		m_pSource->SetGnutella( 1 );
	}
	else if ( strHeader.CompareNoCase( _T("X-Alt") ) == 0 )
	{
		if ( Settings.Library.SourceMesh )
		{
			m_pDownload->AddSourceURLs( strValue, m_bHashMatch, FALSE, PROTOCOL_G1 );
		}
		m_pSource->SetGnutella( 1 );
	}
	else if (	strHeader.CompareNoCase( _T("Alt-Location") ) == 0 )
	{
		if ( Settings.Library.SourceMesh )
		{
			if ( strValue.Find( _T("Zhttp://") ) < 0 )
			{
				m_pDownload->AddSourceURLs( strValue, m_bHashMatch,  FALSE, PROTOCOL_HTTP );
			}
		}
		m_pSource->SetGnutella( 2 );	// basically any of Gnutella1 servents do not use this "Alt-Location" so assume
										// it is G2 for now.
	}
	else if (	strHeader.CompareNoCase( _T("X-G2Alt") ) == 0 )
	{
		if ( Settings.Library.SourceMesh )
		{
			m_pDownload->AddSourceURLs( strValue, m_bHashMatch,  FALSE, PROTOCOL_G2 );
		}
		m_pSource->SetGnutella( 2 );	// basically any of Gnutella1 servents do not use this "Alt-Location" so assume
		// it is G2 for now.
	}
	else if ( strHeader.CompareNoCase( _T("X-Available-Ranges") ) == 0 )
	{
		m_bGotRanges = TRUE;
		m_pSource->SetAvailableRanges( strValue );
		m_pSource->SetGnutella( 1 );
		if ( m_pSource->m_oAvailable.empty() )
		{
			// Dropping source without wanted range here is inappropriate,
			// because Close(TS_FALSE) will cause tell others that the source is not good for partial share
			// even if there might be some one which is so behind than you and still want range you dont need.
			// Plug the source might get some useful range to you later.

            // theApp.Message( MSG_DEBUG, _T( "header did not include valid ranges, dropping source..." ) );
			// Close( TS_FALSE );

            Close( TS_UNKNOWN );
			return FALSE;
		}
	}
	else if ( strHeader.CompareNoCase( _T("X-Queue") ) == 0 )
	{
		m_pSource->SetGnutella( 1 );

		m_bQueueFlag = TRUE;
		CharLower( strValue.GetBuffer() );
		strValue.ReleaseBuffer();

		int nPos = strValue.Find( _T("position=") );
		if ( nPos >= 0 ) _stscanf( strValue.Mid( nPos + 9 ), _T("%i"), &m_nQueuePos );

		nPos = strValue.Find( _T("length=") );
		if ( nPos >= 0 ) _stscanf( strValue.Mid( nPos + 7 ), _T("%i"), &m_nQueueLen );

		DWORD nLimit = 0;

		nPos = strValue.Find( _T("pollmin=") );
		if ( nPos >= 0 && _stscanf( strValue.Mid( nPos + 8 ), _T("%u"), &nLimit ) == 1 )
		{
			m_nRetryDelay = max( m_nRetryDelay, nLimit * 1000 + 3000  );
		}

		nPos = strValue.Find( _T("pollmax=") );
		if ( nPos >= 0 && _stscanf( strValue.Mid( nPos + 8 ), _T("%u"), &nLimit ) == 1 )
		{
			m_nRetryDelay = min( m_nRetryDelay, nLimit * 1000 - 8000 );
		}

		nPos = strValue.Find( _T("id=") );
		if ( nPos >= 0 )
		{
			m_sQueueName = strValue.Mid( nPos + 3 );
			m_sQueueName.TrimLeft();
			if ( m_sQueueName.Find( '\"' ) == 0 )
			{
				m_sQueueName = m_sQueueName.Mid( 1 ).SpanExcluding( _T("\"") );
			}
			else
			{
				m_sQueueName = m_sQueueName.SpanExcluding( _T("\" ") );
			}
			if ( m_sQueueName == _T("s") ) m_sQueueName = _T("Small Queue");
			else if ( m_sQueueName == _T("l") ) m_sQueueName = _T("Large Queue");
		}
	}
	else if (	strHeader.CompareNoCase( _T("X-PerHost") ) == 0 ||
				strHeader.CompareNoCase( _T("X-Gnutella-maxSlotsPerHost") ) == 0 )
	{
		int nLimit = 0;

		if ( _stscanf( strValue, _T("%i"), &nLimit ) != 1 )
		{
			Downloads.SetPerHostLimit( &m_pHost.sin_addr, nLimit );
		}
	}
	else if ( strHeader.CompareNoCase( _T("X-Delete-Source") ) == 0 )
	{
		m_bBadResponse = TRUE;
	}
	else if (	strHeader.CompareNoCase( _T("X-Nick") ) == 0 ||
				strHeader.CompareNoCase( _T("X-Name") ) == 0 ||
				strHeader.CompareNoCase( _T("X-UserName") ) == 0 )
	{
		m_pSource->m_sNick = URLDecode( strValue );
	}
	else if ( strHeader.CompareNoCase( _T("X-Features") ) == 0 )
	{
		if ( _tcsistr( strValue, _T("g2/") ) != NULL ) m_pSource->SetGnutella( 2 );
		if ( _tcsistr( strValue, _T("gnet2/") ) != NULL ) m_pSource->SetGnutella( 2 );
		if ( _tcsistr( strValue, _T("gnutella2/") ) != NULL ) m_pSource->SetGnutella( 2 );
		m_pSource->SetGnutella( 1 );
	}
	else if ( strHeader.CompareNoCase( _T("Location") ) == 0 )
	{
		m_sRedirectionURL = strValue;
	}
	else if ( strHeader.CompareNoCase( _T("X-NAlt") ) == 0 ||
			  strHeader.CompareNoCase( _T("X-PAlt") ) == 0 ||
			  strHeader.CompareNoCase( _T("FP-1a") ) == 0 ||
			  strHeader.CompareNoCase( _T("FP-Auth-Challenge") ) == 0 )
	{
		m_pSource->SetGnutella( 1 );
	}
	else if ( strHeader.CompareNoCase( _T("X-G2NH") ) == 0 )
	{	// The remote computer is giving us a list of G2 hubs the remote node is connected to
		int nCount = 0;
		CDownloadSource::HubList oHubList;
		CString sHublist(strValue);
		for ( sHublist += ',' ; ; ) 
		{
			int nPos = sHublist.Find( ',' );		// Set nPos to the distance in characters from the start to the comma
			if ( nPos < 0 ) break;					// If no comma was found, leave the loop
			CString sHub = sHublist.Left( nPos );// Copy the text up to the comma into strHost
			sHublist = sHublist.Mid( nPos + 1 );    // Clip that text and the comma off the start of strValue

			// since there is no clever way to detect the given what Hosts' vender codes are, just add then as NULL
			// in order to prevent HostCache/KHL pollution done by mis-assumptions.
			// if ( HostCache.Gnutella2.Add( sHub, 0, NULL ) ) nCount++; // Count it
			SOCKADDR_IN pHub;
			if ( StrToSockaddr( sHub, pHub ) )
			{
				nCount++;
				oHubList.push_back(pHub);
			}
		}
		if ( nCount > 0 ) m_pSource->m_oHubList = oHubList;
		m_pSource->SetGnutella( 2 );
	}
	else if ( strHeader.CompareNoCase( _T("X-Push-Proxy") ) == 0 )
	{	// The remote computer is giving us a list of G1 PushProxy the remote node is connected to
		int nCount = 0;
		CDownloadSource::HubList pProxies;
		CString sProxylist(strValue);

		for ( sProxylist += ',' ; ; ) 
		{
			int nPos = sProxylist.Find( ',' );		// Set nPos to the distance in characters from the start to the comma
			if ( nPos < 0 ) break;					// If no comma was found, leave the loop
			CString sProxy = sProxylist.Left( nPos );// Copy the text up to the comma into strHost
			sProxylist = sProxylist.Mid( nPos + 1 );    // Clip that text and the comma off the start of strValue

			// since there is no clever way to detect the given what Hosts' vender codes are, just add then as NULL
			// in order to prevent HostCache/KHL pollution done by mis-assumptions.
			// if ( HostCache.Gnutella2.Add( sHub, 0, NULL ) ) nCount++; // Count it
			SOCKADDR_IN pProxy;
			if ( StrToSockaddr( sProxy, pProxy ) )
			{
				CString strAddr;
				CString strPort;
				strAddr = CString( inet_ntoa( pProxy.sin_addr ) );
				strPort.Format( _T("%hu") ,ntohs( pProxy.sin_port ) );
				nCount++;
				pProxies.push_back(pProxy);
			}
		}
		if ( nCount > 0 ) m_pSource->m_oPushProxyList = pProxies;
		m_pSource->SetGnutella( 1 );
	}
	else if ( strHeader.CompareNoCase( _T("Retry-After") ) == 0 && m_bBusyFault )
	{
		_stscanf( strValue, _T("%i"), &m_nRetryAfter);
	}

	return CTransfer::OnHeaderLine( strHeader, strValue );
}

//////////////////////////////////////////////////////////////////////
// CDownloadTransferHTTP end of headers

BOOL CDownloadTransferHTTP::OnHeadersComplete()
{
	// Close parameters:
	// TS_FALSE   - the source will be added to m_pFailedSources in CDownloadWithSources,
	//			    removed from the sources and can be distributed in the Source Mesh as X-Nalt
	// TS_TRUE    - keeps the source and will be distributed as X-Alt
	// TS_UNKNOWN - keeps the source and will be dropped after several retries, will be
	//            - added to m_pFailedSources when removed

	switch ( m_pSource->m_nGnutella )
	{
		case 1:
			m_pSource->ChangeProtocolID( PROTOCOL_G1 );
			break;
		case 2:
			m_pSource->ChangeProtocolID( PROTOCOL_G2 );
			break;
		case 3:
			m_pSource->ChangeProtocolID( PROTOCOL_G2 );
			break;
		default:
			break;
	}

	// Bad agent check should be moved here, because it can still give out sources with Source-Exchange.
	if ( IsAgentBlocked() )
	{
		Close( TS_FALSE );
		return FALSE;
	}
	else if ( m_bBadResponse )
	{
		if (m_bTigerFetch)
		{
			m_bTigerFailed = TRUE;
			m_bTigerFetch = FALSE;
			m_sTigerTree.Empty();
			ReadFlush();
			return StartNextFragment();
		}
		else
		{
			m_pSource->m_bReConnect = FALSE;
			m_pSource->m_bCloseConn = FALSE;
			Close( TS_FALSE );
			return FALSE;
		}
	}
	else if ( m_bRedirect )
	{
		int nRedirectionCount = m_pSource->m_nRedirectionCount;
		m_pDownload->AddSourceURL( m_sRedirectionURL, m_bHashMatch, NULL, nRedirectionCount + 1 );
		// This TS_FALSE should be fixed for something dropping source without banning because it will 
		// make the source server to be banned for source if the source is on same IP as the server redirected to. 
		// Close( TS_FALSE );
		Close( TS_UNKNOWN );
		return FALSE;
	}
	else if ( m_bHeadRequest )
	{
		if ( !m_bKeepAlive )
		{
			m_pSource->m_bReConnect = TRUE;
			m_pSource->m_bCloseConn = TRUE;
		}
		else
		{
			if ( m_pDownload->m_nSize == SIZE_UNKNOWN )
			{
				m_pDownload->m_nSize = m_nContentLength;
			}

			if ( ! m_bGotRanges )
			{
				m_pSource->SetAvailableRanges( NULL );
			}

			if ( !m_bRangeFault )
			{
				m_bHeadRequest = FALSE;
				if ( m_pDownload->NeedTigerTree() && !m_sTigerTree.IsEmpty() && !m_bTigerFailed ) m_bTigerFetch = TRUE;
				m_nContentLength = SIZE_UNKNOWN;
				return StartNextFragment();
			}
			else
			{
				Close( TS_FALSE );
				return FALSE;
			}
		}
	}
	else if ( ! m_pSource->CanInitiate( TRUE, TRUE ) )
	{
		theApp.Message( MSG_ERROR, IDS_DOWNLOAD_DISABLED,
			(LPCTSTR)m_pDownload->GetDisplayName(), (LPCTSTR)m_sAddress, (LPCTSTR)m_sUserAgent );
		// ???Does this condition needed? if it is ED2K source, HTTP code should not be executed in first place.
		Close( m_pSource->m_bED2K ? TS_FALSE : TS_UNKNOWN );
		return FALSE;
	}
	else if ( m_bBusyFault )
	{
		m_nOffset = SIZE_UNKNOWN;
		m_pSource->m_nFailures = 0;

		if ( Settings.Downloads.QueueLimit > 0 && m_nQueuePos > Settings.Downloads.QueueLimit )
		{
			theApp.Message( MSG_ERROR, IDS_DOWNLOAD_QUEUE_HUGE,
				(LPCTSTR)m_sAddress, (LPCTSTR)m_pDownload->GetDisplayName(), m_nQueuePos );
			Close( TS_UNKNOWN );
			return FALSE;
		}
		else if ( m_bQueueFlag && m_nRetryDelay >= 600000 )
		{
			m_pSource->m_tAttempt = GetTickCount() + m_nRetryDelay;
			m_bQueueFlag = FALSE;
		}

		if ( m_bQueueFlag )
		{
			SetState( dtsFlushing );
			m_tContent = m_mInput.tLast = GetTickCount();
			return ReadFlush();
		}
		else
		{
			SetState( dtsBusy );
			m_pSource->m_nBusyCount++;
			m_tRequest = GetTickCount();
			return TRUE;
		}
	}
	else if ( ! m_bGotRanges && ! m_bTigerFetch && ! m_bMetaFetch )
	{
		m_pSource->SetAvailableRanges( NULL );
	}

	if ( m_bRangeFault )
	{
		if ( m_pHost.sin_addr.S_un.S_addr == Network.m_pHost.sin_addr.S_un.S_addr )
		{
			Close( TS_TRUE );
			return FALSE;
		}

		m_nOffset = SIZE_UNKNOWN;
		SetState( dtsFlushing );
		m_tContent = m_mInput.tLast = GetTickCount();

		return ReadFlush();
	}
	else if ( m_nContentLength == SIZE_UNKNOWN && m_bKeepAlive )
	{
		theApp.Message( MSG_ERROR, IDS_DOWNLOAD_WRONG_SIZE, (LPCTSTR)m_sAddress,
			(LPCTSTR)m_pDownload->GetDisplayName() );
		Close( TS_FALSE );
		return FALSE;
	}
	else if ( m_bTigerFetch )
	{
		if ( m_nContentLength == SIZE_UNKNOWN && !m_bKeepAlive )
		{
            // This should fix the PHEX TTH problem with closed connection.
            SetState( dtsTiger );
            theApp.Message( MSG_DEFAULT, IDS_DOWNLOAD_TIGER_RECV, (LPCTSTR)m_sAddress,
                (LPCTSTR)m_pSource->m_sServer );

            return ReadTiger(); // doesn't actually read but updates timings
		}
		if ( ! m_bGotRange )
		{
			m_nOffset = 0;
			m_nLength = m_nContentLength;
		}
		else if ( m_nOffset > 0 )
		{
			theApp.Message( MSG_DEFAULT, IDS_DOWNLOAD_TIGER_RANGE, (LPCTSTR)m_sAddress );
			Close( TS_FALSE );
			return FALSE;
		}

		if (	m_sContentType.CompareNoCase( _T("application/tigertree-breadthfirst") ) &&
				m_sContentType.CompareNoCase( _T("application/dime") ) && 
				m_sContentType.CompareNoCase( _T("application/binary") ) ) // Content Type used by Phex 
		{
			theApp.Message( MSG_DEFAULT, IDS_DOWNLOAD_TIGER_RANGE, (LPCTSTR)m_sAddress );
			Close( TS_TRUE );
			return FALSE;
		}

		SetState( dtsTiger );
		m_tContent = m_mInput.tLast = GetTickCount();

		theApp.Message( MSG_DEFAULT, IDS_DOWNLOAD_TIGER_RECV, (LPCTSTR)m_sAddress,
			(LPCTSTR)m_pSource->m_sServer );

		return ReadTiger();
	}
	else if ( m_bMetaFetch )
	{
		if ( ! m_bGotRange )
		{
			m_nOffset = 0;
			m_nLength = m_nContentLength;
		}

		SetState( dtsMetadata );
		m_tContent = m_mInput.tLast = GetTickCount();

		theApp.Message( MSG_DEFAULT, IDS_DOWNLOAD_METADATA_RECV,
			(LPCTSTR)m_sAddress, (LPCTSTR)m_pSource->m_sServer );

		return ReadMetadata();
	}
	else if ( ! m_bGotRange )
	{
		if ( m_pDownload->m_nSize == SIZE_UNKNOWN )
		{
			m_pDownload->m_nSize = m_nContentLength;
		}
		else if ( m_pDownload->m_nSize != m_nContentLength )
		{
			theApp.Message( MSG_ERROR, IDS_DOWNLOAD_WRONG_SIZE, (LPCTSTR)m_sAddress,
				(LPCTSTR)m_pDownload->GetDisplayName() );
			Close( TS_FALSE );
			return FALSE;
		}

		if ( m_nOffset == SIZE_UNKNOWN && ! m_pDownload->GetFragment( this ) )
		{
			Close( TS_TRUE );
			return FALSE;
		}

		if ( ! m_pDownload->IsPositionEmpty( 0 ) )
		{
			theApp.Message( MSG_ERROR, IDS_DOWNLOAD_WRONG_RANGE, (LPCTSTR)m_sAddress,
				(LPCTSTR)m_pDownload->GetDisplayName() );
			Close( TS_TRUE );
			return FALSE;
		}

		m_nOffset = 0;
		m_nLength = m_nContentLength;
	}
	else if ( CFailedSource* pBadSource = m_pDownload->LookupFailedSource( m_pSource->m_sURL ) )
	{
		// We already have it added to the list but the source was offline
		if ( pBadSource->m_bOffline )
		{
			pBadSource->m_bOffline = false;
		}
		else
		{
			// Extend the period of keeping it in the failed sources list
			pBadSource->m_nTimeAdded = GetTickCount();
			Close( TS_FALSE );
			return FALSE;
		}
	}
	else if ( m_nContentLength != m_nLength )
	{
		theApp.Message( MSG_ERROR, IDS_DOWNLOAD_WRONG_RANGE, (LPCTSTR)m_sAddress,
			(LPCTSTR)m_pDownload->GetDisplayName() );
		Close( TS_FALSE );
		return FALSE;
	}

	theApp.Message( MSG_DEFAULT, IDS_DOWNLOAD_CONTENT, (LPCTSTR)m_sAddress,
		(LPCTSTR)m_pSource->m_sServer );

	SetState( dtsDownloading );
	if ( ! m_pDownload->IsBoosted() )
		m_mInput.pLimit = m_mOutput.pLimit = &m_nBandwidth;
	m_nPosition = 0;
	m_tContent = m_mInput.tLast = GetTickCount();

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CDownloadTransferHTTP read content

BOOL CDownloadTransferHTTP::ReadContent()
{
	if ( m_pInput->m_nLength > 0 )
	{
		m_pSource->SetValid();

		DWORD nLength	= min( m_pInput->m_nLength, m_nLength - m_nPosition );
		BOOL bSubmit	= FALSE;

		if ( m_bRecvBackwards )
		{
			BYTE* pBuffer = new BYTE[ nLength ];
			CBuffer::ReverseBuffer( m_pInput->m_pBuffer, pBuffer, nLength );
			bSubmit = m_pDownload->SubmitData(
				m_nOffset + m_nLength - m_nPosition - nLength, pBuffer, nLength );
			delete [] pBuffer;
		}
		else
		{
			bSubmit = m_pDownload->SubmitData(
						m_nOffset + m_nPosition, m_pInput->m_pBuffer, nLength );
		}

		m_pInput->Clear();	// Clear the buffer, we don't want any crap
		m_nPosition += nLength;
		m_nDownloaded += nLength;

		if ( ! bSubmit )
		{
			BOOL bUseful = m_pDownload->IsRangeUsefulEnough( this,
				m_bRecvBackwards ? m_nOffset : m_nOffset + m_nPosition,
				m_nLength - m_nPosition );

			if ( /* m_bInitiated || */ ! bUseful )
			{
				theApp.Message( MSG_DEFAULT, IDS_DOWNLOAD_FRAGMENT_OVERLAP, (LPCTSTR)m_sAddress );
				Close( TS_TRUE );
				return FALSE;
			}
		}
	}

	if ( m_nPosition >= m_nLength )
	{
		m_pSource->AddFragment( m_nOffset, m_nLength );

		if ( m_bKeepAlive ) return StartNextFragment();	// send next segment request only if it was keep-alive
	}

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CDownloadTransferHTTP read Metadata

BOOL CDownloadTransferHTTP::ReadMetadata()
{
	if ( m_pInput->m_nLength < m_nLength ) return TRUE;

	CString strXML = m_pInput->ReadString( (DWORD)m_nLength, CP_UTF8 );

	if ( CXMLElement* pXML = CXMLElement::FromString( strXML, TRUE ) )
	{
		if ( m_pDownload->m_pXML == NULL )
		{
			m_pDownload->m_pXML = pXML;
		}
		else
		{
			delete pXML;
		}
	}

	m_pInput->Remove( (DWORD)m_nLength );

	return StartNextFragment();
}

//////////////////////////////////////////////////////////////////////
// CDownloadTransferHTTP read tiger tree

BOOL CDownloadTransferHTTP::ReadTiger()
{
    // It is a fix for very slow DIME uploads, they get dropped while downloading (e.g. LimeWire).
    m_tContent = m_mInput.tLast = GetTickCount();

    // Fix for PHEX TTH which never tell content length for DIME block to get into DIME decoding 
    // until the connection drops, if no content length specified and not keep-alive.
    if ( !m_bKeepAlive && m_nContentLength == SIZE_UNKNOWN ) return TRUE;

    if ( m_pInput->m_nLength < m_nLength ) return TRUE;

	if ( m_sContentType.CompareNoCase( _T("application/tigertree-breadthfirst") ) == 0 )
	{
		m_pDownload->SetTigerTree( m_pInput->m_pBuffer, (DWORD)m_nLength );
		m_pInput->Remove( (DWORD)m_nLength );
	}
	else if ( m_sContentType.CompareNoCase( _T("application/dime") ) == 0 ||
			  m_sContentType.CompareNoCase( _T("application/binary") ) == 0 )
	{
		CString strID, strType, strUUID = _T("x");
		DWORD nFlags, nBody;

		while ( m_pInput->ReadDIME( &nFlags, &strID, &strType, &nBody ) )
		{
			theApp.Message( MSG_DEBUG, _T("THEX DIME: %i, '%s', '%s', %i"),
				nFlags, (LPCTSTR)strID, (LPCTSTR)strType, nBody );

			if ( ( nFlags & 1 ) && strType.CompareNoCase( _T("text/xml") ) == 0 && nBody < 1024*1024 )
			{
				BOOL bSize = FALSE, bDigest = FALSE, bEncoding = FALSE;
				CString strXML;

				strXML = m_pInput->ReadString( nBody, CP_UTF8 );

				if ( CXMLElement* pXML = CXMLElement::FromString( strXML ) )
				{
					if ( pXML->IsNamed( _T("hashtree") ) )
					{
						if ( CXMLElement* pxFile = pXML->GetElementByName( _T("file") ) )
						{
							QWORD nSize = 0;
							_stscanf( pxFile->GetAttributeValue( _T("size") ), _T("%I64i"), &nSize );
							bSize = ( nSize == m_pDownload->m_nSize );
						}
						if ( CXMLElement* pxDigest = pXML->GetElementByName( _T("digest") ) )
						{
							if ( pxDigest->GetAttributeValue( _T("algorithm") ).CompareNoCase( _T("http://open-content.net/spec/digest/tiger") ) == 0 )
							{
								bDigest = ( pxDigest->GetAttributeValue( _T("outputsize") ) == _T("24") );
							}
						}
						if ( CXMLElement* pxTree = pXML->GetElementByName( _T("serializedtree") ) )
						{
							bEncoding = ( pxTree->GetAttributeValue( _T("type") ).CompareNoCase( _T("http://open-content.net/spec/thex/breadthfirst") ) == 0 );
							strUUID = pxTree->GetAttributeValue( _T("uri") );
						}
					}
					delete pXML;
				}

				theApp.Message( MSG_DEBUG, _T("THEX XML: size=%i, digest=%i, encoding=%i"),
					bSize, bDigest, bEncoding );

				if ( ! bSize || ! bDigest || ! bEncoding ) break;
			}
			else if ( ( strID == strUUID || strID.IsEmpty() ) && strType.CompareNoCase( _T("http://open-content.net/spec/thex/breadthfirst") ) == 0 )
			{
				m_pDownload->SetTigerTree( m_pInput->m_pBuffer, nBody );
			}
			else if ( strType.CompareNoCase( _T("http://edonkey2000.com/spec/md4-hashset") ) == 0 )
			{
				m_pDownload->SetHashset( m_pInput->m_pBuffer, nBody );
			}

			m_pInput->Remove( ( nBody + 3 ) & ~3 );
			if ( nFlags & 2 ) break;
		}

		m_pInput->Clear();
	}

    // m_bCloseConn == FALSE means that it was not keep-alive, so should just get disconnected.
    // after reading of DIME message
    // This might be better with returning FALSE because it is not keep alive connection
    // need to disconnect after the business
	if (m_pSource->m_bCloseConn) return TRUE;

	return StartNextFragment();
}

//////////////////////////////////////////////////////////////////////
// CDownloadTransferHTTP read flushing

BOOL CDownloadTransferHTTP::ReadFlush()
{
	if ( m_nContentLength == SIZE_UNKNOWN ) m_nContentLength = 0;

	DWORD nRemove = min( m_pInput->m_nLength, m_nContentLength );
	m_nContentLength -= nRemove;

	m_pInput->Remove( nRemove );

	if ( m_nContentLength == 0 )
	{
		if ( m_bQueueFlag )
		{
			SetState( dtsQueued );
			if ( ! m_pDownload->IsBoosted() )
				m_mInput.pLimit = m_mOutput.pLimit = &Settings.Bandwidth.Request;
			m_tRequest = GetTickCount() + m_nRetryDelay;

			theApp.Message( MSG_ERROR, IDS_DOWNLOAD_QUEUED,
				(LPCTSTR)m_sAddress, m_nQueuePos, m_nQueueLen,
				(LPCTSTR)m_sQueueName );
		}
		else if ( m_bRangeFault && !m_bGotRanges )
        {
			/* we got a "requested range unavailable" error but the source doesn't
			advertise available ranges; don't start to guess, try again later */
			theApp.Message( MSG_DEFAULT, IDS_DOWNLOAD_416_WITHOUT_RANGE, (LPCTSTR)m_sAddress );
			Close( TS_TRUE );
			return FALSE;
        }
		else if ( m_bRangeFault && m_bGotRanges && m_nRequests >= 2 )
		{
			/* we made two requests already and the source does advertise available
            ranges, but we still managed to request a wrong one */
			// TODO: find the reason why this is happening
			theApp.Message( MSG_ERROR, _T("BUG: Shareaza requested a fragment from host %s, although it knew that the host doesn't have that fragment") , (LPCTSTR)m_sAddress );
			Close( TS_TRUE );
			return FALSE;
		}
		else
		{
			return StartNextFragment();
		}
	}

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CDownloadTransferHTTP dropped connection handler

void CDownloadTransferHTTP::OnDropped(BOOL /*bError*/)
{
	if ( m_bBadResponse || m_bRangeFault )
	{
		m_pSource->m_bCloseConn = FALSE;
		m_pSource->m_bReConnect = FALSE;
		Close( TS_FALSE );
	}
	else if ( m_nState == dtsConnecting )
	{
		theApp.Message( MSG_ERROR, IDS_DOWNLOAD_CONNECT_ERROR, (LPCTSTR)m_sAddress );
		if ( m_pSource != NULL ) m_pSource->PushRequest();
		m_pSource->m_bCloseConn = FALSE;
		m_pSource->m_bReConnect = FALSE;
		Close( TS_UNKNOWN );
	}
	else if ( !m_bKeepAlive )
	{
		if ( m_nState == dtsTiger )
		{
			// this is basically for PHEX DIME download
			theApp.Message( MSG_DEBUG, _T("Reading THEX from the closed connection...") );
			// It was closed connection with no content length, so assume the content length is equal to the 
			// size of buffer when the connection gets cut. It is important to set it because the DIME decoding 
			// code check if the content length is equals to size of buffer.
			m_nContentLength = m_pInput->m_nLength;
			m_nLength = m_pInput->m_nLength;
			ReadTiger();
			// CDownloadTransfer::Close will resume the closed connection
			m_pSource->m_bCloseConn = TRUE;
			m_pSource->m_bReConnect = TRUE;
			Close( TS_TRUE );
		}
		else if ( m_nState == dtsDownloading || m_nState == dtsHeaders )
		{
			m_pSource->m_bCloseConn = TRUE;
			m_pSource->m_bReConnect = TRUE;
			Close( TS_TRUE );
		}
	}
	else if ( m_nState == dtsBusy )
	{
		theApp.Message( MSG_ERROR, IDS_DOWNLOAD_BUSY, (LPCTSTR)m_sAddress, Settings.Downloads.RetryDelay / 1000 );
		m_pSource->m_bCloseConn = FALSE;
		m_pSource->m_bReConnect = FALSE;
		Close( TS_TRUE );
	}
	else if ( m_bBusyFault || m_bQueueFlag )
	{
		theApp.Message( MSG_ERROR, IDS_DOWNLOAD_BUSY, (LPCTSTR)m_sAddress, Settings.Downloads.RetryDelay / 1000 );
		m_pSource->m_bCloseConn = FALSE;
		m_pSource->m_bReConnect = FALSE;
		Close( TS_TRUE );
	}
	else if ( m_nState == dtsRequesting )
	{
		m_pSource->m_bCloseConn = FALSE;
		m_pSource->m_bReConnect = FALSE;
		Close( TS_UNKNOWN );
	}
	else
	{
		theApp.Message( MSG_ERROR, IDS_DOWNLOAD_DROPPED, (LPCTSTR)m_sAddress );
		m_pSource->m_bCloseConn = FALSE;
		m_pSource->m_bReConnect = FALSE;
		Close( m_nState >= dtsDownloading ? TS_TRUE : TS_UNKNOWN );
	}
}

