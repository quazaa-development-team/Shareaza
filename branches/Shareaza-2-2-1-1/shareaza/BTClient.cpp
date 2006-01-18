//
// BTClient.cpp
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
#include "BTClient.h"
#include "BTClients.h"
#include "BTPacket.h"
#include "BENode.h"
#include "Buffer.h"
#include "SHA.h"

#include "Download.h"
#include "Downloads.h"
#include "DownloadSource.h"
#include "DownloadTransferBT.h"
#include "Uploads.h"
#include "UploadTransferBT.h"
#include "SourceURL.h"
#include "GProfile.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif


//////////////////////////////////////////////////////////////////////
// CBTClient construction

CBTClient::CBTClient()
{
	m_bExtended			= FALSE;
	m_pUpload			= NULL;
	m_pDownload			= NULL;
	m_pDownloadTransfer	= NULL;
	
	m_bShake			= FALSE;
	m_bOnline			= FALSE;
	m_bClosing			= FALSE;
	m_bExchange			= FALSE;
	
	m_sUserAgent = _T("BitTorrent");
	m_mInput.pLimit = m_mOutput.pLimit = &Settings.Bandwidth.Request;
	
	BTClients.Add( this );
}

CBTClient::~CBTClient()
{
	ASSERT( m_hSocket == INVALID_SOCKET );
	ASSERT( m_pDownloadTransfer == NULL );
	ASSERT( m_pDownload == NULL );
	ASSERT( m_pUpload == NULL );
	
	BTClients.Remove( this );
}

//////////////////////////////////////////////////////////////////////
// CBTClient initiate a new connection

BOOL CBTClient::Connect(CDownloadTransferBT* pDownloadTransfer)
{
	ASSERT( m_hSocket == INVALID_SOCKET );
	ASSERT( m_pDownload == NULL );
	
	CDownloadSource* pSource = pDownloadTransfer->m_pSource;
	
	if ( ! CTransfer::ConnectTo( &pSource->m_pAddress, pSource->m_nPort ) ) return FALSE;
	
	m_pDownload			= pDownloadTransfer->m_pDownload;
	m_pDownloadTransfer	= pDownloadTransfer;
	
	theApp.Message( MSG_DEFAULT, IDS_BT_CLIENT_CONNECTING, (LPCTSTR)m_sAddress );
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CBTClient attach to existing connection

void CBTClient::AttachTo(CConnection* pConnection)
{
	ASSERT( m_hSocket == INVALID_SOCKET );
	CTransfer::AttachTo( pConnection );
	theApp.Message( MSG_DEFAULT, IDS_BT_CLIENT_ACCEPTED, (LPCTSTR)m_sAddress );
}

//////////////////////////////////////////////////////////////////////
// CBTClient close

void CBTClient::Close()
{
	ASSERT( this != NULL );
	
	if ( m_bClosing ) return;
	m_bClosing = TRUE;
	
	if ( m_pUpload != NULL ) m_pUpload->Close();
	ASSERT( m_pUpload == NULL );
	
	if ( m_pDownloadTransfer != NULL ) 
	{
		if ( ( m_pDownload == NULL ) || ( m_pDownload->IsCompleted() ) )
			m_pDownloadTransfer->Close( TS_FALSE );
		else
			m_pDownloadTransfer->Close( TS_UNKNOWN );
	}
	ASSERT( m_pDownloadTransfer == NULL );
	
	m_pDownload = NULL;
	
	CTransfer::Close();
	
	delete this;
}

//////////////////////////////////////////////////////////////////////
// CBTClient send a packet

void CBTClient::Send(CBTPacket* pPacket, BOOL bRelease)
{
	ASSERT( m_hSocket != INVALID_SOCKET );
	ASSERT( m_bOnline );
	
	if ( pPacket != NULL )
	{
		ASSERT( pPacket->m_nProtocol == PROTOCOL_BT );
		
		pPacket->ToBuffer( m_pOutput );
		if ( bRelease ) pPacket->Release();
	}
	
	OnWrite();
}

//////////////////////////////////////////////////////////////////////
// CBTClient run event

BOOL CBTClient::OnRun()
{
	CTransfer::OnRun();
	
	DWORD tNow = GetTickCount();
	
	if ( ! m_bConnected )
	{
		if ( tNow - m_tConnected > Settings.Connection.TimeoutConnect )
		{
			theApp.Message( MSG_ERROR, IDS_BT_CLIENT_CONNECT_TIMEOUT, (LPCTSTR)m_sAddress );
			Close();
			return FALSE;
		}
	}
	else if ( ! m_bOnline )
	{
		if ( tNow - m_tConnected > Settings.Connection.TimeoutHandshake )
		{
			theApp.Message( MSG_ERROR, IDS_BT_CLIENT_HANDSHAKE_TIMEOUT, (LPCTSTR)m_sAddress );
			Close();
			return FALSE;
		}
	}
	else
	{
		if ( tNow - m_mInput.tLast > Settings.BitTorrent.LinkTimeout * 2 )
		{
			theApp.Message( MSG_ERROR, IDS_BT_CLIENT_LOST, (LPCTSTR)m_sAddress );
			Close();
			return FALSE;
		}
		else if ( tNow - m_tLastKeepAlive > /*Settings.BitTorrent.LinkPing*/ 120 * 1000 )
		{
			Send( CBTPacket::New( BT_PACKET_KEEPALIVE ) );
			m_tLastKeepAlive = tNow;
		}
		

		ASSERT ( m_pUpload != NULL );

		if ( m_pDownloadTransfer != NULL && ! m_pDownloadTransfer->OnRun() ) return FALSE;
		if ( m_pUpload == NULL || ! m_pUpload->OnRun() ) return FALSE;
	}
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CBTClient connection establishment event

BOOL CBTClient::OnConnected()
{
	theApp.Message( MSG_DEFAULT, IDS_BT_CLIENT_HANDSHAKING, (LPCTSTR)m_sAddress );
	SendHandshake( TRUE, TRUE );
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CBTClient connection loss event

void CBTClient::OnDropped(BOOL bError)
{
	if ( ! m_bConnected )
		theApp.Message( MSG_ERROR, IDS_BT_CLIENT_DROP_CONNECTING, (LPCTSTR)m_sAddress );
	else if ( ! m_bOnline )
		theApp.Message( MSG_ERROR, IDS_BT_CLIENT_DROP_HANDSHAKE, (LPCTSTR)m_sAddress );
	else
		theApp.Message( MSG_ERROR, IDS_BT_CLIENT_DROP_CONNECTED, (LPCTSTR)m_sAddress );
	   
	Close();
}

//////////////////////////////////////////////////////////////////////
// CBTClient write event

BOOL CBTClient::OnWrite()
{
	CTransfer::OnWrite();
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CBTClient read event

BOOL CBTClient::OnRead()
{
	BOOL bSuccess = TRUE;
	
	CTransfer::OnRead();
	
	if ( m_bOnline )
	{
		CBTPacket* pPacket;
		
		while ( pPacket = CBTPacket::ReadBuffer( m_pInput ) )
		{
			try
			{
				bSuccess = OnPacket( pPacket );
			}
			catch ( CException* pException )
			{
				pException->Delete();
				if ( ! m_bOnline ) bSuccess = FALSE;
			}
			
			pPacket->Release();
			if ( ! bSuccess ) break;
		}
	}
	else
	{
		if ( ! m_bShake && m_pInput->m_nLength >= BT_PROTOCOL_HEADER_LEN + 8 + sizeof(SHA1) )
		{
			bSuccess = OnHandshake1();
		}
		
		if ( bSuccess && m_bShake && m_pInput->m_nLength >= sizeof(SHA1) )
		{
			bSuccess = OnHandshake2();
		}/*
		else if ( bSuccess && m_bShake )
		{
			DWORD tNow = GetTickCount();
			if ( tNow - m_tConnected > Settings.Connection.TimeoutHandshake / 2 )
			{
				theApp.Message( MSG_ERROR,  _T("No peer-id received, forcing connection") );
				bSuccess = OnNoHandshake2();
			}
		}*/
	}
	
	return bSuccess;
}

//////////////////////////////////////////////////////////////////////
// CBTClient handshaking

void CBTClient::SendHandshake(BOOL bPart1, BOOL bPart2)
{
	ASSERT( m_pDownload != NULL );
	
	if ( bPart1 )
	{
		DWORD dwZero = 0;
		m_pOutput->Print( BT_PROTOCOL_HEADER );
		m_pOutput->Add( &dwZero, 4 );
		m_pOutput->Add( &dwZero, 4 );
		m_pOutput->Add( &m_pDownload->m_pBTH, sizeof(SHA1) );
	}
	
	if ( bPart2 )
	{
		m_pOutput->Add( &m_pDownload->m_pPeerID, sizeof(SHA1) );
	}
	
	OnWrite();
}

BOOL CBTClient::OnHandshake1()
{	//First part of the handshake
	ASSERT( ! m_bOnline );
	ASSERT( ! m_bShake );
	
	LPBYTE pIn = m_pInput->m_pBuffer;
	
	// Read in the BT protocol header
	if ( memcmp( pIn, BT_PROTOCOL_HEADER, BT_PROTOCOL_HEADER_LEN ) != 0 )
	{
		ASSERT( FALSE );
		theApp.Message( MSG_ERROR, _T("BitTorrent coupling from %s had invalid header"), (LPCTSTR)m_sAddress );
		Close();
		return FALSE;
	}
	
	pIn += BT_PROTOCOL_HEADER_LEN + 8;
	
	// Read in the file ID
	SHA1 pFileHash = *(SHA1*)pIn;
	pIn += sizeof(SHA1);
	
	m_pInput->Remove( BT_PROTOCOL_HEADER_LEN + 8 + sizeof(SHA1) );
	
	if ( m_bInitiated )		// If we initiated the connection
	{
		ASSERT( m_pDownload != NULL );
		ASSERT( m_pDownloadTransfer != NULL );
		
		if ( pFileHash != m_pDownload->m_pBTH || m_pDownload->IsShared() == FALSE )
		{	//Display and error and exit
			theApp.Message( MSG_ERROR, IDS_BT_CLIENT_WRONG_FILE, (LPCTSTR)m_sAddress );
			Close();
			return FALSE;
		}
		else if ( ! m_pDownload->IsTrying() )
		{	//Display and error and exit
			theApp.Message( MSG_ERROR, IDS_BT_CLIENT_INACTIVE_FILE, (LPCTSTR)m_sAddress );
			Close();
			return FALSE;
		}
	}
	else					// If we didn't initiate the connection
	{
		ASSERT( m_pDownload == NULL );
		ASSERT( m_pDownloadTransfer == NULL );
		
		// Find the requested file
		m_pDownload = Downloads.FindByBTH( &pFileHash, TRUE );
		
		if ( m_pDownload == NULL )				// If we can't find the file
		{	//Display and error and exit
			theApp.Message( MSG_ERROR, IDS_BT_CLIENT_UNKNOWN_FILE, (LPCTSTR)m_sAddress );
			Close();
			return FALSE;
		}
		else if ( ! m_pDownload->IsTrying() )	// If the file isn't active
		{	//Display and error and exit
			m_pDownload = NULL;
			theApp.Message( MSG_ERROR, IDS_BT_CLIENT_INACTIVE_FILE, (LPCTSTR)m_sAddress );
			Close();
			return FALSE;
		}
		else if ( m_pDownload->UploadExists( &m_pHost.sin_addr ) )	// If there is already an upload of this file to this client
		{	// Display and error and exit
			m_pDownload = NULL;
			theApp.Message( MSG_ERROR, IDS_BT_CLIENT_DUPLICATE, (LPCTSTR)m_sAddress );
			Close();
			return FALSE;
		}

		// Check we don't have too many active torrent connections 
		// (Prevent routers overloading for very popular torrents)
		if ( ( m_pDownload->GetTransferCount( dtsCountTorrentAndActive ) ) > ( Settings.BitTorrent.DownloadConnections * 1.25 ) ) 
		{
			theApp.Message( MSG_ERROR, IDS_BT_CLIENT_MAX_CONNECTIONS, (LPCTSTR)m_sAddress );
			Close();
			return FALSE;
		}

	}
	
	// Verify a download and hash
	ASSERT( m_pDownload != NULL );
	ASSERT( m_pDownload->m_pBTH == pFileHash );
	
	// If we didn't start the connection, then send a handshake
	if ( ! m_bInitiated ) SendHandshake( TRUE, TRUE );
	m_bShake = TRUE;
	
	return TRUE;
}

BOOL CBTClient::OnHandshake2()
{	// Second part of the handshake - Peer ID
	m_pGUID = *(SHA1*)m_pInput->m_pBuffer;
	m_pInput->Remove( sizeof(SHA1) );
	
	for ( int nByte = 0 ; nByte < 20 ; nByte++ )
	{
		if ( nByte < 16 )
		{
			if ( m_pGUID.b[ nByte ] ) m_bExtended = TRUE;
		}
		else
		{
			if ( m_pGUID.b[ nByte ]	!= ( m_pGUID.b[ nByte % 16 ] ^ m_pGUID.b[ 15 - ( nByte % 16 ) ] ) )
			{
				m_bExtended = FALSE;
				break;
			}
		}
	}
	
	ASSERT( m_pDownload != NULL );
	
	if ( m_bInitiated )
	{
		ASSERT( m_pDownloadTransfer != NULL );
		CopyMemory( &m_pDownloadTransfer->m_pSource->m_pGUID, &m_pGUID, 16 );
		
		/*

		//ToDo: This seems to trip when it shouldn't. Should be investigated...
		if ( memcmp( &m_pGUID, &m_pDownloadTransfer->m_pSource->m_pGUID, 16 ) != 0 )
		{
			theApp.Message( MSG_ERROR, IDS_BT_CLIENT_WRONG_GUID, (LPCTSTR)m_sAddress );
			Close();
			return FALSE;
		}
		*/
	}
	else 
	{
		if ( m_pDownload->UploadExists( &m_pGUID ) )
		{
			theApp.Message( MSG_ERROR, IDS_BT_CLIENT_DUPLICATE, (LPCTSTR)m_sAddress );
			Close();
			return FALSE;
		}

		if ( ! m_pDownload->IsMoving() && ! m_pDownload->IsPaused() )
		{
			ASSERT( m_pDownloadTransfer == NULL );
			
			// Download from uploaders, unless the user has turned off downloading for this torrent
			if ( m_pDownload->m_nStartTorrentDownloads != dtNever ) 
			{
				// This seems to be set to null sometimes... DownloadwithTorrent: if ( pSource->m_pTransfer != NULL )
				// May just be clients sending duplicate connection requests, though...
				m_pDownloadTransfer = m_pDownload->CreateTorrentTransfer( this );

				if ( m_pDownloadTransfer == NULL )
				{
					m_pDownload = NULL;
					theApp.Message( MSG_ERROR, IDS_BT_CLIENT_UNKNOWN_FILE, (LPCTSTR)m_sAddress );
					Close();
					return FALSE;
				}
			}
		}
	}
	
	ASSERT( m_pUpload == NULL );
	m_pUpload = new CUploadTransferBT( this, m_pDownload );
	
	m_bOnline = TRUE;
	
	DetermineUserAgent();
	if ( m_bExtended ) m_sUserAgent = _T("Shareaza");
	
	return OnOnline();
}
/*
BOOL CBTClient::OnNoHandshake2()
{	// If the other client didn't send a peer ID
	ZeroMemory( m_pGUID.b, 20 );
	
	ASSERT( m_pDownload != NULL );
	
	if ( m_bInitiated )
	{
		ASSERT( m_pDownloadTransfer != NULL );
		CopyMemory( &m_pDownloadTransfer->m_pSource->m_pGUID, &m_pGUID, 16 );
	}
	else if ( ! m_pDownload->IsMoving() && ! m_pDownload->IsPaused() )
	{
		ASSERT( m_pDownloadTransfer == NULL );
		
		m_pDownloadTransfer = m_pDownload->CreateTorrentTransfer( this );
		//This seems to be set to null sometimes... DownloadwithTorrent: if ( pSource->m_pTransfer != NULL )
		if ( m_pDownloadTransfer == NULL )
		{
			m_pDownload = NULL;
			theApp.Message( MSG_ERROR, IDS_BT_CLIENT_UNKNOWN_FILE, (LPCTSTR)m_sAddress );
			Close();
			return FALSE;
		}
	}
	
	ASSERT( m_pUpload == NULL );
	m_pUpload = new CUploadTransferBT( this, m_pDownload );
	
	m_bOnline = TRUE;
	
	if ( ! m_bInitiated ) SendHandshake( FALSE, TRUE );
	
	return OnOnline();
}
*/
//////////////////////////////////////////////////////////////////////
// CBTClient online handler

void CBTClient::DetermineUserAgent()
{
	int nNickStart = 0, nNickEnd = 13;
	CString strVer, strNick;

	if ( m_pGUID.b[0] == '-' && m_pGUID.b[7] == '-' )	
	{	// Azerus style
		if ( m_pGUID.b[1] == 'A' && m_pGUID.b[2] == 'R' )
		{
			m_sUserAgent = _T("Arctic");
		}
		else if ( m_pGUID.b[1] == 'A' && m_pGUID.b[2] == 'Z' )
		{
			m_sUserAgent = _T("Azureus");
		}
		else if ( m_pGUID.b[1] == 'B' && m_pGUID.b[2] == 'B' )
		{
			m_sUserAgent = _T("BitBuddy");
		}
		else if ( m_pGUID.b[1] == 'B' && m_pGUID.b[2] == 'C' )
		{
			m_sUserAgent = _T("BitComet");
		}
		else if ( m_pGUID.b[1] == 'b' && m_pGUID.b[2] == 'k' )
		{
			m_sUserAgent = _T("BitKitten");
		}
		else if ( m_pGUID.b[1] == 'B' && m_pGUID.b[2] == 'O' )
		{
			// ?
			m_sUserAgent = _T("BO");
		}
		else if ( m_pGUID.b[1] == 'B' && m_pGUID.b[2] == 'S' )
		{
			m_sUserAgent = _T("BTSlave");
		}
		else if ( m_pGUID.b[1] == 'B' && m_pGUID.b[2] == 'X' )
		{
			m_sUserAgent = _T("Bittorrent X");
		}
		else if ( m_pGUID.b[1] == 'C' && m_pGUID.b[2] == 'T' )
		{
			m_sUserAgent = _T("CTorrent");
		}
		else if ( ( m_pGUID.b[1] == 'L' && m_pGUID.b[2] == 'T' ) || ( m_pGUID.b[1] == 'l' && m_pGUID.b[2] == 't' ) )
		{
			m_sUserAgent = _T("libtorrent");
		}
		else if ( m_pGUID.b[1] == 'M' && m_pGUID.b[2] == 'P' )
		{
			m_sUserAgent = _T("MooPolice");
		}
		else if ( m_pGUID.b[1] == 'M' && m_pGUID.b[2] == 'T' )
		{
			m_sUserAgent = _T("MoonlightTorrent");
		}
		else if ( m_pGUID.b[1] == 'Q' && m_pGUID.b[2] == 'T' )
		{
			m_sUserAgent = _T("QT4");
		}
		else if ( m_pGUID.b[1] == 'S' && m_pGUID.b[2] == 'B' )
		{
			m_sUserAgent = _T("Swiftbit");
		}
		else if ( m_pGUID.b[1] == 'S' && m_pGUID.b[2] == 'N' )
		{
			m_sUserAgent = _T("ShareNET");
		}
		else if ( m_pGUID.b[1] == 'S' && m_pGUID.b[2] == 'S' )
		{
			m_sUserAgent = _T("Swarmscope");
		}
		else if ( m_pGUID.b[1] == 'S' && m_pGUID.b[2] == '~' )
		{	
			m_sUserAgent = _T("Sbeta");
		}
		else if ( m_pGUID.b[1] == 'S' && m_pGUID.b[2] == 'Z' )
		{	
			//m_sUserAgent = _T("Shareaza");
			// Shareaza versions don't always 'fit' into the BT numbering, so skip that
			m_sUserAgent.Empty();	
		}
		else if ( m_pGUID.b[1] == 'T' && m_pGUID.b[2] == 'N' )
		{
			m_sUserAgent = _T("TorrentDOTnet");
		}
		else if ( m_pGUID.b[1] == 'T' && m_pGUID.b[2] == 'S' )
		{
			m_sUserAgent = _T("Torrentstorm");
		}
		else if ( m_pGUID.b[1] == 'X' && m_pGUID.b[2] == 'T' )
		{
			m_sUserAgent = _T("XanTorrent");
		}
		else if ( m_pGUID.b[1] == 'Z' && m_pGUID.b[2] == 'T' )
		{
			m_sUserAgent = _T("ZipTorrent");
		}
		else // Unknown client using this naming.
		{
			m_sUserAgent.Format( _T("%c%c"), m_pGUID.b[1], m_pGUID.b[2] );
		}
		
		if ( m_sUserAgent.IsEmpty() ) 
		{
			// If we don't want the version, etc.
			m_sUserAgent.Format( _T("BitTorrent (%c%c)"), m_pGUID.b[1], m_pGUID.b[2] );
		}
		else
		{
			// Add the version to the name
			strVer.Format( _T(" %i.%i.%i.%i"),
				( m_pGUID.b[3] - '0' ), ( m_pGUID.b[4] - '0' ),
				( m_pGUID.b[5] - '0' ), ( m_pGUID.b[6] - '0' ) );
			m_sUserAgent += strVer;
		}
	}
	else if ( m_pGUID.b[4] == '-' && m_pGUID.b[5] == '-' && m_pGUID.b[6] == '-' && m_pGUID.b[7] == '-' )
	{	// Shadow style
		switch ( m_pGUID.b[0] )
		{
		case 'A':
			m_sUserAgent = _T("ABC");
			break;
		case 'O':
			m_sUserAgent = _T("Osprey");
			break;
		case 'S':
			m_sUserAgent = _T("Shadow");
			break;
		case 'T':
			m_sUserAgent = _T("BitTornado");
			break;
		case 'U':
			m_sUserAgent = _T("UPnP NAT BT");
			break;
		default: // Unknown client using this naming.
			m_sUserAgent.Format(_T("%c"), m_pGUID.b[0]);
		}
		
		strVer.Format( _T(" %i.%i.%i"),
			( m_pGUID.b[1] - '0' ), ( m_pGUID.b[2] - '0' ),
			( m_pGUID.b[3] - '0' ) );
		m_sUserAgent += strVer;
	}
	else if  ( m_pGUID.b[0] == 'M' && m_pGUID.b[2] == '-' && m_pGUID.b[4] == '-' && m_pGUID.b[6] == '-' )
	{	// BitTorrent (Standard client, newer version)
		m_sUserAgent.Format( _T("BitTorrent %i.%i.%i"), m_pGUID.b[1] - '0' , m_pGUID.b[3] - '0' , m_pGUID.b[5]- '0' );
	}
	else if  ( m_pGUID.b[0] == 'P' && m_pGUID.b[1] == 'l' && m_pGUID.b[2] == 'u' && m_pGUID.b[3] == 's' )
	{	// BitTorrent Plus
		m_sUserAgent.Format( _T("BitTorrent Plus %i.%i%i"), m_pGUID.b[4] - '0', m_pGUID.b[5] - '0', m_pGUID.b[6] - '0' );
	}
	else if  ( m_pGUID.b[0] == 'e' && m_pGUID.b[1] == 'x' && m_pGUID.b[2] == 'b' && m_pGUID.b[3] == 'c' )
	{	
		// BitLord
		if  ( m_pGUID.b[6] == 'L' && m_pGUID.b[7] == 'O' && m_pGUID.b[8] == 'R' && m_pGUID.b[9] == 'D' )
			m_sUserAgent.Format( _T("BitLord %i.%02i"), m_pGUID.b[4], m_pGUID.b[5] );
		// Old BitComet
		else 
			m_sUserAgent.Format( _T("BitComet %i.%02i"), m_pGUID.b[4], m_pGUID.b[5] );
	}
	else if  ( ( m_pGUID.b[0] == 'B' && m_pGUID.b[1] == 'S' ) || ( m_pGUID.b[2] == 'B' && m_pGUID.b[3] == 'S' ) )
	{	// BitSpirit
		m_sUserAgent.Format( _T("BitSpirit") );
	}
	else if  ( m_pGUID.b[0] == 'B' && m_pGUID.b[1] == 'T' && m_pGUID.b[2] == 'M' )
	{	// BTuga Revolution
		m_sUserAgent.Format( _T("BTuga Rv %i.%i"), m_pGUID.b[3] - '0', m_pGUID.b[4] - '0' );
		nNickStart = 5;
	}
	else if  ( ( m_pGUID.b[0] == 'b' && m_pGUID.b[1] == 't' && m_pGUID.b[2] == 'u' && m_pGUID.b[3] == 'g' && m_pGUID.b[4] == 'a' ) || ( m_pGUID.b[0] == 'o' && m_pGUID.b[1] == 'e' && m_pGUID.b[2] == 'r' && m_pGUID.b[3] == 'n' && m_pGUID.b[4] == 'u' ) )
	{	// BTugaXP
		m_sUserAgent.Format( _T("BTugaXP") );
	}
	else if  ( m_pGUID.b[0] == 'M' && m_pGUID.b[1] == 'b' && m_pGUID.b[2] == 'r' && m_pGUID.b[3] == 's' && m_pGUID.b[4] == 't' )
	{	// Burst
		m_sUserAgent.Format( _T("Burst %i.%i.%i"), m_pGUID.b[5] - '0', m_pGUID.b[7] - '0', m_pGUID.b[9] - '0' );
	}
	else if  ( m_pGUID.b[0] == 'e' && m_pGUID.b[1] == 'X' )
	{	// eXeem
		m_sUserAgent.Format( _T("eXeem") );
		nNickStart = 2;
	}
	else if  ( m_pGUID.b[0] == '-' && m_pGUID.b[1] == 'G' && m_pGUID.b[2] == '3' )
	{	// G3 Torrent
		m_sUserAgent.Format( _T("G3 Torrent") );
		nNickStart = 3;
		nNickEnd = 11;
	}
	else if  ( m_pGUID.b[0] == '-' && m_pGUID.b[1] == 'M' && m_pGUID.b[2] == 'L' )
	{	// MLdonkey
		m_sUserAgent.Format( _T("MLdonkey %i.%i.%i"), m_pGUID.b[3] - '0' , m_pGUID.b[5] - '0' , m_pGUID.b[7] - '0' );
	}
	else if  ( m_pGUID.b[0] == 'O' && m_pGUID.b[1] == 'P' )
	{	// Opera
		m_sUserAgent.Format( _T("Opera %i%i%i%i"), m_pGUID.b[2] - '0', m_pGUID.b[3] - '0', m_pGUID.b[4] - '0', m_pGUID.b[5] - '0' );
	}
	else if  ( ( m_pGUID.b[0] == 'a' && m_pGUID.b[1] == '0' && m_pGUID.b[2] == '0' && m_pGUID.b[3] == '-' && m_pGUID.b[4] == '-' && m_pGUID.b[5] == '-' && m_pGUID.b[6] == '0' ) || ( m_pGUID.b[0] == 'a' && m_pGUID.b[1] == '0' && m_pGUID.b[2] == '2' && m_pGUID.b[3] == '-' && m_pGUID.b[4] == '-' && m_pGUID.b[5] == '-' && m_pGUID.b[6] == '0' ) )
	{	// Swarmy
		m_sUserAgent.Format( _T("Swarmy") );
	}
	else if  ( m_pGUID.b[0] == 'X' && m_pGUID.b[1] == 'B' && m_pGUID.b[2] == 'T' )
	{	// XBT
		m_sUserAgent.Format( _T("XBT %i.%i.%i"), m_pGUID.b[3] - '0', m_pGUID.b[4] - '0', m_pGUID.b[5] - '0' );
	}
	else if  ( !m_pGUID.b[0] && !m_pGUID.b[1] && !m_pGUID.b[2] && !m_pGUID.b[3] && !m_pGUID.b[4] && !m_pGUID.b[5] && !m_pGUID.b[6] && !m_pGUID.b[7] && m_pGUID.b[8] && m_pGUID.b[9] && m_pGUID.b[10] && m_pGUID.b[11] && m_pGUID.b[12] && m_pGUID.b[13] && m_pGUID.b[14] && m_pGUID.b[15] && m_pGUID.b[16] == 'U' && m_pGUID.b[17] == 'D' && m_pGUID.b[18] == 'P' && m_pGUID.b[19] == '0' )
	{	// BitSpirit	(Spoofed Client ID)	// GUID 0 - 7: 0	GUID 8 - 15: !0	GUID 16 -19: UDP0	// ToDO: Check that other clients don't use this method
		m_sUserAgent.Format( _T("BitSpirit") );
	}
	else
	{	// Unknown peer ID string
		m_sUserAgent = _T("BitTorrent");
	}

	if ( nNickStart > 0 )
		for ( int i = nNickStart; i <= nNickEnd; i++ )	// Extract nick from m_pGUID.b
		{
			if ( m_pGUID.b[i] == NULL ) break;

			strNick.AppendFormat( _T("%c"), m_pGUID.b[i] );
		}

	if ( m_pDownloadTransfer != NULL )
	{
		m_pDownloadTransfer->m_sUserAgent = m_sUserAgent;
		if ( m_pDownloadTransfer->m_pSource != NULL )
		{
			m_pDownloadTransfer->m_pSource->m_sServer = m_sUserAgent;
			if ( strNick.GetLength() ) m_pDownloadTransfer->m_pSource->m_sNick = strNick;
			m_pDownloadTransfer->m_pSource->m_bClientExtended = ( m_bExtended && ! m_pDownloadTransfer->m_pSource->m_bPushOnly);
		}
	}

	if ( m_pUpload != NULL )
	{
		m_pUpload->m_sUserAgent = m_sUserAgent;
		if ( strNick.GetLength() ) m_pUpload->m_sNick = strNick;
		m_pUpload->m_bClientExtended = m_bExtended;
	}
}

//////////////////////////////////////////////////////////////////////
// CBTClient online handler

BOOL CBTClient::OnOnline()
{
	ASSERT( m_bOnline );
	ASSERT( m_pDownload != NULL );
	ASSERT( m_pUpload != NULL );
	
	theApp.Message( MSG_DEFAULT, IDS_BT_CLIENT_ONLINE, (LPCTSTR)m_sAddress,
		(LPCTSTR)m_pDownload->GetDisplayName() );
	
	if ( m_bExtended ) SendBeHandshake();
	
	if ( CBTPacket* pBitfield = m_pDownload->CreateBitfieldPacket() )
		Send( pBitfield );
	
	if ( m_pDownloadTransfer != NULL && ! m_pDownloadTransfer->OnConnected() ) return FALSE;
	if ( ! m_pUpload->OnConnected() ) return FALSE;
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CBTClient packet switch

BOOL CBTClient::OnPacket(CBTPacket* pPacket)
{
	switch ( pPacket->m_nType )
	{
	case BT_PACKET_KEEPALIVE:
		break;
	case BT_PACKET_CHOKE:
		if ( m_pDownloadTransfer != NULL && ! m_pDownloadTransfer->OnChoked( pPacket ) ) return FALSE;
		m_pDownload->ChokeTorrent();
		break;
	case BT_PACKET_UNCHOKE:
		if ( m_pDownloadTransfer != NULL && ! m_pDownloadTransfer->OnUnchoked( pPacket ) ) return FALSE;
		m_pDownload->ChokeTorrent();
		break;
	case BT_PACKET_INTERESTED:
		if ( ! m_pUpload->OnInterested( pPacket ) ) return FALSE;
		m_pDownload->ChokeTorrent();
		break;
	case BT_PACKET_NOT_INTERESTED:
		if ( ! m_pUpload->OnUninterested( pPacket ) ) return FALSE;
		m_pDownload->ChokeTorrent();
		break;
	case BT_PACKET_HAVE:
		return m_pDownloadTransfer == NULL || m_pDownloadTransfer->OnHave( pPacket );
	case BT_PACKET_BITFIELD:
		return m_pDownloadTransfer == NULL || m_pDownloadTransfer->OnBitfield( pPacket );
	case BT_PACKET_REQUEST:
		return m_pUpload->OnRequest( pPacket );
	case BT_PACKET_PIECE:
		return m_pDownloadTransfer == NULL || m_pDownloadTransfer->OnPiece( pPacket );
	case BT_PACKET_CANCEL:
		return m_pUpload->OnCancel( pPacket );
	
	case BT_PACKET_HANDSHAKE:
		if ( ! m_bExtended ) break;
		return OnBeHandshake( pPacket );
	case BT_PACKET_SOURCE_REQUEST:
		if ( ! m_bExchange ) break;
		return OnSourceRequest( pPacket );
	case BT_PACKET_SOURCE_RESPONSE:
		if ( ! m_bExchange ) break;
		return m_pDownloadTransfer == NULL || m_pDownloadTransfer->OnSourceResponse( pPacket );
	}
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CBTClient advanced handshake

void CBTClient::SendBeHandshake()
{	// Send extended handshake (for G2 capable clients)
	CBENode pRoot;
	
	CString strNick = MyProfile.GetNick().Left( 255 ); // Truncate to 255 characters
	if ( strNick.GetLength() ) pRoot.Add( "nickname" )->SetString( strNick );

	
	pRoot.Add( "source-exchange" )->SetInt( 2 );
	pRoot.Add( "user-agent" )->SetString( Settings.SmartAgent() );
	
	CBuffer pOutput;
	pRoot.Encode( &pOutput );
	
	CBTPacket* pPacket = CBTPacket::New( BT_PACKET_HANDSHAKE );
	pPacket->Write( pOutput.m_pBuffer, pOutput.m_nLength );
	Send( pPacket );
}

BOOL CBTClient::OnBeHandshake(CBTPacket* pPacket)
{	// On extended handshake (for G2 capable clients)
	if ( pPacket->GetRemaining() > 1024 ) return TRUE;
	
	CBuffer pInput;
	pInput.Add( pPacket->m_pBuffer, pPacket->GetRemaining() );
	
	CBENode* pRoot = CBENode::Decode( &pInput );
	if ( pRoot == NULL ) return TRUE;
	
	CBENode* pAgent = pRoot->GetNode( "user-agent" );
	
	if ( pAgent->IsType( CBENode::beString ) )
	{
		m_sUserAgent = pAgent->GetString();
		
		if ( m_pDownloadTransfer != NULL )
		{
			m_pDownloadTransfer->m_sUserAgent = m_sUserAgent;
			if ( m_pDownloadTransfer->m_pSource != NULL )
			{
				m_pDownloadTransfer->m_pSource->m_sServer = m_sUserAgent;
				m_pDownloadTransfer->m_pSource->m_bClientExtended = TRUE;
			}
		}
		
		if ( m_pUpload != NULL ) 
		{
			m_pUpload->m_sUserAgent = m_sUserAgent;
			m_pUpload->m_bClientExtended = TRUE;
		}
	}
	
	CBENode* pNick = pRoot->GetNode( "nickname" );
	
	if ( pNick->IsType( CBENode::beString ) )
	{
		if ( m_pDownloadTransfer != NULL )
		{
			m_pDownloadTransfer->m_pSource->m_sNick = pNick->GetString();
		}
	}
	
	if ( CBENode* pExchange = pRoot->GetNode( "source-exchange" ) )
	{
		if ( pExchange->GetInt() >= 2 )
		{
			m_bExchange = TRUE;
			
			if ( m_pDownloadTransfer != NULL )
				Send( CBTPacket::New( BT_PACKET_SOURCE_REQUEST ) );
		}
	}
	
	delete pRoot;
	
	theApp.Message( MSG_DEFAULT, IDS_BT_CLIENT_EXTENDED, (LPCTSTR)m_sAddress, (LPCTSTR)m_sUserAgent );
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CBTClient source request

BOOL CBTClient::OnSourceRequest(CBTPacket* pPacket)
{
	if ( m_pDownload == NULL ) return TRUE;
	
	CBENode pRoot;
	CBENode* pPeers = pRoot.Add( "peers" );
	
	for ( CDownloadSource* pSource = m_pDownload->GetFirstSource() ; pSource ; pSource = pSource->m_pNext )
	{
		if ( pSource->m_pTransfer == NULL ) continue;
		if ( pSource->m_pTransfer->m_nState < dtsRequesting ) continue;
		
		if ( pSource->m_nProtocol == PROTOCOL_BT )
		{
			CBENode* pPeer = pPeers->Add();
			CSourceURL pURL;
			
			if ( pURL.Parse( pSource->m_sURL ) && pURL.m_bBTC )
			{
				pPeer->Add( "peer id" )->SetString( &pURL.m_pBTC, sizeof(SHA1) );
			}
			
			pPeer->Add( "ip" )->SetString( CString( inet_ntoa( pSource->m_pAddress ) ) );
			pPeer->Add( "port" )->SetInt( pSource->m_nPort );
		}
		else if (	pSource->m_nProtocol == PROTOCOL_HTTP &&
					pSource->m_bReadContent == TRUE &&
					pSource->m_bPushOnly == FALSE )
		{
			CBENode* pPeer = pPeers->Add();
			pPeer->Add( "url" )->SetString( pSource->m_sURL );
		}
	}
	
	if ( pPeers->GetCount() == 0 ) return TRUE;
	
	CBuffer pOutput;
	pRoot.Encode( &pOutput );
	
	CBTPacket* pResponse = CBTPacket::New( BT_PACKET_SOURCE_RESPONSE );
	pResponse->Write( pOutput.m_pBuffer, pOutput.m_nLength );
	Send( pResponse );
	
	return TRUE;
}
