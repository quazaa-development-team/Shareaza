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
	m_tLastKeepAlive = GetTickCount();

	
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
	m_tConnected = GetTickCount();
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
		/*else if ( tNow - m_mOutput.tLast > Settings.BitTorrent.LinkPing / 2 && m_pOutput->m_nLength == 0 )
		{
			DWORD dwZero = 0;
			m_pOutput->Add( &dwZero, 4 );			// wtf???
			OnWrite();
		}*/
		else if ( tNow - m_tLastKeepAlive > Settings.BitTorrent.LinkPing )
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

void CBTClient::OnDropped(BOOL /*bError*/)
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
		while ( CBTPacket* pPacket = CBTPacket::ReadBuffer( m_pInput ) )
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
        if ( ! m_bShake && m_pInput->m_nLength >= BT_PROTOCOL_HEADER_LEN + 8 + Hashes::Sha1Hash::byteCount )
		{
			bSuccess = OnHandshake1();
		}
		
		if ( bSuccess && m_bShake && m_pInput->m_nLength >= Hashes::Sha1Hash::byteCount )
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
		m_pOutput->Add( m_pDownload->m_oBTH );
	}
	
	if ( bPart2 )
	{
        m_pOutput->Add( m_pDownload->m_pPeerID );
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
	Hashes::BtHash oFileHash( reinterpret_cast<
			const Hashes::BtHash::RawStorage& >( *pIn ) );
	pIn += Hashes::BtHash::byteCount;
	
	m_pInput->Remove( BT_PROTOCOL_HEADER_LEN + 8 + Hashes::Sha1Hash::byteCount );
	
	if ( m_bInitiated )		// If we initiated the connection
	{
		ASSERT( m_pDownload != NULL );
		ASSERT( m_pDownloadTransfer != NULL );
		
		if ( validAndUnequal( oFileHash, m_pDownload->m_oBTH ) || !m_pDownload->IsShared() )
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
		m_pDownload = Downloads.FindByBTH( oFileHash, TRUE );

		if ( m_pDownload == NULL )				// If we can't find the file
		{	//Display and error and exit
			theApp.Message( MSG_ERROR, IDS_BT_CLIENT_UNKNOWN_FILE, (LPCTSTR)m_sAddress );
			Close();
			return FALSE;
		}
		else if ( ! m_pDownload->IsTrying() && ! m_pDownload->IsSeeding() )	// If the file isn't active
		{	//Display and error and exit
			m_pDownload = NULL;
			theApp.Message( MSG_ERROR, IDS_BT_CLIENT_INACTIVE_FILE, (LPCTSTR)m_sAddress );
			Close();
			return FALSE;
		}
		else if ( m_pDownload->UploadExists( &m_pHost.sin_addr ) )	// If there is already an upload of this file to this client
		{
			// Display and error and exit
			m_pDownload = NULL;
			theApp.Message( MSG_ERROR, IDS_BT_CLIENT_DUPLICATE, (LPCTSTR)m_sAddress );
			Close();
			return FALSE;
		}
		// The file isn't verified yet, close the connection
		else if ( m_pDownload->IsMoving() && !m_pDownload->m_bVerify || 
				  m_pDownload->IsCompleted() && !m_pDownload->m_bVerify )
		{
			theApp.Message( MSG_ERROR, IDS_BT_CLIENT_INACTIVE_FILE, (LPCTSTR)m_sAddress );
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
	ASSERT( validAndEqual( m_pDownload->m_oBTH, oFileHash ) );
	
	// If we didn't start the connection, then send a handshake
	if ( ! m_bInitiated ) SendHandshake( TRUE, TRUE );
	m_bShake = TRUE;
	
	return TRUE;
}

BOOL CBTClient::OnHandshake2()
{	// Second part of the handshake - Peer ID
	m_oGUID = reinterpret_cast< const Hashes::BtGuid::RawStorage& >( *m_pInput->m_pBuffer );
	m_pInput->Remove( Hashes::BtGuid::byteCount );
	
	m_bExtended = isExtendedBtGuid( m_oGUID );
	
	ASSERT( m_pDownload != NULL );
	
	if ( m_bInitiated )
	{
		ASSERT( m_pDownloadTransfer != NULL );
		m_pDownloadTransfer->m_pSource->m_oGUID = transformGuid( m_oGUID );
		
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
		if ( m_pDownload->UploadExists( m_oGUID ) )
		{
			theApp.Message( MSG_ERROR, IDS_BT_CLIENT_DUPLICATE, (LPCTSTR)m_sAddress );
			Close();
			return FALSE;
		}

		if ( ! m_pDownload->IsMoving() && ! m_pDownload->IsPaused() )
		{
			ASSERT( m_pDownloadTransfer == NULL );
			
			// Download from uploaders, unless the user has turned off downloading for this torrent
			if ( m_pDownload->m_pTorrent.m_nStartDownloads != dtNever )
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

//////////////////////////////////////////////////////////////////////
// CBTClient online handler

void CBTClient::DetermineUserAgent()
{
	int nNickStart = 0, nNickEnd = 13;
	CString strVer, strNick;

	if ( m_oGUID[ 0 ] == '-' && m_oGUID[ 7 ] == '-' )	
	{	//Azureus style
		struct azureusStyleEntry
		{
			uchar signature[ 2 ];
			LPCTSTR client;
		};
		static const azureusStyleEntry azureusStyleClients[] =
		{
			{ 'A', 'R', L"Arctic" },
			{ 'A', 'X', L"BitPump" },
			{ 'A', 'Z', L"Azureus" },
			{ 'B', 'B', L"BitBuddy" },
			{ 'B', 'C', L"BitComet" },
			{ 'b', 'k', L"BitKitten" },
			{ 'B', 'O', L"BO" },
			{ 'B', 'R', L"BitRocket" },
			{ 'B', 'S', L"BitSlave" },
			{ 'B', 'X', L"Bittorrent X" },
			{ 'C', 'D', L"Enhanced CTorrent" },
			{ 'C', 'T', L"CTorrent" },
			{ 'K', 'T', L"KTorrent" },
			{ 'L', 'P', L"Lphant" },
			{ 'L', 'T', L"libtorrent" },
			{ 'l', 't', L"rTorrent" },
			{ 'M', 'T', L"MoonlightTorrent" },
			{ 'M', 'P', L"MooPolice" },
			{ 'Q', 'T', L"QT4" },
			{ 'R', 'T', L"Retriever" },
			{ 'S', 'B', L"SwiftBit" },
			{ 'S', 'N', L"ShareNet" },
			{ 'S', 'S', L"Swarmscope" },
		// Shareaza versions don't always 'fit' into the BT numbering, so skip that for now
		//	{ 'S', 'Z', L"Shareaza" },
			{ 'S', '~', L"Sbeta" },
			{ 'T', 'N', L"TorrentDotNET" },
			{ 'T', 'R', L"Transmission" },
			{ 'T', 'S', L"Torrentstorm" },
			{ 'U', 'T', L"\x00B5Torrent" },
			{ 'X', 'T', L"XanTorrent" },
			{ 'Z', 'T', L"ZipTorrent" }
		};
		static const size_t azureusClients = sizeof azureusStyleClients / sizeof azureusStyleEntry;

		m_sUserAgent.Empty();
		for ( size_t i = 0; i < azureusClients; ++i )
		{
			if ( m_oGUID[ 1 ] == azureusStyleClients[ i ].signature[ 0 ]
				&& m_oGUID[ 2 ] == azureusStyleClients[ i ].signature[ 1 ] )
			{
				m_sUserAgent.Format( _T( "%s %i.%i.%i.%i" ), azureusStyleClients[ i ].client,
					( m_oGUID[ 3 ] - '0' ), ( m_oGUID[ 4 ] - '0' ),
					( m_oGUID[ 5 ] - '0' ), ( m_oGUID[ 6 ] - '0' ) );
				break;
			}
		}
		if ( m_sUserAgent.IsEmpty() ) 
		{
			// If we don't want the version, etc.
			m_sUserAgent.Format( _T("BitTorrent (%c%c)"), m_oGUID[1], m_oGUID[2] );
		}
	}
	else if ( m_oGUID[4] == '-' && m_oGUID[5] == '-' && m_oGUID[6] == '-' && m_oGUID[7] == '-' )
	{	// Shadow style
		switch ( m_oGUID[0] )
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
			m_sUserAgent.Format(_T("%c"), m_oGUID[0]);
		}
		
		strVer.Format( _T(" %i.%i.%i"),
			( m_oGUID[1] - '0' ), ( m_oGUID[2] - '0' ),
			( m_oGUID[3] - '0' ) );
		m_sUserAgent += strVer;
	}
	else if  ( m_oGUID[0] == 'M' && m_oGUID[2] == '-' && m_oGUID[4] == '-' && m_oGUID[6] == '-' )
	{	// BitTorrent (Standard client, newer version)
		m_sUserAgent.Format( _T("BitTorrent %i.%i.%i"), m_oGUID[1] - '0' , m_oGUID[3] - '0' , m_oGUID[5]- '0' );
	}
	else if  ( m_oGUID[0] == 'P' && m_oGUID[1] == 'l' && m_oGUID[2] == 'u' && m_oGUID[3] == 's' )
	{	// BitTorrent Plus
		m_sUserAgent.Format( _T("BitTorrent Plus %i.%i%i"), m_oGUID[4] - '0', m_oGUID[5] - '0', m_oGUID[6] - '0' );
	}
	else if  ( m_oGUID[0] == 'e' && m_oGUID[1] == 'x' && m_oGUID[2] == 'b' && m_oGUID[3] == 'c' )
	{	
		// BitLord
		if  ( m_oGUID[6] == 'L' && m_oGUID[7] == 'O' && m_oGUID[8] == 'R' && m_oGUID[9] == 'D' )
			m_sUserAgent.Format( _T("BitLord %i.%02i"), m_oGUID[4], m_oGUID[5] );
		// Old BitComet
		else 
			m_sUserAgent.Format( _T("BitComet %i.%02i"), m_oGUID[4], m_oGUID[5] );
	}
	else if  ( ( m_oGUID[0] == 'B' && m_oGUID[1] == 'S' ) || ( m_oGUID[2] == 'B' && m_oGUID[3] == 'S' ) )
	{	// BitSpirit
		m_sUserAgent.Format( _T("BitSpirit") );
	}
	else if  ( m_oGUID[0] == 'B' && m_oGUID[1] == 'T' && m_oGUID[2] == 'M' )
	{	// BTuga Revolution
		m_sUserAgent.Format( _T("BTuga Rv %i.%i"), m_oGUID[3] - '0', m_oGUID[4] - '0' );
		nNickStart = 5;
	}
	else if  ( ( m_oGUID[0] == 'b' && m_oGUID[1] == 't' && m_oGUID[2] == 'u' && m_oGUID[3] == 'g' && m_oGUID[4] == 'a' ) || ( m_oGUID[0] == 'o' && m_oGUID[1] == 'e' && m_oGUID[2] == 'r' && m_oGUID[3] == 'n' && m_oGUID[4] == 'u' ) )
	{	// BTugaXP
		m_sUserAgent.Format( _T("BTugaXP") );
	}
	else if  ( m_oGUID[0] == 'M' && m_oGUID[1] == 'b' && m_oGUID[2] == 'r' && m_oGUID[3] == 's' && m_oGUID[4] == 't' )
	{	// Burst
		m_sUserAgent.Format( _T("Burst %i.%i.%i"), m_oGUID[5] - '0', m_oGUID[7] - '0', m_oGUID[9] - '0' );
	}
	else if  ( m_oGUID[0] == 'e' && m_oGUID[1] == 'X' )
	{	// eXeem
		m_sUserAgent.Format( _T("eXeem") );
		nNickStart = 2;
	}
	else if  ( m_oGUID[0] == '-' && m_oGUID[1] == 'G' && m_oGUID[2] == '3' )
	{	// G3 Torrent
		m_sUserAgent.Format( _T("G3 Torrent") );
		nNickStart = 3;
		nNickEnd = 11;
	}
	else if  ( m_oGUID[2] == 'R' && m_oGUID[3] == 'S' )
	{	// Rufus
		// The first two bits are version numbers. e.g. 0.6.5 = (0)(6+5) = char(0)char(11)
		// The same with BitMagnet
		m_sUserAgent.Format( _T("Rufus") );
		nNickStart = 4;
		nNickEnd = 12;
	}
	else if  ( m_oGUID[2] == 'B' && m_oGUID[3] == 'M' )
	{	// BitMagnet, the former Rufus
		m_sUserAgent.Format( _T("BitMagnet") );
		nNickStart = 4;
		nNickEnd = 12;
	}
	else if  ( m_oGUID[0] == '-' && m_oGUID[1] == 'M' && m_oGUID[2] == 'L' )
	{	// MLdonkey
		m_sUserAgent.Format( _T("MLdonkey %i.%i.%i"), m_oGUID[3] - '0' , m_oGUID[5] - '0' , m_oGUID[7] - '0' );
	}
	else if  ( m_oGUID[0] == 'O' && m_oGUID[1] == 'P' )
	{	// Opera
		m_sUserAgent.Format( _T("Opera %i%i%i%i"), m_oGUID[2] - '0', m_oGUID[3] - '0', m_oGUID[4] - '0', m_oGUID[5] - '0' );
	}
	else if  ( ( m_oGUID[0] == 'a' && m_oGUID[1] == '0' && m_oGUID[2] == '0' && m_oGUID[3] == '-' && m_oGUID[4] == '-' && m_oGUID[5] == '-' && m_oGUID[6] == '0' ) || ( m_oGUID[0] == 'a' && m_oGUID[1] == '0' && m_oGUID[2] == '2' && m_oGUID[3] == '-' && m_oGUID[4] == '-' && m_oGUID[5] == '-' && m_oGUID[6] == '0' ) )
	{	// Swarmy
		m_sUserAgent.Format( _T("Swarmy") );
	}
	else if  ( m_oGUID[0] == 'X' && m_oGUID[1] == 'B' && m_oGUID[2] == 'T' )
	{	// XBT
		m_sUserAgent.Format( _T("XBT %i.%i.%i"), m_oGUID[3] - '0', m_oGUID[4] - '0', m_oGUID[5] - '0' );
	}
	else if  ( !m_oGUID[0] && !m_oGUID[1] && !m_oGUID[2] && !m_oGUID[3] && !m_oGUID[4] && !m_oGUID[5] && !m_oGUID[6] && !m_oGUID[7] && m_oGUID[8] && m_oGUID[9] && m_oGUID[10] && m_oGUID[11] && m_oGUID[12] && m_oGUID[13] && m_oGUID[14] && m_oGUID[15] && m_oGUID[16] == 'U' && m_oGUID[17] == 'D' && m_oGUID[18] == 'P' && m_oGUID[19] == '0' )
	{	// BitSpirit	(Spoofed Client ID)	// GUID 0 - 7: 0	GUID 8 - 15: !0	GUID 16 -19: UDP0	// ToDO: Check that other clients don't use this method
		m_sUserAgent.Format( _T("BitSpirit") );
	}
	else
	{	// Unknown peer ID string
		m_sUserAgent = _T("BitTorrent");
	}

	if ( nNickStart > 0 )
		for ( int i = nNickStart; i <= nNickEnd; i++ )	// Extract nick from m_oGUID
		{
			if ( m_oGUID[i] == NULL ) break;

			strNick.AppendFormat( _T("%c"), m_oGUID[i] );
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
	if ( Uploads.GetTorrentUploadCount() < Settings.BitTorrent.UploadCount )
	{
		m_pUpload->m_bChoked = FALSE;
		Send( CBTPacket::New( BT_PACKET_UNCHOKE ) );
	}
	
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

	if ( ( m_pDownload ) && ( m_pDownload->m_pTorrent.m_bPrivate ) )
		pRoot.Add( "source-exchange" )->SetInt( 0 );
	else
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
			if ( ( m_pDownload ) && ( m_pDownload->m_pTorrent.m_bPrivate ) )
			{
				m_bExchange = FALSE;
			}
			else
			{
				m_bExchange = TRUE;
				
				if ( m_pDownloadTransfer != NULL )
					Send( CBTPacket::New( BT_PACKET_SOURCE_REQUEST ) );
			}
		}
	}
	
	delete pRoot;
	
	theApp.Message( MSG_DEFAULT, IDS_BT_CLIENT_EXTENDED, (LPCTSTR)m_sAddress, (LPCTSTR)m_sUserAgent );
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CBTClient source request

BOOL CBTClient::OnSourceRequest(CBTPacket* /*pPacket*/)
{
	if ( ( m_pDownload == NULL ) || ( m_pDownload->m_pTorrent.m_bPrivate ) ) return TRUE;
	
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
			
			if ( pURL.Parse( pSource->m_sURL ) && pURL.m_oBTC )
			{
                pPeer->Add( "peer id" )->SetString( pURL.m_oBTC.begin(), Hashes::BtGuid::byteCount );
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
