//
// EDClient.cpp
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
#include "Settings.h"
#include "Network.h"
#include "Neighbours.h"
#include "EDNeighbour.h"
#include "EDClient.h"
#include "EDClients.h"
#include "EDPacket.h"
#include "GProfile.h"
#include "HostCache.h"
#include "ED2K.h"

#include "Library.h"
#include "SharedFile.h"
#include "Download.h"
#include "Downloads.h"
#include "DownloadSource.h"
#include "DownloadTransferED2K.h"
#include "UploadTransferED2K.h"
#include "SourceURL.h"

#include "ChatWindows.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif


//////////////////////////////////////////////////////////////////////
// CEDClient construction

CEDClient::CEDClient()
{
	m_pEdPrev		= NULL;
	m_pEdNext		= NULL;
	
	m_bGUID			= FALSE;
	m_pGUID			= (GGUID&)GUID_NULL;
	m_nClientID		= 0;
	m_nUDP			= 0;
	
	// Client ID and version
	m_bEmule		= FALSE;
	m_nEmVersion	= 0;
	m_nEmCompatible	= 0;
	m_nSoftwareVersion=0;

	// Client capabilities
	m_bEmAICH		= FALSE;		// Not supported
	m_bEmUnicode	= FALSE;
	m_bEmUDPVersion	= FALSE;
	m_bEmDeflate	= FALSE;
	m_bEmSecureID	= FALSE;		// Not supported
	m_bEmSources	= FALSE;
	m_bEmRequest	= FALSE;
	m_bEmComments	= FALSE;		// Not supported over ed2k
	m_bEmPeerCache	= FALSE;		// Not supported
	m_bEmBrowse		= FALSE;		// Not supported over ed2k
	m_bEmMultiPacket= FALSE;		// Not supported
	m_bEmPreview	= FALSE;		// Not supported over ed2k
	
	// Misc stuff
	m_bLogin		= FALSE;
	m_bUpMD4		= FALSE;
	
	m_pDownload		= NULL;
	m_pUpload		= NULL;
	m_bSeeking		= FALSE;
	m_nRunExCookie	= 0;
	
	m_mInput.pLimit		= &Settings.Bandwidth.Request;
	m_mOutput.pLimit	= &Settings.Bandwidth.Request;
	
	EDClients.Add( this );
}

CEDClient::~CEDClient()
{
	ASSERT( m_hSocket == INVALID_SOCKET );
	ASSERT( m_pUpload == NULL );
	ASSERT( m_pDownload == NULL );
	
	EDClients.Remove( this );
}

//////////////////////////////////////////////////////////////////////
// CEDClient outbound connection

BOOL CEDClient::ConnectTo(DWORD nClientID, WORD nClientPort, IN_ADDR* pServerAddress, WORD nServerPort, GGUID* pGUID)
{
	ASSERT( m_nClientID == 0 );
	
	m_nClientID = nClientID;
	if ( m_bGUID = ( pGUID != NULL ) ) m_pGUID = *pGUID;
	
	m_pHost.sin_family		= AF_INET;
	m_pHost.sin_addr		= (IN_ADDR&)nClientID;
	m_pHost.sin_port		= htons( nClientPort );
	
	if ( pServerAddress != NULL && nServerPort != 0 )
	{
		m_pServer.sin_family	= AF_INET;
		m_pServer.sin_addr		= *pServerAddress;
		m_pServer.sin_port		= htons( nServerPort );
	}
	else
	{
		ZeroMemory( &m_pServer, sizeof(m_pServer) );
	}
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CEDClient equality

BOOL CEDClient::Equals(CEDClient* pClient)
{
	ASSERT( this != NULL );
	ASSERT( pClient != NULL );
	
	if ( m_bGUID && pClient->m_bGUID ) return m_pGUID == pClient->m_pGUID;
	
	if ( CEDPacket::IsLowID( m_nClientID ) &&
		 CEDPacket::IsLowID( pClient->m_nClientID ) )
	{
		return	( m_pServer.sin_addr.S_un.S_addr == pClient->m_pServer.sin_addr.S_un.S_addr ) &&
				( m_nClientID == pClient->m_nClientID );
	}
	
	return m_pHost.sin_addr.S_un.S_addr == pClient->m_pHost.sin_addr.S_un.S_addr;
}

//////////////////////////////////////////////////////////////////////
// CEDClient connect

BOOL CEDClient::Connect()
{
	if ( m_hSocket != INVALID_SOCKET ) return FALSE;
	if ( EDClients.IsFull( this ) ) return FALSE;
	
	if ( CEDPacket::IsLowID( m_nClientID ) )
	{
		if ( ! Neighbours.PushDonkey( m_nClientID, &m_pServer.sin_addr, htons( m_pServer.sin_port ) ) ) return FALSE;
		m_tConnected = GetTickCount();
	}
	else
	{
		if ( ! CConnection::ConnectTo( &m_pHost ) ) return FALSE;
		theApp.Message( MSG_DEFAULT, IDS_ED2K_CLIENT_CONNECTING, (LPCTSTR)m_sAddress );
	}
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CEDClient remove

void CEDClient::Remove()
{
	ASSERT( this != NULL );
	
	m_bGUID = TRUE;
	Close();
	
	DetachUpload();
	DetachDownload();
	
	Close();
	
	if ( Settings.General.Debug && Settings.General.DebugLog ) theApp.Message( MSG_DEBUG, _T("CEDClient::Remove(): %x"), this );
	
	delete this;
}

//////////////////////////////////////////////////////////////////////
// CEDClient merge

void CEDClient::Merge(CEDClient* pClient)
{
	ASSERT( pClient != NULL );
	
	if ( pClient->m_pDownload != NULL )
	{
		DetachDownload();
		m_pDownload = pClient->m_pDownload;
		m_pDownload->m_pClient = this;
		pClient->m_pDownload = NULL;
	}
	
	if ( pClient->m_pUpload != NULL )
	{
		DetachUpload();
		m_pUpload = pClient->m_pUpload;
		m_pUpload->m_pClient = this;
		pClient->m_pUpload = NULL;
	}
}

//////////////////////////////////////////////////////////////////////
// CEDClient send a packet

void CEDClient::Send(CEDPacket* pPacket, BOOL bRelease)
{
	if ( pPacket != NULL )
	{
		ASSERT( pPacket->m_nProtocol == PROTOCOL_ED2K );
		ASSERT( pPacket->m_nEdProtocol == ED2K_PROTOCOL_EDONKEY || m_bEmule || pPacket->m_nType == ED2K_C2C_EMULEINFO );
		
		if ( m_hSocket != INVALID_SOCKET )
		{
			// pPacket->Debug( _T("CEDClient::Send") );
			pPacket->ToBuffer( m_pOutput );
			OnWrite();
		}
		
		if ( bRelease ) pPacket->Release();
	}
	else if ( m_hSocket != INVALID_SOCKET )
	{
		OnWrite();
	}
}

//////////////////////////////////////////////////////////////////////
// CEDClient attach to existing connection

void CEDClient::AttachTo(CConnection* pConnection)
{
	ASSERT( m_hSocket == INVALID_SOCKET );
	CTransfer::AttachTo( pConnection );
	theApp.Message( MSG_DEFAULT, IDS_ED2K_CLIENT_ACCEPTED, (LPCTSTR)m_sAddress );
}

//////////////////////////////////////////////////////////////////////
// CEDClient close

void CEDClient::Close()
{
	ASSERT( this != NULL );
	CTransfer::Close();
	m_bConnected = m_bLogin = FALSE;
	// if ( ! m_bGUID ) Remove();
}

//////////////////////////////////////////////////////////////////////
// CEDClient transfer coupling

BOOL CEDClient::AttachDownload(CDownloadTransferED2K* pDownload)
{
	if ( m_pDownload != NULL ) return FALSE;
	m_pDownload = pDownload;
	
	if ( m_bLogin )
		return m_pDownload->OnConnected();
	else if ( m_hSocket == INVALID_SOCKET )
		Connect();
	
	return TRUE;
}

void CEDClient::OnDownloadClose()
{
	CDownloadSource* pExcept = m_pDownload ? m_pDownload->m_pSource : NULL;
	m_pDownload = NULL;
	m_mInput.pLimit = &Settings.Bandwidth.Request;
	SeekNewDownload( pExcept );
}

BOOL CEDClient::SeekNewDownload(CDownloadSource* pExcept)
{
	// Removed for a while
	return FALSE;
	
	if ( m_pDownload != NULL ) return FALSE;
	if ( m_bSeeking ) return FALSE;
	m_bSeeking = TRUE;
	BOOL bSeek = Downloads.OnDonkeyCallback( this, pExcept );
	m_bSeeking = FALSE;
	return bSeek;
}

void CEDClient::DetachDownload()
{
	m_bSeeking = TRUE;
	if ( m_pDownload != NULL ) m_pDownload->Close( TS_UNKNOWN );
	ASSERT( m_pDownload == NULL );
	m_bSeeking = FALSE;
}

void CEDClient::OnUploadClose()
{
	m_pUpload = NULL;
	m_mOutput.pLimit = &Settings.Bandwidth.Request;
}

void CEDClient::DetachUpload()
{
	if ( m_pUpload != NULL ) m_pUpload->Close();
	ASSERT( m_pUpload == NULL );
}

//////////////////////////////////////////////////////////////////////
// CEDClient run event

BOOL CEDClient::OnRun()
{
	// CTransfer::OnRun();
	
	DWORD tNow = GetTickCount();
	
	if ( ! m_bConnected )
	{
		if ( tNow - m_tConnected > Settings.Connection.TimeoutConnect )
		{
			theApp.Message( MSG_ERROR, IDS_ED2K_CLIENT_CONNECT_TIMEOUT, (LPCTSTR)m_sAddress );
			NotifyDropped();
			Close();
			return FALSE;
		}
	}
	else if ( ! m_bLogin )
	{
		if ( tNow - m_tConnected > Settings.Connection.TimeoutHandshake )
		{
			theApp.Message( MSG_ERROR, IDS_ED2K_CLIENT_HANDSHAKE_TIMEOUT, (LPCTSTR)m_sAddress );
			NotifyDropped();
			Close();
			return FALSE;
		}
	}
	else
	{
		if ( tNow - m_mInput.tLast > Settings.Connection.TimeoutTraffic &&
			 tNow - m_mOutput.tLast > Settings.Connection.TimeoutTraffic )
		{
			theApp.Message( MSG_DEFAULT, IDS_ED2K_CLIENT_CLOSED, (LPCTSTR)m_sAddress );
			Close();
			return FALSE;
		}
	}
	
	return TRUE;
}

void CEDClient::OnRunEx(DWORD tNow)
{
	if ( m_pDownload != NULL )
	{
		m_pDownload->OnRunEx( tNow );
		if ( m_pUpload != NULL ) m_pUpload->OnRunEx( tNow );
	}
	else if ( m_pUpload != NULL )
	{
		m_pUpload->OnRunEx( tNow );
	}
	else if ( m_hSocket == INVALID_SOCKET )
	{
		Remove();
	}
}

//////////////////////////////////////////////////////////////////////
// CEDClient connection event

BOOL CEDClient::OnConnected()
{
	SendHello( ED2K_C2C_HELLO );
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CEDClient connection loss event

void CEDClient::OnDropped(BOOL bError)
{
	theApp.Message( MSG_ERROR, IDS_ED2K_CLIENT_DROPPED, (LPCTSTR)m_sAddress );
	NotifyDropped( bError );
	Close();
}

void CEDClient::NotifyDropped(BOOL bError)
{
	m_bSeeking = TRUE;
	if ( m_pDownload != NULL ) m_pDownload->OnDropped( bError );
	if ( m_pUpload != NULL ) m_pUpload->OnDropped( bError );
	m_bSeeking = FALSE;
}

//////////////////////////////////////////////////////////////////////
// CEDClient write event

BOOL CEDClient::OnWrite()
{
	CTransfer::OnWrite();
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CEDClient read event

BOOL CEDClient::OnRead()
{
	BOOL bSuccess = TRUE;
	CEDPacket* pPacket;
	
	CTransfer::OnRead();
	
	while ( pPacket = CEDPacket::ReadBuffer( m_pInput, ED2K_PROTOCOL_EMULE ) )
	{
		try
		{
			bSuccess = OnPacket( pPacket );
		}
		catch ( CException* pException )
		{
			pException->Delete();
			if ( ! m_bGUID ) bSuccess = FALSE;
		}
		
		pPacket->Release();
		if ( ! bSuccess ) break;
	}
	
	return bSuccess;
}

//////////////////////////////////////////////////////////////////////
// CEDClient logged in event

BOOL CEDClient::OnLoggedIn()
{
	m_bLogin = TRUE;

	EDClients.Merge( this );

	if ( m_pDownload != NULL )
	{
		m_pDownload->OnConnected();
	}
	else
	{
		SeekNewDownload();
	}
	
	if ( m_pUpload != NULL ) m_pUpload->OnConnected();
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CEDClient packet switch

BOOL CEDClient::OnPacket(CEDPacket* pPacket)
{
	// pPacket->Debug( _T("CEDClient::OnPacket") );
	
	if ( pPacket->m_nEdProtocol == ED2K_PROTOCOL_EDONKEY )
	{
		switch ( pPacket->m_nType )
		{
		// Handshake

		case ED2K_C2C_HELLO:
			if ( pPacket->GetRemaining() ) pPacket->ReadByte();
			return OnHello( pPacket );
		case ED2K_C2C_HELLOANSWER:
			return OnHello( pPacket );
		
		// Upload

		case ED2K_C2C_FILEREQUEST:
			return OnFileRequest( pPacket );
		case ED2K_C2C_FILESTATUSREQUEST:
			return OnFileStatusRequest( pPacket );
		case ED2K_C2C_HASHSETREQUEST:
			return OnHashsetRequest( pPacket );
		case ED2K_C2C_QUEUEREQUEST:
			return OnQueueRequest( pPacket );
		case ED2K_C2C_QUEUERELEASE:
			if ( m_pUpload != NULL ) m_pUpload->OnQueueRelease( pPacket );
			return TRUE;
		case ED2K_C2C_REQUESTPARTS:
			if ( m_pUpload != NULL ) m_pUpload->OnRequestParts( pPacket );
			return TRUE;
		
		// Download
		
		case ED2K_C2C_FILEREQANSWER:
			if ( m_pDownload != NULL ) m_pDownload->OnFileReqAnswer( pPacket );
			return TRUE;
		case ED2K_C2C_FILENOTFOUND:
			if ( m_pDownload != NULL ) m_pDownload->OnFileNotFound( pPacket );
			return TRUE;
		case ED2K_C2C_FILESTATUS:
			if ( m_pDownload != NULL ) m_pDownload->OnFileStatus( pPacket );
			return TRUE;
		case ED2K_C2C_HASHSETANSWER:
			if ( m_pDownload != NULL ) m_pDownload->OnHashsetAnswer( pPacket );
			return TRUE;
		case ED2K_C2C_QUEUERANK:
			if ( m_pDownload != NULL ) m_pDownload->OnQueueRank( pPacket );
			return TRUE;
		case ED2K_C2C_STARTUPLOAD:
			if ( m_pDownload != NULL ) m_pDownload->OnStartUpload( pPacket );
			return TRUE;
		case ED2K_C2C_FINISHUPLOAD:
			if ( m_pDownload != NULL ) m_pDownload->OnFinishUpload( pPacket );
			return TRUE;
		case ED2K_C2C_SENDINGPART:
			if ( m_pDownload != NULL ) m_pDownload->OnSendingPart( pPacket );
			return TRUE;

		// Misc

		case ED2K_C2C_MESSAGE:
			return OnMessage( pPacket );

		}
	}
	else if ( pPacket->m_nEdProtocol == ED2K_PROTOCOL_EMULE )
	{
		switch ( pPacket->m_nType )
		{
		case ED2K_C2C_EMULEINFO:
			return OnEmuleInfo( pPacket );
		case ED2K_C2C_EMULEINFOANSWER:
			return OnEmuleInfo( pPacket );
		
		case ED2K_C2C_REQUESTSOURCES:
			return OnSourceRequest( pPacket );
		case ED2K_C2C_ANSWERSOURCES:
			return OnSourceAnswer( pPacket );
		
		case ED2K_C2C_QUEUERANKING:
			if ( m_pDownload != NULL ) m_pDownload->OnRankingInfo( pPacket );
			return TRUE;
		case ED2K_C2C_COMPRESSEDPART:
			if ( m_pDownload != NULL ) m_pDownload->OnCompressedPart( pPacket );
			return TRUE;

		}
	}
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CEDClient HELLO packet exchange

void CEDClient::SendHello(BYTE nType)
{
	CEDPacket* pPacket = CEDPacket::New( nType );
	
	if ( nType == ED2K_C2C_HELLO ) pPacket->WriteByte( 0x10 );
	
	CEDNeighbour* pServer = Neighbours.GetDonkeyServer();
	
	GGUID pGUID	= MyProfile.GUID;
	pGUID.n[5]	= 14;
	pGUID.n[14]	= 111;
	pPacket->Write( &pGUID, 16 );
	
	pPacket->WriteLongLE( pServer ? pServer->m_nClientID : Network.m_pHost.sin_addr.S_un.S_addr );
	pPacket->WriteShortLE( htons( Network.m_pHost.sin_port ) );
	
	pPacket->WriteLongLE( 5 );	// Number of Tags
	
	// 1 - Nickname
	CString strNick = MyProfile.GetNick();
	
	if ( Settings.eDonkey.TagNames )
	{
		if ( strNick.GetLength() )
			strNick += _T(" (shareaza.com)");
		else
			strNick = _T("www.shareaza.com");
	}
	strNick.Left( 255 );
	
	CEDTag( ED2K_CT_NAME, strNick ).Write( pPacket );

	// 2 - ED2K version
	CEDTag( ED2K_CT_VERSION, ED2K_VERSION ).Write( pPacket );

	// 3 - Software Version. 
	//		Note we're likely to corrupt the beta number, since there's only 3 bits available, 
	//		but it's the least important anyway.
	//		Note: Including this stops the remote client sending the eMuleInfo packet.
	DWORD nVersion =  ( ( ( ED2K_COMPATIBLECLIENT_ID & 0xFF ) << 24 ) | 
							( ( theApp.m_nVersion[1] & 0x7F ) << 17 ) | 
							( ( theApp.m_nVersion[2] & 0x7F ) << 10 ) |
							( ( theApp.m_nVersion[2] & 0x03 ) << 7  ) |
							( ( theApp.m_nVersion[3] & 0x7F )       ) );

	CEDTag( ED2K_CT_SOFTWAREVERSION, nVersion ).Write( pPacket );

	// 4 - Feature Versions. 
	nVersion = ( ( ED2K_VERSION_AICH << 29) | // AICH
				 //( TRUE << 28) | // Unicode
				 ( ED2K_VERSION_UDP << 24) | // UDP version
				 ( ED2K_VERSION_COMPRESSION << 20) | // Compression
			     ( ED2K_VERSION_SECUREID << 16) | // Secure ID
				 ( ED2K_VERSION_SOURCEEXCHANGE << 12) | // Source exchange
				 ( ED2K_VERSION_EXTENDEDREQUEST << 8) | // Extended requests
				 ( ED2K_VERSION_COMMENTS << 4) | // Comments
				 ( FALSE << 3) | // Peer Cache
				 ( TRUE << 2) | // No browse
				 ( FALSE << 1) | // Multipacket
				 ( FALSE ) );// Preview


	CEDTag( ED2K_CT_FEATUREVERSIONS, nVersion ).Write( pPacket );

	// 5 - UDP Port
	CEDTag( ED2K_CT_UDPPORTS, htons( Network.m_pHost.sin_port ) ).Write( pPacket );


//Note: This isn't needed
/*
	// 6 - Port
	CEDTag( ED2K_CT_PORT, htons( Network.m_pHost.sin_port )  ).Write( pPacket );
*/	
	if ( pServer != NULL )
	{
		pPacket->WriteLongLE( pServer->m_pHost.sin_addr.S_un.S_addr );
		pPacket->WriteShortLE( htons( pServer->m_pHost.sin_port ) );
	}
	else
	{
		pPacket->WriteLongLE( 0 );
		pPacket->WriteShortLE( 0 );
	}
	
	Send( pPacket );
}

BOOL CEDClient::OnHello(CEDPacket* pPacket)
{
	if ( m_bLogin ) return TRUE;
	
	if ( pPacket->GetRemaining() < sizeof(GUID) + 6 + 4 + 6 )
	{
		theApp.Message( MSG_ERROR, IDS_ED2K_CLIENT_HANDSHAKE_FAIL, (LPCTSTR)m_sAddress );
		Close();
		return FALSE;
	}
	
	GGUID pGUID;
	pPacket->Read( &pGUID, sizeof(GUID) );
	
	/*
	if ( m_bGUID )
	{
		if ( pGUID != m_pGUID )
		{
			theApp.Message( MSG_ERROR, IDS_ED2K_CLIENT_WRONG_GUID, (LPCTSTR)m_sAddress );
			Close();
			return FALSE;
		}
	}
	*/
	
	m_bGUID				= TRUE;
	m_pGUID				= pGUID;
	m_nClientID			= pPacket->ReadLongLE();
	m_pHost.sin_port	= htons( pPacket->ReadShortLE() );
	
	DWORD nCount = pPacket->ReadLongLE();
	
	while ( nCount-- > 0 && pPacket->GetRemaining() > 0 )
	{
		CEDTag pTag;
		if ( ! pTag.Read( pPacket ) )
		{
			theApp.Message( MSG_ERROR, IDS_ED2K_CLIENT_HANDSHAKE_FAIL, (LPCTSTR)m_sAddress );
			Close();
			return FALSE;
		}
		switch ( pTag.m_nKey )
		{
		case ED2K_CT_NAME:
			if ( pTag.m_nType == ED2K_TAG_STRING ) m_sNick = pTag.m_sValue;
			break;
		case ED2K_CT_PORT:
			if ( pTag.m_nType == ED2K_TAG_INT ) m_pHost.sin_port = htons( (WORD)pTag.m_nValue );
			break;
		case ED2K_CT_VERSION:
			if ( pTag.m_nType == ED2K_TAG_INT ) m_nVersion = pTag.m_nValue;
			break;
		case ED2K_CT_UDPPORTS:
			if ( pTag.m_nType == ED2K_TAG_INT )	m_nUDP = (WORD)(pTag.m_nValue & 0x0000FFFF);
			break;
		case ED2K_CT_FEATUREVERSIONS:
			if ( pTag.m_nType == ED2K_TAG_INT ) 
			{
				m_bEmule = TRUE;
				m_bEmAICH		= (pTag.m_nValue >> 29) & 0x07;
				m_bEmUnicode	= (pTag.m_nValue >> 28) & 0x01;
				m_bEmUDPVersion	= (pTag.m_nValue >> 24) & 0x0F;
				m_bEmDeflate	= (pTag.m_nValue >> 20) & 0x0F;
				m_bEmSecureID	= (pTag.m_nValue >> 16) & 0x0F;
				m_bEmSources	= (pTag.m_nValue >> 12) & 0x0F;
				m_bEmRequest	= (pTag.m_nValue >> 8 ) & 0x0F;
				m_bEmComments	= (pTag.m_nValue >> 4 ) & 0x0F;
				m_bEmPeerCache	= (pTag.m_nValue >> 3 ) & 0x01;
				m_bEmBrowse		=!(pTag.m_nValue >> 2 ) & 0x01;
				m_bEmMultiPacket= (pTag.m_nValue >> 1 ) & 0x01;
				m_bEmPreview	= (pTag.m_nValue) & 0x01;
			}
			break;
		case ED2K_CT_SOFTWAREVERSION:
			if ( pTag.m_nType == ED2K_TAG_INT ) 
			{
				m_bEmule = TRUE;
				m_nSoftwareVersion = pTag.m_nValue & 0x00FFFFFF;
				m_nEmCompatible = pTag.m_nValue >> 24;
			}
			break;
		default:
			theApp.Message( MSG_DEBUG, _T("Unrecognised packet in CEDClient::OnHello") );
		}
	}
	
	if ( pPacket->GetRemaining() < 6 )
	{
		theApp.Message( MSG_ERROR, IDS_ED2K_CLIENT_HANDSHAKE_FAIL, (LPCTSTR)m_sAddress );
		Close();
		return FALSE;
	}
	
	// Read their server IP / port
	m_pServer.sin_addr.S_un.S_addr = pPacket->ReadLongLE();
	m_pServer.sin_port = htons( pPacket->ReadShortLE() );
	
	// If we are learning new servers
	if ( Settings.eDonkey.LearnNewServers && ! Network.IsFirewalledAddress( &m_pServer.sin_addr ) )
	{	// Add their server
		HostCache.eDonkey.Add( &m_pServer.sin_addr, htons( m_pServer.sin_port ) );
	}

	// Get client name/version
	DeriveVersion();
	
	// If this was a hello
	if ( pPacket->m_nType == ED2K_C2C_HELLO )
	{
		// If it's an eMule compatible client that has not already sent us extended details
		if ( ( m_bEmule ) && ( ! m_nSoftwareVersion ) ) 
			SendEmuleInfo( ED2K_C2C_EMULEINFO );	// Send extended hello

		// Send hello answer
		SendHello( ED2K_C2C_HELLOANSWER );
	}
	
	if ( m_bLogin )
		return TRUE;
	else
		return OnLoggedIn();
}

//////////////////////////////////////////////////////////////////////
// CEDClient EMULE INFO packet exchange

void CEDClient::SendEmuleInfo(BYTE nType)
{
	CEDPacket* pPacket = CEDPacket::New( nType, ED2K_PROTOCOL_EMULE );
	
	pPacket->WriteByte( 0x40 );		// eMule version
	pPacket->WriteByte( 0x01 );		// eMule protocol
	
	// Write number of tags
	pPacket->WriteLongLE( Settings.eDonkey.ExtendedRequest ? 6 : 5 );

	// Write tags
	CEDTag( ED2K_ET_COMPATIBLECLIENT, ED2K_COMPATIBLECLIENT_ID ).Write( pPacket );
	CEDTag( ED2K_ET_COMPRESSION, ED2K_VERSION_COMPRESSION ).Write( pPacket );
	CEDTag( ED2K_ET_SOURCEEXCHANGE, ED2K_VERSION_SOURCEEXCHANGE ).Write( pPacket );
	if ( Settings.eDonkey.ExtendedRequest ) CEDTag( ED2K_ET_EXTENDEDREQUEST, ED2K_VERSION_EXTENDEDREQUEST ).Write( pPacket ); //Extended request version 1
	CEDTag( ED2K_ET_UDPVER, ED2K_VERSION_UDP ).Write( pPacket );
	CEDTag( ED2K_ET_UDPPORT, htons( Network.m_pHost.sin_port ) ).Write( pPacket );
//	CEDTag( ED2K_ET_COMMENTS, 1 ).Write( pPacket );	
	Send( pPacket );
}

BOOL CEDClient::OnEmuleInfo(CEDPacket* pPacket)
{
	if ( pPacket->GetRemaining() < 5 )
	{
		theApp.Message( MSG_ERROR, IDS_ED2K_CLIENT_HANDSHAKE_FAIL, (LPCTSTR)m_sAddress );
		Close();
		return FALSE;
	}
	
	m_nEmVersion	= pPacket->ReadByte();
	BYTE nProtocol	= pPacket->ReadByte();
	
	if ( nProtocol != 1 ) return TRUE;
	
	// Have to assume capabilities for these versions
	if ( m_nEmVersion > 0x22 && m_nEmVersion < 0x25 ) m_bEmSources = 1;
	if ( m_nEmVersion == 0x24 ) m_bEmComments = 1;
	
	// Read number of tags
	DWORD nCount = pPacket->ReadLongLE();
	
	while ( nCount-- > 0 && pPacket->GetRemaining() > 0 )
	{
		CEDTag pTag;
		
		// Read tag
		if ( ! pTag.Read( pPacket ) )
		{
			theApp.Message( MSG_ERROR, IDS_ED2K_CLIENT_HANDSHAKE_FAIL, (LPCTSTR)m_sAddress );
			Close();
			return FALSE;
		}
		
		if ( pTag.m_nType != ED2K_TAG_INT ) continue;
		
		switch ( pTag.m_nKey )
		{
		case ED2K_ET_COMPRESSION:
			m_bEmDeflate = pTag.m_nValue;
			break;
		case ED2K_ET_UDPPORT:
			m_nUDP = (WORD)pTag.m_nValue;
			break;
		case ED2K_ET_UDPVER:
			m_bEmUDPVersion = (WORD)pTag.m_nValue;
			break;
		case ED2K_ET_SOURCEEXCHANGE:
			m_bEmSources = pTag.m_nValue;
			break;
		case ED2K_ET_COMMENTS:
			m_bEmComments = pTag.m_nValue;
			break;
		case ED2K_ET_EXTENDEDREQUEST:
			m_bEmRequest = pTag.m_nValue;
			break;
		case ED2K_ET_COMPATIBLECLIENT:
			m_nEmCompatible = pTag.m_nValue;
			break;
		}
	}
	
	m_bEmule = TRUE;

	// Send answer if required
	if ( pPacket->m_nType == ED2K_C2C_EMULEINFO ) SendEmuleInfo( ED2K_C2C_EMULEINFOANSWER );

	// Get client name/version
	DeriveVersion();
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CEDClient client version

void CEDClient::DeriveVersion()
{
	//Newer clients send the 24 bit software version
	if ( m_nSoftwareVersion )
	{
		if ( m_nEmCompatible == 14 )  m_nEmCompatible = 4; //Temp ****************

		// It's eMule compatible
		m_bEmule = TRUE;

		// Determine client from the compatible client byte
		switch ( m_nEmCompatible )
		{
		case 0:
			m_sUserAgent.Format( _T("eMule %i.%i%c"), 
				( ( m_nSoftwareVersion >> 17 ) & 0x7F ), ( ( m_nSoftwareVersion >> 10 ) & 0x7F ), 
				( ( m_nSoftwareVersion >>  7 ) & 0x03 ) + 'a' );
/*
			//This code displays the eMule build number- not currently used
			m_sUserAgent.Format( _T("eMule %i.%i%c (%i)"), 
				( ( m_nSoftwareVersion >> 17 ) & 0x7F ), ( ( m_nSoftwareVersion >> 10 ) & 0x7F ), 
				( ( m_nSoftwareVersion >>  7 ) & 0x03 ) + 'a', ( ( m_nSoftwareVersion ) & 0x7F ) );
*/
			break;
		case 1:
			m_sUserAgent.Format( _T("cDonkey %i.%i%c"), 
				( ( m_nSoftwareVersion >> 17 ) & 0x7F ), ( ( m_nSoftwareVersion >> 10 ) & 0x7F ), 
				( ( m_nSoftwareVersion >>  7 ) & 0x03 ) + 'a' );
			break;
		case 2:
			m_sUserAgent.Format( _T("aMule %i.%i%c"), 
				( ( m_nSoftwareVersion >> 17 ) & 0x7F ), ( ( m_nSoftwareVersion >> 10 ) & 0x7F ), 
				( ( m_nSoftwareVersion >>  7 ) & 0x03 ) + 'a' );
			break;
		case 3:
			m_sUserAgent.Format( _T("xMule %i.%i%c"), 
				( ( m_nSoftwareVersion >> 17 ) & 0x7F ), ( ( m_nSoftwareVersion >> 10 ) & 0x7F ), 
				( ( m_nSoftwareVersion >>  7 ) & 0x03 ) + 'a' );
			break;
		case 4:
			//Note- 2nd last number (Beta build #) may be truncated, since it's only 3 bits.
			m_sUserAgent.Format( _T("Shareaza %i.%i.%i.%i"), 
				( ( m_nSoftwareVersion >> 17 ) &0x7F ), ( ( m_nSoftwareVersion >> 10 ) &0x7F ), 
				( ( m_nSoftwareVersion >>  7 ) &0x03 ), ( ( m_nSoftwareVersion ) &0x7F ) );
			
			//Client allows G2 chat, etc
			if ( m_pUpload ) m_pUpload->m_bClientExtended = TRUE;
			if ( m_pDownload && m_pDownload->m_pSource ) m_pDownload->m_pSource->m_bClientExtended = TRUE;
		case 10:
			m_sUserAgent.Format( _T("MlDonkey") );
			break;
		case 20:
			m_sUserAgent.Format( _T("Lphant %i.%i%c"), 
				( ( m_nSoftwareVersion >> 17 ) & 0x7F ), ( ( m_nSoftwareVersion >> 10 ) & 0x7F ), 
				( ( m_nSoftwareVersion >>  7 ) & 0x03 ) + 'a' );
			break;
		default:
			m_sUserAgent.Format( _T("eMule/c %i.%i%c"), 
				( ( m_nSoftwareVersion >> 17 ) & 0x7F ), ( ( m_nSoftwareVersion >> 10 ) & 0x7F ), 
				( ( m_nSoftwareVersion >>  7 ) & 0x03 ) + 'a' );
			break;
		}
		return;
	}


	//Older style IDs
	if ( m_pGUID.n[5] == 13 && m_pGUID.n[14] == 110 )
	{
		m_bEmule = TRUE;
		m_sUserAgent.Format( _T("eMule v%i"), m_nVersion );
	}
	else if ( m_pGUID.n[5] == 14 && m_pGUID.n[14] == 111 )
	{
		m_bEmule = TRUE;
		m_sUserAgent.Format( _T("eMule v%i"), m_nVersion );
	}
	else if ( m_pGUID.n[5] == 'M' && m_pGUID.n[14] == 'L' )
	{
		m_sUserAgent.Format( _T("mlDonkey v%i"), m_nVersion );
	}
	else
	{
		if ( m_nVersion >= 1000 )
			m_sUserAgent.Format( _T("eDonkey v1.%i"), m_nVersion - 1000 );
		else
			m_sUserAgent.Format( _T("eDonkey v1.%i"), m_nVersion);
	}

	
	if ( m_bEmule && m_nEmVersion > 0 )
	{
		switch ( m_nEmCompatible )
		{
		case 0:
			m_sUserAgent.Format( _T("eMule v0.%i%i"), m_nEmVersion >> 4, m_nEmVersion & 15 );
			break;
		case 1:
			m_sUserAgent.Format( _T("cDonkey v%i.%i"), m_nEmVersion >> 4, m_nEmVersion & 15 );
			break;
		case 2:
			m_sUserAgent.Format( _T("aMule v0.%i%i"), m_nEmVersion >> 4, m_nEmVersion & 15 );
			break;
		case 3:
			m_sUserAgent.Format( _T("xMule v0.%i%i"), m_nEmVersion >> 4, m_nEmVersion & 15 );
			break;
		case 4:
			m_sUserAgent.Format( _T("Shareaza") );
			if ( m_pUpload ) m_pUpload->m_bClientExtended = TRUE;
			if ( m_pDownload && m_pDownload->m_pSource ) m_pDownload->m_pSource->m_bClientExtended = TRUE;
			break;
		case 10:
			m_sUserAgent.Format( _T("MlDonkey v0.%i%i"), m_nEmVersion >> 4, m_nEmVersion & 15 );
			break;
		case 20:
			m_sUserAgent.Format( _T("Lphant v0.%i%i"), m_nEmVersion >> 4, m_nEmVersion & 15 );
			break;
		default:
			m_sUserAgent.Format( _T("eMule/c (%i) v0.%i%i"), m_nEmCompatible, m_nEmVersion >> 4, m_nEmVersion & 15 );
			break;
		}
	}
}

//////////////////////////////////////////////////////////////////////
// CEDClient FILE REQUEST handler

BOOL CEDClient::OnFileRequest(CEDPacket* pPacket)
{
	if ( pPacket->GetRemaining() < sizeof(MD4) )
	{
		theApp.Message( MSG_ERROR, IDS_ED2K_CLIENT_BAD_PACKET, (LPCTSTR)m_sAddress, pPacket->m_nType );
		return TRUE;
	}
	
	CEDPacket* pReply = CEDPacket::New( ED2K_C2C_FILEREQANSWER );
	
	pPacket->Read( &m_pUpMD4, sizeof(MD4) );
	pReply->Write( &m_pUpMD4, sizeof(MD4) );
	m_bUpMD4 = TRUE;
	
	if ( CLibraryFile* pFile = LibraryMaps.LookupFileByED2K( &m_pUpMD4, TRUE, TRUE, TRUE ) )
	{
		pReply->WriteEDString( pFile->m_sName );
		Library.Unlock();
		Send( pReply );
		return TRUE;
	}
	else if ( CDownload* pDownload = Downloads.FindByED2K( &m_pUpMD4, TRUE ) )
	{
		pReply->WriteEDString( pDownload->m_sRemoteName );
		Send( pReply );
		return TRUE;
	}
	
	pReply->m_nType = ED2K_C2C_FILENOTFOUND;
	Send( pReply );
	
	theApp.Message( MSG_ERROR, IDS_UPLOAD_FILENOTFOUND, (LPCTSTR)m_sAddress,
		(LPCTSTR)CED2K::HashToString( &m_pUpMD4, TRUE ) );
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CEDClient file status request

BOOL CEDClient::OnFileStatusRequest(CEDPacket* pPacket)
{
	if ( pPacket->GetRemaining() < sizeof(MD4) )
	{
		theApp.Message( MSG_ERROR, IDS_ED2K_CLIENT_BAD_PACKET, (LPCTSTR)m_sAddress, pPacket->m_nType );
		return TRUE;
	}
	
	CEDPacket* pReply = CEDPacket::New( ED2K_C2C_FILESTATUS );
	
	pPacket->Read( &m_pUpMD4, sizeof(MD4) );
	pReply->Write( &m_pUpMD4, sizeof(MD4) );
	m_bUpMD4 = TRUE;
	
	if ( CLibraryFile* pFile = LibraryMaps.LookupFileByED2K( &m_pUpMD4, TRUE, TRUE, TRUE ) )
	{
		pReply->WriteShortLE( 0 );
		pReply->WriteByte( 0 );
		
		m_nUpSize = pFile->GetSize();
		if ( ! CEDPacket::IsLowID( m_nClientID ) )
			pFile->AddAlternateSource( GetSourceURL() );
		
		Library.Unlock();
		Send( pReply );
		return TRUE;
	}
	else if ( CDownload* pDownload = Downloads.FindByED2K( &m_pUpMD4, TRUE ) )
	{
		WritePartStatus( pReply, pDownload );
		m_nUpSize = pDownload->m_nSize;
		
		pDownload->AddSourceED2K( m_nClientID, htons( m_pHost.sin_port ),
			m_pServer.sin_addr.S_un.S_addr, htons( m_pServer.sin_port ), &m_pGUID );
		
		Send( pReply );
		return TRUE;
	}
	
	m_bUpMD4 = FALSE;
	
	pReply->m_nType = ED2K_C2C_FILENOTFOUND;
	Send( pReply );
	
	theApp.Message( MSG_ERROR, IDS_UPLOAD_FILENOTFOUND, (LPCTSTR)m_sAddress,
		(LPCTSTR)CED2K::HashToString( &m_pUpMD4, TRUE ) );	
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CEDClient hash set request

BOOL CEDClient::OnHashsetRequest(CEDPacket* pPacket)
{
	if ( pPacket->GetRemaining() < sizeof(MD4) )
	{
		theApp.Message( MSG_ERROR, IDS_ED2K_CLIENT_BAD_PACKET, (LPCTSTR)m_sAddress, pPacket->m_nType );
		return TRUE;
	}
	
	MD4 pHash;
	pPacket->Read( &pHash, sizeof(MD4) );
	
	CED2K* pHashset	= NULL;
	BOOL bDelete = FALSE;
	CString strName;
	
	if ( CLibraryFile* pFile = LibraryMaps.LookupFileByED2K( &pHash, TRUE, TRUE, TRUE ) )
	{
		strName		= pFile->m_sName;
		pHashset	= pFile->GetED2K();
		bDelete		= TRUE;
		Library.Unlock();
	}
	else if ( CDownload* pDownload = Downloads.FindByED2K( &pHash, TRUE ) )
	{
		if ( pHashset = pDownload->GetHashset() )
		{
			strName		= pDownload->m_sRemoteName;
			bDelete		= FALSE;
		}
	}
	
	if ( pHashset != NULL )
	{
		CEDPacket* pReply = CEDPacket::New( ED2K_C2C_HASHSETANSWER );
		pReply->Write( &pHash, sizeof(MD4) );
		int nBlocks = pHashset->GetBlockCount();
		if ( nBlocks <= 1 ) nBlocks = 0;
		pReply->WriteShortLE( (WORD)nBlocks );
		pReply->Write( pHashset->GetRawPtr(), sizeof(MD4) * nBlocks );
		if ( bDelete ) delete pHashset;
		Send( pReply );
		
		theApp.Message( MSG_DEFAULT, IDS_ED2K_CLIENT_SENT_HASHSET,
			(LPCTSTR)strName, (LPCTSTR)m_sAddress );	
	}
	else
	{
		CEDPacket* pReply = CEDPacket::New( ED2K_C2C_FILENOTFOUND );
		pReply->Write( &pHash, sizeof(MD4) );
		Send( pReply );
		
		theApp.Message( MSG_ERROR, IDS_UPLOAD_FILENOTFOUND, (LPCTSTR)m_sAddress,
			(LPCTSTR)CED2K::HashToString( &pHash, TRUE ) );	
	}
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CEDClient queue request

BOOL CEDClient::OnQueueRequest(CEDPacket* pPacket)
{
	if ( m_bUpMD4 == FALSE )
	{
		// MESSAGE: File not requested yet
		return TRUE;
	}
	
	if ( m_pUpload != NULL && m_pUpload->m_pED2K != m_pUpMD4 )
		DetachUpload();
	
	if ( m_pUpload == NULL )
		m_pUpload = new CUploadTransferED2K( this );
	
	m_pUpload->Request( &m_pUpMD4 );
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CEDClient Message handler

BOOL CEDClient::OnMessage(CEDPacket* pPacket)
{
	DWORD nMessageLength;
	CString sMessage;

	//Check packet has message length
	if ( pPacket->GetRemaining() < 3 )
	{
		theApp.Message( MSG_ERROR, _T("Empty message packet recieved from %s"), (LPCTSTR)m_sAddress );
		return TRUE;
	}

	//Read message length
	nMessageLength = pPacket->ReadLongLE();

	//Validate message length
	if ( ( nMessageLength < 1 ) || ( nMessageLength > 500 ) || ( nMessageLength != pPacket->GetRemaining() ) )
	{
		theApp.Message( MSG_ERROR, _T("Invalid message packet recieved from %s"), (LPCTSTR)m_sAddress );
		return TRUE;
	}


	//Read in message
	//if ( m_bEmUnicode )
	//	sMessage = pPacket->ReadStringUTF8( nMessageLength );
	//else
		sMessage = pPacket->ReadString( nMessageLength );

	// Check if chat is enabled
	if ( Settings.Community.ChatEnable )
	{	// Chat is enabled- we should open a chat window
/*
		CPrivateChatFrame* pChatWindow;
	
		pChatWindow = ChatWindows.OpenPrivate( &m_pGUID, &m_pHost, CEDPacket::IsLowID( m_nClientID ) );
*/
		theApp.Message( MSG_DEFAULT, _T("Message from %s recieved, opening chat window."), (LPCTSTR)m_sAddress );

		theApp.Message( MSG_DEFAULT, sMessage ); //***temp- open chat window instead
	}
	else
	{	// Disabled- don't open a chat window
		theApp.Message( MSG_DEFAULT, _T("Message from %s:"), (LPCTSTR)m_sAddress );
		theApp.Message( MSG_DEFAULT, sMessage );
	}

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CEDClient source request

BOOL CEDClient::OnSourceRequest(CEDPacket* pPacket)
{
	if ( pPacket->GetRemaining() < sizeof(MD4) )
	{
		theApp.Message( MSG_ERROR, IDS_ED2K_CLIENT_BAD_PACKET, (LPCTSTR)m_sAddress, pPacket->m_nType );
		return TRUE;
	}
	
	MD4 pHash;
	pPacket->Read( &pHash, sizeof(MD4) );
	
	CEDPacket* pReply = CEDPacket::New( ED2K_C2C_ANSWERSOURCES, ED2K_PROTOCOL_EMULE );
	int nCount = 0;
	
	if ( CDownload* pDownload = Downloads.FindByED2K( &pHash, TRUE ))
	{
		for ( CDownloadSource* pSource = pDownload->GetFirstSource() ; pSource ; pSource = pSource->m_pNext )
		{
			if ( pSource->m_nProtocol == PROTOCOL_ED2K && pSource->m_bReadContent )
			{
				pReply->WriteLongLE( pSource->m_pAddress.S_un.S_addr );
				pReply->WriteShortLE( pSource->m_nPort );
				pReply->WriteLongLE( pSource->m_pServerAddress.S_un.S_addr );
				pReply->WriteShortLE( (WORD)pSource->m_nServerPort );
				if ( m_bEmSources >= 2 ) pReply->Write( &pSource->m_pGUID, sizeof(GGUID) );
				nCount++;
			}
		}
	}
	
	if ( pReply->m_nLength > 0 )
	{
		BYTE* pStart = pReply->WriteGetPointer( sizeof(MD4) + 2, 0 );
		CopyMemory( pStart, &pHash, sizeof(MD4) );
		pStart += sizeof(MD4);
		*(WORD*)pStart = nCount;
		Send( pReply, FALSE );
	}
	
	pReply->Release();
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CEDClient source answer

BOOL CEDClient::OnSourceAnswer(CEDPacket* pPacket)
{
	if ( Settings.Library.SourceMesh == FALSE ) return TRUE;
	
	if ( pPacket->GetRemaining() < sizeof(MD4) + 2 )
	{
		theApp.Message( MSG_ERROR, IDS_ED2K_CLIENT_BAD_PACKET, (LPCTSTR)m_sAddress, pPacket->m_nType );
		return TRUE;
	}
	
	MD4 pHash;
	pPacket->Read( &pHash, sizeof(MD4) );
	int nCount = pPacket->ReadShortLE();
	
	if ( pPacket->GetRemaining() < nCount * ( m_bEmSources >= 2 ? 12+16 : 12 ) )
	{
		theApp.Message( MSG_ERROR, IDS_ED2K_CLIENT_BAD_PACKET, (LPCTSTR)m_sAddress, pPacket->m_nType );
		return TRUE;
	}
	
	if ( CDownload* pDownload = Downloads.FindByED2K( &pHash ))
	{
		while ( nCount-- > 0 )
		{
			GGUID pGUID;
			
			DWORD nClientID		= pPacket->ReadLongLE();
			WORD nClientPort	= pPacket->ReadShortLE();
			DWORD nServerIP		= pPacket->ReadLongLE();
			WORD nServerPort	= pPacket->ReadShortLE();
			
			if ( m_bEmSources >= 2 )
			{
				pPacket->Read( &pGUID, sizeof(GGUID) );
				pDownload->AddSourceED2K( nClientID, nClientPort, nServerIP, nServerPort, &pGUID );
			}
			else
			{
				pDownload->AddSourceED2K( nClientID, nClientPort, nServerIP, nServerPort );
			}
		}
	}	
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CEDClient source URL utility

CString CEDClient::GetSourceURL()
{
	ASSERT( m_bGUID );
	ASSERT( m_bUpMD4 );
	
	CString str;

	if ( CEDPacket::IsLowID( m_nClientID ) )
	{
		str.Format( _T("ed2kftp://%lu@%s:%i/%s/%I64i/"),
			m_nClientID,
			(LPCTSTR)CString( inet_ntoa( m_pHost.sin_addr ) ),
			htons( m_pHost.sin_port ),
			(LPCTSTR)CED2K::HashToString( &m_pUpMD4 ), m_nUpSize );
	}
	else
	{
		str.Format( _T("ed2kftp://%s:%lu/%s/%I64i/"),
			(LPCTSTR)CString( inet_ntoa( m_pHost.sin_addr ) ),
			htons( m_pHost.sin_port ),
			(LPCTSTR)CED2K::HashToString( &m_pUpMD4 ), m_nUpSize );
	}
	
	return str;
}

//////////////////////////////////////////////////////////////////////
// CEDClient part status utility

void CEDClient::WritePartStatus(CEDPacket* pPacket, CDownload* pDownload)
{
	QWORD nParts = ( pDownload->m_nSize + ED2K_PART_SIZE - 1 ) / ED2K_PART_SIZE;
	pPacket->WriteShortLE( (WORD)nParts );
	
	if ( pDownload->m_pHashsetBlock != NULL && pDownload->m_nHashsetBlock == nParts )
	{
		for ( QWORD nPart = 0 ; nPart < nParts ; )
		{
			BYTE nByte = 0;
			
			for ( DWORD nBit = 0 ; nBit < 8 && nPart < nParts ; nBit++, nPart++ )
			{
				if ( pDownload->m_pHashsetBlock[ nPart ] == TS_TRUE )
				{
					nByte |= ( 1 << nBit );
				}
			}
			
			pPacket->WriteByte( nByte );
		}
	}
	else
	{
		for ( QWORD nPart = 0 ; nPart < nParts ; )
		{
			BYTE nByte = 0;
			
			for ( DWORD nBit = 0 ; nBit < 8 && nPart < nParts ; nBit++, nPart++ )
			{
				QWORD nOffset = nPart * ED2K_PART_SIZE;
				QWORD nLength = min( ED2K_PART_SIZE, pDownload->m_nSize - nOffset );
				
				if ( pDownload->IsRangeUseful( nOffset, nLength ) == FALSE )
				{
					nByte |= ( 1 << nBit );
				}
			}
			
			pPacket->WriteByte( nByte );
		}
	}
}

//////////////////////////////////////////////////////////////////////
// CEDClient UDP packet handlers

BOOL CEDClient::OnUdpReask(CEDPacket* pPacket)
{
	if ( pPacket->GetRemaining() < sizeof(MD4) ) return FALSE;
	if ( m_bUpMD4 == FALSE || m_pUpload == NULL ) return FALSE;
	
	MD4 pMD4;
	pPacket->Read( &pMD4, sizeof(MD4) );
	if ( pMD4 != m_pUpMD4 ) return FALSE;
	
	return m_pUpload->OnReask();
}

BOOL CEDClient::OnUdpReaskAck(CEDPacket* pPacket)
{
	if ( pPacket->GetRemaining() < 2 ) return FALSE;
	if ( m_pDownload == NULL ) return FALSE;
	
	int nRank = pPacket->ReadShortLE();
	m_pDownload->SetQueueRank( nRank );
	
	return TRUE;
}

BOOL CEDClient::OnUdpQueueFull(CEDPacket* pPacket)
{
	if ( m_pDownload != NULL )
	{
		m_pDownload->m_pSource->m_tAttempt = GetTickCount() + Settings.eDonkey.ReAskTime * 1000;
		m_pDownload->Close( TS_UNKNOWN );
	}
	
	return TRUE;
}

BOOL CEDClient::OnUdpFileNotFound(CEDPacket* pPacket)
{
	if ( m_pDownload != NULL ) m_pDownload->Close( TS_FALSE );
	return TRUE;
}
