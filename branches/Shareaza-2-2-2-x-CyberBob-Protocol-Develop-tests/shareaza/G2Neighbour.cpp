//
// G2Neighbour.cpp
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
#include "Network.h"
#include "Security.h"
#include "Statistics.h"
#include "Neighbours.h"
#include "G2Neighbour.h"
#include "G2Packet.h"
#include "G1Packet.h"
#include "Buffer.h"
#include "Handshakes.h"
#include "Datagrams.h"
#include "HostCache.h"
#include "RouteCache.h"
#include "VendorCache.h"
#include "QuerySearch.h"
#include "QueryHit.h"
#include "Library.h"
#include "LocalSearch.h"
#include "SearchManager.h"
#include "QueryHashTable.h"
#include "HubHorizon.h"
#include "GProfile.h"
#include "Uploads.h"
#include "XML.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif


//////////////////////////////////////////////////////////////////////
// CG2Neighbour construction

CG2Neighbour::CG2Neighbour(CNeighbour* pBase) : CNeighbour( PROTOCOL_G2, pBase )
{
	theApp.Message( MSG_DEFAULT, IDS_HANDSHAKE_ONLINE_G2, (LPCTSTR)m_sAddress,
		m_sUserAgent.IsEmpty() ? _T("Unknown") : (LPCTSTR)m_sUserAgent );

	m_nLeafCount	= 0;
	m_nLeafLimit	= 0;
	m_bCachedKeys	= FALSE;

	m_pGUIDCache	= new CRouteCache();
	m_pHubGroup		= new CHubHorizonGroup();

	m_tAdjust		= 0;
	m_tLastPingIn	= 0;
	m_tLastPingOut	= 0;
	m_tLastPacket	= GetTickCount();
	m_tWaitLNI		= m_tLastPacket;
	m_tLastKHL		= m_tLastPacket - Settings.Gnutella2.KHLPeriod + 1000;
	m_tLastHAW		= m_tLastPacket;

	m_nQueryLimiter	= 40;
	m_tQueryTimer	= 0;
	m_bBlacklisted	= FALSE;

	m_tRTT			= 0;
	m_tLastPongIn	= 0;
	m_bBusy			= TRUE;
	m_nPingsSent	= 0;
	m_tBusyTime		= m_tLastPacket;
	m_bHubAble		= FALSE; //add
	m_bFirewall		= FALSE; //add
	m_bRouter		= FALSE; //add
	m_nCPU			= 0; //add
	m_nMEM			= 0; //add
	m_nBandwidthIn	= 0; //add
	m_nBandwidthOut	= 0; //add
	m_nUptime		= 0; //add
	m_nLatitude		= 0; //add
	m_nLongitude	= 0; //add
	m_bSFLCheckFW	= FALSE; // add
	m_bFWCheckSent	= FALSE; // add

	SendStartups();
}

CG2Neighbour::~CG2Neighbour()
{
	delete m_pHubGroup;
	delete m_pGUIDCache;

	for ( POSITION pos = m_pOutbound.GetHeadPosition() ; pos ; )
	{
		CG2Packet* pOutbound = m_pOutbound.GetNext( pos );
		pOutbound->Release();
	}
}

//////////////////////////////////////////////////////////////////////
// CG2Neighbour read and write events

BOOL CG2Neighbour::OnRead()
{
	CNeighbour::OnRead();
	return ProcessPackets();
}

BOOL CG2Neighbour::OnWrite()
{
	CBuffer* pOutput = m_pZOutput ? m_pZOutput : m_pOutput;

	while ( pOutput->m_nLength == 0 && m_nOutbound > 0 )
	{
		CG2Packet* pPacket = m_pOutbound.RemoveHead();
		m_nOutbound--;

		pPacket->ToBuffer( pOutput );
		pPacket->Release();

		CNeighbour::OnWrite();
	}

	CNeighbour::OnWrite();

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CG2Neighbour run event

BOOL CG2Neighbour::OnRun()
{
	if ( ! CNeighbour::OnRun() ) return FALSE;

	DWORD tNow = GetTickCount();

	if ( tNow - m_tLastPongIn > 60 * 1000 /* keepAlive if PONG has been received within 60sec */ && 
		m_tWaitLNI > 0 && tNow - m_tWaitLNI > Settings.Gnutella2.KHLPeriod * 3 )
	{
		Close( IDS_CONNECTION_TIMEOUT_TRAFFIC );
		return FALSE;
	}
	else if ( m_bSFLCheckFW && !m_bFWCheckSent && tNow - m_tLastPingOut >= Settings.Gnutella1.PingRate )
	{
		BOOL bNeedStable = Network.IsListening() && ! Datagrams.IsStable();
		CG2Packet* pPing = CG2Packet::New( G2_PACKET_PING, TRUE );

		if ( bNeedStable )
		{
			pPing->WritePacket( "UDP", 6 );
			pPing->WriteLongLE( Network.m_pHost.sin_addr.S_un.S_addr );
			pPing->WriteShortBE( htons( Network.m_pHost.sin_port ) );
			if ( Network.IsFirewalled() )
			{
				theApp.Message( MSG_DEBUG, _T("Sending a Firewall test request to %s."), m_sAddress );
				pPing->WritePacket( "TFW", 0 );
			}
		}

		Send( pPing );
		m_tLastPingOut = tNow;
		m_nPingsSent++;
		m_bFWCheckSent = TRUE;
	}
	else if ( tNow - m_tLastPingOut >= Settings.Gnutella1.PingRate )
	{
		BOOL bNeedStable = Network.IsListening() && ! Datagrams.IsStable();
		CG2Packet* pPing = CG2Packet::New( G2_PACKET_PING, TRUE );

		if ( bNeedStable )
		{
			pPing->WritePacket( "UDP", 6 );
			pPing->WriteLongLE( Network.m_pHost.sin_addr.S_un.S_addr );
			pPing->WriteShortBE( htons( Network.m_pHost.sin_port ) );
		}

		Send( pPing );
		Datagrams.Send( &m_pHost, CG2Packet::New( G2_PACKET_PING ) );
		m_tLastPingOut = tNow;

		m_nPingsSent++;

		// we are a firewalled leaf and this hub is connected for at least minute
		if ( m_nNodeType == ntHub && Network.IsFirewalled() && ( tNow - m_tConnected ) >= 1 * 60 * 1000 )
		{
			// we have more than one leaf-to-hub connection
			if ( Neighbours.GetCount( PROTOCOL_G2, nrsConnected, ntHub ) > 1 )
			{
				if ( !m_bBusy && ( m_nPingsSent * Settings.Gnutella1.PingRate ) > 1 * 60 * 1000 )
				{
					// no /PO for at least minute, marking as busy
					m_bBusy = TRUE;
					m_tBusyTime = tNow;
					theApp.Message( MSG_DEBUG, _T("Marking hub %s as busy because of lag."), m_sAddress );
				} 

				if ( m_bBusy && ( tNow - m_tBusyTime ) > 3 * 60 * 1000 )
				{
					// this hub is busy for at least 3 minutes, disconnect
					theApp.Message( MSG_DEBUG, _T("Disconnecting from %s because of lag."), m_sAddress );
					Close( IDS_CONNECTION_TIMEOUT_TRAFFIC );
					return FALSE;
				} 
			}
		}

		// Some questions and answers about my patch.

		// Why we're checking for firewalled status above?
		// Because firewalled leaves need better hubs (more network
		// resources) for their searches. 
		// Nodes that are not firewalled do not need as much hub resources
		// as firewalled nodes, so they can stay connected to worse hubs
		// so network resources are used more inteligently.

		// Why we're checking number of leaf-to-hub connections
		// and why this number must be greater than 1?
		// If we have more than 1 leaf-to-hub connection and this hub 
		// is disconnected (due to busy timeout) we are still connected to
		// the network. If we have only one leaf-to-hub connection then
		// this hub is never disconnected due to busy timeout.
	}

	if ( tNow - m_tLastKHL > Settings.Gnutella2.KHLPeriod )
	{
		SendLNI();
		SendKHL();
	}
	else if ( tNow - m_tLastHAW > Settings.Gnutella2.HAWPeriod )
	{
		SendHAW();
	}

	// Update allowed queries based on the node type
	if ( m_nNodeType == ntLeaf )
	{
		if ( ( tNow - m_tQueryTimer ) > ( 5*60*1000 ) )
		{
			if ( m_nQueryLimiter < 60 ) m_nQueryLimiter ++;
			m_tQueryTimer = tNow;
		}
	}
	else
	{
		if ( ( tNow - m_tQueryTimer ) > ( 1000 ) )
		{
			if ( m_nQueryLimiter < 240 ) m_nQueryLimiter += 10;
			m_tQueryTimer = tNow;
		}
	}

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CG2Neighbour send packet

BOOL CG2Neighbour::Send(CPacket* pPacket, BOOL bRelease, BOOL bBuffered)
{
	BOOL bSuccess = FALSE;

	if ( m_nState >= nrsConnected && pPacket->m_nProtocol == PROTOCOL_G2 )
	{
		m_nOutputCount++;
		Statistics.Current.Gnutella2.Outgoing++;

		if ( bBuffered )
		{
			if ( m_nOutbound >= Settings.Gnutella1.PacketBufferSize )
			{
				CG2Packet* pRemove = m_pOutbound.RemoveTail();
				pRemove->Release();
				m_nOutbound--;
				Statistics.Current.Gnutella2.Lost++;
			}

			pPacket->AddRef();
			m_pOutbound.AddHead( static_cast< CG2Packet* >( pPacket ) );
			m_nOutbound++;
		}
		else
		{
			pPacket->ToBuffer( m_pZOutput ? m_pZOutput : m_pOutput );
		}

		QueueRun();

		pPacket->SmartDump( this, NULL, TRUE );

		bSuccess = TRUE;
	}

	if ( bRelease ) pPacket->Release();

	return bSuccess;
}

//////////////////////////////////////////////////////////////////////
// CG2Neighbour startup events

void CG2Neighbour::SendStartups()
{
	CG2Packet* pPing = CG2Packet::New( G2_PACKET_PING, TRUE );

	pPing->WritePacket("VER",0);
	pPing->WritePacket("SFL",0);

	Send( pPing, TRUE, TRUE );
	m_tLastPingOut = GetTickCount();
	if ( m_bShareaza )
		m_nPingsSent++;

	Datagrams.Send( &m_pHost, CG2Packet::New( G2_PACKET_PING ) );

	Send( CG2Packet::New( G2_PACKET_PROFILE_CHALLENGE ), TRUE, TRUE );
}

//////////////////////////////////////////////////////////////////////
// CG2Neighbour packet dispatch

BOOL CG2Neighbour::ProcessPackets()
{
	CBuffer* pInput = m_pZInput ? m_pZInput : m_pInput;

    BOOL bSuccess = TRUE;
	for ( ; bSuccess && pInput->m_nLength ; )
	{
		BYTE nInput = *(pInput->m_pBuffer);

		if ( nInput == 0 )
		{
			pInput->Remove( 1 );
			continue;
		}

		BYTE nLenLen	= ( nInput & 0xC0 ) >> 6;
		BYTE nTypeLen	= ( nInput & 0x38 ) >> 3;
		BYTE nFlags		= ( nInput & 0x07 );

		if ( (DWORD)pInput->m_nLength < (DWORD)nLenLen + nTypeLen + 2 ) break;

		DWORD nLength = 0;

		if ( nFlags & G2_FLAG_BIG_ENDIAN )
		{
			BYTE* pLenIn = pInput->m_pBuffer + 1;

			for ( BYTE nIt = nLenLen ; nIt ; nIt-- )
			{
				nLength <<= 8;
				nLength |= *pLenIn++;
			}
		}
		else
		{
			BYTE* pLenIn	= pInput->m_pBuffer + 1;
			BYTE* pLenOut	= (BYTE*)&nLength;
			for ( BYTE nLenCnt = nLenLen ; nLenCnt-- ; ) *pLenOut++ = *pLenIn++;
		}

		if ( nLength >= Settings.Gnutella1.MaximumPacket )
		{
			Close( IDS_PROTOCOL_TOO_LARGE );
			return FALSE;
		}

		if ( (DWORD)pInput->m_nLength < (DWORD)nLength + nLenLen + nTypeLen + 2 ) break;

		CG2Packet* pPacket = CG2Packet::New( pInput->m_pBuffer );

		try
		{
			bSuccess = OnPacket( pPacket );
		}
		catch ( CException* pException )
		{
			pException->Delete();
			// bSuccess = FALSE;		// SHOULD THIS BE LIKE THIS?
			bSuccess = TRUE;
		}

		pPacket->Release();

		pInput->Remove( nLength + nLenLen + nTypeLen + 2 );
	}

	if ( bSuccess ) return TRUE;

	Close( 0 );
	return FALSE;
}

//////////////////////////////////////////////////////////////////////
// CG2Neighbour packet handler

BOOL CG2Neighbour::OnPacket(CG2Packet* pPacket)
{
	m_nInputCount++;
	m_tLastPacket = GetTickCount();
	Statistics.Current.Gnutella2.Incoming++;

	pPacket->SmartDump( this, NULL, FALSE );

	if ( Network.RoutePacket( pPacket ) ) return TRUE;

	if ( pPacket->IsType( G2_PACKET_PING ) )
	{
		return OnPing( pPacket );
	}
	else if ( pPacket->IsType( G2_PACKET_LNI ) )
	{
		return OnLNI( pPacket );
	}
	else if ( pPacket->IsType( G2_PACKET_KHL ) )
	{
		return OnKHL( pPacket );
	}
	else if ( pPacket->IsType( G2_PACKET_HAW ) )
	{
		return OnHAW( pPacket );
	}
	else if ( pPacket->IsType( G2_PACKET_QUERY ) )
	{
		return OnQuery( pPacket );
	}
	else if ( pPacket->IsType( G2_PACKET_QUERY_WRAP ) )
	{
		//return OnQuery( pPacket );
		theApp.Message( MSG_DEBUG, _T("CG2Neighbour::OnPacket Ignoring wrapped query packet") );
	}
	else if ( pPacket->IsType( G2_PACKET_HIT_WRAP ) )
	{
		return OnCommonHit( pPacket );
	}
	else if ( pPacket->IsType( G2_PACKET_HIT ) )
	{
		return OnCommonHit( pPacket );
	}
	else if ( pPacket->IsType( G2_PACKET_QUERY_ACK ) )
	{
		return OnQueryAck( pPacket );
	}
	else if ( pPacket->IsType( G2_PACKET_QUERY_KEY_REQ ) )
	{
		return OnQueryKeyReq( pPacket );
	}
	else if ( pPacket->IsType( G2_PACKET_QUERY_KEY_ANS ) )
	{
		return OnQueryKeyAns( pPacket );
	}
	else if ( pPacket->IsType( G2_PACKET_QHT ) )
	{
		return OnCommonQueryHash( pPacket );
	}
	else if ( pPacket->IsType( G2_PACKET_PUSH ) )
	{
		return OnPush( pPacket );
	}
	else if ( pPacket->IsType( G2_PACKET_PROFILE_CHALLENGE ) )
	{
		return OnProfileChallenge( pPacket );
	}
	else if ( pPacket->IsType( G2_PACKET_PROFILE_DELIVERY ) )
	{
		return OnProfileDelivery( pPacket );
	}
	else if ( pPacket->IsType( G2_PACKET_PONG ) )
	{
		return OnPong( pPacket );
	}
	else if ( pPacket->IsType( G2_PACKET_MODE_CHANGE_REQ ) ) //add G2/1.1
	{
		return OnModeChangeReq( pPacket );
	}
	else if ( pPacket->IsType( G2_PACKET_MODE_CHANGE_ACK ) ) //add G2/1.1
	{
		return OnModeChangeAck( pPacket );
	}
	else if ( pPacket->IsType( G2_PACKET_PRIVATE_MESSAGE ) ) //add G2/1.1
	{
		return OnPrivateMessage( pPacket );
	}
	else if ( pPacket->IsType( G2_PACKET_CLOSE ) ) //add G2/1.1
	{
		return OnClose( pPacket );
	}

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CG2Neighbour PING packet handler

BOOL CG2Neighbour::OnPing(CG2Packet* pPacket)
{

	CString sVendorCode, sName, sVersion;

	BOOL bRelay = FALSE;
	BOOL bVersion = FALSE;
	BOOL bTestFirewall = FALSE;
	BOOL bConnectRequest = FALSE; //add
	BOOL bHubMode = FALSE; //add
	BOOL bSupportedFeature = FALSE; // add
	DWORD nIdent = 0; //add
	DWORD nAddress = 0;
	WORD nPort = 0;
	CHAR szType[9];
	DWORD nLength;


	if ( ! pPacket->m_bCompound )
	{
		Statistics.Current.Gnutella2.PingsReceived++;
		CG2Packet* pPong = CG2Packet::New( G2_PACKET_PONG, FALSE );
		Send( pPong );
		Statistics.Current.Gnutella2.PongsSent++;
		return TRUE;
	}

	CG2Packet* pPong = CG2Packet::New( G2_PACKET_PONG, TRUE );
	while ( pPacket->ReadPacket( szType, nLength ) )
	{
		DWORD nNext = pPacket->m_nPosition + nLength;

		if ( strcmp( szType, "UDP" ) == 0 && nLength >= 6 )
		{
			nAddress	= pPacket->ReadLongLE();
			nPort		= pPacket->ReadShortBE();
		}
		else if ( strcmp( szType, "VER" ) == 0 )
		{
			bVersion = TRUE;
		}
		else if ( strcmp( szType, "RELAY" ) == 0 )
		{
			bRelay = TRUE;
		}
		else if ( strcmp( szType, "IDENT" ) == 0 && nLength >= 4 ) //add G2/1.1
		{
			nIdent = pPacket->ReadLongBE();
		}
		else if ( strcmp( szType, "TFW" ) == 0 ) //add G2/1.1
		{
			bTestFirewall = TRUE;
		}
		else if ( strcmp( szType, "CR" ) == 0 && nLength >= 1 ) //add G2/1.1
		{
			bHubMode = pPacket->ReadByte();
			bConnectRequest = TRUE;
		}
		else if ( strcmp( szType, "SFL" ) == 0 ) // Supported Feature List
		{
			bSupportedFeature = TRUE;
		}

		pPacket->m_nPosition = nNext;
	}

	if ( !bRelay && nAddress == 0 && nPort == 0 )
	{
		if (bVersion)
		{
			sVendorCode = VENDOR_CODE;
			sName = CLIENT_NAME;
			sVersion = theApp.m_sVersion;

			pPong->WritePacket( "VC", pPong->GetStringLenUTF8( sVendorCode ) );
			pPong->WriteStringUTF8( sVendorCode, TRUE );
			pPong->WritePacket( "AN", pPong->GetStringLenUTF8( sName ) );
			pPong->WriteStringUTF8( sName, TRUE );
			pPong->WritePacket( "AV", pPong->GetStringLenUTF8( sVersion ) );
			pPong->WriteStringUTF8( sVersion, TRUE );
		}

		if ( bSupportedFeature )
		{
			// Format of Supported Feature list is feature name feature name followed by 2Byte feature versions
			// first byte is Major version, and second is Miner version.
			CG2Packet * pSFL = CG2Packet::New( "SFL", TRUE );

			// indicate G2/1.0
			pSFL->WritePacket( "G2",2 );
			pSFL->WriteByte(1);
			pSFL->WriteByte(0);

			// indicate TFW/1.0 (TestFireWall)
			pSFL->WritePacket( "TFW",2 );
			pSFL->WriteByte(1);
			pSFL->WriteByte(0);

			// indicate UDPKHL/1.0
			pSFL->WritePacket( "UDPKHL",2 );
			pSFL->WriteByte(1);
			pSFL->WriteByte(0);

			// adding SFL packet as compound packet in PONG
			pPong->WritePacket( pSFL );
			pSFL->Release();
		}

		Statistics.Current.Gnutella2.PingsReceived++;
		Send( pPong );
		Statistics.Current.Gnutella2.PongsSent++;
	}

	if ( ! nPort || Network.IsFirewalledAddress( &nAddress ) ) return TRUE;

	if ( bRelay && nAddress != 0 && nPort != 0 )
	{
		pPong = CG2Packet::New( G2_PACKET_PONG, TRUE );
		pPong->WritePacket( "RELAY", 0 );
		
		if (bVersion){
			pPong->WritePacket( "VC", pPong->GetStringLenUTF8( sVendorCode ) );
			pPong->WriteStringUTF8( sVendorCode, TRUE );
			pPong->WritePacket( "AN", pPong->GetStringLenUTF8( sName ) );
			pPong->WriteStringUTF8( sName, TRUE );
			pPong->WritePacket( "AV", pPong->GetStringLenUTF8( sVersion ) );
			pPong->WriteStringUTF8( sVersion, TRUE );
		}

		if ( bSupportedFeature )
		{
			// Format of Supported Feature list is feature name feature name followed by 2Byte feature versions
			// first byte is Major version, and second is Miner version.
			CG2Packet * pSFL = CG2Packet::New( "SFL", TRUE );

			// indicate G2/1.0
			pSFL->WritePacket( "G2",2 );
			pSFL->WriteByte(1);
			pSFL->WriteByte(0);

			// indicate TFW/1.0 (TestFireWall)
			pSFL->WritePacket( "TFW",2 );
			pSFL->WriteByte(1);
			pSFL->WriteByte(0);

			// indicate UDPKHL/1.0
			pSFL->WritePacket( "UDPKHL",2 );
			pSFL->WriteByte(1);
			pSFL->WriteByte(0);

			// adding SFL packet as conpound packet in PONG
			pPong->WritePacket( pSFL );
			pSFL->Release();
		}

		Statistics.Current.Gnutella2.PingsReceived++;
		Datagrams.Send( (IN_ADDR*)&nAddress, nPort, pPong );
		Statistics.Current.Gnutella2.PongsSent++;
		if ( bTestFirewall ) Network.TestRemoteFirewall ( nAddress, nPort );
	}
	else
	{
		Statistics.Current.Gnutella2.PingsReceived++;

		DWORD tNow = GetTickCount();
		if ( tNow - m_tLastPingIn < Settings.Gnutella1.PingFlood ) return TRUE;
		m_tLastPingIn = tNow;

		BYTE* pRelay = pPacket->WriteGetPointer( 7, 0 );

		if ( pRelay == NULL )
		{
			theApp.Message( MSG_ERROR, _T("Memory allocation error in CG2Neighbour::OnPing()") );
			return TRUE;
		}

		*pRelay++ = 0x60;
		*pRelay++ = 0;
		*pRelay++ = 'R'; *pRelay++ = 'E'; *pRelay++ = 'L';
		*pRelay++ = 'A'; *pRelay++ = 'Y';

		CArray< CG2Neighbour* > pG2Nodes;

		for ( POSITION pos = Neighbours.GetIterator() ; pos ; )
		{
			CNeighbour* pNeighbour = Neighbours.GetNext( pos );

			if (	pNeighbour->m_nState == nrsConnected &&
					pNeighbour->m_nProtocol == PROTOCOL_G2 &&
					pNeighbour != this)
			{
				pG2Nodes.Add( static_cast< CG2Neighbour* >( pNeighbour ) );
 			}
		}

		int nRelayTo = Settings.Gnutella2.PingRelayLimit;

		INT_PTR nCount = pG2Nodes.GetCount();

		for ( INT_PTR nCur = 0; (nCur < nCount && nCur < nRelayTo); nCur++ )
		{
			INT_PTR nRand = rand() % pG2Nodes.GetCount();

			CG2Neighbour* pNeighbour = pG2Nodes.GetAt( nRand );
			// Remove this debug message later
			theApp.Message( MSG_DEBUG, _T("Ping Relay iteration %i picked random index %i as %s"),
			nCur, nRand, (LPCTSTR)pNeighbour->m_sAddress  );

			pNeighbour->Send( pPacket, FALSE );
			Statistics.Current.Gnutella2.PingsSent++;
			if ( m_bShareaza ) pNeighbour->m_nPingsSent++; //add
			pG2Nodes.RemoveAt( nRand );
		}
	}

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CG2Neighbour PONG packet handler

BOOL CG2Neighbour::OnPong( CG2Packet* pPacket )
{
	DWORD tNow = GetTickCount();
	CString sVendorCode, sName, sVersion;

	if ( ! pPacket->m_bCompound )
	{
		CHAR szType[9];
		DWORD nLength;
		BOOL bCompound;

		while ( pPacket->ReadPacket( szType, nLength, &bCompound ) )
		{
			DWORD nOffset = pPacket->m_nPosition + nLength;

			if ( strcmp( szType, "VC" ) == 0 && nLength >= 4 )	// Vendor Code of Remote Node  (e.g. "RAZA")
			{
				sVendorCode = pPacket->ReadStringUTF8(nLength);
			}
			else if ( strcmp( szType, "AN" ) == 0 && nLength >= 2 )	// Agent name of Remote Node (e.g. "Shareaza")
			{
				sName = pPacket->ReadStringUTF8(nLength);
			}
			else if ( strcmp( szType, "AV" ) == 0 && nLength >= 2 )	// Agent version of Remote Node (e.g. 2.2.2.20)
			{
				sVersion = pPacket->ReadStringUTF8(nLength);
			}
			else if ( strcmp( szType, "SFL" ) == 0 && bCompound == TRUE )	// Agent version of Remote Node (e.g. 2.2.2.20)
			{
				CHAR szInner[9];
				DWORD nInner;

				while ( pPacket->m_nPosition < nOffset && pPacket->ReadPacket( szInner, nInner ) )
				{
					DWORD nSkipInner = pPacket->m_nPosition + nInner;

					if ( strcmp( szInner, "G2" ) == 0 && nInner >= 2 )
					{
						// G2 = TRUE
						// G2Version = pPacket->ReadByte() << 8;
						// G2Version = pPacket->ReadByte();
					}
					else if ( strcmp( szInner, "TFW" ) == 0 && nInner >= 2 )
					{
						// TFW = TRUE
						// TFWVersion = pPacket->ReadByte() << 8;
						// TFWVersion = pPacket->ReadByte();
					}
					else if ( strcmp( szInner, "UDPKHL" ) == 0 && nInner >= 2 )
					{
						// UDPKHL = TRUE
						// UDPKHLVersion = pPacket->ReadByte() << 8;
						// UDPKHLVersion = pPacket->ReadByte();
					}

					pPacket->m_nPosition = nSkipInner;
				}
			}
			pPacket->m_nPosition = nOffset;
		}
	}

	m_tLastPongIn = tNow;

	m_nPingsSent--;
	
	if ( m_nPingsSent < 0 )
		m_nPingsSent = 0;

	if ( m_nPingsSent > 0 )
		theApp.Message( MSG_DEBUG, _T("Received PONG from %s. Pings remaining: %d."), m_sAddress, m_nPingsSent );
	else
	{
		m_tRTT = m_tLastPongIn - m_tLastPingOut;
		if ( m_tRTT <= ( 15 * 1000 ) ) // 15 sec
			m_bBusy = FALSE;
		theApp.Message( MSG_DEBUG, _T("Received PONG from %s. RTT: %d."), m_sAddress, m_tRTT );
	}
	if ( sVendorCode.GetLength() >= 1 )
		theApp.Message( MSG_SYSTEM, _T("Received PONG contained VenderCode: %s"), sVendorCode);
	if ( sName.GetLength() >= 1 )
		theApp.Message( MSG_SYSTEM, _T("Received PONG contained AgentName: %s"), sName);
	if ( sVersion.GetLength() >= 1 )
		theApp.Message( MSG_SYSTEM, _T("Received PONG contained AgentVersion: %s"), sVersion);

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CG2Neighbour LOCAL NODE INFO : send

void CG2Neighbour::SendLNI()
{
	CG2Packet* pPacket = CG2Packet::New( G2_PACKET_LNI, TRUE );

	QWORD nMyVolume = 0;
	DWORD nMyFiles = 0;
	LibraryMaps.GetStatistics( &nMyFiles, &nMyVolume );

	WORD nLeafs = 0;

	for ( POSITION pos = Neighbours.GetIterator() ; pos ; )
	{
		CNeighbour* pNeighbour = Neighbours.GetNext( pos );

		if (	pNeighbour != this &&
				pNeighbour->m_nState == nrsConnected &&
				pNeighbour->m_nNodeType == ntLeaf )
		{
			nMyFiles += pNeighbour->m_nFileCount;
			nMyVolume += pNeighbour->m_nFileVolume;
			nLeafs++;
		}
	}

	pPacket->WritePacket( "NA", 6 );
	pPacket->WriteLongLE( Network.m_pHost.sin_addr.S_un.S_addr );
	pPacket->WriteShortBE( htons( Network.m_pHost.sin_port ) );

	pPacket->WritePacket( "GU", 16 );
	pPacket->Write( Hashes::Guid( MyProfile.oGUID ) );

	pPacket->WritePacket( "V", 4 );
	pPacket->WriteString( SHAREAZA_VENDOR_A, FALSE );

	pPacket->WritePacket( "LS", 8 );
	pPacket->WriteLongBE( (DWORD)nMyFiles );
	pPacket->WriteLongBE( (DWORD)nMyVolume );

	if ( ! Neighbours.IsG2Leaf() )
	{
		pPacket->WritePacket( "HS", 4 );
		pPacket->WriteShortBE( nLeafs );
		pPacket->WriteShortBE( WORD( Settings.Gnutella2.NumLeafs ) );

		pPacket->WritePacket( "QK", 0 );
	}

	if ( Settings.Gnutella2.ClientMode == MODE_AUTO ) //add
	{
		pPacket->WritePacket( "HA", 0 );
	}

	if ( Network.IsFirewalled() ) //add
	{
		pPacket->WritePacket( "FW", 0 );
	}

	pPacket->WritePacket( "NBW", 8 ); //add
	pPacket->WriteLongBE( Settings.Bandwidth.Downloads );
	pPacket->WriteLongBE( Settings.Bandwidth.Uploads );

	pPacket->WritePacket( "UP", 4 ); //add
	pPacket->WriteLongBE( Network.GetStableTime() );

	DWORD nGPS = MyProfile.GetPackedGPS();

	if ( nGPS )
	{
		pPacket->WritePacket( "GPS", 4 ); //add
		pPacket->WriteLongBE( nGPS );
	}

	Send( pPacket, TRUE, FALSE );
}

//////////////////////////////////////////////////////////////////////
// CG2Neighbour LOCAL NODE INFO : receive

BOOL CG2Neighbour::OnLNI(CG2Packet* pPacket)
{
	if ( ! pPacket->m_bCompound ) return TRUE;

//	DWORD tNow = time( NULL );
	CHAR szType[9];
	DWORD nLength;

	m_nLeafCount = 0;

	while ( pPacket->ReadPacket( szType, nLength ) )
	{
		DWORD nNext = pPacket->m_nPosition + nLength;

		if ( strcmp( szType, "NA" ) == 0 && nLength >= 6 )
		{
			m_pHost.sin_addr.S_un.S_addr = pPacket->ReadLongLE();
			m_pHost.sin_port = htons( pPacket->ReadShortBE() );
		}
		else if ( strcmp( szType, "GU" ) == 0 && nLength >= 16 )
		{
			pPacket->Read( m_oGUID );
		}
		else if ( strcmp( szType, "V" ) == 0 && nLength >= 4 )
		{
			CHAR szVendor[5] = { 0, 0, 0, 0, 0 };
			pPacket->Read( szVendor, 4 );
			CVendor * pVendor;

			pVendor = VendorCache.Lookup( szVendor );

			if ( m_pVendor == NULL )
			{
				m_pVendor = pVendor;
			}
			else
			{
				m_pVendor->m_bAuto = pVendor->m_bAuto;
				m_pVendor->m_bChatFlag = pVendor->m_bChatFlag;
				m_pVendor->m_bHTMLBrowse = pVendor->m_bHTMLBrowse;
				m_pVendor->m_sCode = pVendor->m_sCode;
				m_pVendor->m_sLink = pVendor->m_sLink;
				m_pVendor->m_sName = pVendor->m_sName;
			}
		}
		else if ( strcmp( szType, "LS" ) == 0 && nLength >= 8 )
		{
			m_nFileCount	= pPacket->ReadLongBE();
			m_nFileVolume	= pPacket->ReadLongBE();
		}
		else if ( strcmp( szType, "HS" ) == 0 && nLength >= 2 )
		{
			m_nLeafCount = pPacket->ReadShortBE();
			m_nLeafLimit = pPacket->ReadShortBE();
		}
		else if ( strcmp( szType, "QK" ) == 0 )
		{
			m_bCachedKeys = TRUE;
		}
		else if ( strcmp( szType, "HA" ) == 0 ) //add G2/1.1
		{
			m_bHubAble = TRUE;
		}
		else if ( strcmp( szType, "FW" ) == 0 ) //add G2/1.1
		{
			m_bFirewall = TRUE;
		}
		else if ( strcmp( szType, "RTR" ) == 0 ) //add G2/1.1
		{
			m_bRouter = TRUE;
		}
		else if ( strcmp( szType, "CM" ) == 0 && nLength >= 2 ) //add G2/1.1
		{
			m_nCPU = pPacket->ReadShortBE();
			m_nMEM = pPacket->ReadShortBE();
		}
		else if ( strcmp( szType, "NBW" ) == 0 && nLength >= 8) //add G2/1.1
		{
			m_nBandwidthIn = pPacket->ReadLongBE();	
			m_nBandwidthOut = pPacket->ReadLongBE();
		}
		else if ( strcmp( szType, "UP" ) == 0 && nLength >= 4 ) //add G2/1.1
		{
			m_nUptime = pPacket->ReadLongBE();
		}
		else if ( strcmp( szType, "GPS" ) == 0 && nLength >= 4 ) //add G2/1.1
		{
			DWORD nGPS = pPacket->ReadLongBE();
			m_nLatitude	 = (float)HIWORD( nGPS ) / 65535.0f * 180.0f - 90.0f;
			m_nLongitude = (float)LOWORD( nGPS ) / 65535.0f * 360.0f - 180.0f;
		}

		pPacket->m_nPosition = nNext;
	}

	if ( ! Network.IsFirewalledAddress( &m_pHost.sin_addr, TRUE ) &&
		   m_pVendor != NULL && m_nNodeType != ntLeaf )
	{
		HostCache.Gnutella2.Add( &m_pHost.sin_addr, htons( m_pHost.sin_port ),
			0, m_pVendor->m_sCode );
	}

	m_tWaitLNI = 0;

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CG2Neighbour KNOWN HUB LIST : send

void CG2Neighbour::SendKHL()
{
	CG2Packet* pPacket = CG2Packet::New( G2_PACKET_KHL, TRUE );

//	DWORD nBase = pPacket->m_nPosition;

	for ( POSITION pos = Neighbours.GetIterator() ; pos ; )
	{
		CG2Neighbour* pNeighbour = (CG2Neighbour*)Neighbours.GetNext( pos );

		if (	pNeighbour != this &&
				pNeighbour->m_nProtocol == PROTOCOL_G2 &&
				pNeighbour->m_nState == nrsConnected &&
				pNeighbour->m_nNodeType != ntLeaf &&
				pNeighbour->m_pHost.sin_addr.S_un.S_addr != Network.m_pHost.sin_addr.S_un.S_addr )
		{
			if ( pNeighbour->m_pVendor && pNeighbour->m_pVendor->m_sCode.GetLength() == 4 )
			{
				pPacket->WritePacket( "NH", 14 + 6, TRUE );					// 4
				pPacket->WritePacket( "HS", 2 );							// 4
				pPacket->WriteShortBE( (WORD)pNeighbour->m_nLeafCount );	// 2
				pPacket->WritePacket( "V", 4 );								// 3
				pPacket->WriteString( pNeighbour->m_pVendor->m_sCode );		// 5
			}
			else
			{
				pPacket->WritePacket( "NH", 7 + 6, TRUE );					// 4
				pPacket->WritePacket( "HS", 2 );							// 4
				pPacket->WriteShortBE( (WORD)pNeighbour->m_nLeafCount );	// 2
				pPacket->WriteByte( 0 );									// 1
			}

			pPacket->WriteLongLE( pNeighbour->m_pHost.sin_addr.S_un.S_addr );	// 4
			pPacket->WriteShortBE( htons( pNeighbour->m_pHost.sin_port ) );		// 2
		}
	}

	int nCount = Settings.Gnutella2.KHLHubCount;
	DWORD tNow = static_cast< DWORD >( time( NULL ) );

	pPacket->WritePacket( "TS", 4 );
	pPacket->WriteLongBE( static_cast< DWORD >( time( NULL ) ) );

	for ( CHostCacheHost* pHost = HostCache.Gnutella2.GetNewest() ; pHost && nCount > 0 ; pHost = pHost->m_pPrevTime )
	{
		if (	pHost->CanQuote( tNow ) &&
				Neighbours.Get( &pHost->m_pAddress ) == NULL &&
				pHost->m_pAddress.S_un.S_addr != Network.m_pHost.sin_addr.S_un.S_addr )
		{
			int nLength = 10;

			if ( pHost->m_pVendor && pHost->m_pVendor->m_sCode.GetLength() == 4 )
				nLength += 7;
			if ( m_nNodeType == ntLeaf && pHost->m_nKeyValue != 0 && pHost->m_nKeyHost == Network.m_pHost.sin_addr.S_un.S_addr )
				nLength += 8;
			if ( nLength > 10 )
				nLength ++;

			pPacket->WritePacket( "CH", nLength, nLength > 10 );

			if ( pHost->m_pVendor && pHost->m_pVendor->m_sCode.GetLength() == 4 )
			{
				pPacket->WritePacket( "V", 4 );								// 3
				pPacket->WriteString( pHost->m_pVendor->m_sCode, FALSE );	// 4
			}

			if ( m_nNodeType == ntLeaf && pHost->m_nKeyValue != 0 && pHost->m_nKeyHost == Network.m_pHost.sin_addr.S_un.S_addr )
			{
				pPacket->WritePacket( "QK", 4 );							// 4
				pPacket->WriteLongBE( pHost->m_nKeyValue );					// 4
			}

			if ( nLength > 10 ) pPacket->WriteByte( 0 );					// 1

			pPacket->WriteLongLE( pHost->m_pAddress.S_un.S_addr );			// 4
			pPacket->WriteShortBE( pHost->m_nPort );						// 2
			pPacket->WriteLongBE( pHost->m_tSeen );							// 4

			nCount--;
		}
	}

	Send( pPacket, TRUE, TRUE );

	m_tLastKHL = GetTickCount();
}

//////////////////////////////////////////////////////////////////////
// CG2Neighbour KNOWN HUB LIST : receive

BOOL CG2Neighbour::OnKHL(CG2Packet* pPacket)
{
	if ( ! pPacket->m_bCompound ) return TRUE;

	CHAR szType[9], szInner[9];
	DWORD nLength, nInner;
	BOOL bCompound;

	DWORD tNow = static_cast< DWORD >( time( NULL ) );

	m_pHubGroup->Clear();

	while ( pPacket->ReadPacket( szType, nLength, &bCompound ) )
	{
		DWORD nNext = pPacket->m_nPosition + nLength;

		if (	strcmp( szType, "NH" ) == 0 ||
				strcmp( szType, "CH" ) == 0 )
		{
			DWORD nAddress = 0, nKey = 0, tSeen = tNow;
			WORD nPort = 0;
			CString strVendor;

			if ( bCompound || 0 == strcmp( szType, "NH" ) )
			{
				while ( pPacket->m_nPosition < nNext && pPacket->ReadPacket( szInner, nInner ) )
				{
					DWORD nNextX = pPacket->m_nPosition + nInner;

					if ( strcmp( szInner, "NA" ) == 0 && nInner >= 6 )
					{
						nAddress = pPacket->ReadLongLE();
						nPort = pPacket->ReadShortBE();
					}
					else if ( strcmp( szInner, "V" ) == 0 && nInner >= 4 )
					{
						strVendor = pPacket->ReadString( 4 );
					}
					else if ( strcmp( szInner, "QK" ) == 0 && nInner >= 4 )
					{
						nKey = pPacket->ReadLongBE();
						m_bCachedKeys = TRUE;
					}
					else if ( strcmp( szInner, "TS" ) == 0 && nInner >= 4 )
					{
						tSeen = pPacket->ReadLongBE() + m_tAdjust;
					}

					pPacket->m_nPosition = nNextX;
				}

				nLength = nNext - pPacket->m_nPosition;
			}

			if ( nLength >= 6 )
			{
				nAddress = pPacket->ReadLongLE();
				nPort = pPacket->ReadShortBE();
				if ( nLength >= 10 ) tSeen = pPacket->ReadLongBE() + m_tAdjust;
			}

			if ( FALSE == Network.IsFirewalledAddress( &nAddress, TRUE ) )
			{
				CHostCacheHost* pCached = HostCache.Gnutella2.Add(
					(IN_ADDR*)&nAddress, nPort, tSeen, strVendor );

				if ( pCached != NULL && m_nNodeType == ntHub )
				{
					if ( pCached->m_nKeyValue == 0 ||
						 pCached->m_nKeyHost != Network.m_pHost.sin_addr.S_un.S_addr )
					{
						pCached->SetKey( nKey, &m_pHost.sin_addr );
					}
				}

				if ( strcmp( szType, "NH" ) == 0 )
				{
					m_pHubGroup->Add( (IN_ADDR*)&nAddress, nPort );
				}
			}
		}
		else if ( strcmp( szType, "TS" ) == 0 && nLength >= 4 )
		{
			m_tAdjust = (LONG)tNow - (LONG)pPacket->ReadLongBE();
		}

		pPacket->m_nPosition = nNext;
	}

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CG2Neighbour HUB ADVERTISEMENT WALKER : send

void CG2Neighbour::SendHAW()
{
	m_tLastHAW = GetTickCount();

	if ( m_nNodeType == ntLeaf || Neighbours.IsG2Leaf() ) return;

	CG2Packet* pPacket = CG2Packet::New( G2_PACKET_HAW, TRUE );

	WORD nLeafs = 0;

	// This GUID will gets added to RouteCache of Receivers so this should not be any Random GUID as it is
	// thus it is better to use Profile's GUID instead of Randomly generated GUID in CreateID() function.
	// Otherwize will cause Mess of RouteCache.
	// Note: because it is notsame as Main RouteCache used on Normal Packet Handling, it is not sever problem right now.
	//		However this can cause problem if in future this GUID gets used for getting GUID for normal routing too...
	//		P.S. I do not know what other G2 Nodes(GnucDNA) use this GUID as main RouteCache or separate cache, so better
	//			check up with them.
	// Hashes::Guid oGUID;
	// Network.CreateID( oGUID );

	for ( POSITION pos = Neighbours.GetIterator() ; pos ; )
	{
		CNeighbour* pNeighbour = Neighbours.GetNext( pos );

		if (	pNeighbour != this &&
				pNeighbour->m_nState == nrsConnected &&
				pNeighbour->m_nNodeType == ntLeaf )
		{
			nLeafs++;
		}
	}

	pPacket->WritePacket( "NA", 6 );
	pPacket->WriteLongLE( Network.m_pHost.sin_addr.S_un.S_addr );
	pPacket->WriteShortBE( htons( Network.m_pHost.sin_port ) );

	pPacket->WritePacket( "HS", 2 );
	pPacket->WriteShortBE( nLeafs );

	pPacket->WritePacket( "V", 4 );
	pPacket->WriteString( SHAREAZA_VENDOR_A );	// 5 bytes

	pPacket->WriteByte( 100 );
	pPacket->WriteByte( 0 );
	// This GUID will gets added to RouteCache of Receivers so this should not be any Random GUID as it is
	// thus it is better to use Profile's GUID instead of Randomly generated GUID in CreateID() function.
	// Otherwize will cause Mess of RouteCache.
	// Note: because it is notsame as Main RouteCache used on Normal Packet Handling, it is not sever problem right now.
	//		However this can cause problem if in future this GUID gets used for getting GUID for normal routing too...
	//		P.S. I do not know what other G2 Nodes(GnucDNA) use this GUID as main RouteCache or separate cache, so better
	//			check up with them.
	pPacket->Write( Hashes::Guid( MyProfile.oGUID ) );
	
	Send( pPacket, TRUE, TRUE );
	
	//m_pGUIDCache->Add( oGUID, this );
	m_pGUIDCache->Add( Hashes::Guid( MyProfile.oGUID ), this );
}

//////////////////////////////////////////////////////////////////////
// CG2Neighbour HUB ADVERTISEMENT WALKER : receive

BOOL CG2Neighbour::OnHAW(CG2Packet* pPacket)
{
	if ( ! pPacket->m_bCompound ) return TRUE;

	CString strVendor;
	CHAR szType[9];
	DWORD nLength;

	DWORD nAddress	= 0;
	WORD nPort		= 0;

	while ( pPacket->ReadPacket( szType, nLength ) )
	{
		DWORD nNext = pPacket->m_nPosition + nLength;

		if ( strcmp( szType, "V" ) == 0 && nLength >= 4 )
		{
			strVendor = pPacket->ReadString( 4 );
		}
		else if ( strcmp( szType, "NA" ) == 0 && nLength >= 6 )
		{
			nAddress	= pPacket->ReadLongLE();
			nPort		= pPacket->ReadShortBE();
		}

		pPacket->m_nPosition = nNext;
	}

	if ( pPacket->GetRemaining() < 2 + 16 ) return TRUE;
	if ( nAddress == 0 || nPort == 0 ) return TRUE;
	if ( Network.IsFirewalledAddress( &nAddress, TRUE ) ) return TRUE;

	BYTE* pPtr	= pPacket->m_pBuffer + pPacket->m_nPosition;
	BYTE nTTL	= pPacket->ReadByte();
	BYTE nHops	= pPacket->ReadByte();

	Hashes::Guid oGUID;
	pPacket->Read( oGUID );

	HostCache.Gnutella2.Add( (IN_ADDR*)&nAddress, nPort, 0, strVendor );

	if ( nTTL > 0 && nHops < 255 )
	{
		m_pGUIDCache->Add( oGUID, this );	// adding GUID to RouteCache of this Neighbouring connection
											// thus the GUID should not be the one created randomly
											// Currently all the existing Hubs( up to Shareaza 2.2.2.20 )
											// Are sending HAW with randomly created GUIDs, which can cause big mess
											// in RouteCache.
		// Note: because it is notsame as Main RouteCache used on Normal Packet Handling, it is not sever problem right now.
		//		However this can cause problem if in future this GUID gets used for getting GUID for normal routing too...
		//		P.S. I do not know what other G2 Nodes(GnucDNA) use this GUID as main RouteCache or separate cache, so better
		//			check up with them.

		pPtr[0] = nTTL  - 1;
		pPtr[1] = nHops + 1;

		if ( CG2Neighbour* pNeighbour = Neighbours.GetRandomHub( this, oGUID ) )
		{
			pNeighbour->Send( pPacket, FALSE, TRUE );
		}
	}

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CG2Neighbour QUERY packet handler

BOOL CG2Neighbour::SendQuery(CQuerySearch* pSearch, CPacket* pPacket, BOOL bLocal)
{
	if ( m_nState != nrsConnected )
	{
		return FALSE;
	}
	else if ( pPacket == NULL || pPacket->m_nProtocol != PROTOCOL_G2 )
	{
		return FALSE;
	}
	else if ( m_nNodeType == ntHub && ! bLocal )
	{
		return FALSE;
	}
	else if ( m_pQueryTableRemote != NULL && m_pQueryTableRemote->m_bLive && ( m_nNodeType == ntLeaf || pSearch->m_bUDP ) )
	{
		if ( ! m_pQueryTableRemote->Check( pSearch ) ) return FALSE;
	}
	else if ( m_nNodeType == ntLeaf && ! bLocal )
	{
		return FALSE;
	}

//	Network.OnQuerySearch( pSearch, TRUE );
	Send( pPacket, FALSE, ! bLocal );

	return TRUE;
}

BOOL CG2Neighbour::OnQuery(CG2Packet* pPacket)
{
	CQuerySearch* pSearch = CQuerySearch::FromPacket( pPacket );

	// Check for invalid / blocked searches
	if ( pSearch == NULL )
	{
		theApp.Message( MSG_DEFAULT, IDS_PROTOCOL_BAD_QUERY, (LPCTSTR)m_sAddress );
		Statistics.Current.Gnutella2.Dropped++;
		m_nDropCount++;
		return TRUE;
	}

	// Check for excessive source searching
	if ( pSearch->m_oSHA1 || pSearch->m_oBTH || pSearch->m_oED2K )
	{

		// Update allowed query operations, check for bad client
		if ( m_nQueryLimiter > -60 ) 
		{
			m_nQueryLimiter--;
		}
		else if ( ! m_bBlacklisted && ( m_nNodeType == ntLeaf ) )
		{
			// Abusive client
			m_bBlacklisted = TRUE;
			theApp.Message( MSG_SYSTEM, _T("Blacklisting %s due to excess traffic"), (LPCTSTR)m_sAddress );
			//Security.Ban( &m_pHost.sin_addr, ban30Mins, FALSE );

		}

		if ( ( m_bBlacklisted ) || ( m_nQueryLimiter < 0 ) )
		{
			// Too many FMS operations
			if ( ! m_bBlacklisted )
				theApp.Message( MSG_DEBUG, _T("Dropping excess query traffic from %s"), (LPCTSTR)m_sAddress );

			delete pSearch;
			Statistics.Current.Gnutella2.Dropped++;
			m_nDropCount++;
			return TRUE;
		}
	}

	// Check for old wrapped queries
	if ( pPacket->IsType( G2_PACKET_QUERY_WRAP ) )
	{
		theApp.Message( MSG_DEBUG, _T("CG2Neighbour::OnQuery Ignoring wrapped query packet") );
		delete pSearch;
		Statistics.Current.Gnutella2.Dropped++;
		m_nDropCount++;
		return TRUE;
	}

	if ( m_nNodeType == ntLeaf && pSearch->m_bUDP &&
		 pSearch->m_pEndpoint.sin_addr.S_un.S_addr != m_pHost.sin_addr.S_un.S_addr )
	{
		delete pSearch;
		Statistics.Current.Gnutella2.Dropped++;
		m_nDropCount++;
		return TRUE;
	}

	if ( ! Network.QueryRoute->Add( pSearch->m_oGUID, this ) )
	{
		delete pSearch;
		Statistics.Current.Gnutella2.Dropped++;
		m_nDropCount++;
		return TRUE;
	}

	if ( m_nNodeType != ntHub )
	{
		/*
		if ( pPacket->IsType( G2_PACKET_QUERY_WRAP ) )
		{
			if ( ! pPacket->SeekToWrapped() ) return TRUE;
			GNUTELLAPACKET* pG1 = (GNUTELLAPACKET*)( pPacket->m_pBuffer + pPacket->m_nPosition );

			if ( pG1->m_nTTL > 1 )
			{
				pG1->m_nTTL--;
				pG1->m_nHops++;
				Neighbours.RouteQuery( pSearch, pPacket, this, TRUE );
			}
		}
		else
		{
			Neighbours.RouteQuery( pSearch, pPacket, this, m_nNodeType == ntLeaf );
		}*/

		Neighbours.RouteQuery( pSearch, pPacket, this, m_nNodeType == ntLeaf );
	}

	Network.OnQuerySearch( pSearch );

	if ( pSearch->m_bUDP && /* Network.IsStable() && Datagrams.IsStable() && !Network.IsFirewalled() && */
		 pSearch->m_pEndpoint.sin_addr.S_un.S_addr != m_pHost.sin_addr.S_un.S_addr )
	{
		CLocalSearch pLocal( pSearch, &pSearch->m_pEndpoint );
		pLocal.Execute();
	}
	else
	{
		/*
		BOOL bIsG1 = pPacket->IsType( G2_PACKET_QUERY_WRAP );

		if ( ! bIsG1 || Settings.Gnutella1.EnableToday )
		{
			CLocalSearch pLocal( pSearch, this, bIsG1 );
			pLocal.Execute();
		}
		*/
		CLocalSearch pLocal( pSearch, this, FALSE );
		pLocal.Execute();
	}
	
	if ( m_nNodeType == ntLeaf ) Send( Neighbours.CreateQueryWeb( pSearch->m_oGUID, this ), TRUE, FALSE );
	
	delete pSearch;
	Statistics.Current.Gnutella2.Queries++;

	return TRUE;
}

BOOL CG2Neighbour::OnQueryAck(CG2Packet* pPacket)
{
	HostCache.Gnutella2.Add( &m_pHost.sin_addr, htons( m_pHost.sin_port ) );
	Hashes::Guid oGuid;
	SearchManager.OnQueryAck( pPacket, &m_pHost, oGuid );
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CG2Neighbour QUERY KEY REQUEST packet handler

BOOL CG2Neighbour::OnQueryKeyReq(CG2Packet* pPacket)
{
	if ( ! pPacket->m_bCompound ) return TRUE;
	if ( m_nNodeType != ntLeaf ) return TRUE;

	DWORD nLength, nAddress = 0;
	BOOL bCacheOkay = TRUE;
	CHAR szType[9];
	WORD nPort = 0;

	while ( pPacket->ReadPacket( szType, nLength ) )
	{
		DWORD nOffset = pPacket->m_nPosition + nLength;

		if ( strcmp( szType, "QNA" ) == 0 && nLength >= 6 )
		{
			nAddress	= pPacket->ReadLongLE();
			nPort		= pPacket->ReadShortBE();
		}
		else if ( strcmp( szType, "REF" ) == 0 )
		{
			bCacheOkay = FALSE;
		}

		pPacket->m_nPosition = nOffset;
	}

	if ( Network.IsFirewalledAddress( &nAddress, TRUE ) || 0 == nPort ) return TRUE;

	CHostCacheHost* pCached = bCacheOkay ? HostCache.Gnutella2.Find( (IN_ADDR*)&nAddress ) : NULL;

	if ( pCached != NULL && pCached->m_nKeyValue != 0 &&
		 pCached->m_nKeyHost == Network.m_pHost.sin_addr.S_un.S_addr )
	{
		CG2Packet* pAnswer = CG2Packet::New( G2_PACKET_QUERY_KEY_ANS, TRUE );
		pAnswer->WritePacket( "QNA", 6 );
		pAnswer->WriteLongLE( nAddress );
		pAnswer->WriteShortBE( nPort );
		pAnswer->WritePacket( "QK", 4 );
		pAnswer->WriteLongBE( pCached->m_nKeyValue );
		pAnswer->WritePacket( "CACHED", 0 );
		Send( pAnswer );
	}
	else
	{
		CG2Packet* pRequest = CG2Packet::New( G2_PACKET_QUERY_KEY_REQ, TRUE );
		pRequest->WritePacket( "SNA", 4 );
		pRequest->WriteLongLE( m_pHost.sin_addr.S_un.S_addr );
		Datagrams.Send( (IN_ADDR*)&nAddress, nPort, pRequest, TRUE, NULL, FALSE );
	}

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CG2Neighbour QUERY KEY ANSWER packet handler

BOOL CG2Neighbour::OnQueryKeyAns(CG2Packet* pPacket)
{
	if ( ! pPacket->m_bCompound ) return TRUE;
	if ( m_nNodeType != ntHub ) return TRUE;

	DWORD nKey = 0, nAddress = 0;
	WORD nPort = 0;

	CHAR szType[9];
	DWORD nLength;

	while ( pPacket->ReadPacket( szType, nLength ) )
	{
		DWORD nOffset = pPacket->m_nPosition + nLength;

		if ( strcmp( szType, "QK" ) == 0 && nLength >= 4 )
		{
			nKey = pPacket->ReadLongBE();
		}
		else if ( strcmp( szType, "QNA" ) == 0 && nLength >= 6 )
		{
			nAddress	= pPacket->ReadLongLE();
			nPort		= pPacket->ReadShortBE();
		}
		else if ( strcmp( szType, "CACHED" ) == 0 )
		{
			m_bCachedKeys = TRUE;
		}

		pPacket->m_nPosition = nOffset;
	}

	theApp.Message( MSG_DEBUG, _T("Got a query key for %s:%i via neighbour %s: 0x%x"),
		(LPCTSTR)CString( inet_ntoa( *(IN_ADDR*)&nAddress ) ), nPort, (LPCTSTR)m_sAddress, nKey );

	if ( Network.IsFirewalledAddress( &nAddress ) || 0 == nPort ) return TRUE;

	CHostCacheHost* pCache = HostCache.Gnutella2.Add( (IN_ADDR*)&nAddress, nPort );
	if ( pCache != NULL ) pCache->SetKey( nKey, &m_pHost.sin_addr );

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CG2Neighbour PUSH packet handler

BOOL CG2Neighbour::OnPush(CG2Packet* pPacket)
{
	if ( ! pPacket->m_bCompound ) return TRUE;

	DWORD nLength = pPacket->GetRemaining();

	if ( ! pPacket->SkipCompound( nLength, 6 ) )
	{
		pPacket->Debug( _T("BadPush") );
		Statistics.Current.Gnutella2.Dropped++;
		return TRUE;
	}

	DWORD nAddress	= pPacket->ReadLongLE();
	WORD nPort		= pPacket->ReadShortBE();

	if ( Security.IsDenied( (IN_ADDR*)&nAddress ) )
	{
		Statistics.Current.Gnutella2.Dropped++;
		m_nDropCount++;
		return TRUE;
	}
	else if ( ! nPort || Network.IsFirewalledAddress( &nAddress ) )
	{
		theApp.Message( MSG_ERROR, IDS_PROTOCOL_ZERO_PUSH, (LPCTSTR)m_sAddress );
		Statistics.Current.Gnutella2.Dropped++;
		m_nDropCount++;
		return TRUE;
	}

	Handshakes.PushTo( (IN_ADDR*)&nAddress, nPort );

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CG2Neighbour USER PROFILE CHALLENGE packet handler

BOOL CG2Neighbour::OnProfileChallenge(CG2Packet* /*pPacket*/)
{
	if ( ! MyProfile.IsValid() ) return TRUE;

	CG2Packet* pProfile = CG2Packet::New( G2_PACKET_PROFILE_DELIVERY, TRUE );

	CString strXML = MyProfile.GetXML( NULL, TRUE )->ToString( TRUE );

	pProfile->WritePacket( "XML", pProfile->GetStringLen( strXML ) );
	pProfile->WriteString( strXML, FALSE );

	Send( pProfile, TRUE, TRUE );

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CG2Neighbour USER PROFILE DELIVERY packet handler

BOOL CG2Neighbour::OnProfileDelivery(CG2Packet* pPacket)
{
	if ( ! pPacket->m_bCompound ) return TRUE;

	CHAR szType[9];
	DWORD nLength;

	while ( pPacket->ReadPacket( szType, nLength ) )
	{
		DWORD nOffset = pPacket->m_nPosition + nLength;

		if ( strcmp( szType, "XML" ) == 0 )
		{
			CXMLElement* pXML = CXMLElement::FromString( pPacket->ReadString( nLength ), TRUE );

			if ( pXML )
			{
				if ( m_pProfile == NULL ) m_pProfile = new CGProfile();
				if ( ! m_pProfile->FromXML( pXML ) ) delete pXML;
			}
		}

		pPacket->m_nPosition = nOffset;
	}

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CG2Neighbour G2/1.1

BOOL CG2Neighbour::OnModeChangeReq(CG2Packet* pPacket)
{
	return TRUE;
}

BOOL CG2Neighbour::OnModeChangeAck(CG2Packet* pPacket)
{
	return TRUE;
}

BOOL CG2Neighbour::OnPrivateMessage(CG2Packet* pPacket)
{
	return TRUE;
}

BOOL CG2Neighbour::OnClose(CG2Packet* pPacket)
{
	return TRUE;
}
