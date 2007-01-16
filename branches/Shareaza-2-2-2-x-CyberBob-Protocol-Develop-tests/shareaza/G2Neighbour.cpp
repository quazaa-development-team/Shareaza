//
// G2Neighbour.cpp
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

CG2Neighbour::CG2Neighbour(CNeighbour* pBase) :
	CNeighbour( PROTOCOL_G2, pBase ),
	m_nLeafCount			( 0 ),
	m_nLeafLimit			( 0 ),
	m_bCachedKeys			( FALSE ),
	m_pGUIDCache			( new CRouteCache() ),
	m_pHubGroup				( new CHubHorizonGroup() ),
	m_tLastRun				( 0 ),
	m_tAdjust				( 0 ),
	m_tLastPingIn			( 0 ),
	m_tLastPingOut			( 0 ),
	m_nCountPingIn			( 0 ),
	m_nCountPingOut			( 0 ),
	m_tLastRelayPingIn		( 0 ),
	m_tLastRelayPingOut		( 0 ),
	m_nCountRelayPingIn		( 0 ),
	m_nCountRelayPingOut	( 0 ),
	m_tLastRelayedPingIn	( 0 ),
	m_tLastRelayedPingOut	( 0 ),
	m_nCountRelayedPingIn	( 0 ),
	m_nCountRelayedPingOut	( 0 ),
	m_tLastKHLIn			( 0 ),
	m_tLastKHLOut			( 0 ),
	m_nCountKHLIn			( 0 ),
	m_nCountKHLOut			( 0 ),
	m_tLastLNIIn			( 0 ),
	m_tLastLNIOut			( 0 ),
	m_nCountLNIIn			( 0 ),
	m_nCountLNIOut			( 0 ),
	m_tLastHAWIn			( 0 ),
	m_tLastHAWOut			( 0 ),
	m_nCountHAWIn			( 0 ),
	m_nCountHAWOut			( 0 ),
	m_nQueryLimiter			( 40 ),
	m_tQueryTimer			( 0 ),
	m_bBlacklisted			( FALSE ),
	m_bHubAble		( FALSE ), //add
	m_bFirewall		( FALSE ), //add
	m_bRouter		( FALSE ), //add
	m_nCPU			( 0 ), //add
	m_nMEM			( 0 ), //add
	m_nBandwidthIn	( 0 ), //add
	m_nBandwidthOut	( 0 ), //add
	m_nUptime		( 0 ), //add
	m_nLatitude		( 0 ), //add
	m_nLongitude	( 0 ), //add
	m_bSFLCheck		( FALSE ), // add
	m_bFWCheckSent	( FALSE )  // add

{
	theApp.Message( MSG_DEFAULT, IDS_HANDSHAKE_ONLINE_G2, (LPCTSTR)m_sAddress,
		m_sUserAgent.IsEmpty() ? _T("Unknown") : (LPCTSTR)m_sUserAgent );

	InterlockedIncrement( (PLONG)&(Neighbours.m_nCount[PROTOCOL_G2][( (m_nNodeType != ntLeaf )? ntHub : ntLeaf )]) );
	if ( m_nNodeType == ntHub || m_nNodeType == ntNode )
		Neighbours.m_oHub.push_back(this);
	else if ( m_nNodeType == ntLeaf )
		Neighbours.m_oLeaf.push_back(this);
	SendStartups();
}

CG2Neighbour::~CG2Neighbour()
{
	if ( m_nNodeType == ntHub || m_nNodeType == ntNode )
		Neighbours.m_oHub.remove(this);
	else if ( m_nNodeType == ntLeaf )
		Neighbours.m_oLeaf.remove(this);

	InterlockedDecrement( (PLONG)&(Neighbours.m_nCount[PROTOCOL_G2][( (m_nNodeType != ntLeaf )? ntHub : ntLeaf )]) );
	delete m_pHubGroup;
	delete m_pGUIDCache;

	for ( POSITION pos = m_pOutbound.GetHeadPosition() ; pos ; )
	{
		CG2Packet* pOutbound = m_pOutbound.GetNext( pos );
		pOutbound->Release();
	}
}

void CG2Neighbour::Close(UINT nError)  // Send the buffer then close the socket, record the error given
{
	CNeighbour::Close(nError);
}

void CG2Neighbour::DelayClose(UINT nError)  // Send the buffer then close the socket, record the error given
{

	if ( nError == IDS_CONNECTION_CLOSED )
	{
		CG2Packet * pClosePacket = CG2Packet::New( G2_PACKET_CLOSE, FALSE );
		pClosePacket->WriteString( "Closing Connection", TRUE );
		Send( pClosePacket );
	}
	else if ( nError == IDS_CONNECTION_PEERPRUNE )
	{
		CG2Packet * pClosePacket = CG2Packet::New( G2_PACKET_CLOSE, FALSE );
		pClosePacket->WriteString( "Demoting to Leaf", TRUE );
		Send( pClosePacket );
	}
	else if ( nError == IDS_CONNECTION_REFUSED )
	{
		CG2Packet * pClosePacket = CG2Packet::New( G2_PACKET_CLOSE, FALSE );
		pClosePacket->WriteString( "Sorry, refusing any more transaction. Please check your software and update", TRUE );
		Send( pClosePacket );
	}

	CNeighbour::DelayClose(nError);
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

	// Check incoming LNI traffic
	if ( m_nCountLNIIn == 0 && tNow - m_tConnected > Settings.Gnutella2.LNIPeriod * 3 )
	{
		// No LNI packet was recieved during 3 periods (dead or annonymous host)
		Close( IDS_CONNECTION_TIMEOUT_TRAFFIC );
		return FALSE;
	}

	// Is it time to send TCP ping?
	if ( tNow - m_tLastPingOut >= Settings.Gnutella1.PingRate &&
	// But don't ping neighbour if we recently got any packets
		tNow - m_tLastPacket >= Settings.Connection.TimeoutTraffic / 2 )
	{
		Send( CG2Packet::New( G2_PACKET_PING ) );
		m_tLastPingOut = tNow;
		m_nCountPingOut++;
	}

	// We are unsure in our UDP capabilities therefore
	// we perform limited "two hop" ping ourself using this neighbour
	if ( Network.IsListening() && ! Datagrams.IsStable() &&	
		m_nCountRelayPingOut < 3 &&
		tNow - m_tLastRelayPingOut >= Settings.Gnutella1.PingRate )
	{
		CG2Packet* pPing = CG2Packet::New( G2_PACKET_PING, TRUE );
		pPing->WritePacket( G2_PACKET_UDP, 6 );
		pPing->WriteLongLE( Network.m_pHost.sin_addr.S_un.S_addr );
		pPing->WriteShortBE( htons( Network.m_pHost.sin_port ) );
		Send( pPing );
		m_tLastRelayPingOut = tNow;
		m_nCountRelayPingOut++;
	}

	// Is it time to send LNI?
	if ( tNow - m_tLastLNIOut > Settings.Gnutella2.LNIPeriod )
	{
		SendLNI();
	}

	// Is it time to send KHL?
	if ( tNow - m_tLastKHLOut > Settings.Gnutella2.KHLPeriod * ( Neighbours.IsG2Leaf() ? 3 : 1 ) )
	{
		SendKHL();
	}

	// Is it time to send HAW?
	if ( tNow - m_tLastHAWOut > Settings.Gnutella2.HAWPeriod &&
		m_nNodeType != ntLeaf && ! Neighbours.IsG2Leaf() )
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

	if ( Network.IsListening() && ( !Datagrams.IsStable() || Network.IsFirewalled() || Network.IsTestingUDPFW() ) )
	{
		pPing->WritePacket( G2_PACKET_UDP, 6 );
		pPing->WriteLongLE( Network.m_pHost.sin_addr.S_un.S_addr );
		pPing->WriteShortBE( htons( Network.m_pHost.sin_port ) );
		theApp.Message( MSG_DEBUG, _T("Sending a Firewall test request to %s."), m_sAddress );
		pPing->WritePacket( G2_PACKET_TEST_FIREWALL, 0 );
	}

	Send( pPing, TRUE, TRUE );
	m_tLastPingOut = GetTickCount();

	Send( CG2Packet::New( G2_PACKET_PROFILE_CHALLENGE ), TRUE, TRUE );

	SendLNI();

	if ( !Network.IsTestingUDPFW() )
		Datagrams.Send( &m_pHost, CG2Packet::New( G2_PACKET_PING ), TRUE, NULL, FALSE );
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

	switch( pPacket->m_nType )
	{
	case G2_PACKET_PING:
		return OnPing( pPacket );
	case G2_PACKET_PONG:
		return OnPong( pPacket );
	case G2_PACKET_LNI:
		return OnLNI( pPacket );
	case G2_PACKET_KHL:
		return OnKHL( pPacket );
	case G2_PACKET_HAW:
		return OnHAW( pPacket );
	case G2_PACKET_QUERY:
		return OnQuery( pPacket );
	case G2_PACKET_QUERY_WRAP:
		// G2_PACKET_QUERY_WRAP deprecated and ignored
		break;
	case G2_PACKET_HIT:
		return OnCommonHit( pPacket );
	case G2_PACKET_HIT_WRAP:
		return OnCommonHit( pPacket );
	case G2_PACKET_QUERY_ACK:
		return OnQueryAck( pPacket );
	case G2_PACKET_QUERY_KEY_REQ:
		return OnQueryKeyReq( pPacket );
	case G2_PACKET_QUERY_KEY_ANS:
		return OnQueryKeyAns( pPacket );
	case G2_PACKET_QHT:
		return OnCommonQueryHash( pPacket );
	case G2_PACKET_PUSH:
		return OnPush( pPacket );
	case G2_PACKET_PROFILE_CHALLENGE:
		return OnProfileChallenge( pPacket );
	case G2_PACKET_PROFILE_DELIVERY:
		return OnProfileDelivery( pPacket );
	case G2_PACKET_MODE_CHANGE_REQ: //add G2/1.1
		return OnModeChangeReq( pPacket );
	case G2_PACKET_MODE_CHANGE_ACK: //add G2/1.1
		return OnModeChangeAck( pPacket );
	case G2_PACKET_PRIVATE_MESSAGE: //add G2/1.1
		return OnPrivateMessage( pPacket );
	case G2_PACKET_CLOSE: //add G2/1.1
		return OnClose( pPacket );
	default:
		theApp.Message( MSG_DEBUG, _T("TCP: Received unexpected packet %s from %s"),
			pPacket->GetType(), (LPCTSTR)CString( inet_ntoa( m_pHost.sin_addr ) ) );
	}

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CG2Neighbour PING packet handler

BOOL CG2Neighbour::OnPing(CG2Packet* pPacket, BOOL bTCP)
{
	Statistics.Current.Gnutella2.PingsReceived++;

	DWORD tNow = GetTickCount();
	BOOL bRelay = FALSE;
	BOOL bUDP = FALSE;
	DWORD nAddress = 0;
	WORD nPort = 0;
	DWORD nLength;
	CString strVendorCode, strName, strVersion;
	BOOL bVersion = FALSE;
	BOOL bTestFirewall = FALSE;
	BOOL bConnectRequest = FALSE; //add
	BOOL bHubMode = FALSE; //add
	BOOL bSupportedFeature = FALSE; // add
	DWORD nIdent = 0; //add
	G2_PACKET nType;

	if ( pPacket->m_bCompound )
	{
		while ( pPacket->ReadPacket( nType, nLength ) )
		{
			DWORD nNext = pPacket->m_nPosition + nLength;

			if ( nType == G2_PACKET_UDP && nLength >= 6 )
			{
				nAddress	= pPacket->ReadLongLE();
				nPort		= pPacket->ReadShortBE();
				if ( nAddress != 0 && nPort != 0 && !Network.IsFirewalledAddress( &nAddress, TRUE, TRUE ) )
					bUDP = TRUE;
			}
			else if ( nType == G2_PACKET_RELAY )
			{
				bRelay = TRUE;
			}
			else if ( nType == G2_PACKET_VER_DESC )
			{
				bVersion = TRUE;
			}
			else if ( nType == G2_PACKET_IDENT && nLength >= 4 ) //add G2/1.1
			{
				nIdent = pPacket->ReadLongBE();
			}
			else if ( nType == G2_PACKET_TEST_FIREWALL ) //add G2/1.1
			{
				bTestFirewall = TRUE;
			}
			else if ( nType == G2_PACKET_CONNECT_REQUEST && nLength >= 1 ) //add G2/1.1
			{
				bHubMode = pPacket->ReadByte();
				bConnectRequest = TRUE;
			}
			else if ( nType == G2_PACKET_SFL_DESC ) // Supported Feature List
			{
				bSupportedFeature = TRUE;
			}

			pPacket->m_nPosition = nNext;
		}
	}


	if ( ! bUDP )
	{
		if ( ! bRelay )
		{
			// This is a direct ping packet
			if ( tNow - m_tLastPingIn < Settings.Gnutella1.PingFlood )
				// We are flooded
				return TRUE;
			m_tLastPingIn = tNow;
			m_nCountPingIn++;

			CG2Packet* pPong = CG2Packet::New( G2_PACKET_PONG, TRUE );
			//// START OWN EXTENSION
			if (bVersion)
			{
				strVendorCode = VENDOR_CODE;
				strName = CLIENT_NAME;
				strVersion = theApp.m_sVersion;
				pPong->WritePacket( G2_PACKET_VENDORCODE, pPong->GetStringLen( strVendorCode ) );
				pPong->WriteString( strVendorCode, FALSE );
				pPong->WritePacket( G2_PACKET_AGENT_NAME, pPong->GetStringLen( strName ) );
				pPong->WriteString( strName, FALSE );
				pPong->WritePacket( G2_PACKET_AGENT_VERSION, pPong->GetStringLen( strVersion ) );
				pPong->WriteString( strVersion, FALSE );

			}
			if ( bSupportedFeature )
			{
				// Format of Supported Feature list is feature name feature name followed by 2Byte feature versions
				// first byte is Major version, and second is Miner version.
				CG2Packet * pSFL = CG2Packet::New( G2_PACKET_SFL_DESC, TRUE );

				// indicate G2/1.0
				pSFL->WritePacket( G2_PACKET_G2DESC, 2 );
				pSFL->WriteByte(1);
				pSFL->WriteByte(0);

				// indicate TFW/1.0 (TestFireWall)
				pSFL->WritePacket( G2_PACKET_TEST_FIREWALL, 2 );
				pSFL->WriteByte(1);
				pSFL->WriteByte(0);

				// indicate UDPKHL/1.0
				pSFL->WritePacket( G2_PACKET_UDPKHL_DESC, 2 );
				pSFL->WriteByte(1);
				pSFL->WriteByte(0);

				// end compound
				pSFL->WriteByte(0);

				// adding SFL packet as conpound packet in PONG
				pPong->WritePacket( pSFL );
				pSFL->Release();
			}
			//// END OWN EXTENSION
			if ( bTCP )
				Send( pPong );
			else
				Datagrams.Send( &m_pHost, pPong, TRUE, NULL, FALSE, FALSE );
			Statistics.Current.Gnutella2.PongsSent++;
			return TRUE;
		}
		else
		{
			// This is a "/PI/RELAY without /PI/UDP" error packet
			return TRUE;
		}
	}
	else if ( ! nPort ||
		Network.IsFirewalledAddress( &nAddress, TRUE, TRUE ) || 
		Network.IsReserved( (IN_ADDR*)&nAddress ) )
	{
		// Invalid /PI/UDP address
		return TRUE;
	}
	else if ( bRelay && bTCP ) // This is a TCP relayed ping packet
	{
		// Testing if UDP port is firewalled or not.
		if ( Network.IsTestingUDPFW() && !Datagrams.IsStable() )
			return TRUE; //do not send any /PO/RELAY on UDP to prevent miss detection of FW status

		if ( tNow - m_tLastRelayedPingIn < Settings.Gnutella1.PingFlood )
			// We are flooded
			return TRUE;
		m_tLastRelayedPingIn = tNow;
		m_nCountRelayedPingIn++;

		CG2Packet* pPong = CG2Packet::New( G2_PACKET_PONG, TRUE );
		//// START OWN EXTENSION
		if (bVersion)
		{
			strVendorCode = VENDOR_CODE;
			strName = CLIENT_NAME;
			strVersion = theApp.m_sVersion;
			pPong->WritePacket( G2_PACKET_VENDORCODE, pPong->GetStringLen( strVendorCode ) );
			pPong->WriteString( strVendorCode, FALSE );
			pPong->WritePacket( G2_PACKET_AGENT_NAME, pPong->GetStringLen( strName ) );
			pPong->WriteString( strName, FALSE );
			pPong->WritePacket( G2_PACKET_AGENT_VERSION, pPong->GetStringLen( strVersion ) );
			pPong->WriteString( strVersion, FALSE );

		}
		if ( bSupportedFeature )
		{
			// Format of Supported Feature list is feature name feature name followed by 2Byte feature versions
			// first byte is Major version, and second is Miner version.
			CG2Packet * pSFL = CG2Packet::New( G2_PACKET_SFL_DESC, TRUE );

			// indicate G2/1.0
			pSFL->WritePacket( G2_PACKET_G2DESC, 2 );
			pSFL->WriteByte(1);
			pSFL->WriteByte(0);

			// indicate TFW/1.0 (TestFireWall)
			pSFL->WritePacket( G2_PACKET_TEST_FIREWALL, 2 );
			pSFL->WriteByte(1);
			pSFL->WriteByte(0);

			// indicate UDPKHL/1.0
			pSFL->WritePacket( G2_PACKET_UDPKHL_DESC, 2 );
			pSFL->WriteByte(1);
			pSFL->WriteByte(0);

			// end compound
			pSFL->WriteByte(0);

			// adding SFL packet as conpound packet in PONG
			pPong->WritePacket( pSFL );
			pSFL->Release();
		}
		//// END OWN EXTENSION
		pPong->WritePacket( G2_PACKET_RELAY, 0 );

		Datagrams.Send( (IN_ADDR*)&nAddress, nPort, pPong, TRUE, NULL, FALSE, FALSE );
		Statistics.Current.Gnutella2.PongsSent++;
		return TRUE;
	}
	else if ( ! bRelay && bTCP )
	{
		// This is a TCP relayed ping request packet
		if ( tNow - m_tLastRelayPingIn < Settings.Gnutella1.PingFlood )
			// We are flooded
			return TRUE;
		m_tLastRelayPingIn = tNow;
		m_nCountRelayPingIn++;

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
			if ( pNeighbour->m_nProtocol == PROTOCOL_G2 )
			{
				CG2Neighbour* pNeighbour2 = static_cast< CG2Neighbour* >( pNeighbour );
				if ( pNeighbour2->m_nState == nrsConnected &&
					pNeighbour2 != this &&
					tNow - pNeighbour2->m_tLastRelayedPingOut >= Settings.Gnutella1.PingRate )
				{
					pG2Nodes.Add(  pNeighbour2 );
				}
			}
		}

		int nRelayTo = Settings.Gnutella2.PingRelayLimit;

		INT_PTR nCount = pG2Nodes.GetCount();

		for ( INT_PTR nCur = 0; (nCur < nCount && nCur < nRelayTo); nCur++ )
		{
			INT_PTR nRand = rand() % pG2Nodes.GetCount();

			CG2Neighbour* pNeighbour = pG2Nodes.GetAt( nRand );
			pNeighbour->Send( pPacket, FALSE );
			pNeighbour->m_tLastRelayedPingOut = tNow;
			pNeighbour->m_nCountRelayedPingOut++;
			Statistics.Current.Gnutella2.PingsSent++;
			pG2Nodes.RemoveAt( nRand );
		}
	}

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CG2Neighbour PONG packet handler

BOOL CG2Neighbour::OnPong( CG2Packet* pPacket, BOOL bTCP )
{
	CString strVendorCode, strName, strVersion;
	Statistics.Current.Gnutella2.PongsReceived++;

	BOOL bRelayed = FALSE;
	if ( pPacket->m_bCompound )
	{
		G2_PACKET nType;
		DWORD nLength;
		BOOL bCompound;

		while ( pPacket->ReadPacket( nType, nLength, &bCompound ) )
		{
			DWORD nOffset = pPacket->m_nPosition + nLength;
			if ( nType == G2_PACKET_RELAY )
				bRelayed = TRUE;
			if ( nType == G2_PACKET_VENDORCODE && nLength != 0 )	// Vendor Code of Remote Node  (e.g. "RAZA")
			{
				strVendorCode = pPacket->ReadStringUTF8( nLength );
			}
			else if ( nType == G2_PACKET_AGENT_NAME && nLength != 0 )	// Agent name of Remote Node (e.g. "Shareaza")
			{
				strName = pPacket->ReadStringUTF8( nLength );
			}
			else if ( nType == G2_PACKET_AGENT_VERSION && nLength != 0 )	// Agent version of Remote Node (e.g. 2.2.2.20)
			{
				strVersion = pPacket->ReadStringUTF8( nLength );
			}
			else if ( nType == G2_PACKET_SFL_DESC && bCompound == TRUE )	// SupportedFeatureList
			{
				G2_PACKET nInnerType;
				DWORD nInner;

				while ( pPacket->m_nPosition < nOffset && pPacket->ReadPacket( nInnerType, nInner ) )
				{
					DWORD nSkipInner = pPacket->m_nPosition + nInner;

					if ( nInnerType == G2_PACKET_G2DESC && nInner >= 2 )
					{
						// G2 = TRUE
						// G2Version = pPacket->ReadByte() << 8;
						// G2Version = pPacket->ReadByte();
					}
					else if ( nInnerType == G2_PACKET_TEST_FIREWALL && nInner >= 2 )
					{
						// TFW = TRUE
						// TFWVersion = pPacket->ReadByte() << 8;
						// TFWVersion = pPacket->ReadByte();
					}
					else if ( nInnerType == G2_PACKET_UDPKHL_DESC && nInner >= 2 )
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

	if ( strVendorCode.GetLength() > 0 )
		theApp.Message( MSG_SYSTEM, _T("Received PONG contained VenderCode: %s"), (LPCTSTR)strVendorCode);
	if ( strName.GetLength() > 0 )
		theApp.Message( MSG_SYSTEM, _T("Received PONG contained AgentName: %s"), (LPCTSTR)strName);
	if ( strVersion.GetLength() > 0 )
		theApp.Message( MSG_SYSTEM, _T("Received PONG contained AgentVersion: %s"), (LPCTSTR)strVersion);

	// Condition below never be TRUE thus this condition should be removed.(Only commenting out for now.)
	//if ( bRelayed && ! bTCP && ! Network.IsConnectedTo( &m_pHost.sin_addr ) )
	//	Datagrams.SetStable();
	UNUSED_ALWAYS( bTCP );
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CG2Neighbour LOCAL NODE INFO : send

void CG2Neighbour::SendLNI()
{
	Send( Neighbours.CreateLNIPacket( this ), TRUE, FALSE );

	m_tLastLNIOut = GetTickCount();
	m_nCountLNIOut ++;
}

//////////////////////////////////////////////////////////////////////
// CG2Neighbour LOCAL NODE INFO : receive

BOOL CG2Neighbour::OnLNI(CG2Packet* pPacket)
{
	if ( ! pPacket->m_bCompound ) return TRUE;
	Hashes::Guid oTO;
	if ( pPacket->GetTo( oTO ) )
	{
		theApp.Message(MSG_SYSTEM, _T("Detected LNI packet with faked Destination. Ignoring the packet") );
		return TRUE;
	}

	m_tLastLNIIn = GetTickCount();
	m_nCountLNIIn ++;

	G2_PACKET nType;
	DWORD nLength;

	DWORD nLeafCount = 0, nFileCount = 0, nFileVolume = 0;
	SOCKADDR_IN	pHostAddr;
	
	pHostAddr.sin_addr.S_un.S_addr = 0;
	pHostAddr.sin_port = 0;

	while ( pPacket->ReadPacket( nType, nLength ) )
	{
		DWORD nNext = pPacket->m_nPosition + nLength;

		if ( nType == G2_PACKET_NODE_ADDRESS && nLength >= 6 )
		{
			pHostAddr.sin_addr.S_un.S_addr = pPacket->ReadLongLE();
			pHostAddr.sin_port = htons( pPacket->ReadShortBE() );
		}
		else if ( nType == G2_PACKET_NODE_GUID && nLength >= 16 )
		{
			pPacket->Read( m_oGUID );
			m_oGUID.validate();
		}
		else if ( nType == G2_PACKET_VENDOR && nLength >= 4 )
		{
			CHAR szVendor[5] = { 0, 0, 0, 0, 0 };
			pPacket->Read( szVendor, 4 );
			m_pVendor = VendorCache.Lookup( szVendor );
		}
		else if ( nType == G2_PACKET_LIBRARY_STATUS && nLength >= 8 )
		{
			nFileCount	= pPacket->ReadLongBE();
			nFileVolume	= pPacket->ReadLongBE();
		}
		else if ( nType == G2_PACKET_HUB_STATUS && nLength >= 2 )
		{
			nLeafCount = pPacket->ReadShortBE();
			m_nLeafLimit = pPacket->ReadShortBE();
		}
		else if ( nType == G2_PACKET_QUERY_KEY )
		{
			m_bCachedKeys = TRUE;
		}
		else if ( nType == G2_PACKET_HUB_ABLE ) //add G2/1.1
		{
			m_bHubAble = TRUE;
			m_bFirewall = m_bFirewall ? FALSE : m_bFirewall;
		}
		else if (nType == G2_PACKET_PEER_FIREWALLED ) //add G2/1.1
		{
			m_bHubAble = FALSE;
			m_bFirewall = TRUE;
		}
		else if ( nType == G2_PACKET_PEER_NOTFIREWALLED ) //add G2/1.1
		{
			m_bFirewall = FALSE;
		}
		else if ( nType == G2_PACKET_PEER_BEHINDROUTER ) //add G2/1.1
		{
			m_bRouter = TRUE;
		}
		else if ( nType == G2_PACKET_CPU_AND_MEMORY && nLength >= 2 ) //add G2/1.1
		{
			m_nCPU = pPacket->ReadShortBE();
			m_nMEM = pPacket->ReadShortBE();
		}
		else if ( nType == G2_PACKET_NETWORK_BANDWIDTH && nLength >= 8) //add G2/1.1
		{
			m_nBandwidthIn = pPacket->ReadLongBE();	
			m_nBandwidthOut = pPacket->ReadLongBE();
		}
		else if ( nType == G2_PACKET_UPTIME && nLength >= 4 ) //add G2/1.1
		{
			m_nUptime = pPacket->ReadLongBE();
		}
		else if ( nType == G2_PACKET_GPS && nLength >= 4 ) //add G2/1.1
		{
			DWORD nGPS = pPacket->ReadLongBE();
			m_nLatitude	 = (float)HIWORD( nGPS ) / 65535.0f * 180.0f - 90.0f;
			m_nLongitude = (float)LOWORD( nGPS ) / 65535.0f * 360.0f - 180.0f;
		}

		pPacket->m_nPosition = nNext;
	}

	m_nLeafCount = nLeafCount;
	if ( m_nNodeType != ntLeaf )
	{
		if ( m_pHost.sin_addr.S_un.S_addr != pHostAddr.sin_addr.S_un.S_addr )
		{
			CString strAddress = inet_ntoa( pHostAddr.sin_addr );
			theApp.Message(MSG_SYSTEM, _T("LNI packet detected host \"%s\" has changed IP to \"%s\""),
				m_sAddress, strAddress );
			m_pHost.sin_addr.S_un.S_addr = pHostAddr.sin_addr.S_un.S_addr;
			m_sAddress = strAddress;
		}
		if ( m_pHost.sin_port != pHostAddr.sin_port )
		{
			theApp.Message(MSG_SYSTEM, _T("LNI packet detected host \"%s\" has changed port from \"%u\" to \"%u\""),
				CString( inet_ntoa( m_pHost.sin_addr ) ), ntohs( m_pHost.sin_port ), ntohs( pHostAddr.sin_port ) );
			m_pHost.sin_port = pHostAddr.sin_port;
		}

		CHostCacheHost* pCache = HostCache.Gnutella2.Add( &m_pHost.sin_addr, htons( m_pHost.sin_port ), 0, m_pVendor->m_sCode, 0 );

		if ( pCache != NULL )
		{
			pCache->m_nUserCount = m_nLeafCount;
			pCache->m_nUserLimit = m_nLeafLimit;
		}
	}
	else
	{
		if ( m_nFileCount != nFileCount )
		{
			Neighbours.m_nG2FileCount -= m_nFileCount;
			Neighbours.m_nG2FileCount += nFileCount;
			m_nFileCount	= nFileCount;
		}

		if ( m_nFileVolume != nFileVolume )
		{
			Neighbours.m_nG2FileVolume -= m_nFileVolume;
			Neighbours.m_nG2FileVolume += nFileVolume;
			m_nFileVolume	= nFileVolume;
		}
	}

	if ( m_oGUID.isValid() )
		Network.NodeRoute->Add( m_oGUID, this, NULL, GetTickCount() );

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CG2Neighbour KNOWN HUB LIST : send

void CG2Neighbour::SendKHL()
{
	Send( Neighbours.CreateKHLPacket( this ), TRUE, TRUE );

	m_tLastKHLOut = GetTickCount();
	m_nCountKHLOut ++;
}

//////////////////////////////////////////////////////////////////////
// CG2Neighbour KNOWN HUB LIST : receive

BOOL CG2Neighbour::OnKHL(CG2Packet* pPacket)
{
	m_tLastKHLIn = GetTickCount();
	m_nCountKHLIn ++;

	return Neighbours.ParseKHLPacket( pPacket, this );
}

//////////////////////////////////////////////////////////////////////
// CG2Neighbour HUB ADVERTISEMENT WALKER : send

void CG2Neighbour::SendHAW()
{
	if ( !Neighbours.NeedMoreLeafs( PROTOCOL_G2 ) ) return;
	if ( (WORD)Neighbours.m_nCount[PROTOCOL_G2][ntLeaf] >= (WORD)( Neighbours.m_nLimit[PROTOCOL_G2][ntLeaf] * 0.75 ) ) return;

	CG2Packet* pPacket = CG2Packet::New( G2_PACKET_HAW, TRUE );

	Hashes::Guid oGUID;
	Network.CreateID( oGUID );

	/*
	WORD nLeaf = 0;

	for ( POSITION pos = Neighbours.GetIterator() ; pos ; )
	{
		CNeighbour* pNeighbour = Neighbours.GetNext( pos );

		if (	pNeighbour != this &&
				pNeighbour->m_nState == nrsConnected &&
				pNeighbour->m_nNodeType == ntLeaf )
		{
			nLeaf++;
		}
	}
	*/

	pPacket->WritePacket( G2_PACKET_NODE_ADDRESS, 6 );
	pPacket->WriteLongLE( Network.m_pHost.sin_addr.S_un.S_addr );
	pPacket->WriteShortBE( htons( Network.m_pHost.sin_port ) );

	pPacket->WritePacket( G2_PACKET_HUB_STATUS, 4 );
	pPacket->WriteShortBE( (WORD)Neighbours.m_nCount[PROTOCOL_G2][ntLeaf] );
	pPacket->WriteShortBE( (WORD)Neighbours.m_nLimit[PROTOCOL_G2][ntLeaf] );

	pPacket->WritePacket( G2_PACKET_VENDOR, 4 );
	pPacket->WriteString( SHAREAZA_VENDOR_A );	// 5 bytes

	pPacket->WriteByte( 100 );	// TTL = 100
	pPacket->WriteByte( 0 );	// HOP = 0
	pPacket->Write( Hashes::Guid( oGUID ) );
	
	Send( pPacket, TRUE, TRUE );
	
	m_pGUIDCache->Add( oGUID, this );

	m_tLastHAWOut = GetTickCount();
	m_nCountHAWOut++;
}

//////////////////////////////////////////////////////////////////////
// CG2Neighbour HUB ADVERTISEMENT WALKER : receive

BOOL CG2Neighbour::OnHAW(CG2Packet* pPacket)
{
	if ( ! pPacket->m_bCompound ) return TRUE;
	Hashes::Guid oTO;
	if ( pPacket->GetTo( oTO ) )
	{
		theApp.Message(MSG_SYSTEM, _T("Detected HAW packet with faked Destination. Ignoring the packet") );
		return TRUE;
	}

	m_tLastHAWIn = GetTickCount();
	m_nCountHAWIn ++;

	CString strVendor;
	G2_PACKET nType;
	DWORD nLength;
	WORD nLeaf = 0;
	WORD nMaxLeaf = 0;
	BOOL bHSCurrent = FALSE;
	BOOL bHSMax = FALSE;

	DWORD nAddress	= 0;
	WORD nPort		= 0;

	while ( pPacket->ReadPacket( nType, nLength ) )
	{
		DWORD nNext = pPacket->m_nPosition + nLength;

		if ( nType == G2_PACKET_VENDOR && nLength >= 4 )
		{
			strVendor = pPacket->ReadString( 4 );
		}
		else if ( nType == G2_PACKET_NODE_ADDRESS && nLength >= 6 )
		{
			nAddress	= pPacket->ReadLongLE();
			nPort		= pPacket->ReadShortBE();
		}
		else if ( nType == G2_PACKET_HUB_STATUS && nLength >= 2 )
		{
			nLeaf = pPacket->ReadShortBE();
			bHSCurrent = TRUE;
			if ( nLength >= 4 )
			{
				bHSMax = TRUE;
				nMaxLeaf = pPacket->ReadShortBE();
			}
		}

		pPacket->m_nPosition = nNext;
	}

	if ( pPacket->GetRemaining() < 2 + 16 ) return TRUE;
	if ( nAddress == 0 || nPort == 0 ) return TRUE;
	if ( Network.IsFirewalledAddress( &nAddress, TRUE, TRUE ) ||
		 Network.IsReserved( (IN_ADDR*)&nAddress ) ) return TRUE;

	BYTE* pPtr	= pPacket->m_pBuffer + pPacket->m_nPosition;
	BYTE nTTL	= pPacket->ReadByte();
	BYTE nHops	= pPacket->ReadByte();

	Hashes::Guid oGUID;
	pPacket->Read( oGUID );

	if ( strVendor.GetLength() != 0 )
	{
		CHostCacheHost* pHost = HostCache.Gnutella2.Add( (IN_ADDR*)&nAddress, nPort, 0, strVendor );
		if (pHost != NULL)
		{
			if ( bHSCurrent )
			{
				pHost->m_nUserCount = nLeaf;
				if ( bHSMax )
					pHost->m_nUserLimit = nMaxLeaf;
			}
		}
	}
	
	if ( nTTL > 0 && nHops < 255 )
	{
		m_pGUIDCache->Add( oGUID, this );

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
	if ( m_nNodeType == ntLeaf && m_bObsoleteClient )
	{
		Statistics.Current.Gnutella2.Dropped++;
		m_nDropCount++;
		return TRUE;
	}

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
	if ( pSearch->m_oSHA1 || pSearch->m_oBTH || pSearch->m_oED2K || pSearch->m_oTiger || pSearch->m_oMD5 )
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
			CSecureRule* pRule = Security.Ban( &m_pHost.sin_addr, ban30Mins, FALSE );
			if ( pRule ) pRule->m_sComment = _T("Blacklisted due to excess traffic");
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
	if ( ! pPacket->m_bCompound || m_nNodeType != ntLeaf || m_bObsoleteClient )
	{
		Statistics.Current.Gnutella2.Dropped++;
		m_nDropCount++;
		return TRUE;
	}

	DWORD nLength, nAddress = 0;
	BOOL bCacheOkay = TRUE;
	G2_PACKET nType;
	WORD nPort = 0;

	while ( pPacket->ReadPacket( nType, nLength ) )
	{
		DWORD nOffset = pPacket->m_nPosition + nLength;

		if ( nType == G2_PACKET_QUERY_ADDRESS && nLength >= 6 )
		{
			nAddress	= pPacket->ReadLongLE();
			nPort		= pPacket->ReadShortBE();
		}
		else if ( nType == G2_PACKET_QUERY_REFRESH )
		{
			bCacheOkay = FALSE;
		}

		pPacket->m_nPosition = nOffset;
	}

	if ( Network.IsFirewalledAddress( &nAddress, TRUE ) || 
		 0 == nPort ||  Network.IsReserved( (IN_ADDR*)&nAddress ) ) return TRUE;

	CHostCacheHost* pCached = bCacheOkay ? HostCache.Gnutella2.Find( (IN_ADDR*)&nAddress ) : NULL;

	if ( pCached != NULL && pCached->m_nKeyValue != 0 &&
		 pCached->m_nKeyHost == Network.m_pHost.sin_addr.S_un.S_addr )
	{
		CG2Packet* pAnswer = CG2Packet::New( G2_PACKET_QUERY_KEY_ANS, TRUE );
		pAnswer->WritePacket( G2_PACKET_QUERY_ADDRESS, 6 );
		pAnswer->WriteLongLE( nAddress );
		pAnswer->WriteShortBE( nPort );
		pAnswer->WritePacket( G2_PACKET_QUERY_KEY, 4 );
		pAnswer->WriteLongBE( pCached->m_nKeyValue );
		pAnswer->WritePacket( G2_PACKET_QUERY_CACHED, 0 );
		Send( pAnswer );
	}
	else
	{
		CG2Packet* pRequest = CG2Packet::New( G2_PACKET_QUERY_KEY_REQ, TRUE );
		pRequest->WritePacket( G2_PACKET_SEND_ADDRESS, 4 );
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

	G2_PACKET nType;
	DWORD nLength;

	while ( pPacket->ReadPacket( nType, nLength ) )
	{
		DWORD nOffset = pPacket->m_nPosition + nLength;

		if ( nType == G2_PACKET_QUERY_KEY && nLength >= 4 )
		{
			nKey = pPacket->ReadLongBE();
		}
		else if ( nType == G2_PACKET_QUERY_ADDRESS && nLength >= 6 )
		{
			nAddress	= pPacket->ReadLongLE();
			nPort		= pPacket->ReadShortBE();
		}
		else if ( nType == G2_PACKET_QUERY_CACHED )
		{
			m_bCachedKeys = TRUE;
		}

		pPacket->m_nPosition = nOffset;
	}

	theApp.Message( MSG_DEBUG, _T("Got a query key for %s:%i via neighbour %s: 0x%x"),
		(LPCTSTR)CString( inet_ntoa( *(IN_ADDR*)&nAddress ) ), nPort, (LPCTSTR)m_sAddress, nKey );

	if ( Network.IsFirewalledAddress( &nAddress ) || 
		 0 == nPort || Network.IsReserved( (IN_ADDR*)&nAddress ) ) return TRUE;

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

	if ( Security.IsDenied( (IN_ADDR*)&nAddress ) ||
		Network.IsReserved( (IN_ADDR*)&nAddress ) )
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

	pProfile->WritePacket( G2_PACKET_XML, pProfile->GetStringLen( strXML ) );
	pProfile->WriteString( strXML, FALSE );

	Send( pProfile, TRUE, TRUE );

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CG2Neighbour USER PROFILE DELIVERY packet handler

BOOL CG2Neighbour::OnProfileDelivery(CG2Packet* pPacket)
{
	if ( ! pPacket->m_bCompound ) return TRUE;

	G2_PACKET nType;
	DWORD nLength;

	while ( pPacket->ReadPacket( nType, nLength ) )
	{
		DWORD nOffset = pPacket->m_nPosition + nLength;

		if ( nType == G2_PACKET_XML )
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
	UNUSED_ALWAYS(pPacket);

	return TRUE;
}

BOOL CG2Neighbour::OnModeChangeAck(CG2Packet* pPacket)
{
	UNUSED_ALWAYS(pPacket);
	return TRUE;
}

BOOL CG2Neighbour::OnPrivateMessage(CG2Packet* pPacket)
{
	UNUSED_ALWAYS(pPacket);
	return TRUE;
}

BOOL CG2Neighbour::OnClose(CG2Packet* pPacket)
{
	if ( pPacket->m_bCompound )
	{
		G2_PACKET nType;
		DWORD nLength;

		Hashes::Guid oTO;
		if ( pPacket->GetTo( oTO ) )
		{
			theApp.Message(MSG_SYSTEM, _T("Detected CLOSE packet with faked Destination. Ignoring the packet") );
			return TRUE;
		}

		while ( pPacket->ReadPacket( nType, nLength ) )
		{
			DWORD nNext = pPacket->m_nPosition + nLength;

			if ( nType == G2_PACKET_CACHED_HUB && nLength >= 6 )
			{
				// there would be Hub node addresses in /CLOSE/CH for cache/alt-hub
				// NOTE: this is ARRAY of 6Byte Addresses.
			}

			pPacket->m_nPosition = nNext;
		}
	}
	
	if ( pPacket->GetRemaining() )
	{
		CString strReason = pPacket->ReadString( pPacket->GetRemaining() );
		theApp.Message(MSG_SYSTEM, _T("Remote Client is closing connection: %s"), (LPCTSTR)strReason );
	}

	return FALSE;
}
