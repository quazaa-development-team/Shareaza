//
// Datagrams.cpp
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
#include "Statistics.h"
#include "Network.h"
#include "Datagrams.h"
#include "Datagram.h"
#include "DatagramPart.h"
#include "Buffer.h"

#include "Handshakes.h"
#include "Neighbours.h"
#include "Neighbour.h"
#include "RouteCache.h"
#include "LocalSearch.h"
#include "SearchManager.h"
#include "QuerySearch.h"
#include "QueryHit.h"
#include "GProfile.h"
#include "CrawlSession.h"

#include "GGEP.h"
#include "G1Neighbour.h"
#include "G2Neighbour.h"
#include "G1Packet.h"
#include "G2Packet.h"
#include "EDClients.h"
#include "EDPacket.h"
#include "Security.h"
#include "HostCache.h"
#include "DiscoveryServices.h"
#include "QueryKeys.h"
#include "HubHorizon.h"
#include "LibraryMaps.h"
#include "VendorCache.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

#define HASH_SIZE		32
#define HASH_MASK		31

#define TEMP_BUFFER		4096
#define METER_MINIMUM	100
#define METER_LENGTH	24
#define METER_PERIOD	2000
#define METER_SECOND	1000

CDatagrams Datagrams;


//////////////////////////////////////////////////////////////////////
// CDatagrams construction

CDatagrams::CDatagrams()
{
	m_hSocket	= INVALID_SOCKET;
	m_nSequence	= 0;
	m_bStable	= FALSE;

	ZeroMemory( &m_mInput, sizeof(m_mInput) );
	ZeroMemory( &m_mOutput, sizeof(m_mOutput) );

	m_nInBandwidth	= m_nInFrags	= m_nInPackets	= 0;
	m_nOutBandwidth	= m_nOutFrags	= m_nOutPackets	= 0;
}

CDatagrams::~CDatagrams()
{
	Disconnect();
}

//////////////////////////////////////////////////////////////////////
// CDatagrams listen

BOOL CDatagrams::Listen()
{
	if ( m_hSocket != INVALID_SOCKET ) return FALSE;

	m_hSocket = socket( PF_INET, SOCK_DGRAM, IPPROTO_UDP );
	if ( m_hSocket == INVALID_SOCKET ) return FALSE;

	SOCKADDR_IN saHost;

	if ( Network.Resolve( Settings.Connection.InHost, Settings.Connection.InPort, &saHost ) )
	{
		// Inbound resolved
		if ( ! Settings.Connection.InBind ) 
			saHost.sin_addr.S_un.S_addr = 0;
		else
		{
			// Set the exclusive address option
			BOOL bVal = TRUE;
			setsockopt( m_hSocket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char*)&bVal, sizeof(bVal) );
		}
	}
	else if ( Network.Resolve( Settings.Connection.OutHost, Settings.Connection.InPort, &saHost ) )
	{
		// Outbound resolved
	}
	else
	{
		saHost = Network.m_pHost;
		if ( ! Settings.Connection.InBind ) 
			saHost.sin_addr.S_un.S_addr = 0;
		else
		{
			// Set the exclusive address option
			BOOL bVal = TRUE;
			setsockopt( m_hSocket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char*)&bVal, sizeof(bVal) );
		}
	}

	if ( bind( m_hSocket, (SOCKADDR*)&saHost, sizeof(saHost) ) == 0 )
	{
		theApp.Message( MSG_DEFAULT, IDS_NETWORK_LISTENING_UDP,
			(LPCTSTR)CString( inet_ntoa( saHost.sin_addr ) ), htons( saHost.sin_port ) );
	}

	WSAEventSelect( m_hSocket, Network.m_pWakeup, FD_READ );

	m_nBufferBuffer	= Settings.Gnutella2.UdpBuffers; // 256;
	m_pBufferBuffer	= new CBuffer[ m_nBufferBuffer ];
	m_pBufferFree	= m_pBufferBuffer;
	m_nBufferFree	= m_nBufferBuffer;

	CBuffer* pBuffer = m_pBufferBuffer;

	for ( DWORD nPos = m_nBufferBuffer ; nPos ; nPos--, pBuffer++ )
	{
		pBuffer->m_pNext = ( nPos == 1 ) ? NULL : ( pBuffer + 1 );
	}

	m_nInputBuffer	= Settings.Gnutella2.UdpInFrames; // 128;
	m_pInputBuffer	= new CDatagramIn[ m_nInputBuffer ];
	m_pInputFree	= m_pInputBuffer;

	CDatagramIn* pDGI = m_pInputBuffer;

	for ( DWORD nPos = m_nInputBuffer ; nPos ; nPos--, pDGI++ )
	{
		pDGI->m_pNextHash = ( nPos == 1 ) ? NULL : ( pDGI + 1 );
	}

	m_nOutputBuffer	= Settings.Gnutella2.UdpOutFrames; // 128;
	m_pOutputBuffer	= new CDatagramOut[ m_nOutputBuffer ];
	m_pOutputFree	= m_pOutputBuffer;

	CDatagramOut* pDGO = m_pOutputBuffer;

	for ( DWORD nPos = m_nOutputBuffer ; nPos ; nPos--, pDGO++ )
	{
		pDGO->m_pNextHash = ( nPos == 1 ) ? NULL : ( pDGO + 1 );
	}

	ZeroMemory( m_pInputHash,  sizeof(CDatagramIn*) * HASH_SIZE );
	ZeroMemory( m_pOutputHash, sizeof(CDatagramIn*) * HASH_SIZE );

	m_pInputFirst	= m_pInputLast	= NULL;
	m_pOutputFirst	= m_pOutputLast	= NULL;

	m_tLastWrite = 0;

	m_nInFrags	= m_nInPackets = 0;
	m_nOutFrags	= m_nOutPackets = 0;

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CDatagrams disconnect

void CDatagrams::Disconnect()
{
	if ( m_hSocket == INVALID_SOCKET ) return;

	// Set linger period to zero (it will close the socket immediatelly)
	// Default behaviour is to send data and close or timeout and close
	linger ls = {1, 0};
	int ret = setsockopt( m_hSocket, SOL_SOCKET, SO_LINGER, (char*)&ls, sizeof(ls) );

	shutdown( m_hSocket, SD_RECEIVE );
	ret = closesocket( m_hSocket );
	m_hSocket = INVALID_SOCKET;

	delete [] m_pOutputBuffer;
	m_pOutputBuffer = NULL;
	m_nOutputBuffer = 0;
	m_pOutputFirst = m_pOutputLast = m_pOutputFree = NULL;

	delete [] m_pInputBuffer;
	m_pInputBuffer = NULL;
	m_nInputBuffer = 0;
	m_pInputFirst = m_pInputLast = m_pInputFree = NULL;

	delete [] m_pBufferBuffer;
	m_pBufferBuffer = NULL;
	m_nBufferBuffer = 0;

	m_nInBandwidth	= m_nInFrags	= m_nInPackets	= 0;
	m_nOutBandwidth	= m_nOutFrags	= m_nOutPackets	= 0;
}

//////////////////////////////////////////////////////////////////////
// CDatagrams stable test

BOOL CDatagrams::IsStable()
{
	if ( m_hSocket == INVALID_SOCKET ) return FALSE;
	if ( ! Network.IsListening() ) return FALSE;

	if ( Settings.Connection.FirewallStatus == CONNECTION_FIREWALLED )
		return FALSE;			// We know we are firewalled
	else if ( Settings.Connection.FirewallStatus == CONNECTION_OPEN )
		return TRUE;			// We know we are not firewalled
	else // ( Settings.Connection.FirewallStatus == CONNECTION_AUTO )
		return m_bStable;		// Use detected state
}

//////////////////////////////////////////////////////////////////////
// CDatagrams send

BOOL CDatagrams::Send(IN_ADDR* pAddress, WORD nPort, CPacket* pPacket, BOOL bRelease, LPVOID pToken, BOOL bAck)
{
	SOCKADDR_IN pHost;

	pHost.sin_family	= PF_INET;
	pHost.sin_addr		= *pAddress;
	pHost.sin_port		= htons( nPort );

	return Send( &pHost, pPacket, bRelease, pToken, bAck );
}

BOOL CDatagrams::Send(SOCKADDR_IN* pHost, CPacket* pPacket, BOOL bRelease, LPVOID pToken, BOOL bAck)
{
	ASSERT( pHost != NULL && pPacket != NULL );

	if ( m_hSocket == INVALID_SOCKET || Security.IsDenied( &pHost->sin_addr ) )
	{
		if ( bRelease ) pPacket->Release();
		return FALSE;
	}

	if ( pPacket->m_nProtocol == PROTOCOL_ED2K )
	{
		CBuffer pBuffer;

		((CEDPacket*)pPacket)->ToBufferUDP( &pBuffer );
		pPacket->SmartDump( NULL, &pHost->sin_addr, TRUE );
		if ( bRelease ) pPacket->Release();

		// Do not really get what kind of Hack it is.
		// if ( ntohs( pHost->sin_port ) != 4669 )	// Hack
		//{
			sendto( m_hSocket, (LPSTR)pBuffer.m_pBuffer, pBuffer.m_nLength, 0,
				(SOCKADDR*)pHost, sizeof(SOCKADDR_IN) );
		//}

		return TRUE;
	}
	else if ( pPacket->m_nProtocol == PROTOCOL_G1 )
	{
		// Quick hack
		CBuffer pBuffer;

		((CG1Packet*)pPacket)->ToBuffer( &pBuffer );
		pPacket->SmartDump( NULL, &pHost->sin_addr, TRUE );
		if ( bRelease ) pPacket->Release();

		sendto( m_hSocket, (LPSTR)pBuffer.m_pBuffer, pBuffer.m_nLength, 0,
			(SOCKADDR*)pHost, sizeof(SOCKADDR_IN) );

		m_nOutPackets++;

		return TRUE;
	}
	else if ( pPacket->m_nProtocol == PROTOCOL_G2 )
	{
		if ( m_pOutputFree == NULL || m_pBufferFree == NULL )
		{
			if ( m_pOutputLast == NULL )
			{
				if ( bRelease ) pPacket->Release();
				theApp.Message( MSG_DEBUG, _T("CDatagrams output frames exhausted.") );
				return FALSE;
			}
			Remove( m_pOutputLast );
		}

		if ( m_pBufferFree == NULL )
		{
			if ( bRelease ) pPacket->Release();
			theApp.Message( MSG_DEBUG, _T("CDatagrams output frames really exhausted.") );
			return FALSE;
		}

		CDatagramOut* pDG = m_pOutputFree;
		m_pOutputFree = m_pOutputFree->m_pNextHash;

		if ( m_nInFrags < 1 ) bAck = FALSE;

		pDG->Create( pHost, (CG2Packet*)pPacket, m_nSequence++, m_pBufferFree, bAck );

		m_pBufferFree = m_pBufferFree->m_pNext;
		m_nBufferFree--;

		pDG->m_pToken		= pToken;
		pDG->m_pNextTime	= NULL;
		pDG->m_pPrevTime	= m_pOutputFirst;

		if ( m_pOutputFirst )
			m_pOutputFirst->m_pNextTime = pDG;
		else
			m_pOutputLast = pDG;

		m_pOutputFirst = pDG;

		BYTE nHash	= BYTE( pHost->sin_addr.S_un.S_un_b.s_b1
			+ pHost->sin_addr.S_un.S_un_b.s_b2
			+ pHost->sin_addr.S_un.S_un_b.s_b3
			+ pHost->sin_addr.S_un.S_un_b.s_b4
			+ pHost->sin_port
			+ pDG->m_nSequence );

		CDatagramOut** pHash = m_pOutputHash + ( nHash & HASH_MASK );

		if ( *pHash ) (*pHash)->m_pPrevHash = &pDG->m_pNextHash;
		pDG->m_pNextHash = *pHash;
		pDG->m_pPrevHash = pHash;
		*pHash = pDG;

		m_nOutPackets++;

		pPacket->SmartDump( NULL, &pHost->sin_addr, TRUE );

#ifdef DEBUG_UDP
		pPacket->Debug( _T("UDP Out") );
		theApp.Message( MSG_DEBUG, _T("UDP: Queued (#%i) x%i for %s:%lu"),
			pDG->m_nSequence, pDG->m_nCount,
			(LPCTSTR)CString( inet_ntoa( pDG->m_pHost.sin_addr ) ),
			htons( pDG->m_pHost.sin_port ) );
#endif

		if ( bRelease ) pPacket->Release();

		TryWrite();

		return TRUE;
	}

	if ( bRelease ) pPacket->Release();
	return FALSE;
}

//////////////////////////////////////////////////////////////////////
// CDatagrams purge outbound fragments with a specified token

void CDatagrams::PurgeToken(LPVOID pToken)
{
	CSingleLock pLock( &Network.m_pSection );
	if ( ! pLock.Lock( 100 ) ) return;

	int nCount = 0;

	for ( CDatagramOut* pDG = m_pOutputLast ; pDG ; )
	{
		CDatagramOut* pNext = pDG->m_pNextTime;

		if ( pDG->m_pToken == pToken )
		{
			Remove( pDG );
			nCount++;
		}

		pDG = pNext;
	}

	if ( nCount ) theApp.Message( MSG_DEBUG, _T("CDatagrams::PurgeToken() = %i"), nCount );
}

//////////////////////////////////////////////////////////////////////
// CDatagrams run event handler

void CDatagrams::OnRun()
{
	if ( m_hSocket == INVALID_SOCKET ) return;

	TryWrite();
	ManageOutput();

	do
	{
		ManagePartials();
	}
	while ( TryRead() );

	Measure();
}

//////////////////////////////////////////////////////////////////////
// CDatagrams measure

void CDatagrams::Measure()
{
	DWORD tCutoff		= GetTickCount() - METER_PERIOD;
	DWORD* pInHistory	= m_mInput.pHistory;
	DWORD* pInTime		= m_mInput.pTimes;
	DWORD* pOutHistory	= m_mOutput.pHistory;
	DWORD* pOutTime		= m_mOutput.pTimes;
	DWORD nInput		= 0;
	DWORD nOutput		= 0;

	for ( int tNow = METER_LENGTH ; tNow ; tNow-- )
	{
		if ( *pInTime >= tCutoff ) nInput += *pInHistory;
		if ( *pOutTime >= tCutoff ) nOutput += *pOutHistory;
		pInHistory++, pInTime++;
		pOutHistory++, pOutTime++;
	}

	m_nInBandwidth	= m_mInput.nMeasure		= nInput * 1000 / METER_PERIOD;
	m_nOutBandwidth	= m_mOutput.nMeasure	= nOutput * 1000 / METER_PERIOD;
}

//////////////////////////////////////////////////////////////////////
// CDatagrams write datagrams

BOOL CDatagrams::TryWrite()
{
	DWORD tNow		= GetTickCount();
	DWORD nLimit	= 0xFFFFFFFF;
	DWORD nTotal	= 0;

	if ( Settings.Live.BandwidthScale <= 100 )
	{
		DWORD tCutoff	= tNow - METER_SECOND;
		DWORD* pHistory	= m_mOutput.pHistory;
		DWORD* pTime	= m_mOutput.pTimes;
		DWORD nUsed		= 0;

		for ( int nSeek = METER_LENGTH ; nSeek ; nSeek--, pHistory++, pTime++ )
		{
			if ( *pTime >= tCutoff ) nUsed += *pHistory;
		}

		nLimit = Settings.Connection.OutSpeed * 128;
		if ( Settings.Bandwidth.UdpOut != 0 ) nLimit = Settings.Bandwidth.UdpOut;

		if ( Settings.Live.BandwidthScale < 100 )
		{
			nLimit = nLimit * Settings.Live.BandwidthScale / 100;
		}

		nLimit = ( nUsed >= nLimit ) ? 0 : ( nLimit - nUsed );
	}

	DWORD nLastHost = 0;

	while ( nLimit > 0 )
	{
        CDatagramOut* pDG = m_pOutputFirst;
		for ( ; pDG ; pDG = pDG->m_pPrevTime )
		{
			BYTE* pPacket;
			DWORD nPacket;

			if ( nLastHost == pDG->m_pHost.sin_addr.S_un.S_addr )
			{
				// Same host, skip it
			}
			else if ( pDG->GetPacket( tNow, &pPacket, &nPacket, m_nInFrags > 0 ) )
			{
				sendto( m_hSocket, (LPCSTR)pPacket, nPacket, 0,
					(SOCKADDR*)&pDG->m_pHost, sizeof(SOCKADDR_IN) );

				nLastHost = pDG->m_pHost.sin_addr.S_un.S_addr;

				if ( nLimit >= nPacket )
					nLimit -= nPacket;
				else
					nLimit = 0;

				m_tLastWrite = GetTickCount();
				nTotal += nPacket;
				m_nOutFrags++;

#ifdef DEBUG_UDP
				SGP_HEADER* pTemp = (SGP_HEADER*)pPacket;
				theApp.Message( MSG_DEBUG, _T("UDP: Sending (#%i) %i of %i to %s:%lu"),
					pDG->m_nSequence, pTemp->nPart, pTemp->nCount,
					(LPCTSTR)CString( inet_ntoa( pDG->m_pHost.sin_addr ) 0,
					htons( pDG->m_pHost.sin_port ) );
#endif

				break;
			}
		}

		if ( pDG == NULL ) break;
	}

	if ( m_mOutput.pHistory && nTotal )
	{
		if ( tNow - m_mOutput.tLastSlot < METER_MINIMUM )
		{
			m_mOutput.pHistory[ m_mOutput.nPosition ]	+= nTotal;
		}
		else
		{
			m_mOutput.nPosition = ( m_mOutput.nPosition + 1 ) % METER_LENGTH;
			m_mOutput.pTimes[ m_mOutput.nPosition ]		= tNow;
			m_mOutput.pHistory[ m_mOutput.nPosition ]	= nTotal;
			m_mOutput.tLastSlot = tNow;
		}
	}

	m_mOutput.nTotal += nTotal;
	Statistics.Current.Bandwidth.Outgoing += nTotal;

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CDatagrams manage output queue datagrams

void CDatagrams::ManageOutput()
{
	DWORD tNow = GetTickCount();

	for ( CDatagramOut* pDG = m_pOutputLast ; pDG ; )
	{
		CDatagramOut* pNext = pDG->m_pNextTime;

		if ( tNow - pDG->m_tSent > Settings.Gnutella2.UdpOutExpire )
		{
			Remove( pDG );
		}

		pDG = pNext;
	}
}

//////////////////////////////////////////////////////////////////////
// CDatagrams remove output datagrams

void CDatagrams::Remove(CDatagramOut* pDG)
{
	if ( pDG->m_pBuffer )
	{
		pDG->m_pBuffer->m_pNext = m_pBufferFree;
		m_pBufferFree = pDG->m_pBuffer;
		m_pBufferFree->Clear();
		pDG->m_pBuffer = NULL;
		m_nBufferFree++;
	}

	if ( pDG->m_pNextHash ) pDG->m_pNextHash->m_pPrevHash = pDG->m_pPrevHash;
	*(pDG->m_pPrevHash) = pDG->m_pNextHash;

	if ( pDG->m_pNextTime )
		pDG->m_pNextTime->m_pPrevTime = pDG->m_pPrevTime;
	else
		m_pOutputFirst = pDG->m_pPrevTime;

	if ( pDG->m_pPrevTime )
		pDG->m_pPrevTime->m_pNextTime = pDG->m_pNextTime;
	else
		m_pOutputLast = pDG->m_pNextTime;

	pDG->m_pNextHash = m_pOutputFree;
	m_pOutputFree = pDG;
}

//////////////////////////////////////////////////////////////////////
// CDatagrams read datagram

#define TEMP_BUFFER 4096

BOOL CDatagrams::TryRead()
{
	static BYTE pBuffer[ TEMP_BUFFER ];
	int nLength, nFromLen;
	SOCKADDR_IN pFrom;

	nFromLen = sizeof(pFrom);
	nLength	= recvfrom( m_hSocket, (LPSTR)pBuffer, TEMP_BUFFER, 0,
						(SOCKADDR*)&pFrom, &nFromLen );

	if ( nLength < 1 ) return FALSE;

	if ( m_mInput.pHistory && nLength > 0 )
	{
		DWORD tNow = GetTickCount();

		if ( tNow - m_mInput.tLastSlot < METER_MINIMUM )
		{
			m_mInput.pHistory[ m_mInput.nPosition ] += nLength;
		}
		else
		{
			m_mInput.nPosition = ( m_mInput.nPosition + 1 ) % METER_LENGTH;
			m_mInput.pTimes[ m_mInput.nPosition ]	= tNow;
			m_mInput.pHistory[ m_mInput.nPosition ]	= nLength;
			m_mInput.tLastSlot = tNow;
		}
	}

	m_mInput.nTotal += nLength;
	Statistics.Current.Bandwidth.Incoming += nLength;

	if ( Security.IsAccepted( &pFrom.sin_addr ) )
	{
		OnDatagram( &pFrom, pBuffer, nLength );
	}

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CDatagrams datagram handler

BOOL CDatagrams::OnDatagram(SOCKADDR_IN* pHost, BYTE* pBuffer, DWORD nLength)
{
	GNUTELLAPACKET* pG1UDP = (GNUTELLAPACKET*)pBuffer;
	
	// if it is Gnutella UDP packet, packet size is 23 bytes or bigger.
	if ( nLength >= sizeof(GNUTELLAPACKET)
		// if it is Gnutella packet, packet header size + payload length written in length field = UDP packet size
		&& ( sizeof(GNUTELLAPACKET) + pG1UDP->m_nLength ) == nLength )
	{
		CG1Packet* pG1Packet = CG1Packet::New( (GNUTELLAPACKET*)pG1UDP );
		ASSERT( pG1Packet->m_nReference == 1 );
		pG1Packet->SmartDump( NULL, &pHost->sin_addr, FALSE );
		if ( OnPacket( pHost, pG1Packet ) )
		{
			pG1Packet->Release();
			return TRUE;
		}
		else
		{
			pG1Packet->Release();
		}
	}

	ED2K_UDP_HEADER* pMULE = (ED2K_UDP_HEADER*)pBuffer;

	if ( nLength > sizeof(*pMULE) && (
		 pMULE->nProtocol == ED2K_PROTOCOL_EDONKEY ||
		 pMULE->nProtocol == ED2K_PROTOCOL_EMULE ||
		 pMULE->nProtocol == ED2K_PROTOCOL_PACKED ) )
	{
		CEDPacket* pPacket = CEDPacket::New( pMULE, nLength );

		if ( ! pPacket->InflateOrRelease( ED2K_PROTOCOL_EMULE ) )
		{
			pPacket->SmartDump( NULL, &pHost->sin_addr, FALSE );
			EDClients.OnUDP( pHost, pPacket );
			pPacket->Release();
		}

		return TRUE;
	}

	SGP_HEADER* pSGP = (SGP_HEADER*)pBuffer;

	if ( nLength >= sizeof(*pSGP) && strncmp( pSGP->szTag, SGP_TAG_2, 3 ) == 0 )
	{
		if ( pSGP->nPart == 0 ) return FALSE;
		if ( pSGP->nCount && pSGP->nPart > pSGP->nCount ) return FALSE;

		nLength -= sizeof(*pSGP);

		if ( pSGP->nCount )
		{
			OnReceiveSGP( pHost, pSGP, nLength );
		}
		else
		{
			OnAcknowledgeSGP( pHost, pSGP, nLength );
		}

		return TRUE;
	}
	theApp.Message( MSG_ERROR, _T("Recieved unknown UDP packet type") );

	return FALSE;
}

//////////////////////////////////////////////////////////////////////
// CDatagrams SGP receive handler

BOOL CDatagrams::OnReceiveSGP(SOCKADDR_IN* pHost, SGP_HEADER* pHeader, DWORD nLength)
{
#ifdef DEBUG_UDP
	theApp.Message( MSG_DEBUG, _T("UDP: Received (#%i) %i of %i from %s"),
		pHeader->nSequence, pHeader->nPart, pHeader->nCount,
		(LPCTSTR)CString( inet_ntoa( pHost->sin_addr ) ) );
#endif

	m_nInFrags++;

	if ( pHeader->nFlags & SGP_ACKNOWLEDGE )
	{
		SGP_HEADER pAck;

		strncpy( pAck.szTag, SGP_TAG_2, 3 );
		pAck.nFlags		= 0;
		pAck.nSequence	= pHeader->nSequence;
		pAck.nPart		= pHeader->nPart;
		pAck.nCount		= 0;

		sendto( m_hSocket, (LPCSTR)&pAck, sizeof(pAck), 0,
			(SOCKADDR*)pHost, sizeof(SOCKADDR_IN) );
	}

	BYTE nHash	= BYTE( pHost->sin_addr.S_un.S_un_b.s_b1
				+ pHost->sin_addr.S_un.S_un_b.s_b2
				+ pHost->sin_addr.S_un.S_un_b.s_b3
				+ pHost->sin_addr.S_un.S_un_b.s_b4
				+ pHost->sin_port
				+ pHeader->nSequence );

	CDatagramIn** pHash = m_pInputHash + ( nHash & HASH_MASK );

    CDatagramIn* pDG = *pHash;
	for ( ; pDG ; pDG = pDG->m_pNextHash )
	{
		if (	pDG->m_pHost.sin_addr.S_un.S_addr == pHost->sin_addr.S_un.S_addr &&
				pDG->m_pHost.sin_port == pHost->sin_port &&
				pDG->m_nSequence == pHeader->nSequence &&
				pDG->m_nCount == pHeader->nCount )
		{
			if ( pDG->Add( pHeader->nPart, &pHeader[1], nLength ) )
			{
				if ( CG2Packet* pPacket = pDG->ToG2Packet() )
				{
					try
					{
						OnPacket( pHost, pPacket );
					}
					catch ( CException* pException )
					{
						pException->Delete();
					}

					pPacket->Release();
				}

				// Keep it to check sequence numbers
				// Remove( pDG );
			}

			return TRUE;
		}
	}

	while ( m_pInputFree == NULL || m_nBufferFree < pHeader->nCount )
	{
		if ( m_pInputLast == NULL ) return FALSE;
		Remove( m_pInputLast );
	}

	if ( m_nBufferFree < pHeader->nCount ) return FALSE;

	pDG = m_pInputFree;

	pDG->Create( pHost, pHeader->nFlags, pHeader->nSequence, pHeader->nCount );

	for ( WORD nPart = 0 ; nPart < pDG->m_nCount ; nPart++ )
	{
		ASSERT( pDG->m_pBuffer[ nPart ] == NULL );
		pDG->m_pBuffer[ nPart ] = m_pBufferFree;
		m_pBufferFree = m_pBufferFree->m_pNext;
		m_nBufferFree--;
	}

	if ( pDG->Add( pHeader->nPart, &pHeader[1], nLength ) )
	{
		if ( CG2Packet* pPacket = pDG->ToG2Packet() )
		{
			try
			{
				OnPacket( pHost, pPacket );
			}
			catch ( CException* pException )
			{
				pException->Delete();
			}
			pPacket->Release();
		}

		// Don't remove it, keep it to check sequence numbers
		// Remove( pDG, TRUE );
	}

	// Always add it to the list

	pDG->m_pNextTime = NULL;
	pDG->m_pPrevTime = m_pInputFirst;

	if ( m_pInputFirst )
		m_pInputFirst->m_pNextTime = pDG;
	else
		m_pInputLast = pDG;

	m_pInputFirst = pDG;
	m_pInputFree = pDG->m_pNextHash;

	if ( *pHash ) (*pHash)->m_pPrevHash = &pDG->m_pNextHash;
	pDG->m_pNextHash = *pHash;
	pDG->m_pPrevHash = pHash;
	*pHash = pDG;

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CDatagrams SGP acknowledgement handler

BOOL CDatagrams::OnAcknowledgeSGP(SOCKADDR_IN* pHost, SGP_HEADER* pHeader, DWORD /*nLength*/)
{
#ifdef DEBUG_UDP
	theApp.Message( MSG_DEBUG, _T("UDP: Received ack (#%i) %i from %s"),
		pHeader->nSequence, pHeader->nPart, (LPCTSTR)CString( inet_ntoa( pHost->sin_addr ) ) );
#endif

	BYTE nHash	= BYTE( pHost->sin_addr.S_un.S_un_b.s_b1
				+ pHost->sin_addr.S_un.S_un_b.s_b2
				+ pHost->sin_addr.S_un.S_un_b.s_b3
				+ pHost->sin_addr.S_un.S_un_b.s_b4
				+ pHost->sin_port
				+ pHeader->nSequence );

	CDatagramOut** pHash = m_pOutputHash + ( nHash & HASH_MASK );

	for ( CDatagramOut* pDG = *pHash ; pDG ; pDG = pDG->m_pNextHash )
	{
		if (	pDG->m_pHost.sin_addr.S_un.S_addr == pHost->sin_addr.S_un.S_addr &&
				pDG->m_pHost.sin_port == pHost->sin_port &&
				pDG->m_nSequence == pHeader->nSequence )
		{
			if ( pDG->Acknowledge( pHeader->nPart ) ) Remove( pDG );
			return TRUE;
		}
	}

	return FALSE;
}

//////////////////////////////////////////////////////////////////////
// CDatagrams manage partial datagrams

void CDatagrams::ManagePartials()
{
	DWORD tNow = GetTickCount();

	for ( CDatagramIn* pDG = m_pInputLast ; pDG ; )
	{
		CDatagramIn* pNext = pDG->m_pNextTime;

		if ( tNow - pDG->m_tStarted > Settings.Gnutella2.UdpInExpire )
		{
			Remove( pDG );
		}

		pDG = pNext;
	}
}

//////////////////////////////////////////////////////////////////////
// CDatagrams remove a partiallly received datagram

void CDatagrams::Remove(CDatagramIn* pDG, BOOL bReclaimOnly)
{
	for ( int nPart = 0 ; nPart < pDG->m_nCount ; nPart++ )
	{
		if ( pDG->m_pBuffer[ nPart ] )
		{
			pDG->m_pBuffer[ nPart ]->m_pNext = m_pBufferFree;
			m_pBufferFree = pDG->m_pBuffer[ nPart ];
			m_pBufferFree->Clear();
			pDG->m_pBuffer[ nPart ] = NULL;
			m_nBufferFree++;
		}
	}

	if ( bReclaimOnly ) return;

	if ( pDG->m_pNextHash ) pDG->m_pNextHash->m_pPrevHash = pDG->m_pPrevHash;
	*(pDG->m_pPrevHash) = pDG->m_pNextHash;

	if ( pDG->m_pNextTime )
		pDG->m_pNextTime->m_pPrevTime = pDG->m_pPrevTime;
	else
		m_pInputFirst = pDG->m_pPrevTime;

	if ( pDG->m_pPrevTime )
		pDG->m_pPrevTime->m_pNextTime = pDG->m_pNextTime;
	else
		m_pInputLast = pDG->m_pNextTime;

	pDG->m_pNextHash = m_pInputFree;
	m_pInputFree = pDG;
}

//////////////////////////////////////////////////////////////////////
// CDatagrams G1UDP packet handler

BOOL CDatagrams::OnPacket(SOCKADDR_IN* pHost, CG1Packet* pPacket)
{
	theApp.Message( MSG_SYSTEM, _T("G1UDP: Received Type(0x%x) TTL(%i) Hops(%i) size(%i) from %s:%i"),
		pPacket->m_nType, pPacket->m_nTTL, pPacket->m_nHops, pPacket->m_nLength,
		(LPCTSTR)CString( inet_ntoa( pHost->sin_addr ) ),pHost->sin_port );

	m_nInPackets++;
	switch ( pPacket->m_nType )
	{
		case G1_PACKET_PING:		return OnPing( pHost, pPacket );			// Ping
		case G1_PACKET_PONG:		return OnPong( pHost, pPacket );			// Pong, response to a ping
		case G1_PACKET_BYE:			return OnBye( pHost, pPacket );				// Bye message
		case G1_PACKET_QUERY_ROUTE:	return OnCommonQueryHash( pHost, pPacket );	// Common query hash
		case G1_PACKET_VENDOR:		return OnVendor( pHost, pPacket );			// Vendor-specific message
		case G1_PACKET_VENDOR_APP:	return OnVendor( pHost, pPacket );			// Vendor-specific message
		case G1_PACKET_PUSH:		return OnPush( pHost, pPacket );			// Push open a connection
		case G1_PACKET_RUDP:		return OnRUDP( pHost, pPacket );				// Push open a connection
		case G1_PACKET_QUERY:		return OnQuery( pHost, pPacket );			// Search query
		case G1_PACKET_HIT:			return OnHit( pHost, pPacket );				// Hit, a search result
	}
	return FALSE;
}

//////////////////////////////////////////////////////////////////////
// CDatagrams G2UDP packet handler

BOOL CDatagrams::OnPacket(SOCKADDR_IN* pHost, CG2Packet* pPacket)
{
	pPacket->SmartDump( NULL, &pHost->sin_addr, FALSE );

	m_nInPackets++;

	if ( Network.RoutePacket( pPacket ) ) return TRUE;

	if ( pPacket->IsType( G2_PACKET_QUERY ) )
	{
		return OnQuery( pHost, pPacket );
	}
	else if ( pPacket->IsType( G2_PACKET_QUERY_KEY_REQ ) )
	{
		return OnQueryKeyRequest( pHost, pPacket );
	}
	else if ( pPacket->IsType( G2_PACKET_HIT ) )
	{
		return OnHit( pHost, pPacket );
	}
	else if ( pPacket->IsType( G2_PACKET_HIT_WRAP ) )
	{
		return OnHit( pHost, pPacket );
	}
	else if ( pPacket->IsType( G2_PACKET_QUERY_ACK ) )
	{
		return OnQueryAck( pHost, pPacket );
	}
	else if ( pPacket->IsType( G2_PACKET_QUERY_KEY_ANS ) )
	{
		return OnQueryKeyAnswer( pHost, pPacket );
	}
	else if ( pPacket->IsType( G2_PACKET_PING ) )
	{
		return OnPing( pHost, pPacket );
	}
	else if ( pPacket->IsType( G2_PACKET_PONG ) )
	{
		return OnPong( pHost, pPacket );
	}
	else if ( pPacket->IsType( G2_PACKET_PUSH ) )
	{
		return OnPush( pHost, pPacket );
	}
	else if ( pPacket->IsType( G2_PACKET_CRAWL_REQ ) )
	{
		return OnCrawlRequest( pHost, pPacket );
	}
	else if ( pPacket->IsType( G2_PACKET_CRAWL_ANS ) )
	{
		return OnCrawlAnswer( pHost, pPacket );
	}
	else if ( pPacket->IsType( G2_PACKET_MODE_CHANGE_REQ ) )
	{
		return OnModeChangeReq( pHost, pPacket );
	}
	else if ( pPacket->IsType( G2_PACKET_MODE_CHANGE_ACK ) )
	{
		return OnModeChangeAck( pHost, pPacket );
	}
	else if ( pPacket->IsType( G2_PACKET_PRIVATE_MESSAGE ) )
	{
		return OnPrivateMessage( pHost, pPacket );
	}
	else if ( pPacket->IsType( G2_PACKET_CLOSE ) )
	{
		return OnClose( pHost, pPacket );
	}
	else if ( pPacket->IsType( G2_PACKET_KHL_ANS ) )
	{
		return OnKHLA( pHost, pPacket );
	}
	else if ( pPacket->IsType( G2_PACKET_KHL_REQ ) )
	{
		return OnKHLR( pHost, pPacket );
	}
	return FALSE;
}

namespace
{
	struct CompareNums
	{
		bool operator()(WORD lhs, WORD rhs) const
		{
			return lhs > rhs;
		}
	};
}

//////////////////////////////////////////////////////////////////////
// CDatagrams PING packet handler for G1UDP

BOOL CDatagrams::OnPing(SOCKADDR_IN* pHost, CG1Packet* pPacket)
{
	BOOL bSCP = FALSE;
	// If this ping packet strangely has length, and the remote computer does GGEP blocks
	if ( pPacket->m_nLength )
	{
		CGGEPBlock pGGEP;
		// There is a GGEP block here, and checking and adjusting the TTL and hops counts worked
		if ( pGGEP.ReadFromPacket( pPacket ) )
		{
			if ( CGGEPItem* pItem = pGGEP.Find( _T("SCP") ) )
			{
				bSCP = TRUE;
			}
		}
	}

	CGGEPBlock pGGEP;
	// Received SCP GGEP, send 5 random hosts from the cache
	// Since we do not provide leaves, ignore the preference data
	if ( bSCP )
	{
		CGGEPItem* pItem = pGGEP.Add( _T("IPP") );
		DWORD nCount = min( DWORD(50), HostCache.Gnutella1.CountHosts() );
		WORD nPos = 0;

		// Create 5 random positions from 0 to 50 in the descending order
		std::vector< WORD > pList;
		pList.reserve( Settings.Gnutella1.MaxHostsInPongs );
		for ( WORD nNo = 0 ; nNo < Settings.Gnutella1.MaxHostsInPongs ; nNo++ )
		{
			pList.push_back( (WORD)( ( nCount + 1 ) * rand() / ( RAND_MAX + (float)nCount ) ) );
		}
		std::sort( pList.begin(), pList.end(), CompareNums() );

		nCount = Settings.Gnutella1.MaxHostsInPongs;
		CHostCacheHost* pHost = HostCache.Gnutella1.GetNewest();
		while ( pHost && nCount )
		{
			nPos = pList.back(); // take the smallest value;
			pList.pop_back(); // remove it
			for ( ; pHost && nPos-- ; pHost = pHost->m_pPrevTime );

			// We won't provide Shareaza hosts for G1 cache, since users may disable
			// G1 and it will pollute the host caches ( ??? )
			if ( pHost && pHost->m_pVendor != VendorCache.m_pShareaza )
			{
				pItem->Write( (void*)&pHost->m_pAddress, 4 );
				pItem->Write( (void*)&pHost->m_nPort, 2 );
				theApp.Message( MSG_DEBUG, _T("Sending G1 host through pong (%s:%i)"), 
					(LPCTSTR)CString( inet_ntoa( *(IN_ADDR*)&pHost->m_pAddress ) ), pHost->m_nPort ); 
				nCount--;
			}
			if ( nCount == 0 ) break;
		}

		if ( nCount == (DWORD)Settings.Gnutella1.MaxHostsInPongs ) bSCP = FALSE; // the cache is empty
	}

	// TEST: Try indicate GUESS supported Node.  (GGEP "GUE")
	pGGEP.Add( L"GUE" );

	//Give Vender code
	CGGEPItem * pVC = pGGEP.Add( L"VC");
	pVC->WriteUTF8( SHAREAZA_VENDOR_T );
	pVC->WriteUTF8( L"A" );

	// Make a new pong packet, the response to a ping
	CG1Packet* pPong = CG1Packet::New(			// Gets it quickly from the Gnutella packet pool
		G1_PACKET_PONG,							// We're making a pong packet
		pPacket->m_nHops,						// Give it TTL same as HOP count of received PING packet
		pPacket->m_oGUID);						// Give it the same GUID as the ping

	// Get statistics about how many files we are sharing
	QWORD nMyVolume;
	DWORD nMyFiles;
	LibraryMaps.GetStatistics( &nMyFiles, &nMyVolume );

	// Start the pong's payload with the IP address and port number from the Network object (do)
	pPong->WriteShortLE( htons( Network.m_pHost.sin_port ) );
	pPong->WriteLongLE( Network.m_pHost.sin_addr.S_un.S_addr );

	// Then, write in the information about how many files we are sharing
	pPong->WriteLongLE( nMyFiles );
	pPong->WriteLongLE( (DWORD)nMyVolume );

	if ( !pGGEP.IsEmpty() ) pGGEP.Write( pPong );

	// Send the pong packet to the remote computer we are currently looping on
	Send( pHost, pPong );
	theApp.Message( MSG_SYSTEM, _T("G1UDP: Sent Pong to %s"), (LPCTSTR)CString( inet_ntoa( pHost->sin_addr ) ) );

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CDatagrams PING packet handler for G2UDP
BOOL CDatagrams::OnPing(SOCKADDR_IN* pHost, CG2Packet* pPacket)
{
	CHAR szType[9];
	DWORD nLength;
	BOOL bConnectRequest = FALSE; // add
	BOOL bHubMode = FALSE; // add
	BOOL bVersion = FALSE; // add
	BOOL bSupportedFeature = FALSE; // add
	BOOL bWantSourceAddr = FALSE; // add
	CString sVendorCode, sName, sVersion;

	while ( pPacket->ReadPacket( szType, nLength ) )
	{
		DWORD nNext = pPacket->m_nPosition + nLength;

		if ( strcmp( szType, "CR" ) == 0 && nLength >= 1 ) //add G2/1.1, used on GnucDNA
		{
			bHubMode = pPacket->ReadByte();
			bConnectRequest = TRUE;
		}
		else if ( strcmp( szType, "VER" ) == 0 )
		{
			bVersion = TRUE;
		}
		else if ( strcmp( szType, "SFL" ) == 0 ) // Supported Feature List
		{
			bSupportedFeature = TRUE;
		}
		else if ( strcmp( szType, "SIPP" ) == 0 )	// Sender want IP:Port of the source address of this paclet
		{											// in order to detect Source NAT
			bWantSourceAddr = TRUE;
		}

		pPacket->m_nPosition = nNext;
	}

	CG2Packet* pPong = CG2Packet::New( G2_PACKET_PONG, TRUE );
	if (bVersion)
	{
		sVendorCode = VENDOR_CODE;
		sName = CLIENT_NAME;
		sVersion = theApp.m_sVersion;
		pPong->WritePacket( "VC", pPong->GetStringLen( sVendorCode ) );
		pPong->WriteString( sVendorCode, FALSE );
		pPong->WritePacket( "AN", pPong->GetStringLen( sName ) );
		pPong->WriteString( sName, FALSE );
		pPong->WritePacket( "AV", pPong->GetStringLen( sVersion ) );
		pPong->WriteString( sVersion, FALSE );

	}
	if ( bWantSourceAddr )
	{
		pPong->WritePacket("SIPP", 6);
		pPong->WriteLongLE( pHost->sin_addr.S_un.S_addr );
		pPong->WriteShortBE( htons( pHost->sin_port ) );
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

		// end compound
		pSFL->WriteByte(0);

		// adding SFL packet as conpound packet in PONG
		pPong->WritePacket( pSFL );
		pSFL->Release();
	}
	Send( pHost, pPong, TRUE, NULL, FALSE );

	return TRUE;
}

BOOL CDatagrams::OnPong(SOCKADDR_IN* pHost, CG1Packet* pPacket)
{
	Statistics.Current.Gnutella1.PongsReceived++;
	// If the pong is too short, or the pong is too long and settings say we should watch that
	if ( pPacket->m_nLength < 14 || ( pPacket->m_nLength > 14 && Settings.Gnutella1.StrictPackets && !Settings.Gnutella1.EnableGGEP ) )
	{
		// Pong packets should be 14 bytes long, drop this strangely sized one
		theApp.Message( MSG_ERROR, IDS_PROTOCOL_SIZE_PONG, (LPCTSTR)inet_ntoa( pHost->sin_addr ) );
		Statistics.Current.Gnutella1.Dropped++;
		return TRUE; // Don't disconnect from the remote computer, though
	}

	// Read information from the pong packet
	WORD nPort     = pPacket->ReadShortLE(); // 2 bytes, port number (do) of us? the remote computer? the computer that sent the packet?
	DWORD nAddress = pPacket->ReadLongLE();  // 4 bytes, IP address
	DWORD nFiles   = pPacket->ReadLongLE();  // 4 bytes, the number of files the source computer is sharing
	DWORD nVolume  = pPacket->ReadLongLE();  // 4 bytes, the total size of all those files

	CDiscoveryService * pService = DiscoveryServices.GetByAddress( &(pHost->sin_addr) , ntohs(pHost->sin_port), 3 );

	// If that IP address is in our list of computers to not talk to, except ones in UHC list in discovery
	if ( pService == NULL && Security.IsDenied( (IN_ADDR*)&nAddress ) )
	{
		// Record the packet as dropped, do nothing else, and leave now
		Statistics.Current.Gnutella1.Dropped++;
		return TRUE;
	}

	// If the pong is bigger than 14 bytes, and the remote compuer told us in the handshake it supports GGEP blocks
	if ( pPacket->m_nLength > 14 && Settings.Gnutella1.EnableGGEP )
	{
		CGGEPBlock pGGEP;
		// There is a GGEP block here, and checking and adjusting the TTL and hops counts worked
		if ( pGGEP.ReadFromPacket( pPacket ) )
		{
			int nCount = 0;
			CGGEPItem* pIPPs = pGGEP.Find( L"IPP", 6 );
			// GDNA has a bug in their code; they send DIP but receive DIPP
			CGGEPItem* pGDNAs = pGGEP.Find( L"DIPP", 6 );
			if ( !pGDNAs ) pGDNAs = pGGEP.Find( L"DIP", 6 );

			// We got a response to SCP extension, add hosts to cache if IPP extension exists
			while ( pIPPs || pGDNAs )
			{
				CGGEPItem* pItem = pIPPs ? pIPPs : pGDNAs;
				CString str = pGDNAs ? L"GDNA" : L"G1";
				// The first four bytes represent the IP address and the last two represent the port
				// The length of the number of bytes of IPP must be divisible by 6
				if ( ( pItem->m_nLength - pItem->m_nPosition ) % 6 == 0 )
				{
					while ( pItem->m_nPosition != pItem->m_nLength )
					{
						DWORD nAddress = 0;
						WORD nPort = 0;
						pItem->Read( (void*)&nAddress, 4 );
						pItem->Read( (void*)&nPort, 2 );
						if ( nPort != 0 )
						{
							CHostCacheHost * pCachedHost;
							theApp.Message( MSG_DEBUG, _T("Got %s host through pong (%s:%i)"), 
								(LPCTSTR)str, (LPCTSTR)CString( inet_ntoa( *(IN_ADDR*)&nAddress ) ), nPort ); 
							pCachedHost = HostCache.Gnutella1.Add( (IN_ADDR*)&nAddress, nPort, 0, pGDNAs ? (LPCTSTR)str : NULL );
							// Add to separate cache to have a quick access only to GDNAs
							if ( pGDNAs )
								HostCache.G1DNA.Add( (IN_ADDR*)&nAddress, nPort, 0, (LPCTSTR)str );

							if ( pCachedHost != NULL ) nCount++;
						}
					}
				}
				if ( pIPPs )
					pIPPs = NULL;
				else if ( pGDNAs )
					pGDNAs = NULL;

				if ( pService != NULL )
				{
					pService->OnSuccess();
					pService->m_nHosts = nCount;
				}
			}

		}
		else
		{
			// It's not, drop the packet, but stay connected
			theApp.Message( MSG_ERROR, IDS_PROTOCOL_GGEP_REQUIRED, (LPCTSTR)inet_ntoa( pHost->sin_addr ) );
			Statistics.Current.Gnutella1.Dropped++;
			return TRUE;
		}
	}

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CDatagrams PONG packet handler

BOOL CDatagrams::OnPong(SOCKADDR_IN* pHost, CG2Packet* pPacket)
{
	if ( ! pPacket->m_bCompound ) return TRUE;

	BOOL bRelayed = FALSE, bCompound = FALSE;
	CHAR szType[9];
	DWORD nLength;
	CString sVendorCode, sName, sVersion;
	SOCKADDR_IN	MyAddr;

	MyAddr.sin_addr.S_un.S_addr = 0;
	MyAddr.sin_port = 0;

	while ( pPacket->ReadPacket( szType, nLength, &bCompound ) )
	{
		DWORD nOffset = pPacket->m_nPosition + nLength;

		if ( strcmp( szType, "RELAY" ) == 0 )
		{
			bRelayed = TRUE;
		}
		else if ( strcmp( szType, "CA" ) == 0 ) // add G2/1.1 used on GnucDNA
		{
			// TODO
		}
		else if ( strcmp( szType, "CH" ) == 0 ) // add G2/1.1 used on GnucDNA as G2 version of UDPHC, but no vendor code exist and
		{										// possibly only GnucDNA Hub addresses.
			// TODO
		}
		else if ( strcmp( szType, "VC" ) == 0 && nLength >= 4 )	// Vendor Code of Remote Node  (e.g. "RAZA")
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
		else if ( strcmp( szType, "SIPP" ) == 0 && bCompound == FALSE )	// SIPP: source IP/PORT of UDP Ping packet, this is for
		{																// UDP ip/port detection on NAT/NAPT to find outside 
																		// IP/PORT.
			MyAddr.sin_addr.S_un.S_addr = pPacket->ReadLongLE();
			MyAddr.sin_port = htons( pPacket->ReadShortBE() );
		}
		pPacket->m_nPosition = nOffset;
	}

	if ( ! bRelayed )
	{
		if ( MyAddr.sin_addr.S_un.S_addr != 0 && MyAddr.sin_port != 0 && 
			MyAddr.sin_addr.S_un.S_addr != Network.m_pHost.sin_addr.S_un.S_addr &&
			MyAddr.sin_port != Network.m_pHost.sin_port)
		{
			CString str = inet_ntoa( pHost->sin_addr );
			theApp.Message( MSG_SYSTEM, _T("Pong from %s:%u said IP:PORT is not same as setting, possibly on NAT, %s:%u"), 
			str, ntohs(pHost->sin_port), inet_ntoa( MyAddr.sin_addr ),  ntohs(MyAddr.sin_port) );
		}
		return TRUE;
	}

	if ( ! Network.IsConnectedTo( &pHost->sin_addr ) ) m_bStable = TRUE;

	CString str = inet_ntoa( pHost->sin_addr );
	theApp.Message( MSG_SYSTEM, _T("Relayed Pong from %s:%u"), str, ntohs(pHost->sin_port) );

	return TRUE;
}

BOOL CDatagrams::OnQuery(SOCKADDR_IN* pHost, CG1Packet* pPacket)
{
	//TODO
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CDatagrams QUERY packet handler

BOOL CDatagrams::OnQuery(SOCKADDR_IN* pHost, CG2Packet* pPacket)
{
	CQuerySearch* pSearch = CQuerySearch::FromPacket( pPacket, pHost );

	if ( pSearch == NULL || ! pSearch->m_bUDP )
	{
		if ( pSearch ) delete pSearch;
		theApp.Message( MSG_ERROR, IDS_PROTOCOL_BAD_QUERY,
			(LPCTSTR)CString( inet_ntoa( pHost->sin_addr ) ) );
		Statistics.Current.Gnutella2.Dropped++;
		return FALSE;
	}

	if ( Security.IsDenied( &pSearch->m_pEndpoint.sin_addr ) )
	{
		delete pSearch;
		Statistics.Current.Gnutella2.Dropped++;
		return FALSE;
	}

	if ( ! Network.QueryKeys->Check( pSearch->m_pEndpoint.sin_addr.S_un.S_addr, pSearch->m_nKey ) )
	{
		DWORD nKey = Network.QueryKeys->Create( pSearch->m_pEndpoint.sin_addr.S_un.S_addr );

		CString strNode = inet_ntoa( pSearch->m_pEndpoint.sin_addr );
		theApp.Message( MSG_DEBUG, _T("Issuing correction for node %s's query key for %s"),
			(LPCTSTR)CString( inet_ntoa( pHost->sin_addr ) ), (LPCTSTR)strNode );

		CG2Packet* pAnswer = CG2Packet::New( G2_PACKET_QUERY_KEY_ANS, TRUE );
		pAnswer->WritePacket( "QK", 4 );
		pAnswer->WriteLongBE( nKey );

		if ( pHost->sin_addr.S_un.S_addr != pSearch->m_pEndpoint.sin_addr.S_un.S_addr )
		{
			pAnswer->WritePacket( "SNA", 4 );
			pAnswer->WriteLongLE( pHost->sin_addr.S_un.S_addr );
		}

		Send( &pSearch->m_pEndpoint, pAnswer, TRUE );

		delete pSearch;
		return TRUE;
	}
	
	if ( ! Network.QueryRoute->Add( pSearch->m_oGUID, &pSearch->m_pEndpoint ) )
	{
		CG2Packet* pAnswer = CG2Packet::New( G2_PACKET_QUERY_ACK, TRUE );
		pAnswer->WritePacket( "D", 8 );
		pAnswer->WriteLongLE( Network.m_pHost.sin_addr.S_un.S_addr );
		pAnswer->WriteShortBE( htons( Network.m_pHost.sin_port ) );
		pAnswer->WriteShortBE( 0 );
		pAnswer->WriteByte( 0 );
		pAnswer->Write( pSearch->m_oGUID );
		Send( &pSearch->m_pEndpoint, pAnswer, TRUE );

		delete pSearch;
		Statistics.Current.Gnutella2.Dropped++;
		return TRUE;
	}

	Neighbours.RouteQuery( pSearch, pPacket, NULL, TRUE );

	Network.OnQuerySearch( pSearch );

	CLocalSearch pLocal( pSearch, &pSearch->m_pEndpoint );
	pLocal.Execute();
	
	Send( &pSearch->m_pEndpoint, Neighbours.CreateQueryWeb( pSearch->m_oGUID ), TRUE );
	
	delete pSearch;

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CDatagrams QUERY ACK packet handler

BOOL CDatagrams::OnQueryAck(SOCKADDR_IN* pHost, CG2Packet* pPacket)
{
	CHostCacheHost* pCache = HostCache.Gnutella2.Add( &pHost->sin_addr, htons( pHost->sin_port ) );
	if ( pCache ) pCache->m_tAck = pCache->m_nFailures = 0;
	
	Hashes::Guid oGUID;
	
	if ( SearchManager.OnQueryAck( pPacket, pHost, oGUID ) )
	{
		CNeighbour* pNeighbour = NULL;
		SOCKADDR_IN pEndpoint;

		if ( Network.QueryRoute->Lookup( oGUID, &pNeighbour, &pEndpoint ) )
		{
			// TODO: Add a "FR" from tag

			if ( pNeighbour != NULL && pNeighbour->m_nNodeType == ntLeaf )
			{
				pNeighbour->Send( pPacket, FALSE, FALSE );
			}
			else
			{
				// Don't route it on via UDP
			}
		}
	}

	return TRUE;
}

BOOL CDatagrams::OnHit(SOCKADDR_IN* pHost, CG1Packet* pPacket)
{
	//TODO
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CDatagrams HIT packet handler

BOOL CDatagrams::OnHit(SOCKADDR_IN* pHost, CG2Packet* pPacket)
{
	int nHops = 0;
	CQueryHit* pHits = CQueryHit::FromPacket( pPacket, &nHops );

	if ( pHits == NULL )
	{
//		pPacket->Debug( _T("BadHit") );
		theApp.Message( MSG_ERROR, IDS_PROTOCOL_BAD_HIT,
			(LPCTSTR)CString( inet_ntoa( pHost->sin_addr ) ) );
		Statistics.Current.Gnutella2.Dropped++;
		return FALSE;
	}

	if ( Security.IsDenied( &pHits->m_pAddress ) || nHops > (int)Settings.Gnutella1.MaximumTTL )
	{
		pHits->Delete();
		Statistics.Current.Gnutella2.Dropped++;
		return FALSE;
	}
	
	Network.NodeRoute->Add( pHits->m_oClientID, pHost );
	
	if ( SearchManager.OnQueryHits( pHits ) )
	{
		Network.RouteHits( pHits, pPacket );
	}

	Network.OnQueryHits( pHits );

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CDatagrams QUERY KEY REQUEST packet handler

BOOL CDatagrams::OnQueryKeyRequest(SOCKADDR_IN* pHost, CG2Packet* pPacket)
{
	if ( ! Neighbours.IsG2Hub() ) return FALSE;

	DWORD nRequestedAddress = pHost->sin_addr.S_un.S_addr;
	WORD nRequestedPort = ntohs( pHost->sin_port );
	DWORD nSendingAddress = pHost->sin_addr.S_un.S_addr;

	if ( pPacket->m_bCompound )
	{
		CHAR szType[9];
		DWORD nLength;

		while ( pPacket->ReadPacket( szType, nLength ) )
		{
			DWORD nOffset = pPacket->m_nPosition + nLength;

			if ( strcmp( szType, "RNA" ) == 0 && nLength >= 6 )
			{
				nRequestedAddress	= pPacket->ReadLongLE();
				nRequestedPort		= pPacket->ReadShortBE();
			}
			else if ( strcmp( szType, "SNA" ) == 0 && nLength >= 4 )
			{
				nSendingAddress		= pPacket->ReadLongLE();
			}
			else if ( strcmp( szType, "dna" ) == 0 ) // add G2/1.1 dna
			{
				// TODO
			}

			pPacket->m_nPosition = nOffset;
		}
	}

	CString strNode = inet_ntoa( *(IN_ADDR*)&nRequestedAddress );
	theApp.Message( MSG_DEBUG, _T("Node %s asked for a query key for node %s:%i"),
		(LPCTSTR)CString( inet_ntoa( pHost->sin_addr ) ), (LPCTSTR)strNode, nRequestedPort );

	if ( Network.IsFirewalledAddress( &nRequestedAddress, TRUE ) || 0 == nRequestedPort ) return TRUE;

	DWORD nKey = Network.QueryKeys->Create( nRequestedAddress );

	CG2Packet* pAnswer = CG2Packet::New( G2_PACKET_QUERY_KEY_ANS, TRUE );

	pAnswer->WritePacket( "QK", 4 );
	pAnswer->WriteLongBE( nKey );

	if ( nRequestedAddress != nSendingAddress )
	{
		pAnswer->WritePacket( "SNA", 4 );
		pAnswer->WriteLongLE( nSendingAddress );
	}

	Send( (IN_ADDR*)&nRequestedAddress, nRequestedPort, pAnswer, TRUE );

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CDatagrams QUERY KEY ANSWER packet handler

BOOL CDatagrams::OnQueryKeyAnswer(SOCKADDR_IN* pHost, CG2Packet* pPacket)
{
	if ( ! pPacket->m_bCompound ) return FALSE;

	DWORD nKey = 0, nAddress = 0;

	CHAR szType[9];
	DWORD nLength;

	while ( pPacket->ReadPacket( szType, nLength ) )
	{
		DWORD nOffset = pPacket->m_nPosition + nLength;

		if ( strcmp( szType, "QK" ) == 0 && nLength >= 4 )
		{
			nKey = pPacket->ReadLongBE();
		}
		else if ( strcmp( szType, "SNA" ) == 0 && nLength >= 4 )
		{
			nAddress = pPacket->ReadLongLE();
		}

		pPacket->m_nPosition = nOffset;
	}

	theApp.Message( MSG_DEBUG, _T("Got a query key for %s:%lu: 0x%x"),
		(LPCTSTR)CString( inet_ntoa( pHost->sin_addr ) ), htons( pHost->sin_port ), nKey );

	CHostCacheHost* pCache = HostCache.Gnutella2.Add(
		&pHost->sin_addr, htons( pHost->sin_port ) );

	if ( pCache != NULL ) pCache->SetKey( nKey );

	if ( nAddress != 0 && nAddress != Network.m_pHost.sin_addr.S_un.S_addr )
	{
		if ( CNeighbour* pNeighbour = Neighbours.Get( (IN_ADDR*)&nAddress ) )
		{
			BYTE* pOut = pPacket->WriteGetPointer( 11, 0 );

			if ( pOut == NULL )
			{
				theApp.Message( MSG_ERROR, _T("Memory allocation error in CDatagrams::OnQueryKeyAnswer()") );
				return TRUE;
			}

			*pOut++ = 0x50;
			*pOut++ = 6;
			*pOut++ = 'Q';
			*pOut++ = 'N';
			*pOut++ = 'A';
			*pOut++ = pHost->sin_addr.S_un.S_un_b.s_b1;
			*pOut++ = pHost->sin_addr.S_un.S_un_b.s_b2;
			*pOut++ = pHost->sin_addr.S_un.S_un_b.s_b3;
			*pOut++ = pHost->sin_addr.S_un.S_un_b.s_b4;

			if ( pPacket->m_bBigEndian )
			{
				*pOut++ = (BYTE)( pHost->sin_port & 0xFF );
				*pOut++ = (BYTE)( pHost->sin_port >> 8 );
			}
			else
			{
				*pOut++ = (BYTE)( pHost->sin_port >> 8 );
				*pOut++ = (BYTE)( pHost->sin_port & 0xFF );
			}

			pNeighbour->Send( pPacket, FALSE, FALSE );
		}
	}

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CDatagrams PUSH packet handler
BOOL CDatagrams::OnPush(SOCKADDR_IN* pHost, CG1Packet* pPacket)
{
	// Push packets should be 26 bytes long, if it's too short, or too long and settings say to care
	if ( pPacket->m_nLength < 26 || ( pPacket->m_nLength > 26 && Settings.Gnutella1.StrictPackets 
		&& !Settings.Gnutella1.EnableGGEP ) )
	{
		// Record the weird packet and don't do anything else with it
		theApp.Message( MSG_ERROR, IDS_PROTOCOL_SIZE_PUSH, (LPCTSTR)inet_ntoa( pHost->sin_addr ) );
		Statistics.Current.Gnutella1.Dropped++;
		return FALSE;
	}

	// The first 16 bytes of the packet payload are the Gnutella client ID GUID, read them into pClientID
	Hashes::Guid oClientID;
	pPacket->Read( oClientID );

	// After that are the file index, IP address, and port number, read them
	DWORD nFileIndex = pPacket->ReadLongLE();  // 4 bytes, the file index (do)
	DWORD nAddress   = pPacket->ReadLongLE();  // 4 bytes, the IP address of (do)
	WORD nPort       = pPacket->ReadShortLE(); // 2 bytes, the port number

	// Assume this push packet does not have a GGEP block
	BOOL bGGEP = FALSE;

	// Check the security list to make sure the IP address isn't on it
	if ( Security.IsDenied( (IN_ADDR*)&nAddress ) )
	{
		// It is, count this packet as dropped and do nothing more with it
		Statistics.Current.Gnutella1.Dropped++;
		return TRUE;
	}

	// If the packet is longer than a normal push packet, and the remote computer said it supports GGEP blocks in the handshake
	if ( pPacket->m_nLength > 26 && Settings.Gnutella1.EnableGGEP )
	{
		// Read the next byte from the packet and make sure it's 0xC3, the magic code for a GGEP block
		if ( pPacket->ReadByte() != GGEP_MAGIC )
		{
			// It's not, drop the packet, but stay connected
			theApp.Message( MSG_ERROR, IDS_PROTOCOL_GGEP_REQUIRED, (LPCTSTR)inet_ntoa( pHost->sin_addr ) );
			Statistics.Current.Gnutella1.Dropped++;
			return FALSE;
		}

		// This push packet does have a GGEP block
		bGGEP = TRUE;
	}
	if ( Security.IsDenied( (IN_ADDR*)&nAddress ) )
	{
		theApp.Message( MSG_ERROR, _T("G2UDP: PUSH connection request from %s requested PUSH connection to Blocked Node %s"), 
			(LPCTSTR)inet_ntoa( pHost->sin_addr ), (LPCTSTR)inet_ntoa( *(IN_ADDR*)&nAddress ) );
		Statistics.Current.Gnutella1.Dropped++;
		return FALSE;
	}

	// If there is no port number specified in the packet, or we know the IP address to be firewalled
	if ( ! nPort || Network.IsFirewalledAddress( &nAddress ) )
	{
		// Then we can't push open a connection, do nothing more with the packet
		theApp.Message( MSG_ERROR, IDS_PROTOCOL_ZERO_PUSH, (LPCTSTR)inet_ntoa( pHost->sin_addr ) );
		Statistics.Current.Gnutella1.Dropped++;
		return FALSE;
	}

	// If the push packet contains our own client ID, this is someone asking us to push open a connection
	if ( validAndEqual( oClientID, Hashes::Guid( MyProfile.oGUID ) ) )
	{
		// Push open the connection
		Handshakes.PushTo( (IN_ADDR*)&nAddress, nPort, nFileIndex );
		return TRUE;
	}


	if ( Neighbours.IsG1Ultrapeer() || Neighbours.IsG2Hub() )
	{
		// Otherwise, the push packet is for another computer that we can hopefully can send it to, try to find it
		CNeighbour* pOrigin;
		Network.NodeRoute->Lookup( oClientID, (CNeighbour**)&pOrigin );

		// If we are connected to a computer with that client ID, and the packet's TTL and hop counts are OK
		if ( pOrigin && pPacket->Hop() ) // Calling Hop moves 1 from TTL to hops
		{
			// If the remote computer the push packet is for is running Gnutella
			if ( pOrigin->m_nProtocol == PROTOCOL_G1 )
			{
				// If this packet has a GGEP block, but the computer its for doesn't support them, cut it off
				if ( bGGEP && ! pOrigin->m_bGGEP ) pPacket->Shorten( 26 );

				// Send the push packet to the computer that needs to do it
				pOrigin->Send( pPacket, FALSE, TRUE );

			} // If instead it's running Gnutella2 software like Shareaza
			else if ( pOrigin->m_nProtocol == PROTOCOL_G2 )
			{
				// Create a new Gnutella2 push packet with the same information as this one, and send it
				CG2Packet* pWrap = CG2Packet::New( G2_PACKET_PUSH, TRUE );
				pWrap->WritePacket( "TO", 16 );
				pWrap->Write( oClientID );
				pWrap->WriteByte( 0 );
				pWrap->WriteLongLE( nAddress );
				pWrap->WriteShortLE( nPort );
				pOrigin->Send( pWrap, TRUE, TRUE );
			}

			// Record that we routed one more packet
			Statistics.Current.Gnutella1.Routed++;
		}
	}

	// The PUSH packet destination is not (me) but (I'm) not Ultrapeer nor Hub, packet should not be forwarded to
	// anywhere else.
	theApp.Message( MSG_ERROR, _T("G1UDP: PUSH packet received from %s is destinated to unknown node"), 
		(LPCTSTR)inet_ntoa( pHost->sin_addr ) );
	Statistics.Current.Gnutella1.Dropped++;
	return FALSE;
}

BOOL CDatagrams::OnPush(SOCKADDR_IN* pHost, CG2Packet* pPacket)
{
	DWORD nLength = pPacket->GetRemaining();

	if ( ! pPacket->SkipCompound( nLength, 6 ) )
	{
		theApp.Message( MSG_ERROR, _T("G2UDP: Invalid PUSH packet received from %s"), 
			(LPCTSTR)inet_ntoa( pHost->sin_addr ) );
		Statistics.Current.Gnutella2.Dropped++;
		return FALSE;
	}

	DWORD nAddress	= pPacket->ReadLongLE();
	WORD nPort		= pPacket->ReadShortBE();

	if ( Security.IsDenied( (IN_ADDR*)&nAddress ) )
	{
		theApp.Message( MSG_ERROR, _T("G2UDP: PUSH connection request from %s requested PUSH connection to Blocked Node %s"), 
			(LPCTSTR)inet_ntoa( pHost->sin_addr ), (LPCTSTR)inet_ntoa( *(IN_ADDR*)&nAddress ) );
		Statistics.Current.Gnutella2.Dropped++;
		return FALSE;
	}

	if ( Network.IsFirewalledAddress( &nAddress ) )
	{
		theApp.Message( MSG_ERROR, IDS_PROTOCOL_ZERO_PUSH, (LPCTSTR)inet_ntoa( pHost->sin_addr ) );
		Statistics.Current.Gnutella2.Dropped++;
		return FALSE;
	}

	Handshakes.PushTo( (IN_ADDR*)&nAddress, nPort );

	return TRUE;
}

BOOL CDatagrams::OnRUDP(SOCKADDR_IN* pHost, CG1Packet* pPacket)
{
	// To do: should implement asap, since a lot of request for this.
	return FALSE;
}

//////////////////////////////////////////////////////////////////////
// CDatagrams CRAWL packet handler

BOOL CDatagrams::OnCrawlRequest(SOCKADDR_IN* pHost, CG2Packet* pPacket)
{
	if ( ! pPacket->m_bCompound ) return FALSE;

	BOOL bWantLeaves	= FALSE;
	BOOL bWantNames		= FALSE;
	BOOL bWantGPS		= FALSE;
	BOOL bWantREXT		= FALSE;
	BOOL bIsHub			= ( ! Neighbours.IsG2Leaf() ) && ( Neighbours.IsG2Hub() || Neighbours.IsG2HubCapable() );

	CHAR szType[9];
	DWORD nLength;

	while ( pPacket->ReadPacket( szType, nLength ) )
	{
		DWORD nNext = pPacket->m_nPosition + nLength;

		if ( strcmp( szType, "RLEAF" ) == 0 )
		{
			bWantLeaves = TRUE;
		}
		else if ( strcmp( szType, "RNAME" ) == 0 )
		{
			bWantNames = TRUE;
		}
		else if ( strcmp( szType, "RGPS" ) == 0 )
		{
			bWantGPS = TRUE;
		}
		else if ( strcmp( szType, "REXT" ) == 0 )
		{
			bWantREXT = TRUE;
		}

		pPacket->m_nPosition = nNext;
	}

	pPacket = CG2Packet::New( G2_PACKET_CRAWL_ANS, TRUE );

	CString strNick;
	DWORD nGPS = 0;
	CString vendorCode;
	CString currentVersion;

	if ( bWantNames ) strNick = MyProfile.GetNick().Left( 255 ); //trim if over 255 characters

	if ( bWantGPS ) nGPS = MyProfile.GetPackedGPS();

	if ( bWantREXT )
	{
		vendorCode = VENDOR_CODE;
		currentVersion = CLIENT_NAME;
		currentVersion += " ";
		currentVersion += theApp.m_sVersion;
	}

	pPacket->WritePacket(
		"SELF",
		16 + ( strNick.GetLength() ? pPacket->GetStringLen( strNick ) + 6 : 0 ) +
			( nGPS ? 5 + 4 : 0 ) + (vendorCode.GetLength() ? pPacket->GetStringLen( vendorCode ) + 3 : 0 ) +
		(currentVersion.GetLength() ? pPacket->GetStringLen( currentVersion ) + 4 : 0 ) +
		(bIsHub ? 5 : 6),
		TRUE );

	pPacket->WritePacket( "NA", 6 );
	pPacket->WriteLongLE( Network.m_pHost.sin_addr.S_un.S_addr );
	pPacket->WriteShortBE( htons( Network.m_pHost.sin_port ) );

	pPacket->WritePacket( "HS", 2 );
	pPacket->WriteShortBE( WORD( Neighbours.GetCount( PROTOCOL_G2, -1, ntLeaf ) ) );

	if ( strNick.GetLength() )
	{
		pPacket->WritePacket( "NAME", pPacket->GetStringLen( strNick) );
		pPacket->WriteString( strNick, FALSE );
	}
	if ( vendorCode.GetLength() )
	{
		pPacket->WritePacket( "V", pPacket->GetStringLen( vendorCode) );
		pPacket->WriteString( vendorCode, FALSE );
	}
	if ( currentVersion.GetLength() )
	{
		pPacket->WritePacket( "CV", pPacket->GetStringLen( currentVersion) );
		pPacket->WriteString( currentVersion, FALSE );
	}

	if ( bIsHub )
	{
		pPacket->WritePacket( "HUB", 0 );
	}
	else
	{
		pPacket->WritePacket( "LEAF", 0 );
	}

	if ( nGPS )
	{
		pPacket->WritePacket( "GPS", 4 );
		pPacket->WriteLongBE( nGPS );
	}

	for ( POSITION pos = Neighbours.GetIterator() ; pos ; )
	{
		CNeighbour* pNeighbour = Neighbours.GetNext( pos );
		if ( pNeighbour->m_nState < nrsConnected ) continue;

		int nExtraLen = 0;
		strNick.Empty();
		nGPS = 0;

		if ( pNeighbour->m_nProtocol == PROTOCOL_G2 )
		{
			if ( CGProfile* pProfile = ((CG2Neighbour*)pNeighbour)->m_pProfile )
			{
				if ( bWantNames ) strNick = pProfile->GetNick().Left( 255 ); //Trim if over 255 characters

				if ( bWantGPS ) nGPS = pProfile->GetPackedGPS();

				if ( strNick.GetLength() ) nExtraLen += 6 + pPacket->GetStringLen( strNick );
				if ( nGPS ) nExtraLen += 9;
			}
		}

		if ( pNeighbour->m_nProtocol == PROTOCOL_G2 &&
			 pNeighbour->m_nNodeType != ntLeaf )
		{
			pPacket->WritePacket( "NH", 16 + nExtraLen, TRUE );

			pPacket->WritePacket( "NA", 6 );
			pPacket->WriteLongLE( pNeighbour->m_pHost.sin_addr.S_un.S_addr );
			pPacket->WriteShortBE( htons( pNeighbour->m_pHost.sin_port ) );

			pPacket->WritePacket( "HS", 2 );
			pPacket->WriteShortBE( (WORD)((CG2Neighbour*)pNeighbour)->m_nLeafCount );
		}
		else if ( pNeighbour->m_nNodeType == ntLeaf && bWantLeaves )
		{
			pPacket->WritePacket( "NL", 10 + nExtraLen, TRUE );

			pPacket->WritePacket( "NA", 6 );
			pPacket->WriteLongLE( pNeighbour->m_pHost.sin_addr.S_un.S_addr );
			pPacket->WriteShortBE( htons( pNeighbour->m_pHost.sin_port ) );
		}
		else
		{
			nExtraLen = 0;
		}

		if ( nExtraLen > 0 )
		{
			if ( strNick.GetLength() )
			{
				pPacket->WritePacket( "NAME", pPacket->GetStringLen( strNick ) );
				pPacket->WriteString( strNick, FALSE );
			}

			if ( nGPS )
			{
				pPacket->WritePacket( "GPS", 4 );
				pPacket->WriteLongBE( nGPS );
			}
		}
	}

	Send( pHost, pPacket );

	return TRUE;
}

// packet for answer to Crawler request. 
// the code to send Crawler request is not really used, possibly just there for debug network
BOOL CDatagrams::OnCrawlAnswer(SOCKADDR_IN* pHost, CG2Packet* pPacket)
{
	CrawlSession.OnCrawl( pHost, pPacket );
	return TRUE;
}

// this is packet GnucDNA use to request remote node to change more either to Hub or Leaf
BOOL CDatagrams::OnModeChangeReq(SOCKADDR_IN* pHost, CG2Packet* pPacket)
{
	//TODO
	return TRUE;
}

// this is packet GnucDNA use as Acknowledgment to mode change request
BOOL CDatagrams::OnModeChangeAck(SOCKADDR_IN* pHost, CG2Packet* pPacket)
{
	//TODO
	return TRUE;
}

// Private Message packet GnucDNA use 
BOOL CDatagrams::OnPrivateMessage(SOCKADDR_IN* pHost, CG2Packet* pPacket)
{
	//TODO
	return TRUE;
}

// little Question, is this needed for UDP?
BOOL CDatagrams::OnClose(SOCKADDR_IN* pHost, CG2Packet* pPacket)
{
	return TRUE;
}

BOOL CDatagrams::OnVendor(SOCKADDR_IN* pHost, CG1Packet* pPacket)
{
	if ( pPacket->m_nLength < 8 || ! Settings.Gnutella1.VendorMsg )
	{
		return FALSE;
	}

	// Read the vendor, function, and version numbers from the packet payload
	DWORD nVendor  = pPacket->ReadLongBE();  // 4 bytes, vendor code in ASCII characters, like "RAZA" (do)
	WORD nFunction = pPacket->ReadShortLE(); // 2 bytes, function (do)
	WORD nVersion  = pPacket->ReadShortLE(); // 2 bytes, version (do)

	// If the packet has 0 for the vendor and function (do)
	if ( nVendor == 0 && nFunction == 0 )
	{
		// Supported vendor messages array (do)
		return FALSE;
	} // The packet has vendor or function numbers, and the 2 bytes of function are all 1s
	else if ( nFunction == 0xFFFF )
	{
		// Vendor is 0
		if ( nVendor == 0 )
		{
			// Vendor code query (do)
			CG1Packet* pReply = CG1Packet::New( pPacket->m_nType, 1, pPacket->m_oGUID ); // Create a reply packet
			pReply->WriteLongLE( 0 );
			pReply->WriteShortLE( 0xFFFE );
			pReply->WriteShortLE( 1 );
			pReply->WriteLongBE( 'RAZA' );
			pReply->WriteLongBE( 'BEAR' );
			Send( pHost, pReply ); // Send the reply packet to the remote computer

		} // Vendor is the ASCII text "RAZA" for Shareaza
		else if ( nVendor == 'AZAR' ) // It's backwards because of network byte order
		{
			// Function code query for "RAZA" (do)
			CG1Packet* pReply = CG1Packet::New( pPacket->m_nType, 1, pPacket->m_oGUID ); // Create a reply packet
			pReply->WriteLongBE( 'RAZA' );
			pReply->WriteShortLE( 0xFFFE );
			pReply->WriteShortLE( 1 );
			pReply->WriteShortLE( 0x0001 );
			pReply->WriteShortLE( 1 );
			pReply->WriteShortLE( 0x0002 );
			pReply->WriteShortLE( 1 );
			pReply->WriteShortLE( 0x0003 );
			pReply->WriteShortLE( 1 );
			Send( pHost, pReply ); // Send the reply packet to the remote computer

		} // Vendor is the ASCII text "BEAR" for BearShare
		else if ( nVendor == 'BEAR' ) // It's backwards because of network byte order
		{
			// Function code query for "BEAR"
			CG1Packet* pReply = CG1Packet::New( pPacket->m_nType, 1, pPacket->m_oGUID ); // Create a reply packet
			pReply->WriteLongBE( 'BEAR' );
			pReply->WriteShortLE( 0xFFFE );
			pReply->WriteShortLE( 1 );
			pReply->WriteShortLE( 0x0004 );
			pReply->WriteShortLE( 1 );
			pReply->WriteShortLE( 0x000B );
			pReply->WriteShortLE( 1 );
			pReply->WriteShortLE( 0x000C );
			pReply->WriteShortLE( 1 );
			Send( pHost, pReply ); // Send the reply packet to the remote computer
		}
	}
	else if ( nVendor == 'RAZA' )
	{
		// Switch on what the function is
		switch ( nFunction )
		{

			// Version Query (do)
		case 0x0001:

			// The version number from the packet is 0 or 1
			if ( nVersion <= 1 )
			{
				// Send a response packet (do)
				CG1Packet* pReply = CG1Packet::New( pPacket->m_nType, 1, pPacket->m_oGUID );
				pReply->WriteLongBE( 'RAZA' );
				pReply->WriteShortLE( 0x0002 );
				pReply->WriteShortLE( 1 );
				pReply->WriteShortLE( theApp.m_nVersion[0] );
				pReply->WriteShortLE( theApp.m_nVersion[1] );
				pReply->WriteShortLE( theApp.m_nVersion[2] );
				pReply->WriteShortLE( theApp.m_nVersion[3] );
				Send( pHost, pReply ); // Send the reply packet to the remote computer
			}

			break;

			// Version Response (do)
		case 0x0002:

			// The version number we read from the packet is 0 or 1, and there are 8 bytes of payload left to read
			if ( nVersion <= 1 && pPacket->GetRemaining() >= 8 )
			{
				// Read those 8 bytes (do)
				WORD nVersion[4];
				nVersion[0] = pPacket->ReadShortLE();
				nVersion[1] = pPacket->ReadShortLE();
				nVersion[2] = pPacket->ReadShortLE();
				nVersion[3] = pPacket->ReadShortLE();
			}

			break;

			// Cluster Advisor (do)
		case 0x0003:

			// The version number we read from the packet is 0 or 1, and there are 28 bytes of payload left to read
			if ( nVersion <= 1 && pPacket->GetRemaining() >= 28 )
			{
				// Does not look like this is needed anymore.
				// specially on G1

				// This is a cluster advisor packet
				//OnClusterAdvisor( pPacket );
			}
			else
			{
				return FALSE;
			}
			break;

		default:
			return FALSE;
		}

	}
	else if ( nVendor == 'BEAR' )
	{
		// Sort by the function number to see what the vendor specific packet from BearShare wants
		switch ( nFunction )
		{

			// Super Pong (do)
		case 0x0001:

			break;

			// Product Identifiers (do)
		case 0x0003:

			break;

			// Hops Flow (do)
		case 0x0004:

			break;

			// Horizon Ping (do)
		case 0x0005:

			break;

			// Horizon Pong (do)
		case 0x0006:

			break;

			// Query Status Request (do)
		case 0x000B:

			// If the version is 0 or 1, then we can deal with this
			if ( nVersion <= 1 )
			{
				// Send a response packet (do)
				CG1Packet* pReply = CG1Packet::New( pPacket->m_nType, 1, pPacket->m_oGUID );
				pReply->WriteLongLE( 'BEAR' );
				pReply->WriteShortLE( 0x000C );
				pReply->WriteShortLE( 1 );
				pReply->WriteShortLE( SearchManager.OnQueryStatusRequest( pPacket->m_oGUID ) );
				Send( pHost, pReply );
			}

			break;

			// Query Status Response
		case 0x000C:

			break;
		}
	}
	else if ( nVendor == 'LIME' )
	{
		//TODO
	}
	else if ( nVendor == 'GTKG' )
	{
		//TODO
	}
	else if ( nVendor == 'GNUC' )
	{
		//TODO
	}

	return TRUE;
}

BOOL CDatagrams::OnCommonQueryHash(SOCKADDR_IN* pHost, CG1Packet* pPacket)
{
	//TODO
	return TRUE;
}

// little Question, is this needed for UDP?
BOOL CDatagrams::OnBye(SOCKADDR_IN* pHost, CG1Packet* pPacket)
{
	//TODO
	return TRUE;
}

// KHLA - KHL(Known Hub List) Answer, go over G2 UDP packet more like Gnutella2 version of UDPHC
// Better put cache as security to prevent attack, such as flooding cache with invalid host addresses.
BOOL CDatagrams::OnKHLA(SOCKADDR_IN* pHost, CG2Packet* pPacket)
{
	if ( /* ! pPacket->m_bCompound */ TRUE ) return FALSE; // block execution of code for above reason

	CDiscoveryService * pService = DiscoveryServices.GetByAddress( &(pHost->sin_addr) , ntohs(pHost->sin_port), 4 );

	if ( pService == NULL && ( Security.IsDenied( &pHost->sin_addr ) || Network.IsFirewalledAddress( (LPVOID*)&pHost->sin_addr, TRUE ) ||
		Network.IsReserved( &pHost->sin_addr ) ) ) return FALSE;

	CHAR szType[9], szInner[9];
	DWORD nLength, nInner;
	BOOL bCompound;
	int nCount = 0;

	DWORD tNow = static_cast< DWORD >( time( NULL ) );

	while ( pPacket->ReadPacket( szType, nLength, &bCompound ) )
	{
		DWORD nNext = pPacket->m_nPosition + nLength;

		if (	strcmp( szType, "NH" ) == 0 ||
				strcmp( szType, "CH" ) == 0 )
		{
			DWORD nAddress = 0, tSeen = tNow, tAdjust = 0;
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
					else if ( strcmp( szInner, "TS" ) == 0 && nInner >= 4 )
					{
						tSeen = pPacket->ReadLongBE() + tAdjust;
					}

					pPacket->m_nPosition = nNextX;
				}

				if ( nLength >= 6 )
				{
					nAddress = pPacket->ReadLongLE();
					nPort = pPacket->ReadShortBE();
					if ( nLength >= 10 ) tSeen = pPacket->ReadLongBE() + tAdjust;
				}

			}
			else if ( strcmp( szType, "TS" ) == 0 && nLength >= 4 )
			{
				tAdjust = (LONG)tNow - (LONG)pPacket->ReadLongBE();
			}

			if ( ! Security.IsDenied( (IN_ADDR*)&nAddress ) && ! Network.IsFirewalledAddress( &nAddress, TRUE, TRUE ) &&
                ! Network.IsReserved((IN_ADDR*)&nAddress) && strVendor.GetLength() == 4 && nPort != 0 && 
				nAddress != Network.m_pHost.sin_addr.S_un.S_addr)
			{
				CHostCacheHost* pCached = HostCache.Gnutella2.Add(
					(IN_ADDR*)&nAddress, nPort, tSeen, strVendor );


				if ( pCached != NULL )
				{
					nCount++;
					pCached->m_pVendor->m_sCode = strVendor;
				}
				// HubHorizonPool.Add( (IN_ADDR*)&nAddress, nPort );
			}
		}

		pPacket->m_nPosition = nNext;
	}

	if ( pService != NULL )
	{
		pService->OnSuccess();
		pService->m_nHosts = nCount;
	}

	return TRUE;
}

// KHLR - KHL(Known Hub List) request, go over UDP packet more like UDPHC for G1.
BOOL CDatagrams::OnKHLR(SOCKADDR_IN* pHost, CG2Packet* pPacket)
{
	if ( Security.IsDenied( &pHost->sin_addr ) || Network.IsFirewalledAddress( (LPVOID*)&pHost->sin_addr, TRUE ) ||
		Network.IsReserved( &pHost->sin_addr ) ) return FALSE;

	CG2Packet* pKHLA = CG2Packet::New( G2_PACKET_KHL_ANS, TRUE );

	//	DWORD nBase = pPacket->m_nPosition;

	for ( POSITION pos = Neighbours.GetIterator() ; pos ; )
	{
		CG2Neighbour* pNeighbour = (CG2Neighbour*)Neighbours.GetNext( pos );

		if (pNeighbour->m_nProtocol == PROTOCOL_G2 &&
			pNeighbour->m_nState == nrsConnected &&
			pNeighbour->m_nNodeType != ntLeaf &&
			pNeighbour->m_pHost.sin_addr.S_un.S_addr != Network.m_pHost.sin_addr.S_un.S_addr )
		{
			if ( pNeighbour->m_pVendor && pNeighbour->m_pVendor->m_sCode.GetLength() == 4 )
			{
				pKHLA->WritePacket( "NH", 14 + 6, TRUE );					// 4
				pKHLA->WritePacket( "HS", 2 );								// 4
				pKHLA->WriteShortBE( (WORD)pNeighbour->m_nLeafCount );		// 2
				pKHLA->WritePacket( "V", 4 );								// 3
				pKHLA->WriteString( pNeighbour->m_pVendor->m_sCode );		// 5
			}
			else
			{
				pKHLA->WritePacket( "NH", 7 + 6, TRUE );					// 4
				pKHLA->WritePacket( "HS", 2 );								// 4
				pKHLA->WriteShortBE( (WORD)pNeighbour->m_nLeafCount );		// 2
				pKHLA->WriteByte( 0 );										// 1
			}

			pKHLA->WriteLongLE( pNeighbour->m_pHost.sin_addr.S_un.S_addr );	// 4
			pKHLA->WriteShortBE( htons( pNeighbour->m_pHost.sin_port ) );		// 2
		}
	}

	int nCount = Settings.Gnutella2.KHLHubCount;
	DWORD tNow = static_cast< DWORD >( time( NULL ) );

	pKHLA->WritePacket( "TS", 4 );
	pKHLA->WriteLongBE( static_cast< DWORD >( time( NULL ) ) );

	for ( CHostCacheHost* pCachedHost = HostCache.Gnutella2.GetNewest() ; pCachedHost && nCount > 0 ;
			pCachedHost = pCachedHost->m_pPrevTime )
	{
		if (	pCachedHost->CanQuote( tNow ) &&
			Neighbours.Get( &pCachedHost->m_pAddress ) == NULL &&
			pCachedHost->m_pAddress.S_un.S_addr != Network.m_pHost.sin_addr.S_un.S_addr )
		{
			/*
			int nLength = 10;

			if ( pCachedHost->m_pVendor && pCachedHost->m_pVendor->m_sCode.GetLength() == 4 )
				nLength += 8;
			//if ( nLength > 10 )
			//	nLength ++;

			pKHLA->WritePacket( "CH", nLength, nLength > 10 );

			if ( pCachedHost->m_pVendor && pCachedHost->m_pVendor->m_sCode.GetLength() == 4 )
			{
				pKHLA->WritePacket( "V", 5 );									// 3
				pKHLA->WriteString( pCachedHost->m_pVendor->m_sCode, TRUE );	// 4
			}

			//if ( nLength > 10 ) pPacket->WriteByte( 0 );						// 1

			pKHLA->WriteLongLE( pCachedHost->m_pAddress.S_un.S_addr );			// 4
			pKHLA->WriteShortBE( pCachedHost->m_nPort );						// 2
			pKHLA->WriteLongBE( pCachedHost->m_tSeen );							// 4
			*/

			BOOL bCompound = ( pCachedHost->m_pVendor && pCachedHost->m_pVendor->m_sCode.GetLength() > 0 );
			CG2Packet* pCHPacket = CG2Packet::New( "CH", bCompound );

			if ( bCompound )
			{
				pCHPacket->WritePacket( "V", pCachedHost->m_pVendor->m_sCode.GetLength() );
				pCHPacket->WriteString( pCachedHost->m_pVendor->m_sCode );
			}
			pCHPacket->WriteLongLE( pCachedHost->m_pAddress.S_un.S_addr );					// 4
			pCHPacket->WriteShortBE( pCachedHost->m_nPort );								// 2
			pCHPacket->WriteLongBE( pCachedHost->m_tSeen );									// 4
			pKHLA->WritePacket( pCHPacket );
			pCHPacket->Release();


			nCount--;
		}
	}

	Send( pHost, pKHLA );

	return TRUE;
}

