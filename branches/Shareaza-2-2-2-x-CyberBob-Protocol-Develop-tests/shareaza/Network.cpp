//
// Network.cpp
//
// Copyright (c) Shareaza Development Team, 2002-2007.
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
#include "Handshakes.h"
#include "Neighbours.h"
#include "Neighbour.h"
#include "EDNeighbour.h"
#include "Datagrams.h"
#include "HostCache.h"
#include "RouteCache.h"
#include "QueryKeys.h"
#include "GProfile.h"
#include "Transfers.h"
#include "Downloads.h"
#include "DownloadSource.h"
#include "Statistics.h"
#include "DiscoveryServices.h"
#include "HttpRequest.h"
#include "UPnPFinder.h"

#include "CrawlSession.h"
#include "SearchManager.h"
#include "QueryHashMaster.h"
#include "QuerySearch.h"
#include "QueryHit.h"
#include "Buffer.h"
#include "G1Packet.h"
#include "G2Packet.h"
#include "EDpacket.h"
#include "GGEP.h"
#include "G1Neighbour.h"

#include "WndMain.h"
#include "WndChild.h"
#include "WndSearchMonitor.h"
#include "WndHitMonitor.h"
#include "Uploads.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

CNetwork Network;

//////////////////////////////////////////////////////////////////////
// CITMSendPush construction

CNetwork::CITMSendPush::CITMSendPush() : m_oGUID(), m_oPushProxies(), m_oG2Hubs()
{
	m_nProtocol				= PROTOCOL_NULL;
	m_pAddress.S_un.S_addr	= 0;
	m_nPort					= 0;
	m_nIndex				= 0;
}

CNetwork::CITMSendPush::~CITMSendPush()
{
	m_oGUID.clear();
	m_oPushProxies.clear();
	m_oG2Hubs.clear();
}

//////////////////////////////////////////////////////////////////////
// CITMSendPush Function member implementations

CNetwork::CITMSendPush* CNetwork::CITMSendPush::CreateMessage( PROTOCOLID nProtocol, const Hashes::Guid& oGUID, const DWORD nIndex,
															IN_ADDR pAddress, WORD nPort, const HubList& oPushProxies,
															const HubList& oG2Hubs )
{
	CITMSendPush* tempSP	= new CITMSendPush();
	tempSP->m_nProtocol = nProtocol;

	if ( nProtocol == PROTOCOL_HTTP || nProtocol == PROTOCOL_G1 || nProtocol == PROTOCOL_G2 )
	{
		tempSP->m_oGUID = oGUID;
		tempSP->m_nIndex = nIndex;
		tempSP->m_pAddress.S_un.S_addr = pAddress.S_un.S_addr;
		tempSP->m_nPort = nPort;
		if ( oPushProxies.empty() ) tempSP->m_oPushProxies = oPushProxies;
		if ( oG2Hubs.empty() ) tempSP->m_oG2Hubs = oG2Hubs;
	}
	else if ( nProtocol == PROTOCOL_ED2K )
	{
		tempSP->m_nIndex = nIndex; // ClientID
		tempSP->m_pAddress.S_un.S_addr = pAddress.S_un.S_addr; // Server address
		tempSP->m_nPort = nPort; // Server Port
	}
	return tempSP;
}

BOOL CNetwork::CITMSendPush::OnProcess()
{
	if ( ! Network.IsListening() ) return FALSE;

	// error, protocol can not be PROTOCOL_NULL
	if ( m_nProtocol == PROTOCOL_NULL ) return FALSE;

	CSingleLock pLock( &Network.m_pSection, TRUE );
	//if ( ! pLock.Lock( 250 ) ) return TRUE;

	int nCount = 0;
	SOCKADDR_IN pEndpoint;

	if ( m_nProtocol == PROTOCOL_HTTP || m_nProtocol == PROTOCOL_G1 || m_nProtocol == PROTOCOL_G2 )
	{
		Hashes::Guid oGUID2 = m_oGUID;
		CNeighbour* pOrigin;

		if ( !m_oGUID.isValid() ) return TRUE;

		while ( Network.GetNodeRoute( oGUID2, &pOrigin, &pEndpoint ) )
		{
			if ( pOrigin != NULL && pOrigin->m_nProtocol == PROTOCOL_G1 )
			{
				CG1Packet* pPacket = CG1Packet::New( G1_PACKET_PUSH,
					Settings.Gnutella1.MaximumTTL - 1 );

				pPacket->Write( m_oGUID );
				pPacket->WriteLongLE( m_nIndex );
				pPacket->WriteLongLE( Network.m_pHost.sin_addr.S_un.S_addr );
				pPacket->WriteShortLE( htons( Network.m_pHost.sin_port ) );

				pOrigin->Send( pPacket );
				nCount++;
			}
			else
			{

				if ( pOrigin != NULL )
				{
					CG2Packet* pPacket = CG2Packet::New( G2_PACKET_PUSH, TRUE );

					pPacket->WritePacket( G2_PACKET_TO, 16 );
					pPacket->Write( m_oGUID );

					pPacket->WriteByte( 0 );
					pPacket->WriteLongLE( Network.m_pHost.sin_addr.S_un.S_addr );
					pPacket->WriteShortBE( htons( Network.m_pHost.sin_port ) );

					pOrigin->Send( pPacket );
					nCount++;
				}
				else
				{
					pLock.Unlock();
					//Datagrams.Send( &pEndpoint, pPacket, TRUE, NULL, FALSE  );
					HubIndex iTemp = m_oG2Hubs.begin();
					HubIndex iEnd = m_oG2Hubs.end();
					BOOL bFound = FALSE;

					for (;iTemp != iEnd;iTemp++)
					{
						if ( (*iTemp).sin_addr.S_un.S_addr == pEndpoint.sin_addr.S_un.S_addr &&
							(*iTemp).sin_port == pEndpoint.sin_port )
							bFound = TRUE;
					}
					if ( !bFound ) m_oG2Hubs.push_back( pEndpoint );
					pLock.Lock();
				}
			}
			oGUID2[15]++;
		}

	}
	else if ( m_nProtocol == PROTOCOL_ED2K )
	{
		BOOL bReqSucceed = FALSE;

		// If we don't have a socket listening for incoming connections, leave now
		if ( ! Network.IsListening() ) return FALSE;

		// Get the neighbour with the given IP address, and look at it as an eDonkey2000 computer
		CEDNeighbour* pNeighbour = (CEDNeighbour*)Neighbours.Get( &m_pAddress );

		// If we found it, and it really is running eDonkey2000
		if ( ( pNeighbour != NULL ) && ( pNeighbour->m_nProtocol == PROTOCOL_ED2K ) && ( ! CEDPacket::IsLowID( pNeighbour->m_nClientID ) ) )
		{
			// Make a new eDonkey2000 call back request packet, write in the client ID, and send it to the eDonkey2000 computer
			CEDPacket* pPacket = CEDPacket::New( ED2K_C2S_CALLBACKREQUEST );
			pPacket->WriteLongLE( m_nIndex );
			bReqSucceed = pNeighbour->Send( pPacket );
		}

		if ( !bReqSucceed )
		{
			// lugdunum requests no more of this
			CEDPacket* pPacket = CEDPacket::New( ED2K_C2SG_CALLBACKREQUEST );
			pPacket->WriteLongLE( Network.m_pHost.sin_addr.S_un.S_addr );
			pPacket->WriteShortLE( htons( Network.m_pHost.sin_port ) );
			pPacket->WriteLongLE( m_nIndex );
			bReqSucceed = Datagrams.Send( &m_pAddress, m_nPort, pPacket ) ;
		}

		return bReqSucceed;
	}
	else
	{
		return FALSE;
	}

	pLock.Unlock();

	if ( m_nProtocol == PROTOCOL_G1 )
	{
		SOCKADDR_IN	pEndPoint;
		HubIndex iTemp = m_oPushProxies.begin();
		HubIndex iEnd = m_oPushProxies.end();
		BOOL bFound = FALSE;

		pEndPoint.sin_addr.S_un.S_addr = m_pAddress.S_un.S_addr;
		pEndPoint.sin_port = htons( m_nPort );

		for (;iTemp != iEnd;iTemp++)
		{
			if ( (*iTemp).sin_addr.S_un.S_addr == pEndpoint.sin_addr.S_un.S_addr &&
				(*iTemp).sin_port == pEndpoint.sin_port )
				bFound = TRUE;
		}
		if ( !bFound ) m_oPushProxies.push_back( pEndPoint );
	}

	if ( m_nProtocol == PROTOCOL_G2 )
	{
		SOCKADDR_IN	pEndPoint;
		HubIndex iTemp = m_oG2Hubs.begin();
		HubIndex iEnd = m_oG2Hubs.end();
		BOOL bFound = FALSE;

		pEndPoint.sin_addr.S_un.S_addr = m_pAddress.S_un.S_addr;
		pEndPoint.sin_port = htons( m_nPort );

		for (;iTemp != iEnd;iTemp++)
		{
			if ( (*iTemp).sin_addr.S_un.S_addr == pEndpoint.sin_addr.S_un.S_addr &&
				(*iTemp).sin_port == pEndpoint.sin_port )
				bFound = TRUE;
		}
		if ( !bFound ) m_oG2Hubs.push_back( pEndPoint );
	}

	pLock.Lock();
	if ( !m_oPushProxies.empty() )
	{
		for ( HubIndex POS = m_oPushProxies.begin();POS != m_oPushProxies.end();POS++)
		{
			CPacket* pPacket = CG1Packet::New( G1_PACKET_PUSH,
				Settings.Gnutella1.MaximumTTL - 1 );

			pPacket->Write( m_oGUID );
			pPacket->WriteLongLE( m_nIndex );
			pPacket->WriteLongLE( Network.m_pHost.sin_addr.S_un.S_addr );
			pPacket->WriteShortLE( htons( Network.m_pHost.sin_port ) );

			Datagrams.Send( &(*POS), pPacket );
			nCount++;
		}
	}

	if ( !m_oG2Hubs.empty() )
	{
		for ( HubIndex POS = m_oG2Hubs.begin();POS != m_oG2Hubs.end();POS++)
		{
			CG2Packet* pPacket = CG2Packet::New( G2_PACKET_PUSH, TRUE );

			pPacket->WritePacket( G2_PACKET_TO, 16 );
			pPacket->Write( m_oGUID );

			pPacket->WriteByte( 0 );
			pPacket->WriteLongLE( Network.m_pHost.sin_addr.S_un.S_addr );
			pPacket->WriteShortBE( htons( Network.m_pHost.sin_port ) );
			Datagrams.Send( &(*POS), pPacket, TRUE, NULL, FALSE  );
			nCount++;
		}
	}

	// need some code to send reply message to Source if failed to PUSH;

	return TRUE;

}

//////////////////////////////////////////////////////////////////////
// CNetwork construction

CNetwork::CNetwork() : m_pMessageQueue()
{
	NodeRoute				= new CRouteCache();
	QueryRoute				= new CRouteCache();
	QueryKeys				= new CQueryKeys();

	m_bEnabled				= FALSE;
	m_bAutoConnect			= FALSE;
	m_bTCPListeningReady	= FALSE;
	m_bUDPListeningReady	= FALSE;
	m_tStartedConnecting	= 0;
	m_tLastConnect			= 0;
	m_tLastED2KServerHop	= 0;

	m_nSequence				= 0;
	m_hThread				= NULL;

	ZeroMemory( &m_pHost, sizeof( m_pHost ) );
	m_pHost.sin_family		= AF_INET;

	ZeroMemory( &m_pOutBind, sizeof( m_pOutBind ) );
	m_pOutBind.sin_family		= AF_INET;

	m_tLastFirewallTest		= 0;
}

CNetwork::~CNetwork()
{
	delete QueryKeys;
	delete QueryRoute;
	delete NodeRoute;
}

//////////////////////////////////////////////////////////////////////
// CNetwork attributes

BOOL CNetwork::IsAvailable() const
{
	DWORD dwState = 0;
	if ( InternetGetConnectedState( &dwState, 0 ) )
	{
		if ( ! ( dwState & INTERNET_CONNECTION_OFFLINE ) ) return TRUE;
	}

	return FALSE;
}

BOOL CNetwork::IsConnected() const
{
	return m_bEnabled;
}

BOOL CNetwork::IsListening() const
{
	return m_bEnabled
		&& ( m_pHost.sin_addr.S_un.S_addr != 0 )
		&& ( m_pHost.sin_port != 0 )
		&& ( Handshakes.IsListening() );
}

int CNetwork::IsWellConnected() const
{
	return Neighbours.m_nStableCount;
}

BOOL CNetwork::IsStable() const
{
	return IsListening() && ( Handshakes.m_nStableCount > 0 );
}

TRISTATE CNetwork::IsFirewalled(int nCheck)
{
	if ( !IsConnected() ) return TS_UNKNOWN;	// Not connected, so how the hell I know if it is or not.
	else if ( Settings.Connection.FirewallState == CONNECTION_OPEN )	// CHECK_BOTH, CHECK_TCP, CHECK_UDP
		return ( m_bTCPListeningReady && m_bUDPListeningReady ) ? TS_FALSE : TS_TRUE;		// We know we are not firewalled on both TCP and UDP unless failed to bind on port
	else if ( Settings.Connection.FirewallState == CONNECTION_OPEN_TCPONLY && nCheck == CHECK_TCP )
		return ( m_bTCPListeningReady ) ? TS_FALSE : TS_TRUE;		// We know we are not firewalled on TCP port unless failed to bind on port
	else if ( Settings.Connection.FirewallState == CONNECTION_OPEN_UDPONLY && nCheck == CHECK_UDP )
		return ( m_bUDPListeningReady ) ? TS_FALSE : TS_TRUE;		// We know we are not firewalled on UDP port unless failed to bind on port
	else if ( Settings.Connection.FirewallState == CONNECTION_AUTO )
	{
		TRISTATE tsTCPOpened = !m_bTCPListeningReady ? TS_FALSE // port could not be opened so same as firewalled.
			: IsStable() ? TS_TRUE								// port is Stable, so the port is Opened.
			: ( Uploads.IsStable() ? TS_FALSE					// Upload is stable, without port is stable, so must be firewalled
			: TS_UNKNOWN );										// not yet known if firewalled ot not.
		TRISTATE tsUDPOpened = !m_bUDPListeningReady ? TS_FALSE	// port could not be opened so same as firewalled.
			: Datagrams.IsStable() ? TS_TRUE					// port is Stable, so the port is Opened.
			: ( ( IsTestingUDPFW() || !Settings.Gnutella2.EnableToday )? TS_UNKNOWN	// is still testing or G2 is not enabled so do not know if UDP is opened or not
			: TS_FALSE );										// none of above, means UDP is firewalled
		if( nCheck == CHECK_BOTH )
		{
			if ( tsTCPOpened == TS_TRUE && tsUDPOpened == TS_TRUE )
				return TS_FALSE;	// We know we are not firewalled on both TCP and UDP
			else if ( tsTCPOpened == TS_FALSE || tsUDPOpened == TS_FALSE )
				return TS_TRUE;	// We know we are not firewalled on both TCP and UDP
			else
				return TS_UNKNOWN;
		}
		else if ( nCheck == CHECK_TCP )
		{
			switch ( tsTCPOpened )
			{
			case TS_UNKNOWN:
				return TS_UNKNOWN;
			case TS_FALSE:
				return TS_TRUE;			// We know we are firewalled on TCP
			case TS_TRUE:
				return TS_FALSE;	// We know we are not firewalled on TCP port
			}
		}
		else if ( nCheck == CHECK_UDP )
		{
			switch ( tsUDPOpened )
			{
			case TS_UNKNOWN:
				return TS_UNKNOWN;
			case TS_FALSE:
				return TS_TRUE;			// We know we are firewalled on UDP
			case TS_TRUE:
				return TS_FALSE;	// We know we are not firewalled on UDP port
			}
		}
	}

	return TS_TRUE;			// We know we are firewalled
}

BOOL CNetwork::IsTestingUDPFW()
{
	return m_tStartTestingUDPFW != 0 && ( m_nNetworkGlobalTime - m_tStartTestingUDPFW < 3600 );
}

void CNetwork::BeginTestG2UDPFW()
{
	m_tStartTestingUDPFW = static_cast<DWORD>( time( NULL ) );
	Datagrams.SetStable(FALSE);
}

void CNetwork::EndTestG2UDPFW(TRISTATE bFirewalled)
{
	m_tStartTestingUDPFW = 0;
	if ( bFirewalled == TS_TRUE )
		Datagrams.SetStable(FALSE);
	else if ( bFirewalled == TS_FALSE )
		Datagrams.SetStable(TRUE);
}

BOOL CNetwork::CanTestFirewall() 
{
	DWORD tNow = GetTickCount();

	if ( ( tNow - m_tLastFirewallTest ) >= Settings.Connection.FWTestWait * 1000 )	// One test in 3 min.
		return TRUE;

	return FALSE;
}

void CNetwork::TestRemoteFirewall(DWORD nAddress, WORD nPort)
{
	if ( nAddress != 0 && nPort != 0 && (DWORD)m_FWTestQueue.GetSize() <= Settings.Connection.MaxFWTestQueue )	// max 20 queued tests to avoid flooding
	{
		sockaddr_in pHost;
		pHost.sin_addr = *(in_addr*)&nAddress;
		pHost.sin_port = nPort;
		m_FWTestQueue.AddTail( pHost );
	}
}

DWORD CNetwork::GetStableTime() const
{
	if ( ! IsStable() || ! Handshakes.m_tStableTime ) return 0;
	return (DWORD)time( NULL ) - Handshakes.m_tStableTime;
}

BOOL CNetwork::IsConnectedTo(IN_ADDR* pAddress)
{
	if ( pAddress->S_un.S_addr == m_pHost.sin_addr.S_un.S_addr ) return TRUE;
	if ( Handshakes.IsConnectedTo( pAddress ) ) return TRUE;
	if ( Neighbours.Get( pAddress ) != NULL ) return TRUE;
	if ( Transfers.IsConnectedTo( pAddress ) ) return TRUE;
	
	return FALSE;
}

BOOL CNetwork::ReadyToTransfer(DWORD tNow) const
{
	if ( !Network.IsConnected() )
		return FALSE;

	// If a connection isn't needed for transfers, we can start any time
	if ( !Settings.Connection.RequireForTransfers )
		return TRUE;

	// If we have not started connecting, we're not ready to transfer.
	if ( m_tStartedConnecting == 0 )
		return FALSE;

	// We should wait a short time after starting the connection sequence before starting downloads
	if ( Settings.Connection.SlowConnect )
		return ( ( tNow - m_tStartedConnecting ) > 8000 );		// 8 seconds for XPsp2 users
	else
		return ( ( tNow - m_tStartedConnecting ) > 4000 );		// 4 seconds for others
}

//////////////////////////////////////////////////////////////////////
// CNetwork connection

BOOL CNetwork::Connect(BOOL bAutoConnect)
{
	if ( bAutoConnect && !m_bEnabled )
	{
		Settings.Gnutella1.EnableToday = ( Settings.Gnutella1.EnableAlways ? TRUE : Settings.Gnutella1.EnableToday );
		Settings.Gnutella2.EnableToday = ( Settings.Gnutella2.EnableAlways ? TRUE : Settings.Gnutella2.EnableToday );
		Settings.eDonkey.EnableToday = ( Settings.eDonkey.EnableAlways ? TRUE : Settings.eDonkey.EnableToday );
	}

	CSingleLock pLock( &m_pSection, TRUE );
	Settings.Live.AutoClose = FALSE;
	m_bAutoConnect = bAutoConnect ? TRUE : m_bAutoConnect;

	// If we are already connected, skiping further initializations. 
	if ( m_bEnabled )
		return TRUE;

	m_nNetworkGlobalTime = static_cast<DWORD>( time( NULL ) );
	m_nNetworkGlobalTickCount = GetTickCount();

	// Begin network startup
	theApp.Message( MSG_SYSTEM, IDS_NETWORK_STARTUP );

	// Make sure WinINet is connected (IE is not in offline mode)
	if ( Settings.Connection.ForceConnectedState )
	{
		INTERNET_CONNECTED_INFO ici = { 0 };
		HINTERNET hInternet = InternetOpen( Settings.SmartAgent(), INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0 );

		ici.dwConnectedState = INTERNET_STATE_CONNECTED;
		InternetSetOption( hInternet, INTERNET_OPTION_CONNECTED_STATE, &ici, sizeof(ici) );
		InternetCloseHandle( hInternet );
	}

	Resolve( Settings.Connection.InHost, Settings.Connection.InPort, &m_pHost );

	SOCKADDR_IN pOutgoing;

	if ( Resolve( Settings.Connection.OutHost, 0, &pOutgoing ) )
	{
		theApp.Message( MSG_DEFAULT, IDS_NETWORK_OUTGOING,
			(LPCTSTR)CString( inet_ntoa( pOutgoing.sin_addr ) ),
			htons( pOutgoing.sin_port ) );
	}
	else if ( Settings.Connection.OutHost.GetLength() )
	{
		theApp.Message( MSG_ERROR, IDS_NETWORK_CANT_OUTGOING,
			(LPCTSTR)Settings.Connection.OutHost );
	}

	m_bTCPListeningReady = Handshakes.Listen();
	m_bUDPListeningReady = Datagrams.Listen();

	Uploads.SetStable( 0 );

	ASSERT(m_bTCPListeningReady);
	ASSERT(m_bUDPListeningReady);

	if ( !m_bTCPListeningReady || !m_bUDPListeningReady )
	{
		theApp.Message( MSG_DISPLAYED_ERROR, _T("The connection process is failed.") );
		Handshakes.Disconnect();
		Datagrams.Disconnect();
		return FALSE;
	}

	Neighbours.Connect();

	NodeRoute->SetDuration( Settings.Gnutella.RouteCache );
	QueryRoute->SetDuration( Settings.Gnutella.RouteCache );

	if ( IsFirewalled(CHECK_BOTH) == TS_TRUE )
		theApp.Message( MSG_DEFAULT, IDS_NETWORK_FIREWALLED );

	m_bEnabled				= TRUE;
	m_tStartedConnecting	= GetTickCount();
	CITMQueue::EnableITM( &(Network.m_pMessageQueue) );
	if ( Settings.Gnutella2.EnableToday ) BeginTestG2UDPFW();
    
	CWinThread* pThread = AfxBeginThread( ThreadStart, this, THREAD_PRIORITY_NORMAL );
	m_hThread				= pThread->m_hThread;
	SetThreadName( pThread->m_nThreadID, "Network" );

	if ( Settings.Gnutella1.EnableToday)
		DiscoveryServices.ExecuteBootstraps( Settings.Discovery.BootstrapCount, FALSE, PROTOCOL_G1 );
	if ( Settings.Gnutella2.EnableToday)
		DiscoveryServices.ExecuteBootstraps( Settings.Discovery.BootstrapCount, FALSE, PROTOCOL_G2 );
	// No BootStrap for ED2K at all but maybe in future.
	//if ( Settings.eDonkey.EnableToday )
	//	DiscoveryServices.ExecuteBootstraps( Settings.Discovery.BootstrapCount, FALSE, PROTOCOL_ED2K );
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CNetwork disconnect

void CNetwork::Disconnect()
{
	CSingleLock pLock( &m_pSection, TRUE );

	CITMQueue::DisableITM( &(Network.m_pMessageQueue) );
	if ( Settings.Gnutella2.EnableToday ) EndTestG2UDPFW( TS_UNKNOWN );
	if ( ! m_bEnabled ) return;
	
	Settings.Gnutella1.EnableToday = FALSE;
	Settings.Gnutella2.EnableToday = FALSE;
	Settings.eDonkey.EnableToday = FALSE;

	theApp.Message( MSG_DEFAULT, _T("") );
	theApp.Message( MSG_SYSTEM, IDS_NETWORK_DISCONNECTING );

	m_bEnabled				= FALSE;
	m_bAutoConnect			= FALSE;
	m_bTCPListeningReady	= FALSE;
	m_bUDPListeningReady	= FALSE;
	m_tStartedConnecting	= 0;
	m_tStartTestingUDPFW	= 0;
	Datagrams.SetStable(FALSE);

	Neighbours.Close();

	pLock.Unlock();

	m_pWakeup.SetEvent();
	CloseThread( &m_hThread, _T("CNetwork") );

	Handshakes.Disconnect();
	pLock.Lock();

	Neighbours.Close();
	Datagrams.Disconnect();

	NodeRoute->Clear();
	QueryRoute->Clear();

	if ( TRUE )
	{
		for ( POSITION pos = m_pLookups.GetStartPosition() ; pos ; )
		{
			HANDLE pAsync;
			ResolveStruct* pBuffer;
			m_pLookups.GetNextAssoc( pos, pAsync, pBuffer );
			WSACancelAsyncRequest( pAsync );
			delete pBuffer->m_sAddress;
			delete pBuffer;
		}

		m_pLookups.RemoveAll();
	}

	pLock.Unlock();

	m_nNetworkGlobalTime = static_cast<DWORD>( time( NULL ) );
	m_nNetworkGlobalTickCount = GetTickCount();

	DiscoveryServices.Stop();

	Uploads.SetStable( 0 );

	theApp.Message( MSG_SYSTEM, IDS_NETWORK_DISCONNECTED ); 
	theApp.Message( MSG_SYSTEM, _T("") );
}

//////////////////////////////////////////////////////////////////////
// CNetwork host connection

BOOL CNetwork::ConnectTo(LPCTSTR pszAddress, int nPort, PROTOCOLID nProtocol, BOOL bNoUltraPeer, BOOL bUDP)
{
	CSingleLock pLock( &m_pSection, TRUE );
	
	if ( ! m_bEnabled && ! Connect() ) return FALSE;
	
	if ( nPort == 0 ) nPort = GNUTELLA_DEFAULT_PORT;
	theApp.Message( MSG_DEFAULT, IDS_NETWORK_RESOLVING, pszAddress );
	
	if ( AsyncResolve( pszAddress, (WORD)nPort, nProtocol, ( bUDP ? 4 : ( bNoUltraPeer ? 2 : 1 ) ) ) ) return TRUE;
	
	theApp.Message( MSG_ERROR, IDS_NETWORK_RESOLVE_FAIL, pszAddress );
	
	return FALSE;
}

//////////////////////////////////////////////////////////////////////
// CNetwork local IP aquisition and sending

void CNetwork::AcquireLocalAddress(LPCTSTR pszHeader)
{
	int nIP[4];
	
	if ( _stscanf( pszHeader, _T("%i.%i.%i.%i"), &nIP[0], &nIP[1], &nIP[2], &nIP[3] ) != 4 ) return;
	
	IN_ADDR pAddress;
	
	pAddress.S_un.S_un_b.s_b1 = (BYTE)nIP[0];
	pAddress.S_un.S_un_b.s_b2 = (BYTE)nIP[1];
	pAddress.S_un.S_un_b.s_b3 = (BYTE)nIP[2];
	pAddress.S_un.S_un_b.s_b4 = (BYTE)nIP[3];
	
	if ( IsFirewalledAddress( &pAddress, FALSE, TRUE ) ) return;
	
	m_pHost.sin_addr = pAddress;

	//Security.Ban( &pAddress, banSession, 0 );		// Ban self
}

//////////////////////////////////////////////////////////////////////
// CNetwork GGUID generation

void CNetwork::CreateID(Hashes::Guid& oID)
{
	oID = MyProfile.oGUID;
	Hashes::Guid::iterator i = oID.begin();
	*i++ += GetTickCount();
	*i++ += m_nSequence++;
	*i++ += rand() * ( RAND_MAX + 1 ) * ( RAND_MAX + 1 ) + rand() * ( RAND_MAX + 1 ) + rand();
	*i   += rand() * ( RAND_MAX + 1 ) * ( RAND_MAX + 1 ) + rand() * ( RAND_MAX + 1 ) + rand();
}

//////////////////////////////////////////////////////////////////////
// CNetwork firewalled address checking

BOOL CNetwork::IsFirewalledAddress(LPVOID pAddress, BOOL bIncludeSelf, BOOL bForceCheck)
{
	if ( ! pAddress ) return TRUE;
	if ( ! bForceCheck && ! Settings.Connection.IgnoreLocalIP ) return FALSE;
	
	DWORD nAddress = *(DWORD*)pAddress;
	
	if ( ! nAddress ) return TRUE;
	if ( ( nAddress & 0xFFFF ) == 0xA8C0 ) return TRUE;
	if ( ( nAddress & 0xF0AC ) == 0x08AC ) return TRUE;
	if ( ( nAddress & 0xFF ) == 0x0A ) return TRUE;
	if ( ( nAddress & 0xFF ) == 0x7F ) return TRUE;		// 127.*
	
	if ( ( bIncludeSelf || bForceCheck ) && nAddress == *(DWORD*)(&m_pHost.sin_addr) ) return TRUE;
	
	return FALSE;
}

//////////////////////////////////////////////////////////////////////
// CNetwork name resolution

BOOL CNetwork::Resolve(LPCTSTR pszHost, int nPort, SOCKADDR_IN* pHost, BOOL bNames) const
{
	ZeroMemory( pHost, sizeof(*pHost) );
	pHost->sin_family	= PF_INET;
	pHost->sin_port		= htons( u_short( nPort ) );
	
	if ( pszHost == NULL || *pszHost == 0 ) return FALSE;
	
	CString strHost( pszHost );
	
	int nColon = strHost.Find( ':' );
	
	if ( nColon >= 0 )
	{
		if ( _stscanf( strHost.Mid( nColon + 1 ), _T("%i"), &nPort ) == 1 )
		{
			pHost->sin_port = htons( u_short( nPort ) );
		}
		
		strHost = strHost.Left( nColon );
	}
	
	USES_CONVERSION;
	LPCSTR pszaHost = T2CA( (LPCTSTR)strHost );
	
	DWORD dwIP = inet_addr( pszaHost );
	
	if ( dwIP == INADDR_NONE )
	{
		if ( ! bNames ) return TRUE;
		
		HOSTENT* pLookup = gethostbyname( pszaHost );
		
		if ( pLookup == NULL ) return FALSE;
		
		CopyMemory( &pHost->sin_addr, pLookup->h_addr, sizeof pHost->sin_addr );
	}
	else
	{
		CopyMemory( &pHost->sin_addr, &dwIP, sizeof pHost->sin_addr );
	}
	
	return TRUE;
}

BOOL CNetwork::AsyncResolve(LPCTSTR pszAddress, WORD nPort, PROTOCOLID nProtocol, BYTE nCommand)
{
	CSingleLock pLock( &m_pSection );
	if ( ! pLock.Lock( 250 ) ) return FALSE;
	
	ResolveStruct* pResolve = new ResolveStruct;
	
	USES_CONVERSION;
	
	HANDLE hAsync = WSAAsyncGetHostByName( AfxGetMainWnd()->GetSafeHwnd(), WM_WINSOCK,
		T2CA(pszAddress), pResolve->m_pBuffer, MAXGETHOSTSTRUCT );
	
	if ( hAsync != NULL )
	{
		pResolve->m_sAddress = new CString( pszAddress );
		pResolve->m_nProtocol = nProtocol;
		pResolve->m_nPort = nPort;
		pResolve->m_nCommand = nCommand;

		m_pLookups.SetAt( hAsync, pResolve );
		return TRUE;
	}
	else
	{
		delete pResolve;
		return FALSE;
	}
}

// Returns TRUE if the IP address is reserved.
// Private addresses are treated as reserved when Connection.IgnoreLocalIP = TRUE.
// The code is based on nmap code and updated according to
// http://www.cymru.com/Documents/bogon-bn-nonagg.txt
// and http://www.iana.org/assignments/ipv4-address-space

BOOL CNetwork::IsReserved(IN_ADDR* pAddress, bool bCheckLocal)
{
	char *ip = (char*)&(pAddress->s_addr);
	unsigned char i1 = ip[ 0 ], i2 = ip[ 1 ], i3 = ip[ 2 ], i4 = ip[ 3 ];

	switch ( i1 )
	{
		case 0:         // 000/8 is IANA reserved
		case 1:         // 001/8 is IANA reserved       
		case 2:         // 002/8 is IANA reserved       
		case 5:         // 005/8 is IANA reserved       
		case 6:         // USA Army ISC                 
		case 7:         // used for BGP protocol        
		case 23:        // 023/8 is IANA reserved       
		case 27:        // 027/8 is IANA reserved       
		case 31:        // 031/8 is IANA reserved       
		case 36:        // 036/8 is IANA reserved       
		case 37:        // 037/8 is IANA reserved       
		case 39:        // 039/8 is IANA reserved       
		case 42:        // 042/8 is IANA reserved       
		case 49:        // 049/8 is IANA reserved       
		case 50:        // 050/8 is IANA reserved       
		case 55:        // misc. USA Armed forces    
		case 127:       // 127/8 is reserved for loopback 
		case 197:       // 197/8 is IANA reserved       
		case 223:       // 223/8 is IANA reserved       
			return TRUE;
		case 10:        // Private addresses
			return bCheckLocal && Settings.Connection.IgnoreLocalIP;
		default:
			break;
	}

	// 077-079/8 is IANA reserved 
	if ( i1 >= 77 && i1 <= 79 ) return TRUE;

	// 092-123/8 is IANA reserved 
	if ( i1 >= 92 && i1 <= 120 ) return TRUE;

	// 172.16.0.0/12 is reserved for private nets by RFC1819 
	if ( i1 == 172 && i2 >= 16 && i2 <= 31 ) 
		return bCheckLocal && Settings.Connection.IgnoreLocalIP;

	// 173-187/8 is IANA reserved 
	if ( i1 >= 173 && i1 <= 187 ) return TRUE;

	// 192.168.0.0/16 is reserved for private nets by RFC1819 
	// 192.0.2.0/24 is reserved for documentation and examples 
	// 192.88.99.0/24 is used as 6to4 Relay anycast prefix by RFC3068 
	if ( i1 == 192 )
	{
		if ( i2 == 168 ) return bCheckLocal && Settings.Connection.IgnoreLocalIP;
		if ( i2 == 0 && i3 == 2 ) return TRUE;
		if ( i2 == 88 && i3 == 99 ) return TRUE;
	}

	// 198.18.0.0/15 is used for benchmark tests by RFC2544 
	if ( i1 == 198 && i2 == 18 && i3 >= 1 && i3 <= 64 ) return TRUE;

	// reserved for DHCP clients seeking addresses, not routable outside LAN 
	if ( i1 == 169 && i2 == 254 ) return TRUE;

	// 204.152.64.0/23 is some Sun proprietary clustering thing 
	if ( i1 == 204 && i2 == 152 && ( i3 == 64 || i3 == 65 ) )
		return TRUE;

	// 224-239/8 is all multicast stuff 
	// 240-255/8 is IANA reserved 
	if ( i1 >= 224 ) return TRUE;

	// 255.255.255.255, we already tested for i1 
	if ( i2 == 255 && i3 == 255 && i4 == 255 ) return TRUE;

	return FALSE;
}

WORD CNetwork::RandomPort() const
{
	return WORD( 10000 + ( rand() % 50000 ) );
}

//////////////////////////////////////////////////////////////////////
// CNetwork thread run

UINT CNetwork::ThreadStart(LPVOID pParam)
{
	CNetwork* pNetwork = (CNetwork*)pParam;
	pNetwork->OnRun();
	return 0;
}

void CNetwork::OnRun()
{
	while ( m_bEnabled )
	{
		Sleep(50);
		WaitForSingleObject( m_pWakeup, 100 );

		m_nNetworkGlobalTime = static_cast<DWORD>( time( NULL ) );
		m_nNetworkGlobalTickCount = GetTickCount();

		if ( ! theApp.m_bLive ) continue;
		if ( theApp.m_pUPnPFinder && theApp.m_pUPnPFinder->IsAsyncFindRunning() )
			continue;

		if ( m_bEnabled && m_pSection.Lock() )
		{
			Datagrams.OnRun();
			SearchManager.OnRun();
			QueryHashMaster.Build();
			
			if ( CrawlSession.m_bActive ) CrawlSession.OnRun();

			if ( m_FWTestQueue.GetSize() )
			{
				if ( CanTestFirewall() )
				{
					sockaddr_in pHost;
					pHost = m_FWTestQueue.GetHead();

					theApp.Message( MSG_SYSTEM, _T("Making a firewall test for %s, port %lu"), (CString)inet_ntoa( pHost.sin_addr ), pHost.sin_port );
					Neighbours.ConnectTo( (IN_ADDR*)&pHost.sin_addr, pHost.sin_port, PROTOCOL_G2, FALSE, FALSE, TRUE );
					m_tLastFirewallTest = m_nNetworkGlobalTickCount;

                    m_FWTestQueue.RemoveHead();
				}	
			}
			
			m_pSection.Unlock();
		}
		
		Neighbours.OnRun();
		m_pMessageQueue.ProcessMessages();
	}
}

//////////////////////////////////////////////////////////////////////
// CNetwork resolve callback

void CNetwork::OnWinsock(WPARAM wParam, LPARAM lParam)
{
	CSingleLock pLock( &m_pSection, TRUE );

	ResolveStruct* pResolve = NULL;
	if ( ! m_pLookups.Lookup( (HANDLE)wParam, pResolve ) ) return;
	m_pLookups.RemoveKey( (HANDLE)wParam );

	CString strAddress;
	CDiscoveryService* pService;

	if ( WSAGETASYNCERROR(lParam) == 0 )
	{
		if ( pResolve->m_nCommand == 0 ) // Old Bootstrap
		{
			HostCache.ForProtocol( pResolve->m_nProtocol )->Add( (IN_ADDR*)pResolve->m_pHost.h_addr, pResolve->m_nPort );
		}
		else if ( pResolve->m_nCommand == 1 ) // 1 = normal
		{
			Neighbours.ConnectTo( (IN_ADDR*)pResolve->m_pHost.h_addr, pResolve->m_nPort, pResolve->m_nProtocol, FALSE, FALSE, FALSE, FALSE );
		}
		else if ( pResolve->m_nCommand == 2 ) // 2 = No Ultrapeer
		{
			Neighbours.ConnectTo( (IN_ADDR*)pResolve->m_pHost.h_addr, pResolve->m_nPort, pResolve->m_nProtocol, FALSE, TRUE, FALSE, FALSE );
		}
		else if ( pResolve->m_nCommand == 4 ) // 4 = UDP (ToDo) currently only for G2.
		{
			Neighbours.ConnectTo( (IN_ADDR*)pResolve->m_pHost.h_addr, pResolve->m_nPort, pResolve->m_nProtocol, FALSE, FALSE, FALSE, TRUE );
		}
		else if ( pResolve->m_nCommand == 3 ) // 3 = UHC/UKHL bootstraps.
		{
			// code to invoke UDPHC/UDPKHL Sender.
			if ( pResolve->m_nProtocol == PROTOCOL_G1 )
			{
				strAddress.Format( _T("uhc:%s"), LPCTSTR(*(pResolve->m_sAddress)) );
				pService = DiscoveryServices.GetByAddress( strAddress );
				if ( pService == NULL )
				{
					strAddress.AppendFormat(_T(":%u"), pResolve->m_nPort );
					pService = DiscoveryServices.GetByAddress( strAddress );
				}

				if ( pService != NULL )
				{
					pService->m_pAddress = *((IN_ADDR*)pResolve->m_pHost.h_addr);
					pService->m_nPort =  pResolve->m_nPort;
				}
				Datagrams.SendUDPHostCache((IN_ADDR*)pResolve->m_pHost.h_addr, pResolve->m_nPort, ubsDiscovery );
			}
			else if ( pResolve->m_nProtocol == PROTOCOL_G2 )
			{
				strAddress.Format( _T("ukhl:%s"), LPCTSTR(*(pResolve->m_sAddress)) );
				pService = DiscoveryServices.GetByAddress( strAddress );
				if ( pService == NULL )
				{
					strAddress.AppendFormat(_T(":%u"), pResolve->m_nPort );
					pService = DiscoveryServices.GetByAddress( strAddress );
				}

				if ( pService != NULL )
				{
					pService->m_pAddress =  *((IN_ADDR*)pResolve->m_pHost.h_addr);
					pService->m_nPort =  pResolve->m_nPort;
				}
				Datagrams.SendUDPKnownHubCache((IN_ADDR*)pResolve->m_pHost.h_addr, pResolve->m_nPort, ubsDiscovery );
			}
		}
	}
	else if ( pResolve->m_nCommand == 0 )
	{
		theApp.Message( MSG_ERROR, IDS_NETWORK_RESOLVE_FAIL, LPCTSTR( *pResolve->m_sAddress ) );
	}
	else
	{
		if ( pResolve->m_nCommand == 3 )
		{
			if ( pResolve->m_nProtocol == PROTOCOL_G1 )
			{
				strAddress.Format( _T("uhc:%s"), LPCTSTR(*(pResolve->m_sAddress)) );
				pService = DiscoveryServices.GetByAddress( strAddress );
				if ( pService == NULL )
				{
					strAddress.AppendFormat(_T(":%u"), pResolve->m_nPort );
					pService = DiscoveryServices.GetByAddress( strAddress );
				}

				if ( pService != NULL )
				{
					pService->OnFailure();
				}
			}
			else if ( pResolve->m_nProtocol == PROTOCOL_G2 )
			{
				strAddress.Format( _T("ukhl:%s"), LPCTSTR(*(pResolve->m_sAddress)) );
				pService = DiscoveryServices.GetByAddress( strAddress );
				if ( pService == NULL )
				{
					strAddress.AppendFormat(_T(":%u"), pResolve->m_nPort );
					pService = DiscoveryServices.GetByAddress( strAddress );
				}

				if ( pService != NULL )
				{
					pService->OnFailure();
				}
			}
		}

	}

	delete pResolve->m_sAddress;
	delete pResolve;
}

//////////////////////////////////////////////////////////////////////
// CNetwork get node route

BOOL CNetwork::GetNodeRoute(const Hashes::Guid& oGUID, CNeighbour** ppNeighbour, SOCKADDR_IN* pEndpoint)
{
	if ( validAndEqual( oGUID, Hashes::Guid( MyProfile.oGUID ) ) ) return FALSE;
	
	if ( Network.NodeRoute->Lookup( oGUID, ppNeighbour, pEndpoint ) ) return TRUE;
	if ( ppNeighbour == NULL ) return FALSE;
	
	for ( POSITION pos = Neighbours.GetIterator() ; pos ; )
	{
		CNeighbour* pNeighbour = Neighbours.GetNext( pos );
		
		if ( validAndEqual( pNeighbour->m_oGUID, oGUID ) )
		{
			*ppNeighbour = pNeighbour;
			return TRUE;
		}
	}
	
	return FALSE;
}

//////////////////////////////////////////////////////////////////////
// CNetwork route generic packets

BOOL CNetwork::RoutePacket(CG2Packet* pPacket)
{
	Hashes::Guid oGUID;
	
	if ( ! pPacket->GetTo( oGUID ) || validAndEqual( oGUID, Hashes::Guid( MyProfile.oGUID ) ) ) return FALSE;
	
	CNeighbour* pOrigin = NULL;
	SOCKADDR_IN pEndpoint;
	
	if ( GetNodeRoute( oGUID, &pOrigin, &pEndpoint ) )
	{
		if ( pOrigin != NULL )
		{
			if ( pOrigin->m_nProtocol == PROTOCOL_G1 &&
				 pPacket->IsType( G2_PACKET_PUSH ) )
			{
				//CG1Neighbour* pG1 = (CG1Neighbour*)pOrigin;
				//pPacket->SkipCompound();
				//pG1->SendG2Push( oGUID, pPacket );
				return TRUE;
			}
			else
			{
				pOrigin->Send( pPacket, FALSE, TRUE );
			}
		}
		else
		{
			Datagrams.Send( &pEndpoint, pPacket, FALSE );
		}
		
		Statistics.Current.Gnutella2.Routed++;
	}
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CNetwork send a push request

BOOL CNetwork::SendPush(const Hashes::Guid& oGUID, DWORD nIndex, PROTOCOLID nProtocol, IN_ADDR pAddress, WORD nPort,
						HubList& oPushProxyList, HubList& oHubList)
{
	if ( !m_bEnabled ) return FALSE;
	m_pMessageQueue.PushMessage( (CITMQueue::CITMItem*)CITMSendPush::CreateMessage( nProtocol, oGUID, nIndex, pAddress, nPort,
								oPushProxyList, oHubList ) );

	return TRUE;
}

BOOL CNetwork::SendPush( CDownloadSource * pSource )
{
	if ( !m_bEnabled ) return FALSE;
	m_pMessageQueue.PushMessage( (CITMQueue::CITMItem*)CITMSendPush::CreateMessage( pSource->m_nProtocol, pSource->m_oGUID,
								pSource->m_nIndex, pSource->m_pAddress, pSource->m_nPort, pSource->m_oPushProxyList,
								pSource->m_oHubList ) );
	return TRUE;

}

//////////////////////////////////////////////////////////////////////
// CNetwork hit routing

BOOL CNetwork::RouteHits(CQueryHit* pHits, CPacket* pPacket)
{
	SOCKADDR_IN pEndpoint;
	CNeighbour* pOrigin;
	
	if ( ! QueryRoute->Lookup( pHits->m_oSearchID, &pOrigin, &pEndpoint ) ) return FALSE;
	
	//BOOL bWrapped = FALSE;
	
	if ( pPacket->m_nProtocol == PROTOCOL_G1 )
	{
		CG1Packet* pG1 = (CG1Packet*)pPacket;
		if ( ! pG1->Hop() ) return FALSE;
	}
	else if ( pPacket->m_nProtocol == PROTOCOL_G2 )
	{
		CG2Packet* pG2 = (CG2Packet*)pPacket;

		if ( pG2->IsType( G2_PACKET_HIT ) && pG2->m_nLength > 17 )
		{
			BYTE* pHops = pG2->m_pBuffer + pG2->m_nLength - 17;
			if ( *pHops > Settings.Gnutella1.MaximumTTL ) return FALSE;
			(*pHops) ++;
		}
		else if ( pG2->IsType( G2_PACKET_HIT_WRAP ) )
		{
			//if ( ! pG2->SeekToWrapped() ) return FALSE;
			//GNUTELLAPACKET* pG1 = (GNUTELLAPACKET*)( pPacket->m_pBuffer + pPacket->m_nPosition );
			//if ( pG1->m_nTTL == 0 ) return FALSE;
			//pG1->m_nTTL --;
			//pG1->m_nHops ++;
			//bWrapped = TRUE;
		}
	}
	
	if ( pOrigin != NULL )
	{
		if ( pOrigin->m_nProtocol == pPacket->m_nProtocol )
		{
			pOrigin->Send( pPacket, FALSE, FALSE );	// Don't buffer
		}
		else if ( pOrigin->m_nProtocol == PROTOCOL_G1 && pPacket->m_nProtocol == PROTOCOL_G2 )
		{
			//if ( ! bWrapped ) return FALSE;
			//pPacket = CG1Packet::New( (GNUTELLAPACKET*)( pPacket->m_pBuffer + pPacket->m_nPosition ) );
			//pOrigin->Send( pPacket, TRUE, TRUE );
		}
		else if ( pOrigin->m_nProtocol == PROTOCOL_G2 && pPacket->m_nProtocol == PROTOCOL_G1 )
		{
			//pPacket = CG2Packet::New( G2_PACKET_HIT_WRAP, (CG1Packet*)pPacket );
			//pOrigin->Send( pPacket, TRUE, FALSE );	// Don't buffer
		}
		else
		{
			// Should not happen either (logic flaw)
			return FALSE;
		}
	}
	else if ( pPacket->m_nProtocol == PROTOCOL_G2 )
	{
		if ( pEndpoint.sin_addr.S_un.S_addr == Network.m_pHost.sin_addr.S_un.S_addr ) return FALSE;
		Datagrams.Send( &pEndpoint, (CG2Packet*)pPacket, FALSE );
	}
	else
	{
		if ( pEndpoint.sin_addr.S_un.S_addr == Network.m_pHost.sin_addr.S_un.S_addr ) return FALSE;
		//pPacket = CG2Packet::New( G2_PACKET_HIT_WRAP, (CG1Packet*)pPacket );
		//Datagrams.Send( &pEndpoint, (CG2Packet*)pPacket, TRUE );
	}
	
	if ( pPacket->m_nProtocol == PROTOCOL_G1 )
		Statistics.Current.Gnutella1.Routed++;
	else if ( pPacket->m_nProtocol == PROTOCOL_G2 )
		Statistics.Current.Gnutella2.Routed++;
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CNetwork common handler functions

void CNetwork::OnQuerySearch(CQuerySearch* pSearch, BOOL bOUT)
{
	
	if (bOUT) return;

	CSingleLock pListLock( &theApp.m_mSearchMonitorList );
	CSingleLock pLock( &theApp.m_pSection );
	
	/*
	if ( pLock.Lock( 10 ) )
	{
		if ( CMainWnd* pMainWnd = theApp.SafeMainWnd() )
		{
			CWindowManager* pWindows	= &pMainWnd->m_pWindows;
			CRuntimeClass* pClass		= RUNTIME_CLASS(CSearchMonitorWnd);
			CChildWnd* pChildWnd		= NULL;

			while ( ( pChildWnd = pWindows->Find( pClass, pChildWnd ) ) != NULL )
			{
				pChildWnd->OnQuerySearch( pSearch, bOUT );
			}
		}

		pLock.Unlock();
	}
	*/

	if ( !theApp.m_oSearchMonitorList.empty() && pLock.Lock( 50 ) )
	{
		if ( pListLock.Lock( 10 ) )
		{
			std::list<CSearchMonitorWnd*>::iterator iIndex = theApp.m_oSearchMonitorList.begin();
			std::list<CSearchMonitorWnd*>::iterator iEnd = theApp.m_oSearchMonitorList.end();
			while ( iIndex != iEnd )
			{
				(*iIndex)->OnQuerySearch( pSearch, bOUT );
				iIndex++;
			}
			pLock.Unlock();
		}
		pListLock.Unlock();
	}
}

void CNetwork::OnQueryHits(CQueryHit* pHits)
{
	Downloads.OnQueryHits( pHits );
	theApp.OnQueryHits( pHits );

/*
	CSingleLock pLock( &theApp.m_pSection );

	if ( pLock.Lock( 250 ) )
	{
		if ( CMainWnd* pMainWnd = theApp.SafeMainWnd() )
		{
			CWindowManager* pWindows	= &pMainWnd->m_pWindows;
			CChildWnd* pMonitorWnd		= NULL;
			CRuntimeClass* pMonitorType	= RUNTIME_CLASS(CHitMonitorWnd);
			CChildWnd* pChildWnd		= NULL;

			while ( ( pChildWnd = pWindows->Find( NULL, pChildWnd ) ) != NULL )
			{
				if ( pChildWnd->GetRuntimeClass() == pMonitorType )
				{
					pMonitorWnd = pChildWnd;
				}
				else
				{
					if ( pChildWnd->OnQueryHits( pHits ) ) return;
				}
			}

			if ( pMonitorWnd != NULL )
			{
				if ( pMonitorWnd->OnQueryHits( pHits ) ) return;
			}
		}

		pLock.Unlock();
	}
*/

	pHits->Delete();
}
