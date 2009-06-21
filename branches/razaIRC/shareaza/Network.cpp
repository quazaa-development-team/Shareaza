//
// Network.cpp
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
#include "Handshakes.h"
#include "Neighbours.h"
#include "Neighbour.h"
#include "Datagrams.h"
#include "HostCache.h"
#include "RouteCache.h"
#include "QueryKeys.h"
#include "GProfile.h"
#include "Transfers.h"
#include "Downloads.h"
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
#include "G1Neighbour.h"

#include "WndMain.h"
#include "WndChild.h"
#include "WndSearchMonitor.h"
#include "WndHitMonitor.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

CNetwork Network;


//////////////////////////////////////////////////////////////////////
// CNetwork construction

CNetwork::CNetwork()
{
	NodeRoute				= new CRouteCache();
	QueryRoute				= new CRouteCache();
	QueryKeys				= new CQueryKeys();
	
	m_bEnabled				= FALSE;
	m_bAutoConnect			= FALSE;
	m_tStartedConnecting	= 0;
	m_tLastConnect			= 0;
	m_tLastED2KServerHop	= 0;

	m_nSequence				= 0;
	m_hThread				= NULL;
	ZeroMemory( &m_pHost, sizeof( m_pHost ) );
	m_pHost.sin_family		= AF_INET;
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
	// If a connection isn't needed for transfers, we can start any time
	if ( ! Settings.Connection.RequireForTransfers )
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
		Settings.Gnutella1.EnableToday = Settings.Gnutella1.EnableAlways;
		Settings.Gnutella2.EnableToday = Settings.Gnutella2.EnableAlways;
		Settings.eDonkey.EnableToday = Settings.eDonkey.EnableAlways;
	}

	CSingleLock pLock( &m_pSection, TRUE );
	
	Settings.Live.AutoClose = FALSE;
	if ( bAutoConnect ) 
	{
		m_bAutoConnect = TRUE;
		// Remove really old G1 hosts before trying to connect to G1
		if ( Settings.Gnutella1.EnableToday ) HostCache.Gnutella1.PruneOldHosts();
	}
	
	// If we are already connected, see if we need to query discovery services and exit.
	if ( m_bEnabled )
	{
		if ( bAutoConnect ) DiscoveryServices.Execute();
		return TRUE;
	}
	
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
	
	if ( Settings.Connection.FirewallStatus == CONNECTION_FIREWALLED )
		theApp.Message( MSG_DEFAULT, IDS_NETWORK_FIREWALLED );
	
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
	
	Handshakes.Listen();
	Datagrams.Listen();
	Neighbours.Connect();
	
	NodeRoute->SetDuration( Settings.Gnutella.RouteCache );
	QueryRoute->SetDuration( Settings.Gnutella.RouteCache );
	
	m_bEnabled				= TRUE;
	m_tStartedConnecting	= GetTickCount();
	CWinThread* pThread = AfxBeginThread( ThreadStart, this, THREAD_PRIORITY_NORMAL );
	m_hThread				= pThread->m_hThread;
	SetThreadName( pThread->m_nThreadID, "Network" );
	
	// if ( m_bAutoConnect && bAutoConnect ) DiscoveryServices.Execute();
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CNetwork disconnect

void CNetwork::Disconnect()
{
	CSingleLock pLock( &m_pSection, TRUE );
	
	if ( ! m_bEnabled ) return;
	
	Settings.Gnutella1.EnableToday = !Settings.Connection.RequireForTransfers;
	Settings.Gnutella2.EnableToday = !Settings.Connection.RequireForTransfers;
	Settings.eDonkey.EnableToday = !Settings.Connection.RequireForTransfers;

	theApp.Message( MSG_DEFAULT, _T("") );
	theApp.Message( MSG_SYSTEM, IDS_NETWORK_DISCONNECTING );
	
	m_bEnabled				= FALSE;
	m_bAutoConnect			= FALSE;
	m_tStartedConnecting	= 0;
	
	Neighbours.Close();
	
	pLock.Unlock();
	
	if ( m_hThread != NULL )
	{
		m_pWakeup.SetEvent();
		
        int nAttempt = 10;
		for ( ; nAttempt > 0 ; nAttempt-- )
		{
			DWORD nCode;
			if ( ! GetExitCodeThread( m_hThread, &nCode ) ) break;
			if ( nCode != STILL_ACTIVE ) break;
			Sleep( 100 );
		}
		
		if ( nAttempt == 0 )
		{
			TerminateThread( m_hThread, 0 );
			theApp.Message( MSG_DEBUG, _T("WARNING: Terminating CNetwork thread.") );
			Sleep( 100 );
		}
		
		m_hThread = NULL;
	}
	
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
	
	DiscoveryServices.Stop();
	
	theApp.Message( MSG_SYSTEM, IDS_NETWORK_DISCONNECTED ); 
	theApp.Message( MSG_DEFAULT, _T("") );
}

//////////////////////////////////////////////////////////////////////
// CNetwork host connection

BOOL CNetwork::ConnectTo(LPCTSTR pszAddress, int nPort, PROTOCOLID nProtocol, BOOL bNoUltraPeer)
{
	CSingleLock pLock( &m_pSection, TRUE );
	
	if ( ! m_bEnabled && ! Connect() ) return FALSE;
	
	if ( nPort == 0 ) nPort = GNUTELLA_DEFAULT_PORT;
	theApp.Message( MSG_DEFAULT, IDS_NETWORK_RESOLVING, pszAddress );
	
	if ( AsyncResolve( pszAddress, (WORD)nPort, nProtocol, bNoUltraPeer ? 2 : 1 ) ) return TRUE;
	
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
	
	if ( IsFirewalledAddress( &pAddress ) ) return;
	
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

BOOL CNetwork::IsFirewalledAddress(LPVOID pAddress, BOOL bIncludeSelf)
{
	if ( ! pAddress ) return TRUE;
	if ( ! Settings.Connection.IgnoreLocalIP ) return FALSE;
	
	DWORD nAddress = *(DWORD*)pAddress;
	
	if ( ! nAddress ) return TRUE;
	if ( ( nAddress & 0xFFFF ) == 0xA8C0 ) return TRUE;
	if ( ( nAddress & 0xF0AC ) == 0x08AC ) return TRUE;
	if ( ( nAddress & 0xFF ) == 0x0A ) return TRUE;
	if ( ( nAddress & 0xFF ) == 0x7F ) return TRUE;		// 127.*
	
	if ( bIncludeSelf && nAddress == *(DWORD*)(&m_pHost.sin_addr) ) return TRUE;
	
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
	DWORD m_tUPnP = GetTickCount();
	while ( m_bEnabled )
	{
		Sleep( 50 );
		WaitForSingleObject( m_pWakeup, 100 );
	
		if ( ! theApp.m_bLive ) continue;
		if ( theApp.m_pUPnPFinder && theApp.m_pUPnPFinder->IsAsyncFindRunning() )
		{
			// If the UPnP device host service hangs we can do nothing.
			// In this situation only reboot helps since network thread stucks
			// when we try to kill or reset the finder.
			if ( GetTickCount() - m_tUPnP < 30000 )
				continue;
			else
			{
				theApp.m_bUPnPPortsForwarded = TS_FALSE;
			}
		}

		if ( m_bEnabled && m_pSection.Lock() )
		{
			Datagrams.OnRun();
			SearchManager.OnRun();
			QueryHashMaster.Build();
			
			if ( CrawlSession.m_bActive ) CrawlSession.OnRun();
			
			m_pSection.Unlock();
		}
		
		Neighbours.OnRun();
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

	if ( WSAGETASYNCERROR(lParam) == 0 )
	{
		if ( pResolve->m_nCommand == 0 )
		{
			HostCache.ForProtocol( pResolve->m_nProtocol )->Add( (IN_ADDR*)pResolve->m_pHost.h_addr, pResolve->m_nPort );
		}
		else
		{
			Neighbours.ConnectTo( (IN_ADDR*)pResolve->m_pHost.h_addr, pResolve->m_nPort, pResolve->m_nProtocol, FALSE, pResolve->m_nCommand );
		}
	}
	else if ( pResolve->m_nCommand > 0 )
	{
		theApp.Message( MSG_ERROR, IDS_NETWORK_RESOLVE_FAIL, LPCTSTR( *pResolve->m_sAddress ) );
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
				CG1Neighbour* pG1 = (CG1Neighbour*)pOrigin;
				pPacket->SkipCompound();
				pG1->SendG2Push( oGUID, pPacket );
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

BOOL CNetwork::SendPush(const Hashes::Guid& oGUID, DWORD nIndex)
{
	CSingleLock pLock( &Network.m_pSection );
	if ( ! pLock.Lock( 250 ) ) return TRUE;

	if ( ! IsListening() ) return FALSE;
	
	Hashes::Guid oGUID2 = oGUID;
	SOCKADDR_IN pEndpoint;
	CNeighbour* pOrigin;
	int nCount = 0;
	
	while ( GetNodeRoute( oGUID2, &pOrigin, &pEndpoint ) )
	{
		if ( pOrigin != NULL && pOrigin->m_nProtocol == PROTOCOL_G1 )
		{
			CG1Packet* pPacket = CG1Packet::New( G1_PACKET_PUSH,
				Settings.Gnutella1.MaximumTTL - 1 );
			
			pPacket->Write( oGUID );
			pPacket->WriteLongLE( nIndex );
			pPacket->WriteLongLE( m_pHost.sin_addr.S_un.S_addr );
			pPacket->WriteShortLE( htons( m_pHost.sin_port ) );
			
			pOrigin->Send( pPacket );
		}
		else
		{
			CG2Packet* pPacket = CG2Packet::New( G2_PACKET_PUSH, TRUE );
			
			pPacket->WritePacket( G2_PACKET_TO, 16 );
			pPacket->Write( oGUID );
			
			pPacket->WriteByte( 0 );
			pPacket->WriteLongLE( m_pHost.sin_addr.S_un.S_addr );
			pPacket->WriteShortBE( htons( m_pHost.sin_port ) );
			
			if ( pOrigin != NULL )
			{
				pOrigin->Send( pPacket );
			}
			else
			{
				Datagrams.Send( &pEndpoint, pPacket );
			}
		}
		
		oGUID2[15] ++;
		nCount++;
	}
	
	return nCount > 0;
}

//////////////////////////////////////////////////////////////////////
// CNetwork hit routing

BOOL CNetwork::RouteHits(CQueryHit* pHits, CPacket* pPacket)
{
	SOCKADDR_IN pEndpoint;
	CNeighbour* pOrigin;
	
	if ( ! QueryRoute->Lookup( pHits->m_oSearchID, &pOrigin, &pEndpoint ) ) return FALSE;
	
	BOOL bWrapped = FALSE;
	
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
			if ( ! pG2->SeekToWrapped() ) return FALSE;
			GNUTELLAPACKET* pG1 = (GNUTELLAPACKET*)( pPacket->m_pBuffer + pPacket->m_nPosition );
			if ( pG1->m_nTTL == 0 ) return FALSE;
			pG1->m_nTTL --;
			pG1->m_nHops ++;
			bWrapped = TRUE;
		}
	}
	
	if ( pOrigin != NULL )
	{
		if ( pOrigin->m_nProtocol == pPacket->m_nProtocol )
		{
			pOrigin->Send( pPacket, FALSE, FALSE );	// Dont buffer
		}
		else if ( pOrigin->m_nProtocol == PROTOCOL_G1 && pPacket->m_nProtocol == PROTOCOL_G2 )
		{
			if ( ! bWrapped ) return FALSE;
			pPacket = CG1Packet::New( (GNUTELLAPACKET*)( pPacket->m_pBuffer + pPacket->m_nPosition ) );
			pOrigin->Send( pPacket, TRUE, TRUE );
		}
		else if ( pOrigin->m_nProtocol == PROTOCOL_G2 && pPacket->m_nProtocol == PROTOCOL_G1 )
		{
			pPacket = CG2Packet::New( G2_PACKET_HIT_WRAP, (CG1Packet*)pPacket );
			pOrigin->Send( pPacket, TRUE, FALSE );	// Dont buffer
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
		pPacket = CG2Packet::New( G2_PACKET_HIT_WRAP, (CG1Packet*)pPacket );
		Datagrams.Send( &pEndpoint, (CG2Packet*)pPacket, TRUE );
	}
	
	if ( pPacket->m_nProtocol == PROTOCOL_G1 )
		Statistics.Current.Gnutella1.Routed++;
	else if ( pPacket->m_nProtocol == PROTOCOL_G2 )
		Statistics.Current.Gnutella2.Routed++;
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CNetwork common handler functions

void CNetwork::OnQuerySearch(CQuerySearch* pSearch)
{
	CSingleLock pLock( &theApp.m_pSection );
	
	if ( pLock.Lock( 10 ) )
	{
		if ( CMainWnd* pMainWnd = theApp.SafeMainWnd() )
		{
			CWindowManager* pWindows	= &pMainWnd->m_pWindows;
			CRuntimeClass* pClass		= RUNTIME_CLASS(CSearchMonitorWnd);
			CChildWnd* pChildWnd		= NULL;

			while ( ( pChildWnd = pWindows->Find( pClass, pChildWnd ) ) != NULL )
			{
				pChildWnd->OnQuerySearch( pSearch );
			}
		}

		pLock.Unlock();
	}
}

void CNetwork::OnQueryHits(CQueryHit* pHits)
{
	Downloads.OnQueryHits( pHits );

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

	pHits->Delete();
}