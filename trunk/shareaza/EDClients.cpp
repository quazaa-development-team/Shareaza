//
// EDClients.cpp
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
#include "Transfers.h"
#include "EDClient.h"
#include "EDClients.h"
#include "EDPacket.h"

#include "Network.h"
#include "Security.h"
#include "Datagrams.h"
#include "Downloads.h"
#include "QueryHit.h"
#include "SearchManager.h"

#include "Neighbours.h"
#include "HostCache.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

CEDClients EDClients;


//////////////////////////////////////////////////////////////////////
// CEDClients construction

CEDClients::CEDClients()
{
	m_pFirst			= NULL;
	m_pLast				= NULL;
	m_nCount			= 0;
	m_tLastRun			= 0;
	m_tLastMaxClients	= 0;
	m_tLastServerStats	= 0;
	m_nLastServerKey	= 0;
	m_bAllServersDone	= FALSE;
}

CEDClients::~CEDClients()
{
	Clear();
}

//////////////////////////////////////////////////////////////////////
// CEDClients add and remove

void CEDClients::Add(CEDClient* pClient)
{
	ASSERT( pClient->m_pEdPrev == NULL );
	ASSERT( pClient->m_pEdNext == NULL );
	
	pClient->m_pEdPrev = m_pLast;
	pClient->m_pEdNext = NULL;
	
	if ( m_pLast != NULL )
	{
		m_pLast->m_pEdNext = pClient;
		m_pLast = pClient;
	}
	else
	{
		m_pFirst = m_pLast = pClient;
	}
	
	m_nCount++;
}

void CEDClients::Remove(CEDClient* pClient)
{
	ASSERT( m_nCount > 0 );
	
	if ( pClient->m_pEdPrev != NULL )
		pClient->m_pEdPrev->m_pEdNext = pClient->m_pEdNext;
	else
		m_pFirst = pClient->m_pEdNext;
	
	if ( pClient->m_pEdNext != NULL )
		pClient->m_pEdNext->m_pEdPrev = pClient->m_pEdPrev;
	else
		m_pLast = pClient->m_pEdPrev;
	
	m_nCount --;
}

//////////////////////////////////////////////////////////////////////
// CEDClients clear

void CEDClients::Clear()
{
	for ( CEDClient* pClient = m_pFirst ; pClient ; )
	{
		CEDClient* pNext = pClient->m_pEdNext;
		pClient->Remove();
		pClient = pNext;
	}
	
	ASSERT( m_pFirst == NULL );
	ASSERT( m_pLast == NULL );
	ASSERT( m_nCount == 0 );
}

//////////////////////////////////////////////////////////////////////
// CEDClients push connection setup

BOOL CEDClients::PushTo(DWORD nClientID, WORD nClientPort)
{
	CEDClient* pClient = Connect( nClientID, nClientPort, NULL, 0, Hashes::Guid() );
	if ( pClient == NULL ) return FALSE;
	return pClient->Connect();
}

//////////////////////////////////////////////////////////////////////
// CEDClients connection setup

CEDClient* CEDClients::Connect(DWORD nClientID, WORD nClientPort, IN_ADDR* pServerAddress, WORD nServerPort, const Hashes::Guid& oGUID)
{
	if ( oGUID )
	{
		if ( CEDClient* pClient = GetByGUID( oGUID ) ) return pClient;
	}
	
	if ( IsFull() ) return NULL;
	
	CEDClient* pClient = NULL;
	
	if ( CEDPacket::IsLowID( nClientID ) )
	{
		if ( pServerAddress == NULL || nServerPort == 0 ) return NULL;
		pClient = GetByID( nClientID, pServerAddress, oGUID );
	}
	else
	{
		if ( Security.IsDenied( (IN_ADDR*)&nClientID ) ) return NULL;
		pClient = GetByID( nClientID, NULL, oGUID );
	}
	
	if ( pClient == NULL )
	{
		pClient = new CEDClient();
		pClient->ConnectTo( nClientID, nClientPort, pServerAddress, nServerPort, oGUID );
	}
	
	return pClient;
}

//////////////////////////////////////////////////////////////////////
// CEDClients find by client ID and/or GUID

CEDClient* CEDClients::GetByIP(IN_ADDR* pAddress)
{
	for ( CEDClient* pClient = m_pFirst ; pClient ; pClient = pClient->m_pEdNext )
	{
		if ( pClient->m_pHost.sin_addr.S_un.S_addr == pAddress->S_un.S_addr )
			return pClient;
	}
	
	return NULL;
}

CEDClient* CEDClients::GetByID(DWORD nClientID, IN_ADDR* pServer, const Hashes::Guid& oGUID)
{
	for ( CEDClient* pClient = m_pFirst ; pClient ; pClient = pClient->m_pEdNext )
	{
		if ( pServer && pClient->m_pServer.sin_addr.S_un.S_addr != pServer->S_un.S_addr ) continue;
		
		if ( pClient->m_nClientID == nClientID )
		{
			if ( !oGUID || validAndEqual( pClient->m_oGUID, oGUID ) ) return pClient;
		}
	}
	
	return NULL;
}

CEDClient* CEDClients::GetByGUID(const Hashes::Guid& oGUID)
{
	for ( CEDClient* pClient = m_pFirst ; pClient ; pClient = pClient->m_pEdNext )
	{
		if ( validAndEqual( pClient->m_oGUID, oGUID ) ) return pClient;
	}
	
	return NULL;
}

//////////////////////////////////////////////////////////////////////
// CEDClients merge

BOOL CEDClients::Merge(CEDClient* pClient)
{
	ASSERT( pClient != NULL );

	for ( CEDClient* pOther = m_pFirst ; pOther ; pOther = pOther->m_pEdNext )
	{
		if ( pOther != pClient && pOther->Equals( pClient ) )
		{
			pClient->Merge( pOther );
			pOther->Remove();
			return TRUE;
		}
	}
	
	return FALSE;
}

//////////////////////////////////////////////////////////////////////
// CEDClients full test

BOOL CEDClients::IsFull(CEDClient* pCheckThis)
{
	int nCount = 0;
	DWORD tNow = GetTickCount();

	// Count the number of connected clients
	for ( CEDClient* pClient = m_pFirst ; pClient ; pClient = pClient->m_pEdNext )
	{
		if ( pClient->m_hSocket != INVALID_SOCKET ) nCount++;
	}

	// If there are more clients current connected than there should be, set the full timer
	if ( nCount >= Settings.eDonkey.MaxLinks ) m_tLastMaxClients = tNow;

	// If we have not been full in the past 2 seconds, then we're okay to start new connections
	if ( ( tNow - m_tLastMaxClients ) > ( 2*1000 ) ) return FALSE;

	// If we're checking a client that's already connected, say we aren't full. (don't drop it)
	if ( ( pCheckThis != NULL ) && ( pCheckThis->m_hSocket != INVALID_SOCKET ) ) return FALSE;
	

	// We're too full to start new connections
	return TRUE;


/*
	if ( pCheckThis != NULL )
	{
		for ( CEDClient* pClient = m_pFirst ; pClient ; pClient = pClient->m_pEdNext )
		{
			if ( pClient->m_hSocket != INVALID_SOCKET ) nCount++;
			if ( pClient == pCheckThis ) pCheckThis = NULL;
		}
	}
	else
	{
		for ( CEDClient* pClient = m_pFirst ; pClient ; pClient = pClient->m_pEdNext )
		{
			if ( pClient->m_hSocket != INVALID_SOCKET ) nCount++;
		}
	}
	
	ASSERT( pCheckThis == NULL );
	return ( nCount >= Settings.eDonkey.MaxLinks ) || ( pCheckThis != NULL );*/
}

BOOL CEDClients::IsOverloaded()
{
	int nCount = 0;

	for ( CEDClient* pClient = m_pFirst ; pClient ; pClient = pClient->m_pEdNext )
	{
		if ( pClient->m_hSocket != INVALID_SOCKET ) nCount++;
	}
	
	return ( nCount >= ( Settings.eDonkey.MaxLinks + 25 ) );
}


//////////////////////////////////////////////////////////////////////
// CEDClients run

void CEDClients::OnRun()
{

	// Delay to limit the rate of ed2k packets being sent.
	// keep ed2k transfers under 10 KB/s per source
	DWORD tNow = GetTickCount();
	if ( tNow - m_tLastRun < Settings.eDonkey.PacketThrottle ) return;
	m_tLastRun = tNow;

	if ( Settings.eDonkey.ServerWalk && Settings.eDonkey.EnableToday )
	{
		RunGlobalStatsRequests( tNow );
	}
	
	for ( CEDClient* pClient = m_pFirst ; pClient ; )
	{
		CEDClient* pNext = pClient->m_pEdNext;
		pClient->OnRunEx( tNow );
		pClient = pNext;
	}
}

//////////////////////////////////////////////////////////////////////
// CEDClients accept new connections

BOOL CEDClients::OnAccept(CConnection* pConnection)
{
	ASSERT( pConnection != NULL );
	
	if ( Settings.Connection.RequireForTransfers && ! Settings.eDonkey.EnableToday )
	{
		theApp.Message( MSG_ERROR, IDS_ED2K_CLIENT_DISABLED,
			(LPCTSTR)pConnection->m_sAddress );
		return FALSE;
	}
	
	CSingleLock pLock( &Transfers.m_pSection );
	if ( ! pLock.Lock( 250 ) ) return FALSE;

	if ( IsFull() )
	{
		// Even if we're full, we still need to accept connections from clients we have queued, etc
		if ( ( GetByIP( &pConnection->m_pHost.sin_addr ) == NULL ) || ( IsOverloaded() ) )
		{
			theApp.Message( MSG_DEBUG, _T("Rejecting ed2k connection from %s, max client connections reached."),
				(LPCTSTR)pConnection->m_sAddress );
			return FALSE;
		}
		else 
		{
			theApp.Message( MSG_DEBUG, _T("Accepting ed2k connection from %s despite client connection limit."),
				(LPCTSTR)pConnection->m_sAddress );

		}
	}
	
	CEDClient* pClient = new CEDClient();
	pClient->AttachTo( pConnection );
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CEDClients process UDP Packets

// UDP packet received
BOOL CEDClients::OnUDP(SOCKADDR_IN* pHost, CEDPacket* pPacket)
{
	CSingleLock pLock( &Transfers.m_pSection );
	
	switch ( pPacket->m_nType )
	{
	case ED2K_C2C_UDP_REASKFILEPING:
		if ( ! pLock.Lock( 100 ) ) return FALSE;
		if ( CEDClient* pClient = GetByIP( &pHost->sin_addr ) )
		{
			pClient->m_nUDP = ntohs( pHost->sin_port );
			
			if ( ! pClient->OnUdpReask( pPacket ) )
			{
				Datagrams.Send( pHost, CEDPacket::New( ED2K_C2C_UDP_FILENOTFOUND, ED2K_PROTOCOL_EMULE ) );
			}
		}
		else
		{
			Datagrams.Send( pHost, CEDPacket::New( ED2K_C2C_UDP_FILENOTFOUND, ED2K_PROTOCOL_EMULE ) );
		}
		break;
	case ED2K_C2C_UDP_REASKACK:
		if ( ! pLock.Lock( 100 ) ) return FALSE;
		if ( CEDClient* pClient = GetByIP( &pHost->sin_addr ) )
		{
			pClient->m_nUDP = ntohs( pHost->sin_port );
			pClient->OnUdpReaskAck( pPacket );
		}
		break;
	case ED2K_C2C_UDP_QUEUEFULL:
		if ( ! pLock.Lock( 100 ) ) return FALSE;
		if ( CEDClient* pClient = GetByIP( &pHost->sin_addr ) )
		{
			pClient->m_nUDP = ntohs( pHost->sin_port );
			pClient->OnUdpQueueFull( pPacket );
		}
		break;
	case ED2K_C2C_UDP_FILENOTFOUND:
		if ( ! pLock.Lock( 100 ) ) return FALSE;
		if ( CEDClient* pClient = GetByIP( &pHost->sin_addr ) )
		{
			pClient->m_nUDP = ntohs( pHost->sin_port );
			pClient->OnUdpFileNotFound( pPacket );
		}
		break;
	case ED2K_S2CG_SERVERSTATUS:
		OnServerStatus( pHost, pPacket );
		break;
	case ED2K_S2CG_SEARCHRESULT:
	case ED2K_S2CG_FOUNDSOURCES:
		// Correct port value. (UDP port is TCP port + 4)
		pHost->sin_port = htons( ntohs( pHost->sin_port ) - 4 );

		// Check server details in host cache
		CHostCacheHost *pServer;
		DWORD nServerFlags = Settings.eDonkey.DefaultServerFlags;
		pServer = HostCache.eDonkey.Find( &pHost->sin_addr );
		if ( pServer && pServer->m_nUDPFlags )
		{
			nServerFlags = pServer->m_nUDPFlags;
		}

		// Decode packet and create hits
		if ( CQueryHit* pHits = CQueryHit::FromPacket( pPacket, pHost, nServerFlags ) )
		{
			Downloads.OnQueryHits( pHits );
			
			if ( pPacket->m_nType == ED2K_S2CG_SEARCHRESULT )
				Network.OnQueryHits( pHits );
			else
				pHits->Delete();
		}
		break;
	}
	
	return TRUE;
}

// Server status packet received
void CEDClients::OnServerStatus(SOCKADDR_IN* /*pHost*/, CEDPacket* pPacket)
{
	DWORD nLen, nKey;
	DWORD nUsers = 0, nFiles = 0, nMaxUsers = 0, nFileLimit = 1000, nUDPFlags = 0;

	// Read in and check the key value to make sure we requested this update
	nKey = pPacket->ReadLongLE();
	if ( nKey != m_nLastServerKey )
	{
		theApp.Message( MSG_ERROR, _T("Received unexpected server status" ) );
		return;
	}

	// Got a status update we were expecting.
	m_nLastServerKey = 0;
	CHostCacheHost *pServer = HostCache.eDonkey.Find( &m_pLastServer );
	if ( pServer == NULL )
	{
		theApp.Message( MSG_DEFAULT, _T("Server status received, but server not found in host cache") );
		return;
	}
	if ( pServer->m_sName.GetLength() )
		theApp.Message( MSG_DEFAULT, _T("Server status received from %s"), pServer->m_sName );
	else
		theApp.Message( MSG_DEFAULT, _T("Server status received from %s"),
            (LPCTSTR)CString( inet_ntoa( m_pLastServer ) ) );

	// Read in the status packet
	nLen = pPacket->GetRemaining();

	if ( nLen >= 8 ) 
	{
		// Current users and files indexed
		nUsers = pPacket->ReadLongLE();
		nFiles = pPacket->ReadLongLE();
	}
	if ( nLen >= 12 ) 
	{
		// Maximum users allowed
		nMaxUsers = pPacket->ReadLongLE();
	}
	if ( nLen >= 20 ) 
	{
		// Client file limit. (Maximum files you can send to the server)
		nFileLimit = pPacket->ReadLongLE();	// Soft limit. (Files over this are ignored)
		pPacket->ReadLongLE();				// 'Hard' limit. (Obey previous, it saves bandwidth)
	}
	if ( nLen >= 24 ) 
	{
		// UDP Flags. (This is important, it determines search types, etc)
		nUDPFlags = pPacket->ReadLongLE();
	}
	if ( nLen >= 28 ) 
	{
		// Low ID users. 
		pPacket->ReadLongLE(); // We don't use this
	}

	// Update the server variables
	pServer->m_nFailures	= 0;
	pServer->m_tFailure		= 0;
	pServer->m_nUserCount	= nUsers;
	pServer->m_nUserLimit	= nMaxUsers;
	pServer->m_nFileLimit	= nFileLimit;
	pServer->m_nUDPFlags	= nUDPFlags;

	if ( pServer->m_tSeen < pServer->m_tStats ) 
		pServer->m_tSeen = pServer->m_tStats;
	if ( nUDPFlags & ED2K_SERVER_UDP_UNICODE ) 
		pServer->m_nTCPFlags |= ED2K_SERVER_TCP_UNICODE;
	if ( nUDPFlags & ED2K_SERVER_UDP_GETSOURCES2 ) 
		pServer->m_nTCPFlags |= ED2K_SERVER_TCP_GETSOURCES2;

	//CString strT;
	//strT.Format( _T("Users:%d Files:%d Max Users:%d File limit:%d UDP flags:%08X"), nUsers, nFiles, nMaxUsers, nFileLimit, nUDPFlags );
	//theApp.Message( MSG_DEFAULT, strT );
}

// Send a server status request
void CEDClients::RequestServerStatus(IN_ADDR* pHost, WORD nPort)
{
	CEDPacket* pPacket = CEDPacket::New( ED2K_C2SG_SERVERSTATUSREQUEST, ED2K_PROTOCOL_EDONKEY );

	srand( GetTickCount() );
	m_nLastServerKey = 0x55AA0000 + rand();
	pPacket->WriteLongLE( m_nLastServerKey );
	Datagrams.Send( pHost, nPort + 4, pPacket );
}

//////////////////////////////////////////////////////////////////////
// CEDClients send/time out UDP global server status packets

void CEDClients::RunGlobalStatsRequests(DWORD tNow)
{
	CHostCacheHost *pHost;

	// Don't send stat requests or time out servers if we're not stable
	if ( ! Datagrams.IsStable() ) return;

	if ( m_nLastServerKey != 0 )
	{
		// We are waiting for a response
		if ( tNow > m_tLastServerStats + Settings.Connection.TimeoutHandshake )
		{
			CSingleLock pLock( &Network.m_pSection );
			if ( ! pLock.Lock( 250 ) ) return;

			// Timed out
			m_nLastServerKey = 0;
			theApp.Message( MSG_DEBUG, _T("Time-out waiting for ed2k server status") );

			pHost = HostCache.eDonkey.Find( &m_pLastServer );
			if ( pHost )
			{
				pHost->m_tFailure = pHost->m_tStats;

				pHost->m_nFailures ++;
				// If we've had multiple failures, remove the host
				if ( pHost->m_nFailures > 3 )
				{		
					theApp.Message( MSG_DEFAULT, _T("Removing ed2k server %s"), pHost->m_sName );
					HostCache.eDonkey.Remove( pHost );
				}
			}	
			// Reset the timer so we query another server right away
			// m_tLastServerStats = 0;
			pLock.Unlock();
		}
	}

	if ( tNow > m_tLastServerStats + Settings.eDonkey.StatsGlobalThrottle )	// Limit requests to every 30 minutes
	{
		// We are due to send another stats request
		CSingleLock pLock( &Network.m_pSection );
		if ( ! pLock.Lock( 250 ) ) return;

		// Get the current time (in seconds)
		DWORD tSecs	= static_cast< DWORD >( time( NULL ) );

		// Loop through servers in the host cache
		for ( pHost = HostCache.eDonkey.GetNewest() ; pHost ; pHost = pHost->m_pPrevTime )
		{
			/*CString strT;
			strT.Format( _T("  -Name:%s Last Stats:%d UDP flags:%08X"), pHost->m_sName, pHost->m_tStats, pHost->m_nUDPFlags );
			theApp.Message( MSG_DEFAULT, strT );*/

			// Check if this server could be asked for stats
			if ( ( pHost->CanQuery( tSecs ) ) &&												// If it hasn't been searched recently	
				 ( ( tSecs > pHost->m_tStats + Settings.eDonkey.StatsServerThrottle  ) ||		// AND we have not checked this host in a week OR
				   ( ( pHost->m_nFailures > 0 ) && ( tSecs > pHost->m_tStats + 8*60*60  ) ) ) &&	// -last check failed, have not checked in 8 hours
				 ( ( pHost->m_nUDPFlags == 0 ) ||												// AND it has no flags set OR
				   ( m_bAllServersDone ) ) )														// -we have checked all servers		
			{
				// Don't ask current neighbours for stats
				if ( ! Neighbours.Get( &pHost->m_pAddress ) )
				{
					// Send a request for stats to this server
					if ( pHost->m_sName.GetLength() )
						theApp.Message( MSG_DEFAULT, _T("Sending status request to ed2k server %s"), pHost->m_sName );
					else
						theApp.Message( MSG_DEFAULT, _T("Sending status request to ed2k server %s"), (LPCTSTR)CString( inet_ntoa( pHost->m_pAddress ) ) );

					RequestServerStatus( &pHost->m_pAddress, pHost->m_nPort );
					pHost->m_tStats = tSecs;
					m_tLastServerStats = tNow;
					m_pLastServer = pHost->m_pAddress;
					return;
				}
			}
		}
		pLock.Unlock();

		// We have checked all known servers, we may go back and re-query any that didn't respond.
		m_bAllServersDone = TRUE;
		// Try again later. (we don't want to keep running this section, it's a little slow)
		m_tLastServerStats = tNow;
	}
}
