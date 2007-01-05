//
// NeighboursWithG2.cpp
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

// Adds 2 methods helpful for Gnutella2 that look at the list of neighbours
// http://wiki.shareaza.com/static/Developers.Code.CNeighboursWithG2

// Copy in the contents of these files here before compiling
#include "StdAfx.h"
#include "Shareaza.h"
#include "Settings.h"
#include "Network.h"
#include "Datagrams.h"
#include "NeighboursWithG2.h"
#include "G2Neighbour.h"
#include "G2Packet.h"
#include "HubHorizon.h"
#include "RouteCache.h"
#include "HostCache.h"
#include "LibraryMaps.h"
#include "GProfile.h"
#include "VendorCache.h"
#include "Security.h"

// If we are compiling in debug mode, replace the text "THIS_FILE" in the code with the name of this file
#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////
// CNeighboursWithG2 construction

// Nothing that CNeighboursWithG2 adds to CNeighbours needs to be setup
CNeighboursWithG2::CNeighboursWithG2() :
m_nG2FileCount(0),
m_nG2FileVolume(0),
m_oHub(),
m_oLeaf()
{
}

// Nothing that CNeighboursWithG2 adds to CNeighbours needs to be put away
CNeighboursWithG2::~CNeighboursWithG2()
{
}

//////////////////////////////////////////////////////////////////////
// CNeighboursWithG2 connect

// Set the ping route cache duration from Gnutella settings, and setup the Gnutella2 hub horizon pool
void CNeighboursWithG2::Connect()
{
	if ( Settings.Gnutella2.EnableToday == TRUE )
	{
		HubHorizonPool.Setup();
	}

	// Set the ping route cache duration from the program settings for Gnutella
	CNeighboursWithG1::Connect();

	// Setup the Gnutella 2 hub horizon pool
}

void CNeighboursWithG2::ConnectG2()
{
	HubHorizonPool.Setup();
}

//////////////////////////////////////////////////////////////////////
// CNeighboursWithG2 close

void CNeighboursWithG2::Close()
{
	HubHorizonPool.Clear();
}

void CNeighboursWithG2::DisconnectG2()
{
	HubHorizonPool.Clear();
}

//////////////////////////////////////////////////////////////////////
// CNeighboursWithG2 create query web packet

// Takes a GUID, and a neighbour to except from the packet we will make
// Makes a Gnutella2 query web packet, containing the IP addresses of the computers we are connected to and from the Gnutella2 host cache
// Returns the packet
CG2Packet* CNeighboursWithG2::CreateQueryWeb(const Hashes::Guid& oGUID, CNeighbour* pExcept)
{
	// Make a new Gnutella2 Query Ack packet
	CG2Packet* pPacket = CG2Packet::New( G2_PACKET_QUERY_ACK, TRUE );

	// Start it with the text "TS" and the time now
	DWORD tNow = static_cast< DWORD >( time( NULL ) ); // Number of seconds since 1970
	pPacket->WritePacket( G2_PACKET_TIMESTAMP, 4 );
	pPacket->WriteLongBE( tNow );

	// Record that we are making this packet
	theApp.Message( MSG_DEBUG, _T("Creating a query acknowledgement:") );

	// Write in header information about us
	pPacket->WritePacket( G2_PACKET_QUERY_DONE, 8 );
	pPacket->WriteLongLE( Network.m_pHost.sin_addr.S_un.S_addr );
	pPacket->WriteShortBE( htons( Network.m_pHost.sin_port ) );
	pPacket->WriteShortBE( WORD( GetCount( PROTOCOL_G2, nrsConnected, ntLeaf ) ) );

	// Loop through the connected computers
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		// Get the neighbour object at this position, and move pos to the next one
		CG2Neighbour* pNeighbour = (CG2Neighbour*)GetNext( pos );

		// If this neighbour is running Gnutella2 software
		if ( pNeighbour->m_nProtocol == PROTOCOL_G2 && // The remote computer is running Gnutella2 software, and
			 pNeighbour->m_nNodeType != ntLeaf      && // Our connection to it is not down to a leaf, and
			 pNeighbour->m_nState >= nrsConnected   && // We've finished the handshake with it, and
			 pNeighbour != pExcept )                   // This isn't the computer the caller warned us to except
		{
			// Write information about this connected computer into the packet
			pPacket->WritePacket( G2_PACKET_QUERY_DONE, 8 );
			pPacket->WriteLongLE( pNeighbour->m_pHost.sin_addr.S_un.S_addr );
			pPacket->WriteShortBE( htons( pNeighbour->m_pHost.sin_port ) );
			pPacket->WriteShortBE( (WORD)pNeighbour->m_nLeafCount );

			// Record that you wrote information about this computer into the packet
			theApp.Message( MSG_DEBUG, _T("  Done neighbour %s"), (LPCTSTR)pNeighbour->m_sAddress );
		}
	}

	// If the caller didn't give us a computer to ignore, make nCount 3, if it did give us an except, make nCount 25
	int nCount = ( pExcept == NULL ) ? 3 : 25; // Will put up to 3 or 25 IP addresses in the packet

	// Loop, starting with the newest entry in the Gnutella2 host cache, then stepping to the one before that
	for ( CHostCacheHost* pHost = HostCache.Gnutella2.GetNewest() ; pHost ; pHost = pHost->m_pPrevTime )
	{
		// If this host cache entry is good
		if ( pHost->CanQuote( tNow )                             && // If this host cache entry hasn't expired, and
			 Get( &pHost->m_pAddress ) == NULL                   && // We're connected to that IP address right now, and
			 HubHorizonPool.Find( &pHost->m_pAddress ) == NULL )    // The IP address is also in the hub horizon pool
		{
			// Add the IP address to the packet we're making
			pPacket->WritePacket( G2_PACKET_QUERY_SEARCH, 10 );
			pPacket->WriteLongLE( pHost->m_pAddress.S_un.S_addr );
			pPacket->WriteShortBE( pHost->m_nPort );
			pPacket->WriteLongBE( pHost->m_tSeen );

			// Report that the packet will encourage the recipient to try this IP address
			theApp.Message( MSG_DEBUG, _T("  Try cached hub %s"), (LPCTSTR)CString( inet_ntoa( pHost->m_pAddress ) ) );

			// Lower the count, if it is then 0, leave the loop
			if ( ! --nCount ) break;
		}
	}

	// Give the packet we're making to our own hub horizon pool
	HubHorizonPool.AddHorizonHubs( pPacket );

	// Finish the packet with a 0 byte and the guid the caller gave us, and return it
	pPacket->WriteByte( 0 );
	pPacket->Write( oGUID );
	return pPacket;
}

//////////////////////////////////////////////////////////////////////
// CNeighboursWithG2 random hub selector

// Takes a connected computer to ignore, and a GUID (do)
// Randomly chooses a neighbour from amongst those that are connected, running Gnutella2, hubs, and don't know about the GUID
// Returns a pointer to that randomly selected neighbour
CG2Neighbour* CNeighboursWithG2::GetRandomHub(CG2Neighbour* pExcept, const Hashes::Guid& oGUID)
{
	// Make a new local empty list that will hold pointers to neighbours
	std::list<CG2Neighbour*> oRandom;

	std::list<CG2Neighbour*>::iterator iIndex = m_oHub.begin();
	std::list<CG2Neighbour*>::iterator iEnd = m_oHub.end();

	// Loop through each computer we're connected to
	for (  ; iIndex != iEnd ; iIndex++ )
	{
		// If this is a Gnutella2 hub
		if ( (*iIndex) != pExcept )                   // It's not the one the caller told us to avoid
		{
			// And, it doesn't know about the given GUID
			if ( (*iIndex)->m_pGUIDCache->Lookup( oGUID ) == NULL )
			{
				// Add it to the random list
				oRandom.push_back( *iIndex );
			}
		}
	}

	// If we didn't find any neighbours to put in the list, return null
	size_t nSize = oRandom.size();
	if ( ! nSize ) return NULL;

	// Choose a random number between 0 and nSize - 1, use it as an index, and return the neighbour at it
	nSize = rand() % nSize; // The C runtime function rand() returns a random number up to RAND_MAX, 32767

	iIndex = oRandom.begin();
	iEnd = oRandom.end();
	DWORD nCount = 0;
	for (  ; iIndex != iEnd ; iIndex++, nCount++ )
	{
		// If this is a Gnutella2 hub
		if ( nCount == nSize ) return *iIndex;
	}
    
	return NULL;
}

//////////////////////////////////////////////////////////////////////
// CNeighboursWithG2 Create LNI packet

CG2Packet* CNeighboursWithG2::CreateLNIPacket(CG2Neighbour* pOwner)
{
	CG2Packet* pPacket = CG2Packet::New( G2_PACKET_LNI, TRUE );

	QWORD nMyVolume = 0;
	DWORD nMyFiles = 0;
	LibraryMaps.GetStatistics( &nMyFiles, &nMyVolume );

	//WORD nLeafs = (WORD)Neighbours.m_nCount[PROTOCOL_G2][ntLeaf];
	WORD nLeafs = (WORD)m_oLeaf.size();

	/*
	for ( POSITION pos = Neighbours.GetIterator() ; pos ; )
	{
		CNeighbour* pNeighbour = Neighbours.GetNext( pos );

		if (	pNeighbour != pOwner &&
		pNeighbour->m_nState == nrsConnected &&
		pNeighbour->m_nNodeType == ntLeaf )
		{
			nMyFiles += pNeighbour->m_nFileCount;
			nMyVolume += pNeighbour->m_nFileVolume;
			nLeafs++;
		}
	}
	*/

	pPacket->WritePacket( G2_PACKET_NODE_ADDRESS, 6 );
	pPacket->WriteLongLE( Network.m_pHost.sin_addr.S_un.S_addr );
	pPacket->WriteShortBE( htons( Network.m_pHost.sin_port ) );

	pPacket->WritePacket( G2_PACKET_NODE_GUID, 16 );
	pPacket->Write( Hashes::Guid( MyProfile.oGUID ) );

	pPacket->WritePacket( G2_PACKET_VENDOR, 4 );
	pPacket->WriteString( SHAREAZA_VENDOR_A, FALSE );

	pPacket->WritePacket( G2_PACKET_LIBRARY_STATUS, 8 );
	pPacket->WriteLongBE( (DWORD)nMyFiles );
	pPacket->WriteLongBE( (DWORD)nMyVolume );

	if ( ! IsG2Leaf() )
	{
		pPacket->WritePacket( G2_PACKET_HUB_STATUS, 4 );				// Hub Statistic - only for Hub node
		pPacket->WriteShortBE( nLeafs );								// Number of Leaf connections currently have
		pPacket->WriteShortBE( WORD( Settings.Gnutella2.NumLeafs ) );	// Max number of Leaf connections this hub can accept

		pPacket->WritePacket( G2_PACKET_QUERY_KEY, 0 );
	}

	if ( Network.IsFirewalled() || !Datagrams.IsStable() ) //add
	{
		if ( !Network.IsTestingUDPFW() )
		{
			pPacket->WritePacket( G2_PACKET_PEER_FIREWALLED, 0 );
			if ( Network.IsFirewalled() )
				pPacket->WritePacket( G2_PACKET_TCP_FIREWALLED, 0 );
			else
				pPacket->WritePacket( G2_PACKET_TCP_NOT_FIREWALLED, 0 );

			if ( !Datagrams.IsStable() )
				pPacket->WritePacket( G2_PACKET_UDP_FIREWALLED, 0 );
			else
				pPacket->WritePacket( G2_PACKET_UDP_NOT_FIREWALLED, 0 );
		}
	}
	else if ( IsG2Hub() && IsG2HubCapable() ) //add
	{
		pPacket->WritePacket( G2_PACKET_HUB_ABLE, 0 );			// Hubable - Not used on shareaza yet but used on Gnucleaus
		//	This might be useful sometime.

		pPacket->WritePacket( G2_PACKET_TCP_NOT_FIREWALLED, 2 );// TCP Not Firewalled
		pPacket->WriteShortLE( Network.m_pHost.sin_port );		// telling TCP port
		pPacket->WritePacket( G2_PACKET_UDP_FIREWALLED, 2 );	// UDP Not Firewalled
		pPacket->WriteShortLE( Network.m_pHost.sin_port );		// telling UDP port
	}
	else
	{
		pPacket->WritePacket( G2_PACKET_PEER_NOTFIREWALLED, 0 );
		pPacket->WritePacket( G2_PACKET_TCP_NOT_FIREWALLED, 2 );// TCP Not Firewalled
		pPacket->WriteShortLE( Network.m_pHost.sin_port );		// telling TCP port
		pPacket->WritePacket( G2_PACKET_UDP_FIREWALLED, 2 );	// UDP Not Firewalled
		pPacket->WriteShortLE( Network.m_pHost.sin_port );		// telling UDP port
	}

	/*	Note: about FW, NFW, TCPFW, TCPNFW, UDPFW, UDPNFW
		These tags are not used in Shareaza yet. for some of them like "FW" has been used in Gnucleus.
		the reason why TCPNFW and UDPNFW has port as payload, this is not really planed yet, but might
		make some specification to use separate port number for TCP/UDP bindings. since there are some
		models of routers can not use same port number forwarded to same PC. if thats the case, G2 does
		not work good in that network and thus need to create this kind of very unusual info transfered
		through LNI packet.
	*/

	pPacket->WritePacket( G2_PACKET_NETWORK_BANDWIDTH, 8 ); //add
	pPacket->WriteLongBE( Settings.Bandwidth.Downloads );	// These two are not used on Shareaza. only on Gnucleus right now.
	pPacket->WriteLongBE( Settings.Bandwidth.Uploads );		//

	pPacket->WritePacket( G2_PACKET_UPTIME, 4 );			//add
	pPacket->WriteLongBE( Network.GetStableTime() );		// not used - only on Gnucleus

	DWORD nGPS = MyProfile.GetPackedGPS();

	if ( nGPS )
	{
		pPacket->WritePacket( G2_PACKET_GPS, 4 );			//add
		pPacket->WriteLongBE( nGPS );						// not used - only on Gnucleus
	}
	return pPacket;
}

//////////////////////////////////////////////////////////////////////
// CNeighboursWithG2 Create KHL packet

CG2Packet* CNeighboursWithG2::CreateKHLPacket(CG2Neighbour* pOwner)
{
	CG2Packet* pPacket = CG2Packet::New( G2_PACKET_KHL, TRUE );

	/*
	for ( POSITION pos = Neighbours.GetIterator() ; pos ; )
	{
		CG2Neighbour* pNeighbour = (CG2Neighbour*)Neighbours.GetNext( pos );

		if (	pNeighbour != pOwner &&
			pNeighbour->m_nProtocol == PROTOCOL_G2 &&
			pNeighbour->m_nState == nrsConnected &&
			pNeighbour->m_nNodeType != ntLeaf &&
			pNeighbour->m_pHost.sin_addr.S_un.S_addr != Network.m_pHost.sin_addr.S_un.S_addr )
		{
			if ( pNeighbour->m_pVendor && pNeighbour->m_pVendor->m_sCode.GetLength() == 4 )
			{
				pPacket->WritePacket( G2_PACKET_NEIGHBOUR_HUB, 14 + 6, TRUE );	// 4
				pPacket->WritePacket( G2_PACKET_HUB_STATUS, 2 );				// 4
				pPacket->WriteShortBE( (WORD)pNeighbour->m_nLeafCount );		// 2
				pPacket->WritePacket( G2_PACKET_VENDOR, 4 );					// 3
				pPacket->WriteString( pNeighbour->m_pVendor->m_sCode );			// 5
			}
			else
			{
				pPacket->WritePacket( G2_PACKET_NEIGHBOUR_HUB, 7 + 6, TRUE );	// 4
				pPacket->WritePacket( G2_PACKET_HUB_STATUS, 2 );				// 4
				pPacket->WriteShortBE( (WORD)pNeighbour->m_nLeafCount );		// 2
				pPacket->WriteByte( 0 );										// 1
			}

			pPacket->WriteLongLE( pNeighbour->m_pHost.sin_addr.S_un.S_addr );	// 4
			pPacket->WriteShortBE( htons( pNeighbour->m_pHost.sin_port ) );		// 2
		}
	}
	*/

	if ( m_oHub.size() != 0 && !pOwner->m_bObsoleteClient )
	{
		std::list<CG2Neighbour*>::iterator iIndex = m_oHub.begin();
		std::list<CG2Neighbour*>::iterator iEnd = m_oHub.end();
		for ( ; iIndex != iEnd ; iIndex++ )
		{
			CG2Neighbour* pNeighbour = *iIndex;

			if (pNeighbour != pOwner &&
				pNeighbour->m_pHost.sin_addr.S_un.S_addr != Network.m_pHost.sin_addr.S_un.S_addr )
			{
				if ( pNeighbour->m_pVendor && pNeighbour->m_pVendor->m_sCode.GetLength() == 4 )
				{
					pPacket->WritePacket( G2_PACKET_NEIGHBOUR_HUB, 16 + 6, TRUE );	// 4
					pPacket->WritePacket( G2_PACKET_HUB_STATUS, 4 );				// 4
					pPacket->WriteShortBE( (WORD)pNeighbour->m_nLeafCount );		// 2
					pPacket->WriteShortBE( (WORD)pNeighbour->m_nLeafLimit );		// 2
					pPacket->WritePacket( G2_PACKET_VENDOR, 4 );					// 3
					pPacket->WriteString( pNeighbour->m_pVendor->m_sCode );			// 5
				}
				else
				{
					pPacket->WritePacket( G2_PACKET_NEIGHBOUR_HUB, 9 + 6, TRUE );	// 4
					pPacket->WritePacket( G2_PACKET_HUB_STATUS, 4 );				// 4
					pPacket->WriteShortBE( (WORD)pNeighbour->m_nLeafCount );		// 2
					pPacket->WriteShortBE( (WORD)pNeighbour->m_nLeafLimit );		// 2
					pPacket->WriteByte( 0 );										// 1
				}

				pPacket->WriteLongLE( pNeighbour->m_pHost.sin_addr.S_un.S_addr );	// 4
				pPacket->WriteShortBE( htons( pNeighbour->m_pHost.sin_port ) );		// 2
			}
		}
	}

	int nCount;

	if ( !pOwner->m_bObsoleteClient )
		nCount = Settings.Gnutella2.KHLHubCount;
	else 
		nCount = 0;

	DWORD tNow = static_cast< DWORD >( time( NULL ) );

	pPacket->WritePacket( G2_PACKET_TIMESTAMP, 4 );
	pPacket->WriteLongBE( tNow );

	for ( CHostCacheHost* pHost = HostCache.Gnutella2.GetNewest() ; pHost && nCount > 0 ; pHost = pHost->m_pPrevTime )
	{
		if (	pHost->CanQuote( tNow ) &&
			Get( &pHost->m_pAddress ) == NULL &&
			pHost->m_pAddress.S_un.S_addr != Network.m_pHost.sin_addr.S_un.S_addr )
		{
			int nLength = 10;

			if ( pHost->m_pVendor && pHost->m_pVendor->m_sCode.GetLength() == 4 )
				nLength += 7;
			if ( pOwner && pOwner->m_nNodeType == ntLeaf && pHost->m_nKeyValue != 0 && pHost->m_nKeyHost == Network.m_pHost.sin_addr.S_un.S_addr )
				nLength += 8;
			if ( nLength > 10 )
				nLength ++;

			pPacket->WritePacket( G2_PACKET_CACHED_HUB, nLength, nLength > 10 );

			if ( pHost->m_pVendor && pHost->m_pVendor->m_sCode.GetLength() == 4 )
			{
				pPacket->WritePacket( G2_PACKET_VENDOR, 4 );				// 3
				pPacket->WriteString( pHost->m_pVendor->m_sCode, FALSE );	// 4
			}

			if ( pOwner && pOwner->m_nNodeType == ntLeaf && pHost->m_nKeyValue != 0 && pHost->m_nKeyHost == Network.m_pHost.sin_addr.S_un.S_addr )
			{
				pPacket->WritePacket( G2_PACKET_QUERY_KEY, 4 );				// 4
				pPacket->WriteLongBE( pHost->m_nKeyValue );					// 4
			}

			if ( nLength > 10 ) pPacket->WriteByte( 0 );					// 1

			pPacket->WriteLongLE( pHost->m_pAddress.S_un.S_addr );			// 4
			pPacket->WriteShortBE( pHost->m_nPort );						// 2
			pPacket->WriteLongBE( pHost->m_tSeen );							// 4

			nCount--;
		}
	}

	return pPacket;
}

//////////////////////////////////////////////////////////////////////
// CNeighboursWithG2 Parse KHL packet

BOOL CNeighboursWithG2::ParseKHLPacket(CG2Packet* pPacket, CG2Neighbour* pOwner)
{
	if ( ! pPacket->m_bCompound ) return TRUE;
	Hashes::Guid oTO;
	if ( pPacket->GetTo( oTO ) )
	{
		theApp.Message(MSG_SYSTEM, _T("Detected KHL packet with faked Destination. Ignoring the packet") );
		return TRUE;
	}

	G2_PACKET nType, nInnerType;
	DWORD nLength, nInner, nHubCount = 0;
	BOOL bCompound;
	DWORD tAdjust = ( pOwner ) ? pOwner->m_tAdjust : 0;
	DWORD tNow = Network.m_nNetworkGlobalTime;

	if ( pOwner ) pOwner->m_pHubGroup->Clear();

	while ( pPacket->ReadPacket( nType, nLength, &bCompound ) )
	{
		DWORD nNext = pPacket->m_nPosition + nLength;

		if (	nType == G2_PACKET_NEIGHBOUR_HUB ||
			(	!pOwner->m_bObsoleteClient && nType == G2_PACKET_CACHED_HUB ) )
		{
			DWORD nAddress = 0, nKey = 0, tSeen = tNow, nLeafCurrent = 0, nLeafLimit = 0;
			WORD nPort = 0;
			CString strVendor;
			BOOL bHSCurrent = FALSE, bHSMax = FALSE;

			if ( bCompound || nType == G2_PACKET_NEIGHBOUR_HUB )
			{
				while ( pPacket->m_nPosition < nNext && pPacket->ReadPacket( nInnerType, nInner ) )
				{
					DWORD nNextX = pPacket->m_nPosition + nInner;

					if ( nInnerType == G2_PACKET_NODE_ADDRESS && nInner >= 6 )
					{
						nAddress = pPacket->ReadLongLE();
						nPort = pPacket->ReadShortBE();
					}
					else if ( nInnerType == G2_PACKET_VENDOR && nInner >= 4 )
					{
						strVendor = pPacket->ReadString( 4 );
					}
					else if ( nInnerType == G2_PACKET_QUERY_KEY && nInner >= 4 )
					{
						nKey = pPacket->ReadLongBE();
						if ( pOwner ) pOwner->m_bCachedKeys = TRUE;
					}
					else if ( nInnerType == G2_PACKET_TIMESTAMP && nInner >= 4 )
					{
						tSeen = pPacket->ReadLongBE() + tAdjust;
					}
					else if ( nInnerType == G2_PACKET_HUB_STATUS && nInner >= 2 )
					{
						nLeafCurrent = pPacket->ReadShortBE();
						bHSCurrent = TRUE;
						if ( nInner >= 4 ) 
						{
							nLeafLimit = pPacket->ReadShortBE();
							bHSMax = TRUE;
						}
					}

					pPacket->m_nPosition = nNextX;
				}

				nLength = nNext - pPacket->m_nPosition;
			}

			if ( nLength >= 6 )
			{
				nAddress = pPacket->ReadLongLE();
				nPort = pPacket->ReadShortBE();
				if ( nLength >= 10 ) tSeen = pPacket->ReadLongBE() + tAdjust;
			}

			CHostCacheHost* pCached = NULL;
			BOOL bNewer = TRUE;
			if ( nType == G2_PACKET_NEIGHBOUR_HUB )
			{
				pCached = HostCache.Gnutella2.Add( (IN_ADDR*)&nAddress, nPort, tSeen, strVendor );
			}
			else if ( nType == G2_PACKET_CACHED_HUB )
			{
				pCached = HostCache.Gnutella2.Find( (IN_ADDR*)&nAddress );
				if ( !pCached )	HostCache.Gnutella2.Add( (IN_ADDR*)&nAddress, nPort, tSeen, strVendor );
				else if ( pCached->m_tSeen > tSeen ) bNewer = FALSE;
			}

			if ( pCached )
			{
				if ( bNewer )
				{
					if ( bHSCurrent ) pCached->m_nUserCount = nLeafCurrent;
					if ( bHSMax ) pCached->m_nUserLimit = nLeafLimit;
				}
				if ( pOwner && ( pOwner->m_nNodeType == ntHub || pOwner->m_nNodeType == ntNode ) )
				{
					if ( pCached->m_nKeyValue == 0 ||
						pCached->m_nKeyHost != Network.m_pHost.sin_addr.S_un.S_addr )
					{
						if ( pCached->m_nKeyValue == 0 ||
							pCached->m_nKeyHost != Network.m_pHost.sin_addr.S_un.S_addr )
						{
							pCached->SetKey( nKey, &(pOwner->m_pHost.sin_addr) );
						}
					}
				}
			}

			if ( nType == G2_PACKET_NEIGHBOUR_HUB )
			{
				// Neighbour LEAF's Neighbour HUB is not part of CLUSTER, is it???
				if ( pOwner && ( pOwner->m_nNodeType == ntHub || pOwner->m_nNodeType == ntNode ) )
					pOwner->m_pHubGroup->Add( (IN_ADDR*)&nAddress, nPort );
				nHubCount++;
			}

		}
		else if ( nType == G2_PACKET_TIMESTAMP && nLength >= 4 )
		{
			tAdjust = (LONG)tNow - (LONG)pPacket->ReadLongBE();
		}

		pPacket->m_nPosition = nNext;
	}

	if ( pOwner ) pOwner->m_tAdjust = tAdjust;

	if ( pOwner && pOwner->m_nNodeType == ntLeaf && nHubCount >= Settings.Gnutella2.MaxHubsOnRemoteLeaf && Settings.Gnutella2.BadLeafHandler > 0 )
	{
		CString strTemp( inet_ntoa( pOwner->m_pHost.sin_addr ) );
		theApp.Message(MSG_SYSTEM, _T( "Detected Leaf node (%s:%u) is connected to ambiguous number of Hubs: Connected to %u Hubs"),
			strTemp, ntohs(pOwner->m_pHost.sin_port), nHubCount + 1 );
		if ( Settings.Gnutella2.BadLeafHandler > 1 )
		{
			if ( Settings.Gnutella2.BadLeafHandler == 3 ) Security.Ban( &pOwner->m_pHost.sin_addr, ban2Hours );
			return FALSE;
		}
	}

	return TRUE;
}

