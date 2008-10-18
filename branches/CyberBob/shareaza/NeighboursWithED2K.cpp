//
// NeighboursWithED2K.cpp
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

// Add methods helpful for eDonkey2000 that look at the list of neighbours
// http://wiki.shareaza.com/static/Developers.Code.CNeighboursWithED2K

// Copy in the contents of these files here before compiling
#include "StdAfx.h"
#include "Shareaza.h"
#include "NeighboursWithED2K.h"
#include "EDNeighbour.h"
#include "EDPacket.h"
#include "Datagrams.h"
#include "Network.h"
#include "ED2K.h"

// If we are compiling in debug mode, replace the text "THIS_FILE" in the code with the name of this file
#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////
// CNeighboursWithED2K construction

// CNeighboursWithED2K adds two arrays that need to be filled with 0s when the program creates its CNeighbours object
CNeighboursWithED2K::CNeighboursWithED2K()
// Zero the memory of the sources array
: m_tEDSources()
, m_oEDServers()
{
}

// CNeighboursWithED2K doesn't add anything to the CNeighbours inheritance column that needs to be cleaned up
CNeighboursWithED2K::~CNeighboursWithED2K()
{
}

//////////////////////////////////////////////////////////////////////
// CNeighboursWithED2K server lookup

// Looks in the neighbours list for an eDonkey2000 computer that we've finished the handshake with and that has a client ID
// Returns a pointer to the first one found, or null if none found in the list
CEDNeighbour* CNeighboursWithED2K::GetDonkeyServer() const // Here, const means this method doesn't change the value of any member variables
{
	std::list<CEDNeighbour*>::const_iterator iIndex = m_oEDServers.begin();
	std::list<CEDNeighbour*>::const_iterator iEnd = m_oEDServers.end();

	// Loop through each neighbour in the m_oEDServers
	for ( ; iIndex != iEnd ; iIndex++ )
	{
		// Get the neighbour object at the current position, and move pos to the next position
		CEDNeighbour* pNeighbour = *iIndex;

		// This neighbour really is running eDonkey2000
		if ( pNeighbour->m_nProtocol == PROTOCOL_ED2K )
		{
			// And, we've finished the handshake with it, and it has a client ID
			if ( pNeighbour->m_nState == nrsConnected &&
				 pNeighbour->m_nClientID != 0 )
			{
				// Return a pointer to it
				return pNeighbour;
			}
		}
	}

	// We couldn't find a connected eDonkey2000 computer that we've finished the handshake with and that has a client ID
	return NULL;
}

//////////////////////////////////////////////////////////////////////
// CNeighboursWithED2K server lookup

// Calls Close() on all the eDonkey2000 computers in the list of neighbours we're connected to
void CNeighboursWithED2K::CloseDonkeys()
{
	// Loop through each neighbour in the m_oEDServers
	for ( ; m_oEDServers.size() ; )
	{
		// Get the neighbour object at the current position, and move pos to the next position
		CEDNeighbour* pNeighbour = *m_oEDServers.begin();

		// If this neighbour really is running eDonkey2000, close our connection to it
		if ( pNeighbour->m_nProtocol == PROTOCOL_ED2K ) pNeighbour->Close();
	}
}

//////////////////////////////////////////////////////////////////////
// CNeighboursWithED2K advertise a new download

// Takes a pointer to a CDownload object (do)
// Tells all the eDonkey2000 computers we're connected to about it
void CNeighboursWithED2K::SendDonkeyDownload(CDownload* pDownload)
{
	std::list<CEDNeighbour*>::const_iterator iIndex = m_oEDServers.begin();
	std::list<CEDNeighbour*>::const_iterator iEnd = m_oEDServers.end();

	// Loop through each neighbour in the m_oEDServers
	for ( ; iIndex != iEnd ; iIndex++ )
	{
		// Get the neighbour object at the current position, and move pos to the next position
		CEDNeighbour* pNeighbour = *iIndex;

		// If this neighbour is running eDonkey2000 software
		if ( pNeighbour->m_nProtocol == PROTOCOL_ED2K )
		{
			// Tell it about this download
			pNeighbour->SendSharedDownload( pDownload );
		}
	}
}

//////////////////////////////////////////////////////////////////////
// CNeighboursWithED2K server push

// Takes a client ID (do), the IP address of an eDonkey2000 computer we're connected to, nServerPort unused (do)
// Finds the computer we're connected to with that IP address, and sends it a call back request with the client ID
// Returns true if we sent the packet, false if we couldn't find the computer
BOOL CNeighboursWithED2K::PushDonkey(DWORD nClientID, IN_ADDR* pServerAddress, WORD nServerPort) // Was named nServerPort (do)
{
	/*
	BOOL bReqSucceed = FALSE;

	// If we don't have a socket listening for incoming connections, leave now
	if ( ! Network.IsListening() ) return FALSE;

	// Get the neighbour with the given IP address, and look at it as an eDonkey2000 computer
	CEDNeighbour* pNeighbour = (CEDNeighbour*)Get( pServerAddress );

	// If we found it, and it really is running eDonkey2000
	if ( ( pNeighbour != NULL ) && ( pNeighbour->m_nProtocol == PROTOCOL_ED2K ) && ( ! CEDPacket::IsLowID( pNeighbour->m_nClientID ) ) )
	{
		// Make a new eDonkey2000 call back request packet, write in the client ID, and send it to the eDonkey2000 computer
		CEDPacket* pPacket = CEDPacket::New( ED2K_C2S_CALLBACKREQUEST );
		pPacket->WriteLongLE( nClientID );
		bReqSucceed = pNeighbour->Send( pPacket );
	}

	if ( !bReqSucceed )
	{
		// lugdunum requests no more of this
		CEDPacket* pPacket = CEDPacket::New( ED2K_C2SG_CALLBACKREQUEST );
		pPacket->WriteLongLE( Network.m_pHost.sin_addr.S_un.S_addr );
		pPacket->WriteShortLE( htons( Network.m_pHost.sin_port ) );
		pPacket->WriteLongLE( nClientID );
		bReqSucceed = Datagrams.Send( pServerAddress, nServerPort + 4, pPacket ) ;
	}

	return bReqSucceed;
	*/
	Network.m_pMessageQueue.PushMessage( (CITMQueue::CITMItem*)CNetwork::CITMSendPush::CreateMessage( PROTOCOL_ED2K, Hashes::Guid(),
										nClientID, *pServerAddress, nServerPort ) );
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CNeighboursWithED2K quick source lookup

// Takes the MD4 hash, IP address, and port number from a query hit (do), nServerPort unused (do)
// Updates the hash in the hash and time arrays, and sends an eDonkey2000 get sources packet to the given IP address
// Returns true if we sent a packet, false if we didn't because of the arrays (do)
BOOL CNeighboursWithED2K::FindDonkeySources(const Hashes::Ed2kHash& oED2K, IN_ADDR* pServerAddress, WORD nServerPort)
{
	// If we don't have a socket listening for incoming connections, leave now
	if ( ! Network.IsListening() ) return FALSE;

	// Start out nHash as the lowest byte 0xff of the IP address
	int nHash = (int)pServerAddress->S_un.S_un_b.s_b4 & 255;

	// Number of milliseconds since the user turned the computer on
	DWORD tNow = GetTickCount();

	// Make sure nHash is between 0 and 255
	if ( nHash < 0 ) nHash = 0;
	else if ( nHash > 255 ) nHash = 255;

	// Lookup the MD4 hash at nHash in the m_pEDSources array of them, if it's equal to the given hash
	if ( validAndEqual( m_oEDSources[ nHash ], oED2K ) )
	{
		// If the hash in the array is less than an hour old, don't do anything and return false
		if ( tNow - m_tEDSources[ nHash ] < 3600000 ) return FALSE; // 3600000 milliseconds is 1 hour

	} // The m_pEDSources array doesn't have pED2K at position nHash
	else
	{
		// If that spot in the array was added in the last 15 seconds, don't do anything and return false
		if ( tNow - m_tEDSources[ nHash ] < 15000 ) return FALSE; // 15000 milliseconds is 15 seconds

		// That spot in the array is more than 15 seconds old, put the hash there
		m_oEDSources[ nHash ] = oED2K;
	}

	// Record that we visited this spot in the array now
	m_tEDSources[ nHash ] = tNow;

	// Make a eDonkey2000 get sources packet, write in the MD4 hash, and send it to the given address
	CEDPacket* pPacket = CEDPacket::New( ED2K_C2SG_GETSOURCES );
	pPacket->Write( oED2K );
	Datagrams.Send( pServerAddress, nServerPort + 4, pPacket );

	// Report that we sent a packet
	return TRUE;
}

// Takes an IP address
// Finds the G1neighbour object in the m_pUniques map that represents the remote computer with that address
// Returns it, or null if not found
CEDNeighbour* CNeighboursWithED2K::GetEDNode(IN_ADDR* pAddress) const // Saying const here means this method won't change any member variables
{
	std::list<CEDNeighbour*>::const_iterator iIndex = m_oEDServers.begin();
	std::list<CEDNeighbour*>::const_iterator iEnd = m_oEDServers.end();

	// Loop through each neighbour in the m_oEDServers
	for ( ; iIndex != iEnd ; iIndex++ )
	{
		// Get the neighbour object at the current position, and move pos to the next position
		CEDNeighbour* pNeighbour = *iIndex;

		// If this neighbour object has the IP address we are looking for, return it
		if ( pNeighbour->m_pRealHost.sin_addr.S_un.S_addr == pAddress->S_un.S_addr ) return pNeighbour;
	}

	// None of the neighbour objects in the map had the IP address we are looking for
	return NULL; // Not found
}

// Takes an SOCKADDR
// Finds the EDNeighbour object in the m_pUniques map that represents the remote computer with that address
// Returns it, or null if not found
CEDNeighbour* CNeighboursWithED2K::GetEDNode(SOCKADDR_IN* pAddress) const // Saying const here means this method won't change any member variables
{
	std::list<CEDNeighbour*>::const_iterator iIndex = m_oEDServers.begin();
	std::list<CEDNeighbour*>::const_iterator iEnd = m_oEDServers.end();

	// Loop through each neighbour in the m_oEDServers
	for ( ; iIndex != iEnd ; iIndex++ )
	{
		// Get the neighbour object at the current position, and move pos to the next position
		CEDNeighbour* pNeighbour = *iIndex;

		// If this neighbour object has the SOCKADDR we are looking for, return it
		if ( pNeighbour->m_pRealHost.sin_addr.S_un.S_addr == pAddress->sin_addr.S_un.S_addr &&
			pNeighbour->m_pRealHost.sin_port == pAddress->sin_port &&
			pNeighbour->m_pRealHost.sin_family == pAddress->sin_family ) return pNeighbour;
	}

	// None of the neighbour objects in the map had the IP address we are looking for
	return NULL; // Not found
}