//
// NeighboursWithG2.h
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

// Make the compiler only include the lines here once, this is the same thing as pragma once
#if !defined(AFX_NEIGHBOURSWITHG2_H__6C703D82_AD8C_48F1_9C6A_B54F5C05231E__INCLUDED_)
#define AFX_NEIGHBOURSWITHG2_H__6C703D82_AD8C_48F1_9C6A_B54F5C05231E__INCLUDED_

// Only include the lines beneath this one once
#pragma once

// Copy in the contents of these files here before compiling
#include "NeighboursWithG1.h"

// Tell the compiler these classes exist, and it will find out more about them soon
class CG2Neighbour;
class CG2Packet;

// Add methods helpful for Gnutella that need to look at the list of computers we're connected to
class CNeighboursWithG2 : public CNeighboursWithG1 // Continue the inheritance column CNeighbours : CNeighboursWithConnect : Routing : ED2K : G2 : G1 : CNeighboursBase
{

public:

	// Nothing that CNeighboursWithG2 adds to CNeighbours needs to be set up or put away
	CNeighboursWithG2(); // The constructor and destructor don't do anything
	virtual ~CNeighboursWithG2();

public:

	DWORD						m_nG2FileCount;		// Total File Count on Leafs
	DWORD						m_nG2FileVolume;	// Total File Volume of Leafs
	std::list<CG2Neighbour*>	m_oG2Peers;			// list of Hub-to-Hub(PEER) connections
	std::list<CG2Neighbour*>	m_oG2Hubs;			// list of Leaf-to-Hub(HUB) connections
	std::list<CG2Neighbour*>	m_oG2Leafs;			// list of Hub-to-Leaf(LEAF) connections
	std::list<CG2Neighbour*>	m_oG2Specials;		// list of any-to-any(Special) connections

public:

	// Methods implimented by several classes in the CNeighbours inheritance column
	virtual void	Connect();								// Set the ping route duration and setup the hub horizon pool
	virtual void	Close();
	virtual void	ConnectG2();
	virtual void	DisconnectG2();
	// Pure virtual memombers.
	virtual BOOL	IsG2Leaf() = 0;							// Returns true if we are acting as a Gnutella2 leaf on at least one connection
	virtual BOOL	IsG2Hub() = 0;							// Returns true if we are acting as a Gnutella2 hub on at least one connection
	virtual DWORD	IsG2HubCapable(BOOL bIgnoreCurrentMode, BOOL bDebug) = 0;// Returns true if we have a computer and Internet connection powerful enough to become a Gnutella2 hub

public:

	// Make and return a query web packet with IP addresses from the neighbours list and the Gnutella2 host cache
	CG2Packet*		CreateQueryWeb(const Hashes::Guid& oGUID, CNeighbour* pExcept = NULL);

	// Return a random Gnutella2 hub neighbour that isn't pExcept and doesn't know about pGUID
	CG2Neighbour*	GetRandomHub(CG2Neighbour* pExcept, const Hashes::Guid& oGUID);

	CG2Packet*		CreateLNIPacket(CG2Neighbour* pOwner = NULL);
	CG2Packet*		CreateKHLPacket(CG2Neighbour* pOwner = NULL);
	BOOL			ParseKHLPacket(CG2Packet* pPacket, CG2Neighbour* pOwner = NULL);
	CG2Neighbour*	GetG2Node(IN_ADDR* pAddress) const;		// By the remote computer's IP address
	CG2Neighbour*	GetG2Node(SOCKADDR_IN* pAddress) const;	// By the remote computer's SOCKET address
};

// End the group of lines to only include once, pragma once doesn't require an endif at the bottom
#endif // !defined(AFX_NEIGHBOURSWITHG2_H__6C703D82_AD8C_48F1_9C6A_B54F5C05231E__INCLUDED_)