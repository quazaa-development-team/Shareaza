//
// NeighboursWithConnect.h
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

// Determine our hub or leaf role, count connections for each, and make new ones or close them to have the right number
// http://wiki.shareaza.com/static/Developers.Code.CNeighboursWithConnect

// Make the compiler only include the lines here once, this is the same thing as pragma once
#if !defined(AFX_NEIGHBOURSWITHCONNECT_H__7BAE2435_FF99_4E23_8EBE_B7C3E5FFCCB0__INCLUDED_)
#define AFX_NEIGHBOURSWITHCONNECT_H__7BAE2435_FF99_4E23_8EBE_B7C3E5FFCCB0__INCLUDED_

// Only include the lines beneath this one once
#pragma once

// Copy in the contents of these files here before compiling
#include "NeighboursWithRouting.h"

// Tell the compiler these classes exist, and it will find out more about them soon
class CConnection;

// Determine our hub or leaf role, count connections for each, and make new ones or close them to have the right number
class CNeighboursWithConnect : public CNeighboursWithRouting // Continue the inheritance column CNeighbours : CNeighboursWithConnect : Routing : ED2K : G2 : G1 : CNeighboursBase
{

public:	// Typedefs
	typedef std::list<SOCKADDR_IN>				HostAddrList;
	typedef std::list<SOCKADDR_IN>::iterator	HostAddrPtr;

public:

	// Set up and clean up anything CNeighboursWithConnect adds to the CNeighbours class
	CNeighboursWithConnect(); // Zero the tick counts in the m_tPresent array
	virtual ~CNeighboursWithConnect();

public:

	// Connect to a computer at an IP address, and accept a connection from a computer that has connected to us
	CNeighbour* ConnectTo(IN_ADDR* pAddress, WORD nPort, PROTOCOLID nProtocol, BOOL bAutomatic = FALSE, BOOL bNoUltraPeer = FALSE, BOOL bFirewallTest = FALSE );
	CNeighbour* OnAccept(CConnection* pConnection);

protected:
	virtual void Connect();
	virtual void Close();
public:

	// Determine our role on the Gnutella2 network
	virtual BOOL  IsG2Leaf();                          // Returns true if we are acting as a Gnutella2 leaf on at least one connection
	virtual BOOL  IsG2Hub();                           // Returns true if we are acting as a Gnutella2 hub on at least one connection
	virtual DWORD IsG2HubCapable(BOOL bDebug = FALSE); // Returns true if we have a computer and Internet connection powerful enough to become a Gnutella2 hub

	// Determine our role on the Gnutella network
	virtual BOOL  IsG1Leaf();                                // Returns true if we are acting as a Gnutella leaf on at least one connection
	virtual BOOL  IsG1Ultrapeer();                           // Returns true if we are acting as a Gnutella ultrapeer on at least one connection
	virtual DWORD IsG1UltrapeerCapable(BOOL bDebug = FALSE); // Returns true if we have a computer and Internet connection powerful enough to become a Gnutella ultrapeer

	// Determine our needs on the given network, Gnutella or Gnutella2
	virtual BOOL NeedMoreHubs(PROTOCOLID nProtocol, BOOL bMaxPeerSlot = FALSE);		// Returns true if we need more hub connections on 
																					// the given network
	virtual BOOL NeedMoreLeafs(PROTOCOLID nProtocol); // Returns true if we need more leaf connections on the given network
	virtual BOOL IsHubLoaded(PROTOCOLID nProtocol);   // Returns true if we have more than 75% of the number of hub connections settings says is our limit

protected:

	// Member variables that tell our current role on the Gnutella and Gnutella2 networks
	DWORD			m_tHubG2Promotion;		// Time we were promoted to a G2 hub(UTC Time in seconds)
	DWORD			m_tModeCheck;			// Time we checked and decided network mode(UTC Time in seconds)

	// Gnutella2 Bootstrap management.
	DWORD			m_tG2Start;				// Time we enabled Gnutella2 network mode(UTC Time in seconds)
	DWORD			m_tG2AttemptStart;		// Time we enabled Gnutella2 network mode(UTC Time in seconds)
	HostAddrList	m_oG2LocalCache;

	// Gnutella1 Bootstrap management.
	DWORD			m_tG1Start;				// Time we enabled Gnutella1 network mode(UTC Time in seconds)
	DWORD			m_tG1AttemptStart;		// Time we enabled Gnutella1 network mode(UTC Time in seconds)
	HostAddrList	m_oG1LocalCache;

public:
	// Members for maintaining connections.
	PROTOCOLID		m_nLastManagedProtocol;
	int				m_nCount[4][5];			// Number of Neighbours we currently connected with
	int				m_nLimit[4][5];			// max number of neighbor connections we can connect.

	// Hub(Ultrapeer)/Leaf status for Gnutella1/Gnutella2 (BOOLs only need 1Bit.)
	BOOL			m_bG2Leaf		:1;		// True if we are a Leaf to at least one computer on the Gnutella2 network
	BOOL			m_bG2Hub		:1;		// True if we are a Hub to at least one computer on the Gnutella2 network
	BOOL			m_bG1Leaf		:1;		// True if we are a Leaf to at least one computer on the Gnutella network
	BOOL			m_bG1Ultrapeer	:1;		// True if we are an Ultrapeer to at least one computer on the Gnutella network


public:

	// Methods implemented by several classes in the CNeighbours inheritance column
	virtual void OnRun(); // Call DoRun on each neighbour in the list, and maintain the network auto connection

protected:

	// Make new connections and close existing ones
	void Maintain(PROTOCOLID nProtocol);	// Count how many connections we have, and initiate or close them to match the ideal numbers in settings
	void ModeCheck();						// Time to check Local Node mode for networks(Gnutella1/2 only)
	void PeerPrune(PROTOCOLID nProtocol);	// Close hub to hub connections when we get demoted to the leaf role (do)
	void NetworkPrune(PROTOCOLID nProtocol);// Close hub to hub connections when we get demoted to the leaf role (do)

protected:
	// The tick count when we last connected to a hub for each network
	DWORD m_tPresent[8]; // The index is a protocol identifier, like 3 eDonkey2000, 2 Gnutella2, and 1 Gnutella

public:
	int		GetCount(PROTOCOLID nProtocol, int nState, int nNodeType) const;
	void	StoreCache(PROTOCOLID nProtocol, SOCKADDR_IN& pHost);	// Store UDP Bootstrap Reply to LocalCache

	virtual void ConnectG2();			// Connect to Gnutella2
	virtual void DisconnectG2();		// Disconnect from Gnutella2
	virtual void ConnectG1();			// Connect to Gnutella1
	virtual void DisconnectG1();		// Disconnect from Gnutella1
	virtual void ConnectED2K();			// Connect to eDonkey2000
	virtual void DisconnectED2K();		// Disconnect from eDonkey2000

};

// End the group of lines to only include once, pragma once doesn't require an endif at the bottom
#endif // !defined(AFX_NEIGHBOURSWITHCONNECT_H__7BAE2435_FF99_4E23_8EBE_B7C3E5FFCCB0__INCLUDED_)
