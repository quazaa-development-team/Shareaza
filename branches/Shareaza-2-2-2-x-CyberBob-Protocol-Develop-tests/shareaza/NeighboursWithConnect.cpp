//
// NeighboursWithConnect.cpp
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

// Determine our hub or leaf role, count connections for each, and make new ones or close them to have the right number
// http://wiki.shareaza.com/static/Developers.Code.CNeighboursWithConnect

// Copy in the contents of these files here before compiling
#include "StdAfx.h"
#include "Shareaza.h"
#include "Settings.h"
#include "Network.h"
#include "Datagrams.h"
#include "Security.h"
#include "HostCache.h"
#include "Downloads.h"
#include "DiscoveryServices.h"
#include "NeighboursWithConnect.h"
#include "ShakeNeighbour.h"
#include "EDNeighbour.h"
#include "G2Neighbour.h"
#include "G1Neighbour.h"
#include "Neighbours.h"

// If we are compiling in debug mode, replace the text "THIS_FILE" in the code with the name of this file
#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////
// CNeighboursWithConnect construction

// CNeighboursWithConnect adds an array that needs to be filled with 0s when the program creates its CNeighbours object
CNeighboursWithConnect::CNeighboursWithConnect() :
// We're not acting as a hub/ultrapeer or leaf on Gnutella or Gnutella2 yet
m_bG2Hub(FALSE),
m_bG2Leaf(FALSE),
m_bG1Ultrapeer(FALSE),
m_bG1Leaf(FALSE),
m_tHubG2Promotion(0),	// G2Hub promotion time (TIME)
m_tModeCheck(0),			// Node state check for G2Hub/G2Leaf, G1Ultrapeer/G1Leaf (TickCount)
m_nLastManagedProtocol(PROTOCOL_G1),
m_tG2Start(0),
m_tG2AttemptStart(0),
m_oG2LocalCache(),
m_tG1Start(0),
m_tG1AttemptStart(0),
m_oG1LocalCache()
{
	// Zero the tick counts in m_tPresent, we haven't connected to a hub for any network yet
	ZeroMemory( m_tPresent, sizeof(m_tPresent) );
	// Zero clear the connection count array(hold number of connection for each Protocol/NodeType in array)
	ZeroMemory( m_nCount, sizeof( m_nCount ) );
	ZeroMemory( m_nLimit, sizeof( m_nLimit ) );
}

// CNeighboursWithConnect doesn't add anything to the CNeighbours inheritance column that needs to be cleaned up
CNeighboursWithConnect::~CNeighboursWithConnect()
{
}

//////////////////////////////////////////////////////////////////////
// CNeighboursWithConnect connection initiation

// Maintain calls CHostCacheHost::ConnectTo, which calls this
// Takes an IP address and port number from the host cache, and connects to it
// Returns a pointer to the new neighbour in the connected list, or null if no connection was made
CNeighbour* CNeighboursWithConnect::ConnectTo(
	IN_ADDR*		pAddress,		// IP address from the host cache to connect to, like 67.163.208.23
	WORD			nPort,			// Port number that goes with that IP address, like 6346
	PROTOCOLID		nProtocol,		// Protocol name, like PROTOCOL_G1 for Gnutella
	BOOL			bAutomatic,		// True to (do)
	BOOL			bNoUltraPeer,	// By default, false to not (do)
	BOOL			bFirewallTest,	// Making Connection to test if the remote node's TCP is firewalled or not.
	BOOL			bUDP)
{
	// Get this thread exclusive access to the network (do) while this method runs 
	CSingleLock pLock( &Network.m_pSection, TRUE ); // When control leaves the method, pLock will go out of scope and release access

	// If the list of connected computers already has this IP address and not testing firewall
	if ( !bFirewallTest )
	{
		bool bExist = false;
		switch ( nProtocol )
		{
		case PROTOCOL_G1:
			bExist = GetG1Node( pAddress ) ? true : false;
			break;
		case PROTOCOL_G2:
			bExist = GetG2Node( pAddress ) ? true : false;
			break;
		case PROTOCOL_ED2K:
			bExist = GetEDNode( pAddress ) ? true : false;
			break;
		default:
			bExist = Get( pAddress ) ? true : false;
			break;
		}

		if ( bExist )
		{
			// If automatic (do) leave without making a note of the error
			if ( bAutomatic ) return NULL;

			// Report that we're already connected to that computer, and return no new connection made
			theApp.Message( MSG_ERROR, IDS_CONNECTION_ALREADY_ABORT, (LPCTSTR)CString( inet_ntoa( *pAddress ) ) );
			return NULL;
		}
	}

	// Don't connect to self
	if ( Settings.Connection.IgnoreOwnIP && pAddress->S_un.S_addr == Network.m_pHost.sin_addr.S_un.S_addr ) 
		return NULL;

	// Commenting out for now, this part would mean nothing since CConnection Blocks

	// Don't connect to blocked addresses
	//if ( Security.IsDenied( pAddress ) )
	//{
	//	// If automatic (do) leave without making a note of the error
	//	if ( bAutomatic ) return NULL;
	//
	//	// Report that this address is on the block list, and return no new connection made
	//	theApp.Message( MSG_ERROR, IDS_NETWORK_SECURITY_OUTGOING, (LPCTSTR)CString( inet_ntoa( *pAddress ) ) );
	//	return NULL;
	//}

	// If automatic (do) and the network object knows this IP address is firewalled and can't receive connections, give up
	if ( bAutomatic && Network.IsFirewalledAddress( pAddress, TRUE ) ) return NULL;

	// Run network connect (do), and leave if it reports an error
	if ( !Network.IsConnected() && !Network.Connect() ) return NULL;

	// If the caller wants automatic behavior, then make this connection request also connect the network it is for
	if ( !bAutomatic )
	{
		// Activate the appropriate network (if required)
		switch ( nProtocol )
		{

		// The computer we will connect to is running Gnutella software
		case PROTOCOL_G1:

			// Let the program connect to the Gnutella network
			if ( !Settings.Gnutella1.EnableToday ) ConnectG1();
			break;

		// The computer we will connect to is running Gnutella2 software
		case PROTOCOL_G2:

			// Let the program connect to the Gnutella2 network
			if ( !Settings.Gnutella2.EnableToday ) ConnectG2();
			break;

		// The computer we will connect to is running eDonkey2000 software
		case PROTOCOL_ED2K:

			// Let the program connect to the eDonkey2000 network
			if ( !Settings.eDonkey.EnableToday ) ConnectED2K();
			// Reset the eDonkey2000 network (do)
			CloseDonkeys();
			break;
		default:
//			ASSERT( 0 )
			;
		}
	}

	// The computer at the IP address we have is running eDonkey2000 software
	if ( nProtocol == PROTOCOL_ED2K )
	{
		// Make a new CEDNeighbour object, connect it to the IP address, and return a pointer to it
		CEDNeighbour* pNeighbour = new CEDNeighbour();
		if ( pNeighbour->ConnectTo( pAddress, nPort, bAutomatic ) ) 
		{
			// Started connecting to an ed2k neighbour
			return pNeighbour;
		}
		delete pNeighbour;

	} // The computer at the IP address we have is running Gnutella or Gnutella2 software
	else if ( nProtocol == PROTOCOL_G2 && bUDP )
	{
		// Make a new CEDNeighbour object, connect it to the IP address, and return a pointer to it
		CG2Neighbour* pNeighbour = new CG2Neighbour();
		if ( pNeighbour->ConnectTo( pAddress, nPort, bAutomatic, TRUE ) ) 
		{
			// Started connecting to an ed2k neighbour
			return pNeighbour;
		}
		delete pNeighbour;

	} // The computer at the IP address we have is running Gnutella or Gnutella2 software
	else
	{
		// Make a new CShakeNeighbour object, connect it to the IP address, and return a pointer to it
		CShakeNeighbour* pNeighbour = new CShakeNeighbour();

		if ( pNeighbour->ConnectTo( pAddress, nPort, bAutomatic, bNoUltraPeer, bFirewallTest ) ) // Started connecting to a Gnutella or Gnutella2 neighbour
		{
			// Started connecting to a G1/G2 neighbour

			// If we only want G1 connections now, specify that to begin with.
			if ( Settings.Gnutella.SpecifyProtocol )
			{
				pNeighbour->m_nProtocol = nProtocol;
			}

			return pNeighbour;
		}

		// ConnectTo failed, delete the object we made
		delete pNeighbour;
	}

	// Some other protocol, return no connection made
	return NULL; // Not able to connect
}

//////////////////////////////////////////////////////////////////////
// CNeighboursWithConnect accept a connection

// CHandshake::OnRead gets an incoming socket connection, looks at the first 7 bytes, and passes Gnutella and Gnutella2 here
// Takes a pointer to the CHandshake object the program made when it accepted the new connection from the listening socket
// Makes a new CShakeNeighbour object, and calls AttachTo to have it take this incoming connection
// Returns a pointer to the CShakeNeighbour object
CNeighbour* CNeighboursWithConnect::OnAccept(CConnection* pConnection)
{
	// Get this thread exclusive access to the network (do) while this method runs 
	CSingleLock pLock( &Network.m_pSection ); // When control leaves the method, pLock will go out of scope and release access
	if ( ! pLock.Lock( 250 ) ) return NULL;   // If more than a quarter second passes here waiting for access, give up and leave now

	// Make a new CShakeNeighbour object, have it pickup this incoming connection, and return a pointer to it
	CShakeNeighbour* pNeighbour = new CShakeNeighbour();
	if ( pNeighbour != NULL )
	{
		pNeighbour->AttachTo( pConnection );
	}
	else
	{
		theApp.Message( MSG_ERROR, _T("memory allocation error making new CNeighbour from CHandshake.") );
	}
	return pNeighbour;
}

//////////////////////////////////////////////////////////////////////
// CNeighboursWithConnect

// If we've been demoted to the leaf role for a protocol, this function trims peers after we get a hub (do)
// Takes a protocol like PROTOCOL_G1 or PROTOCOL_G2
// If we don't need any more hub connections, closes them all (do)
void CNeighboursWithConnect::PeerPrune(PROTOCOLID nProtocol)
{
	// True if we need more hub connections for the requested protocol
	BOOL bNeedMore = NeedMoreHubs( nProtocol );

	// True if we need more hub connections for either Gnutella or Gnutella2
	BOOL bNeedMoreAnyProtocol = NeedMoreHubs( PROTOCOL_NULL );

	// Loop through all the neighbours in the list
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		// Get the neighbour at this position in the list, and move to the next one
		CNeighbour* pNeighbour = GetNext( pos );

		// This neighbour is on the network the caller wants us to prune, and
		if ( pNeighbour->m_nProtocol == nProtocol )
		{
			// Our connection to this neighbour is not up to a hub, and
			if ( pNeighbour->m_nNodeType == ntNode || pNeighbour->m_nNodeType == ntLeaf )
			{
				// Either we don't need any more hubs, or we're done with the handshake so we know it wont' be a hub, then
				if ( ! bNeedMore || pNeighbour->m_nState == nrsConnected )
				{
					// Drop this connection
					pNeighbour->Close( IDS_CONNECTION_PEERPRUNE );
				}
			}

		} // This must be a Gnutella or Gnutella2 computer in the middle of the handshake
		else if ( pNeighbour->m_nProtocol == PROTOCOL_NULL )
		{
			// If we initiated the connection, we know it's not a leaf trying to contact us, it's probably a hub
			if ( pNeighbour->m_bInitiated )
			{
				// If we dont' need any more hubs, on any protocol, drop this connection
				if ( !bNeedMoreAnyProtocol ) pNeighbour->Close( IDS_CONNECTION_PEERPRUNE );
			}
		}
	}
}

// Determines if we are a leaf on the Gnutella2 network right now
// Returns true or false
BOOL CNeighboursWithConnect::IsG2Leaf()
{
	// If the network is enabled (do) and we have at least 1 connection up to a hub, then we're a leaf
	return ( Network.m_bEnabled && m_bG2Leaf && Settings.Gnutella2.ClientMode != MODE_HUB );
}

// Determines if we are a hub on the Gnutella2 network right now
// Returns true or false
BOOL CNeighboursWithConnect::IsG2Hub()
{
	// If the network is enabled (do) and we have at least 1 connection down to a leaf, then we're a hub
	return ( Network.m_bEnabled && m_bG2Hub && Settings.Gnutella2.ClientMode != MODE_LEAF );
}

// Takes true if we are running the program in debug mode, and this method should write out debug information
// Determines if the computer and Internet connection here are strong enough for this program to run as a Gnutella2 hub
// Returns false, which is 0, if we can't be a hub, or a number 1+ that is higher the better hub we'd be
DWORD CNeighboursWithConnect::IsG2HubCapable(BOOL bIgnoreCurrentMode, BOOL bDebug)
{
	// Start the rating at 0, which means we can't be a hub
	DWORD nRating = 0; // We'll make this number bigger if we find signs we can be a hub

	// If the caller wants us to report debugging information, start out with a header line
	if ( bDebug ) theApp.Message( MSG_DEBUG, _T("IsHubCapable():") );

	// We can't be a Gnutella2 hub if the user has not chosen to connect to Gnutella2 in the program settings
	if ( !Network.IsConnected() || !Settings.Gnutella2.EnableToday )
	{
		// Finish the lines of debugging information, and report no, we can't be a hub
		if ( bDebug ) theApp.Message( MSG_DEBUG, _T("NO: G2 not enabled") );
		return FALSE;
	}

	// Windows 95, 98, and Me don't support enough socket connections for a good Gnutella2 hub
	if ( !theApp.m_bNT ) // If the program isn't running on a version of Windows NT, like 2000 or XP
	{
		// Finish the lines of debugging information, and report no, we can't be a hub
		if ( bDebug ) theApp.Message( MSG_DEBUG, _T("NO: OS is not NT based") );
		return FALSE;

	} // The program is running on Windows NT, 2000, or XP
	else
	{
		// Report that we passed this test
		if ( bDebug ) theApp.Message( MSG_DEBUG, _T("OK: OS is NT based") );
	}

	// The user can go into settings and check a box to make the program never run in hub mode, even if it could
	if ( Settings.Gnutella2.ClientMode == MODE_LEAF ) // If the user disalbled hub mode for the program in settings
	{
		// Finish the lines of debugging information, and report no, we can't be a hub
		if ( bDebug ) theApp.Message( MSG_DEBUG, _T("NO: hub mode disabled") );
		return FALSE;
	}

	if ( !bIgnoreCurrentMode )
	{
		// We are running as a Gnutella2 leaf right now
		if ( IsG2Leaf() )
		{
			// We can never be a hub because we are a leaf (do)
			if ( bDebug ) theApp.Message( MSG_DEBUG, _T("NO: leaf") );
			return FALSE;
		} // We are not running as a Gnutella2 leaf right now (do)
		else
		{
			// Note this and keep going
			if ( bDebug ) theApp.Message( MSG_DEBUG, _T("OK: not a leaf") );
		}
	}

	// Make sure the connection limits for Gnutella2 in settings aren't too low
	if ( Settings.Gnutella2.NumPeers < 4 ) // The user says we can't have 4 or more connections to hubs (do)
	{
		// If debugging, log the reason we can't be a hub, and return no
		if ( bDebug ) theApp.Message( MSG_DEBUG, _T("NO: less than 4x G2 hub to hub") );
		return FALSE;
	}

	// The user says we can't have 50 or more connetions to leaves, as a hub, we would need more
	if ( Settings.Gnutella2.NumLeafs < 50 )
	{
		// If debugging, log the reason we can't be a hub, and return no
		if ( bDebug ) theApp.Message( MSG_DEBUG, _T("NO: less than 50x G2 hub to leaf") );
		return FALSE;
	}

	// The user can check a box in settings to let the program become a hub without passing the additional tests below
	if ( Settings.Gnutella2.ClientMode == MODE_HUB )
	{
		// Make a note about this and keep going
		if ( bDebug ) theApp.Message( MSG_DEBUG, _T("YES: hub mode forced") );

	} // The user didn't check the force hub box in settings, so the program will have to pass the additional tests below
	else
	{
		// See how much physical memory the computer we are running on has
		if ( theApp.m_nPhysicalMemory < 250 * 1024 * 1024 ) // It's less than 250 MB
		{
			// Not enough memory to be a hub
			if ( bDebug ) theApp.Message( MSG_DEBUG, _T("NO: less than 250 MB RAM") );
			return FALSE;

		} // The computer has 250 MB or more RAM
		else
		{
			// Make a note we passed this test, and keep going
			if ( bDebug ) theApp.Message( MSG_DEBUG, _T("OK: more than 250 MB RAM") );
		}

		// Check the connection speed, make sure the download speed is fast enough
		if ( Settings.Connection.InSpeed < 200 ) // If the inbound speed is less than 200 (do)
		{
			// Download speed too slow
			if ( bDebug ) theApp.Message( MSG_DEBUG, _T("NO: less than 200 Kb/s in") );
			return FALSE;
		}

		// Make sure the upload speed is fast enough
		if ( Settings.Connection.OutSpeed < 200 )
		{
			// Upload speed too slow
			if ( bDebug ) theApp.Message( MSG_DEBUG, _T("NO: less than 200 Kb/s out") );
			return FALSE;
		}

		// Confirm how long the node has been running.
		if ( Settings.Gnutella2.HubVerified )
		{
			// Systems that have been good hubs before can promote in 2 hours
			if ( Network.GetStableTime() < 7200 )
			{
				if ( bDebug ) theApp.Message( MSG_DEBUG, _T("NO: not stable for 2 hours") );
				return FALSE;
			}
			else
			{
				if ( bDebug ) theApp.Message( MSG_DEBUG, _T("OK: stable for 2 hours") );
			}
		}
		else
		{
			// Untested hubs need 3 hours uptime to be considered
			if ( Network.GetStableTime() < 10800 )
			{
				if ( bDebug ) theApp.Message( MSG_DEBUG, _T("NO: not stable for 3 hours") );
				return FALSE;
			}
			else
			{
				if ( bDebug ) theApp.Message( MSG_DEBUG, _T("OK: stable for 3 hours") );
			}
		}

		// Make sure UDP is stable (do)
		if ( Network.IsFirewalled(CHECK_UDP) != TS_FALSE )
		{
			// Record this is why we can't be a hub, and return no
			if ( bDebug ) theApp.Message( MSG_DEBUG, _T("NO: UDP not stable") );
			return FALSE;

		} // The datagram is stable (do)
		else
		{
			// Make a note we passed this test, and keep going
			if ( bDebug ) theApp.Message( MSG_DEBUG, _T("OK: UDP stable") );
		}

		// Make sure TCP is stable (do)
		if ( Network.IsFirewalled(CHECK_TCP) != TS_FALSE )
		{
			// Record this is why we can't be a hub, and return no
			if ( bDebug ) theApp.Message( MSG_DEBUG, _T("NO: TCP not stable") );
			return FALSE;

		} // The datagram is stable (do)
		else
		{
			// Make a note we passed this test, and keep going
			if ( bDebug ) theApp.Message( MSG_DEBUG, _T("OK: TCP stable") );
		}

		// The scheduler is enabled in settings, and it says we can't be a hub
		if ( Settings.Scheduler.Enable && ! Settings.Scheduler.AllowHub )
		{
			// Record this is why we can't be a hub, and return no
			if ( bDebug ) theApp.Message( MSG_DEBUG, _T("NO: scheduler active") );
			return FALSE;

		} // The scheduler is off, or it's on and it's OK with us being a hub
		else
		{
			// Make a note we passed this test, and keep going
			if ( bDebug ) theApp.Message( MSG_DEBUG, _T("OK: scheduler OK") );
		}

		// Report that we meet the minimum requirements to be a hub
		if ( bDebug ) theApp.Message( MSG_DEBUG, _T("YES: hub capable by test") );
	}

	// If we've made it this far, change the rating number from 0 to 1
	nRating = 1; // The higher it is, the better a hub we can be

	// Now, evaluate how good a hub we are likely to be, starting out with a point for lots of memory
	if ( theApp.m_nPhysicalMemory > 600 * 1024 * 1024 ) // The computer here has more than 600 MB of memory
	{
		nRating++;
		if ( bDebug ) theApp.Message( MSG_DEBUG, _T("More than 600 MB RAM") );
	}

	// Our Internet connection allows fast downloads
	if ( Settings.Connection.InSpeed > 1000 ) // More than 1 Mbps inbound (do)
	{
		nRating++;
		if ( bDebug ) theApp.Message( MSG_DEBUG, _T("More than 1 Mb/s in") );
	}

	// Our Internet connection allows fast uploads
	if ( Settings.Connection.OutSpeed > 1000 ) // More than 1 Mbps outbound (do)
	{
		nRating++;
		if ( bDebug ) theApp.Message( MSG_DEBUG, _T("More than 1 Mb/s out") );
	}

	// We'll be a better Gnutella2 hub if the program isn't connected to the other networks
	if ( ! Settings.eDonkey.EnableToday ) // Not connected to eDonkey2000
	{
		nRating++;
		if ( bDebug ) theApp.Message( MSG_DEBUG, _T("eDonkey not enabled") );
	}

	// The user has never used BitTorrent, so that won't be taking up any bandwidth
	if ( ! Settings.BitTorrent.AdvancedInterfaceSet )
	{
		nRating++;
		if ( bDebug ) theApp.Message( MSG_DEBUG, _T("BT is not in use") );
	}

	// The program is not connected to the Gnutella network
	if ( ! Settings.Gnutella1.EnableToday )
	{
		nRating++;
		if ( bDebug ) theApp.Message( MSG_DEBUG, _T("G1 not enabled") );
	}

	// If the program has been connected (do) for more than 8 hours, give it another point
	if ( Network.GetStableTime() > 28800 ) // 28800 seconds is 8 hours
	{
		nRating++;
		if ( bDebug ) theApp.Message( MSG_DEBUG, _T("Stable for 8 hours") );
	}

	// If the scheduler isn't enabled, award another point
	if ( !Settings.Scheduler.Enable )
	{
		nRating++;
	}

	// ToDo: Find out more about the computer to award more rating points
	// Scheduler: If the scheduler is going to shut down the program and the computer at any time, this isn't a good choice for a hub
	// Scheduler: If the scheduler is going to shut us down in the next few hours, we shouldn't become a hub at all
	// CPU: Add a CPU check, award a point if this computer has a fast processor
	// Router: Some routers can't handle the 100+ socket connections a hub maintains, check for a router and lower the score
	// File transfer: Check how many files are shared and the file transfer in both directions, the perfect hub isn't sharing or doing any file transfer at all

	// If debug mode is enabled, display the hub rating in the system window log (do)
	if ( bDebug )
	{
		CString strRating;
		strRating.Format( _T("Hub rating: %d"), nRating );
		theApp.Message( MSG_DEBUG, strRating );
	}

	// Return 0 if we can't be a Gnutella2 hub, or 1+ if we can, a higher number means we'd be a better hub
	return nRating;
}

// Determines if we are a leaf on the Gnutella network right now
// Returns true or false
BOOL CNeighboursWithConnect::IsG1Leaf()
{
	// If the network is enabled (do) and we have at least 1 connection up to an ultrapeer, then we're a leaf
	return ( Network.m_bEnabled && m_bG1Leaf && Settings.Gnutella1.ClientMode != MODE_ULTRAPEER );
}

// Determines if we are an ultrapeer on the Gnutella network right now
// Returns true or false
BOOL CNeighboursWithConnect::IsG1Ultrapeer()
{
	// If the network is enabled (do) and we have at least 1 connection down to a leaf, then we're an ultrapeer
	return ( Network.m_bEnabled && m_bG1Ultrapeer && Settings.Gnutella1.ClientMode != MODE_LEAF );
}

// Takes true if we are running the program in debug mode, and this method should write out debug information
// Determines if the computer and Internet connection here are strong enough for this program to run as a Gnutella ultrapeer
// Returns false, which is 0, if we can't be an ultrapeer, or a number 1+ that is higher the better ultrapeer we'd be
DWORD CNeighboursWithConnect::IsG1UltrapeerCapable(BOOL bIgnoreCurrentMode, BOOL bDebug)
{
	// Start out the rating as 0, meaning we can't be a Gnutella ultrapeer
	DWORD nRating = 0; // If we can be an ultrapeer, we'll set this to 1, and then make it higher if we'd be an even better ultrapeer

	// If the caller requested we write out debugging information, start out by titling that the messages that follow come from this method
	if ( bDebug ) theApp.Message( MSG_DEBUG, _T("IsUltrapeerCapable():") );

	// We can't be a Gnutella ultrapeer if we're not connected to the Gnutella network
	if ( !Network.IsConnected() || !Settings.Gnutella1.EnableToday )
	{
		if ( bDebug ) theApp.Message( MSG_DEBUG, _T("NO: Gnutella1 not enabled") );
		return FALSE;
	}

	// Windows 95, 98, and Me don't support enough socket connections for a good Gnutella ultrapeer
	if ( !theApp.m_bNT )
	{
		if ( bDebug ) theApp.Message( MSG_DEBUG, _T("NO: OS is not NT based") );
		return FALSE;

	} // The program is running on Windows NT, 2000, or XP
	else
	{
		if ( bDebug ) theApp.Message( MSG_DEBUG, _T("OK: OS is NT based") );
	}

	// The user can go into settings and check a box to make the program never become an ultrapeer, even if it could
	if ( Settings.Gnutella1.ClientMode == MODE_LEAF )
	{
		if ( bDebug ) theApp.Message( MSG_DEBUG, _T("NO: ultrapeer mode disabled") );
		return FALSE;
	}

	if ( !bIgnoreCurrentMode )
	{
		// We are running as a Gnutella leaf right now
		if ( IsG1Leaf() )
		{
			// We can never be an ultrapeer because we are a leaf (do)
			if ( bDebug ) theApp.Message( MSG_DEBUG, _T("NO: leaf") );
			return FALSE;
		} // We are running as a Gnutella ultrapeer already (do)
		else
		{
			if ( bDebug ) theApp.Message( MSG_DEBUG, _T("OK: not a leaf") );
		}
	}

	// The user can check a box in settings to let the program become an ultrapeer without passing the additional tests below
	if ( Settings.Gnutella1.ClientMode == MODE_ULTRAPEER )
	{
		// Note this and keep going
		if ( bDebug ) theApp.Message( MSG_DEBUG, _T("YES: ultrapeer mode forced") );

	} // The user didn't check the force ultrapeer box in settings, so the program will have to pass the additional tests below
	else
	{
		// If we are a Gnutella2 hub, then we shouldn't also be a Gnutella ultrapeer
		if ( IsG2Hub() )
		{
			// ToDo: Check what sort of machine could handle being both a Gnutella ultrapeer and a Gnutella2 hub at the same time

			// Report the reason we can't be an ultrapeer, and return no
			if ( bDebug ) theApp.Message( MSG_DEBUG, _T("NO: Acting as a G2 hub") );
			return FALSE;

		} // We aren't a Gnutella2 hub right now
		else
		{
			// Make a note we passed this test, and keep going
			if ( bDebug ) theApp.Message( MSG_DEBUG, _T("OK: not a G2 hub") );
		}

		// Check how much memory is installed in this computer
		if ( theApp.m_nPhysicalMemory < 250 * 1024 * 1024 ) // If it's less than 250 MB
		{
			// Not enough memory to become a Gnutella ultrapeer
			if ( bDebug ) theApp.Message( MSG_DEBUG, _T("NO: less than 250 MB RAM") );
			return FALSE;

		} // This computer has 256 MB of memory or more
		else
		{
			// Make a note we passed this test, and keep going
			if ( bDebug ) theApp.Message( MSG_DEBUG, _T("OK: more than 250 MB RAM") );
		}

		// Check the connection speed, make sure the download speed is fast enough
		if ( Settings.Connection.InSpeed < 200 ) // If the inbound speed is less than 200 (do)
		{
			if ( bDebug ) theApp.Message( MSG_DEBUG, _T("NO: less than 200 Kb/s in") );
			return FALSE;
		}

		// Make sure the upload speed is fast enough
		if ( Settings.Connection.OutSpeed < 200 )
		{
			if ( bDebug ) theApp.Message( MSG_DEBUG, _T("NO: less than 200 Kb/s out") );
			return FALSE;
		}

		// Make sure settings aren't limiting the upload speed too much
		if ( ( Settings.Bandwidth.Uploads <= 4096 ) && ( Settings.Bandwidth.Uploads != 0 ) )
		{
			if ( bDebug ) theApp.Message( MSG_DEBUG, _T("NO: Upload limit set too low") );
			return FALSE;
		}

		// Check other settings related to Gnutella ultrapeer mode, they should all be higher than these values
		if ( Settings.Gnutella1.NumPeers < 4 ) // The user says we can't have 4 or more connections to ultrapeers (do)
		{
			if ( bDebug ) theApp.Message( MSG_DEBUG, _T("NO: less than 4x G1 peer to peer") );
			return FALSE;
		}

		// Settings limit the number of leaf connetions to fewer than 5, as an ultrapeer, we would need more
		if ( Settings.Gnutella1.NumLeafs < 5 )
		{
			if ( bDebug ) theApp.Message( MSG_DEBUG, _T("NO: less than 5x G1 ultrapeer to leaf") );
			return FALSE;
		}

		// We can only become an ultrapeer if we've been connected for 4 hours or more, it takes awhile for ultrapeers to get leaves, so stability is important
		if ( Network.GetStableTime() < 14400 ) // 14400 seconds is 4 hours
		{
			if ( bDebug ) theApp.Message( MSG_DEBUG, _T("NO: not stable for 4 hours") );
			return FALSE;

		} // We have been connected to the Gnutella network for more than 4 hours
		else
		{
			if ( bDebug ) theApp.Message( MSG_DEBUG, _T("OK: stable for 4 hours") );
		}

		// Make sure the TCP is open
		if ( Network.IsFirewalled(CHECK_TCP) != TS_FALSE )
		{
			if ( bDebug ) theApp.Message( MSG_DEBUG, _T("NO: TCP might be Firewalled") );
			return FALSE;

		} // The TCP is stable (do)
		else
		{
			if ( bDebug ) theApp.Message( MSG_DEBUG, _T("OK: TCP is not firewalled") );
		}

		// Make sure the datagram is stable (do)
		if ( Network.IsFirewalled(CHECK_UDP) != TS_FALSE )
		{
			if ( bDebug ) theApp.Message( MSG_DEBUG, _T("NO: datagram not stable") );
			return FALSE;

		} // The datagram is stable (do)
		else
		{
			if ( bDebug ) theApp.Message( MSG_DEBUG, _T("OK: datagram stable") );
		}

		// The scheduler is enabled in settings, and it says we can't be an ultrapeer
		if ( Settings.Scheduler.Enable && !Settings.Scheduler.AllowHub )
		{	
			if ( bDebug ) theApp.Message( MSG_DEBUG, _T("NO: scheduler active") );
			return FALSE;

		} // The scheduler is off, or it's on and it's OK with us being an ultrapeer
		else
		{	
			if ( bDebug ) theApp.Message( MSG_DEBUG, _T("OK: scheduler OK") );
		}

		if ( bDebug ) theApp.Message( MSG_DEBUG, _T("YES: ultrapeer capable by test") );
	}

	// If we've made it this far, change the rating number from 0 to 1
	nRating = 1; // The higher it is, the better an ultrapeer we can be

	// Now, evaluate how good an ultrapeer we are likely to be, starting out with a point for lots of memory
	if ( theApp.m_nPhysicalMemory > 600 * 1024 * 1024 ) // The computer here has more than 600 MB of memory
	{
		nRating++;
		if ( bDebug ) theApp.Message( MSG_DEBUG, _T("More than 600 MB RAM") );
	}

	// Our Internet connection allows fast downloads
	if ( Settings.Connection.InSpeed > 1000 ) // More than 1 Mbps inbound (do)
	{
		nRating++;
		if ( bDebug ) theApp.Message( MSG_DEBUG, _T("More than 1 Mb/s in") );
	}

	// Our Internet connection allows fast uploads
	if ( Settings.Connection.OutSpeed > 1000 ) // More than 1 Mbps outbound (do)
	{
		nRating++;
		if ( bDebug ) theApp.Message( MSG_DEBUG, _T("More than 1 Mb/s out") );
	}

	// We'll be a better Gnutella ultrapeer if the program isn't connected to the other networks
	if ( !Settings.eDonkey.EnableToday ) // Not connected to eDonkey2000
	{
		nRating++;
		if ( bDebug ) theApp.Message( MSG_DEBUG, _T("eDonkey not enabled") );
	}

	// The user has never used BitTorrent, so that won't be taking up any bandwidth
	if ( ! Settings.BitTorrent.AdvancedInterfaceSet )
	{
		nRating++;
		if ( bDebug ) theApp.Message( MSG_DEBUG, _T("BT is not in use") );
	}

	// The program is not connected to the Gnutella2 network
	if ( !Settings.Gnutella2.EnableToday )
	{
		nRating++;
		if ( bDebug ) theApp.Message( MSG_DEBUG, _T("G2 not enabled") );
	}

	// If the program has been connected (do) for more than 8 hours, give it another point
	if ( Network.GetStableTime() > 28800 ) // 28800 seconds is 8 hours
	{
		nRating++;
		if ( bDebug ) theApp.Message( MSG_DEBUG, _T("Stable for 8 hours") );
	}

	// If the scheduler isn't enabled, award another point
	if ( !Settings.Scheduler.Enable )
	{
		nRating++;
	}

	// ToDo: Find out more about the computer to award more rating points
	// Scheduler: If the scheduler is going to shut down the program and the computer at any time, this isn't a good choice for an ultrapeer
	// Scheduler: If the scheduler is going to shut us down in the next few hours, we shouldn't become an ultrapeer
	// CPU: Add a CPU check, award a point if this computer has a fast processor
	// Router: Some routers can't handle the 100+ socket connections an ultrapeer maintains, check for a router and lower the score
	// File transfer: Check how many files are shared and the file transfer in both directions, the perfect ultrapeer isn't sharing or doing any file transfer at all

	// If debug mode is enabled, display the ultrapeer rating in the system window log (do)
	if ( bDebug )
	{
		// Compose text that includes the rating, and show it in the user interface
		CString strRating;
		strRating.Format( _T("Ultrapeer rating: %d"), nRating );
		theApp.Message( MSG_DEBUG, strRating );
	}

	// Return 0 if we can't be a Gnutella ultrapeer, or 1+ if we can, a higher number means we'd be a better ultrapeer
	return nRating;
}

//////////////////////////////////////////////////////////////////////
// CNeighboursWithConnect connection capacity

// Takes a protocol name, like PROTOCOL_G1, PROTOCOL_G2, or PROTOCOL_NULL for both
// Counts how many connections to hubs we have for that protocol, and compares that number to settings
// Returns true if we need more hub connections, false if we have enough
BOOL CNeighboursWithConnect::NeedMoreHubs(PROTOCOLID nProtocol, BOOL bWithMaxPeerSlot)
{
	// Only continue if the network is connected (do)
	if ( ! Network.IsConnected() ) return FALSE;

	/*	Need something like Unlimited mode.
	if ( ! Network.m_bAutoConnect )
	{
		if (bWithMaxPeerSlot)
			return TRUE;
		else
			return FALSE;
	}
	*/

	// Make an array to count the number of hub connections we have for each network
	//int nConnected[4] = { 0, 0, 0, 0 }; // Unknown network, Gnutella, Gnutella2, eDonkey2000

	/*
	// Count the number of hubs we are connected to
	for ( POSITION pos = GetIterator() ; pos ; ) // Loop for each neighbour in the list
	{
		// Get the neighbour at this position, and move the position forward
		CNeighbour* pNeighbour = GetNext( pos );

		// If we've finished the handshake with this neighbour, and our connection to it isn't down to a leaf
		if ( pNeighbour->m_nState == nrsConnected && pNeighbour->m_nNodeType != ntLeaf )
		{
			// Count it as one more for its protocol
			nConnected[ pNeighbour->m_nProtocol ]++;
		}
	}
	*/

	// Compose the answer for the protocol the caller wants to know about
	switch ( nProtocol )
	{

	// The caller wants to know if we need more hubs for either Gnutella or Gnutella2
	case PROTOCOL_NULL:

		// If we need more Gnutella ultrapeers or Gnutella2 hubs, return true, only return false if we don't need more hubs from either network
		//return ( ( Settings.Gnutella1.EnableToday ) && ( ( nConnected[1] ) < ( IsG1Leaf() ? Settings.Gnutella1.NumHubs : Settings.Gnutella1.NumPeers ) ) ||
		//		   ( Settings.Gnutella2.EnableToday ) && ( ( nConnected[2] ) < ( IsG2Leaf() ? Settings.Gnutella2.NumHubs : Settings.Gnutella2.NumPeers ) ) );
		if ( bWithMaxPeerSlot )
		{
			return ( ( ( Settings.Gnutella1.EnableToday ) && ( m_nCount[PROTOCOL_G1][ntHub] + m_nCount[PROTOCOL_G1][ntNode] < m_nLimit[PROTOCOL_G1][ntNode] ) ) ||
					 ( ( Settings.Gnutella2.EnableToday ) && ( m_nCount[PROTOCOL_G2][ntHub] + m_nCount[PROTOCOL_G2][ntNode] < m_nLimit[PROTOCOL_G2][ntNode] ) ) );
		}
		else
		{
			return ( ( ( Settings.Gnutella1.EnableToday ) && ( m_nCount[PROTOCOL_G1][ntHub] + m_nCount[PROTOCOL_G1][ntNode] < m_nLimit[PROTOCOL_G1][ntHub] ) ) ||
					 ( ( Settings.Gnutella2.EnableToday ) && ( m_nCount[PROTOCOL_G2][ntHub] + m_nCount[PROTOCOL_G2][ntNode] < m_nLimit[PROTOCOL_G2][ntHub] ) ) );
		}

	// Return true if we need more Gnutella ultrapeer connections
	case PROTOCOL_G1:

		// If we're not connected to Gnutella, say we have enough ultrapeer connections
		if ( Settings.Gnutella1.EnableToday == FALSE ) return FALSE;

		// If we're a leaf, compare our hub count to NumHubs from settings, return true if we don't have enough
		//return ( nConnected[1] ) < ( IsG1Leaf() ? Settings.Gnutella1.NumHubs : Settings.Gnutella1.NumPeers ); // 2 and 0 defaults

		if ( bWithMaxPeerSlot )
		{
			return ( m_nCount[PROTOCOL_G1][ntHub] + m_nCount[PROTOCOL_G1][ntNode] < m_nLimit[PROTOCOL_G1][ntNode] ); // 2
		}
		else
		{
			return ( m_nCount[PROTOCOL_G1][ntHub] + m_nCount[PROTOCOL_G1][ntNode] < m_nLimit[PROTOCOL_G1][ntHub] ); // 2
		}

	// Return true if we need more Gnutella2 hub connections
	case PROTOCOL_G2:

		// If we're not connected to Gnutella2, say we have enough hub connections
		if ( Settings.Gnutella2.EnableToday == FALSE ) return FALSE;

		// If we're a leaf, compare our hub count to NumHubs from settings, return true if we don't have enough
		//return ( nConnected[2] ) < ( IsG2Leaf() ? Settings.Gnutella2.NumHubs : Settings.Gnutella2.NumPeers ); // 2 and 6 defaults

		// new setting, use NumHubs for Required Min Hub connection, and NumPeer is only for Max Allowed Hub connection in Hub when
		// in Hub mode.
		if ( bWithMaxPeerSlot )
		{
			return ( m_nCount[PROTOCOL_G2][ntHub] + m_nCount[PROTOCOL_G2][ntNode] < m_nLimit[PROTOCOL_G2][ntNode] ); // 2
		}
		else
		{
			return ( m_nCount[PROTOCOL_G2][ntHub] + m_nCount[PROTOCOL_G2][ntNode] < m_nLimit[PROTOCOL_G2][ntHub] ); // 2
		}

	// The caller specified some other network
	default:

		// Report no, we don't need any more connections for that
		return FALSE;
	}
}

// Takes a protocol name, like PROTOCOL_G1, PROTOCOL_G2, or PROTOCOL_NULL for both
// Counts how many connections to leaves we have for that protocol, and compares that number to settings
// Returns true if we need more leaf connections, false if we have enough
BOOL CNeighboursWithConnect::NeedMoreLeafs(PROTOCOLID nProtocol)
{
	// Only continue if the network is connected (do)
	if ( ! Network.IsConnected() ) return FALSE;

	/* need something like Unlimited mode.
	if ( ! Network.m_bAutoConnect ) return TRUE;
	*/

	// Make an array to count the number of leaf connections we have for each network
	//int nConnected[4] = { 0, 0, 0, 0 }; // Unknown network, Gnutella, Gnutella2, eDonkey2000

	/*
	// Count the number of leaf connections we have
	for ( POSITION pos = GetIterator() ; pos ; ) // Loop for each neighbour in the list
	{
		// Get the neighbour at this position, and move the position forward
		CNeighbour* pNeighbour = GetNext( pos );

		// If we've finished the handshake with this neighbour, and our connection to is down to a leaf
		if ( pNeighbour->m_nState == nrsConnected && pNeighbour->m_nNodeType == ntLeaf )
		{
			// Count it as one more for its protocol
			nConnected[ pNeighbour->m_nProtocol ]++;
		}
	}
	*/

	// Compose the answer for the protocol the caller wants to know about
	switch ( nProtocol )
	{

	// The caller wants to know if we need more leaves for either Gnutella or Gnutella2
	case PROTOCOL_NULL:

		// If we need more Gnutella or Gnutella2 leaves, return true, only return false if we don't need more leaves from either network
		return ( ( ( Settings.Gnutella1.EnableToday ) && ( m_nCount[PROTOCOL_G1][ntLeaf] < m_nLimit[PROTOCOL_G1][ntLeaf] ) ) ||
		         ( ( Settings.Gnutella2.EnableToday ) && ( m_nCount[PROTOCOL_G2][ntLeaf] < m_nLimit[PROTOCOL_G2][ntLeaf] ) ) );

	// Return true if we need more Gnutella ultrapeer connections
	case PROTOCOL_G1:

		// If we're not connected to Gnutella, say we have enough leaf connections
		if ( Settings.Gnutella1.EnableToday == FALSE ) return FALSE;

		// Compare our leaf count to NumLeafs from settings, return true if we don't have enough
		return ( m_nCount[PROTOCOL_G1][ntLeaf] < m_nLimit[PROTOCOL_G1][ntLeaf] ); // Gnutella NumLeafs is 0 by default, we always have enough leaves

	// Return true if we need more Gnutella2 hub connections
	case PROTOCOL_G2:

		// If we're not connected to Gnutella2, say we have enough leaf connections
		if ( Settings.Gnutella2.EnableToday == FALSE ) return FALSE;

		// Compare our leaf count to NumLeafs from settings, return true if we don't have enough
		return ( m_nCount[PROTOCOL_G2][ntLeaf] < m_nLimit[PROTOCOL_G2][ntLeaf] ); // Gnutella2 NumLeafs is 1024 by default

	// The caller specified some other network
	default:

		// Report no, we don't need any more connections for that
		return FALSE;
	}
}

// Takes a protocol name, like PROTOCOL_G1, PROTOCOL_G2, or PROTOCOL_NULL for both
// Determines if we are running at at least 75% of our capacity as a hub on that network
// Returns true if we are that busy, false if we have unused capacity
BOOL CNeighboursWithConnect::IsHubLoaded(PROTOCOLID nProtocol)
{
	/*
	// Make an array to count connections for each network the program connects to
	int nConnected[4] = {
		0,   // No unknown network connections counted yet
		0,   // No Gnutella connections counted yet
		0,   // No Gnutella2 connections counted yet
		0 }; // No eDonkey2000 connections counted yet

	// Count how many leaves are connected to us
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		// Loop for each neighbour in the list
		CNeighbour* pNeighbour = GetNext( pos );

		// If we're done with the handshake for this neighbour, and the connection is down to a leaf
		if ( pNeighbour->m_nState == nrsConnected && pNeighbour->m_nNodeType == ntLeaf )
		{
			// Increment the count for this protocol
			nConnected[ pNeighbour->m_nProtocol ]++;
		}
	}
	*/

	// Return information based on the protocol the caller wants to know about
	switch ( nProtocol )
	{

	// The caller wants to know about Gnutella and Gnutella2 combined
	case PROTOCOL_NULL:

		// If the total connection number is bigger than 75% of the totals from settings, say yes
		return ( m_nCount[PROTOCOL_G1][ntLeaf] + m_nCount[PROTOCOL_G2][ntLeaf] ) >= 
				( m_nLimit[PROTOCOL_G1][ntLeaf] + m_nLimit[PROTOCOL_G2][ntLeaf] ) * 3 / 4;

	// The caller wants to know about Gnutella
	case PROTOCOL_G1:

		// If we're not connected to Gnutella, say no
		if ( Settings.Gnutella1.EnableToday == FALSE ) return FALSE;

		// If we've got more than 75% of the leaf number from settings, say yes
		return m_nCount[PROTOCOL_G1][ntLeaf] > m_nLimit[PROTOCOL_G1][ntLeaf] * 3 / 4;

	// The caller wants to know about Gnutella2
	case PROTOCOL_G2:

		// If we're not connected to Gnutella2, say no
		if ( Settings.Gnutella2.EnableToday == FALSE ) return FALSE;

		// If we've got more than 75% of the leaf number from settings, say yes
		return m_nCount[PROTOCOL_G2][ntLeaf] > m_nLimit[PROTOCOL_G2][ntLeaf] * 3 / 4;

	// The caller wants to know about something else
	default:

		// Just say no, we don't have the capacity for that
		return FALSE;
	}
}

//////////////////////////////////////////////////////////////////////
// CNeighboursWithConnect run event

// Call DoRun on each neighbour in the list, and maintain the network auto connection
void CNeighboursWithConnect::OnRun()
{
	// Call DoRun on each neighbour in the list
	CNeighboursWithRouting::OnRun(); // This method doesn't exist, control goes to CNeighboursBase::OnRun()

	// If this thread can get exclusive access to the network object
	if ( Network.m_pSection.Lock( 50 ) ) // If we're waiting more than 1/20th of a second, give up
	{
		ModeCheck();
		// Maintain the network (do)
		if ( Network.m_bEnabled )
		{
			switch (m_nLastManagedProtocol)
			{
			case PROTOCOL_G1:								// Last one was G1
				if (Network.m_bAutoConnect)
				{
					// Count how many connections, calculate how many we should have, and close and open connections accordingly
					// Makes new connections by getting IP addresses from the host caches for the network
					Maintain(PROTOCOL_ED2K);					// Connect to ED2K server if needed
				}
				// control excess connections.
				NetworkPrune(PROTOCOL_ED2K);				// Disconnect from ED2K server if needed
				m_nLastManagedProtocol = PROTOCOL_ED2K;		// Set ED2K as last checked
				break;
			case PROTOCOL_G2:								// Last one was G2
				if (Network.m_bAutoConnect)
				{
					// Count how many connections, calculate how many we should have, and close and open connections accordingly
					// Makes new connections by getting IP addresses from the host caches for the network
					Maintain(PROTOCOL_G1);						// Connect to G1 Ultrapeers if needed
				}
				else
				{
					// Auto is disabled, so clear LocalCache if there, and set current time as time the network
					// started to Attempting to connect.
					m_tG1AttemptStart = Network.m_nNetworkGlobalTime;
					if ( m_oG1LocalCache.size() ) m_oG1LocalCache.clear();
				}
				// control excess connections.
				NetworkPrune(PROTOCOL_G1);					// Disconnect from G1 nodes if needed
				m_nLastManagedProtocol = PROTOCOL_G1;		// Set G1 as last checked
				break;
			case PROTOCOL_ED2K:								// Last one was ED2K
			default:										// or value was something else.
				if (Network.m_bAutoConnect)
				{
					// Count how many connections, calculate how many we should have, and close and open connections accordingly
					// Makes new connections by getting IP addresses from the host caches for the network
					Maintain(PROTOCOL_G2);						// Connect to G2 Hubs if needed
				}
				else
				{
					// Auto is disabled, so clear LocalCache if there, and set current time as time the network
					// started to Attempting to connect.
					m_tG2AttemptStart = Network.m_nNetworkGlobalTime;
					if ( m_oG2LocalCache.size() ) m_oG2LocalCache.clear();
				}
				// control excess connections.
				NetworkPrune(PROTOCOL_G2);					// Disconnect from G2 nodes if needed
				m_nLastManagedProtocol = PROTOCOL_G2;		// Set G2 as last checked
				break;
			}
		}

		// Release this thread's exclusive access to the network object
		Network.m_pSection.Unlock();
	}
}

//////////////////////////////////////////////////////////////////////
// CNeighboursWithConnect maintain connection

void CNeighboursWithConnect::ModeCheck()
{
	DWORD tNow   = Network.m_nNetworkGlobalTime;			// The time (in seconds)

	if ( m_tModeCheck == 0 || ( tNow - m_tModeCheck ) > 60 )
	{
		if ( !Settings.Gnutella1.EnableToday )
		{
			// No Ultrapeer mode, no Leaf mode.
			m_bG1Leaf      = FALSE;
			m_bG1Ultrapeer = FALSE;

			// Set the limit as no Gnutella hub or leaf connections allowed at all
			m_nLimit[ PROTOCOL_G1 ][ ntHub ] = m_nLimit[ PROTOCOL_G1 ][ ntLeaf ] = m_nLimit[ PROTOCOL_G1 ][ ntNode ] = 0;
		}
		else
		{
			if ( m_nCount[PROTOCOL_G1][ntLeaf] || IsG1Ultrapeer() )
			{
				// We're an ultrapeer on the Gnutella network
				m_bG1Leaf      = FALSE;
				m_bG1Ultrapeer = TRUE;
			}
			else if ( m_nCount[PROTOCOL_G1][ntHub] )
			{
				// We're a leaf on the Gnutella network
				m_bG1Leaf      = TRUE;
				m_bG1Ultrapeer = FALSE;
			}
			else if ( IsG1UltrapeerCapable( FALSE, FALSE ) )
			{
				m_bG1Leaf      = FALSE;
				m_bG1Ultrapeer = TRUE;
			}
			else
			{
				m_bG1Leaf      = TRUE;
				m_bG1Ultrapeer = FALSE;
			}

			if ( m_bG1Ultrapeer )
			{
				// Set the limit for Gnutella ultrapeer connections as whichever number from settings is bigger, peers or hubs
				m_nLimit[ PROTOCOL_G1 ][ ntNode ] = max( Settings.Gnutella1.NumPeers, Settings.Gnutella1.NumHubs ); // Defaults are 0 and 2
				// Set the minimum required Gnutella ultrapeer connections as whichever number from settings is smaller, peers or hubs
				m_nLimit[ PROTOCOL_G1 ][ ntHub ] = min( Settings.Gnutella1.NumPeers, Settings.Gnutella1.NumHubs ); // Defaults are 6 and 2
				// Set the limit for Gnutella leaf connections from settings
				m_nLimit[ PROTOCOL_G1 ][ ntLeaf ] = Settings.Gnutella1.NumLeafs; // 0 by default
			}
			else
			{
				// Set the limit for Gnutella hub connections as whichever is smaller, the number from settings, or 5
				m_nLimit[ PROTOCOL_G1 ][ ntHub ] = m_nLimit[ PROTOCOL_G1 ][ ntNode ] = min( Settings.Gnutella1.NumHubs, 32 ); // NumHubs is 2 by default
			}
		}

		if ( !Settings.Gnutella2.EnableToday )
		{
			m_bG2Leaf	= FALSE;
			m_bG2Hub	= FALSE;
			// Set the limit as no Gnutella2 hub or leaf connections allowed at all
			m_nLimit[ PROTOCOL_G2 ][ ntHub ] = m_nLimit[ PROTOCOL_G2 ][ ntLeaf ] = m_nLimit[ PROTOCOL_G2 ][ ntNode ] = 0;
			m_tHubG2Promotion = 0; // If we're not a hub, time promoted is 0
		}
		else
		{
			if ( m_nCount[PROTOCOL_G2][ntLeaf] ||		// have some Leaf node connected
				( IsG2Hub() &&							// running in G2Hub mode already
				m_nCount[PROTOCOL_G2][ntNode] ) )		// have some peer nodes connected
			{
				// We're a hub on the Gnutella2 network
				m_bG2Leaf	= FALSE;
				m_bG2Hub	= TRUE;
			}
			else if ( m_nCount[PROTOCOL_G2][ntHub] == m_nLimit[PROTOCOL_G2][ntHub] &&	// have enough Hub connections
					IsG2Leaf() )														// running in G2Leaf mode right now
			{
				// We're a leaf on the Gnutella2 network
				m_bG2Leaf	= TRUE;
				m_bG2Hub	= FALSE;
			}
			else if ( tNow - m_tG2AttemptStart < 5 * 60 &&	// has been more than 5minute since connection attempt started
															// same meaning as not having enough Hub/Peer connections for 5minutes
					IsG2HubCapable( FALSE, FALSE ) )			// capable to be G2Hub node
			{
				// We're a hub on the Gnutella2 network
				m_bG2Leaf	= FALSE;
				m_bG2Hub	= TRUE;
			}
			else
			{
				// We're a leaf on the Gnutella2 network
				m_bG2Leaf	= TRUE;
				m_bG2Hub	= FALSE;
			}

			if ( m_bG2Hub )
			{
				// Set our "promoted to hub" timer
				if ( m_tHubG2Promotion == 0 ) m_tHubG2Promotion = tNow; // If we've just been promoted, set the timer
				// Set the limit for Gnutella2 hub connections as whichever number from settings is bigger, peers or hubs
				m_nLimit[ PROTOCOL_G2 ][ ntNode ] = max( Settings.Gnutella2.NumPeers, Settings.Gnutella2.NumHubs ); // Defaults are 6 and 2
				// Set the minimum required Gnutella2 hub connections as whichever number from settings is smaller, peers or hubs
				m_nLimit[ PROTOCOL_G2 ][ ntHub ] = min( Settings.Gnutella2.NumPeers, Settings.Gnutella2.NumHubs ); // Defaults are 6 and 2
				// Set the limit for Gnutella2 leaf connections from settings
				m_nLimit[ PROTOCOL_G2 ][ ntLeaf ] = Settings.Gnutella2.NumLeafs; // 300 by default
			}
			else
			{
				if ( Network.IsFirewalled( CHECK_BOTH ) == TS_TRUE )
				{
					// Set the limit for Gnutella2 hub connections fixed to 3
					// currently this might not for PUSH because of CRouteCache, but in future when X-G2NH or similar become
					// standard, extra number of hub for firewalled node helps for PUSH connection.
					// for search from firewalled nodes, extra hubs can actually distribute Load on Hubs, if and only if the
					// QueryKey's KeyNode(Hub address) is evenly distributed. hopefully this will be optimized in future.
					m_nLimit[ PROTOCOL_G2 ][ ntHub ] = m_nLimit[ PROTOCOL_G2 ][ ntNode ] = 3; // NumHubs is 3
					m_tHubG2Promotion = 0; // If we're not a hub, time promoted is 0
				}
				else
				{
					// Set the limit for Gnutella2 hub connections as whichever is smaller, the number from settings, or 2
					m_nLimit[ PROTOCOL_G2 ][ ntHub ] = m_nLimit[ PROTOCOL_G2 ][ ntNode ] = min( Settings.Gnutella2.NumHubs, 2 ); // NumHubs is 2 by default
					m_tHubG2Promotion = 0; // If we're not a hub, time promoted is 0
				}
			}

			// Check if we have verified if we make a good G2 hub
			if ( ( Settings.Gnutella2.HubVerified == FALSE ) && ( m_tHubG2Promotion > 0 ) && ( Network.m_bEnabled ) )
			{
				// If we have been a hub for at least 8 hours
				if ( ( tNow - m_tHubG2Promotion ) > ( 8 * 60 * 60 ) )
				{
					// And we're loaded ( 75% capacity )
					if ( ( m_nCount[ PROTOCOL_G2 ][ ntLeaf ] ) > ( Settings.Gnutella2.NumLeafs * 3 / 4 ) )
					{
						// Then we probably make a pretty good hub
						Settings.Gnutella2.HubVerified = TRUE;
					}
				}
			}

		}

		m_tModeCheck = tNow;
	}

}


//////////////////////////////////////////////////////////////////////
// CNeighboursWithConnect maintain connection

// As the program runs, CNetwork::OnRun calls this method periodically and repeatedly
// Counts how many connections we have for each network and in each role, and connects to more from the host cache or disconnects from some
void CNeighboursWithConnect::Maintain(PROTOCOLID nProtocol)
{

	// Get the time
	DWORD tTimer = Network.m_nNetworkGlobalTickCount;		// The tick count (milliseconds)
	DWORD tNow   = Network.m_nNetworkGlobalTime;			// The time (in seconds) 

	// Don't initiate neighbour connections too quickly if connections are limited
	if ( ( Settings.Connection.ConnectThrottle != 0 ) && ( tTimer >= Network.m_tLastConnect ) )
	{
		// If we've started a new connection recently, wait a little before starting another
		if ( tTimer - Network.m_tLastConnect < Settings.Connection.ConnectThrottle ) return;
	}


	// If we're connected to a hub of this protocol, store the tick count now in m_tPresent for this protocol
	if ( m_nCount[ nProtocol ][ ntHub ] + m_nCount[ nProtocol ][ntNode] > 0 ) m_tPresent[ nProtocol ] = tNow;

	// If we don't have enough hubs for this protocol
	if ( m_nCount[ nProtocol ][ ntHub ] + m_nCount[ nProtocol ][ntNode] < m_nLimit[ nProtocol ][ ntHub ] )
	{
		// Don't try to connect to G1 right away, wait a few seconds to reduce the number of connections
		if ( ( nProtocol == PROTOCOL_G1 ) && ( Settings.Gnutella2.EnableToday == TRUE ) )
		{
			// Wait 4 seconds before trying G1
			if ( ! Network.ReadyToTransfer( tTimer ) ) return;
		}

		// Get a pointer to the host cache for the given protocol
		CHostCacheList* pCache = HostCache.ForProtocol( nProtocol );

		// We are going to try to connect to a computer running Gnutella or Gnutella2 software
		int nAttempt;
		if ( nProtocol != PROTOCOL_ED2K )
		{
			// For Gnutella and Gnutella2, try connection to the number of free slots multiplied by the connect factor from settings
			nAttempt = m_nLimit[ nProtocol ][ ntHub ] - ( m_nCount[ nProtocol ][ ntHub ] + m_nCount[ nProtocol ][ntNode] );
			nAttempt *=  Settings.Gnutella.ConnectFactor;
		}
		else
		{
			// For ed2k we try one attempt at a time to begin with, but we can step up to 
			// 2 at a time after a few seconds if the FastConnect option is selected. 
			if ( ( Settings.eDonkey.FastConnect ) && ( Network.ReadyToTransfer( tTimer ) ) )
				nAttempt = 2;
			else
				nAttempt = 1;
		}

		// Lower the needed hub number to avoid hitting Windows XP Service Pack 2's half open connection limit
		nAttempt = min(nAttempt, ( Settings.Downloads.MaxConnectingSources - 2 ) );

		// In the loop for eDonkey2000, handle priority eDonkey2000 servers
		if ( nProtocol == PROTOCOL_ED2K )
		{
			CHostCacheHost* pHost = pCache->GetNewest(); // Get the newest host from the eDonkey2000 host cache is network's host cache
			if ( pHost != NULL ) // if there are any cache 
			{
				// Loop into the host cache until we have as many handshaking connections as we need hub connections
				for ( ;pHost && m_nCount[ nProtocol ][ntHub] < nAttempt;  // Loop if we need more eDonkey2000 hubs than we have handshaking connections
					pHost = pHost->m_pPrevTime )                 // At the end of the loop, move to the next youngest host cache entry
				{
					// If we can connect to this host, try it, if it works, move into this if block
					if ( pHost->m_bPriority       && // This host in the host cache is marked as priority (do)
						pHost->CanConnect( tNow ) && // We can connect to this host now (do)
						pHost->ConnectTo( TRUE ) )   // Try to connect to this host now (do), if it works
					{
						// Make sure it's an eDonkey2000 computer we just connected to
						ASSERT( pHost->m_nProtocol == nProtocol );

						// Prevent queries while we connect with this computer (do)
						pHost->m_tQuery = tNow;

						// If settings wants to limit how frequently this method can run
						if ( Settings.Connection.ConnectThrottle != 0 )
						{
							// Save the time we last made a connection as now, and leave
							Network.m_tLastConnect = tTimer;
							Downloads.m_tLastConnect = tTimer;
							return;
						}
					}
				}
				if ( m_nCount[ nProtocol ][ntHub] < nAttempt && !Settings.Discovery.DisableAutoQuery )
					DiscoveryServices.Execute( TRUE, PROTOCOL_ED2K );
			}
			else if ( pCache->GetOldest() == NULL && !Settings.Discovery.DisableAutoQuery )
			{
				DiscoveryServices.Execute( TRUE, PROTOCOL_ED2K );
			}
		}
		else if ( nProtocol == PROTOCOL_G2 )
		{
			CHostCacheHost* pHost = pCache->GetNewest();
			if ( !m_oG2LocalCache.empty() )
			{
				if ( m_nCount[ PROTOCOL_G2 ][ntNull] < nAttempt )
				{
					m_tG2AttemptStart = tNow;
					HostAddrPtr	iHostPtr = m_oG2LocalCache.begin();
					// Make sure the connection we just made matches the protocol we're looping for right now
					if ( ConnectTo( &(iHostPtr->sin_addr), ntohs( iHostPtr->sin_port ), PROTOCOL_G2, TRUE, FALSE, FALSE ) )
					{
						// If settings wants to limit how frequently this method can run
						if ( Settings.Connection.ConnectThrottle != 0 )
						{
							m_oG2LocalCache.erase( iHostPtr );
							// Save the time we last made a connection as now, and leave
							Network.m_tLastConnect = tTimer;
							Downloads.m_tLastConnect = tTimer;
							return;
						}
					}
					m_oG2LocalCache.erase( iHostPtr );
				}
			}
			// If it is within 20Sec from start of this network, and UDP Cache Query has been done.
			else if ( pHost )// Get the newest entry in the host cache for this network
			{
				if ( Network.m_bUDPListeningReady && tNow - m_tG2AttemptStart <= 20 )
				{
					for (; pHost ; pHost = pHost->m_pPrevTime ) // At the end of the loop, move to the next youngest host cache entry
					{
						if ( pHost->UDPCacheQuery() )
						{
							// Make sure the connection we just made matches the protocol we're looping for right now
							ASSERT( pHost->m_nProtocol == nProtocol );

							// If settings wants to limit how frequently this method can run
							if ( Settings.Connection.ConnectThrottle != 0 )
							{
								// Save the time we last made a connection as now, and leave
								Network.m_tLastConnect = tTimer;
								Downloads.m_tLastConnect = tTimer;
							}
							return;
						}
					}
				}
				else
				{
					// If we need more connections for this network, get IP addresses from the host cache and try to connect to them
					for (; pHost && m_nCount[ PROTOCOL_G2 ][ntNull] < nAttempt;  // Loop if we need more hubs that we have handshaking connections
						pHost = pHost->m_pPrevTime )                 // At the end of the loop, move to the next youngest host cache entry
					{
						// if Local Storage of Host for this network is not empty.
						// If we can connect to this IP address from the host cache, try to make the connection
						if ( pHost->CanConnect( tNow ) && pHost->ConnectTo( TRUE ) )
						{
							// Make sure the connection we just made matches the protocol we're looping for right now
							ASSERT( pHost->m_nProtocol == nProtocol );

							// If settings wants to limit how frequently this method can run
							if ( Settings.Connection.ConnectThrottle != 0 )
							{
								// Save the time we last made a connection as now, and leave
								Network.m_tLastConnect = tTimer;
								Downloads.m_tLastConnect = tTimer;
							}
							return;
						}
					}
				}
			}
			if ( m_nCount[ nProtocol ][ntNull] < nAttempt && !Settings.Discovery.DisableAutoQuery )
				DiscoveryServices.Execute( TRUE, PROTOCOL_G2 );
		}
		else if ( nProtocol == PROTOCOL_G1 )
		{
			CHostCacheHost* pHost = pCache->GetNewest();
			if ( !m_oG1LocalCache.empty() )
			{
				if ( m_nCount[ PROTOCOL_G1 ][ntNull] < nAttempt )
				{
					HostAddrPtr	iHostPtr = m_oG1LocalCache.begin();
					// Make sure the connection we just made matches the protocol we're looping for right now
					if ( ConnectTo( &(iHostPtr->sin_addr), ntohs( iHostPtr->sin_port ), PROTOCOL_G1, TRUE, FALSE, FALSE ) )
					{
						m_tG1AttemptStart = tNow;
						// If settings wants to limit how frequently this method can run
						if ( Settings.Connection.ConnectThrottle != 0 )
						{
							m_tG1AttemptStart = tNow;
							m_oG1LocalCache.erase( iHostPtr );
							// Save the time we last made a connection as now, and leave
							Network.m_tLastConnect = tTimer;
							Downloads.m_tLastConnect = tTimer;
							return;
						}
					}
					m_oG1LocalCache.erase( iHostPtr );
				}
			}
			else if ( pHost )// Get the newest entry in the host cache for this network
			{
				// if Local Storage of Host for this network is not empty.
				// If it is within 20Sec from start of this network, and UDP Cache Query has been done.
				if (  Network.m_bUDPListeningReady && tNow - m_tG1AttemptStart <= 20 )
				{
					// If we need more connections for this network, get IP addresses from the host cache and try to connect to them
					for (;	pHost ;	pHost = pHost->m_pPrevTime ) // At the end of the loop, move to the next youngest host cache entry
					{
						if ( pHost->UDPCacheQuery() )
						{
							// Make sure the connection we just made matches the protocol we're looping for right now
							ASSERT( pHost->m_nProtocol == nProtocol );

							// If settings wants to limit how frequently this method can run
							if ( Settings.Connection.ConnectThrottle != 0 )
							{
								// Save the time we last made a connection as now, and leave
								Network.m_tLastConnect = tTimer;
								Downloads.m_tLastConnect = tTimer;
							}
							return;
						}
					}
				}
				// If we can connect to this IP address from the host cache, try to make the connection
				else
				{
					// If we need more connections for this network, get IP addresses from the host cache and try to connect to them
					for (;	pHost && m_nCount[ PROTOCOL_G1 ][ntNull] < nAttempt;
							pHost = pHost->m_pPrevTime ) // At the end of the loop, move to the next youngest host cache entry
					{
						if ( pHost->CanConnect( tNow ) && pHost->ConnectTo( TRUE ) )
						{
							// Make sure the connection we just made matches the protocol we're looping for right now
							ASSERT( pHost->m_nProtocol == nProtocol );

							// If settings wants to limit how frequently this method can run
							if ( Settings.Connection.ConnectThrottle != 0 )
							{
								// Save the time we last made a connection as now, and leave
								Network.m_tLastConnect = tTimer;
								Downloads.m_tLastConnect = tTimer;
							}
							return;
						}
					}
				}
			}
			if ( m_nCount[ nProtocol ][ntNull] < nAttempt && !Settings.Discovery.DisableAutoQuery )
				DiscoveryServices.Execute( TRUE, PROTOCOL_G1 );
		}
/*
		// If network autoconnet is on (do)
		// this condition is very funny since it is not reachable unless m_bAutoConnect is TRUE anyway.
		if ( Network.m_bAutoConnect )
		{
			// If we don't have any handshaking connections for this network, and we've been connected to a hub for more than 30 seconds
			if ( m_nCount[ nProtocol ][ ntNull ] == 0          || // We don't have any handshaking connections for this network, or
				tNow - m_tPresent[ nProtocol ] >= 30 )    // We've not been connected to a hub for more than 30 seconds
			{
				// We're looping for Gnutella2 right now
				if ( nProtocol == PROTOCOL_G2 && Settings.Gnutella2.EnableToday )
				{
					// If the Gnutella host cache is empty and Auto is not Disabled, execute discovery services (do)
					if ( !Settings.Discovery.DisableAutoQuery )
						DiscoveryServices.Execute( TRUE, PROTOCOL_G2 );
				} // We're looping for Gnutella right now
				else if ( nProtocol == PROTOCOL_G1 && Settings.Gnutella1.EnableToday )
				{
					// If the Gnutella host cache is empty and Auto is not Disabled, execute discovery services (do)
					if ( !Settings.Discovery.DisableAutoQuery )
						DiscoveryServices.Execute( TRUE, PROTOCOL_G1 );
				}
			}
		}
*/
	}
	else
	{
		switch ( nProtocol )
		{
		case PROTOCOL_G1:
			m_tG1AttemptStart = tNow;
			if ( m_oG1LocalCache.size() ) m_oG1LocalCache.clear();
			break;
		case PROTOCOL_G2:
			m_tG2AttemptStart = tNow;
			if ( m_oG2LocalCache.size() ) m_oG2LocalCache.clear();
			break;
		case PROTOCOL_ED2K:
			break;
		default:
			break;
		}
	}
}

void CNeighboursWithConnect::NetworkPrune(PROTOCOLID nProtocol)
{
	// If we're over our leaf connection limit for this network
	if ( m_nCount[ nProtocol ][ ntLeaf ] > m_nLimit[ nProtocol ][ ntLeaf ] )
	{
		// Find the leaf we most recently connected to
		CNeighbour* pNewest = NULL;
		switch (nProtocol)
		{
		case PROTOCOL_G1:
			pNewest = static_cast<CNeighbour*>( *m_oG1Leafs.rbegin() );
			break;
		case PROTOCOL_G2:
			pNewest = static_cast<CNeighbour*>( *m_oG2Leafs.rbegin() );
			break;
		case PROTOCOL_ED2K:
			// There should be no LEAF for ED2K. thus the line below should not be here, unless the type added in Future.
			//pNewest = static_cast<CNeighbour*>( *m_oEDServers.rbegin() );
			break;
		default:
			for ( POSITION pos = GetIterator() ; pos ; )
			{
				// Loop through the list of neighbours
				CNeighbour* pNeighbour = GetNext( pos );

				if ( ( pNeighbour->m_nNodeType == ntLeaf ) && ( pNeighbour->m_nProtocol == nProtocol ) )
				{
					// If this is the newest hub, remember it.
					if ( pNewest == NULL || pNeighbour->m_tConnected > pNewest->m_tConnected ) 
						pNewest = pNeighbour;
				}
			}
			break;
		}

		// Disconnect from one leaf
		if ( pNewest != NULL ) pNewest->Close(); // Close the connection
	}
	// We have too many hub connections for this protocol
	else if ( m_nCount[ nProtocol ][ ntHub ] + m_nCount[ nProtocol ][ntNode] > m_nLimit[ nProtocol ][ ntNode ] ) // We're over the limit we just calculated
	{
		// Find the hub we connected to most recently for this protocol
		CNeighbour* pNewest = NULL;
		switch (nProtocol)
		{
		case PROTOCOL_G1:
			if ( IsG1Ultrapeer() )
			{
				if ( m_oG1Ultrapeers.size() ) pNewest = static_cast<CNeighbour*>( *m_oG1Ultrapeers.rbegin() );
				else if ( m_oG1Peers.size() ) pNewest = static_cast<CNeighbour*>( *m_oG1Peers.rbegin() );
			}
			else
			{
				if ( m_oG1Peers.size() ) pNewest = static_cast<CNeighbour*>( *m_oG1Peers.rbegin() );
				else if ( m_oG1Ultrapeers.size() ) pNewest = static_cast<CNeighbour*>( *m_oG1Ultrapeers.rbegin() );
			}
			break;
		case PROTOCOL_G2:
			if ( IsG2Hub() )
			{
				if ( m_oG2Hubs.size() ) pNewest = static_cast<CNeighbour*>( *m_oG2Hubs.rbegin() );
				else if ( m_oG2Peers.size() ) pNewest = static_cast<CNeighbour*>( *m_oG2Peers.rbegin() );
			}
			else
			{
				if ( m_oG2Peers.size() ) pNewest = static_cast<CNeighbour*>( *m_oG2Peers.rbegin() );
				else if ( m_oG2Hubs.size() ) pNewest = static_cast<CNeighbour*>( *m_oG2Hubs.rbegin() );
			}
			break;
		case PROTOCOL_ED2K:
			pNewest = static_cast<CNeighbour*>( *m_oEDServers.rbegin() );
			break;
		default:
			for ( POSITION pos = GetIterator() ; pos ; )
			{
				// Loop through the list of neighbours
				CNeighbour* pNeighbour = GetNext( pos );

				// If this is a hub connection that connected to us recently
				if (
					// If this connection isn't down to a leaf, and
					( pNeighbour->m_nNodeType != ntLeaf ) &&
					// This connection is for the protocol we're looping on right now, and
					( pNeighbour->m_nProtocol == nProtocol ) &&
					// If the neighbour connected to us
					( pNeighbour->m_bAutomatic              || // The neighbour is automatic, or
					!pNeighbour->m_bInitiated             || // The neighbour connected to us, or
					m_nLimit[ nProtocol ][ ntNode ] == 0 ) )    // We're not supposed to be connected to this network at all
				{
					// If this is the newest hub, remember it.
					if ( pNewest == NULL || pNeighbour->m_tConnected > pNewest->m_tConnected ) 
						pNewest = pNeighbour;
				}
			}
			break;
		}

		// Disconnect from one hub
		if ( pNewest != NULL ) pNewest->Close(); // Close the connection
	}
}

int CNeighboursWithConnect::GetCount(PROTOCOLID nProtocol, int nState, int nNodeType) const
{

	if ( nProtocol == PROTOCOL_ED2K && nNodeType == ntHub )
	{
		if ( nState == nrsConnected )
		{
			return m_nCount[PROTOCOL_ED2K][ntHub];
		}
	}
	else if ( nProtocol == PROTOCOL_G1 || nProtocol == PROTOCOL_G2 )
	{
		if ( nState == nrsConnected )
		{
			if ( nNodeType == ntLeaf || nNodeType == ntHub || nNodeType == ntNode )
			{
				return m_nCount[nProtocol][nNodeType];
			}
		}
	}
	if ( nProtocol == PROTOCOL_ANY && nNodeType == -1 )
	{
		if ( nState == nrsConnected )
		{
			return m_nCount[PROTOCOL_ED2K][ntHub] +
					m_nCount[PROTOCOL_G1][ntHub] +
					m_nCount[PROTOCOL_G1][ntLeaf] +
					m_nCount[PROTOCOL_G2][ntHub] +
					m_nCount[PROTOCOL_G2][ntLeaf];
		}
	}
	return CNeighboursWithRouting::GetCount( nProtocol, nState, nNodeType );
}

void CNeighboursWithConnect::Connect()
{
	m_tModeCheck = 0;

	if ( !Settings.Gnutella2.EnableToday )
	{
		m_bG2Leaf	= FALSE;
		m_bG2Hub	= FALSE;
	}
	else if ( Settings.Gnutella2.ClientMode == MODE_HUB )
	{
		m_bG2Leaf	= FALSE;
		m_bG2Hub	= TRUE;
		m_tG2Start	= static_cast<DWORD>( time(NULL) );
		m_tG2AttemptStart = m_tG2Start;
	}
	else
	{
		m_bG2Leaf	= TRUE;
		m_bG2Hub	= FALSE;
		m_tG2Start	= static_cast<DWORD>( time(NULL) );
		m_tG2AttemptStart = m_tG2Start;
	}

	if ( !Settings.Gnutella1.EnableToday )
	{
		m_bG1Leaf		= FALSE;
		m_bG1Ultrapeer	= FALSE;
	}
	else if ( Settings.Gnutella1.ClientMode == MODE_HUB )
	{
		m_bG1Leaf		= FALSE;
		m_bG1Ultrapeer	= TRUE;
		m_tG1Start		= static_cast<DWORD>( time(NULL) );
		m_tG1AttemptStart = m_tG1Start;
	}
	else
	{
		m_bG1Leaf		= TRUE;
		m_bG1Ultrapeer	= FALSE;
		m_tG1Start		= static_cast<DWORD>( time(NULL) );
		m_tG1AttemptStart = m_tG1Start;
	}


	CNeighboursWithRouting::Connect();
	Network.BeginTestG2UDPFW();
}

void CNeighboursWithConnect::Close()
{
	Network.EndTestG2UDPFW(TS_TRUE);
	m_tModeCheck	= 0;		// Reset status
	m_bG2Leaf		= FALSE;
	m_bG2Hub		= FALSE;
	m_bG1Leaf		= FALSE;
	m_bG1Ultrapeer	= FALSE;
	m_tG2Start		= 0;
	m_tG1Start		= 0;

	CNeighboursWithRouting::Close();
}

void CNeighboursWithConnect::ConnectG2()
{
	Settings.Gnutella2.EnableToday = TRUE;
	m_tG2Start	= static_cast<DWORD>( time(NULL) );
	m_tG2AttemptStart = m_tG2Start;
	if ( Settings.Gnutella2.ClientMode == MODE_HUB && Network.IsFirewalled(CHECK_BOTH) == TS_FALSE )
	{
		// We're a hub on the Gnutella2 network
		m_bG2Leaf	= FALSE;
		m_bG2Hub	= TRUE;
		// Set our "promoted to hub" timer
		if ( m_tHubG2Promotion == 0 ) m_tHubG2Promotion = Network.m_nNetworkGlobalTime; // If we've just been promoted, set the timer
		// Set the limit for Gnutella2 hub connections as whichever number from settings is bigger, peers or hubs
		m_nLimit[ PROTOCOL_G2 ][ ntNode ] = max( Settings.Gnutella2.NumPeers, Settings.Gnutella2.NumHubs ); // Defaults are 6 and 2
		// Set the minimum required Gnutella2 hub connections as whichever number from settings is smaller, peers or hubs
		m_nLimit[ PROTOCOL_G2 ][ ntHub ] = min( Settings.Gnutella2.NumPeers, Settings.Gnutella2.NumHubs ); // Defaults are 6 and 2
		// Set the limit for Gnutella2 leaf connections from settings
		m_nLimit[ PROTOCOL_G2 ][ ntLeaf ] = Settings.Gnutella2.NumLeafs; // 300 by default
	}
	else
	{
		// We're a leaf on the Gnutella2 network
		m_bG2Leaf	= TRUE;
		m_bG2Hub	= FALSE;
		// Set the limit for Gnutella2 hub connections as whichever is smaller, the number from settings, or 2
		m_nLimit[ PROTOCOL_G2 ][ ntHub ] = m_nLimit[ PROTOCOL_G2 ][ ntNode ] = min( Settings.Gnutella2.NumHubs, 2 ); // NumHubs is 2 by default
		m_tHubG2Promotion = 0; // If we're not a hub, time promoted is 0
	}


	CNeighboursWithRouting::ConnectG2();
	Network.BeginTestG2UDPFW();
}

void CNeighboursWithConnect::DisconnectG2()
{
	Network.EndTestG2UDPFW(TS_TRUE);
	m_bG2Leaf	= FALSE;
	m_bG2Hub	= FALSE;
	// Set the limit as no Gnutella2 hub or leaf connections allowed at all
	m_nLimit[ PROTOCOL_G2 ][ ntHub ] = m_nLimit[ PROTOCOL_G2 ][ ntLeaf ] = m_nLimit[ PROTOCOL_G2 ][ ntNode ] = 0;
	m_tHubG2Promotion = 0; // If we're not a hub, time promoted is 0

	CNeighboursWithRouting::DisconnectG2();
	m_tG2Start	= 0;
	m_tG2AttemptStart = m_tG2Start;
	Settings.Gnutella2.EnableToday = FALSE;
}

void CNeighboursWithConnect::ConnectG1()
{
	Settings.Gnutella1.EnableToday = TRUE;
	m_tG1Start	= static_cast<DWORD>( time(NULL) );
	m_tG1AttemptStart = m_tG1Start;
	if ( Settings.Gnutella1.ClientMode == MODE_HUB && Network.IsFirewalled(CHECK_TCP) == TS_FALSE )
	{
		// We're a Ultrapeer on the Gnutella1 network
		m_bG1Leaf		= FALSE;
		m_bG1Ultrapeer	= TRUE;
		// Set the limit for Gnutella1 Ultrapeer connections as whichever number from settings is bigger, peers or Ultrapeer
		m_nLimit[ PROTOCOL_G1 ][ ntNode ] = max( Settings.Gnutella1.NumPeers, Settings.Gnutella1.NumHubs ); // Defaults are 6 and 2
		// Set the minimum required Gnutella1 Ultrapeer connections as whichever number from settings is smaller, peers or Ultrapeer
		m_nLimit[ PROTOCOL_G1 ][ ntHub ] = min( Settings.Gnutella1.NumPeers, Settings.Gnutella1.NumHubs ); // Defaults are 6 and 2
		// Set the limit for Gnutella1 leaf connections from settings
		m_nLimit[ PROTOCOL_G1 ][ ntLeaf ] = Settings.Gnutella1.NumLeafs; // 300 by default
	}
	else
	{
		// We're a leaf on the Gnutella1 network
		m_bG1Leaf		= TRUE;
		m_bG1Ultrapeer	= FALSE;
		// Set the limit for Gnutella1 Ultrapeer connections as whichever is smaller, the number from settings, or 2
		m_nLimit[ PROTOCOL_G1 ][ ntHub ] = m_nLimit[ PROTOCOL_G1 ][ ntNode ] = min( Settings.Gnutella1.NumHubs, 5 ); // NumHubs is 2 by default
	}

	CNeighboursWithRouting::ConnectG1();
}

void CNeighboursWithConnect::DisconnectG1()
{
	m_bG1Leaf		= FALSE;
	m_bG1Ultrapeer	= FALSE;
	// Set the limit as no Gnutella1 Ultrapeer or leaf connections allowed at all
	m_nLimit[ PROTOCOL_G1 ][ ntHub ] = m_nLimit[ PROTOCOL_G1 ][ ntLeaf ] = m_nLimit[ PROTOCOL_G1 ][ ntNode ] = 0;

	CNeighboursWithRouting::DisconnectG1();
	m_tG1Start	= 0;
	m_tG1AttemptStart = m_tG1Start;
	Settings.Gnutella1.EnableToday = FALSE;
}

void CNeighboursWithConnect::ConnectED2K()
{
	Settings.eDonkey.EnableToday = TRUE;

	m_nLimit[ PROTOCOL_ED2K ][ ntLeaf ] = 0;
	m_nLimit[ PROTOCOL_ED2K ][ ntHub ] = m_nLimit[ PROTOCOL_ED2K ][ ntNode ] = min( 1u, Settings.eDonkey.NumServers ); // NumServers is 1 by default

	CNeighboursWithRouting::ConnectED2K();
}

void CNeighboursWithConnect::DisconnectED2K()
{
	m_nLimit[ PROTOCOL_ED2K ][ ntHub ] = m_nLimit[ PROTOCOL_ED2K ][ ntLeaf ] = m_nLimit[ PROTOCOL_ED2K ][ ntNode ] = 0;

	CNeighboursWithRouting::DisconnectED2K();
	Settings.eDonkey.EnableToday = FALSE;
}

void CNeighboursWithConnect::StoreCache(PROTOCOLID nProtocol, SOCKADDR_IN& pHost)
{
	if ( nProtocol == PROTOCOL_G1 )
	{
		m_oG1LocalCache.push_back( pHost );
	}
	else if ( nProtocol == PROTOCOL_G2 )
	{
		m_oG2LocalCache.push_back( pHost );
	}
}
