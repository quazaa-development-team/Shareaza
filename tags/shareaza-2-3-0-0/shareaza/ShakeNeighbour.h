//
// ShakeNeighbour.h
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

// CShakeNeighbour reads and sends handshake headers to negotiate the Gnutella or Gnutella2 handshake
// http://wiki.shareaza.com/static/Developers.Code.CShakeNeighbour

// Make the compiler only include the lines here once, this is the same thing as pragma once
#if !defined(AFX_SHAKENEIGHBOUR_H__259E22A0_EFA9_4684_B642_B98CE4CE682F__INCLUDED_)
#define AFX_SHAKENEIGHBOUR_H__259E22A0_EFA9_4684_B642_B98CE4CE682F__INCLUDED_

// Only include the lines beneath this one once
#pragma once

// Copy in the contents of these files here before compiling
#include "Neighbour.h"

// Define the class CShakeNeighbour to inherit from CNeighbour, which inherits from CConnection, picking up a socket
class CShakeNeighbour : public CNeighbour
{

public:

	// Make a new CShakeNeighbour object, and delete this one
	CShakeNeighbour();          // Make a new blank CShakeNeighbour object
	virtual ~CShakeNeighbour(); // Delete this CShakeNeighbour object, virtual means we expect a derived class to redefine this

protected:

	// Shareaza Settings allow us to send and receive compressed data
	BOOL		m_bCanDeflate;

	// Set to true when we have sent the following handshake header
	BOOL        m_bSentAddress;     // We told the remote computer our Internet IP address that we are listening on
									// We sent it a header like this
									//
									//    Listen-IP: 1.2.3.4:5
									//

	// Set to true when we have received the following handshake headers
	BOOL        m_bG1Send;          // The remote computer is going to send us Gnutella1 packets
									// It Did not send any "Content-Type: " or sent us a header like one of these
									//
									//    Content-Type: application/x-gnutella-packets
									//    
									//
	BOOL        m_bG1Accept;        // The remote computer accepts Gnutella1 packets
									// It Did not send any "Accept: " or sent us a header like one of these
									//
									//    Accept: application/x-gnutella-packets
									//
									//
	BOOL        m_bG2Send;          // The remote computer is going to send us Gnutella2 packets
									// It sent us a header like one of these
									//
									//    Content-Type: application/x-gnutella2
									//    Content-Type: application/x-shareaza
									//
	BOOL        m_bG2Accept;        // The remote computer accepts Gnutella2 packets
									// It sent us a header like one of these
									//
									//    Accept: application/x-gnutella2
									//    Accept: application/x-shareaza
									//
	BOOL        m_bDeflateSend;     // All the data from the remote computer is going to be compressed
									// It sent us a header like this
									//
									//    Content-Encoding: deflate
									//
	BOOL        m_bDeflateAccept;   // The remote computer accepts compressed data
									// It sent us a header like this
									//
									//    Accept-Encoding: deflate
									//
	TRISTATE    m_bUltraPeerSet;    // The remote computer is an ultrapeer or hub, true, a leaf, false, or hasn't told us yet, unknown
									// True if it sent us a header like this
									//
									//    X-Ultrapeer: True
									//    X-Hub: True
									//
									// False if it sent us a header like this
									//
									//    X-Ultrapeer: False
									//    X-Hub: False
									//
									// Unknown if it hasn't sent us any headers like that yet
	TRISTATE    m_bUltraPeerNeeded; // True if the remote computer has told us it needs more connections to ultrapeers or hubs
									// True if it sent us a header like this
									//
									//    X-Ultrapeer-Needed: True
									//    X-Hub-Needed: True
									//
									// False if it sent us a header like this
									//
									//    X-Ultrapeer-Needed: False
									//    X-Hub-Needed: False
									//
									// Unknown if it hasn't sent us any headers like that yet

	// Possibly not in use (do)
	TRISTATE m_bUltraPeerLoaded;
	BOOL	m_bDelayClose;			// This is DelayClose
	UINT	m_nDelayCloseReason;	// Reason for DelayClose;
	CString	m_sTryUltrapeers;		// Storage of X-Try-Ultrapeers Header
	CString	m_sTryHubs;				// Storage of X-Try-Hubs Header
	CString	m_sTryDNAHubs;			// Storage of X-Try-DNA-Hubs Header

public:

	// Connect, disconnect, and copy
	virtual BOOL ConnectTo(IN_ADDR* pAddress, WORD nPort, BOOL bAutomatic = FALSE, BOOL bNoUltraPeer = FALSE); // Connect to an ip address and port number
	virtual void AttachTo(CConnection* pConnection); // Copy the values from the given CConnection object into the CConnection core of this one
	virtual void Close(UINT nError = IDS_CONNECTION_CLOSED ); // Close the socket and log the reason the connection didn't work
	virtual void DelayClose(UINT nError = IDS_CONNECTION_CLOSED ); // Close the socket and log the reason the connection didn't work

protected:

	// Read headers and respond to them
	virtual BOOL OnConnected();          // Send the remote computer our first big block of Gnutella headers
	virtual BOOL OnRead();               // Read data from the remote computer, and look at it as a handshake
	virtual void OnDropped(BOOL bError); // Document that the connection was lost and why, and put everything away
	virtual BOOL OnRun();                // Make sure the handshake hasn't been taking too long
	virtual BOOL OnHeaderLine(CString& strHeader, CString& strValue); // Reads a header line and sets a corresponding member variable to true
	virtual BOOL OnHeadersComplete();    // Responds to a group of headers by closing, sending a response, or turning this object into a more specific one
	virtual BOOL OnHeadersCompleteG1();
	virtual BOOL OnHeadersCompleteG2();

	// Send headers to the remote computer
	void SendMinimalHeaders();									// Tell the remote computer we are Shareaza, and try to setup Gnutella2 communications
	void SendPublicHeaders();									// Send our first big group of Gnutella headers to the remote computer
	void SendPrivateHeaders();									// Reply to a remote computer's headers, confirming Gnutella2 packets and data compression
	void SendHostHeaders(LPCTSTR pszMessage = NULL, size_t nLength = 0); // Send a 503 error message, and the "X-Try-Ultrapeers:" header
	BOOL ReadResponse();										// Read the first line of a new group of headers from the remote computer
	void OnHandshakeComplete();									// Turn this object into one specialized for Gnutella or Gnutella2

	BOOL IsClientObsolete();									// Checks the user agent to see if it's an old client.
	BOOL IsClientBad();											// Checks to see if it's a GPL violator or glitchy client.
	BOOL IsClientBanned();										// Checks to see if it's a leecher. (Clients are blocked)
};

// End the group of lines to only include once, pragma once doesn't require an endif at the bottom
#endif // !defined(AFX_SHAKENEIGHBOUR_H__259E22A0_EFA9_4684_B642_B98CE4CE682F__INCLUDED_)