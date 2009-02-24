//
// G2Neighbour.h
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

#if !defined(AFX_G2NEIGHBOUR_H__F3C423B0_60F0_4721_81A3_1109E59CD425__INCLUDED_)
#define AFX_G2NEIGHBOUR_H__F3C423B0_60F0_4721_81A3_1109E59CD425__INCLUDED_

#pragma once

#include "Neighbour.h"
#include "NeighboursWithG2.h"

class CG2Packet;
class CHubHorizonGroup;


class CG2Neighbour : public CNeighbour
{
// Construction
public:
	CG2Neighbour();
	CG2Neighbour(CNeighbour* pBase);
	virtual ~CG2Neighbour();

	virtual BOOL	ConnectTo(IN_ADDR* pAddress, WORD nPort, BOOL bAutomatic, BOOL bUDP);
	virtual BOOL	Send(CPacket* pPacket, BOOL bRelease = TRUE, BOOL bBuffered = FALSE);
	virtual BOOL	SendQuery(CQuerySearch* pSearch, CPacket* pPacket, BOOL bLocal);
	virtual void	Close(UINT nError = IDS_CONNECTION_CLOSED);
	virtual void	DelayClose(UINT nError = 0); // Send the buffer then close the socket, record the error given

	BOOL			OnPing(CG2Packet* pPacket, BOOL bTCP = TRUE);
	BOOL			OnPong(CG2Packet* pPacket, BOOL bTCP = TRUE);
	BOOL			OnPacket(CG2Packet* pPacket, SOCKADDR_IN* pHost);
	void			SendLNI();
	BOOL			OnLNI(CG2Packet* pPacket);
	void			SendKHL();
	BOOL			OnKHL(CG2Packet* pPacket);
	void			SendHAW();
	BOOL			OnHAW(CG2Packet* pPacket);
	BOOL			OnQuery(CG2Packet* pPacket);
	BOOL			OnQueryAck(CG2Packet* pPacket);
	BOOL			OnQueryKeyReq(CG2Packet* pPacket);
	BOOL			OnQueryKeyAns(CG2Packet* pPacket);
	BOOL			OnPush(CG2Packet* pPacket);
	BOOL			OnProfileChallenge(CG2Packet* pPacket);
	BOOL			OnProfileDelivery(CG2Packet* pPacket);
	BOOL			OnModeChangeReq(CG2Packet* pPacket); //add
	BOOL			OnModeChangeAck(CG2Packet* pPacket); //add
	BOOL			OnPrivateMessage(CG2Packet* pPacket); //add
	BOOL			OnClose(CG2Packet* pPacket); //add

	BOOL			SendUDPConnect(DWORD tNow);
	BOOL			OnConnect(SOCKADDR_IN* pHost, CG2Packet* pPacket); //add
	BOOL			OnConnectAck(SOCKADDR_IN* pHost, CG2Packet* pPacket); //add

public:
	DWORD				m_nLeafCount;
	DWORD				m_nLeafLimit;
	BOOL				m_bCachedKeys;
	CRouteCache*		m_pGUIDCache;
	CHubHorizonGroup*	m_pHubGroup;

protected:
	DWORD				m_tLastRun;
	LONG				m_tAdjust;				// Time adjust of neighbour
	DWORD				m_tLastPingIn;			// Time when /PI packet recievied
	DWORD				m_tLastPingOut;			// Time when /PI packet sent
	DWORD				m_nCountPingIn;			// Number of /PI packets recievied
	DWORD				m_nCountPingOut;		// Number of /PI packets sent
	DWORD				m_tLastRelayPingIn;		// Time when /PI/UDP packet recievied
	DWORD				m_tLastRelayPingOut;	// Time when /PI/UDP packet sent
	DWORD				m_nCountRelayPingIn;	// Number of /PI/UDP packets recievied
	DWORD				m_nCountRelayPingOut;	// Number of /PI/UDP packets sent
	DWORD				m_tLastRelayedPingIn;	// Time when /PI/RELAY/UDP packet recievied
	DWORD				m_tLastRelayedPingOut;	// Time when /PI/RELAY/UDP packet sent
	DWORD				m_nCountRelayedPingIn;	// Number of /PI/RELAY/UDP packets recievied
	DWORD				m_nCountRelayedPingOut;	// Number of /PI/RELAY/UDP packets sent
	DWORD				m_tLastKHLIn;			// Time when KHL packet recievied
	DWORD				m_tLastKHLOut;			// Time when KHL packet sent
	DWORD				m_nCountKHLIn;			// Number of KHL packets recievied
	DWORD				m_nCountKHLOut;			// Number of KHL packets sent
	DWORD				m_tLastLNIIn;			// Time when LNI packet recievied
	DWORD				m_tLastLNIOut;			// Time when LNI packet sent
	DWORD				m_nCountLNIIn;			// Number of LNI packets recievied
	DWORD				m_nCountLNIOut;			// Number of LNI packets sent
	DWORD				m_tLastHAWIn;			// Time when HAW packet recievied
	DWORD				m_tLastHAWOut;			// Time when HAW packet sent
	DWORD				m_nCountHAWIn;			// Number of HAW packets recievied
	DWORD				m_nCountHAWOut;			// Number of HAW packets sent
	CList< CG2Packet* >	m_pOutbound;			// Queue of outbound packets
	int					m_nQueryLimiter;		// Counter for query limiting
	DWORD				m_tQueryTimer;			// Timer for query limiting
	BOOL				m_bBlacklisted;			// Has this client been over-querying.
	BOOL				m_bFWCheckSent;			// TestFireWall(TFW) has been sent.
	BOOL				m_bSFLCheck;			// SupportedFeatureList(SFL) has been Sent
	BOOL				m_bHubAble; //add G2/1.1
	BOOL				m_bFirewall; //add G2/1.1
	BOOL				m_bRouter; //add G2/1.1
	DWORD				m_nCPU; //add G2/1.1
	DWORD				m_nMEM; //add G2/1.1
	DWORD				m_nBandwidthIn; //add G2/1.1
	DWORD				m_nBandwidthOut; //add G2/1.1
	DWORD				m_nUptime; //add G2/1.1
	float				m_nLatitude; //add G2/1.1
	float				m_nLongitude; //add G2/1.1

protected:
	virtual BOOL	OnRead();
	virtual BOOL	OnWrite();
	virtual BOOL	OnRun();

	void			SendStartups();
	BOOL			ProcessPackets();

	// this might be needed.
	friend class CNeighboursWithG2;
};

#endif // !defined(AFX_G2NEIGHBOUR_H__F3C423B0_60F0_4721_81A3_1109E59CD425__INCLUDED_)