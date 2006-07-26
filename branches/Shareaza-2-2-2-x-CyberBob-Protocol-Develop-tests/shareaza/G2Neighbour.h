//
// G2Neighbour.h
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

#if !defined(AFX_G2NEIGHBOUR_H__F3C423B0_60F0_4721_81A3_1109E59CD425__INCLUDED_)
#define AFX_G2NEIGHBOUR_H__F3C423B0_60F0_4721_81A3_1109E59CD425__INCLUDED_

#pragma once

#include "Neighbour.h"

class CG2Packet;
class CHubHorizonGroup;


class CG2Neighbour : public CNeighbour
{
// Construction
public:
	CG2Neighbour(CNeighbour* pBase);
	virtual ~CG2Neighbour();

// Attributes
public:
	DWORD				m_nLeafCount;
	DWORD				m_nLeafLimit;
	BOOL				m_bCachedKeys;
	CRouteCache*		m_pGUIDCache;
	CHubHorizonGroup*	m_pHubGroup;
	LONG				m_nPingsSent;
	DWORD				m_tRTT;
	BOOL				m_bBusy;
	DWORD				m_tLastPongIn;
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
	LONG				m_tAdjust;
	DWORD				m_tLastPingIn;
	DWORD				m_tLastPingOut;
	DWORD				m_tWaitLNI;
	DWORD				m_tLastKHL;
	DWORD				m_tLastHAW;
	DWORD				m_tBusyTime;
protected:
	CList< CG2Packet* >	m_pOutbound;

protected:
	int					m_nQueryLimiter;				// Counter for query limiting
	DWORD				m_tQueryTimer;					// Timer for query limiting
	BOOL				m_bBlacklisted;					// Has this client been over-querying.
	BOOL				m_bSFLCheckFW;					// Supported Feature List contained FireWallCheck (TFW).
	BOOL				m_bFWCheckSent;					// FireWall check (TFW) has been sent.

// Operations
public:
	virtual BOOL	Send(CPacket* pPacket, BOOL bRelease = TRUE, BOOL bBuffered = FALSE);
	virtual BOOL	SendQuery(CQuerySearch* pSearch, CPacket* pPacket, BOOL bLocal);
	virtual void	Close(UINT nError = IDS_CONNECTION_CLOSED);
	virtual void	DelayClose(UINT nError = 0); // Send the buffer then close the socket, record the error given
protected:
	virtual BOOL	OnRead();
	virtual BOOL	OnWrite();
	virtual BOOL	OnRun();
protected:
	void	SendStartups();
	BOOL	ProcessPackets();
	BOOL	OnPacket(CG2Packet* pPacket);
	BOOL	OnPing(CG2Packet* pPacket);
	BOOL	OnPong(CG2Packet* pPacket);
	void	SendLNI();
	BOOL	OnLNI(CG2Packet* pPacket);
	void	SendKHL();
	BOOL	OnKHL(CG2Packet* pPacket);
	void	SendHAW();
	BOOL	OnHAW(CG2Packet* pPacket);
	BOOL	OnQuery(CG2Packet* pPacket);
	BOOL	OnQueryAck(CG2Packet* pPacket);
	BOOL	OnQueryKeyReq(CG2Packet* pPacket);
	BOOL	OnQueryKeyAns(CG2Packet* pPacket);
	BOOL	OnPush(CG2Packet* pPacket);
	BOOL	OnProfileChallenge(CG2Packet* pPacket);
	BOOL	OnProfileDelivery(CG2Packet* pPacket);
	BOOL	OnModeChangeReq(CG2Packet* pPacket); //add
	BOOL	OnModeChangeAck(CG2Packet* pPacket); //add
	BOOL	OnPrivateMessage(CG2Packet* pPacket); //add
	BOOL	OnClose(CG2Packet* pPacket); //add

};

#endif // !defined(AFX_G2NEIGHBOUR_H__F3C423B0_60F0_4721_81A3_1109E59CD425__INCLUDED_)
