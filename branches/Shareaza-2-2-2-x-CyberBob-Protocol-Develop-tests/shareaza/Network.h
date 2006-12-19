//
// Network.h
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

#if !defined(AFX_NETWORK_H__544414B1_3698_4C92_B0B0_1DC56AB48074__INCLUDED_)
#define AFX_NETWORK_H__544414B1_3698_4C92_B0B0_1DC56AB48074__INCLUDED_

#pragma once
#include "ITMQueue.h"

class CNeighbour;
class CBuffer;
class CPacket;
class CG2Packet;
class CRouteCache;
class CQueryKeys;
class CQuerySearch;
class CQueryHit;
class CDownloadSource;

class CNetwork
{
// typedef
public:
	typedef std::list<SOCKADDR_IN> HubList;
	typedef std::list<SOCKADDR_IN>::iterator HubIndex;

// Construction
public:
	CNetwork();
	virtual ~CNetwork();

// Attributes
public:
	CRouteCache*	NodeRoute;
	CRouteCache*	QueryRoute;
	CQueryKeys*		QueryKeys;
public:
	CMutex			m_pSection;
	CEvent			m_pWakeup;
	SOCKADDR_IN		m_pHost;				// Structure (Windows Sockets) which holds address of the local machine
	SOCKADDR_IN		m_pOutBind;				// Structure (Windows Sockets) which holds OutBind address.
	BOOL			m_bEnabled;				// If the network "enabled" (Connected or trying)
	BOOL			m_bAutoConnect;
	DWORD			m_tStartedConnecting;	// The time Shareaza started trying to connect
	DWORD			m_tLastConnect;			// The last time a neighbour connection attempt was made
	DWORD			m_tLastED2KServerHop;	// The last time the ed2k server was changed
protected:
	HANDLE			m_hThread;
	DWORD			m_nSequence;
	DWORD			m_tLastFirewallTest;
	DWORD			m_tStartTestingUDPFW;
	CList<sockaddr_in> m_FWTestQueue;

	struct ResolveStruct
	{
		CString* m_sAddress;
		PROTOCOLID m_nProtocol;
		WORD m_nPort;
		BYTE m_nCommand;
		union
		{
			char m_pBuffer[ MAXGETHOSTSTRUCT ];
			HOSTENT m_pHost;
		};
	};
	CMap< HANDLE, HANDLE, ResolveStruct*, ResolveStruct* > m_pLookups;
public:
	CITMQueue		m_pMessageQueue;
	DWORD			m_nNetworkGlobalTime;
	DWORD			m_nNetworkGlobalTickCount;

public:
	class CITMSendPush : CITMQueue::CITMItem
	{
	// typedef
	public:
		typedef std::list<SOCKADDR_IN> HubList;
		typedef std::list<SOCKADDR_IN>::iterator HubIndex;

	// Constructor
	public:
		CITMSendPush();
		~CITMSendPush();

	// Data Members
	public:
		PROTOCOLID		m_nProtocol;
		IN_ADDR			m_pAddress;
		WORD			m_nPort;
		Hashes::Guid	m_oGUID;
		DWORD			m_nIndex;
		HubList			m_oPushProxies;
		HubList			m_oG2Hubs;

	// function members
	public:
		static CITMSendPush* CreateMessage( PROTOCOLID nProtocol, const Hashes::Guid& oGUID, const DWORD nIndex, IN_ADDR pAddress,
											WORD nPort, const HubList& oPushProxies = HubList(), const HubList& oG2Hubs = HubList() );
		virtual BOOL OnProcess();

	};

// Operations
public:
	BOOL		IsAvailable() const;
	BOOL		IsConnected() const;
	BOOL		IsListening() const;
	int			IsWellConnected() const;
	BOOL		IsStable() const;
	DWORD		GetStableTime() const;
	BOOL		IsConnectedTo(IN_ADDR* pAddress);
	BOOL		ReadyToTransfer(DWORD tNow) const;		// Are we ready to start downloading?
	BOOL		IsFirewalled();
	BOOL		IsTestingUDPFW();
	void		BeginTestG2UDPFW();
	void		EndTestG2UDPFW(TRISTATE bFirewalled = TS_UNKNOWN);

public:
	BOOL		Connect(BOOL bAutoConnect = FALSE);
	void		Disconnect();
	BOOL		ConnectTo(LPCTSTR pszAddress, int nPort = 0, PROTOCOLID nProtocol = PROTOCOL_NULL, BOOL bNoUltraPeer = FALSE);
	void		AcquireLocalAddress(LPCTSTR pszHeader);
	BOOL		Resolve(LPCTSTR pszHost, int nPort, SOCKADDR_IN* pHost, BOOL bNames = TRUE) const;
	BOOL		AsyncResolve(LPCTSTR pszAddress, WORD nPort, PROTOCOLID nProtocol, BYTE nCommand);
	BOOL		IsReserved(IN_ADDR* pAddress, bool bCheckLocal=true);
	WORD		RandomPort() const;
	void		CreateID(Hashes::Guid& oID);
	BOOL		IsFirewalledAddress(LPVOID pAddress, BOOL bIncludeSelf = FALSE, BOOL bForceCheck = FALSE );
	void		TestRemoteFirewall(DWORD nAddress, WORD nPort);
public:
	BOOL		GetNodeRoute(const Hashes::Guid& oGUID, CNeighbour** ppNeighbour, SOCKADDR_IN* pEndpoint);
	BOOL		RoutePacket(CG2Packet* pPacket);
	BOOL		SendPush(const Hashes::Guid& oGUID, DWORD nIndex, PROTOCOLID nProtocol = PROTOCOL_HTTP, IN_ADDR pAddress = IN_ADDR(),
						WORD nPort = 0,	HubList& oPushProxyList = HubList(), HubList& oHubList = HubList());
	//BOOL		SendPush(const Hashes::Guid& oGUID, DWORD nIndex = 0);
	BOOL		SendPush( CDownloadSource * pSource );
	BOOL		RouteHits(CQueryHit* pHits, CPacket* pPacket);
	void		OnWinsock(WPARAM wParam, LPARAM lParam);
	void		OnQuerySearch(CQuerySearch* pSearch, BOOL bOUT = FALSE );
	void		OnQueryHits(CQueryHit* pHits);
protected:
	static UINT	ThreadStart(LPVOID pParam);
	void		OnRun();
	BOOL		CanTestFirewall();
public:
	void		UDPHostCache(IN_ADDR* pAddress, WORD nPort);
	void		UDPKnownHubCache(IN_ADDR* pAddress, WORD nPort);

	friend class CHandshakes;
	friend class CNeighbours;
	friend class CNeighboursWithED2K;
};

extern CNetwork Network;


#endif // !defined(AFX_NETWORK_H__544414B1_3698_4C92_B0B0_1DC56AB48074__INCLUDED_)
