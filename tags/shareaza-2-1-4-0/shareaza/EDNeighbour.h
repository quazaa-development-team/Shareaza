//
// EDNeighbour.h
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

#if !defined(AFX_EDNEIGHBOUR_H__7E77CD2A_D3AA_4E53_981B_3B4624968921__INCLUDED_)
#define AFX_EDNEIGHBOUR_H__7E77CD2A_D3AA_4E53_981B_3B4624968921__INCLUDED_

#pragma once

#include "Neighbour.h"

class CEDPacket;
class CDownload;


class CEDNeighbour : public CNeighbour
{
// Construction
public:
	CEDNeighbour();
	virtual ~CEDNeighbour();

// Attributes
public:
	DWORD		m_nClientID;
	DWORD		m_nUserCount;
	DWORD		m_nUserLimit;
	DWORD		m_nFileLimit;
	DWORD		m_nTCPFlags;
	DWORD		m_nUDPFlags;
	CString		m_sServerName;

	CPtrList	m_pQueries;
	DWORD		m_nFilesSent;

// Operations
public:
	virtual BOOL	ConnectTo(IN_ADDR* pAddress, WORD nPort, BOOL bAutomatic);
	virtual BOOL	Send(CPacket* pPacket, BOOL bRelease = TRUE, BOOL bBuffered = FALSE);
	virtual BOOL	SendQuery(CQuerySearch* pSearch, CPacket* pPacket, BOOL bLocal);
protected:
	virtual BOOL	OnRun();
	virtual BOOL	OnConnected();
	virtual void	OnDropped(BOOL bError);
	virtual BOOL	OnRead();
public:
	BOOL	SendSharedDownload(CDownload* pDownload);
protected:
	BOOL	OnPacket(CEDPacket* pPacket);
	BOOL	OnRejected(CEDPacket* pPacket);
	BOOL	OnServerMessage(CEDPacket* pPacket);
	BOOL	OnIdChange(CEDPacket* pPacket);
	BOOL	OnServerList(CEDPacket* pPacket);
	BOOL	OnServerStatus(CEDPacket* pPacket);
	BOOL	OnServerIdent(CEDPacket* pPacket);
	BOOL	OnCallbackRequest(CEDPacket* pPacket);
	BOOL	OnSearchResults(CEDPacket* pPacket);
	BOOL	OnFoundSources(CEDPacket* pPacket);
	void	SendSharedFiles();

};

#endif // !defined(AFX_EDNEIGHBOUR_H__7E77CD2A_D3AA_4E53_981B_3B4624968921__INCLUDED_)
