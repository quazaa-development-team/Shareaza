//
// SearchManager.h
//
// Copyright (c) Shareaza Development Team, 2002-2007.
// This file is part of SHAREAZA (shareaza.sourceforge.net)
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

#if !defined(AFX_SEARCHMANAGER_H__FE71D8A9_8260_4548_B331_C1BF2D0DFEF0__INCLUDED_)
#define AFX_SEARCHMANAGER_H__FE71D8A9_8260_4548_B331_C1BF2D0DFEF0__INCLUDED_

#pragma once

class CManagedSearch;
class CG2Packet;
class CQueryHit;


class CSearchManager
{
// Construction
public:
	CSearchManager();
	virtual ~CSearchManager();

// Attributes
public:
	CMutex			m_pSection;
	Hashes::Guid	m_oLastED2KSearch;
protected:
	CList< CManagedSearch* > m_pList;
	DWORD			m_tLastTick;
	int				m_nPriorityClass;
	int				m_nPriorityCount;

// Operations
public:
	POSITION		GetIterator() const;
	CManagedSearch*	GetNext(POSITION& pos) const;
	INT_PTR			GetCount() const;
	CManagedSearch*	Find(const Hashes::Guid& oGUID);
	void			OnRun();
	BOOL			OnQueryAck(CG2Packet* pPacket, SOCKADDR_IN* pHost, Hashes::Guid& oGUID);
	BOOL			OnQueryHits(CQueryHit* pHits);
	WORD			OnQueryStatusRequest(const Hashes::Guid& oGUID);
protected:
	void			Add(CManagedSearch* pSearch);
	void			Remove(CManagedSearch* pSearch);

	friend class CManagedSearch;
	friend class CSearchWnd;
};

extern CSearchManager SearchManager;

#endif // !defined(AFX_SEARCHMANAGER_H__FE71D8A9_8260_4548_B331_C1BF2D0DFEF0__INCLUDED_)