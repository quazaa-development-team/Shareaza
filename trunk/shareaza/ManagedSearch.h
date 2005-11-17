//
// ManagedSearch.h
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

#if !defined(AFX_MANAGEDSEARCH_H__F6DF037C_8FF5_4D18_AB90_3BF637B3CAA9__INCLUDED_)
#define AFX_MANAGEDSEARCH_H__F6DF037C_8FF5_4D18_AB90_3BF637B3CAA9__INCLUDED_

#pragma once

#include "QuerySearch.h"

class CPacket;
class CNeighbour;


class CManagedSearch : private boost::noncopyable
{
// Construction
public:
	CManagedSearch(std::auto_ptr< CQuerySearch > pSearch = std::auto_ptr< CQuerySearch >( new CQuerySearch() ),
			int nPriority = 0);
	~CManagedSearch() { Stop(); }
	
	enum { spHighest, spMedium, spLowest, spMax };

// Attributes
public:
	boost::scoped_ptr< CQuerySearch > m_pSearch;
	int				m_nPriority;
	BOOL			m_bAllowG2;
	BOOL			m_bAllowG1;
	BOOL			m_bAllowED2K;
public:
	BOOL			m_bActive;
	BOOL			m_bReceive;
public:
	DWORD			m_tStarted;					// Time search was started
	DWORD			m_nHits;					// Hits
	DWORD			m_nHubs;					// Number of G2 hubs searched
	DWORD			m_nLeaves;					// Number of G2 leaves searched
	DWORD			m_nQueryCount;				// Total Gnutella2 queries sent
	DWORD			m_tLastG2;					// Time a G2 hub was last searched
	DWORD			m_tLastED2K;				// Time an ed2k server was last searched
	DWORD			m_tMoreResults;				// Time more results were requested from an ed2k server
	DWORD			m_nEDServers;				// Number of EDonkey servers searched
	DWORD			m_nEDClients;				// Number of ED2K clients searched (Guess)
protected:
	CMap< DWORD, DWORD, DWORD, DWORD > m_pNodes;
	DWORD			m_tExecute;

// Operations
public:
	void	Serialize(CArchive& ar);
	void	Start();
	void	Stop();
	BOOL	Execute();
	void	OnHostAcknowledge(DWORD nAddress);
	BOOL	IsLastED2KSearch();
protected:
	BOOL	ExecuteNeighbours(DWORD tTicks, DWORD tSecs);
	BOOL	ExecuteG2Mesh(DWORD tTicks, DWORD tSecs);
	BOOL	ExecuteDonkeyMesh(DWORD tTicks, DWORD tSecs);
	
// Inlines
public:

	inline CQuerySearch* GetSearch() const { return m_pSearch.get(); }
	inline BOOL IsActive() const { return m_bActive; }
	inline int GetPriority() const { return m_nPriority; }
	inline void SetPriority(int nPriority) { m_nPriority = nPriority; }

};

#endif // !defined(AFX_MANAGEDSEARCH_H__F6DF037C_8FF5_4D18_AB90_3BF637B3CAA9__INCLUDED_)
