//
// ManagedSearch.h
//
// Copyright (c) Shareaza Development Team, 2002-2009.
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

#pragma once

#include "QuerySearch.h"

class CPacket;
class CNeighbour;

class CManagedSearch
{
// Construction
public:
	CManagedSearch(CQuerySearch* pSearch = NULL, int nPriority = 0);
	~CManagedSearch();

	typedef CMap< DWORD, DWORD, DWORD, DWORD > CDwordDwordMap;
	
	enum { spHighest, spMedium, spLowest, spMax };

	inline CQuerySearchPtr GetSearch() const
	{
		return m_pSearch;
	}

	inline bool IsEqualGUID(const Hashes::Guid& oGUID) const
	{
		return m_pSearch && validAndEqual( m_pSearch->m_oGUID, oGUID );
	}

	inline CSchema* GetSchema() const
	{
		return m_pSearch ? m_pSearch->m_pSchema : NULL;
	}

	inline BOOL IsActive() const
	{
		return m_bActive;
	}

	inline void SetActive(BOOL bActive)
	{
		m_bActive = bActive;
	}

	inline int GetPriority() const
	{
		return m_nPriority;
	}

	inline void SetPriority(int nPriority)
	{
		m_nPriority = nPriority;
	}

	void	Serialize(CArchive& ar);
	void	Start();
	void	Stop();
	BOOL	Execute();
	void	OnHostAcknowledge(DWORD nAddress);
	BOOL	IsLastED2KSearch();
	void	CreateGUID();

// Attributes
	BOOL			m_bAllowG2;
	BOOL			m_bAllowG1;
	BOOL			m_bAllowED2K;
	BOOL			m_bReceive;
	DWORD			m_tStarted;					// Time search was started (s)
	DWORD			m_nHits;					// Total hits
	DWORD			m_nG1Hits;					// G1 hits
	DWORD			m_nG2Hits;					// G2 hits
	DWORD			m_nEDHits;					// ED2k hits
	DWORD			m_nHubs;					// Number of G2 hubs searched
	DWORD			m_nLeaves;					// Number of G2 leaves searched
	DWORD			m_nQueryCount;				// Total Gnutella2 queries sent
	DWORD			m_tLastED2K;				// Time an ed2k server was last searched
	DWORD			m_tMoreResults;				// Time more results were requested from an ed2k server

protected:
	int				m_nPriority;
	BOOL			m_bActive;
	DWORD			m_tLastG2;					// Time a G2 hub was last searched
	DWORD			m_nEDServers;				// Number of EDonkey servers searched
	DWORD			m_nEDClients;				// Number of ED2K clients searched (Guess)
	CQuerySearchPtr m_pSearch;					// Search handler	
	CDwordDwordMap	m_pNodes;					// Pair of IP and query time (s)
	CDwordDwordMap	m_pG1Nodes;					// Pair of IP and last sent packet TTL
	DWORD			m_tExecute;					// Search execute time (ticks)

	BOOL	ExecuteNeighbours(DWORD tTicks, DWORD tSecs);
	BOOL	ExecuteG2Mesh(DWORD tTicks, DWORD tSecs);
	BOOL	ExecuteDonkeyMesh(DWORD tTicks, DWORD tSecs);
};