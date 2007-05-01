//
// HostCache.h
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

#if !defined(AFX_HOSTCACHE_H__7F2764B0_BB17_4FF0_AF03_7BB7D4E22F7F__INCLUDED_)
#define AFX_HOSTCACHE_H__7F2764B0_BB17_4FF0_AF03_7BB7D4E22F7F__INCLUDED_

#pragma once

class CNeighbour;
class CG1Packet;
class CVendor;


class CHostCacheHost
{
public:
	CHostCacheHost(PROTOCOLID nProtocol = PROTOCOL_NULL);

	// Attributes: Host Information
	PROTOCOLID	m_nProtocol;
	IN_ADDR		m_pAddress;
	WORD		m_nPort;
	CVendor*	m_pVendor;
	BOOL		m_bPriority;
	DWORD		m_nUserCount;
	DWORD		m_nUserLimit;
	DWORD		m_nFileLimit;
	CString		m_sName;
	CString		m_sDescription;
	DWORD		m_nTCPFlags;
	DWORD		m_nUDPFlags;
	BOOL		m_bCheckedLocally;
	CString		m_sCountry;

	// Attributes: Contact Times
	DWORD		m_tAdded;
	DWORD		m_tRetryAfter;
	DWORD		m_tConnect;
	DWORD		m_tQuery;
	DWORD		m_tAck;
	DWORD		m_tStats;			// ED2K stats UDP request
	DWORD		m_tFailure;
	DWORD		m_nFailures;
	DWORD		m_nDailyUptime;
	DWORD		m_tCheckTime;

	// Attributes: Query Keys
	DWORD		m_tKeyTime;
	DWORD		m_nKeyValue;
	DWORD		m_nKeyHost;

	CNeighbour*	ConnectTo(BOOL bAutomatic = FALSE);
	CString		ToString() const;
	BOOL		CanConnect(DWORD tNow = 0) const;	// Can we connect to this host now?
	BOOL		CanQuote(DWORD tNow = 0) const;		// Is this a recently seen host?
	BOOL		CanQuery(DWORD tNow = 0) const;		// Can we UDP query this host? (G2/ed2k)
	void		SetKey(DWORD nKey, const IN_ADDR* pHost = NULL);

	inline DWORD Seen() const throw()
	{
		return m_tSeen;
	}

protected:
	DWORD		m_tSeen;

	// Return: true - if tSeen cnaged, false - otherwise.
	bool		Update(WORD nPort, DWORD tSeen = 0, LPCTSTR pszVendor = NULL, DWORD nUptime = 0);
	void		Serialize(CArchive& ar, int nVersion);

	inline bool	IsValid() const throw()
	{
		return m_nProtocol != PROTOCOL_NULL &&
			m_pAddress.s_addr != INADDR_ANY && m_pAddress.s_addr != INADDR_NONE &&
			m_nPort != 0 &&
			m_tSeen != 0;
	}

	friend class CHostCacheList;
};

typedef CHostCacheHost* CHostCacheHostPtr;


template<>
struct std::less< IN_ADDR > : public std::binary_function< IN_ADDR, IN_ADDR, bool>
{
	inline bool operator()(const IN_ADDR& _Left, const IN_ADDR& _Right) const throw()
	{
		return ( ntohl( _Left.s_addr ) < ntohl( _Right.s_addr ) );
	}
};

typedef std::map< IN_ADDR, CHostCacheHostPtr > CHostCacheMap;
typedef std::pair< IN_ADDR, CHostCacheHostPtr > CHostCacheMapPair;

template<>
struct std::less< CHostCacheHostPtr > : public std::binary_function< CHostCacheHostPtr, CHostCacheHostPtr, bool>
{
	inline bool operator()(const CHostCacheHostPtr& _Left, const CHostCacheHostPtr& _Right) const throw()
	{
		return ( _Left->Seen() > _Right->Seen() );
	}
};

typedef std::multiset< CHostCacheHostPtr > CHostCacheIndex;
typedef std::pair < CHostCacheIndex::iterator, CHostCacheIndex::iterator > CHostCacheTimeItPair;
typedef CHostCacheIndex::const_iterator CHostCacheIterator;

struct good_host : public std::binary_function< CHostCacheMapPair, BOOL, bool>
{
	inline bool operator()(const CHostCacheMapPair& _Pair, const BOOL& _bLocally) const throw()
	{
		return ( _Pair.second->m_nFailures == 0 &&
			( _Pair.second->m_bCheckedLocally || _bLocally ) );
	}
};


class CHostCacheList
{
public:
	CHostCacheList(PROTOCOLID nProtocol);
	virtual ~CHostCacheList();

	PROTOCOLID					m_nProtocol;
	DWORD						m_nCookie;
	mutable CCriticalSection	m_pSection;

	CHostCacheHostPtr	Add(IN_ADDR* pAddress, WORD nPort, DWORD tSeen = 0, LPCTSTR pszVendor = NULL, DWORD nUptime = 0);
	BOOL				Add(LPCTSTR pszHost, DWORD tSeen = 0, LPCTSTR pszVendor = NULL, DWORD nUptime = 0);
	void				Update(CHostCacheHostPtr pHost, WORD nPort = 0, DWORD tSeen = 0, LPCTSTR pszVendor = NULL, DWORD nUptime = 0);
	void				Remove(CHostCacheHostPtr pHost);
	void				OnFailure(const IN_ADDR* pAddress, WORD nPort, bool bRemove=true);
	void				OnSuccess(const IN_ADDR* pAddress, WORD nPort, bool bUpdate=true);
	void				PruneByQueryAck();			// For G2
	void				PruneOldHosts();			// For G1
	void				Clear();
	void				Serialize(CArchive& ar, int nVersion);
	int					Import(LPCTSTR pszFile);
	int					ImportMET(CFile* pFile);
	bool				CheckMinimumED2KServers();

	inline bool EnoughED2KServers() const throw()
	{
		return ( CountHosts( TRUE ) >= 8 );
	}

	inline CHostCacheIterator Begin() const throw()
	{
		return m_HostsTime.begin();
	}

	inline CHostCacheIterator End() const throw()
	{
		return m_HostsTime.end();
	}

	inline const CHostCacheHostPtr GetNewest() const throw()
	{
		return IsEmpty() ? NULL : *Begin();
	}

	inline bool IsEmpty() const throw()
	{
		return m_HostsTime.empty();
	}

	inline DWORD GetCount() const throw()
	{
		return (DWORD)m_Hosts.size();
	}

	inline CHostCacheHostPtr Find(const IN_ADDR* pAddress) const throw()
	{
		CQuickLock oLock( m_pSection );
		CHostCacheMap::const_iterator i = m_Hosts.find( *pAddress );
		return ( i != m_Hosts.end() ) ? (*i).second : NULL;
	}

	inline bool Check(const CHostCacheHostPtr pHost) const throw()
	{
		CQuickLock oLock( m_pSection );
		return std::find( m_HostsTime.begin(), m_HostsTime.end(), pHost )
			!= m_HostsTime.end();
	}

	inline DWORD CountHosts(const BOOL bCountUncheckedLocally = FALSE) const throw()
	{
		CQuickLock oLock( m_pSection );
		return (DWORD)(size_t) std::count_if( m_Hosts.begin(), m_Hosts.end(),
			std::bind2nd( good_host(), bCountUncheckedLocally ) );
	}

protected:
	CHostCacheMap				m_Hosts;		// Hosts map (sorted by IP)
	CHostCacheIndex				m_HostsTime;	// Host index (sorted from newer to older)

	CHostCacheHostPtr	AddInternal(const IN_ADDR* pAddress, WORD nPort, DWORD tSeen, LPCTSTR pszVendor, DWORD nUptime);
	void				PruneHosts();
	int					LoadDefaultED2KServers();
	void				DoED2KServersImport();
};


class CHostCache
{
public:
	CHostCache();

	CHostCacheList	Gnutella1;
	CHostCacheList	Gnutella2;
	CHostCacheList	eDonkey;
	CHostCacheList	G1DNA;

	BOOL				Load();
	BOOL				Save();
	CHostCacheHostPtr	Find(const IN_ADDR* pAddress) const;
	BOOL				Check(const CHostCacheHostPtr pHost) const;
	void				Remove(CHostCacheHostPtr pHost);
	void				OnFailure(const IN_ADDR* pAddress, WORD nPort, 
							  PROTOCOLID nProtocol=PROTOCOL_NULL, bool bRemove=true);
	void				OnSuccess(const IN_ADDR* pAddress, WORD nPort, 
							  PROTOCOLID nProtocol=PROTOCOL_NULL, bool bUpdate=true);

	inline CHostCacheList* ForProtocol(PROTOCOLID nProtocol) throw()
	{
		switch ( nProtocol )
		{
		case PROTOCOL_G1:
			return &Gnutella1;
		case PROTOCOL_G2:
			return &Gnutella2;
		case PROTOCOL_ED2K:
			return &eDonkey;
		default:
			ASSERT(FALSE);
			return NULL;
		}
	}

protected:
	CList< CHostCacheList* >	m_pList;
	mutable CCriticalSection	m_pSection;

	void				Serialize(CArchive& ar);
	void				Clear();
};

extern CHostCache HostCache;

#endif // !defined(AFX_HOSTCACHE_H__7F2764B0_BB17_4FF0_AF03_7BB7D4E22F7F__INCLUDED_)
