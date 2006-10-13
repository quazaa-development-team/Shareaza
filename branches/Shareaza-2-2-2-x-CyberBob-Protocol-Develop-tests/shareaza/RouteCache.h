//
// RouteCache.h
//
//	Date:			"$Date: 2006/03/31 15:22:13 $"
//	Revision:		"$Revision: 1.52 $"
//  Last change by:	"$Author: CyberBob $"
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

#if !defined(AFX_ROUTECACHE_H__7FDD7D02_ABC8_4718_A985_C411BCE0D660__INCLUDED_)
#define AFX_ROUTECACHE_H__7FDD7D02_ABC8_4718_A985_C411BCE0D660__INCLUDED_

#pragma once

class CNeighbour;


class CRouteCacheItem
{
// Attributes
public:
	CRouteCacheItem*			m_pNext;
	DWORD						m_tAdded;
	Hashes::Guid				m_oGUID;
	const CNeighbour*			m_pNeighbour;
	SOCKADDR_IN					m_pEndpoint;
};


class CRouteCacheTable
{
// Construction
public:
	CRouteCacheTable();
	virtual ~CRouteCacheTable();

// Attributes
protected:
	CRouteCacheItem*	m_pHash[1024];
	CRouteCacheItem*	m_pFree;
	CRouteCacheItem*	m_pBuffer;
	DWORD				m_nBuffer;
	DWORD				m_nUsed;
	DWORD				m_tFirst;
	DWORD				m_tLast;
	BOOL				m_bLocked;

// Protected Operations
protected:
	CRouteCacheItem*	RCT_Find(const Hashes::Guid& oGUID);
	CRouteCacheItem*	RCT_Add(const Hashes::Guid& oGUID, const CNeighbour* pNeighbour, const SOCKADDR_IN* pEndpoint, DWORD nTime = 0);
	void				RCT_Remove(CNeighbour* pNeighbour);
	void				RCT_Resize(DWORD nSize);
	DWORD				RCT_GetNextSize(DWORD nDesired);
	void				RCT_Clear();

	// This is some experimental Object base Locking mechanism
	class Lock
	{
		private:
			CRouteCacheTable* m_pRCT;
		public:
			// Lock the Object when you make instance of this lock class;
			Lock(CRouteCacheTable* pRCT)
			{
				while (pRCT->m_bLocked)	// 1.Wait until the resource gets free
				{
					// Wait loop
				}
				pRCT->m_bLocked	= TRUE;	// 2.Lock
				m_pRCT = pRCT;			// 3.Copy Pointer of the Object so Distructor can 
										//	track object for unlocking process
			}

			// UnLock Automatically whenever you exit Function with instance of This Lock Object
			~Lock()
			{
				m_pRCT->m_bLocked	= FALSE; // UnLock
			}

			//In case you wanna unlock in Middle of Function
			inline void UnLock()
			{
				m_pRCT->m_bLocked	= FALSE; // UnLock
			}
	};

	friend class CRouteCacheTable::Lock;

// Public Operations
public:
	inline CRouteCacheItem* Find(const Hashes::Guid& oGUID)
	{
		Lock pLock(this);
		return RCT_Find( oGUID );
	}

	inline CRouteCacheItem* Add(const Hashes::Guid& oGUID, const CNeighbour* pNeighbour, const SOCKADDR_IN* pEndpoint, DWORD nTime = 0)
	{
		Lock pLock(this);
		return RCT_Add( oGUID, pNeighbour, pEndpoint, nTime);
	}

	inline void Remove(CNeighbour* pNeighbour)
	{
		Lock pLock(this);
		RCT_Remove( pNeighbour );
	}
	inline void Resize(DWORD nSize)
	{
		Lock pLock(this);
		RCT_Resize( nSize );
	}

	inline DWORD GetNextSize(DWORD nDesired)
	{
		Lock pLock(this);
		return RCT_GetNextSize( nDesired );
	}

	inline void Clear()
	{
		Lock pLock(this);
		RCT_Clear();
	}

	inline BOOL IsFull() const
	{
		// Can not use this Lock object in Const function member
		//Lock pLock(this);
		return m_nUsed == m_nBuffer;
	}
};


class CRouteCache
{
// Construction
public:
	CRouteCache();
	virtual ~CRouteCache();

// Attributes
protected:
	DWORD				m_nSeconds;
	CRouteCacheTable	m_pTable[2];
	CRouteCacheTable*	m_pRecent;
	CRouteCacheTable*	m_pHistory;
	BOOL				m_bLocked;

// Protected Operations
protected:
	void				RC_SetDuration(DWORD nSeconds);
	BOOL				RC_Add(const Hashes::Guid& oGUID, const CNeighbour* pNeighbour);
	BOOL				RC_Add(const Hashes::Guid& oGUID, const SOCKADDR_IN* pEndpoint);
	void				RC_Remove(CNeighbour* pNeighbour);
	void				RC_Clear();
	CRouteCacheItem*	RC_Add(const Hashes::Guid& oGUID, const CNeighbour* pNeighbour, const SOCKADDR_IN* pEndpoint, DWORD tAdded);
	CRouteCacheItem*	RC_Lookup(const Hashes::Guid& oGUID, CNeighbour** ppNeighbour = NULL, SOCKADDR_IN* pEndpoint = NULL);

	// This is some experimental Object base Locking mechanism
	class Lock
	{
		private:
			CRouteCache* m_pRC;
		public:
			// Lock the Object when you make instance of this lock class;
			Lock(CRouteCache* pRC)
			{
				while (pRC->m_bLocked)	// 1.Wait until the resource gets free
				{
					// Wait loop
				}
				pRC->m_bLocked	= TRUE;	// 2.Lock
				m_pRC = pRC;			// 3.Copy Pointer of the Object so Distructor can 
										//	track object for unlocking process
			}

			// UnLock Automatically whenever you exit Function with instance of This Lock Object
			~Lock()
			{
				m_pRC->m_bLocked	= FALSE; // UnLock
			}

			//In case you wanna unlock in Middle of Function
			inline void UnLock()
			{
				m_pRC->m_bLocked	= FALSE; // UnLock
			}
	};

	friend class CRouteCache::Lock;

// Operations
public:
	inline void SetDuration(DWORD nSeconds)
	{
		Lock pLock(this);
		RC_SetDuration(nSeconds);
	}

	inline BOOL Add(const Hashes::Guid& oGUID, const CNeighbour* pNeighbour)
	{
		Lock pLock(this);
		return RC_Add( oGUID, pNeighbour );
	}

	inline BOOL Add(const Hashes::Guid& oGUID, const SOCKADDR_IN* pEndpoint)
	{
		Lock pLock(this);
		return RC_Add( oGUID, pEndpoint );
	}

	inline void Remove(CNeighbour* pNeighbour)
	{
		Lock pLock(this);
		RC_Remove( pNeighbour );
	}

	inline void Clear()
	{
		Lock pLock(this);
		RC_Clear();
	}

	inline CRouteCacheItem* Add(const Hashes::Guid& oGUID, const CNeighbour* pNeighbour, const SOCKADDR_IN* pEndpoint, DWORD tAdded)
	{
		Lock pLock(this);
		return RC_Add(oGUID, pNeighbour, pEndpoint, tAdded);
	}

	inline CRouteCacheItem* Lookup(const Hashes::Guid& oGUID, CNeighbour** ppNeighbour = NULL, SOCKADDR_IN* pEndpoint = NULL)
	{
		Lock pLock(this);
		return RC_Lookup(oGUID, ppNeighbour, pEndpoint);
	}
};

#endif // !defined(AFX_ROUTECACHE_H__7FDD7D02_ABC8_4718_A985_C411BCE0D660__INCLUDED_)
