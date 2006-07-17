//
// PongCache.h
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

#if !defined(AFX_PONGCACHE_H__0F9B689A_5132_49EB_8F13_670563C80A1D__INCLUDED_)
#define AFX_PONGCACHE_H__0F9B689A_5132_49EB_8F13_670563C80A1D__INCLUDED_

#pragma once

class CPongItem;
class CNeighbour;
class CG1Packet;


class CPongCache
{
// Construction
public:
	CPongCache();
	virtual ~CPongCache();

// Attributes
protected:
	CList< CPongItem* >	m_pCache;
	DWORD				m_nTime;
	BOOL				m_bLocked;

// Protected Operations 
protected:
	void		PC_Clear();
	BOOL		PC_ClearIfOld();
	CPongItem*	PC_Add(CNeighbour* pNeighbour, IN_ADDR* pAddress, WORD nPort, BYTE nHops, DWORD nFiles, DWORD nVolume);
	CPongItem*	PC_Lookup(CNeighbour* pNotFrom, BYTE nHops, CList< CPongItem* >* pIgnore);
	POSITION	PC_GetIterator() const;
	CPongItem*	PC_GetNext(POSITION& pos) const;

	// This is some experimental Object base Locking mechanism
	class Lock
	{
		private:
			CPongCache* m_pPC;
		public:
			// Lock the Object when you make instance of this lock class;
			Lock(CPongCache* pPC)
			{
				while (pPC->m_bLocked)	// 1.Wait until the resource gets free
				{
					// Wait loop
				}
				pPC->m_bLocked	= TRUE;	// 2.Lock
				m_pPC = pPC;			// 3.Copy Pointer of the Object so Distructor can 
										//	track object for unlocking process
			}

			// UnLock Automatically whenever you exit Function with instance of This Lock Object
			~Lock()
			{
				m_pPC->m_bLocked	= FALSE; // UnLock
			}

			//In case you wanna unlock in Middle of Function
			inline void UnLock()
			{
				m_pPC->m_bLocked	= FALSE; // UnLock
			}
	};

	friend class CPongCache::Lock;

// Public Operations 
public:
	inline void Clear()
	{
		Lock pLock(this);
		PC_Clear();
	}

	inline BOOL ClearIfOld()
	{
		Lock pLock(this);
		return PC_ClearIfOld();
	}

	inline CPongItem* Add(CNeighbour* pNeighbour, IN_ADDR* pAddress, WORD nPort, BYTE nHops, DWORD nFiles, DWORD nVolume)
	{
		Lock pLock(this);
		return PC_Add(pNeighbour, pAddress, nPort, nHops, nFiles, nVolume);
	}

	inline CPongItem* Lookup(CNeighbour* pNotFrom, BYTE nHops, CList< CPongItem* >* pIgnore)
	{
		Lock pLock(this);
		return PC_Lookup(pNotFrom, nHops, pIgnore);
	}

	inline POSITION GetIterator() const
	{
		//Lock pLock(this);
		return PC_GetIterator();
	}

	inline CPongItem* GetNext(POSITION& pos) const
	{
		//Lock pLock(this);
		return PC_GetNext(pos);
	}

};


class CPongItem
{
// Construction
public:
	CPongItem(CNeighbour* pNeighbour, IN_ADDR* pAddress, WORD nPort, BYTE nHops, DWORD nFiles, DWORD nVolume);
	virtual ~CPongItem();

// Attributes
public:
	CNeighbour*		m_pNeighbour;
	IN_ADDR			m_pAddress;
	WORD			m_nPort;
	BYTE			m_nHops;
	DWORD			m_nFiles;
	DWORD			m_nVolume;

// Operations
public:
	CG1Packet*		ToPacket(int nTTL, const Hashes::Guid& oGUID);

};

#endif // !defined(AFX_PONGCACHE_H__0F9B689A_5132_49EB_8F13_670563C80A1D__INCLUDED_)
