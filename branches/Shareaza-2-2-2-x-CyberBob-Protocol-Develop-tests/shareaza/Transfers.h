//
// Transfers.h
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

#if !defined(AFX_TRANSFERS_H__950AC162_FF34_4B40_8D8A_2745AA245316__INCLUDED_)
#define AFX_TRANSFERS_H__950AC162_FF34_4B40_8D8A_2745AA245316__INCLUDED_

#include "Transfer.h"
#pragma once

class CTransfers;

extern CTransfers Transfers;

class CTransfers
{
// typedef
public:
	typedef std::list<CTransfer*>::iterator TransferItem;
	typedef std::list<CTransfer*>::const_iterator const_TransferItem;

// Construction
public:
	CTransfers();
	virtual ~CTransfers();

// Attributes
public:
	CMutex			m_pSection;
class Lock
{
public:
	Lock() { Transfers.m_pSection.Lock(); }
	~Lock() { Transfers.m_pSection.Unlock(); }
private:
	Lock(const Lock&);
	Lock& operator=(const Lock&);
	static void* operator new(std::size_t);
	static void* operator new[](std::size_t);
	static void operator delete(void*);
	static void operator delete[](void*);
};
	DWORD			m_nBuffer;
	BYTE*			m_pBuffer;
protected:
	std::list<CTransfer*> m_pList;
	HANDLE			m_hThread;
	volatile BOOL	m_bThread;
	CEvent			m_pWakeup;

// Operations
public:
	INT_PTR		GetActiveCount() const;
	BOOL		IsConnectedTo(IN_ADDR* pAddress);
	BOOL		StartThread();
	void		StopThread();
protected:
	static UINT	ThreadStart(LPVOID pParam);
	void		OnRun();
	void		OnRunTransfers();
	void		OnCheckExit();
protected:
	void		Add(CTransfer* pTransfer);
	void		Remove(CTransfer* pTransfer);

// List Access
public:
	inline const_TransferItem begin() const
	{
		return m_pList.begin();
	}

	inline const_TransferItem end() const
	{
		return m_pList.end();
	}

	inline size_t size() const
	{
		return m_pList.size();
	}

	inline BOOL Check(CTransfer* pTransfer) const
	{
		
		const_TransferItem index  = m_pList.begin();
		const_TransferItem indexEnd  = m_pList.end();

		for (; index != indexEnd; index++ )
		{
			if ( *index == pTransfer ) return TRUE;
		}

		return FALSE;
		//return ( pTransfer->m_pSelf != NULL );
	}

	friend class CTransfer;
	friend class CUpload;
	friend class CDownloadWithTransfers;

};

#endif // !defined(AFX_TRANSFERS_H__950AC162_FF34_4B40_8D8A_2745AA245316__INCLUDED_)
