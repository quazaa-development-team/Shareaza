//
// ITMQueues.cpp
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

// This is source file which implement InterThreadMessegingQueues which solve and minimize Use of Thread Mutex locking.

#include "StdAfx.h"
#include "Shareaza.h"
#include "ITMQueue.h"

CITMQueue::CITMItem::CITMItem()
{

}

CITMQueue::CITMItem::~CITMItem()
{

}

BOOL CITMQueue::CITMItem::DoProcess()
{
	OnProcess();
	delete this;
	return TRUE;
}

CITMQueue::CITMQueue() : m_oMessages(), m_oLock()
{

}

CITMQueue::~CITMQueue()
{
	CSingleLock pLock( &m_oLock, TRUE );
	ProcessMessages();
}

void CITMQueue::PushMessage(CITMItem * pItem)
{
	CSingleLock pLock( &m_oLock, TRUE );
	m_oMessages.push_back(pItem);
}

void CITMQueue::ProcessMessages()
{
	CSingleLock pLock( &m_oLock, TRUE );
	if ( m_oMessages.empty() ) return;
	_TITMQueue tempList = m_oMessages;
	m_oMessages.clear();
	pLock.Unlock();

	for (; !tempList.empty() ;)
	{
		(*(tempList.begin()))->DoProcess();
		tempList.pop_front();
	}
}
