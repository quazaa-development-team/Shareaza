//
// ITMQueues.h
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

#ifndef _ITMQUEUE_H_
#define _ITMQUEUE_H_

#pragma once

class CITMQueue
{
// Child ObjectDefinition
	public:
		class CITMItem
		{
			public:
				CITMItem();
				virtual ~CITMItem();
				virtual BOOL DoProcess();
				virtual BOOL OnProcess()	= 0;
		};

// Typedefs
	public:
		typedef std::list<CITMItem *>	_TITMList;
		//typedef std::queue<CITMList>	_TITMQueue;
		typedef std::list<CITMItem *>	_TITMQueue;

// Constructors
	public:
		CITMQueue();
		virtual ~CITMQueue();

// Data members.
	public:
        CMutex		m_oLock;
		_TITMQueue	m_oMessages;

// Function members
	public:
		void PushMessage(CITMItem * pItem);
		void ProcessMessages();

};

#endif // _ITMQUEUE_H_
