//
// QueryKeys.h
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


class CQueryKeys
{
// Construction
public:
	CQueryKeys();
	virtual ~CQueryKeys();

// Attributes
protected:
	DWORD	m_nBits;
	DWORD*	m_pTable;
	DWORD	m_nTable;
	DWORD*	m_pMap;

	void	Alloc();

// Operations
public:
	DWORD	Create(DWORD nAddress);
	BOOL	Check(DWORD nAddress, DWORD nKey);
};
