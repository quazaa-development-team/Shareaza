//
// DownloadBase.h
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

#include "ShareazaFile.h"

class CDownloadTask;


class CDownloadBase : public CShareazaFile
{
// Construction
protected:
	CDownloadBase();
	virtual ~CDownloadBase();

// Attributes
public:
	bool			m_bSHA1Trusted;		// True if SHA1 hash is trusted
	bool			m_bTigerTrusted;
	bool			m_bED2KTrusted;
	bool			m_bBTHTrusted;
	bool			m_bMD5Trusted;
	int				m_nCookie;
	CString			m_sSearchKeyword;	// Search keyword to override G1 keyword search.
private:
	CDownloadTask*	m_pTask;

// Operations
public:
	bool		IsTasking() const;						// Check if a task is already running
	void		SetTask(CDownloadTask* pTask);
	DWORD		GetTaskType() const;
	bool		CheckTask(CDownloadTask* pTask) const;
	void		AbortTask();
	void		SetModified();

// Overrides
protected:
	virtual bool	IsCompleted() const = 0;
	virtual bool	IsMoving() const = 0;
	virtual bool	IsPaused(bool bRealState = false) const = 0;
	virtual bool	IsTrying() const = 0;
	virtual void	Serialize(CArchive& ar, int nVersion);
};