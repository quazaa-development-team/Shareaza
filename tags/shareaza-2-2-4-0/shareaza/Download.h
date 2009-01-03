//
// Download.h
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

#if !defined(AFX_DOWNLOAD_H__156689EC_D090_4285_BB8C_9AD058024BB5__INCLUDED_)
#define AFX_DOWNLOAD_H__156689EC_D090_4285_BB8C_9AD058024BB5__INCLUDED_

#pragma once

#include "DownloadWithExtras.h"


class CDownload : public CDownloadWithExtras
{
// Construction
public:
	CDownload();
	virtual ~CDownload();

// Attributes
public:
	DWORD		m_nSerID;
	BOOL		m_bExpanded;
	BOOL		m_bSelected;
	TRISTATE	m_bVerify;
	DWORD		m_tCompleted;
	int			m_nRunCookie;
	int			m_nSaveCookie;
	int			m_nGroupCookie;
private:
	BOOL		m_bTempPaused;
	BOOL		m_bPaused;
	BOOL		m_bBoosted;
	BOOL		m_bShared;
	BOOL		m_bComplete;
	DWORD		m_tSaved;
	DWORD		m_tBegan;		// The time when this download began trying to download (Started
								// searching, etc). 0 means has not tried this session.
	BOOL		m_bDownloading;	// This is used to store if a download is downloading. (Performance tweak)
								// You should count the transfers if you need a 100% current answer.
// Operations
public:
	void        	Pause(BOOL bRealPause = TRUE);
	void        	Resume();
	void        	Remove(BOOL bDelete = FALSE);
	void        	Boost();
	void        	Share(BOOL bShared);
	BOOL        	Rename(LPCTSTR pszName);
	void        	SetStartTimer();
	BOOL        	IsStarted() const;		//Has the download actually downloaded anything?
	virtual BOOL	IsPaused( BOOL bRealState = FALSE ) const;
	virtual BOOL	IsDownloading() const;	//Is the download receiving data?
	virtual BOOL	IsMoving() const;
	virtual BOOL	IsCompleted() const;
	BOOL        	IsBoosted() const;
	BOOL        	IsShared() const;
	virtual BOOL	IsTrying() const;		//Is the download currently trying to download?
	BOOL			Load(LPCTSTR pszPath);
	BOOL			Save(BOOL bFlush = FALSE);
	virtual void	Serialize(CArchive& ar, int nVersion);
	void			OnRun();
	BOOL			OnVerify(LPCTSTR pszPath, BOOL bVerified);
private:
	void        	StopTrying();
	DWORD       	GetStartTimer() const;
	void			OnTaskComplete(CDownloadTask* pTask);
	void			OnDownloaded();
	void			OnMoved(CDownloadTask* pTask);
	void			SerializeOld(CArchive& ar, int nVersion);
	
	friend class CDownloadTask; // m_pTask && OnTaskComplete
	friend class CDownloadTransfer; // GetVerifyLength
	friend class CDownloadWithTorrent; // m_bComplete
	friend class CDownloadsWnd; // m_pTask
	friend class CDownloads;	// m_bComplete for Load()
};

#endif // !defined(AFX_DOWNLOAD_H__156689EC_D090_4285_BB8C_9AD058024BB5__INCLUDED_)