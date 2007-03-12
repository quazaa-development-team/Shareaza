//
// DownloadWithSearch.h
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

#if !defined(AFX_DOWNLOADWITHSEARCH_H__0ED8A270_13B0_47A6_9917_727CBDD82B27__INCLUDED_)
#define AFX_DOWNLOADWITHSEARCH_H__0ED8A270_13B0_47A6_9917_727CBDD82B27__INCLUDED_

#pragma once

#include "DownloadWithTiger.h"

class CManagedSearch;
class CDownloadEditHashesPage;
class CDownloads;


class CDownloadWithSearch : public CDownloadWithTiger
{
// Construction
protected:
	CDownloadWithSearch();
	virtual ~CDownloadWithSearch();

// Attributes
private:
	CManagedSearch*	m_pSearch;
	DWORD			m_tSearchTime;		// Timer for manual search
	DWORD			m_tSearchCheck;		// Limit auto searches
public:
	DWORD			m_tLastED2KGlobal;	// Time the last ed2k UDP GetSources was done on this download
	DWORD			m_tLastED2KLocal;	// Time the last ed2k TCP GetSources was done on this download
private:
	DWORD			m_tSearchStart;		// time this download started search (TickCount)
	DWORD			m_tSearchDuration;	// Period of time this search should be executed for (TickCount)
	BOOL			m_bSearchActive;

// Operations
public:
	BOOL	FindSourcesAllowed(DWORD tNow) const;
	virtual BOOL	FindMoreSources();
protected:
	void	RunSearch(DWORD tNow);
	void	StopSearch(DWORD tNow, BOOL bQueuePending);
private:
	void	StartManualSearch(DWORD tNow);
	void	StartAutomaticSearch( DWORD tNow, BOOL bG1 = TRUE, BOOL bG2 = TRUE, BOOL bED2K = TRUE );
	BOOL	CanSearch() const;
	void	PrepareSearch( BOOL bG1 = TRUE, BOOL bG2 = TRUE, BOOL bED2K = TRUE );

	friend class CDownloadsCtrl;
	friend class CDownloadEditHashesPage;
	friend class CDownloads;
};

#endif // !defined(AFX_DOWNLOADWITHSEARCH_H__0ED8A270_13B0_47A6_9917_727CBDD82B27__INCLUDED_)
