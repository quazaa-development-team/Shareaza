//
// WndBaseMatch.h
//
// Copyright (c) Shareaza Development Team, 2002-2004.
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

#if !defined(AFX_WNDBASEMATCH_H__BB7F6950_C699_40C4_8817_E3741CE3A8B2__INCLUDED_)
#define AFX_WNDBASEMATCH_H__BB7F6950_C699_40C4_8817_E3741CE3A8B2__INCLUDED_

#pragma once

#include "WndPanel.h"
#include "CtrlMatch.h"

class CMatchList;
class CCoolMenu;


class CBaseMatchWnd : public CPanelWnd
{
// Construction
public:
	CBaseMatchWnd();
	virtual ~CBaseMatchWnd();
	
	DECLARE_DYNCREATE(CBaseMatchWnd)

// Attributes
public:
	CMatchCtrl		m_wndList;
	CCoolBarCtrl	m_wndToolBar;
	CEdit			m_wndFilter;
protected:
	CMatchList*		m_pMatches;
	CCoolMenu*		m_pCoolMenu;
	BOOL			m_bContextMenu;
	DWORD			m_tContextMenu;
	BOOL			m_bPaused;
	BOOL			m_bUpdate;
	BOOL			m_bBMWActive;
	DWORD			m_nCacheFiles;
	
// Operations
protected:
	int	CheckExisting(BOOL bSHA1, SHA1* pSHA1, BOOL bTiger, TIGEROOT* pTiger, BOOL bED2K, MD4* pED2K);

// Overrides
public:
	//{{AFX_VIRTUAL(CBaseMatchWnd)
	public:
	virtual BOOL OnCmdMsg(UINT nID, int nCode, void* pExtra, AFX_CMDHANDLERINFO* pHandlerInfo);
	//}}AFX_VIRTUAL
	
	virtual void	UpdateMessages(BOOL bActive = TRUE);
	virtual HRESULT	GetGenericView(IGenericView** ppView);
	
// Implementation
protected:
	//{{AFX_MSG(CBaseMatchWnd)
	afx_msg int OnCreate(LPCREATESTRUCT lpCreateStruct);
	afx_msg void OnDestroy();
	afx_msg void OnSize(UINT nType, int cx, int cy);
	afx_msg void OnTimer(UINT nIDEvent);
	afx_msg void OnContextMenu(CWnd* pWnd, CPoint point);
	afx_msg void OnMeasureItem(int nIDCtl, LPMEASUREITEMSTRUCT lpMeasureItemStruct);
	afx_msg void OnDrawItem(int nIDCtl, LPDRAWITEMSTRUCT lpDrawItemStruct);
	afx_msg void OnUpdateSearchDownload(CCmdUI* pCmdUI);
	afx_msg void OnSearchDownload();
	afx_msg void OnUpdateSearchCopy(CCmdUI* pCmdUI);
	afx_msg void OnSearchCopy();
	afx_msg void OnUpdateSearchChat(CCmdUI* pCmdUI);
	afx_msg void OnSearchChat();
	afx_msg void OnUpdateSearchFilter(CCmdUI* pCmdUI);
	afx_msg void OnSearchFilter();
	afx_msg void OnUpdateSearchFilterRemove(CCmdUI* pCmdUI);
	afx_msg void OnSearchFilterRemove();
	afx_msg void OnSearchColumns();
	afx_msg void OnUpdateLibraryBitziWeb(CCmdUI* pCmdUI);
	afx_msg void OnLibraryBitziWeb();
	afx_msg void OnUpdateSecurityBan(CCmdUI* pCmdUI);
	afx_msg void OnSecurityBan();
	afx_msg void OnUpdateHitMonitorSearch(CCmdUI* pCmdUI);
	afx_msg void OnHitMonitorSearch();
	afx_msg BOOL OnMouseWheel(UINT nFlags, short zDelta, CPoint pt);
	afx_msg void OnMDIActivate(BOOL bActivate, CWnd* pActivateWnd, CWnd* pDeactivateWnd);
	afx_msg void OnUpdateBrowseLaunch(CCmdUI* pCmdUI);
	afx_msg void OnBrowseLaunch();
	afx_msg void OnSearchFilterRaw();
	afx_msg void OnUpdateSearchForThis(CCmdUI* pCmdUI);
	afx_msg void OnSearchForThis();
	afx_msg void OnUpdateSearchForSimilar(CCmdUI* pCmdUI);
	afx_msg void OnSearchForSimilar();
	afx_msg void OnUpdateSearchForArtist(CCmdUI* pCmdUI);
	afx_msg void OnSearchForArtist();
	afx_msg void OnUpdateSearchForAlbum(CCmdUI* pCmdUI);
	afx_msg void OnSearchForAlbum();
	afx_msg void OnUpdateSearchForSeries(CCmdUI* pCmdUI);
	afx_msg void OnSearchForSeries();
	afx_msg void OnUpdateLibraryJigle(CCmdUI* pCmdUI);
	afx_msg void OnLibraryJigle();
	//}}AFX_MSG
	afx_msg void OnKillFocusFilter();
	afx_msg void OnToolbarReturn();
	afx_msg void OnToolbarEscape();
	afx_msg void OnUpdateBlocker(CCmdUI* pCmdUI);

	DECLARE_MESSAGE_MAP()

};

//{{AFX_INSERT_LOCATION}}

#define IDC_FILTER_BOX	107

#endif // !defined(AFX_WNDBASEMATCH_H__BB7F6950_C699_40C4_8817_E3741CE3A8B2__INCLUDED_)