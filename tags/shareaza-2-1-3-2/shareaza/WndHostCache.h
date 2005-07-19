//
// WndHostCache.h
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

#if !defined(AFX_WNDHOSTCACHE_H__CF02C3BA_2D52_49F3_85C1_07365B714B3D__INCLUDED_)
#define AFX_WNDHOSTCACHE_H__CF02C3BA_2D52_49F3_85C1_07365B714B3D__INCLUDED_

#pragma once

#include "WndPanel.h"

class CHostCacheHost;


class CHostCacheWnd : public CPanelWnd
{
public:
	CHostCacheWnd();
	virtual ~CHostCacheWnd();

	DECLARE_SERIAL(CHostCacheWnd)

// Attributes
public:
	PROTOCOLID		m_nMode;
	BOOL			m_bAllowUpdates;
protected:
	CCoolBarCtrl	m_wndToolBar;
	CListCtrl		m_wndList;
	CLiveListSizer	m_pSizer;
	CImageList		m_gdiImageList;
	DWORD			m_nCookie;
	DWORD			tLastUpdate;

// Operations
public:
	void			Update(BOOL bForce = FALSE);
	CHostCacheHost*	GetItem(int nItem);
	virtual void	OnSkinChange();
	
// Overrides
public:
	//{{AFX_VIRTUAL(CHostCacheWnd)
	public:
	virtual BOOL PreTranslateMessage(MSG* pMsg);
	//}}AFX_VIRTUAL

// Implementation
protected:
	//{{AFX_MSG(CHostCacheWnd)
	afx_msg int OnCreate(LPCREATESTRUCT lpCreateStruct);
	afx_msg void OnSize(UINT nType, int cx, int cy);
	afx_msg void OnCustomDrawList(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnDblClkList(NMHDR* pNMHDR, LRESULT* pResult);
	afx_msg void OnSortList(NMHDR* pNotifyStruct, LRESULT *pResult);
	afx_msg void OnTimer(UINT nIDEvent);
	afx_msg void OnContextMenu(CWnd* pWnd, CPoint point);
	afx_msg void OnNcMouseMove(UINT nHitTest, CPoint point);
	afx_msg void OnUpdateHostCacheConnect(CCmdUI* pCmdUI);
	afx_msg void OnHostCacheConnect();
	afx_msg void OnUpdateHostCacheDisconnect(CCmdUI* pCmdUI);
	afx_msg void OnHostCacheDisconnect();
	afx_msg void OnUpdateHostCacheRemove(CCmdUI* pCmdUI);
	afx_msg void OnHostCacheRemove();
	afx_msg void OnDestroy();
	afx_msg void OnUpdateHostcacheG2Horizon(CCmdUI* pCmdUI);
	afx_msg void OnHostcacheG2Horizon();
	afx_msg void OnUpdateHostcacheG2Cache(CCmdUI* pCmdUI);
	afx_msg void OnHostcacheG2Cache();
	afx_msg void OnUpdateHostcacheG1Cache(CCmdUI* pCmdUI);
	afx_msg void OnHostcacheG1Cache();
	afx_msg void OnUpdateHostcacheEd2kCache(CCmdUI* pCmdUI);
	afx_msg void OnHostcacheEd2kCache();
	afx_msg void OnHostcacheImport();
	afx_msg void OnHostcacheEd2kDownload();
	afx_msg void OnUpdateHostcachePriority(CCmdUI* pCmdUI);
	afx_msg void OnHostcachePriority();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()

protected:
	virtual void RecalcLayout(BOOL bNotify = TRUE);
};

//{{AFX_INSERT_LOCATION}}

#define IDC_HOSTS		100

#endif // !defined(AFX_WNDHOSTCACHE_H__CF02C3BA_2D52_49F3_85C1_07365B714B3D__INCLUDED_)
