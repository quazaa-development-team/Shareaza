//
// CtrlMatch.h
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

#if !defined(AFX_CTRLMATCH_H__7AF5A040_15D1_4BC1_A384_3C27F226F878__INCLUDED_)
#define AFX_CTRLMATCH_H__7AF5A040_15D1_4BC1_A384_3C27F226F878__INCLUDED_

#pragma once

#include "CtrlMatchTip.h"

class CMatchList;
class CMatchFile;
class CQueryHit;
class CSchema;


class CMatchCtrl : public CWnd
{
// Construction
public:
	CMatchCtrl();
	virtual ~CMatchCtrl();

// Attributes
public:
	CMatchList*		m_pMatches;
	LPCTSTR			m_sType;
	CSchema*		m_pSchema;
	CPtrList		m_pColumns;
protected:
	CHeaderCtrl		m_wndHeader;
	CMatchTipCtrl	m_wndTip;
	CImageList		m_pStars;
protected:
	DWORD			m_nTopIndex;
	DWORD			m_nHitIndex;
	DWORD			m_nBottomIndex;
	DWORD			m_nFocus;
	int				m_nPageCount;
	int				m_nCurrentWidth;
	DWORD			m_nCacheItems;
	int				m_nTrailWidth;	
	UINT			m_nMessage;
	CString			m_sMessage;
	BOOL			m_bSearchLink;
	CBitmap			m_bmSortAsc;
	CBitmap			m_bmSortDesc;
	BOOL			m_bTips;

// Operations
public:
	void	Update();
	void	DestructiveUpdate();
	void	SelectSchema(CSchema* pSchema, CPtrList* pColumns);
	void	SetBrowseMode();
	BOOL	HitTestHeader(const CPoint& point);
	void	SetSortColumn(int nColumn = -1, BOOL bDirection = FALSE);
	void	SetMessage(UINT nMessageID, BOOL bLink = FALSE);
	void	SetMessage(LPCTSTR pszMessage, BOOL bLink = FALSE);
	void	EnableTips(BOOL bTips);
protected:
	void	InsertColumn(int nColumn, LPCTSTR pszCaption, int nFormat, int nWidth);
	void	SaveColumnState();
	BOOL	LoadColumnState();
	void	UpdateScroll(DWORD nScroll = 0xFFFFFFFF);
	void	ScrollBy(int nDelta);
	void	ScrollTo(DWORD nIndex);
	void	DrawItem(CDC& dc, CRect& rc, CMatchFile* pFile, CQueryHit* pHit, BOOL bFocus);
	void	DrawStatus(CDC& dc, CRect& rcCol, CMatchFile* pFile, CQueryHit* pHit, BOOL bSelected, COLORREF crBack);
	void	DrawRating(CDC& dc, CRect& rcCol, int nRating, BOOL bSelected, COLORREF crBack);
	void	DrawEmptyMessage(CDC& dc, CRect& rcClient);
	BOOL	HitTest(const CPoint& point, CMatchFile** poFile, CQueryHit** poHit, DWORD* pnIndex = NULL, CRect* pRect = NULL);
	BOOL	GetItemRect(CMatchFile* pFindFile, CQueryHit* pFindHit, CRect* pRect);
	BOOL	PixelTest(const CPoint& point);
	void	MoveFocus(int nDelta, BOOL bShift);
	void	NotifySelection();
	void	DoDelete();
	void	DoExpand(BOOL bExpand);
	
// Overrides
public:
	//{{AFX_VIRTUAL(CMatchCtrl)
	public:
	virtual BOOL Create(CMatchList* pMatches, CWnd* pParentWnd);
	//}}AFX_VIRTUAL

// Implementation
public:
	DECLARE_MESSAGE_MAP()
	afx_msg int OnCreate(LPCREATESTRUCT lpCreateStruct);
	afx_msg void OnDestroy();
	afx_msg void OnSize(UINT nType, int cx, int cy);
	afx_msg BOOL OnEraseBkgnd(CDC* pDC);
	afx_msg void OnPaint();
	afx_msg void OnVScroll(UINT nSBCode, UINT nPos, CScrollBar* pScrollBar);
	afx_msg void OnLButtonDown(UINT nFlags, CPoint point);
	afx_msg void OnMouseMove(UINT nFlags, CPoint point);
	afx_msg void OnLButtonUp(UINT nFlags, CPoint point);
	afx_msg void OnLButtonDblClk(UINT nFlags, CPoint point);
	afx_msg void OnKeyDown(UINT nChar, UINT nRepCnt, UINT nFlags);
	afx_msg void OnRButtonDown(UINT nFlags, CPoint point);
	afx_msg void OnRButtonUp(UINT nFlags, CPoint point);
	afx_msg BOOL OnSetCursor(CWnd* pWnd, UINT nHitTest, UINT message);
	afx_msg BOOL OnMouseWheel(UINT nFlags, short zDelta, CPoint pt);
	afx_msg void OnHScroll(UINT nSBCode, UINT nPos, CScrollBar* pScrollBar);
	afx_msg void OnTimer(UINT nIDEvent);
	afx_msg void OnChangeHeader(NMHDR* pNotifyStruct, LRESULT* pResult);
	afx_msg void OnClickHeader(NMHDR* pNotifyStruct, LRESULT* pResult);
	afx_msg void OnSetFocus(CWnd* pOldWnd);
	afx_msg void OnKillFocus(CWnd* pNewWnd);

};

//{{AFX_INSERT_LOCATION}}

#define MATCH_COL_NAME		0
#define MATCH_COL_TYPE		1
#define MATCH_COL_SIZE		2
#define MATCH_COL_RATING	3
#define MATCH_COL_STATUS	4
#define MATCH_COL_COUNT		5
#define MATCH_COL_SPEED		6
#define MATCH_COL_CLIENT	7
#define MATCH_COL_MAX		8

#define IDC_MATCHES			100
#define IDC_MATCH_HEADER	115

#endif // !defined(AFX_CTRLMATCH_H__7AF5A040_15D1_4BC1_A384_3C27F226F878__INCLUDED_)