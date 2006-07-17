//
// DlgDownloadEditSheet.h
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

#ifndef __DLGDOWNLOADEDITSHEET__H_
#define __DLGDOWNLOADEDITSHEET__H_

#pragma once


class	CDownloadEditGeneralPage;
class	CDownloadEditHashesPage;
class	CDownloadEditActionsPage;

class CDownloadEditSheet : public CPropertySheet
{
public:
	CDownloadEditSheet(CDownload* pDownload);
	virtual ~CDownloadEditSheet(void);

	DECLARE_DYNAMIC(CDownloadEditSheet)

// Attributes
public:
	CDownload*	m_pDownload;
protected:
	CSkinWindow*	m_pSkin;
	CBrush			m_brDialog;
	CDownloadEditGeneralPage*		m_pGeneral;
	CDownloadEditHashesPage*		m_pHashes;
	CDownloadEditActionsPage*		m_pActions;
	CString			m_sGeneralTitle;
	CString			m_sHashesTitle;
	CString			m_sActionsTitle;

	// Overrides
public:
	//{{AFX_VIRTUAL(CDownloadEditSheet)
public:
	virtual INT_PTR DoModal(int nPage = -1);
	virtual BOOL OnInitDialog();
	//}}AFX_VIRTUAL

// Implementation
protected:
	void SetTabTitle(CPropertyPage* pPage, CString& strTitle);

	//{{AFX_MSG(CDownloadEditSheet)
	afx_msg void OnNcCalcSize(BOOL bCalcValidRects, NCCALCSIZE_PARAMS FAR* lpncsp);
	afx_msg ONNCHITTESTRESULT OnNcHitTest(CPoint point);
	afx_msg BOOL OnNcActivate(BOOL bActive);
	afx_msg void OnNcPaint();
	afx_msg void OnNcLButtonDown(UINT nHitTest, CPoint point);
	afx_msg void OnNcLButtonUp(UINT nHitTest, CPoint point);
	afx_msg void OnNcLButtonDblClk(UINT nHitTest, CPoint point);
	afx_msg void OnNcMouseMove(UINT nHitTest, CPoint point);
	afx_msg void OnSize(UINT nType, int cx, int cy);
	afx_msg BOOL OnEraseBkgnd(CDC* pDC);
	afx_msg LRESULT OnSetText(WPARAM wParam, LPARAM lParam);
	afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);
	afx_msg BOOL OnHelpInfo(HELPINFO* pHelpInfo);
public:
	afx_msg void OnClose();		// Quick and dirty hack
	//}}AFX_MSG

	DECLARE_MESSAGE_MAP()
};

//{{AFX_INSERT_LOCATION}}

#endif // __DLGDOWNLOADEDITSHEET__H_
