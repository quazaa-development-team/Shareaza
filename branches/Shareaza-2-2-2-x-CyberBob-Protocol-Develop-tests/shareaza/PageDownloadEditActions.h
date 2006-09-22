//
// PageDownloadEditGeneral.h
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
#ifndef __PAGEDOWNLOADEDITACTIONS__H_
#define __PAGEDOWNLOADEDITACTIONS__H_

#pragma once
#include "DlgDownloadEditPage.h"

#pragma once

class CDownloadEditActionsPage : public CDownloadEditPage
{
public:
	CDownloadEditActionsPage();
	virtual ~CDownloadEditActionsPage(void);

	DECLARE_DYNCREATE(CDownloadEditActionsPage)
	enum{ IDD = IDD_DOWNLOADEDITPAGE_ACTIONS };

	CDownloadEditSheet * pParent;

// Attributes
public:
	CStatic m_wndPurgeHashset;
	CStatic m_wndForgetVerify;
	CStatic m_wndForgetSources;
	CString m_sEraseFrom;
	CString m_sEraseTo;
	CButton m_wndTorrent;
	CStatic m_wndCompleteVerify;
	CStatic m_wndMergeVerify;

// Operations
public:

// Implementation
protected:
	virtual void DoDataExchange(CDataExchange* pDX);
	virtual BOOL OnInitDialog();
	afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);
	afx_msg BOOL OnSetCursor(CWnd* pWnd, UINT nHitTest, UINT message);
	afx_msg void OnLButtonUp(UINT nFlags, CPoint point);
	afx_msg void OnErase();
	afx_msg void OnMergeAndVerify();
	DECLARE_MESSAGE_MAP()
};

#endif //  __PAGEDOWNLOADEDITACTIONS__H_
