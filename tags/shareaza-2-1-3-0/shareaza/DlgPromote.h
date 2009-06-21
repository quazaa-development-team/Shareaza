//
// DlgPromote.h
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

#if !defined(AFX_DLGPROMOTE_H__2EAEB2FC_31CD_4B1D_92D6_75FB346C8B8A__INCLUDED_)
#define AFX_DLGPROMOTE_H__2EAEB2FC_31CD_4B1D_92D6_75FB346C8B8A__INCLUDED_

#pragma once

#include "DlgSkinDialog.h"


class CPromoteDlg : public CSkinDialog
{
// Construction
public:
	CPromoteDlg(CWnd* pParent = NULL);

// Dialog Data
public:
	//{{AFX_DATA(CPromoteDlg)
	enum { IDD = IDD_PROMOTE };
	CStatic	m_wndWeb;
	CStatic	m_wndTitle;
	//}}AFX_DATA

	COLORREF	m_crWhite;
	CBrush		m_brWhite;

// Overrides
public:
	//{{AFX_VIRTUAL(CPromoteDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	//{{AFX_MSG(CPromoteDlg)
	afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);
	afx_msg BOOL OnSetCursor(CWnd* pWnd, UINT nHitTest, UINT message);
	afx_msg void OnLButtonUp(UINT nFlags, CPoint point);
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	//}}AFX_MSG

	DECLARE_MESSAGE_MAP()

};

//{{AFX_INSERT_LOCATION}}

#endif // !defined(AFX_DLGPROMOTE_H__2EAEB2FC_31CD_4B1D_92D6_75FB346C8B8A__INCLUDED_)