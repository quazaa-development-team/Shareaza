//
// DlgBitziDownload.h
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

#if !defined(AFX_DLGBITZIDOWNLOAD_H__14C3A521_9E56_42DE_A449_75BAD986DFFC__INCLUDED_)
#define AFX_DLGBITZIDOWNLOAD_H__14C3A521_9E56_42DE_A449_75BAD986DFFC__INCLUDED_

#pragma once

#include "DlgSkinDialog.h"
#include "BitziDownloader.h"


class CBitziDownloadDlg : public CSkinDialog
{
// Construction
public:
	CBitziDownloadDlg(CWnd* pParent = NULL);

// Attributes
protected:
	CBitziDownloader	m_pDownloader;
	DWORD				m_nFailures;

// Operations
public:
	void	AddFile(DWORD nIndex);
	void	OnNextFile(DWORD nIndex);
	void	OnRequesting(DWORD nIndex, LPCTSTR pszName);
	void	OnSuccess(DWORD nIndex);
	void	OnFailure(DWORD nIndex, LPCTSTR pszMessage);
	void	OnFinishedFile(DWORD nIndex);

// Dialog Data
public:
	//{{AFX_DATA(CBitziDownloadDlg)
	enum { IDD = IDD_BITZI_DOWNLOAD };
	CStatic	m_wndWeb;
	CListCtrl	m_wndFiles;
	CButton	m_wndCancel;
	CProgressCtrl	m_wndProgress;
	//}}AFX_DATA

// Overrides
public:
	//{{AFX_VIRTUAL(CBitziDownloadDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	//{{AFX_MSG(CBitziDownloadDlg)
	virtual BOOL OnInitDialog();
	virtual void OnCancel();
	afx_msg void OnTimer(UINT nIDEvent);
	afx_msg BOOL OnSetCursor(CWnd* pWnd, UINT nHitTest, UINT message);
	afx_msg void OnLButtonDown(UINT nFlags, CPoint point);
	afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

//{{AFX_INSERT_LOCATION}}

#endif // !defined(AFX_DLGBITZIDOWNLOAD_H__14C3A521_9E56_42DE_A449_75BAD986DFFC__INCLUDED_)