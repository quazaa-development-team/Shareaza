//
// DlgPluginExtSetup.h
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

#pragma once

class CPluginExtSetupDlg : public CDialog
{
	DECLARE_DYNAMIC(CPluginExtSetupDlg)

// Construction
public:
	CPluginExtSetupDlg(CWnd* pParent = NULL, LPCTSTR pszExt = NULL );
	virtual ~CPluginExtSetupDlg();

// Members
private:
	CListCtrl*	m_pParent;
	CString		m_sExtensions;
	BOOL		m_bRunning;
	TRISTATE	m_bParentState;

// Dialog Data
	//{{AFX_DATA(CPluginExtSetupDlg)
	enum { IDD = IDD_PLUGIN_EXT_SETUP };
	CListCtrl m_wndList;
	//}}AFX_DATA

// Overrides
protected:
	//{{AFX_VIRTUAL(CPluginExtSetupDlg)
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	//{{AFX_MSG(CPluginExtSetupDlg)
	virtual BOOL OnInitDialog();
	afx_msg void OnChangingAssociations(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnOK();
	//}}AFX_MSG

	DECLARE_MESSAGE_MAP()
};