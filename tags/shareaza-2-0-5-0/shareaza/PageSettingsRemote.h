//
// PageSettingsRemote.h
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

#pragma once

#include "WndSettingsPage.h"


class CRemoteSettingsPage : public CSettingsPage
{
// Construction
public:
	CRemoteSettingsPage();
	virtual ~CRemoteSettingsPage();
	
	DECLARE_DYNAMIC(CRemoteSettingsPage)
	enum { IDD = IDD_SETTINGS_REMOTE };

// Attributes
protected:
	BOOL		m_bEnable;
	CStatic		m_wndURL;
	CEdit		m_wndUsername;
	CString		m_sUsername;
	CEdit		m_wndPassword;
	CString		m_sPassword;
protected:
	BOOL		m_bOldEnable;
	CString		m_sOldUsername;
	CString		m_sOldPassword;
	
// Operations
public:

// Implementation
protected:
	DECLARE_MESSAGE_MAP()
	virtual void DoDataExchange(CDataExchange* pDX);
	virtual BOOL OnInitDialog();
	afx_msg void OnNewPassword();
	afx_msg void OnBnClickedRemoteEnable();
	afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);
	afx_msg BOOL OnSetCursor(CWnd* pWnd, UINT nHitTest, UINT message);
	afx_msg void OnLButtonUp(UINT nFlags, CPoint point);
	virtual void OnCancel();
};