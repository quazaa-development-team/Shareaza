//
// PageSettingsIRC.h
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
// Author: peer_l_@hotmail.com
//

#if !defined(AFX_PAGESETTINGSIRC__INCLUDED_)
#define AFX_PAGESETTINGSIRC__INCLUDED_

#pragma once

#include "WndSettingsPage.h"
#include "CtrlFontCombo.h"

class CIRCSettingsPage : public CSettingsPage
{
// Construction
public:
	CIRCSettingsPage();
	virtual ~CIRCSettingsPage();

	DECLARE_DYNCREATE(CIRCSettingsPage)
// Dialog Data
public:
	//{{AFX_DATA(CIRCSettingsPage)
	enum { IDD = IDD_SETTINGS_IRC };
	CButton m_wndColorServer;
	CButton	m_wndColorTopic;
	CButton	m_wndColorAction;
	CButton	m_wndColorNotice;
	CButton	m_wndColorBg;
	CButton	m_wndColorText;
	BOOL	m_bShow;
	BOOL	m_bFloodEnable;
	BOOL	m_bTimestamp;
	CString	m_sNick;
	CString	m_sAlternate;
	CString	m_sServerName;
	CString m_sUserName;
	CString m_sRealName;
	CString	m_sServerPort;
	CString	m_sFloodLimit;
	CString m_sScreenFont;
	CFontCombo m_wndFonts;
	//}}AFX_DATA

// Overrides
protected:
	//{{AFX_VIRTUAL(CIRCSettingsPage)
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	virtual BOOL OnInitDialog();
	virtual void OnDrawItem(int /* nIDCtl */, LPDRAWITEMSTRUCT lpDrawItemStruct);
	//}}AFX_VIRTUAL
public:
	//{{AFX_VIRTUAL(CButton)
	virtual void OnOK();
	virtual BOOL OnApply();
	//}}AFX_VIRTUAL

// Implementation
protected:
	//{{AFX_MSG(CIRCSettingsPage)
	afx_msg void OnBnClickedIrcColorServer();
	afx_msg void OnBnClickedIrcColorTopic();
	afx_msg void OnBnClickedIrcColorAction();
	afx_msg void OnBnClickedIrcColorNotice();
	afx_msg void OnBnClickedIrcColorBg();
	afx_msg void OnBnClickedIrcColorText();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

//{{AFX_INSERT_LOCATION}}

#endif // !defined(AFX_PAGESETTINGSIRC__INCLUDED_)
 
#define	ID_COLOR_SERVERMSG				2
#define	ID_COLOR_TOPIC					3
#define	ID_COLOR_CHANNELACTION			4
#define	ID_COLOR_NOTICE					5
#define	ID_COLOR_CHATBACK				7
#define ID_COLOR_TEXT					8
