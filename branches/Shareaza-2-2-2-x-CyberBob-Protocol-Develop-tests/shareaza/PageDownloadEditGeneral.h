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
#ifndef __PAGEDOWNLOADEDITGENERAL__H_
#define __PAGEDOWNLOADEDITGENERAL__H_

#pragma once
#include "DlgDownloadEditPage.h"

class CDownloadEditGeneralPage : public CDownloadEditPage
{
public:
	CDownloadEditGeneralPage();
	virtual ~CDownloadEditGeneralPage(void);

	DECLARE_DYNCREATE(CDownloadEditGeneralPage)
	enum{ IDD = IDD_DOWNLOADEDITPAGE_GENERAL };

// Attributes
public:
	CString m_sName;
	CString m_sDiskName;
	CString m_sFileSize;
	CString m_sSearchKeyword;

// Operations
public:
	BOOL	Commit();
	void	Apply();

// Implementation
protected:
	virtual void DoDataExchange(CDataExchange* pDX);
	virtual BOOL OnInitDialog();
	virtual	void OnOK();
	DECLARE_MESSAGE_MAP()
//	afx_msg void OnTorrentInfo();
};

#endif //  __PAGEDOWNLOADEDITGENERAL__H_
