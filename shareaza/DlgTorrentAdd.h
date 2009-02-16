//
// DlgTorrentAdd.h
//
// Copyright (c) Shareaza Development Team, 2002-2009.
// This file is part of SHAREAZA (shareaza.sourceforge.net)
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

// DlgTorrentAdd.cpp : implementation file
//
#pragma once

#include "LTHookTorrent.hpp"
#include "CtrlIconButton.h"
#include "DlgSkinDialog.h"


// CTorrentAddDialog dialog

class CTorrentAddDlg : public CDialog
{
	DECLARE_DYNAMIC(CTorrentAddDlg)

public:
	CTorrentAddDlg(CWnd* pParent = NULL, wstring& sSaveFolder, wstring& sTempFolder, bool& bUseTemp, bool& bManagedTorrent, bool& bPausedTorrent, LTHook::bit::allocations& nAllocationType);   // standard constructor
	virtual ~CTorrentAddDlg();

// Dialog Data
	enum { IDD = IDD_TORRENT_ADD };
	CIconButtonCtrl	m_wndSavePath;
	CIconButtonCtrl	m_wndTempPath;
	CString         m_sSavePath;
	CString         m_sTempPath;
	BOOL            m_bUseTemp;
	BOOL            m_bManagedTorrent;
	BOOL            m_bPauseTorrent;
	CComboBox       m_wndAllocationMode;


protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnOk();
	afx_msg void OnCompleteBrowse();
	afx_msg void OnTempBrowse();
	afx_msg void OnSelchangeComboAllocation();
	afx_msg void OnChangeCheckTemp();
	afx_msg void OnChangeCheckManaged();
	afx_msg void OnChangeCheckPaused();
	afx_msg void OnChangeEditSave();
	afx_msg void OnChangeEditTemp();
protected:
	// Special processing when the dialog box is initialized
	virtual BOOL OnInitDialog();
};
