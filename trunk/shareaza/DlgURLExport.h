//
// DlgURLExport.h
//
// Copyright (c) Shareaza Development Team, 2002-2007.
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

#if !defined(AFX_DLGURLEXPORT_H__1B69A614_F171_4EE4_925E_FEDBBAF13A0D__INCLUDED_)
#define AFX_DLGURLEXPORT_H__1B69A614_F171_4EE4_925E_FEDBBAF13A0D__INCLUDED_

#pragma once

#include "DlgSkinDialog.h"
#include "ShareazaFile.h"

class CURLExportDlg : public CSkinDialog
{
	DECLARE_DYNAMIC(CURLExportDlg)

public:
	CURLExportDlg(CWnd* pParent = NULL);

public:
	enum { IDD = IDD_URL_EXPORT };
	CButton			m_wndSave;
	CButton			m_wndCopy;
	CProgressCtrl	m_wndProgress;
	CComboBox		m_wndToken;
	CComboBox		m_wndPreset;
	CEdit			m_wndFormat;
	CStatic			m_wndMessage;
	CString			m_sFormat;

	void		Add(const CShareazaFile* pFile);

protected:
	CList< const CShareazaFile* >	m_pFiles;

	void		MakeURL(const CShareazaFile* pFile, CString& strLine);

	virtual void DoDataExchange(CDataExchange* pDX);
	virtual BOOL OnInitDialog();
	afx_msg void OnCloseUpUrlToken();
	afx_msg void OnSelChangeUrlPreset();
	afx_msg void OnKillFocusUrlPreset();
	afx_msg void OnSave();
	afx_msg void OnCopy();

	DECLARE_MESSAGE_MAP()

};

#endif // !defined(AFX_DLGURLEXPORT_H__1B69A614_F171_4EE4_925E_FEDBBAF13A0D__INCLUDED_)
