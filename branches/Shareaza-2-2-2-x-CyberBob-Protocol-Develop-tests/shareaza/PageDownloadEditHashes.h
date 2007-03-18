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
#ifndef __PAGEDOWNLOADEDITHASHES__H_
#define __PAGEDOWNLOADEDITHASHES__H_

#pragma once

class CDownloadEditHashesPage : public CDownloadEditPage
{
public:
	CDownloadEditHashesPage();
	virtual ~CDownloadEditHashesPage(void);

	DECLARE_DYNCREATE(CDownloadEditHashesPage)

// Attributes
public:
	enum{ IDD = IDD_DOWNLOADEDITPAGE_HASHES };
	CString m_sFileSize;
	CString m_sSHA1;
	CString m_sTiger;
	CString m_sED2K;
	CString m_sMD5;
	BOOL m_bSHA1Trusted;
	BOOL m_bTigerTrusted;
	BOOL m_bED2KTrusted;
	BOOL m_bMD5Trusted;

	//Copy of data from Download
	QWORD				m_nSize;
	Hashes::Sha1Hash	m_oSHA1;
	Hashes::TigerHash	m_oTiger;
	Hashes::Ed2kHash	m_oED2K;
	Hashes::Md5Hash		m_oMD5;
	BOOL				m_bSHA1OldTrusted;
	BOOL				m_bTigerOldTrusted;
	BOOL				m_bED2KOldTrusted;
	BOOL				m_bMD5OldTrusted;

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
};

#endif //  __PAGEDOWNLOADEDITHASHES__H_
