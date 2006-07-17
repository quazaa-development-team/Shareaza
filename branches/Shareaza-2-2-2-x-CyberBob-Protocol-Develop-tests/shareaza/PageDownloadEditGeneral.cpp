//
// PageDownloadEditGeneral.cpp
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

#include "StdAfx.h"
#include "Shareaza.h"
#include "CoolInterface.h"
#include "ShellIcons.h"
#include "Skin.h"
#include "download.h"
#include "downloads.h"
#include "Transfers.h"
#include "FragmentedFile.h"
#include "DlgDownloadEditSheet.h"
#include "DlgDownloadEditPage.h"
#include "PageDownloadEditGeneral.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


IMPLEMENT_DYNCREATE( CDownloadEditGeneralPage, CDownloadEditPage )

BEGIN_MESSAGE_MAP( CDownloadEditGeneralPage, CDownloadEditPage )
	ON_BN_CLICKED(IDC_DOWNLOADEDITPAGE_GENERAL_APPLY, Apply)
END_MESSAGE_MAP()



CDownloadEditGeneralPage::CDownloadEditGeneralPage() : CDownloadEditPage(IDD)
{
	m_psp.dwFlags |= PSP_USETITLE;
}

CDownloadEditGeneralPage::~CDownloadEditGeneralPage(void)
{
}

void CDownloadEditGeneralPage::DoDataExchange(CDataExchange* pDX)
{
	DDX_Text(pDX, IDC_NAME, m_sName);
	DDX_Text(pDX, IDC_DISKNAME, m_sDiskName);
	DDX_Text(pDX, IDC_FILESIZE, m_sFileSize);
	DDX_Text(pDX, IDC_SEARCHKEYWORD, m_sSearchKeyword);
}

BOOL CDownloadEditGeneralPage::OnInitDialog()
{
	CDownloadEditPage::OnInitDialog();

	m_sName = m_pDownload->m_sDisplayName;
	m_sDiskName = m_pDownload->m_sDiskName;
	if ( m_pDownload->m_nSize != SIZE_UNKNOWN )
		m_sFileSize.Format( _T("%I64i"), m_pDownload->m_nSize );
	m_sSearchKeyword = m_pDownload->m_sSearchKeyword;

	UpdateData( FALSE );

	return TRUE;
}

BOOL CDownloadEditGeneralPage::Commit()
{
	CString strMessage;

	UpdateData();

	CSingleLock pLock( &Transfers.m_pSection, TRUE );
    if ( ! Downloads.Check( m_pDownload ) || m_pDownload->IsMoving() ) return FALSE;

	if ( m_pDownload->m_sDisplayName != m_sName )
	{
		pLock.Unlock();
		LoadString( strMessage, IDS_DOWNLOAD_EDIT_RENAME );
		if ( AfxMessageBox( strMessage, MB_ICONQUESTION|MB_YESNO ) != IDYES ) return FALSE;
		pLock.Lock();
		if ( ! Downloads.Check( m_pDownload ) || m_pDownload->IsMoving() ) return FALSE;

		m_pDownload->Rename( m_sName );
	}

	if ( m_pDownload->m_sSearchKeyword != m_sSearchKeyword )
	{
		pLock.Unlock();
//		LoadString( strMessage, IDS_DOWNLOAD_EDIT_RENAME );
		strMessage = "If you change search keyword, you might get your Download with no source specially for files exist only in G1 network.";
		strMessage += "Are you Sure you wanna change Search Keyword?";
		if ( AfxMessageBox( strMessage, MB_ICONQUESTION|MB_YESNO ) != IDYES ) return FALSE;
		pLock.Lock();
		if ( ! Downloads.Check( m_pDownload ) || m_pDownload->IsMoving() ) return FALSE;

		m_pDownload->m_sSearchKeyword = m_sSearchKeyword;
		m_pDownload->SetModified();
	}

	QWORD nNewSize = 0;
    if ( _stscanf( m_sFileSize, _T("%I64i"), &nNewSize ) == 1 && nNewSize != m_pDownload->m_nSize )
	{
		pLock.Unlock();
		LoadString( strMessage, IDS_DOWNLOAD_EDIT_CHANGE_SIZE );
		if ( AfxMessageBox( strMessage, MB_ICONQUESTION|MB_YESNO ) != IDYES ) return FALSE;
		pLock.Lock();
		if ( ! Downloads.Check( m_pDownload ) || m_pDownload->IsMoving() ) return FALSE;
		m_pDownload->m_nSize = nNewSize;
		m_pDownload->SetModified();
	}
	return TRUE;
}

void CDownloadEditGeneralPage::Apply()
{
	Commit();
}

void CDownloadEditGeneralPage::OnOK()
{
	if (!Commit()) 	return;
	CPropertyPage::OnOK();
}
