//
// PageDownloadEditHashes.cpp
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
#include "PageDownloadEditHashes.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

#include "SHA.h"
#include "ED2K.h"
#include "TigerTree.h"

IMPLEMENT_DYNCREATE(CDownloadEditHashesPage, CDownloadEditPage)

BEGIN_MESSAGE_MAP(CDownloadEditHashesPage, CDownloadEditPage)
	ON_BN_CLICKED(IDC_DOWNLOADEDITPAGE_HASHES_APPLY, Apply)
END_MESSAGE_MAP()


//////////////////////////////////////////////////////////////////////////////
// CDownloadEditHashesPage construction
CDownloadEditHashesPage::CDownloadEditHashesPage() : CDownloadEditPage(IDD)
{
	m_psp.dwFlags |= PSP_USETITLE;
}

CDownloadEditHashesPage::~CDownloadEditHashesPage()
{
}

void CDownloadEditHashesPage::DoDataExchange(CDataExchange* pDX)
{
	DDX_Text(pDX, IDC_URN_SHA1, m_sSHA1);
	DDX_Text(pDX, IDC_URN_TIGER, m_sTiger);
	DDX_Text(pDX, IDC_URN_ED2K, m_sED2K);
	DDX_Check(pDX, IDC_TRUST_SHA1, m_bSHA1Trusted);
	DDX_Check(pDX, IDC_TRUST_TIGER, m_bTigerTrusted);
	DDX_Check(pDX, IDC_TRUST_ED2K, m_bED2KTrusted);
}

//////////////////////////////////////////////////////////////////////////////
// CDownloadEditHashesPage message handlers
BOOL CDownloadEditHashesPage::OnInitDialog()
{
	CDownloadEditPage::OnInitDialog();

	if ( m_pDownload->m_oSHA1 )
		m_sSHA1 = m_pDownload->m_oSHA1.toString();
	if ( m_pDownload->m_oTiger )
		m_sTiger = m_pDownload->m_oTiger.toString();
	if ( m_pDownload->m_oED2K )
        m_sED2K = m_pDownload->m_oED2K.toString();

	m_bSHA1Trusted	=	m_pDownload->m_oSHA1.isTrusted();
	m_bTigerTrusted	=	m_pDownload->m_oTiger.isTrusted();
	m_bED2KTrusted	=	m_pDownload->m_oED2K.isTrusted();
	
	UpdateData( FALSE );

	return TRUE;
}

void CDownloadEditHashesPage::Apply()
{
	Commit();
}

void CDownloadEditHashesPage::OnOK()
{
	if (!Commit()) 	return;
	CPropertyPage::OnOK();
}

BOOL CDownloadEditHashesPage::Commit()
{
	CString strMessage;

	UpdateData();
	
    Hashes::Sha1Hash oSHA1;
    oSHA1.fromString( m_sSHA1 );
    Hashes::TigerHash oTiger;
    oTiger.fromString( m_sTiger );
    Hashes::Ed2kHash oED2K;
    oED2K.fromString( m_sED2K );
	
	if ( m_sSHA1.GetLength() > 0 && !oSHA1 )
	{
		LoadString( strMessage, IDS_DOWNLOAD_EDIT_BAD_SHA1 );
		AfxMessageBox( strMessage, MB_ICONEXCLAMATION );
		return FALSE;
	}
	else if ( m_sTiger.GetLength() > 0 && !oTiger )
	{
		LoadString( strMessage, IDS_DOWNLOAD_EDIT_BAD_TIGER );
		AfxMessageBox( strMessage, MB_ICONEXCLAMATION );
		return FALSE;
	}
	else if ( m_sED2K.GetLength() > 0 && !oED2K )
	{
		LoadString( strMessage, IDS_DOWNLOAD_EDIT_BAD_ED2K );
		AfxMessageBox( strMessage, MB_ICONEXCLAMATION );
		return FALSE;
	}

	CSingleLock pLock( &Transfers.m_pSection, TRUE );
    if ( ! Downloads.Check( m_pDownload ) || m_pDownload->IsMoving() ) return FALSE;


	if ( m_pDownload->m_oSHA1.isValid() != oSHA1.isValid()
		|| validAndUnequal( m_pDownload->m_oSHA1, oSHA1 ) )
	{
		pLock.Unlock();
		LoadString( strMessage, IDS_DOWNLOAD_EDIT_CHANGE_SHA1 );
		if ( AfxMessageBox( strMessage, MB_ICONQUESTION|MB_YESNO ) != IDYES ) return FALSE;
		pLock.Lock();
		if ( ! Downloads.Check( m_pDownload ) || m_pDownload->IsMoving() ) return FALSE;
		
		m_pDownload->m_oSHA1 = oSHA1;
		if ( oSHA1 ) m_pDownload->m_oSHA1.signalTrusted();
		
		m_pDownload->CloseTransfers();
		m_pDownload->ClearVerification();
	}
	
	if ( m_pDownload->m_oTiger.isValid() != oTiger.isValid()
		|| validAndUnequal( m_pDownload->m_oTiger, oTiger ) )
	{
		pLock.Unlock();
		LoadString( strMessage, IDS_DOWNLOAD_EDIT_CHANGE_TIGER );
		if ( AfxMessageBox( strMessage, MB_ICONQUESTION|MB_YESNO ) != IDYES ) return FALSE;
		pLock.Lock();
		if ( ! Downloads.Check( m_pDownload ) || m_pDownload->IsMoving() ) return FALSE;
		
		m_pDownload->m_oTiger = oTiger;
		if ( oTiger ) m_pDownload->m_oTiger.signalTrusted();
		
		m_pDownload->CloseTransfers();
		m_pDownload->ClearVerification();
	}
	
	if ( m_pDownload->m_oED2K.isValid() != oED2K.isValid()
		|| validAndUnequal( m_pDownload->m_oED2K, oED2K ) )
	{
		pLock.Unlock();
		LoadString( strMessage, IDS_DOWNLOAD_EDIT_CHANGE_ED2K );
		if ( AfxMessageBox( strMessage, MB_ICONQUESTION|MB_YESNO ) != IDYES ) return FALSE;
		pLock.Lock();
		if ( ! Downloads.Check( m_pDownload ) || m_pDownload->IsMoving() ) return FALSE;
		
		m_pDownload->m_oED2K = oED2K;
		if ( oED2K ) m_pDownload->m_oED2K.signalTrusted();
		
		m_pDownload->CloseTransfers();
		m_pDownload->ClearVerification();
	}

	if ( m_bSHA1Trusted ) 
		m_pDownload->m_oSHA1.signalTrusted();
	else
		m_pDownload->m_oSHA1.signalUntrusted();

	if ( m_bTigerTrusted )
		m_pDownload->m_oTiger.signalTrusted();
	else
		m_pDownload->m_oTiger.signalUntrusted();

	if ( m_bED2KTrusted )
		m_pDownload->m_oED2K.signalTrusted();
	else
		m_pDownload->m_oED2K.signalUntrusted();

	return TRUE;
}



