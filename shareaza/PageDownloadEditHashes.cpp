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
	DDX_Text(pDX, IDC_FILESIZE, m_sFileSize);
	DDX_Text(pDX, IDC_URN_SHA1, m_sSHA1);
	DDX_Text(pDX, IDC_URN_TIGER, m_sTiger);
	DDX_Text(pDX, IDC_URN_ED2K, m_sED2K);
	DDX_Text(pDX, IDC_URN_MD5, m_sMD5);
	DDX_Check(pDX, IDC_TRUST_SHA1, m_bSHA1Trusted);
	DDX_Check(pDX, IDC_TRUST_TIGER, m_bTigerTrusted);
	DDX_Check(pDX, IDC_TRUST_ED2K, m_bED2KTrusted);
	DDX_Check(pDX, IDC_TRUST_MD5, m_bMD5Trusted);
}

//////////////////////////////////////////////////////////////////////////////
// CDownloadEditHashesPage message handlers
BOOL CDownloadEditHashesPage::OnInitDialog()
{
	CDownloadEditPage::OnInitDialog();

	CSingleLock pLock( &Transfers.m_pSection, TRUE );
	if ( ! Downloads.Check( m_pDownload ) || m_pDownload->IsMoving() || m_pDownload->IsCompleted() ) return FALSE;

	m_oSHA1		= m_pDownload->m_oSHA1;
	m_oTiger	= m_pDownload->m_oTiger;
	m_oED2K		= m_pDownload->m_oED2K;
	m_oMD5		= m_pDownload->m_oMD5;
	m_nSize		= m_pDownload->m_nSize;

	m_bSHA1Trusted	=	m_pDownload->m_oSHA1.isTrusted();
	m_bTigerTrusted	=	m_pDownload->m_oTiger.isTrusted();
	m_bED2KTrusted	=	m_pDownload->m_oED2K.isTrusted();
	m_bMD5Trusted	=	m_pDownload->m_oMD5.isTrusted();
	pLock.Unlock();

	if ( m_nSize != SIZE_UNKNOWN )
		m_sFileSize.Format( _T("%I64i"), m_nSize );
	if ( m_oSHA1 )
		m_sSHA1 = m_oSHA1.toString();
	if ( m_oTiger )
		m_sTiger = m_oTiger.toString();
	if ( m_oED2K )
		m_sED2K = m_oED2K.toString();
	if ( m_oMD5 )
		m_sMD5 = m_oMD5.toString();

	m_bSHA1OldTrusted = m_bSHA1Trusted;
	m_bTigerOldTrusted = m_bTigerTrusted;
	m_bED2KOldTrusted = m_bED2KTrusted;
	m_bMD5OldTrusted = m_bMD5Trusted;

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

	Hashes::Sha1Hash oSHA1;
    Hashes::TigerHash oTiger;
	Hashes::Ed2kHash oED2K;
	Hashes::Md5Hash oMD5;

	bool	bSizeChanged	= false,
			bSHA1Changed	= false,
			bTigerChanged	= false,
			bED2KChanged	= false,
			bMD5Changed		= false;

	UpdateData();
	oSHA1.fromString( m_sSHA1 );
	oTiger.fromString( m_sTiger );
	oED2K.fromString( m_sED2K );
	oMD5.fromString( m_sMD5 );

	bool	bNeedUpdate = false,
			bCriticalChange = false;

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
	else if ( m_sMD5.GetLength() > 0 && !oMD5 )
	{
		LoadString( strMessage, IDS_DOWNLOAD_EDIT_BAD_ED2K );
		AfxMessageBox( strMessage, MB_ICONEXCLAMATION );
		return FALSE;
	}

	QWORD nNewSize = 0;
	if ( _stscanf( m_sFileSize, _T("%I64i"), &nNewSize ) == 1 && nNewSize != m_nSize )
	{
		LoadString( strMessage, IDS_DOWNLOAD_EDIT_CHANGE_SIZE );
		if ( AfxMessageBox( strMessage, MB_ICONQUESTION|MB_YESNO ) != IDYES ) return FALSE;
		bSizeChanged = true;
	}

	if ( m_oSHA1.isValid() != oSHA1.isValid()
		|| validAndUnequal( m_oSHA1, oSHA1 ) )
	{
		LoadString( strMessage, IDS_DOWNLOAD_EDIT_CHANGE_SHA1 );
		if ( AfxMessageBox( strMessage, MB_ICONQUESTION|MB_YESNO ) != IDYES ) return FALSE;
		bSHA1Changed = true;
	}
	
	if ( m_oTiger.isValid() != oTiger.isValid()
		|| validAndUnequal( m_oTiger, oTiger ) )
	{
		LoadString( strMessage, IDS_DOWNLOAD_EDIT_CHANGE_TIGER );
		if ( AfxMessageBox( strMessage, MB_ICONQUESTION|MB_YESNO ) != IDYES ) return FALSE;
		bTigerChanged = true;
	}
	
	if ( m_oED2K.isValid() != oED2K.isValid()
		|| validAndUnequal( m_oED2K, oED2K ) )
	{
		LoadString( strMessage, IDS_DOWNLOAD_EDIT_CHANGE_ED2K );
		if ( AfxMessageBox( strMessage, MB_ICONQUESTION|MB_YESNO ) != IDYES ) return FALSE;
		bED2KChanged = true;
	}

	if ( m_oMD5.isValid() != oMD5.isValid()
		|| validAndUnequal( m_oMD5, oMD5 ) )
	{
		//LoadString( strMessage, IDS_DOWNLOAD_EDIT_CHANGE_ED2K );
		strMessage = "If you change MD5 hash, you might make your download not downloadable";
		strMessage += "Are you Sure you wanna change MD5 hash?";
		if ( AfxMessageBox( strMessage, MB_ICONQUESTION|MB_YESNO ) != IDYES ) return FALSE;
		bMD5Changed = true;
	}

	if ( bSizeChanged || bSHA1Changed || bTigerChanged || bED2KChanged || bMD5Changed ) bCriticalChange = true;
	else if ( ( m_bSHA1Trusted != m_bSHA1OldTrusted ) ||
			( m_bTigerTrusted != m_bTigerOldTrusted ) ||
			( m_bED2KTrusted != m_bED2KOldTrusted ) ||
			( m_bMD5Trusted != m_bMD5OldTrusted ) )
	{
		bNeedUpdate = true;
	}

	if ( bNeedUpdate || bCriticalChange )
	{
		CSingleLock pLock( &Transfers.m_pSection, TRUE );
		if ( ! Downloads.Check( m_pDownload ) || m_pDownload->IsMoving() || m_pDownload->IsCompleted() ) return FALSE;

		if ( bSizeChanged )		m_pDownload->m_nSize	= nNewSize;
		if ( bSHA1Changed )		m_pDownload->m_oSHA1	= oSHA1;
		if ( bTigerChanged )	m_pDownload->m_oTiger	= oTiger;
		if ( bED2KChanged )		m_pDownload->m_oED2K	= oED2K;
		if ( bMD5Changed )		m_pDownload->m_oMD5		= oMD5;

		if ( m_bSHA1Trusted )
		{
			m_pDownload->m_oSHA1.signalTrusted();
		}
		else
		{
			m_pDownload->m_oSHA1.signalUntrusted();
		}

		if ( m_bTigerTrusted )
		{
			m_pDownload->m_oTiger.signalTrusted();
		}
		else
		{
			m_pDownload->m_oTiger.signalUntrusted();
		}

		if ( m_bED2KTrusted )
		{
			m_pDownload->m_oED2K.signalTrusted();
		}
		else
		{
			m_pDownload->m_oED2K.signalUntrusted();
		}

		if ( m_bMD5Trusted )
		{
			m_pDownload->m_oMD5.signalTrusted();
		}
		else
		{
			m_pDownload->m_oMD5.signalUntrusted();
		}

		if ( bCriticalChange )
		{
			DWORD tNow = GetTickCount();
			m_pDownload->CloseTransfers();
			m_pDownload->ClearSources();
			m_pDownload->ClearFailedSources();
			m_pDownload->ClearVerification();
			if ( !m_pDownload->IsPaused() )
			{
				m_pDownload->StopSearch( tNow, FALSE );
				m_pDownload->StartManualSearch( tNow );
			}
			m_pDownload->SetModified();
		}
		pLock.Unlock();
	}

	return TRUE;
}



