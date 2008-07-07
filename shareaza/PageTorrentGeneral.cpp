//
// PageTorrentGeneral.cpp
//
// Copyright (c) Shareaza Development Team, 2002-2007.
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

#include "StdAfx.h"
#include "Shareaza.h"
#include "Settings.h"

#include "DlgDownloadSheet.h"
#include "PageTorrentGeneral.h"
#include "Transfers.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

IMPLEMENT_DYNCREATE(CTorrentGeneralPage, CPropertyPageAdv)

BEGIN_MESSAGE_MAP(CTorrentGeneralPage, CPropertyPageAdv)
	//{{AFX_MSG_MAP(CTorrentGeneralPage)
	ON_WM_PAINT()
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()


/////////////////////////////////////////////////////////////////////////////
// CTorrentGeneralPage property page

CTorrentGeneralPage::CTorrentGeneralPage() : 
	CPropertyPageAdv( CTorrentGeneralPage::IDD )
{
}

CTorrentGeneralPage::~CTorrentGeneralPage()
{
}

void CTorrentGeneralPage::DoDataExchange(CDataExchange* pDX)
{
	CPropertyPageAdv::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CTorrentGeneralPage)
	DDX_Text(pDX, IDC_TORRENT_NAME, m_sName);
	DDX_Text(pDX, IDC_TORRENT_COMMENTS, m_sComment);
	DDX_Text(pDX, IDC_TORRENT_CREATEDBY, m_sCreatedBy );
	DDX_Text(pDX, IDC_TORRENT_CREATIONDATE, m_sCreationDate );
	DDX_Text(pDX, IDC_TORRENT_OTHER, m_sTorrentOther );
	DDX_Control(pDX, IDC_TORRENT_STARTDOWNLOADS, m_wndStartDownloads);
	DDX_Text(pDX, IDC_TORRENT_UPLOADTOTAL, m_sUploadTotal );
	//}}AFX_DATA_MAP
}

/////////////////////////////////////////////////////////////////////////////
// CTorrentGeneralPage message handlers

BOOL CTorrentGeneralPage::OnInitDialog()
{
	CPropertyPageAdv::OnInitDialog();

	CSingleLock pLock( &Transfers.m_pSection, TRUE );
	CBTInfo* pInfo = &((CDownloadSheet*)GetParent())->m_pDownload->m_pTorrent;

	m_sName			= pInfo->m_sName;
	m_sComment		= pInfo->m_sComment;
	m_sCreatedBy	= pInfo->m_sCreatedBy;
	if ( pInfo->m_tCreationDate > 0 )
	{
		CTime pTime( (time_t)pInfo->m_tCreationDate );
		m_sCreationDate = pTime.Format( _T("%Y-%m-%d  %H:%M") );
	}

	// Assember 'other' string
	if ( pInfo->m_bPrivate )
	{
		CString str;
		LoadString( str, IDS_BT_PRIVATE );
		m_sTorrentOther += str;
		m_sTorrentOther += _T(", ");
	}
	if ( pInfo->HasEncodingError() )
	{
		CString str;
		LoadString( str, IDS_BT_ENCODING );
		m_sTorrentOther += str;
		m_sTorrentOther += _T(", ");
	}

	// Cut off last comma
	if ( m_sTorrentOther.GetLength() )
		m_sTorrentOther = m_sTorrentOther.Left( m_sTorrentOther.GetLength() - 2 );

	m_wndStartDownloads.SetItemData( 0, dtAlways );
	m_wndStartDownloads.SetItemData( 1, dtWhenRatio );
	m_wndStartDownloads.SetItemData( 2, dtNever );

	m_wndStartDownloads.SetCurSel( pInfo->m_nStartDownloads );

	m_sUploadTotal.Format( _T(" %s"),
		(LPCTSTR)Settings.SmartVolume( pInfo->m_nTotalUpload ) );

	UpdateData( FALSE );
	
	return TRUE;
}

void CTorrentGeneralPage::OnOK()
{
	UpdateData();

	CSingleLock pLock( &Transfers.m_pSection, TRUE );
	CBTInfo* pInfo = &((CDownloadSheet*)GetParent())->m_pDownload->m_pTorrent;

	// Update the starting of torrent transfers
	pInfo->m_nStartDownloads = m_wndStartDownloads.GetCurSel();
	if ( pInfo->m_nStartDownloads > dtNever )
		pInfo->m_nStartDownloads = dtAlways;
	
	CPropertyPageAdv::OnOK();
}
