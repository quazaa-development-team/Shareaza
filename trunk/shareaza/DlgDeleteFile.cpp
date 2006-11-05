//
// DlgDeleteFile.cpp
//
// Copyright (c) Shareaza Development Team, 2002-2006.
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
#include "DlgDeleteFile.h"

#include "Library.h"
#include "SharedFile.h"
#include "Download.h"
#include "ShellIcons.h"
#include "Settings.h"

IMPLEMENT_DYNAMIC(CDeleteFileDlg, CSkinDialog)

BEGIN_MESSAGE_MAP(CDeleteFileDlg, CSkinDialog)
	ON_WM_CTLCOLOR()
	ON_WM_MEASUREITEM()
	ON_WM_DRAWITEM()
	ON_CBN_SELCHANGE(IDC_DELETE_OPTIONS, OnCbnChangeOptions)
	ON_BN_CLICKED(IDC_DELETE_ALL, OnDeleteAll)
	ON_CBN_SELCHANGE(IDC_GHOST_RATING, OnCbnChangeGhostRating)
	ON_EN_CHANGE(IDC_RATE_COMMENTS, OnChangeComments)
	ON_BN_CLICKED(IDC_CREATE_GHOST, OnClickedCreateGhost)
END_MESSAGE_MAP()


CDeleteFileDlg::CDeleteFileDlg(CWnd* pParent) : CSkinDialog( CDeleteFileDlg::IDD, pParent )
, m_nOption(0)
, m_bCreateGhost(Settings.Library.CreateGhosts)
, m_nRateValue(0)
, m_bAll(FALSE)
{
}

CDeleteFileDlg::~CDeleteFileDlg()
{
}

void CDeleteFileDlg::DoDataExchange(CDataExchange* pDX)
{
	CSkinDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_FILE_NAME, m_wndName);
	DDX_Control(pDX, IDC_RATE_COMMENTS, m_wndComments);
	DDX_Text(pDX, IDC_RATE_COMMENTS, m_sComments);
	DDX_Text(pDX, IDC_FILE_NAME, m_sName);
	DDX_Control(pDX, IDOK, m_wndOK);
	DDX_Control(pDX, IDC_DELETE_ALL, m_wndAll);
	DDX_Control(pDX, IDC_DELETE_OPTIONS, m_wndOptions);
	DDX_CBIndex(pDX, IDC_DELETE_OPTIONS, m_nOption);
	DDX_Control(pDX, IDC_GHOST_RATING, m_wndRating);
	DDX_CBIndex(pDX, IDC_GHOST_RATING, m_nRateValue);
	DDX_Check(pDX, IDC_CREATE_GHOST, m_bCreateGhost);
}

BOOL CDeleteFileDlg::OnInitDialog()
{
	CSkinDialog::OnInitDialog();

	SkinMe( NULL, ID_LIBRARY_DELETE );

	if ( m_bAll )
	{
		m_wndAll.EnableWindow( TRUE );
		m_bAll = FALSE;
	}
	RecalcDropWidth( &m_wndOptions );
	UpdateData( FALSE );

	return FALSE;
}

HBRUSH CDeleteFileDlg::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
	HBRUSH hbr = CSkinDialog::OnCtlColor( pDC, pWnd, nCtlColor );

	if ( pWnd == &m_wndName )
	{
		pDC->SelectObject( &theApp.m_gdiFontBold );
	}

	return hbr;
}

void CDeleteFileDlg::OnDeleteAll()
{
	UpdateData( TRUE );
	if ( m_nOption != 1 ) m_bAll = TRUE; // Can't all if misnamed
	CDialog::OnOK();
}

void CDeleteFileDlg::Apply(CLibraryFile* pFile)
{
	if ( m_nRateValue > 0 || m_sComments.GetLength() > 0 )
	{
		if ( m_bCreateGhost )
		{
			if ( m_sComments.GetLength() > 0 )
				pFile->m_sComments = m_sComments;

			pFile->m_nRating = m_nRateValue;
		}
		else 
		{
			pFile->m_sComments.Empty();
			pFile->m_nRating = 0;
		}
		pFile->SaveMetadata();
	}
}

void CDeleteFileDlg::Create(CDownload* pDownload, BOOL bShare)
{
	if ( !pDownload->m_oSHA1 && !pDownload->m_oTiger && !pDownload->m_oED2K ) return;

	CSingleLock oLock( &Library.m_pSection );
	if ( !oLock.Lock( 500 ) ) return;

	CLibraryFile* pFile = NULL;
	
	if ( pFile == NULL && pDownload->m_oSHA1 )
		pFile = LibraryMaps.LookupFileBySHA1( pDownload->m_oSHA1 );
    if ( pFile == NULL && pDownload->m_oTiger )
		pFile = LibraryMaps.LookupFileByTiger( pDownload->m_oTiger );
	if ( pFile == NULL && pDownload->m_oED2K )
		pFile = LibraryMaps.LookupFileByED2K( pDownload->m_oED2K );
	
	if ( pFile == NULL && m_bCreateGhost && 
		 ( m_nRateValue > 0 || m_sComments.GetLength() > 0 ) ) // The file is not completed
	{
		pFile = new CLibraryFile( NULL, pDownload->m_sDisplayName );
		pFile->m_nSize		= pDownload->m_nSize;
		pFile->m_oSHA1		= pDownload->m_oSHA1;
		pFile->m_oTiger		= pDownload->m_oTiger;
		pFile->m_oMD5		= pDownload->m_oMD5;
		pFile->m_oED2K		= pDownload->m_oED2K;
		pFile->m_bShared	= bShare ? TS_TRUE : TS_FALSE;
		pFile->Ghost();
	}

	if ( pFile != NULL ) // If we got ghost file, update its info too
	{
		Apply( pFile );
		Library.Update();
	}
}

void CDeleteFileDlg::OnMeasureItem(int /*nIDCtl*/, LPMEASUREITEMSTRUCT lpMeasureItemStruct)
{
	lpMeasureItemStruct->itemWidth	= 1024;
	lpMeasureItemStruct->itemHeight	= 18;
}

void CDeleteFileDlg::OnDrawItem(int /*nIDCtl*/, LPDRAWITEMSTRUCT lpDrawItemStruct)
{
	if ( lpDrawItemStruct->itemID == (UINT)-1 ) return;
	if ( ( lpDrawItemStruct->itemAction & ODA_SELECT ) == 0 &&
		( lpDrawItemStruct->itemAction & ODA_DRAWENTIRE ) == 0 ) return;

	CRect rcItem( &lpDrawItemStruct->rcItem );
	CPoint pt( rcItem.left + 1, rcItem.top + 1 );
	CDC dc;

	dc.Attach( lpDrawItemStruct->hDC );
	if ( theApp.m_bRTL ) theApp.m_pfnSetLayout( dc.m_hDC, LAYOUT_RTL );

	int nRating = lpDrawItemStruct->itemID;

	CFont* pOldFont = (CFont*)dc.SelectObject( nRating > 0 ? &theApp.m_gdiFontBold : &theApp.m_gdiFont );
	dc.SetTextColor( GetSysColor( ( lpDrawItemStruct->itemState & ODS_SELECTED )
		? COLOR_HIGHLIGHTTEXT : COLOR_MENUTEXT ) );

	// fix me :(. the disabled box should have grey color
	COLORREF crBack = COLOR_WINDOW;

	dc.FillSolidRect( &rcItem,
		GetSysColor( ( lpDrawItemStruct->itemState & ODS_SELECTED )
		? COLOR_HIGHLIGHT : crBack ) );
	dc.SetBkMode( TRANSPARENT );

	rcItem.DeflateRect( 4, 1 );

	if ( nRating > 1 )
	{
		for ( int nStar = nRating - 1 ; nStar ; nStar-- )
		{
			rcItem.right -= 16;
			ShellIcons.Draw( &dc, SHI_STAR, 16, rcItem.right, rcItem.top, CLR_NONE,
				( lpDrawItemStruct->itemState & ODS_SELECTED ) );
			rcItem.right -= 2;
		}
	}
	else if ( nRating == 1 )
	{
		rcItem.right -= 16;
		ShellIcons.Draw( &dc, SHI_FAKE, 16, rcItem.right, rcItem.top, CLR_NONE,
			( lpDrawItemStruct->itemState & ODS_SELECTED ) );
	}

	if ( ( lpDrawItemStruct->itemState & ODS_SELECTED ) == 0 )
	{
		static COLORREF crRating[7] =
		{
			RGB( 0, 0, 0 ),			// Unrated
			RGB( 255, 0, 0 ),		// 0 - Fake
			RGB( 128, 128, 128 ),	// 1 - Poor
			RGB( 0, 0, 0 ),			// 2 - Average
			RGB( 128, 128, 128 ),	// 3 - Good
			RGB( 0, 128, 0 ),		// 4 - Very good
			RGB( 0, 0, 255 ),		// 5 - Excellent
		};

		dc.SetTextColor( crRating[ nRating ] );
	}

	CString str;
	m_wndRating.GetLBText( nRating, str );
	dc.DrawText( str, &rcItem, DT_SINGLELINE|DT_LEFT|DT_VCENTER|DT_NOPREFIX );

	dc.SelectObject( pOldFont );
	dc.Detach();
}

void CDeleteFileDlg::OnCbnChangeOptions()
{
	static const CString strOriginalComments = m_sComments;
	UpdateData();

	switch ( m_nOption )
	{
	case 0: // Original comments
		m_sComments = strOriginalComments;
		break;
	case 1:	// Misnamed
		m_sComments = _T("Incorrectly named \"") + m_sName + _T("\"");
		break;
	case 2:	// Poor Quality
		m_sComments = _T("Very poor quality");
		break;
	case 3:	// Fake
		m_sComments = _T("Fake/corrupt");
		break;
	case 4: // New comments
		m_sComments = strOriginalComments;
		break;
	}

	m_wndComments.SetWindowText( m_sComments );
	m_wndComments.EnableWindow( m_nOption > 0 );

	if ( m_nOption > 0 )
	{
		m_wndComments.SetFocus();
		m_wndComments.SetSel( 0, m_sComments.GetLength() );
	}

	m_bCreateGhost = m_sComments.GetLength() || m_nRateValue > 0;
	UpdateData( FALSE );
}

void CDeleteFileDlg::OnCbnChangeGhostRating()
{
	UpdateData( TRUE );
	m_bCreateGhost = m_sComments.GetLength() || m_nRateValue > 0;
	UpdateData( FALSE );
}

void CDeleteFileDlg::OnChangeComments()
{
	UpdateData( TRUE );
	m_bCreateGhost = m_sComments.GetLength() || m_nRateValue > 0;
	UpdateData( FALSE );
}


void CDeleteFileDlg::OnClickedCreateGhost()
{
	m_bCreateGhost = !m_bCreateGhost;
	m_wndOptions.EnableWindow( m_bCreateGhost );
	m_wndRating.EnableWindow( m_bCreateGhost );
	UpdateData( FALSE );
}
