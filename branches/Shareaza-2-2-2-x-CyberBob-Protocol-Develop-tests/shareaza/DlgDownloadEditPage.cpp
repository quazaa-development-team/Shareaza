//
// DlgDownloadEditPage.cpp
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
#include "DlgDownloadEditSheet.h"
#include "DlgDownloadEditPage.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


IMPLEMENT_DYNAMIC(CDownloadEditPage, CPropertyPage)

BEGIN_MESSAGE_MAP(CDownloadEditPage, CPropertyPage)
	//{{AFX_MSG_MAP(CDownloadEditPage)
	ON_WM_PAINT()
	//}}AFX_MSG_MAP
	ON_WM_CTLCOLOR()
END_MESSAGE_MAP()


/////////////////////////////////////////////////////////////////////////////
// CDownloadEditInfoPage property page

CDownloadEditPage::CDownloadEditPage(UINT nIDD) : 
	CPropertyPage( nIDD ), m_nIcon( -1 )
{
}

CDownloadEditPage::~CDownloadEditPage()
{
}

void CDownloadEditPage::DoDataExchange(CDataExchange* pDX)
{
	CPropertyPage::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CDownloadEditPage)
	//}}AFX_DATA_MAP
}

CDownload* CDownloadEditPage::GetDownloadEdit()
{
	return ((CDownloadEditSheet*)GetParent())->m_pDownload;
}

/////////////////////////////////////////////////////////////////////////////
// CDownloadEditPage message handlers

BOOL CDownloadEditPage::OnInitDialog()
{
	CPropertyPage::OnInitDialog();

	Skin.Apply( NULL, this );

	m_pDownload = GetDownloadEdit();
	
	return TRUE;
}

void CDownloadEditPage::OnPaint()
{
	CPaintDC dc( this );
	if ( theApp.m_bRTL ) theApp.m_pfnSetLayout( dc.m_hDC, LAYOUT_RTL );

	if ( m_nIcon >= 0 )
	{
		ShellIcons.Draw( &dc, m_nIcon, 48, 4, 4 );
	}

	for ( CWnd* pWnd = GetWindow( GW_CHILD ) ; pWnd ; pWnd = pWnd->GetNextWindow() )
	{
		if ( pWnd->GetStyle() & WS_VISIBLE ) continue;

		TCHAR szClass[16];
		GetClassName( pWnd->GetSafeHwnd(), szClass, 16 );
		if ( _tcsicmp( szClass, _T("STATIC") ) ) continue;

		CString str;
		CRect rc;

		pWnd->GetWindowText( str );
		pWnd->GetWindowRect( &rc );
		ScreenToClient( &rc );

		if ( str.IsEmpty() || str.GetAt( 0 ) != '-' )
			PaintStaticHeader( &dc, &rc, str );
	}

	dc.SetBkColor( CCoolInterface::GetDialogBkColor() );
}

void CDownloadEditPage::PaintStaticHeader(CDC* pDC, CRect* prc, LPCTSTR psz)
{
	CFont* pOldFont = (CFont*)pDC->SelectObject( GetFont() );
	CSize sz = pDC->GetTextExtent( psz );

	pDC->SetBkMode( OPAQUE );
	pDC->SetBkColor( Skin.m_crBannerBack );
	pDC->SetTextColor( Skin.m_crBannerText );

	CRect rc( prc );
	rc.bottom	= rc.top + min( rc.Height(), 16 );
	rc.right	= rc.left + sz.cx + 10;

	pDC->ExtTextOut( rc.left + 4, rc.top + 1, ETO_CLIPPED|ETO_OPAQUE,
		&rc, psz, static_cast< UINT >( _tcslen( psz ) ), NULL );

	rc.SetRect( rc.right, rc.top, prc->right, rc.top + 1 );
	pDC->ExtTextOut( rc.left, rc.top, ETO_OPAQUE, &rc, NULL, 0, NULL );

	pDC->SelectObject( pOldFont );
}

HBRUSH CDownloadEditPage::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
	HBRUSH hbr = CPropertyPage::OnCtlColor( pDC, pWnd, nCtlColor );

	if ( nCtlColor == CTLCOLOR_DLG || nCtlColor == CTLCOLOR_STATIC )
	{
		pDC->SetBkColor( Skin.m_crDialog );
		hbr = Skin.m_brDialog;
	}

	return hbr;
}
