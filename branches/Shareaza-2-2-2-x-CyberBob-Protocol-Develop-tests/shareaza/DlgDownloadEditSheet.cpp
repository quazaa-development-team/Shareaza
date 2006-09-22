//
// DlgDownloadEditSheet.h
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
#include "Settings.h"
#include "Skin.h"
#include "SkinWindow.h"
#include "Download.h"
#include "Downloads.h"
#include "Transfers.h"
#include "DlgDownloadEditSheet.h"
#include "DlgDownloadEditPage.h"
#include "PageDownloadEditGeneral.h"
#include "PageDownloadEditHashes.h"
#include "PageDownloadEditActions.h"
#include "FragmentedFile.h"

#include "SHA.h"
#include "ED2K.h"
#include "TigerTree.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

IMPLEMENT_DYNAMIC(CDownloadEditSheet, CPropertySheet)

BEGIN_MESSAGE_MAP(CDownloadEditSheet, CPropertySheet)
	//{{AFX_MSG_MAP(CDownloadEditSheet)
	ON_WM_NCCALCSIZE()
	ON_WM_NCHITTEST()
	ON_WM_NCACTIVATE()
	ON_WM_NCPAINT()
	ON_WM_NCLBUTTONDOWN()
	ON_WM_NCLBUTTONUP()
	ON_WM_NCLBUTTONDBLCLK()
	ON_WM_NCMOUSEMOVE()
	ON_WM_SIZE()
	ON_WM_ERASEBKGND()
	ON_WM_CTLCOLOR()
	ON_WM_HELPINFO()
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CDownloadEditSheet
CDownloadEditSheet::CDownloadEditSheet(CDownload* pDownload) :
	CPropertySheet( L"" ), m_sGeneralTitle( L"General" ),
	m_sHashesTitle( L"Hashes" ), m_sActionsTitle( L"Actions" ),
	m_pSkin( NULL )
{
	m_psh.dwFlags &= ~PSP_HASHELP;

	m_pDownload	= pDownload;

}

CDownloadEditSheet::~CDownloadEditSheet()
{
}

/////////////////////////////////////////////////////////////////////////////
// CTorrentInfoSheet operations

INT_PTR CDownloadEditSheet::DoModal(int nPage)
{
	CSingleLock pLock( &Transfers.m_pSection, TRUE );

	if ( ! Downloads.Check( m_pDownload ) || m_pDownload->IsMoving() )
	{
		PostMessage( WM_CLOSE );
		return TRUE;
	}

	m_pGeneral	= new CDownloadEditGeneralPage();
	m_pHashes = new CDownloadEditHashesPage();
	m_pActions = new CDownloadEditActionsPage();

	SetTabTitle( m_pGeneral, m_sGeneralTitle );
	AddPage( m_pGeneral );

	SetTabTitle( m_pHashes, m_sHashesTitle );
	AddPage( m_pHashes );

	SetTabTitle( m_pActions, m_sActionsTitle );
	AddPage( m_pActions );

	m_pActions->pParent = this;
	m_psh.nStartPage = nPage;
	return CPropertySheet::DoModal();
}

void CDownloadEditSheet::SetTabTitle(CPropertyPage* pPage, CString& strTitle)
{
	CString strClass = pPage->GetRuntimeClass()->m_lpszClassName;
	CString strTabLabel = Skin.GetDialogCaption( strClass );
	if ( ! strTabLabel.IsEmpty() )
		strTitle = strTabLabel;
	pPage->m_psp.pszTitle = strTitle.GetBuffer();
}

/////////////////////////////////////////////////////////////////////////////
// CDownloadEditSheet message handlers

BOOL CDownloadEditSheet::OnInitDialog()
{
	BOOL bResult = CPropertySheet::OnInitDialog();

	SetFont( &theApp.m_gdiFont );
	SetIcon( theApp.LoadIcon( IDI_PROPERTIES ), TRUE );

	CString strCaption;
//	LoadString( strCaption, IDS_TORRENT_INFO );
	strCaption = "Advanced Edit";
	SetWindowText( strCaption );

	m_pSkin = Skin.GetWindowSkin( _T("CDownloadEditSheet") );
	if ( m_pSkin == NULL ) m_pSkin = Skin.GetWindowSkin( this );
	if ( m_pSkin == NULL ) m_pSkin = Skin.GetWindowSkin( _T("CDialog") );

	if ( m_pSkin != NULL )
	{
		CRect rc;
		GetClientRect( &rc );
		m_pSkin->CalcWindowRect( &rc );
		m_brDialog.CreateSolidBrush( Skin.m_crDialog );
		SetWindowPos( NULL, 0, 0, rc.Width(), rc.Height(), SWP_NOMOVE|SWP_NOZORDER|SWP_NOACTIVATE|SWP_FRAMECHANGED );
		OnSize( 1982, 0, 0 );
	}

	if ( GetDlgItem( IDOK ) )
	{
		CRect rc;
		GetDlgItem( IDOK )->GetWindowRect( &rc );
		ScreenToClient( &rc );
		GetDlgItem( IDOK )->SetWindowPos( NULL, 300, rc.top, 0, 0, SWP_NOSIZE|SWP_NOZORDER|SWP_NOACTIVATE );
		GetDlgItem( IDCANCEL )->SetWindowPos( NULL, 311 + rc.Width(), rc.top, 0, 0, SWP_NOSIZE|SWP_NOZORDER|SWP_NOACTIVATE );
	}

	if ( GetDlgItem( 0x3021 ) ) GetDlgItem( 0x3021 )->ShowWindow( SW_HIDE );
	if ( GetDlgItem( 0x0009 ) ) GetDlgItem( 0x0009 )->ShowWindow( SW_HIDE );

	return bResult;
}

/////////////////////////////////////////////////////////////////////////////
// CDownloadEditSheet skin support

void CDownloadEditSheet::OnNcCalcSize(BOOL bCalcValidRects, NCCALCSIZE_PARAMS FAR* lpncsp)
{
	if ( m_pSkin )
		m_pSkin->OnNcCalcSize( this, bCalcValidRects, lpncsp );
	else
		CPropertySheet::OnNcCalcSize( bCalcValidRects, lpncsp );
}

ONNCHITTESTRESULT CDownloadEditSheet::OnNcHitTest(CPoint point)
{
	if ( m_pSkin )
		return m_pSkin->OnNcHitTest( this, point, ( GetStyle() & WS_THICKFRAME ) ? TRUE : FALSE );
	else
		return CPropertySheet::OnNcHitTest( point );
}

BOOL CDownloadEditSheet::OnNcActivate(BOOL bActive)
{
	if ( m_pSkin )
	{
		BOOL bVisible = IsWindowVisible();
		if ( bVisible ) ModifyStyle( WS_VISIBLE, 0 );
		BOOL bResult = CPropertySheet::OnNcActivate( bActive );
		if ( bVisible ) ModifyStyle( 0, WS_VISIBLE );
		m_pSkin->OnNcActivate( this, bActive || ( m_nFlags & WF_STAYACTIVE ) );
		return bResult;
	}
	else
	{
		return CPropertySheet::OnNcActivate( bActive );
	}
}

void CDownloadEditSheet::OnNcPaint()
{
	if ( m_pSkin )
		m_pSkin->OnNcPaint( this );
	else
		CPropertySheet::OnNcPaint();
}

void CDownloadEditSheet::OnNcLButtonDown(UINT nHitTest, CPoint point)
{
	if ( m_pSkin && m_pSkin->OnNcLButtonDown( this, nHitTest, point ) ) return;
	CPropertySheet::OnNcLButtonDown(nHitTest, point);
}

void CDownloadEditSheet::OnNcLButtonUp(UINT nHitTest, CPoint point)
{
	if ( m_pSkin && m_pSkin->OnNcLButtonUp( this, nHitTest, point ) ) return;
	CPropertySheet::OnNcLButtonUp( nHitTest, point );
}

void CDownloadEditSheet::OnNcLButtonDblClk(UINT nHitTest, CPoint point)
{
	if ( m_pSkin && m_pSkin->OnNcLButtonDblClk( this, nHitTest, point ) ) return;
	CPropertySheet::OnNcLButtonDblClk( nHitTest, point );
}

void CDownloadEditSheet::OnNcMouseMove(UINT nHitTest, CPoint point)
{
	if ( m_pSkin ) m_pSkin->OnNcMouseMove( this, nHitTest, point );
	CPropertySheet::OnNcMouseMove( nHitTest, point );
}

void CDownloadEditSheet::OnSize(UINT nType, int cx, int cy)
{
	if ( m_pSkin ) m_pSkin->OnSize( this );

	if ( nType != 1982 ) CPropertySheet::OnSize( nType, cx, cy );
}

LRESULT CDownloadEditSheet::OnSetText(WPARAM /*wParam*/, LPARAM /*lParam*/)
{
	if ( m_pSkin )
	{
		BOOL bVisible = IsWindowVisible();
		if ( bVisible ) ModifyStyle( WS_VISIBLE, 0 );
		LRESULT lResult = Default();
		if ( bVisible ) ModifyStyle( 0, WS_VISIBLE );
		if ( m_pSkin ) m_pSkin->OnSetText( this );
		return lResult;
	}
	else
	{
		return Default();
	}
}

BOOL CDownloadEditSheet::OnEraseBkgnd(CDC* pDC)
{
	if ( m_pSkin )
	{
		if ( m_pSkin->OnEraseBkgnd( this, pDC ) ) return TRUE;
	}

	return CPropertySheet::OnEraseBkgnd( pDC );
}

HBRUSH CDownloadEditSheet::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
	// if ( m_brDialog.m_hObject ) return m_brDialog;
	return CPropertySheet::OnCtlColor( pDC, pWnd, nCtlColor );
}

BOOL CDownloadEditSheet::OnHelpInfo(HELPINFO* /*pHelpInfo*/)
{
	return FALSE;
}

void CDownloadEditSheet::OnClose()
{
	CPropertySheet::OnClose();
}
