//
// DlgAbout.cpp
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
#include "DlgAbout.h"
#include "CoolInterface.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

BEGIN_MESSAGE_MAP(CAboutDlg, CSkinDialog)
	//{{AFX_MSG_MAP(CAboutDlg)
	ON_WM_PAINT()
	ON_WM_CTLCOLOR()
	ON_WM_SETCURSOR()
	ON_WM_LBUTTONDOWN()
	ON_WM_RBUTTONDOWN()
	ON_WM_CREATE()
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()


/////////////////////////////////////////////////////////////////////////////
// CAboutDlg dialog

CAboutDlg::CAboutDlg(CWnd* pParent) : CSkinDialog(CAboutDlg::IDD, pParent)
{
	//{{AFX_DATA_INIT(CAboutDlg)
	//}}AFX_DATA_INIT
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CSkinDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CAboutDlg)
	DDX_Control(pDX, IDC_WEB, m_wndWeb);
	DDX_Control(pDX, IDC_TITLE, m_wndTitle);
	//}}AFX_DATA_MAP
}

/////////////////////////////////////////////////////////////////////////////
// CAboutDlg message handlers

BOOL CAboutDlg::OnInitDialog()
{
	CSkinDialog::OnInitDialog();

	SkinMe( _T("CAboutDlg"), IDR_MAINFRAME, FALSE );

	CString strCaption;

	GetWindowText( strCaption );
	strCaption += _T(" v");
	strCaption += theApp.m_sVersion;
	SetWindowText( strCaption );

	m_wndTitle.GetWindowText( strCaption );
	strCaption += theApp.m_sVersion;
#ifndef _WIN64
	strCaption += _T(" (") + theApp.m_sBuildDate + _T(")");
#else
	strCaption += L" x64 Edition (" + theApp.m_sBuildDate + _T(")");
#endif
	m_wndTitle.SetWindowText( strCaption );

	m_crWhite = CCoolInterface::GetDialogBkColor();
	m_brWhite.CreateSolidBrush( m_crWhite );

	TCHAR szPath[MAX_PATH];
	GetModuleFileName( NULL, szPath, MAX_PATH );
	LPCTSTR pszPath = szPath;

	DWORD dwSize = GetFileVersionInfoSize( (LPTSTR)pszPath, &dwSize );
	BYTE* pBuffer = new BYTE[ dwSize ];
	GetFileVersionInfo( (LPTSTR)pszPath, NULL, dwSize, pBuffer );

	BYTE* pValue = NULL;
	CString strCopyRight;

	if ( VerQueryValue( pBuffer, L"\\StringFileInfo\\000004b0\\LegalCopyright", 
		 (void**)&pValue, (UINT*)&dwSize ) )
		strCopyRight = (LPCTSTR)pValue;

	delete [] pBuffer;

	CWnd* pWnd = GetDlgItem( IDC_COPYRIGHT );
	pWnd->SetWindowText( (LPCTSTR)strCopyRight );

	return TRUE;
}

void CAboutDlg::OnPaint()
{
	CPaintDC dc( this );
	CRect rc;

	GetClientRect( &rc );
	rc.top += 51;

	dc.Draw3dRect( 0, 50, rc.right + 1, 0,
		RGB( 128, 128, 128 ), RGB( 128, 128, 128 ) );
	dc.FillSolidRect( &rc, m_crWhite );
}

HBRUSH CAboutDlg::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
	/*HBRUSH hbr =*/ (HBRUSH)CSkinDialog::OnCtlColor( pDC, pWnd, nCtlColor );

	pDC->SetBkColor( m_crWhite );

	if ( pWnd == &m_wndTitle )
	{
		pDC->SelectObject( &theApp.m_gdiFontBold );
	}
	else if ( pWnd == &m_wndWeb )
	{
		pDC->SetTextColor( CoolInterface.m_crTextLink );
		pDC->SelectObject( &theApp.m_gdiFontLine );
	}

	return m_brWhite;
}

BOOL CAboutDlg::OnSetCursor(CWnd* pWnd, UINT nHitTest, UINT message)
{
	CPoint point;
	CRect rc;

	GetCursorPos( &point );
	m_wndWeb.GetWindowRect( &rc );

	if ( rc.PtInRect( point ) )
	{
		SetCursor( theApp.LoadCursor( IDC_HAND ) );
		return TRUE;
	}

	return CSkinDialog::OnSetCursor( pWnd, nHitTest, message );
}

void CAboutDlg::OnLButtonDown(UINT nFlags, CPoint point)
{
	CSkinDialog::OnLButtonUp( nFlags, point );

	CRect rc;
	m_wndWeb.GetWindowRect( &rc );
	ScreenToClient( &rc );

	if ( rc.PtInRect( point ) )
	{
		ShellExecute( GetSafeHwnd(), _T("open"),
			_T("http://www.shareaza.com/?Version=") + theApp.m_sVersion,
			NULL, NULL, SW_SHOWNORMAL );
	}
}

void CAboutDlg::OnRButtonDown(UINT /*nFlags*/, CPoint point)
{
	CRect rc;

	m_wndWeb.GetWindowRect( &rc );
	ScreenToClient( &rc );

	if ( rc.PtInRect( point ) && ( GetAsyncKeyState( VK_SHIFT ) & 0x8000 ) )
	{
		DWORD* pNullPtr = (DWORD*)NULL;
		*pNullPtr = 0xFFFFFFFF;
	}
}

int CAboutDlg::OnCreate(LPCREATESTRUCT lpCreateStruct)
{
	if (CDialog::OnCreate(lpCreateStruct) == -1)
		return -1;
	return 0;
}