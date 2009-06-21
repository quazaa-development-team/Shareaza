//
// CtrlLibraryFrame.cpp
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

#include "StdAfx.h"
#include "Shareaza.h"
#include "Settings.h"
#include "Library.h"
#include "LibraryBuilder.h"
#include "AlbumFolder.h"
#include "SharedFile.h"
#include "QuerySearch.h"
#include "Schema.h"
#include "XML.h"

#include "CtrlLibraryFrame.h"
#include "DlgNewSearch.h"
#include "Skin.h"

#include "CtrlLibraryView.h"
#include "CtrlLibraryCollectionView.h"
#include "CtrlLibraryDetailView.h"
#include "CtrlLibraryThumbView.h"
#include "CtrlLibraryAlbumView.h"
#include "CtrlLibraryTileView.h"

#include "CtrlLibraryPanel.h"
#include "CtrlLibraryMetaPanel.h"
#include "CtrlLibraryHistoryPanel.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

IMPLEMENT_DYNAMIC(CLibraryFrame, CWnd)

BEGIN_MESSAGE_MAP(CLibraryFrame, CWnd)
	ON_WM_CREATE()
	ON_WM_DESTROY()
	ON_WM_SIZE()
	ON_WM_PAINT()
	ON_WM_LBUTTONDOWN()
	ON_WM_SETCURSOR()
	ON_WM_TIMER()
	ON_WM_CONTEXTMENU()
	ON_WM_MEASUREITEM()
	ON_COMMAND(ID_LIBRARY_REFRESH, OnLibraryRefresh)
	ON_UPDATE_COMMAND_UI(ID_LIBRARY_TREE_PHYSICAL, OnUpdateLibraryTreePhysical)
	ON_COMMAND(ID_LIBRARY_TREE_PHYSICAL, OnLibraryTreePhysical)
	ON_UPDATE_COMMAND_UI(ID_LIBRARY_TREE_VIRTUAL, OnUpdateLibraryTreeVirtual)
	ON_COMMAND(ID_LIBRARY_TREE_VIRTUAL, OnLibraryTreeVirtual)
	ON_UPDATE_COMMAND_UI(ID_LIBRARY_PANEL, OnUpdateLibraryPanel)
	ON_COMMAND(ID_LIBRARY_PANEL, OnLibraryPanel)
	ON_COMMAND(ID_LIBRARY_SEARCH, OnLibrarySearch)
	ON_COMMAND(ID_LIBRARY_SEARCH_QUICK, OnLibrarySearchQuick)
	ON_NOTIFY(LTN_SELCHANGED, IDC_LIBRARY_TREE, OnTreeSelection)
	ON_CBN_CLOSEUP(AFX_IDW_TOOLBAR, OnFilterTypes)
	ON_BN_CLICKED(AFX_IDW_TOOLBAR, OnToolbarReturn)
	ON_BN_DOUBLECLICKED(AFX_IDW_TOOLBAR, OnToolbarEscape)
	ON_WM_SETFOCUS()
END_MESSAGE_MAP()

#define BAR_HEIGHT		28
#define SPLIT_SIZE		6


/////////////////////////////////////////////////////////////////////////////
// CLibraryFrame construction

CLibraryFrame::CLibraryFrame()
{
	m_pViews.AddTail( new CLibraryDetailView() );
	m_pViews.AddTail( new CLibraryListView() );
	m_pViews.AddTail( new CLibraryIconView() );
	m_pViews.AddTail( new CLibraryThumbView() );
	m_pViews.AddTail( new CLibraryAlbumView() );
	m_pViews.AddTail( new CLibraryCollectionView() );
	m_pViews.AddTail( new CLibraryTileView() );

	m_pPanels.AddTail( new CLibraryMetaPanel() );
	m_pPanels.AddTail( new CLibraryHistoryPanel() );

	m_pView			= NULL;
	m_pPanel		= NULL;
	m_nTreeSize		= Settings.Library.TreeSize;
	m_nPanelSize	= Settings.Library.PanelSize;
	m_bPanelShow	= Settings.Library.ShowPanel;
	m_nHeaderSize	= 0;
	m_bUpdating		= FALSE;
}

CLibraryFrame::~CLibraryFrame()
{
	for ( POSITION pos = m_pViews.GetHeadPosition() ; pos ; )
	{
		delete m_pViews.GetNext( pos );
	}

	for ( POSITION pos = m_pPanels.GetHeadPosition() ; pos ; )
	{
		delete m_pPanels.GetNext( pos );
	}
}

/////////////////////////////////////////////////////////////////////////////
// CLibraryFrame system message handlers

BOOL CLibraryFrame::Create(CWnd* pParentWnd)
{
	CRect rect;
	return CWnd::Create( NULL, _T("CLibraryFrame"),
		WS_CHILD|WS_VISIBLE|WS_TABSTOP, rect, pParentWnd, IDC_LIBRARY_FRAME, NULL );
}

int CLibraryFrame::OnCreate(LPCREATESTRUCT lpCreateStruct)
{
	if ( CWnd::OnCreate( lpCreateStruct ) == -1 ) return -1;

	m_wndTreeTop.EnableDrop();
	if ( ! m_wndTreeTop.Create( this, WS_CHILD|WS_VISIBLE|CBRS_NOALIGN, AFX_IDW_TOOLBAR ) ) return -1;
	m_wndTreeTop.SetBarStyle( m_wndTreeTop.GetBarStyle() | CBRS_TOOLTIPS|CBRS_BORDER_BOTTOM );
	m_wndTreeTop.SetOwner( GetOwner() );

	if ( ! m_wndTreeBottom.Create( this, WS_CHILD|CBRS_NOALIGN, AFX_IDW_TOOLBAR ) ) return -1;
	m_wndTreeBottom.SetBarStyle( m_wndTreeBottom.GetBarStyle() | CBRS_TOOLTIPS|CBRS_BORDER_TOP );
	m_wndTreeBottom.SetOwner( GetOwner() );

	CRect rcTypes( 0, 0, 128, BAR_HEIGHT );
	if ( ! m_wndTreeTypes.Create( WS_CHILD, rcTypes, this, AFX_IDW_TOOLBAR ) ) return -1;
	m_wndTreeTypes.GetWindowRect( &rcTypes );
	m_nTreeTypesHeight = rcTypes.Height();

	if ( ! m_wndViewTop.Create( this, WS_CHILD|WS_VISIBLE|CBRS_NOALIGN, AFX_IDW_TOOLBAR ) ) return -1;
	m_wndViewTop.SetBarStyle( m_wndViewTop.GetBarStyle() | CBRS_TOOLTIPS );
	m_wndViewTop.SetOwner( GetOwner() );

	if ( ! m_wndViewBottom.Create( this, WS_CHILD|WS_VISIBLE|CBRS_NOALIGN, AFX_IDW_TOOLBAR ) ) return -1;
	m_wndViewBottom.SetBarStyle( m_wndViewBottom.GetBarStyle() | CBRS_TOOLTIPS|CBRS_BORDER_TOP );
	m_wndViewBottom.SetOwner( GetOwner() );

	if ( ! m_wndSearch.Create( WS_CHILD|ES_AUTOHSCROLL, rcTypes, &m_wndViewBottom, IDC_SEARCH_BOX ) ) return -1;
	m_wndSearch.SetFont( &theApp.m_gdiFont );

	m_wndTree.Create( this );
	m_wndHeader.Create( this );
	m_wndViewTip.Create( this, &Settings.Interface.TipLibrary );

	return 0;
}

void CLibraryFrame::OnDestroy()
{
	if ( m_wndViewTip.m_hWnd ) m_wndViewTip.DestroyWindow();

	Settings.Library.TreeSize	= m_nTreeSize;
	Settings.Library.PanelSize	= m_nPanelSize;
	Settings.Library.ShowPanel	= m_bPanelShow;

	CWnd::OnDestroy();
}

BOOL CLibraryFrame::PreTranslateMessage(MSG* pMsg)
{
	if ( pMsg->message == WM_KEYDOWN && pMsg->wParam == VK_TAB )
	{
		CWnd* pFocus = GetFocus();

		if ( pFocus == &m_wndTree && m_pView != NULL )
		{
			m_pView->SetFocus();
			return TRUE;
		}
		else
		{
			m_wndTree.SetFocus();
			return TRUE;
		}
	}

	return CWnd::PreTranslateMessage( pMsg );
}

/////////////////////////////////////////////////////////////////////////////
// CLibraryFrame skin change

void CLibraryFrame::OnSkinChange()
{
	m_wndTree.SetVirtual( Settings.Library.ShowVirtual );

	Skin.CreateToolBar( _T("CLibraryTree.Top"), &m_wndTreeTop );

	if ( Settings.Library.ShowVirtual )
	{
		Skin.CreateToolBar( _T("CLibraryHeaderBar.Virtual"), &m_wndViewTop );
		Skin.CreateToolBar( _T("CLibraryTree.Virtual"), &m_wndTreeBottom );
	}
	else
	{
		Skin.CreateToolBar( _T("CLibraryHeaderBar.Physical"), &m_wndViewTop );
		Skin.CreateToolBar( _T("CLibraryTree.Physical"), &m_wndTreeBottom );

		m_wndTreeTypes.SetEmptyString( IDS_LIBRARY_TYPE_FILTER_ALL );
		m_wndTreeTypes.Load( Settings.Library.FilterURI );
	}

	m_wndTreeBottom.ShowWindow( Settings.Library.ShowVirtual ? SW_SHOW : SW_HIDE );
	m_wndTreeTypes.ShowWindow( Settings.Library.ShowVirtual ? SW_HIDE : SW_SHOW );
	m_wndHeader.OnSkinChange();

	CLibraryView* pView		= m_pView;
	CLibraryPanel* pPanel	= m_pPanel;

	SetView( NULL, TRUE, FALSE );
	SetView( pView, TRUE, FALSE );
	SetPanel( pPanel );
}

/////////////////////////////////////////////////////////////////////////////
// CLibraryFrame more system message handlers

BOOL CLibraryFrame::OnCmdMsg(UINT nID, int nCode, void* pExtra, AFX_CMDHANDLERINFO* pHandlerInfo)
{
	if ( m_wndTreeTop.m_hWnd )
	{
		if ( m_wndTreeTop.OnCmdMsg( nID, nCode, pExtra, pHandlerInfo ) ) return TRUE;
	}
	if ( m_wndTreeBottom.m_hWnd )
	{
		if ( m_wndTreeBottom.OnCmdMsg( nID, nCode, pExtra, pHandlerInfo ) ) return TRUE;
	}
	if ( m_wndViewTop.m_hWnd )
	{
		if ( m_wndViewTop.OnCmdMsg( nID, nCode, pExtra, pHandlerInfo ) ) return TRUE;
	}
	if ( m_wndViewBottom.m_hWnd )
	{
		if ( m_wndViewBottom.OnCmdMsg( nID, nCode, pExtra, pHandlerInfo ) ) return TRUE;
	}
	if ( m_wndTree.m_hWnd )
	{
		if ( m_wndTree.OnCmdMsg( nID, nCode, pExtra, pHandlerInfo ) ) return TRUE;
	}
	if ( m_pView && m_pView->m_hWnd )
	{
		if ( m_pView->OnCmdMsg( nID, nCode, pExtra, pHandlerInfo ) ) return TRUE;
	}
	if ( m_pPanel && m_pPanel->m_hWnd )
	{
		if ( m_pPanel->OnCmdMsg( nID, nCode, pExtra, pHandlerInfo ) ) return TRUE;
	}

	return CWnd::OnCmdMsg( nID, nCode, pExtra, pHandlerInfo );
}

void CLibraryFrame::OnSize(UINT nType, int cx, int cy)
{
	if ( nType != 1982 ) CWnd::OnSize( nType, cx, cy );

	CRect rc;
	GetClientRect( &rc );

	if ( rc.Width() < 32 || rc.Height() < 32 ) return;

	if ( rc.Width() < m_nTreeSize + SPLIT_SIZE )
	{
		m_nTreeSize = max( 0, rc.Width() - SPLIT_SIZE );
	}
	if ( rc.Height() - BAR_HEIGHT * 2 - m_nHeaderSize < m_nPanelSize + SPLIT_SIZE )
	{
		m_nPanelSize = max( 0, rc.Height() - BAR_HEIGHT * 2 - m_nHeaderSize - SPLIT_SIZE );
	}

	HDWP hDWP = BeginDeferWindowPos(
		6 + ( m_pView != NULL ) + ( m_pPanel != NULL ) + ( m_nHeaderSize > 0 ) );

	DeferWindowPos( hDWP, m_wndTreeTop.GetSafeHwnd(), NULL,
		rc.left, rc.top, m_nTreeSize, BAR_HEIGHT, SWP_NOZORDER );

	DeferWindowPos( hDWP, m_wndTreeBottom.GetSafeHwnd(), NULL,
		rc.left, rc.bottom - BAR_HEIGHT, m_nTreeSize, BAR_HEIGHT, SWP_NOZORDER );

	DeferWindowPos( hDWP, m_wndTreeTypes.GetSafeHwnd(), NULL,
		rc.left, rc.bottom - m_nTreeTypesHeight, m_nTreeSize, 256, SWP_NOZORDER );

	DeferWindowPos( hDWP, m_wndViewTop.GetSafeHwnd(), NULL,
		rc.left + m_nTreeSize + SPLIT_SIZE, rc.top,
		rc.Width() - m_nTreeSize - SPLIT_SIZE, BAR_HEIGHT - 1, SWP_NOZORDER );

	DeferWindowPos( hDWP, m_wndViewBottom.GetSafeHwnd(), NULL,
		rc.left + m_nTreeSize + SPLIT_SIZE, rc.bottom - BAR_HEIGHT,
		rc.Width() - m_nTreeSize - SPLIT_SIZE, BAR_HEIGHT, SWP_NOZORDER );

	DeferWindowPos( hDWP, m_wndTree.GetSafeHwnd(), NULL,
		rc.left, rc.top + BAR_HEIGHT, m_nTreeSize, rc.Height() - BAR_HEIGHT * 2, SWP_NOZORDER );

	if ( m_pView != NULL )
	{
		int nTop = rc.top + BAR_HEIGHT - 1;

		if ( m_nHeaderSize > 0 )
		{
			DeferWindowPos( hDWP, m_wndHeader.GetSafeHwnd(), NULL,
				rc.left + m_nTreeSize + SPLIT_SIZE, nTop,
				rc.Width() - m_nTreeSize - SPLIT_SIZE, m_nHeaderSize,
				SWP_NOZORDER|SWP_SHOWWINDOW );
			nTop += m_nHeaderSize + 1;
		}

		int nHeight = rc.bottom - BAR_HEIGHT - nTop;
		if ( m_pPanel ) nHeight -= m_nPanelSize + SPLIT_SIZE;

		DeferWindowPos( hDWP, m_pView->GetSafeHwnd(), NULL,
			rc.left + m_nTreeSize + SPLIT_SIZE, nTop,
			rc.Width() - m_nTreeSize - SPLIT_SIZE, nHeight, SWP_NOZORDER|SWP_SHOWWINDOW );
	}

	if ( m_pPanel != NULL )
	{
		DeferWindowPos( hDWP, m_pPanel->GetSafeHwnd(), NULL,
			rc.left + m_nTreeSize + SPLIT_SIZE, rc.bottom - BAR_HEIGHT - m_nPanelSize,
			rc.Width() - m_nTreeSize - SPLIT_SIZE, m_nPanelSize, SWP_NOZORDER|SWP_SHOWWINDOW );
	}

	EndDeferWindowPos( hDWP );
}

void CLibraryFrame::OnPaint()
{
	CPaintDC dc( this );
	CRect rcClient, rc;

	GetClientRect( &rcClient );

	rc.SetRect(	rcClient.left + m_nTreeSize,
				rcClient.top,
				rcClient.left + m_nTreeSize + SPLIT_SIZE,
				rcClient.bottom );

	dc.FillSolidRect( rc.left, rc.top, 1, rc.Height(), GetSysColor( COLOR_BTNFACE ) );
	dc.FillSolidRect( rc.left + 1, rc.top, 1, rc.Height(), GetSysColor( COLOR_3DHIGHLIGHT ) );
	dc.FillSolidRect( rc.right - 1, rc.top, 1, rc.Height(), GetSysColor( COLOR_3DSHADOW ) );
	dc.FillSolidRect( rc.left + 2, rc.top, rc.Width() - 3, rc.Height(),
		GetSysColor( COLOR_BTNFACE ) );

	if ( m_nHeaderSize > 0 )
	{
		dc.FillSolidRect( rc.right, rcClient.top + BAR_HEIGHT - 1 + m_nHeaderSize,
			rcClient.right - rc.right, 1, GetSysColor( COLOR_3DHIGHLIGHT ) );
	}

	if ( Settings.Library.ShowVirtual == FALSE )
	{
		rc.SetRect( rcClient.left, rcClient.bottom - BAR_HEIGHT,
			rcClient.left + m_nTreeSize, rcClient.bottom - m_nTreeTypesHeight );
		dc.FillSolidRect( rc.left, rc.top, rc.Width(), 1, GetSysColor( COLOR_3DSHADOW ) );
		dc.FillSolidRect( rc.left, rc.top + 1, rc.Width(), 1, GetSysColor( COLOR_3DHIGHLIGHT ) );
		dc.FillSolidRect( rc.left, rc.top + 2, rc.Width(), rc.Height() - 2, GetSysColor( COLOR_BTNFACE ) );
	}

	if ( m_pPanel != NULL )
	{
		rc.SetRect(	rcClient.left + m_nTreeSize + SPLIT_SIZE,
					rcClient.bottom - BAR_HEIGHT - m_nPanelSize - SPLIT_SIZE,
					rcClient.right,
					rcClient.bottom - BAR_HEIGHT - m_nPanelSize );

		dc.FillSolidRect( rc.left, rc.top, rc.Width(), 1, GetSysColor( COLOR_BTNFACE ) );
		dc.FillSolidRect( rc.left, rc.top + 1, rc.Width(), 1, GetSysColor( COLOR_3DHIGHLIGHT ) );
		dc.FillSolidRect( rc.left, rc.bottom - 1, rc.Width(), 1, GetSysColor( COLOR_3DSHADOW ) );
		dc.FillSolidRect( rc.left, rc.top + 2, rc.Width(), rc.Height() - 3,
			GetSysColor( COLOR_BTNFACE ) );
	}
}

void CLibraryFrame::OnContextMenu(CWnd* /*pWnd*/, CPoint /*point*/)
{
//	if ( m_pView ) m_pView->SendMessage( WM_CONTEXTMENU, (WPARAM)pWnd->GetSafeHwnd(), MAKELONG( point.x, point.y ) );
}

void CLibraryFrame::OnMeasureItem(int /*nIDCtl*/, LPMEASUREITEMSTRUCT lpMeasureItemStruct)
{
	lpMeasureItemStruct->itemHeight = 18;
}

/////////////////////////////////////////////////////////////////////////////
// CLibraryFrame resizing behaviour

BOOL CLibraryFrame::OnSetCursor(CWnd* pWnd, UINT nHitTest, UINT message)
{
	CRect rcClient, rc;
	CPoint point;

	GetCursorPos( &point );
	GetClientRect( &rcClient );
	ClientToScreen( &rcClient );


	rc.SetRect(	theApp.m_bRTL ? rcClient.right - m_nTreeSize - SPLIT_SIZE :
				rcClient.left + m_nTreeSize,
				rcClient.top,
				theApp.m_bRTL ? rcClient.right - m_nTreeSize :
				rcClient.left + m_nTreeSize + SPLIT_SIZE,
				rcClient.bottom );

	if ( rc.PtInRect( point ) )
	{
		SetCursor( AfxGetApp()->LoadStandardCursor( IDC_SIZEWE ) );
		return TRUE;
	}

	if ( m_pPanel != NULL )
	{
		rc.SetRect(	theApp.m_bRTL ? rcClient.left :
					rcClient.left + m_nTreeSize + SPLIT_SIZE,
					rcClient.bottom - BAR_HEIGHT - m_nPanelSize - SPLIT_SIZE,
					theApp.m_bRTL ? rcClient.right - m_nTreeSize : rcClient.right,
					rcClient.bottom - BAR_HEIGHT - m_nPanelSize );

		if ( rc.PtInRect( point ) )
		{
			SetCursor( AfxGetApp()->LoadStandardCursor( IDC_SIZENS ) );
			return TRUE;
		}
	}

	return CWnd::OnSetCursor( pWnd, nHitTest, message );
}

void CLibraryFrame::OnLButtonDown(UINT nFlags, CPoint point)
{
	CRect rcClient, rc;

	GetClientRect( &rcClient );

	rc.SetRect(	rcClient.left + m_nTreeSize,
				rcClient.top,
				rcClient.left + m_nTreeSize + SPLIT_SIZE,
				rcClient.bottom );

	if ( rc.PtInRect( point ) )
	{
		DoSizeTree();
		return;
	}

	if ( m_pPanel != NULL )
	{
		rc.SetRect(	rcClient.left + m_nTreeSize + SPLIT_SIZE,
					rcClient.bottom - BAR_HEIGHT - m_nPanelSize - SPLIT_SIZE,
					rcClient.right,
					rcClient.bottom - BAR_HEIGHT - m_nPanelSize );

		if ( rc.PtInRect( point ) )
		{
			DoSizePanel();
			return;
		}
	}

	CWnd::OnLButtonDown( nFlags, point );
}

BOOL CLibraryFrame::DoSizeTree()
{
	MSG* pMsg = &AfxGetThreadState()->m_msgCur;
	CRect rcClient;
	CPoint point;

	GetClientRect( &rcClient );
	ClientToScreen( &rcClient );
	ClipCursor( &rcClient );
	SetCapture();

	GetClientRect( &rcClient );

	int nOffset = 0xFFFF;

	while ( GetAsyncKeyState( VK_LBUTTON ) & 0x8000 )
	{
		while ( ::PeekMessage( pMsg, NULL, WM_MOUSEFIRST, WM_MOUSELAST, PM_REMOVE ) );

		if ( ! AfxGetThread()->PumpMessage() )
		{
			AfxPostQuitMessage( 0 );
			break;
		}

		GetCursorPos( &point );
		ScreenToClient( &point );

		int nSplit = point.x - rcClient.left;

		if ( nOffset == 0xFFFF ) nOffset = m_nTreeSize - nSplit;
		nSplit += nOffset;

		nSplit = max( nSplit, 0 );
		nSplit = min( nSplit, int(rcClient.right - SPLIT_SIZE) );

		if ( nSplit < 8 )
			nSplit = 0;
		if ( nSplit > rcClient.right - SPLIT_SIZE - 8 )
			nSplit = rcClient.right - SPLIT_SIZE;

		if ( nSplit != m_nTreeSize )
		{
			m_nTreeSize = nSplit;
			OnSize( 1982, 0, 0 );
			Invalidate();
		}
	}

	ReleaseCapture();
	ClipCursor( NULL );

	return TRUE;
}

BOOL CLibraryFrame::DoSizePanel()
{
	MSG* pMsg = &AfxGetThreadState()->m_msgCur;
	CRect rcClient;
	CPoint point;

	GetClientRect( &rcClient );
	rcClient.left += m_nTreeSize + SPLIT_SIZE;
	rcClient.top += BAR_HEIGHT + m_nHeaderSize;
	rcClient.bottom -= BAR_HEIGHT;
	ClientToScreen( &rcClient );
	ClipCursor( &rcClient );
	SetCapture();

	ScreenToClient( &rcClient );

	int nOffset = 0xFFFF;

	while ( GetAsyncKeyState( VK_LBUTTON ) & 0x8000 )
	{
		while ( ::PeekMessage( pMsg, NULL, WM_MOUSEFIRST, WM_MOUSELAST, PM_REMOVE ) );

		if ( ! AfxGetThread()->PumpMessage() )
		{
			AfxPostQuitMessage( 0 );
			break;
		}

		GetCursorPos( &point );
		ScreenToClient( &point );

		int nSplit = rcClient.bottom - point.y;

		if ( nOffset == 0xFFFF ) nOffset = m_nPanelSize - nSplit;
		nSplit += nOffset;

		if ( nSplit < 8 )
			nSplit = 0;
		if ( nSplit > rcClient.Height() - SPLIT_SIZE - 8 )
			nSplit = rcClient.Height() - SPLIT_SIZE;

		if ( nSplit != m_nPanelSize )
		{
			m_nPanelSize = nSplit;
			OnSize( 1982, 0, 0 );
			Invalidate();
		}
	}

	ReleaseCapture();
	ClipCursor( NULL );

	return TRUE;
}

/////////////////////////////////////////////////////////////////////////////
// CLibraryFrame view and panel selection

void CLibraryFrame::SetView(CLibraryView* pView, BOOL bUpdate, BOOL bUser)
{
	CSingleLock pLock( &Library.m_pSection, TRUE );

	if ( bUser && pView != NULL )
	{
		for (	CLibraryTreeItem* pItem = m_pFolderSelection ; pItem ;
				pItem = pItem->m_pSelNext )
		{
			if ( pItem->m_pVirtual != NULL )
			{
				pItem->m_pVirtual->m_sBestView = pView->GetRuntimeClass()->m_lpszClassName;
			}
		}
	}

	if ( m_pFolderSelection != NULL && pView != NULL )
	{
		if ( Settings.Library.ShowVirtual && m_pView &&
			 m_pFolderSelection->m_pVirtual->m_pSchema )
			pView->m_bGhostFolder = 
				( m_pFolderSelection->m_pVirtual->m_pSchema->m_sURI == CSchema::uriGhostFolder );
		else 
			pView->m_bGhostFolder = FALSE;
	}

	if ( m_pView == pView )
	{
		if ( m_pView )
		{
			m_pView->Update();
			m_pView->ShowWindow( SW_SHOW );
			m_wndViewTop.Update( m_pView );
		}

		return;
	}

	m_wndViewTip.Hide();
	m_wndViewTip.SetOwner( this );

	CWnd* pFocus = GetFocus();
	BOOL bViewSel = ( pFocus == m_pView || ( pFocus && pFocus->GetParent() == m_pView ) );

	CLibraryView* pOld = m_pView;
	m_pView = pView;

	if ( m_pView ) m_pView->Create( this );
	OnSize( 1982, 0, 0 );

	if ( m_pView && ! bUpdate ) m_pView->Update();

	if ( pOld ) pOld->ShowWindow( SW_HIDE );
	if ( m_pView ) m_pView->ShowWindow( SW_SHOW );
	if ( pOld ) pOld->DestroyWindow();

	if ( m_pView && bUpdate ) Update( TRUE );

	m_wndViewTop.Update( m_pView );

	if ( m_pView )
	{
		CString strBar( m_pView->m_pszToolBar );
		strBar += Settings.Library.ShowVirtual ? _T(".Virtual") : _T(".Physical");
		Skin.CreateToolBar( strBar, &m_wndViewBottom );
		m_wndViewTip.SetOwner( m_pView );

		if ( bViewSel ) m_pView->SetFocus();
	}

	Invalidate();
}

void CLibraryFrame::SetPanel(CLibraryPanel* pPanel)
{
	if ( pPanel == m_pPanel )
	{
		if ( m_pPanel )
		{
			m_pPanel->Update();
			m_pPanel->ShowWindow( SW_SHOW );
		}
		return;
	}

	CLibraryPanel* pOld = m_pPanel;
	m_pPanel = pPanel;

	if ( m_pPanel ) m_pPanel->Create( this );
	OnSize( 1982, 0, 0 );

	if ( m_pPanel ) m_pPanel->Update();

	if ( pOld ) pOld->ShowWindow( SW_HIDE );
	if ( m_pPanel ) m_pPanel->ShowWindow( SW_SHOW );
	if ( pOld ) pOld->DestroyWindow();
}

/////////////////////////////////////////////////////////////////////////////
// CLibraryFrame update operations

BOOL CLibraryFrame::Update(BOOL bForce, BOOL bBestView)
{
	CSingleLock pLock( &Library.m_pSection );
	if ( ! pLock.Lock( bForce ? 500 : 50 ) ) return FALSE;

	if ( ! bForce && m_nLibraryCookie == Library.m_nUpdateCookie ) return FALSE;
	m_nLibraryCookie = Library.m_nUpdateCookie;

	m_bUpdating = TRUE;

	m_nFolderCookie		= GetTickCount();
	m_wndTree.Update( m_nFolderCookie );
	m_pFolderSelection	= m_wndTree.GetFirstSelected();

	CLibraryView* pFirstView	= NULL;
	CLibraryView* pBestView		= NULL;
	CString strBest;

	if ( m_pFolderSelection != NULL && m_pFolderSelection->m_pVirtual != NULL )
		strBest = m_pFolderSelection->m_pVirtual->GetBestView();

	for ( POSITION pos = m_pViews.GetHeadPosition() ; pos ; )
	{
		CLibraryView* pView = m_pViews.GetNext( pos );

		if ( pView->CheckAvailable( m_pFolderSelection ) )
		{
			if ( pFirstView == NULL ) pFirstView = pView;
			if ( strBest.CompareNoCase( CString( pView->GetRuntimeClass()->m_lpszClassName ) ) == 0 )
				pBestView = pView;
		}
	}

	int nHeaderSize = m_wndHeader.Update();

	if ( bBestView && pBestView != NULL )
	{
		if ( pBestView->IsKindOf( RUNTIME_CLASS(CLibraryCollectionView) ) )
			nHeaderSize = 0;
	}

	if ( nHeaderSize != m_nHeaderSize )
	{
		m_nHeaderSize = nHeaderSize;
		if ( m_nHeaderSize == 0 ) m_wndHeader.ShowWindow( SW_HIDE );
		OnSize( 1982, 0, 0 );
	}

	if ( pFirstView == NULL )
	{
		pFirstView = m_pViews.GetTail();
	}

	if ( pBestView != NULL && bBestView )
	{
		SetView( pBestView, FALSE, FALSE );
	}
	else if ( m_pView == NULL || m_pView->m_bAvailable == FALSE )
	{
		SetView( pFirstView, FALSE, FALSE );
	}
	else
	{
		SetView( m_pView, FALSE, FALSE );
	}

	UpdatePanel( TRUE );

	m_bUpdating = FALSE;

	return TRUE;
}

void CLibraryFrame::UpdatePanel(BOOL bForce)
{
	if ( ! bForce && ! m_bViewSelection ) return;
	m_bViewSelection = FALSE;

	m_pViewSelection			= m_pView ? &m_pView->m_pSelection : &m_pViewEmpty;
	CLibraryPanel* pFirstPanel	= NULL;

	for ( POSITION pos = m_pPanels.GetHeadPosition() ; pos ; )
	{
		CLibraryPanel* pPanel = m_pPanels.GetNext( pos );

		if ( pPanel->CheckAvailable( m_pFolderSelection, m_pViewSelection )
			&& pFirstPanel == NULL ) pFirstPanel = pPanel;
	}

	if ( m_bPanelShow )
	{
		if ( m_pPanel == NULL || m_pPanel->m_bAvailable == FALSE )
		{
			SetPanel( pFirstPanel );
		}
		else
		{
			SetPanel( m_pPanel );
		}
	}
}

BOOL CLibraryFrame::Display(CLibraryFolder* pFolder)
{
	if ( Settings.Library.ShowVirtual != FALSE ) OnLibraryTreePhysical();
	return m_wndTree.SelectFolder( pFolder );
}

BOOL CLibraryFrame::Display(CAlbumFolder* pFolder)
{
	if ( Settings.Library.ShowVirtual != TRUE ) OnLibraryTreeVirtual();
	return m_wndTree.SelectFolder( pFolder );
}

BOOL CLibraryFrame::Display(CLibraryFile* pFile)
{
	if ( Settings.Library.ShowVirtual )
	{
		if ( CAlbumFolder* pFolder = Library.GetAlbumRoot()->FindFile( pFile ) )
		{
			Display( pFolder );
		}
		else
		{
			Display( pFile->m_pFolder );
		}
	}
	else
	{
		Settings.Library.FilterURI.Empty();
		Display( pFile->m_pFolder );
	}

	return Select( pFile->m_nIndex );
}

BOOL CLibraryFrame::Select(DWORD nObject)
{
	if ( m_pView == NULL ) return FALSE;
	return m_pView->Select( nObject );
}

/////////////////////////////////////////////////////////////////////////////
// CLibraryFrame selection events

CLibraryTreeItem* CLibraryFrame::GetFolderSelection() const
{
	return m_pFolderSelection;
}

CLibraryList* CLibraryFrame::GetViewSelection() const
{
	return m_pViewSelection;
}

void CLibraryFrame::OnTreeSelection(NMHDR* /*pNotify*/, LRESULT* pResult)
{
	if ( ! m_bUpdating ) Update( TRUE, TRUE );
	*pResult = 0;
}

void CLibraryFrame::OnViewSelection()
{
	if ( m_bUpdating ) return;
	m_bViewSelection = TRUE;
	PostMessage( WM_TIMER, 1 );
}

void CLibraryFrame::OnTimer(UINT_PTR /*nIDEvent*/)
{
	if ( m_bViewSelection ) UpdatePanel( FALSE );
}

void CLibraryFrame::OnFilterTypes()
{
	if ( CSchema* pSchema = m_wndTreeTypes.GetSelected() )
	{
		Settings.Library.FilterURI = pSchema->m_sURI;
	}
	else
	{
		Settings.Library.FilterURI.Empty();
	}

	Update();
}

/////////////////////////////////////////////////////////////////////////////
// CLibraryFrame command handlers

void CLibraryFrame::OnUpdateLibraryTreePhysical(CCmdUI* pCmdUI)
{
	pCmdUI->SetCheck( Settings.Library.ShowVirtual == FALSE );
}

void CLibraryFrame::OnLibraryTreePhysical()
{
	if ( Settings.Library.ShowVirtual != FALSE )
	{
		Settings.Library.ShowVirtual = FALSE;
		OnSkinChange();
		m_wndTreeBottom.Invalidate();
	}
}

void CLibraryFrame::OnUpdateLibraryTreeVirtual(CCmdUI* pCmdUI)
{
	pCmdUI->SetCheck( Settings.Library.ShowVirtual == TRUE );
}

void CLibraryFrame::OnLibraryTreeVirtual()
{
	if ( Settings.Library.ShowVirtual != TRUE )
	{
		Settings.Library.ShowVirtual = TRUE;
		OnSkinChange();
		m_wndTreeBottom.Invalidate();
	}
}

void CLibraryFrame::OnLibraryRefresh()
{
	CWaitCursor pCursor;
	Update( TRUE );
}

void CLibraryFrame::OnUpdateLibraryPanel(CCmdUI* pCmdUI)
{
	pCmdUI->SetCheck( m_pPanel != NULL );
}

void CLibraryFrame::OnLibraryPanel()
{
	if ( m_pPanel )
	{
		m_bPanelShow = FALSE;
		SetPanel( NULL );
	}
	else
	{
		m_bPanelShow = TRUE;
		Update( TRUE );
	}
}

void CLibraryFrame::OnLibrarySearch()
{
	CNewSearchDlg dlg( NULL, auto_ptr< CQuerySearch >(), TRUE );

	if ( dlg.DoModal() == IDOK )
	{
		RunLocalSearch( dlg.GetSearch() );
	}
}

void CLibraryFrame::OnLibrarySearchQuick()
{
	CString str;
	m_wndSearch.GetWindowText( str );

	if ( str.GetLength() > 0 )
	{
		auto_ptr< CQuerySearch > pSearch( new CQuerySearch() );
		pSearch->m_sSearch = str;
		RunLocalSearch( pSearch );
		m_wndSearch.SetWindowText( _T("") );
	}
	else
	{
		OnLibrarySearch();
	}
}

void CLibraryFrame::OnToolbarReturn()
{
	if ( GetFocus() == &m_wndSearch )
	{
		if ( m_wndSearch.GetWindowTextLength() > 0 )
			OnLibrarySearchQuick();
		else if ( m_pView != NULL )
			m_pView->SetFocus();
	}
}

void CLibraryFrame::OnToolbarEscape()
{
	if ( GetFocus() == &m_wndSearch )
	{
		m_wndSearch.SetWindowText( _T("") );
		if ( m_pView != NULL ) m_pView->SetFocus();
	}
}

void CLibraryFrame::RunLocalSearch(auto_ptr< CQuerySearch > pSearch)
{
	CWaitCursor pCursor;

	pSearch->BuildWordList( true, true );

	CAlbumFolder* pRoot		= Library.GetAlbumRoot();
	CAlbumFolder* pFolder	= pRoot->GetFolderByURI( CSchema::uriSearchFolder );

	if ( pFolder == NULL )
	{
		pFolder = pRoot->AddFolder( CSchema::uriSearchFolder, _T("Search Results") );
		if ( pFolder->m_pSchema != NULL )
		{
			int nColon = pFolder->m_pSchema->m_sTitle.Find( ':' );
			if ( nColon >= 0 ) pFolder->m_sName = pFolder->m_pSchema->m_sTitle.Mid( nColon + 1 );
		}
	}
	else
	{
		// Get translated name of the default search folder
		// We will clear it, not others as user may want to keep several folders
		CString strFolderName;
		int nColon = pFolder->m_pSchema->m_sTitle.Find( ':' );
		if ( nColon >= 0 ) 
			strFolderName = pFolder->m_pSchema->m_sTitle.Mid( nColon + 1 );
		if ( !strFolderName.IsEmpty() )
		{
			pFolder	= pRoot->GetFolder( strFolderName );
		}

		if ( pFolder == NULL )
		{
			pFolder = pRoot->AddFolder( CSchema::uriSearchFolder, _T("Search Results") );
			if ( pFolder->m_pSchema != NULL )
			{
				if ( !strFolderName.IsEmpty() ) 
					pFolder->m_sName = strFolderName;
			}
		}
		else
			pFolder->Clear();
	}

	if ( pFolder->m_pSchema != NULL )
	{
		CString strDate, strTime;
		SYSTEMTIME pTime;

		GetLocalTime( &pTime );
		GetDateFormat( LOCALE_USER_DEFAULT, 0, &pTime, _T("yyyy-MM-dd"), strDate.GetBuffer( 64 ), 64 );
		GetTimeFormat( LOCALE_USER_DEFAULT, 0, &pTime, _T("hh:mm tt"), strTime.GetBuffer( 64 ), 64 );
		strDate.ReleaseBuffer(); strTime.ReleaseBuffer();

		CXMLElement* pOuter = pFolder->m_pSchema->Instantiate();
		CXMLElement* pInner = pOuter->AddElement( _T("searchFolder") );
		pInner->AddAttribute( _T("title"), pFolder->m_sName );
		pInner->AddAttribute( _T("content"), pSearch->m_sSearch );
		pInner->AddAttribute( _T("date"), strDate );
		pInner->AddAttribute( _T("time"), strTime );
		pFolder->SetMetadata( pOuter );
		delete pOuter;
	}

	{
		CQuickLock oLock( Library.m_pSection );

		CList< CLibraryFile* >* pFiles = Library.Search( pSearch.get(), 0, TRUE );

		if ( pFiles != NULL )
		{
			for ( POSITION pos = pFiles->GetHeadPosition() ; pos ; )
			{
				CLibraryFile* pFile = (CLibraryFile*)pFiles->GetNext( pos );

				if ( Settings.Search.SchemaTypes && pSearch->m_pSchema != NULL )
				{
					if ( pSearch->m_pSchema->FilterType( pFile->m_sName, TRUE ) == FALSE )
						pFile = NULL;
				}

				if ( pFile != NULL && pFile->IsAvailable() ) pFolder->AddFile( pFile );
			}

			delete pFiles;
		}
	}

	Update();
	Display( pFolder );
}

void CLibraryFrame::OnSetFocus(CWnd* pOldWnd)
{
	CWnd::OnSetFocus( pOldWnd );

	if ( m_pView != NULL && IsWindow( m_pView->m_hWnd ) && m_pView->IsWindowVisible() )
		m_pView->SetFocus();
}