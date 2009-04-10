//
// WndSearchMonitor.cpp
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
#include "QuerySearch.h"
#include "WndSearchMonitor.h"
#include "WndSearch.h"
#include "LiveList.h"
#include "XML.h"
#include "SHA.h"
#include "ED2K.h"
#include "TigerTree.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

IMPLEMENT_SERIAL(CSearchMonitorWnd, CPanelWnd, 0)

BEGIN_MESSAGE_MAP(CSearchMonitorWnd, CPanelWnd)
	//{{AFX_MSG_MAP(CSearchMonitorWnd)
	ON_WM_CREATE()
	ON_WM_SIZE()
	ON_WM_DESTROY()
	ON_WM_CONTEXTMENU()
	ON_UPDATE_COMMAND_UI(ID_SEARCHMONITOR_PAUSE, OnUpdateSearchMonitorPause)
	ON_COMMAND(ID_SEARCHMONITOR_PAUSE, OnSearchMonitorPause)
	ON_COMMAND(ID_SEARCHMONITOR_CLEAR, OnSearchMonitorClear)
	ON_UPDATE_COMMAND_UI(ID_HITMONITOR_SEARCH, OnUpdateSearchMonitorSearch)
	ON_COMMAND(ID_HITMONITOR_SEARCH, OnSearchMonitorSearch)
	ON_NOTIFY(LVN_COLUMNCLICK, IDC_SEARCHES, OnDblClkList)
	ON_WM_TIMER()
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()


/////////////////////////////////////////////////////////////////////////////
// CSearchMonitorWnd construction

CSearchMonitorWnd::CSearchMonitorWnd()
{
	Create( IDR_SEARCHMONITORFRAME );
}

CSearchMonitorWnd::~CSearchMonitorWnd()
{
}

/////////////////////////////////////////////////////////////////////////////
// CSearchMonitorWnd message handlers

int CSearchMonitorWnd::OnCreate(LPCREATESTRUCT lpCreateStruct) 
{
	if ( CPanelWnd::OnCreate( lpCreateStruct ) == -1 ) return -1;
	
	m_wndList.Create( WS_VISIBLE|LVS_ICON|LVS_AUTOARRANGE|LVS_REPORT|LVS_SHOWSELALWAYS,
		rectDefault, this, IDC_SEARCHES );

	m_pSizer.Attach( &m_wndList );
	
	m_wndList.SendMessage( LVM_SETEXTENDEDLISTVIEWSTYLE,
		LVS_EX_FULLROWSELECT|LVS_EX_HEADERDRAGDROP|LVS_EX_LABELTIP,
		LVS_EX_FULLROWSELECT|LVS_EX_HEADERDRAGDROP|LVS_EX_LABELTIP );
	
	VERIFY( m_gdiImageList.Create( 16, 16, ILC_MASK|ILC_COLOR32, 1, 1 ) );
	AddIcon( IDR_SEARCHMONITORFRAME , m_gdiImageList );
	m_wndList.SetImageList( &m_gdiImageList, LVSIL_SMALL );

	m_wndList.InsertColumn( 0, _T("Search"), LVCFMT_LEFT, 200, -1 );
	m_wndList.InsertColumn( 1, _T("URN"), LVCFMT_LEFT, 120, 0 );
	m_wndList.InsertColumn( 2, _T("Schema"), LVCFMT_LEFT, 120, 1 );
	m_wndList.InsertColumn( 3, _T("Direction"), LVCFMT_LEFT, 120, 1 );

	m_wndList.SetFont( &theApp.m_gdiFont );
	
	LoadState( _T("CSearchMonitorWnd"), TRUE );
	
	m_bPaused = FALSE;
	SetTimer( 2, 250, NULL );
	
	CSingleLock pLock( &theApp.m_mSearchMonitorList, TRUE );
	theApp.m_oSearchMonitorList.push_front(this);

	return 0;
}

void CSearchMonitorWnd::OnDestroy() 
{
	CSingleLock pListLock( &theApp.m_mSearchMonitorList, TRUE );
	theApp.m_oSearchMonitorList.remove(this);
	pListLock.Unlock();

	KillTimer( 2 );

	CSingleLock pLock( &m_pSection, TRUE );
	m_bPaused = TRUE;

	for ( POSITION pos = m_pQueue.GetHeadPosition() ; pos ; )
	{
		delete m_pQueue.GetNext( pos );
	}
	m_pQueue.RemoveAll();

	pLock.Unlock();

	Settings.SaveList( _T("CSearchMonitorWnd"), &m_wndList );
	SaveState( _T("CSearchMonitorWnd") );

	CPanelWnd::OnDestroy();
}

void CSearchMonitorWnd::OnSkinChange()
{
	CPanelWnd::OnSkinChange();
	Settings.LoadList( _T("CSearchMonitorWnd"), &m_wndList );
}

void CSearchMonitorWnd::OnSize(UINT nType, int cx, int cy) 
{
	CPanelWnd::OnSize( nType, cx, cy );
	m_pSizer.Resize( cx );
	m_wndList.SetWindowPos( NULL, 0, 0, cx, cy, SWP_NOZORDER );
}

void CSearchMonitorWnd::OnContextMenu(CWnd* /*pWnd*/, CPoint point) 
{
	TrackPopupMenu( _T("CSearchMonitorWnd"), point, ID_HITMONITOR_SEARCH );
}

void CSearchMonitorWnd::OnUpdateSearchMonitorSearch(CCmdUI* pCmdUI) 
{
	pCmdUI->Enable( m_wndList.GetSelectedCount() == 1 );
}

void CSearchMonitorWnd::OnSearchMonitorSearch() 
{
	int nItem = m_wndList.GetNextItem( -1, LVNI_SELECTED );
	Hashes::Sha1Hash oSHA1;
	Hashes::Ed2kHash oED2K;
	Hashes::TigerHash oTiger;

	if ( nItem >= 0 )
	{
		auto_ptr< CQuerySearch > pSearch( new CQuerySearch() );

		pSearch->m_sSearch = m_wndList.GetItemText( nItem, 1 );
		if ( _tcsicmp( pSearch->m_sSearch, _T("None") ) != 0)
		if ( oSHA1.fromUrn ( m_wndList.GetItemText( nItem, 1 ) ) ) pSearch->m_oSHA1 = oSHA1;
		if ( oTiger.fromUrn ( m_wndList.GetItemText( nItem, 1 ) ) ) pSearch->m_oTiger = oTiger;
		if ( oED2K.fromUrn ( m_wndList.GetItemText( nItem, 1 ) ) ) pSearch->m_oED2K = oED2K;

		if ( !oSHA1 && !oTiger && !oED2K ) pSearch->m_sSearch = m_wndList.GetItemText( nItem, 0 );
		CQuerySearch::OpenWindow( pSearch );

/*
		if ( pSearch->m_sSearch.GetLength() == 0 || 
			 _tcscmp( pSearch->m_sSearch, _T("\\") ) == 0 )
		{
			pSearch->m_sSearch = m_wndList.GetItemText( nItem, 1 );
			
			if ( _tcsicmp( pSearch->m_sSearch, _T("None") ) != 0 && 
				 _tcsncmp( pSearch->m_sSearch, _T("btih:"), 5 ) != 0 )
				pSearch->m_sSearch = _T("urn:") + m_wndList.GetItemText( nItem, 1 );
			else
				pSearch->m_sSearch.Empty();
		}

		if ( ! pSearch->m_sSearch.IsEmpty() )
			CQuerySearch::OpenWindow( pSearch );
*/

	}
}

void CSearchMonitorWnd::OnUpdateSearchMonitorPause(CCmdUI* pCmdUI) 
{
	pCmdUI->SetCheck( m_bPaused );
}

void CSearchMonitorWnd::OnSearchMonitorPause() 
{
	m_bPaused = ! m_bPaused;
}

void CSearchMonitorWnd::OnSearchMonitorClear() 
{
	m_wndList.DeleteAllItems();
}

void CSearchMonitorWnd::OnDblClkList(NMHDR* /*pNotifyStruct*/, LRESULT *pResult)
{
	OnSearchMonitorSearch();
	*pResult = 0;
}

/////////////////////////////////////////////////////////////////////////////
// CPanelWnd event handlers

void CSearchMonitorWnd::OnQuerySearch(CQuerySearch* pSearch, BOOL bOUT )
{
	if ( m_bPaused || m_hWnd == NULL ) return;

	CSingleLock pLock( &m_pSection, TRUE );

	if ( m_bPaused ) return;

	CLiveItem* pItem = new CLiveItem( 4, NULL );

	CString strSearch	= pSearch->m_sSearch;
	CString strSchema	= _T("None");
	CString strURN		= _T("");

	if ( pSearch->m_oSHA1 && pSearch->m_oTiger )
	{
		strURN	= _T("urn:bitprint:")
				+ pSearch->m_oSHA1.toString()
				+ '.'
				+ pSearch->m_oTiger.toString();
	}
	else if ( pSearch->m_oTiger )
	{
		strURN = pSearch->m_oTiger.toUrn();
	}
	else if ( pSearch->m_oSHA1 )
	{
		strURN = pSearch->m_oSHA1.toUrn();
	}

	if ( pSearch->m_oED2K )
	{
		if ( !strURN.IsEmpty() ) strURN += " ";
		strURN += pSearch->m_oED2K.toUrn();
	}
	
	if ( pSearch->m_oMD5 )
	{
		if ( !strURN.IsEmpty() ) strURN += " ";
		strURN += pSearch->m_oMD5.toUrn();
	}

	if ( pSearch->m_oBTH )
	{
		if ( !strURN.IsEmpty() ) strURN += " ";
		strURN += pSearch->m_oBTH.toUrn();
	}

	if (strURN.IsEmpty()) strURN = _T("None");

	if ( pSearch->m_pXML )
	{
		strSearch += ' ';
		strSearch += pSearch->m_pXML->GetRecursiveWords();
		
		strSchema = pSearch->m_pXML->GetAttributeValue( CXMLAttribute::schemaName, _T("") );
		
		int nSlash = strSchema.ReverseFind( '/' );
		if ( nSlash > 0 ) strSchema = strSchema.Mid( nSlash + 1 );
	}

	pItem->Set( 0, strSearch );
	pItem->Set( 1, strURN );
	pItem->Set( 2, strSchema );
	if ( bOUT ) 
	{
		pItem->Set( 3, _T("OUT") );
	}
	else
	{
		pItem->Set( 3, _T("IN") );
	}
		
	m_pQueue.AddTail( pItem );
}

void CSearchMonitorWnd::OnTimer(UINT_PTR nIDEvent) 
{
	if ( nIDEvent != 2 ) return;

	BOOL bScroll = m_wndList.GetTopIndex() + m_wndList.GetCountPerPage() >= m_wndList.GetItemCount();

	CSingleLock pLock( &m_pSection );

	while ( TRUE )
	{
		pLock.Lock();

		if ( m_pQueue.GetCount() == 0 ) break;
		CLiveItem* pItem = m_pQueue.RemoveHead();

		pLock.Unlock();

		if ( (DWORD)m_wndList.GetItemCount() >= Settings.Search.MonitorQueue && Settings.Search.MonitorQueue > 0 )
		{
			m_wndList.DeleteItem( 0 );
		}

		/*int nItem =*/ pItem->Add( &m_wndList, -1, 4 );

		delete pItem;
	}

	if ( bScroll ) m_wndList.EnsureVisible( m_wndList.GetItemCount() - 1, FALSE );
}