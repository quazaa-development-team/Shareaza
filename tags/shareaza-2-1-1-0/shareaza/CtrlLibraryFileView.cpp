//
// CtrlLibraryFileView.cpp
//
//	Date:			"$Date: 2005/05/20 22:10:36 $"
//	Revision:		"$Revision: 1.19 $"
//  Last change by:	"$Author: spooky23 $"
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
#include "Library.h"
#include "LibraryFolders.h"
#include "SharedFolder.h"
#include "SharedFile.h"
#include "AlbumFolder.h"
#include "FileExecutor.h"
#include "CoolInterface.h"
#include "ShellIcons.h"
#include "Skin.h"
#include "SHA.h"
#include "ED2K.h"
#include "CtrlLibraryFrame.h"
#include "CtrlLibraryFileView.h"
#include "CtrlLibraryTree.h"
#include "CtrlLibraryTip.h"

#include "DlgFilePropertiesSheet.h"
#include "DlgFileCopy.h"
#include "DlgBitziDownload.h"
#include "DlgURLCopy.h"
#include "DlgURLExport.h"
#include "DlgDeleteFile.h"
#include "DlgTorrentSeed.h"
#include "DlgDecodeMetadata.h"
#include "RelatedSearch.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

IMPLEMENT_DYNAMIC(CLibraryFileView, CLibraryView)

BEGIN_MESSAGE_MAP(CLibraryFileView, CLibraryView)
	//{{AFX_MSG_MAP(CLibraryFileView)
	ON_WM_CONTEXTMENU()
	ON_WM_MOUSEMOVE()
	ON_WM_LBUTTONDOWN()
	ON_WM_RBUTTONDOWN()
	ON_WM_KEYDOWN()
	ON_UPDATE_COMMAND_UI(ID_LIBRARY_LAUNCH, OnUpdateLibraryLaunch)
	ON_COMMAND(ID_LIBRARY_LAUNCH, OnLibraryLaunch)
	ON_UPDATE_COMMAND_UI(ID_LIBRARY_ENQUEUE, OnUpdateLibraryEnqueue)
	ON_COMMAND(ID_LIBRARY_ENQUEUE, OnLibraryEnqueue)
	ON_UPDATE_COMMAND_UI(ID_LIBRARY_URL, OnUpdateLibraryURL)
	ON_COMMAND(ID_LIBRARY_URL, OnLibraryURL)
	ON_UPDATE_COMMAND_UI(ID_LIBRARY_MOVE, OnUpdateLibraryMove)
	ON_COMMAND(ID_LIBRARY_MOVE, OnLibraryMove)
	ON_UPDATE_COMMAND_UI(ID_LIBRARY_COPY, OnUpdateLibraryCopy)
	ON_COMMAND(ID_LIBRARY_COPY, OnLibraryCopy)
	ON_UPDATE_COMMAND_UI(ID_LIBRARY_DELETE, OnUpdateLibraryDelete)
	ON_COMMAND(ID_LIBRARY_DELETE, OnLibraryDelete)
	ON_UPDATE_COMMAND_UI(ID_LIBRARY_BITZI_WEB, OnUpdateLibraryBitziWeb)
	ON_COMMAND(ID_LIBRARY_BITZI_WEB, OnLibraryBitziWeb)
	ON_UPDATE_COMMAND_UI(ID_LIBRARY_BITZI_DOWNLOAD, OnUpdateLibraryBitziDownload)
	ON_COMMAND(ID_LIBRARY_BITZI_DOWNLOAD, OnLibraryBitziDownload)
	ON_UPDATE_COMMAND_UI(ID_LIBRARY_SHARED_FILE, OnUpdateLibraryShared)
	ON_COMMAND(ID_LIBRARY_SHARED_FILE, OnLibraryShared)
	ON_UPDATE_COMMAND_UI(ID_LIBRARY_PROPERTIES, OnUpdateLibraryProperties)
	ON_COMMAND(ID_LIBRARY_PROPERTIES, OnLibraryProperties)
	ON_WM_CREATE()
	ON_UPDATE_COMMAND_UI(ID_LIBRARY_UNLINK, OnUpdateLibraryUnlink)
	ON_COMMAND(ID_LIBRARY_UNLINK, OnLibraryUnlink)
	ON_UPDATE_COMMAND_UI(ID_SEARCH_FOR_THIS, OnUpdateSearchForThis)
	ON_COMMAND(ID_SEARCH_FOR_THIS, OnSearchForThis)
	ON_UPDATE_COMMAND_UI(ID_SEARCH_FOR_SIMILAR, OnUpdateSearchForSimilar)
	ON_COMMAND(ID_SEARCH_FOR_SIMILAR, OnSearchForSimilar)
	ON_UPDATE_COMMAND_UI(ID_SEARCH_FOR_ARTIST, OnUpdateSearchForArtist)
	ON_COMMAND(ID_SEARCH_FOR_ARTIST, OnSearchForArtist)
	ON_UPDATE_COMMAND_UI(ID_SEARCH_FOR_ALBUM, OnUpdateSearchForAlbum)
	ON_COMMAND(ID_SEARCH_FOR_ALBUM, OnSearchForAlbum)
	ON_UPDATE_COMMAND_UI(ID_SEARCH_FOR_SERIES, OnUpdateSearchForSeries)
	ON_COMMAND(ID_SEARCH_FOR_SERIES, OnSearchForSeries)
	ON_UPDATE_COMMAND_UI(ID_LIBRARY_CREATETORRENT, OnUpdateLibraryCreateTorrent)
	ON_COMMAND(ID_LIBRARY_CREATETORRENT, OnLibraryCreateTorrent)
	ON_UPDATE_COMMAND_UI(ID_LIBRARY_REBUILD_ANSI, OnUpdateLibraryRebuildAnsi)
	ON_COMMAND(ID_LIBRARY_REBUILD_ANSI, OnLibraryRebuildAnsi)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()


/////////////////////////////////////////////////////////////////////////////
// CLibraryFileView construction

CLibraryFileView::CLibraryFileView()
{
	m_pszToolBar = _T("CLibraryFileView");
}

CLibraryFileView::~CLibraryFileView()
{
}

/////////////////////////////////////////////////////////////////////////////
// CLibraryFileView selected item interface

BOOL CLibraryFileView::CheckAvailable(CLibraryTreeItem* pSel)
{
	m_bAvailable = FALSE;
	if ( pSel == NULL ) return m_bAvailable;
	m_bAvailable = TRUE;

	if ( pSel->m_pSelNext == NULL && pSel->m_pVirtual != NULL )
	{
		m_bAvailable = ( pSel->m_pVirtual->GetFileCount() > 0 );
	}

	return m_bAvailable;
}

void CLibraryFileView::StartSelectedFileLoop()
{
	m_posSel = m_pSelection.GetHeadPosition();
}

CLibraryFile* CLibraryFileView::GetNextSelectedFile()
{
	while ( m_posSel )
	{
		CLibraryFile* pFile = Library.LookupFile( m_pSelection.GetNext( m_posSel ) );
		if ( pFile != NULL && pFile->IsAvailable() ) return pFile;
	}
	
	return NULL;
}

CLibraryFile* CLibraryFileView::GetSelectedFile()
{
	if ( m_pSelection.GetCount() == 0 ) return NULL;
	CLibraryFile* pFile = Library.LookupFile( m_pSelection.GetHead() );
	if ( pFile != NULL && pFile->IsAvailable() ) return pFile;
	return NULL;
}

/////////////////////////////////////////////////////////////////////////////
// CLibraryFileView message handlers

int CLibraryFileView::OnCreate(LPCREATESTRUCT lpCreateStruct) 
{
	if ( CLibraryView::OnCreate( lpCreateStruct ) == -1 ) return -1;
	m_bEditing = FALSE;	
	return 0;
}

BOOL CLibraryFileView::PreTranslateMessage(MSG* pMsg) 
{
	if ( pMsg->message == WM_KEYDOWN && ! m_bEditing )
	{
		switch ( pMsg->wParam )
		{
		case VK_RETURN:
			OnLibraryLaunch();
			return TRUE;
		case VK_DELETE:
			OnLibraryDelete();
			return TRUE;
		}
	}
	else if ( pMsg->message == WM_SYSKEYDOWN && pMsg->wParam == VK_RETURN )
	{
		OnLibraryProperties();
		return TRUE;
	}
	
	return CLibraryView::PreTranslateMessage( pMsg );
}

void CLibraryFileView::OnContextMenu(CWnd* pWnd, CPoint point) 
{
	CString strName( m_pszToolBar );
	strName += Settings.Library.ShowVirtual ? _T(".Virtual") : _T(".Physical");
	Skin.TrackPopupMenu( strName, point, ID_LIBRARY_LAUNCH );
}

void CLibraryFileView::OnMouseMove(UINT nFlags, CPoint point) 
{
	if ( DWORD nFile = HitTestIndex( point ) )
	{
		GetToolTip()->Show( (LPVOID)nFile );
	}
	else
	{
		GetToolTip()->Hide();
	}
}

void CLibraryFileView::OnLButtonDown(UINT nFlags, CPoint point) 
{
	GetToolTip()->Hide();

	CWnd::OnLButtonDown( nFlags, point );
}

void CLibraryFileView::OnRButtonDown(UINT nFlags, CPoint point) 
{
	GetToolTip()->Hide();
	
	CWnd::OnRButtonDown( nFlags, point );
}

void CLibraryFileView::OnKeyDown(UINT nChar, UINT nRepCnt, UINT nFlags) 
{
	GetToolTip()->Hide();
	
	CWnd::OnKeyDown( nChar, nRepCnt, nFlags );
}

/////////////////////////////////////////////////////////////////////////////
// CLibraryFileView command handlers

void CLibraryFileView::OnUpdateLibraryLaunch(CCmdUI* pCmdUI) 
{
	pCmdUI->Enable( GetSelectedCount() > 0 );
}

void CLibraryFileView::OnLibraryLaunch() 
{
	CSingleLock pLock( &Library.m_pSection, TRUE );
	
	StartSelectedFileLoop();

	for ( CLibraryFile* pFile ; pFile = GetNextSelectedFile() ; )
	{
		CString strPath = pFile->GetPath();

		if ( pFile->m_bVerify == TS_FALSE )
		{
			DWORD nIndex = pFile->m_nIndex;
			CString strFormat, strMessage;
			
			LoadString( strFormat, IDS_LIBRARY_VERIFY_FAIL );
			strMessage.Format( strFormat, (LPCTSTR)strPath );
			
			pLock.Unlock();
			UINT nResponse = AfxMessageBox( strMessage, MB_ICONEXCLAMATION|MB_YESNOCANCEL|MB_DEFBUTTON2 );
			if ( nResponse == IDCANCEL ) break;
			pLock.Lock();
			if ( nResponse == IDNO ) continue;
			pLock.Unlock();
			LoadString( strMessage, IDS_LIBRARY_VERIFY_FIX );
			nResponse = AfxMessageBox( strMessage, MB_ICONQUESTION|MB_YESNOCANCEL|MB_DEFBUTTON2 );
			if ( nResponse == IDCANCEL ) break;
			pLock.Lock();
			
			if ( nResponse == IDYES )
			{
				pFile = Library.LookupFile( nIndex );
				if ( NULL == pFile ) continue;
				pFile->m_bVerify = TS_UNKNOWN;
				Library.Update();
			}
		}
		
		pLock.Unlock();
		
		LPCTSTR pszType = _tcsrchr( strPath, '.' );
		if ( pszType != NULL && _tcsicmp( pszType, _T(".torrent") ) == 0 )
		{
			CTorrentSeedDlg dlg( strPath );
			dlg.DoModal();
		}
		else
		{
			if ( ! CFileExecutor::Execute( strPath ) ) break;
		}
		
		pLock.Lock();
	}
}

void CLibraryFileView::OnUpdateLibraryEnqueue(CCmdUI* pCmdUI) 
{
	CSingleLock pLock( &Library.m_pSection );
	
	if ( GetSelectedCount() > 0 && pLock.Lock( 100 ) )
	{
		StartSelectedFileLoop();
		
		for ( CLibraryFile* pFile ; pFile = GetNextSelectedFile() ; )
		{
			if ( LPCTSTR pszType = _tcsrchr( pFile->m_sName, '.' ) )
			{
				CString strType;
				strType.Format( _T("|%s|"), pszType + 1 );
				
				if ( _tcsistr( Settings.MediaPlayer.FileTypes, strType ) != NULL )
				{
					pCmdUI->Enable( TRUE );
					return;
				}
			}
		}
	}
	
	pCmdUI->Enable( FALSE );
}

void CLibraryFileView::OnLibraryEnqueue() 
{
	CSingleLock pLock( &Library.m_pSection, TRUE );
	
	StartSelectedFileLoop();
	
	for ( CLibraryFile* pFile ; pFile = GetNextSelectedFile() ; )
	{
		CString strPath = pFile->GetPath();
		pLock.Unlock();
		CFileExecutor::Enqueue( strPath );
		pLock.Lock();
	}
}

void CLibraryFileView::OnUpdateLibraryURL(CCmdUI* pCmdUI) 
{
	CString strMessage;

	pCmdUI->Enable( GetSelectedCount() > 0 );
	GetSelectedCount() > 1 ? LoadString( strMessage, IDS_LIBRARY_EXPORTURIS ) : LoadString( strMessage, IDS_LIBRARY_COPYURI );
	pCmdUI->SetText( strMessage );
}

void CLibraryFileView::OnLibraryURL() 
{
	CSingleLock pLock( &Library.m_pSection, TRUE );
	
	if ( GetSelectedCount() == 1 )
	{
		CLibraryFile* pFile = GetSelectedFile();
		if ( ! pFile ) return;
		
		CURLCopyDlg dlg;
		
		dlg.m_sName = pFile->m_sName;
		dlg.m_bSize = TRUE;
		dlg.m_nSize = pFile->GetSize();
		dlg.m_bSHA1 = pFile->m_bSHA1;
		if ( pFile->m_bSHA1 ) dlg.m_pSHA1 = pFile->m_pSHA1;
		dlg.m_bTiger = pFile->m_bTiger;
		if ( pFile->m_bTiger ) dlg.m_pTiger = pFile->m_pTiger;
		dlg.m_bED2K = pFile->m_bED2K;
		if ( pFile->m_bED2K ) dlg.m_pED2K = pFile->m_pED2K;
		
		pLock.Unlock();
		
		dlg.DoModal();
	}
	else
	{
		CURLExportDlg dlg;
		
		StartSelectedFileLoop();
		
		for ( CLibraryFile* pFile ; pFile = GetNextSelectedFile() ; )
		{
			dlg.AddFile( pFile );
		}

		pLock.Unlock();

		if ( dlg.m_pFiles.GetCount() ) dlg.DoModal();
	}
}

void CLibraryFileView::OnUpdateLibraryMove(CCmdUI* pCmdUI) 
{
	pCmdUI->Enable( GetSelectedCount() > 0 );
}

void CLibraryFileView::OnLibraryMove() 
{
	CSingleLock pLock( &Library.m_pSection, TRUE );
	CFileCopyDlg dlg( NULL, TRUE );
	
	StartSelectedFileLoop();
	
	for ( CLibraryFile* pFile ; pFile = GetNextSelectedFile() ; )
	{
		dlg.AddFile( pFile );
	}
	
	pLock.Unlock();
	
	dlg.DoModal();
}

void CLibraryFileView::OnUpdateLibraryCopy(CCmdUI* pCmdUI) 
{
	pCmdUI->Enable( GetSelectedCount() > 0 );
}

void CLibraryFileView::OnLibraryCopy() 
{
	CSingleLock pLock( &Library.m_pSection, TRUE );
	CFileCopyDlg dlg( NULL, FALSE );
	
	StartSelectedFileLoop();
	
	for ( CLibraryFile* pFile ; pFile = GetNextSelectedFile() ; )
	{
		dlg.AddFile( pFile );
	}
	
	pLock.Unlock();
	
	dlg.DoModal();
}

void CLibraryFileView::OnUpdateLibraryDelete(CCmdUI* pCmdUI) 
{
	pCmdUI->Enable( GetSelectedCount() > 0 );
}

void CLibraryFileView::OnLibraryDelete() 
{
	CSingleLock pLock( &Library.m_pSection, TRUE );
	CLibraryList pList;
	
	StartSelectedFileLoop();
	
	for ( CLibraryFile* pFile ; pFile = GetNextSelectedFile() ; )
	{
		pList.AddTail( pFile->m_nIndex );
	}
	
	while ( !pList.IsEmpty() )
	{
		CLibraryFile* pFile = Library.LookupFile( pList.GetHead(), FALSE, TRUE );
		if ( pFile == NULL ) 
		{
			pList.RemoveHead(); // Remove item from list to avoid endless loop
			continue;
		}

		CDeleteFileDlg dlg( this );
		dlg.m_sName	= pFile->m_sName;
		dlg.m_bAll	= pList.GetCount() > 1;
		
		pLock.Unlock();
		if ( dlg.DoModal() != IDOK ) break;
		pLock.Lock();
		
		for ( int nProcess = dlg.m_bAll ? pList.GetCount() : 1 ; nProcess > 0 && pList.GetCount() > 0 ; nProcess-- )
		{
			if ( pFile = Library.LookupFile( pList.RemoveHead(), FALSE, TRUE ) )
			{
				dlg.Apply( pFile );
				pFile->Delete();
			}
		}
		
		Library.Update();
	}
}

void CLibraryFileView::OnUpdateLibraryBitziWeb(CCmdUI* pCmdUI) 
{
	pCmdUI->Enable( GetSelectedCount() == 1 && Settings.Library.BitziWebSubmit.GetLength() );
}

void CLibraryFileView::OnLibraryBitziWeb() 
{
	CSingleLock pLock( &Library.m_pSection, TRUE );
	
	if ( CLibraryFile* pFile = GetSelectedFile() )
	{
		DWORD nIndex = pFile->m_nIndex;
		pLock.Unlock();
		CFileExecutor::ShowBitziTicket( nIndex );
	}
}


void CLibraryFileView::OnUpdateLibraryCreateTorrent(CCmdUI* pCmdUI) 
{
	pCmdUI->Enable( GetSelectedCount() == 1 && ( Settings.BitTorrent.DefaultTracker.GetLength() > 5 ) && ( Settings.BitTorrent.TorrentCreatorPath.GetLength() > 5 ) );
}

void CLibraryFileView::OnLibraryCreateTorrent() 
{
	CSingleLock pLock( &Library.m_pSection, TRUE );
	
	if ( CLibraryFile* pFile = GetSelectedFile() )
	{
		CString sCommandLine, sPath = pFile->GetPath();
		pLock.Unlock();

		if ( sPath.GetLength() > 0 )
		{
			sCommandLine = _T(" -sourcefile \"") + sPath + _T("\" -destination \"") + Settings.Downloads.TorrentPath + _T("\" -tracker \"" + Settings.BitTorrent.DefaultTracker + "\"" );

			ShellExecute( GetSafeHwnd(), _T("open"), Settings.BitTorrent.TorrentCreatorPath, sCommandLine, NULL, SW_SHOWNORMAL );
		
		}

	}
}

void CLibraryFileView::OnUpdateLibraryRebuildAnsi(CCmdUI* pCmdUI) 
{
	int nSelected = GetSelectedCount();

	StartSelectedFileLoop();

	// Count only selected mp3's which have no custom metadata in XML format
	while ( m_posSel )
	{
		// Lookup locks library if it finds a file
		CQuickLock oLock( Library.m_pSection );

		if ( CLibraryFile* pFile = Library.LookupFile( m_pSelection.GetNext( m_posSel ) ) )
		{
			CString strExtension = pFile->m_sName.Right(3);
			CharLower( strExtension.GetBuffer() );
			strExtension.ReleaseBuffer();

			BOOL bXmlPossiblyModified = FALSE;
			if ( !pFile->m_bMetadataAuto )
			{
				HANDLE hFile = CreateFile( pFile->m_pFolder->m_sPath + _T("\\") + pFile->m_sName, GENERIC_READ, FILE_SHARE_READ,
						NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
				
				if ( hFile != INVALID_HANDLE_VALUE )
				{
					FILETIME pFileDataTime;
					ULARGE_INTEGER nMetaDataTime;
					ULARGE_INTEGER nFileDataTime;

					GetFileTime( hFile, NULL, NULL, &pFileDataTime );
					nFileDataTime.HighPart = pFileDataTime.dwHighDateTime;
					nFileDataTime.LowPart = pFileDataTime.dwLowDateTime;
					// Convert 100 ns into seconds
					nFileDataTime.QuadPart /= 10000000;

					nMetaDataTime.HighPart = pFile->m_pMetadataTime.dwHighDateTime;
					nMetaDataTime.LowPart = pFile->m_pMetadataTime.dwLowDateTime;
					nMetaDataTime.QuadPart /= 10000000;

					// assume that XML was not modified during the first 10 sec. of creation
					if ( nMetaDataTime.HighPart = nFileDataTime.HighPart &&
						nMetaDataTime.LowPart - nFileDataTime.LowPart > 10 ) 
						bXmlPossiblyModified = TRUE;
					CloseHandle( hFile );
				}
			}
			if ( ( strExtension != _T("mp3") ) || bXmlPossiblyModified )
				nSelected--;
		}
	}
	pCmdUI->Enable( nSelected > 0 );
}

void CLibraryFileView::OnLibraryRebuildAnsi() 
{
	CDecodeMetadataDlg dlg;

	CSingleLock pLock( &Library.m_pSection, TRUE );

	StartSelectedFileLoop();

	for ( CLibraryFile* pFile ; pFile = GetNextSelectedFile() ; )
	{
		CString strExtension = pFile->m_sName.Right(3);
		CharLower( strExtension.GetBuffer() );
		strExtension.ReleaseBuffer();

		if ( strExtension == _T("mp3") ) dlg.AddFile( pFile );
	}

	pLock.Unlock();

	if ( dlg.m_pFiles.GetCount() ) dlg.DoModal();
}


void CLibraryFileView::OnUpdateLibraryBitziDownload(CCmdUI* pCmdUI) 
{
	pCmdUI->Enable( GetSelectedCount() > 0 && Settings.Library.BitziXML.GetLength() );
}

void CLibraryFileView::OnLibraryBitziDownload() 
{
	if ( ! Settings.Library.BitziOkay )
	{
		CString strFormat;
		Skin.LoadString( strFormat, IDS_LIBRARY_BITZI_MESSAGE );
		if ( AfxMessageBox( strFormat, MB_ICONQUESTION|MB_YESNO ) != IDYES ) return;
		Settings.Library.BitziOkay = TRUE;
		Settings.Save();
	}

	CSingleLock pLock( &Library.m_pSection, TRUE );
	CBitziDownloadDlg dlg;

	StartSelectedFileLoop();

	for ( CLibraryFile* pFile ; pFile = GetNextSelectedFile() ; )
	{
		if ( pFile->m_bSHA1 ) dlg.AddFile( pFile->m_nIndex );
	}

	pLock.Unlock();

	dlg.DoModal();
}

void CLibraryFileView::OnUpdateLibraryProperties(CCmdUI* pCmdUI) 
{
	pCmdUI->Enable( GetSelectedCount() > 0 );
}

void CLibraryFileView::OnLibraryProperties() 
{
	CSingleLock pLock( &Library.m_pSection, TRUE );
	CFilePropertiesSheet dlg;

	StartSelectedFileLoop();

	for ( CLibraryFile* pFile ; pFile = GetNextSelectedFile() ; )
	{
		dlg.Add( pFile->m_nIndex );
	}

	pLock.Unlock();

	dlg.DoModal();
}

void CLibraryFileView::OnUpdateLibraryShared(CCmdUI* pCmdUI) 
{
	CSingleLock pLock( &Library.m_pSection );
	TRISTATE bShared = TS_UNKNOWN;
	
	if ( GetSelectedCount() > 0 && pLock.Lock( 100 ) )
	{
		StartSelectedFileLoop();
		
		for ( CLibraryFile* pFile ; pFile = GetNextSelectedFile() ; )
		{
			if ( bShared == TS_UNKNOWN )
			{
				bShared = pFile->IsShared() ? TS_TRUE : TS_FALSE;
			}
			else if ( ( bShared == TS_TRUE ) != pFile->IsShared() )
			{
				pCmdUI->Enable( FALSE );
				return;
			}
		}
	}
	
	pCmdUI->Enable( GetSelectedCount() > 0 );
	pCmdUI->SetCheck( bShared == TS_TRUE );
}

void CLibraryFileView::OnLibraryShared() 
{
	CQuickLock oLock( Library.m_pSection );

	StartSelectedFileLoop();

	for ( CLibraryFile* pFile ; pFile = GetNextSelectedFile() ; )
	{
		if ( pFile->IsShared() )
			pFile->m_bShared = pFile->m_pFolder->IsShared() ? TS_FALSE : TS_UNKNOWN;
		else
			pFile->m_bShared = pFile->m_pFolder->IsShared() ? TS_UNKNOWN : TS_TRUE;
		pFile->m_nUpdateCookie++;
	}

	Library.Update();
}

void CLibraryFileView::OnUpdateLibraryUnlink(CCmdUI* pCmdUI) 
{
	CLibraryTreeItem* pItem = GetFolderSelection();
	pCmdUI->Enable( GetSelectedCount() > 0 && pItem && pItem->m_pVirtual && pItem->m_pSelNext == NULL );
}

void CLibraryFileView::OnLibraryUnlink() 
{
	CSingleLock pLock( &Library.m_pSection, TRUE );

	CLibraryTreeItem* pItem = GetFolderSelection();

	if ( pItem == NULL || pItem->m_pVirtual == NULL || pItem->m_pSelNext != NULL ) return;

	CAlbumFolder* pFolder = pItem->m_pVirtual;
	if ( ! LibraryFolders.CheckAlbum( pFolder ) ) return;

	StartSelectedFileLoop();

	for ( CLibraryFile* pFile ; pFile = GetNextSelectedFile() ; )
	{
		pFolder->RemoveFile( pFile );
	}
}

void CLibraryFileView::OnUpdateSearchForThis(CCmdUI* pCmdUI) 
{
	CSingleLock pLock( &Library.m_pSection, TRUE );
	CRelatedSearch pSearch( GetSelectedFile() );
	pCmdUI->Enable( pSearch.CanSearchForThis() );
}

void CLibraryFileView::OnSearchForThis() 
{
	CSingleLock pLock( &Library.m_pSection, TRUE );
	CRelatedSearch pSearch( GetSelectedFile() );
	pLock.Unlock();
	pSearch.RunSearchForThis();
}

void CLibraryFileView::OnUpdateSearchForSimilar(CCmdUI* pCmdUI) 
{
	CSingleLock pLock( &Library.m_pSection, TRUE );
	CRelatedSearch pSearch( GetSelectedFile() );
	pCmdUI->Enable( pSearch.CanSearchForSimilar() );
}

void CLibraryFileView::OnSearchForSimilar() 
{
	CSingleLock pLock( &Library.m_pSection, TRUE );
	CRelatedSearch pSearch( GetSelectedFile() );
	pLock.Unlock();
	pSearch.RunSearchForSimilar();
}

void CLibraryFileView::OnUpdateSearchForArtist(CCmdUI* pCmdUI) 
{
	CSingleLock pLock( &Library.m_pSection, TRUE );
	CRelatedSearch pSearch( GetSelectedFile() );
	pCmdUI->Enable( pSearch.CanSearchForArtist() );
}

void CLibraryFileView::OnSearchForArtist() 
{
	CSingleLock pLock( &Library.m_pSection, TRUE );
	CRelatedSearch pSearch( GetSelectedFile() );
	pLock.Unlock();
	pSearch.RunSearchForArtist();
}

void CLibraryFileView::OnUpdateSearchForAlbum(CCmdUI* pCmdUI) 
{
	CSingleLock pLock( &Library.m_pSection, TRUE );
	CRelatedSearch pSearch( GetSelectedFile() );
	pCmdUI->Enable( pSearch.CanSearchForAlbum() );
}

void CLibraryFileView::OnSearchForAlbum() 
{
	CSingleLock pLock( &Library.m_pSection, TRUE );
	CRelatedSearch pSearch( GetSelectedFile() );
	pLock.Unlock();
	pSearch.RunSearchForAlbum();
}

void CLibraryFileView::OnUpdateSearchForSeries(CCmdUI* pCmdUI) 
{
	CSingleLock pLock( &Library.m_pSection, TRUE );
	CRelatedSearch pSearch( GetSelectedFile() );
	pCmdUI->Enable( pSearch.CanSearchForSeries() );
}

void CLibraryFileView::OnSearchForSeries() 
{
	CSingleLock pLock( &Library.m_pSection, TRUE );
	CRelatedSearch pSearch( GetSelectedFile() );
	pLock.Unlock();
	pSearch.RunSearchForSeries();
}