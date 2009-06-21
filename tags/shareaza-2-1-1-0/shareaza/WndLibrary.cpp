//
// WndLibrary.cpp
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
#include "LibraryBuilder.h"
#include "CollectionFile.h"
#include "SharedFile.h"
#include "WndLibrary.h"
#include "SharedFolder.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

IMPLEMENT_SERIAL(CLibraryWnd, CPanelWnd, 0)

BEGIN_MESSAGE_MAP(CLibraryWnd, CPanelWnd)
	//{{AFX_MSG_MAP(CLibraryWnd)
	ON_WM_CREATE()
	ON_WM_DESTROY()
	ON_WM_SIZE()
	ON_WM_MDIACTIVATE()
	ON_WM_TIMER()
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()



/////////////////////////////////////////////////////////////////////////////
// CLibraryWnd construction

CLibraryWnd::CLibraryWnd() : CPanelWnd( TRUE, FALSE )
{
	Create( IDR_LIBRARYFRAME );
}

CLibraryWnd::~CLibraryWnd()
{
}

/////////////////////////////////////////////////////////////////////////////
// CLibraryWnd operations

BOOL CLibraryWnd::Display(CLibraryFile* pFile)
{
	return m_wndFrame.Display( pFile );
}

BOOL CLibraryWnd::Display(CAlbumFolder* pFolder)
{
	return m_wndFrame.Display( pFolder );
}

/////////////////////////////////////////////////////////////////////////////
// CLibraryWnd message handlers

int CLibraryWnd::OnCreate(LPCREATESTRUCT lpCreateStruct)
{
	if ( CPanelWnd::OnCreate( lpCreateStruct ) == -1 ) return -1;

	m_tLast = 0;

	m_wndFrame.Create( this );

	LoadState();

	return 0;
}

void CLibraryWnd::OnDestroy()
{
	SaveState();
	CPanelWnd::OnDestroy();
}

BOOL CLibraryWnd::OnCmdMsg(UINT nID, int nCode, void* pExtra, AFX_CMDHANDLERINFO* pHandlerInfo)
{
	if ( m_wndFrame.m_hWnd )
	{
		if ( m_wndFrame.OnCmdMsg( nID, nCode, pExtra, pHandlerInfo ) ) return TRUE;
	}

	return CPanelWnd::OnCmdMsg( nID, nCode, pExtra, pHandlerInfo );
}

void CLibraryWnd::OnSize(UINT nType, int cx, int cy)
{
	CPanelWnd::OnSize( nType, cx, cy );
	if ( m_wndFrame.m_hWnd ) m_wndFrame.SetWindowPos( NULL, 0, 0, cx, cy, SWP_NOZORDER );
}

void CLibraryWnd::OnMDIActivate(BOOL bActivate, CWnd* pActivateWnd, CWnd* pDeactivateWnd)
{
	CPanelWnd::OnMDIActivate( bActivate, pActivateWnd, pDeactivateWnd );

	if ( bActivate )
	{
		m_wndFrame.Update();
		m_wndFrame.SetFocus();
	}
}

void CLibraryWnd::OnTimer(UINT nIDEvent)
{
	DWORD tNow = GetTickCount();

	if ( nIDEvent == 1 )
	{
		CWaitCursor pCursor;
		m_wndFrame.Update( FALSE );
		m_tLast = tNow;
	}
	else if ( tNow - m_tLast > 30000 )
	{
		m_wndFrame.Update( FALSE );
		m_tLast = tNow;
	}
}

void CLibraryWnd::OnSkinChange()
{
	CPanelWnd::OnSkinChange();
	m_wndFrame.OnSkinChange();
}

/////////////////////////////////////////////////////////////////////////////
// CLibraryWnd events

HRESULT CLibraryWnd::GetGenericView(IGenericView** ppView)
{
	if ( m_wndFrame.m_hWnd == NULL ) return S_FALSE;
	CLibraryList* pList = m_wndFrame.GetViewSelection();
	*ppView = (IGenericView*)pList->GetInterface( IID_IGenericView, TRUE );
	return S_OK;
}

BOOL CLibraryWnd::OnCollection(LPCTSTR pszPath)
{
	CAlbumFolder* pFolder = NULL;
	CString strFormat, strMessage;
	CCollectionFile pCollection;
	CLibraryFolder* pLibFolder;

	if ( pCollection.Open( pszPath ) )
	{	//The specified collection is valid

		//Create the collection folder (in case it doesn't exist)
		CreateDirectory( Settings.Downloads.CollectionPath, NULL );
		//Add the collection folder to the library (in case it isn't there)
		pLibFolder = LibraryFolders.AddFolder( Settings.Downloads.CollectionPath );
		//Force a scan of it (in case watch library folders is disabled)
		pLibFolder =  LibraryFolders.GetFolder( Settings.Downloads.CollectionPath );
		if( pLibFolder != NULL ) pLibFolder->Scan();

		CSingleLock oLock( &Library.m_pSection, TRUE );
		if ( CLibraryFile* pFile = LibraryMaps.LookupFileByPath( pszPath, FALSE, TRUE ) )
		{	//Collection IS already in the library

			//Re-mount the collection
			LibraryFolders.MountCollection( &pFile->m_pSHA1, &pCollection );
			pFolder = LibraryFolders.GetCollection( &pFile->m_pSHA1 );
			oLock.Unlock();
		}
		else
		{	//Collection is not already in the main library
			oLock.Unlock();
			//Check the collection folder
			CString strSource( pszPath ), strTarget;

			int nName = strSource.ReverseFind( '\\' );
			if ( nName >= 0 )
			{
				strTarget = Settings.Downloads.CollectionPath + strSource.Mid( nName );
				LibraryBuilder.RequestPriority( strTarget );
			}

			oLock.Lock();
			if ( CLibraryFile* pFile = LibraryMaps.LookupFileByPath( strTarget, FALSE, TRUE ) )
			{	//Collection is already in the collection folder

				//Re-mount the collection
				LibraryFolders.MountCollection( &pFile->m_pSHA1, &pCollection );
				pFolder = LibraryFolders.GetCollection( &pFile->m_pSHA1 );
				oLock.Unlock();
			}
			else
			{	//Collection is not already in collection folder
				oLock.Unlock();

				if ( strTarget.GetLength() > 0 && CopyFile( strSource, strTarget, TRUE ) )
				{	//Collection was copied into the collection folder

					//Force a scan of collection folder (in case watch library folders is disabled)
					if( pLibFolder != NULL ) pLibFolder->Scan();

					LoadString( strFormat, IDS_LIBRARY_COLLECTION_INSTALLED );
					strMessage.Format( strFormat, (LPCTSTR)pCollection.GetTitle() );
					AfxMessageBox( strMessage, MB_ICONINFORMATION );
					oLock.Lock();
					if ( CLibraryFile* pFile = LibraryMaps.LookupFileByPath( strTarget, FALSE, TRUE ) )
					{
						pFolder = LibraryFolders.GetCollection( &pFile->m_pSHA1 );
					}
					oLock.Unlock();
				}
				else
				{	//Was not able to copy collection to the collection folder
					if( GetLastError() == ERROR_FILE_EXISTS )
					{	//File of this name already exists

						//We cannot copy the collection because it's already there.
						//But it doesn't appear in the library.

						//The greatest probablility is that the file is there, but hasn't
						//been added yet. The best bet is to pretend everything is okay
						//Because the delay it takes the user to respond will fix everything.
						LoadString( strFormat, IDS_LIBRARY_COLLECTION_INSTALLED );
						strMessage.Format( strFormat, (LPCTSTR)pCollection.GetTitle() );
						AfxMessageBox( strMessage , MB_ICONINFORMATION );

						oLock.Lock();
						if ( CLibraryFile* pFile = LibraryMaps.LookupFileByPath( strTarget, FALSE, TRUE ) )
						{	//Collection was already there.
							//Re-mount the collection
							LibraryFolders.MountCollection( &pFile->m_pSHA1, &pCollection );
							pFolder = LibraryFolders.GetCollection( &pFile->m_pSHA1 );
							oLock.Unlock();
						}
						else
						{	//File of this name exists in the folder, but does not appear in the
							//library. Most likely cause- Corrupt file in collection folder.
							oLock.Unlock();
							LoadString( strFormat, IDS_LIBRARY_COLLECTION_CANT_INSTALL );
							strMessage.Format( strFormat, (LPCTSTR)pCollection.GetTitle(), (LPCTSTR)Settings.Downloads.CollectionPath );
							AfxMessageBox( strMessage, MB_ICONEXCLAMATION );
						}
					}
					else
					{	//Unknown reason- Display an error message
						LoadString( strFormat, IDS_LIBRARY_COLLECTION_CANT_INSTALL );
						strMessage.Format( strFormat, (LPCTSTR)pCollection.GetTitle(), (LPCTSTR)Settings.Downloads.CollectionPath );
						AfxMessageBox( strMessage, MB_ICONEXCLAMATION );
					}
				}
			}
		}
	}
	else
	{	//User clicked on an invalid collection
		LoadString( strFormat, IDS_LIBRARY_COLLECTION_INVALID );
		strMessage.Format( strFormat, pszPath );
		AfxMessageBox( strMessage, MB_ICONEXCLAMATION );
	}

	if ( pFolder != NULL ) Display( pFolder ); //Display the collection
	return ( pFolder != NULL );
}


/*
/////////////////////////////////////////////////////////////////////////////
// CLibraryWnd events

HRESULT CLibraryWnd::GetGenericView(IGenericView** ppView)
{
	if ( m_wndFrame.m_hWnd == NULL ) return S_FALSE;
	CLibraryList* pList = m_wndFrame.GetViewSelection();
	*ppView = (IGenericView*)pList->GetInterface( IID_IGenericView, TRUE );
	return S_OK;
}

BOOL CLibraryWnd::OnCollection(LPCTSTR pszPath)
{
	CAlbumFolder* pFolder = NULL;

	if ( CLibraryFile* pFile = LibraryMaps.LookupFileByPath( pszPath, TRUE, FALSE, TRUE ) )
	{
		pFolder = LibraryFolders.GetCollection( &pFile->m_pSHA1 );
		Library.Unlock();
	}
	else
	{
		CString strFormat, strMessage;
		CCollectionFile pCollection;

		if ( pCollection.Open( pszPath ) )
		{
			CString strSource( pszPath ), strTarget;

			int nName = strSource.ReverseFind( '\\' );
			if ( nName >= 0 )
			{
				strTarget = Settings.Downloads.CompletePath + strSource.Mid( nName );
				LibraryBuilder.RequestPriority( strTarget );
			}

			if ( strTarget.GetLength() > 0 && CopyFile( strSource, strTarget, TRUE ) )
			{
				LoadString( strFormat, IDS_LIBRARY_COLLECTION_INSTALLED );
				strMessage.Format( strFormat, (LPCTSTR)pCollection.GetTitle() );
				AfxMessageBox( strMessage, MB_ICONINFORMATION );

				if ( CLibraryFile* pFile = LibraryMaps.LookupFileByPath( strTarget, TRUE, FALSE, TRUE ) )
				{
					pFolder = LibraryFolders.GetCollection( &pFile->m_pSHA1 );
					Library.Unlock();
				}
			}
			else
			{
				LoadString( strFormat, IDS_LIBRARY_COLLECTION_CANT_INSTALL );
				strMessage.Format( strFormat, (LPCTSTR)pCollection.GetTitle(), (LPCTSTR)Settings.Downloads.CompletePath );
				AfxMessageBox( strMessage, MB_ICONEXCLAMATION );
			}
		}
		else
		{
			LoadString( strFormat, IDS_LIBRARY_COLLECTION_INVALID );
			strMessage.Format( strFormat, pszPath );
			AfxMessageBox( strMessage, MB_ICONEXCLAMATION );
		}
	}

	if ( pFolder != NULL ) Display( pFolder );
	return ( pFolder != NULL );
}
*/