//
// WizardSharePage.cpp
//
// Copyright (c) Shareaza Development Team, 2002-2004.
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
#include "WizardSheet.h"
#include "WizardSharePage.h"
#include "Library.h"
#include "LibraryFolders.h"
#include "SharedFolder.h"
#include "DlgFolderScan.h"
#include "ShellIcons.h"
#include "Skin.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

IMPLEMENT_DYNCREATE(CWizardSharePage, CWizardPage)

BEGIN_MESSAGE_MAP(CWizardSharePage, CWizardPage)
	//{{AFX_MSG_MAP(CWizardSharePage)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_SHARE_FOLDERS, OnItemChangedShareFolders)
	ON_BN_CLICKED(IDC_SHARE_ADD, OnShareAdd)
	ON_BN_CLICKED(IDC_SHARE_REMOVE, OnShareRemove)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()


/////////////////////////////////////////////////////////////////////////////
// CWizardSharePage property page

CWizardSharePage::CWizardSharePage() : CWizardPage(CWizardSharePage::IDD)
{
	//{{AFX_DATA_INIT(CWizardSharePage)
	//}}AFX_DATA_INIT
}

CWizardSharePage::~CWizardSharePage()
{
}

void CWizardSharePage::DoDataExchange(CDataExchange* pDX)
{
	CPropertyPage::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CWizardSharePage)
	DDX_Control(pDX, IDC_SHARE_FOLDERS, m_wndList);
	DDX_Control(pDX, IDC_SHARE_REMOVE, m_wndRemove);
	//}}AFX_DATA_MAP
}

/////////////////////////////////////////////////////////////////////////////
// CWizardSharePage message handlers

BOOL CWizardSharePage::OnInitDialog() 
{
	CPropertyPage::OnInitDialog();
	
	Skin.Apply( _T("CWizardSharePage"), this );
	
	CBitmap bmBase;
	bmBase.LoadBitmap( IDB_FOLDERS );
	
	CRect rc;
	m_wndList.GetClientRect( &rc );
	m_wndList.InsertColumn( 0, _T("Folder"), LVCFMT_LEFT, rc.Width() - GetSystemMetrics( SM_CXVSCROLL ) );
	m_wndList.SetImageList( ShellIcons.GetObject( 16 ), LVSIL_SMALL );
	m_wndList.EnableToolTips( TRUE );
	
	Library.Lock();
	
	for ( POSITION pos = LibraryFolders.GetFolderIterator() ; pos ; )
	{
		CLibraryFolder* pFolder = LibraryFolders.GetNextFolder( pos );
		
		m_wndList.InsertItem( LVIF_TEXT|LVIF_IMAGE, m_wndList.GetItemCount(),
			pFolder->m_sPath, 0, 0, SHI_FOLDER_OPEN, 0 );
	}
	
	CreateDirectory( Settings.Downloads.CompletePath, NULL );
	AddPhysicalFolder( Settings.Downloads.CompletePath );
	
	AddPhysicalFolder( _T("C:\\Program Files\\Piolet\\My Shared Folder") );
	AddPhysicalFolder( _T("C:\\Program Files\\eMule\\Incoming") );
	AddPhysicalFolder( _T("C:\\Program Files\\eDonkey2000\\incoming") );
	AddPhysicalFolder( _T("C:\\Program Files\\Ares\\My Shared Folder") );
	AddPhysicalFolder( _T("C:\\Program Files\\morpheus\\My Shared Folder") );
	
	AddRegistryFolder( HKEY_CURRENT_USER, _T("Software\\Kazaa\\Transfer"), _T("DlDir0") );
	AddRegistryFolder( HKEY_CURRENT_USER, _T("Software\\Xolox"), _T("completedir") );
	AddRegistryFolder( HKEY_CURRENT_USER, _T("Software\\Xolox"), _T("sharedir") );
	
	Library.Unlock();
	
	return TRUE;
}

BOOL CWizardSharePage::OnSetActive() 
{
	SetWizardButtons( PSWIZB_BACK | PSWIZB_NEXT );
	return CWizardPage::OnSetActive();
}

void CWizardSharePage::AddPhysicalFolder(LPCTSTR pszFolder)
{
	DWORD nFlags = GetFileAttributes( pszFolder );

	if ( nFlags == 0xFFFFFFFF ) return;
	if ( ( nFlags & FILE_ATTRIBUTE_DIRECTORY ) == 0 ) return;
	
	for ( int nItem = 0 ; nItem < m_wndList.GetItemCount() ; nItem++ )
	{
		if ( m_wndList.GetItemText( nItem, 0 ).CompareNoCase( pszFolder ) == 0 ) return;
	}
	
	m_wndList.InsertItem( LVIF_TEXT|LVIF_IMAGE, m_wndList.GetItemCount(),
		pszFolder, 0, 0, SHI_FOLDER_OPEN, 0 );
}

void CWizardSharePage::AddRegistryFolder(HKEY hRoot, LPCTSTR pszKey, LPCTSTR pszValue)
{
	TCHAR szFolder[MAX_PATH];
	DWORD dwType, dwFolder;
	HKEY hKey = NULL;
		
	if ( RegOpenKeyEx( hRoot, pszKey, 0, KEY_READ, &hKey ) != ERROR_SUCCESS ) return;
	
	dwType = REG_SZ;
	dwFolder = MAX_PATH - 1;

	if ( RegQueryValueEx( hKey, pszValue, NULL, &dwType, (LPBYTE)szFolder, &dwFolder )
		 != ERROR_SUCCESS || dwType != REG_SZ )
	{
		RegCloseKey( hKey );
		return;
	}
	
	RegCloseKey( hKey );

	szFolder[ dwFolder ] = 0;

	AddPhysicalFolder( szFolder );
}

void CWizardSharePage::OnItemChangedShareFolders(NMHDR* pNMHDR, LRESULT* pResult) 
{
	NM_LISTVIEW* pNMListView = (NM_LISTVIEW*)pNMHDR;
	m_wndRemove.EnableWindow( m_wndList.GetSelectedCount() > 0 );
	*pResult = 0;
}

void CWizardSharePage::OnShareAdd() 
{
	TCHAR szPath[MAX_PATH];
	LPITEMIDLIST pPath;
	LPMALLOC pMalloc;
	BROWSEINFO pBI;
		
	ZeroMemory( &pBI, sizeof(pBI) );
	pBI.hwndOwner		= AfxGetMainWnd()->GetSafeHwnd();
	pBI.pszDisplayName	= szPath;
	pBI.lpszTitle		= _T("Select folder to share:");
	pBI.ulFlags			= BIF_RETURNONLYFSDIRS;
	
	pPath = SHBrowseForFolder( &pBI );

	if ( pPath == NULL ) return;

	SHGetPathFromIDList( pPath, szPath );
	SHGetMalloc( &pMalloc );
	pMalloc->Free( pPath );

	CString strPathLC( szPath );
	strPathLC.MakeLower();

	for ( int nItem = 0 ; nItem < m_wndList.GetItemCount() ; nItem++ )
	{
		CString strOldLC( m_wndList.GetItemText( nItem, 0 ) );
		strOldLC.MakeLower();
		
		if ( strPathLC == strOldLC )
		{
			// Matches exactly
		}
		else if ( strPathLC.GetLength() > strOldLC.GetLength() )
		{
			if ( strPathLC.Left( strOldLC.GetLength() + 1 ) != strOldLC + '\\' )
				continue;
		}
		else if ( strPathLC.GetLength() < strOldLC.GetLength() )
		{
			if ( strOldLC.Left( strPathLC.GetLength() + 1 ) != strPathLC + '\\' )
				continue;
		}
		else
		{
			continue;
		}

		CString strFormat, strMessage;
		Skin.LoadString( strFormat, IDS_WIZARD_SHARE_ALREADY );
		strMessage.Format( strFormat, (LPCTSTR)strOldLC );
		AfxMessageBox( strMessage, MB_ICONINFORMATION );
		return;
	}
	
	m_wndList.InsertItem( LVIF_TEXT|LVIF_IMAGE, m_wndList.GetItemCount(),
		szPath, 0, 0, SHI_FOLDER_OPEN, 0 );
}

void CWizardSharePage::OnShareRemove() 
{
	for ( int nItem = 0 ; nItem < m_wndList.GetItemCount() ; nItem++ )
	{
		if ( m_wndList.GetItemState( nItem, LVIS_SELECTED ) )
		{
			m_wndList.DeleteItem( nItem-- );
		}
	}
}

LRESULT CWizardSharePage::OnWizardNext() 
{
	CWaitCursor pCursor;

	if ( m_wndList.GetItemCount() == 0 )
	{
		CString strMessage;
		Skin.LoadString( strMessage, IDS_WIZARD_SHARE_CONFIRM );
		if ( AfxMessageBox( strMessage, MB_ICONQUESTION|MB_YESNO ) == IDNO )
			return -1;
	}
	
	Library.Lock();

	for ( POSITION pos = LibraryFolders.GetFolderIterator() ; pos ; )
	{
		CLibraryFolder* pFolder = LibraryFolders.GetNextFolder( pos );

		for ( int nItem = 0 ; nItem < m_wndList.GetItemCount() ; nItem++ )
		{
			CString strFolder = m_wndList.GetItemText( nItem, 0 );
			if ( strFolder.CompareNoCase( pFolder->m_sPath ) == 0 ) break;
		}

		if ( nItem >= m_wndList.GetItemCount() )
		{
			LibraryFolders.RemoveFolder( pFolder );
		}
	}

	for ( int nItem = 0 ; nItem < m_wndList.GetItemCount() ; nItem++ )
	{
		LibraryFolders.AddFolder( m_wndList.GetItemText( nItem, 0 ) );
	}
	
	Library.Unlock();

	CFolderScanDlg dlgScan;
	dlgScan.DoModal();

	return 0;
}