//
// DlgShareManager.cpp
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
#include "ShellIcons.h"
#include "DlgShareManager.h"
#include "DlgFolderScan.h"
#include "LiveList.h"
#include "Skin.h"
#include "DlgHelp.h"
#include <shlobj.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

IMPLEMENT_DYNAMIC(CShareManagerDlg, CSkinDialog)

BEGIN_MESSAGE_MAP(CShareManagerDlg, CSkinDialog)
	//{{AFX_MSG_MAP(CShareManagerDlg)
	ON_BN_CLICKED(IDC_SHARE_ADD, OnShareAdd)
	ON_BN_CLICKED(IDC_SHARE_REMOVE, OnShareRemove)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_SHARE_FOLDERS, OnItemChangedShareFolders)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()


/////////////////////////////////////////////////////////////////////////////
// CShareManagerDlg dialog

CShareManagerDlg::CShareManagerDlg(CWnd* pParent) : CSkinDialog( CShareManagerDlg::IDD, pParent )
{
	//{{AFX_DATA_INIT(CShareManagerDlg)
	//}}AFX_DATA_INIT
}

void CShareManagerDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CShareManagerDlg)
	DDX_Control(pDX, IDC_SHARE_REMOVE, m_wndRemove);
	DDX_Control(pDX, IDC_SHARE_FOLDERS, m_wndList);
	//}}AFX_DATA_MAP
}

/////////////////////////////////////////////////////////////////////////////
// CShareManagerDlg message handlers

BOOL CShareManagerDlg::OnInitDialog()
{
	CDialog::OnInitDialog();

	SkinMe( NULL, IDR_LIBRARYFRAME );

	CRect rc;
	m_wndList.GetClientRect( &rc );
	m_wndList.InsertColumn( 0, _T("Folder"), LVCFMT_LEFT, rc.Width() - GetSystemMetrics( SM_CXVSCROLL ) );
	m_wndList.SetImageList( ShellIcons.GetObject( 16 ), LVSIL_SMALL );
	m_wndList.EnableToolTips( TRUE );
	m_wndList.SendMessage( LVM_SETEXTENDEDLISTVIEWSTYLE,
		LVS_EX_FULLROWSELECT|LVS_EX_LABELTIP,
		LVS_EX_FULLROWSELECT|LVS_EX_LABELTIP );

	{
		CQuickLock oLock( Library.m_pSection );

		for ( POSITION pos = LibraryFolders.GetFolderIterator() ; pos ; )
		{
			CLibraryFolder* pFolder = LibraryFolders.GetNextFolder( pos );

			m_wndList.InsertItem( LVIF_TEXT|LVIF_IMAGE, m_wndList.GetItemCount(),
				pFolder->m_sPath, 0, 0, SHI_FOLDER_OPEN, 0 );
		}
	}

	m_wndRemove.EnableWindow( FALSE );

	return TRUE;
}

void CShareManagerDlg::OnItemChangedShareFolders(NMHDR* pNMHDR, LRESULT* pResult)
{
	*pResult = 0;
	m_wndRemove.EnableWindow( m_wndList.GetSelectedCount() > 0 );
}

void CShareManagerDlg::OnShareAdd()
{
	//Let user select path to share
	TCHAR szPath[MAX_PATH];
	LPITEMIDLIST pPath;
	LPMALLOC pMalloc;
	BROWSEINFO pBI;

	ZeroMemory( &pBI, sizeof(pBI) );
	pBI.hwndOwner		= AfxGetMainWnd()->GetSafeHwnd();
	pBI.pszDisplayName	= szPath;
	pBI.lpszTitle		= _T("Select folder to share:");
	pBI.ulFlags			= BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;

	pPath = SHBrowseForFolder( &pBI );

	if ( pPath == NULL ) return;

	SHGetPathFromIDList( pPath, szPath );
	SHGetMalloc( &pMalloc );
	pMalloc->Free( pPath );

	CString strPathLC( szPath );
	CharLower( strPathLC.GetBuffer() );
	strPathLC.ReleaseBuffer();


	//Get system paths (to compare)
	CString strWindowsLC, strProgramsLC;
	PTSTR pszWindowsPath, pszProgramsPath;

	pszWindowsPath = strWindowsLC.GetBuffer( MAX_PATH + 1 );
	pszProgramsPath = strProgramsLC.GetBuffer( MAX_PATH + 1 );

	if ( HINSTANCE hShell = LoadLibrary( _T("shfolder.dll") ) )
	{
		HRESULT (WINAPI *pfnSHGetFolderPath)(HWND, int, HANDLE, DWORD, LPWSTR);
		(FARPROC&)pfnSHGetFolderPath = GetProcAddress( hShell, "SHGetFolderPathW" );
		if ( pfnSHGetFolderPath != NULL )
		{
			(*pfnSHGetFolderPath)(NULL, CSIDL_WINDOWS, NULL, NULL, pszWindowsPath);
			(*pfnSHGetFolderPath)(NULL, CSIDL_PROGRAM_FILES, NULL, NULL, pszProgramsPath);
		}
		FreeLibrary( hShell );
	}
	CharLower( pszWindowsPath );
	CharLower( pszProgramsPath );

	strWindowsLC.ReleaseBuffer();
	strProgramsLC.ReleaseBuffer();

	if ( strWindowsLC.IsEmpty() ) strWindowsLC = _T("c:\\windows");
	if ( strProgramsLC.IsEmpty() ) strProgramsLC = _T("c:\\program files");


	//Get various shareaza paths (to compare)
	CString strIncompletePathLC = Settings.Downloads.IncompletePath;
	CharLower( strIncompletePathLC.GetBuffer() );
	strIncompletePathLC.ReleaseBuffer();

	CString strGeneralPathLC = Settings.General.Path;
	CharLower( strGeneralPathLC.GetBuffer() );
	strGeneralPathLC.ReleaseBuffer();

	CString strUserPathLC = Settings.General.UserPath;
	CharLower( strUserPathLC.GetBuffer() );
	strUserPathLC.ReleaseBuffer();


	//Check shared path isn't invalid
	if ( strPathLC == _T( "" ) ||
		 strPathLC == strWindowsLC.Left( 3 ) ||
		 strPathLC == strProgramsLC ||
		 strPathLC == strWindowsLC ||
		 strPathLC == strGeneralPathLC ||
		 strPathLC == strGeneralPathLC + _T("\\data") ||
		 strPathLC == strUserPathLC ||
		 strPathLC == strUserPathLC + _T("\\data") ||
		 strPathLC == strIncompletePathLC )
	{
		CHelpDlg::Show( _T("ShareHelp.BadShare") );
		return;
	}

	//Check shared path isn't already shared
	for ( int nItem = 0 ; nItem < m_wndList.GetItemCount() ; nItem++ )
	{
		CString strOldLC( m_wndList.GetItemText( nItem, 0 ) );
		CharLower( strOldLC.GetBuffer() );
		strOldLC.ReleaseBuffer();

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
		//CHelpDlg::Show(  _T( "ShareHelp.AlreadyShared" ) );
		return;
	}

	//Add path to shared list
	m_wndList.InsertItem( LVIF_TEXT|LVIF_IMAGE, m_wndList.GetItemCount(),
		szPath, 0, 0, SHI_FOLDER_OPEN, 0 );
}

void CShareManagerDlg::OnShareRemove()
{
	for ( int nItem = 0 ; nItem < m_wndList.GetItemCount() ; nItem++ )
	{
		if ( m_wndList.GetItemState( nItem, LVIS_SELECTED ) )
		{
			m_wndList.DeleteItem( nItem-- );
		}
	}
}

void CShareManagerDlg::OnOK()
{
	{
		CQuickLock oLock( Library.m_pSection );

		for ( POSITION pos = LibraryFolders.GetFolderIterator() ; pos ; )
		{
			CLibraryFolder* pFolder = LibraryFolders.GetNextFolder( pos );

			int nItem = 0;
			for ( ; nItem < m_wndList.GetItemCount() ; nItem++ )
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
	}

	CFolderScanDlg dlgScan;
	dlgScan.DoModal();

	CDialog::OnOK();
}