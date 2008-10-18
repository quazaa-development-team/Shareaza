//
// WizardNetworksPage.cpp
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
#include "HostCache.h"
#include "DiscoveryServices.h"
#include "WizardNetworksPage.h"
#include "DlgDonkeyImport.h"
#include <shlobj.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

IMPLEMENT_DYNCREATE(CWizardNetworksPage, CWizardPage)

BEGIN_MESSAGE_MAP(CWizardNetworksPage, CWizardPage)
	//{{AFX_MSG_MAP(CWizardNetworksPage)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()


/////////////////////////////////////////////////////////////////////////////
// CWizardNetworksPage property page

CWizardNetworksPage::CWizardNetworksPage() : CWizardPage(CWizardNetworksPage::IDD)
{
	//{{AFX_DATA_INIT(CWizardNetworksPage)
	m_bG2Enable = FALSE;
	m_bG1Enable = FALSE;
	m_bEDEnable = FALSE;
	//}}AFX_DATA_INIT
}

CWizardNetworksPage::~CWizardNetworksPage()
{
}

void CWizardNetworksPage::DoDataExchange(CDataExchange* pDX)
{
	CWizardPage::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CWizardNetworksPage)
	DDX_Control(pDX, IDC_G2_ENABLE, m_wndG2Enable);
	DDX_Check(pDX, IDC_G2_ENABLE, m_bG2Enable);
	DDX_Check(pDX, IDC_G1_ENABLE, m_bG1Enable);
	DDX_Check(pDX, IDC_ED2K_ENABLE, m_bEDEnable);
	//}}AFX_DATA_MAP
}

/////////////////////////////////////////////////////////////////////////////
// CWizardNetworksPage message handlers

BOOL CWizardNetworksPage::OnInitDialog() 
{
	CWizardPage::OnInitDialog();
	
	m_bG2Enable = Settings.Gnutella2.EnableToday;
	m_bG1Enable = Settings.Gnutella1.EnableToday;
	m_bEDEnable = Settings.eDonkey.EnableToday;
	
	m_wndG2Enable.EnableWindow( ! m_bG2Enable );
	UpdateData( FALSE );
	
	return TRUE;
}

BOOL CWizardNetworksPage::OnSetActive() 
{
	SetWizardButtons( PSWIZB_BACK | PSWIZB_NEXT );
	return CWizardPage::OnSetActive();
}

LRESULT CWizardNetworksPage::OnWizardNext() 
{
	UpdateData();
	
	Settings.Gnutella2.EnableToday	= m_bG2Enable;
	Settings.Gnutella1.EnableToday	= m_bG1Enable;
	Settings.eDonkey.EnableToday	= m_bEDEnable;
	
	DoDonkeyImport();
	
	return 0;
}

void CWizardNetworksPage::DoDonkeyImport()
{
	CString strPrograms, strFolder;
	CDonkeyImportDlg dlg( this );
	
	if ( HINSTANCE hShell = LoadLibrary( _T("shfolder.dll") ) )
	{
#ifdef _UNICODE
		HRESULT (WINAPI *pfnSHGetFolderPath)(HWND, int, HANDLE, DWORD, LPWSTR);
		(FARPROC&)pfnSHGetFolderPath = GetProcAddress( hShell, "SHGetFolderPathW" );
#else
		HRESULT (WINAPI *pfnSHGetFolderPath)(HWND, int, HANDLE, DWORD, LPSTR);
		(FARPROC&)pfnSHGetFolderPath = GetProcAddress( hShell, "SHGetFolderPathA" );
#endif
		
		if ( pfnSHGetFolderPath != NULL )
		{
			strPrograms.ReleaseBuffer(
				(*pfnSHGetFolderPath)( GetSafeHwnd(), 0x26, NULL, 0,
				strPrograms.GetBuffer( MAX_PATH + 1 ) ) == S_OK ? -1 : 0 );
		}
		
		FreeLibrary( hShell );
	}
	
	if ( strPrograms.IsEmpty() ) strPrograms = _T("C:\\Program Files");
	
	strFolder = strPrograms + _T("\\eMule\\server.met");
	HostCache.eDonkey.Import( strFolder );
	
	if ( Settings.eDonkey.EnableToday ) DiscoveryServices.ExecuteDonkey();
	
	LPCTSTR pszFolders[] =
	{
		_T("<%PROGRAMFILES%>\\eMule\\temp"),
		_T("<%PROGRAMFILES%>\\eDonkey2000\\temp"),
		NULL
	};
	
	for ( int nFolder = 0, nCount = 0 ; pszFolders[ nFolder ] ; nFolder++ )
	{
		strFolder = pszFolders[ nFolder ];
		Replace( strFolder, _T("<%PROGRAMFILES%>"), strPrograms );
		
		if ( GetFileAttributes( strFolder ) != 0xFFFFFFFF )
		{
			dlg.m_pImporter.AddFolder( strFolder );
			nCount++;
		}
	}
	
	if ( nCount > 0 ) dlg.DoModal();
}