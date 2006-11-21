//
// DlgDownloadEdit.cpp
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
#include "Transfers.h"
#include "FragmentedFile.h"
#include "DlgDownloadEditSheet.h"
#include "DlgDownloadEditPage.h"
#include "PageDownloadEditActions.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

IMPLEMENT_DYNCREATE(CDownloadEditActionsPage, CDownloadEditPage)

BEGIN_MESSAGE_MAP(CDownloadEditActionsPage, CDownloadEditPage)
	ON_WM_CTLCOLOR()
	ON_WM_SETCURSOR()
	ON_WM_LBUTTONUP()
	ON_BN_CLICKED(IDC_ERASE, OnErase)
END_MESSAGE_MAP()


//////////////////////////////////////////////////////////////////////////////
// CDownloadEditDlg construction

CDownloadEditActionsPage::CDownloadEditActionsPage() : CDownloadEditPage(IDD)
{
	m_psp.dwFlags |= PSP_USETITLE;
}

CDownloadEditActionsPage::~CDownloadEditActionsPage(void)
{
}

void CDownloadEditActionsPage::DoDataExchange(CDataExchange* pDX)
{
	DDX_Control(pDX, IDC_PURGE_HASHSET, m_wndPurgeHashset);
	DDX_Control(pDX, IDC_FORGET_VERIFY, m_wndForgetVerify);
	DDX_Control(pDX, IDC_FORGET_SOURCES, m_wndForgetSources);
	DDX_Control(pDX, IDC_COMPLETE_AND_VERIFY, m_wndCompleteVerify);
	DDX_Control(pDX, IDC_MERGE_AND_VERIFY, m_wndMergeVerify);
	DDX_Text(pDX, IDC_ERASE_FROM, m_sEraseFrom);
	DDX_Text(pDX, IDC_ERASE_TO, m_sEraseTo);
}

//////////////////////////////////////////////////////////////////////////////
// CDownloadEditActionsPage message handlers
BOOL CDownloadEditActionsPage::OnInitDialog()
{
	CDownloadEditPage::OnInitDialog();

	UpdateData( FALSE );

	return TRUE;
}

HBRUSH CDownloadEditActionsPage::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
	HBRUSH hbr = CDownloadEditPage::OnCtlColor( pDC, pWnd, nCtlColor );

	if ( pWnd == &m_wndPurgeHashset || pWnd == &m_wndForgetVerify || 
		pWnd == &m_wndForgetSources || pWnd == &m_wndCompleteVerify || 
		pWnd == &m_wndMergeVerify )
	{
		pDC->SelectObject( &theApp.m_gdiFontLine );
		pDC->SetTextColor( RGB( 0, 0, 255 ) );
	}

	return hbr;
}

BOOL CDownloadEditActionsPage::OnSetCursor(CWnd* pWnd, UINT nHitTest, UINT message)
{
	CRect rcCtrl1, rcCtrl2, rcCtrl3, rcCtrl4, rcCtrl5;
	CPoint point;

	GetCursorPos( &point );
	m_wndPurgeHashset.GetWindowRect( &rcCtrl1 );
    m_wndForgetVerify.GetWindowRect( &rcCtrl2 );
	m_wndForgetSources.GetWindowRect( &rcCtrl3 );
	m_wndCompleteVerify.GetWindowRect( &rcCtrl4 );
	m_wndMergeVerify.GetWindowRect( &rcCtrl5 );

	if ( rcCtrl1.PtInRect( point ) || rcCtrl2.PtInRect( point ) ||
		rcCtrl3.PtInRect( point ) || rcCtrl2.PtInRect( point ) || 
		rcCtrl4.PtInRect( point ) )
	{
		SetCursor( AfxGetApp()->LoadCursor( IDC_HAND ) );
		return TRUE;
	}

	return CPropertyPage::OnSetCursor( pWnd, nHitTest, message );
}

void CDownloadEditActionsPage::OnLButtonUp(UINT nFlags, CPoint point)
{
	CPropertyPage::OnLButtonUp(nFlags, point);

	CRect rcCtrl1, rcCtrl2, rcCtrl3, rcCtrl4, rcCtrl5;

	m_wndPurgeHashset.GetWindowRect( &rcCtrl1 );
	ScreenToClient( &rcCtrl1 );
	m_wndForgetVerify.GetWindowRect( &rcCtrl2 );
	ScreenToClient( &rcCtrl2 );
	m_wndForgetSources.GetWindowRect( &rcCtrl3 );
	ScreenToClient( &rcCtrl3 );
	m_wndCompleteVerify.GetWindowRect( &rcCtrl4 );
	ScreenToClient( &rcCtrl4 );
	m_wndMergeVerify.GetWindowRect( &rcCtrl5 );
	ScreenToClient( &rcCtrl5 );

	if ( rcCtrl1.PtInRect( point ) )
	{
		CString strMessage;
		LoadString( strMessage, IDS_DOWNLOAD_EDIT_FORGET_VERIFY );
		if ( AfxMessageBox( strMessage, MB_ICONQUESTION|MB_YESNO ) != IDYES ) return;

		CSingleLock pLock( &Transfers.m_pSection, TRUE );
		if ( ! Downloads.Check( m_pDownload ) || m_pDownload->IsMoving() ) return;
		m_pDownload->ClearVerification();
	}
	else if ( rcCtrl2.PtInRect( point ) )
	{
		CString strMessage;
		LoadString( strMessage, IDS_DOWNLOAD_EDIT_FORGET_VERIFY );
		if ( AfxMessageBox( strMessage, MB_ICONQUESTION|MB_YESNO ) != IDYES ) return;

		CSingleLock pLock( &Transfers.m_pSection, TRUE );
		if ( ! Downloads.Check( m_pDownload ) || m_pDownload->IsMoving() ) return;
		m_pDownload->ResetVerification();
		m_pDownload->RunValidation(FALSE);
	}
	else if ( rcCtrl3.PtInRect( point ) )
	{
		CString strMessage;
		LoadString( strMessage, IDS_DOWNLOAD_EDIT_FORGET_SOURCES );
		if ( AfxMessageBox( strMessage, MB_ICONQUESTION|MB_YESNO ) != IDYES ) return;

		CSingleLock pLock( &Transfers.m_pSection, TRUE );
		if ( ! Downloads.Check( m_pDownload ) || m_pDownload->IsMoving() ) return;

		m_pDownload->CloseTransfers();
		m_pDownload->ClearSources();
		m_pDownload->SetModified();
	}
	else if ( rcCtrl4.PtInRect( point ) )
	{
		CSingleLock pLock( &Transfers.m_pSection, TRUE );
		CString strMessage;

		if ( ! Downloads.Check( m_pDownload ) || m_pDownload->IsMoving() ) return;
		
		if ( m_pDownload->NeedTigerTree() && m_pDownload->NeedHashset() && !m_pDownload->m_oBTH )
		{
			pLock.Unlock();
			LoadString( strMessage, IDS_DOWNLOAD_EDIT_COMPLETE_NOHASH );
			AfxMessageBox( strMessage, MB_ICONEXCLAMATION );
			return;
		}
		else
		{
			pLock.Unlock();
            LoadString( strMessage, IDS_DOWNLOAD_EDIT_COMPLETE_VERIFY );
			if ( AfxMessageBox( strMessage, MB_ICONQUESTION|MB_YESNO ) != IDYES ) return;
		}

		pLock.Lock();
		if ( ! Downloads.Check( m_pDownload ) || m_pDownload->IsMoving() ) return;

		m_pDownload->MakeComplete();
		m_pDownload->ResetVerification();
		m_pDownload->SetModified();
	}
	else if ( rcCtrl5.PtInRect( point ) )
	{
		OnMergeAndVerify ();
	}
}

void CDownloadEditActionsPage::OnErase()
{
	QWORD nFrom = 0, nTo = 0;
	CString strMessage;

	UpdateData();

	if ( _stscanf( m_sEraseFrom, _T("%I64i"), &nFrom ) != 1 ||
		 _stscanf( m_sEraseTo, _T("%I64i"), &nTo ) != 1 ||
		 nTo < nFrom )
	{
		LoadString( strMessage, IDS_DOWNLOAD_EDIT_BAD_RANGE );
		AfxMessageBox( strMessage, MB_ICONEXCLAMATION );
		return;
	}

	CSingleLock pLock( &Transfers.m_pSection, TRUE );
	if ( ! Downloads.Check( m_pDownload ) || m_pDownload->IsMoving() ) return;

	m_pDownload->CloseTransfers();
	QWORD nErased = m_pDownload->EraseRange( nFrom, nTo + 1 - nFrom );

	if ( nErased > 0 )
	{
//		m_pDownload->ClearVerification();
		m_pDownload->ResetVerification();

		pLock.Unlock();
		CString strFormat;
		LoadString( strFormat, IDS_DOWNLOAD_EDIT_ERASED );
		strMessage.Format( strFormat, nErased );
		AfxMessageBox( strMessage, MB_ICONINFORMATION );
	}
	else
	{
		pLock.Unlock();
		LoadString( strMessage, IDS_DOWNLOAD_EDIT_CANT_ERASE );
		AfxMessageBox( strMessage, MB_ICONEXCLAMATION );
	}
}

void CDownloadEditActionsPage::OnMergeAndVerify()
{
	CString strMessage, strFormat;

	CSingleLock pLock( &Transfers.m_pSection, TRUE );
	if ( ! Downloads.Check( m_pDownload ) ||
		m_pDownload->IsCompleted() ||
		m_pDownload->IsMoving() ||
		! m_pDownload->PrepareFile() )
	{
		// Download almost completed
		pLock.Unlock();
		return;
	}
	if ( m_pDownload->NeedTigerTree() &&
		 m_pDownload->NeedHashset() &&
		! m_pDownload->m_oBTH )
	{
		// No hashsets
		pLock.Unlock();
		LoadString( strMessage, IDS_DOWNLOAD_EDIT_COMPLETE_NOHASH );
		AfxMessageBox( strMessage, MB_ICONEXCLAMATION );
		return;
	}
	const Fragments::List oList( m_pDownload->GetEmptyFragmentList() );
	if ( ! oList.size() )
	{
		// No available fragments
		pLock.Unlock();
		return;
	}
	// Select file
	CString strExt( PathFindExtension( m_pDownload->m_sDisplayName ) );
	if ( ! strExt.IsEmpty() ) strExt = strExt.Mid( 1 );
	CFileDialog dlgSelectFile( TRUE, strExt, m_pDownload->m_sDisplayName,
		OFN_HIDEREADONLY | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR,
		NULL, this );
	if ( dlgSelectFile.DoModal() == IDOK )
	{
		CDownload * pDownload = m_pDownload;
		pParent->EndDialog(IDCANCEL);
		
		// Open selected file in very compatible sharing mode
		HANDLE hSelectedFile = CreateFile( dlgSelectFile.GetPathName(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL, NULL);
		if ( hSelectedFile != INVALID_HANDLE_VALUE ) 
		{
			// Read missing file fragments from selected file
			BYTE Buf [65536];
			DWORD dwToRead, dwReaded;
			for ( Fragments::List::const_iterator pFragment = oList.begin();
				pFragment != oList.end(); ++pFragment )
			{
				QWORD qwLength = pFragment->end() - pFragment->begin();
				QWORD qwOffset = pFragment->begin();
				LONG nOffsetHigh = (LONG)( qwOffset >> 32 );
				LONG nOffsetLow = (LONG)( qwOffset & 0xFFFFFFFF );
				SetFilePointer( hSelectedFile, nOffsetLow, &nOffsetHigh, FILE_BEGIN );
				if ( GetLastError() == NO_ERROR )
				{
					while ( ( dwToRead = (DWORD)min( qwLength, (QWORD)sizeof( Buf ) ) ) != 0 )
					{
						if ( ReadFile( hSelectedFile, Buf, dwToRead, &dwReaded, NULL ) && dwReaded != 0 )
						{
							// "Multithreading" :-)
							MSG msg;
							while ( PeekMessage( &msg, NULL, 0, 0, PM_REMOVE ) )
							{
								TranslateMessage( &msg );
								DispatchMessage( &msg );
							}
							Sleep( 0 );
								pDownload->SubmitData( qwOffset, Buf, (QWORD) dwReaded );
								pDownload->RunValidation(FALSE);
								qwOffset += (QWORD) dwReaded;
								qwLength -= (QWORD) dwReaded;
						}
						else
							// File error or end of file. Not Fatal
							break;
					}
				}
			}
			CloseHandle( hSelectedFile );
//			pDownload->Resume();
//			pDownload->RunValidation(FALSE);
			while ( pDownload->FindNewValidationBlock( HASH_TORRENT ) ||
					pDownload->FindNewValidationBlock( HASH_TIGERTREE ) ||
					pDownload->FindNewValidationBlock( HASH_ED2K ) )
			{
				pDownload->ContinueValidation();
			}

		}
		else
		{
			// File open error
			LoadString( strFormat, IDS_DOWNLOAD_FILE_OPEN_ERROR );
			strMessage.Format( strFormat, dlgSelectFile.GetPathName() );
			AfxMessageBox( strMessage, MB_ICONINFORMATION );
		}
	}

	pLock.Unlock();
}

