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
#include "Download.h"
#include "Downloads.h"
#include "Transfers.h"
#include "DlgDownloadEdit.h"
#include "DlgTorrentInfoSheet.h"
#include "FragmentedFile.h"

#include "SHA.h"
#include "ED2K.h"
#include "TigerTree.h"

IMPLEMENT_DYNAMIC(CDownloadEditDlg, CSkinDialog)

BEGIN_MESSAGE_MAP(CDownloadEditDlg, CSkinDialog)
	ON_WM_CTLCOLOR()
	ON_WM_SETCURSOR()
	ON_WM_LBUTTONUP()
	ON_BN_CLICKED(IDC_TORRENT_INFO, OnTorrentInfo)
	ON_BN_CLICKED(IDC_ERASE, OnErase)
END_MESSAGE_MAP()


//////////////////////////////////////////////////////////////////////////////
// CDownloadEditDlg construction

CDownloadEditDlg::CDownloadEditDlg(CDownload* pDownload, CWnd* pParent) : CSkinDialog( CDownloadEditDlg::IDD, pParent )
{
	m_pDownload = pDownload;
}

CDownloadEditDlg::~CDownloadEditDlg()
{
}

void CDownloadEditDlg::DoDataExchange(CDataExchange* pDX)
{
	CSkinDialog::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_NAME, m_sName);
	DDX_Text(pDX, IDC_DISKNAME, m_sDiskName);
	DDX_Text(pDX, IDC_FILESIZE, m_sFileSize);
	DDX_Text(pDX, IDC_URN_SHA1, m_sSHA1);
	DDX_Text(pDX, IDC_URN_TIGER, m_sTiger);
	DDX_Text(pDX, IDC_URN_ED2K, m_sED2K);
	DDX_Check(pDX, IDC_TRUST_SHA1, m_bSHA1Trusted);
	DDX_Check(pDX, IDC_TRUST_TIGER, m_bTigerTrusted);
	DDX_Check(pDX, IDC_TRUST_ED2K, m_bED2KTrusted);
	DDX_Control(pDX, IDC_FORGET_VERIFY, m_wndForgetVerify);
	DDX_Control(pDX, IDC_FORGET_SOURCES, m_wndForgetSources);
	DDX_Text(pDX, IDC_ERASE_FROM, m_sEraseFrom);
	DDX_Text(pDX, IDC_ERASE_TO, m_sEraseTo);
	DDX_Control(pDX, IDC_TORRENT_INFO, m_wndTorrent);
	DDX_Control(pDX, IDC_COMPLETE_AND_VERIFY, m_wndCompleteVerify);
	DDX_Control(pDX, IDC_MERGE_AND_VERIFY, m_wndMergeVerify);
}

//////////////////////////////////////////////////////////////////////////////
// CDownloadEditDlg message handlers

BOOL CDownloadEditDlg::OnInitDialog()
{
	CSkinDialog::OnInitDialog();

	SkinMe( NULL, ID_TOOLS_DOWNLOAD );

	CSingleLock pLock( &Transfers.m_pSection, TRUE );

	if ( ! Downloads.Check( m_pDownload ) || m_pDownload->IsMoving() )
	{
		PostMessage( WM_CLOSE );
		return TRUE;
	}

	m_sName = m_pDownload->m_sDisplayName;
	m_sDiskName = m_pDownload->m_sDiskName;
	m_sFileSize.Format( _T("%I64i"), m_pDownload->m_nSize );

	if ( m_pDownload->m_oSHA1 )
		m_sSHA1 = m_pDownload->m_oSHA1.toString();
	if ( m_pDownload->m_oTiger )
		m_sTiger = m_pDownload->m_oTiger.toString();
	if ( m_pDownload->m_oED2K )
        m_sED2K = m_pDownload->m_oED2K.toString();

	m_bSHA1Trusted	=	m_pDownload->m_oSHA1.isTrusted();
	m_bTigerTrusted	=	m_pDownload->m_oTiger.isTrusted();
	m_bED2KTrusted	=	m_pDownload->m_oED2K.isTrusted();
	
	m_wndTorrent.EnableWindow( m_pDownload->m_pTorrent.IsAvailable() );

	UpdateData( FALSE );

	return TRUE;
}

HBRUSH CDownloadEditDlg::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
	HBRUSH hbr = CSkinDialog::OnCtlColor( pDC, pWnd, nCtlColor );

	if ( pWnd == &m_wndForgetVerify || pWnd == &m_wndForgetSources ||
		pWnd == &m_wndCompleteVerify || pWnd == &m_wndMergeVerify )
	{
		pDC->SelectObject( &theApp.m_gdiFontLine );
		pDC->SetTextColor( RGB( 0, 0, 255 ) );
	}

	return hbr;
}

BOOL CDownloadEditDlg::OnSetCursor(CWnd* pWnd, UINT nHitTest, UINT message)
{
	CRect rcCtrl1, rcCtrl2, rcCtrl3, rcCtrl4;
	CPoint point;

	GetCursorPos( &point );
    m_wndForgetVerify.GetWindowRect( &rcCtrl1 );
	m_wndForgetSources.GetWindowRect( &rcCtrl2 );
	m_wndCompleteVerify.GetWindowRect( &rcCtrl3 );
	m_wndMergeVerify.GetWindowRect( &rcCtrl4 );

	if ( rcCtrl1.PtInRect( point ) || rcCtrl2.PtInRect( point ) ||
		rcCtrl3.PtInRect( point ) || rcCtrl4.PtInRect( point ) )
	{
		SetCursor( AfxGetApp()->LoadCursor( IDC_HAND ) );
		return TRUE;
	}

	return CSkinDialog::OnSetCursor( pWnd, nHitTest, message );
}

void CDownloadEditDlg::OnLButtonUp(UINT nFlags, CPoint point)
{
	CSkinDialog::OnLButtonUp(nFlags, point);

	CRect rcCtrl1, rcCtrl2, rcCtrl3, rcCtrl4;

	m_wndForgetVerify.GetWindowRect( &rcCtrl1 );
	ScreenToClient( &rcCtrl1 );
	m_wndForgetSources.GetWindowRect( &rcCtrl2 );
	ScreenToClient( &rcCtrl2 );
	m_wndCompleteVerify.GetWindowRect( &rcCtrl3 );
	ScreenToClient( &rcCtrl3 );
	m_wndMergeVerify.GetWindowRect( &rcCtrl4 );
	ScreenToClient( &rcCtrl4 );

	if ( rcCtrl1.PtInRect( point ) )
	{
		if ( ! Commit() ) return;

		CString strMessage;
		LoadString( strMessage, IDS_DOWNLOAD_EDIT_FORGET_VERIFY );
		if ( AfxMessageBox( strMessage, MB_ICONQUESTION|MB_YESNO ) != IDYES ) return;

		CSingleLock pLock( &Transfers.m_pSection, TRUE );
		if ( ! Downloads.Check( m_pDownload ) || m_pDownload->IsMoving() ) return;
		m_pDownload->ClearVerification();
	}
	else if ( rcCtrl2.PtInRect( point ) )
	{
		if ( ! Commit() ) return;

		CString strMessage;
		LoadString( strMessage, IDS_DOWNLOAD_EDIT_FORGET_SOURCES );
		if ( AfxMessageBox( strMessage, MB_ICONQUESTION|MB_YESNO ) != IDYES ) return;

		CSingleLock pLock( &Transfers.m_pSection, TRUE );
		if ( ! Downloads.Check( m_pDownload ) || m_pDownload->IsMoving() ) return;

		m_pDownload->CloseTransfers();
		m_pDownload->ClearSources();
		m_pDownload->SetModified();
	}
	else if ( rcCtrl3.PtInRect( point ) )
	{
		if ( ! Commit() ) return;

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
	else if ( rcCtrl4.PtInRect( point ) )
	{
		OnMergeAndVerify ();
	}
}

void CDownloadEditDlg::OnTorrentInfo()
{
	CSingleLock pLock( &Transfers.m_pSection, TRUE );

	if ( ! Downloads.Check( m_pDownload ) ) return;
	if ( ! m_pDownload->m_pTorrent.IsAvailable() ) return;

	CTorrentInfoSheet dlg( &m_pDownload->m_pTorrent );
	pLock.Unlock();
	dlg.DoModal();

	if ( pLock.Lock(250) )
	{
		if ( Downloads.Check( m_pDownload ) ) 
		{
			if ( dlg.m_pInfo.IsAvailable() )
			{
				m_pDownload->m_pTorrent.m_sTracker = dlg.m_pInfo.m_sTracker;
			}
			m_pDownload->m_pTorrent.m_nStartDownloads = dlg.m_pInfo.m_nStartDownloads;
		}
	}
}

void CDownloadEditDlg::OnErase()
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

	if ( ! Commit() ) return;

	CSingleLock pLock( &Transfers.m_pSection, TRUE );
	if ( ! Downloads.Check( m_pDownload ) || m_pDownload->IsMoving() ) return;

	m_pDownload->CloseTransfers();
	QWORD nErased = m_pDownload->EraseRange( nFrom, nTo + 1 - nFrom );

	if ( nErased > 0 )
	{
		m_pDownload->ClearVerification();
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

void CDownloadEditDlg::OnMergeAndVerify()
{
	CString strMessage, strFormat;

	if ( ! Commit() ) return;

	CSingleLock pLock( &Transfers.m_pSection, TRUE );
	if ( ! Downloads.Check( m_pDownload ) || m_pDownload->IsMoving() )
	{
		pLock.Unlock();
		return;
	}
	if ( m_pDownload->NeedTigerTree() && m_pDownload->NeedHashset() && !m_pDownload->m_oBTH )
	{
		pLock.Unlock();
		LoadString( strMessage, IDS_DOWNLOAD_EDIT_COMPLETE_NOHASH );
		AfxMessageBox( strMessage, MB_ICONEXCLAMATION );
		return;
	}

	CString strExt( PathFindExtension( m_pDownload->m_sDisplayName ) );
	if ( ! strExt.IsEmpty() ) strExt = strExt.Mid( 1 );
	CFileDialog dlgSelectFile( TRUE, strExt, m_pDownload->m_sDisplayName,
		OFN_HIDEREADONLY | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR,
		NULL, this );
	if ( dlgSelectFile.DoModal() == IDOK )
	{
		UpdateWindow ();
		CWaitCursor wc;
		HANDLE hSelectedFile = CreateFile( dlgSelectFile.GetPathName(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL, NULL);
		if ( hSelectedFile != INVALID_HANDLE_VALUE ) 
		{
			m_pDownload->CloseTransfers();
			const Fragments::List oList ( m_pDownload->GetEmptyFragmentList() );
			if ( oList.size() != 0  )
			{
				BYTE Buf [65536];
				DWORD dwToRead, dwReaded;
				for ( Fragments::List::const_iterator pFragment = oList.begin();
					pFragment != oList.end(); ++pFragment )
				{
					QWORD qwLength = pFragment->end() - 1 - pFragment->begin() + 1;
					QWORD qwOffset = pFragment->begin();
					LONG nOffsetHigh = (LONG)( qwOffset >> 32 );
					LONG nOffsetLow = (LONG)( qwOffset & 0xFFFFFFFF );
					SetFilePointer( hSelectedFile, nOffsetLow, &nOffsetHigh, FILE_BEGIN );
					if ( GetLastError() == NO_ERROR )
						while ( ( dwToRead = (DWORD) min( qwLength, sizeof( Buf ) ) ) != 0 )
							if ( ReadFile( hSelectedFile, Buf, dwToRead, &dwReaded, NULL ) &&
								dwReaded != 0 )
							{
								m_pDownload->SubmitData( qwOffset, Buf, (QWORD) dwReaded );
								qwOffset += (QWORD) dwReaded;
								qwLength -= (QWORD) dwReaded;
							}
							else
							{
								// File error or end of file. Not Fatal
								break;
							}
				}
			}
			else
			{
				// No available fragments
				LoadString( strFormat, IDS_DOWNLOAD_FRAGMENT_END );
				strMessage.Format( strFormat, dlgSelectFile.GetPathName() );
				AfxMessageBox( strMessage, MB_ICONINFORMATION );		
			}
			CloseHandle( hSelectedFile );
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

void CDownloadEditDlg::OnOK()
{
	if ( ! Commit() ) return;
	CSkinDialog::OnOK();
}

BOOL CDownloadEditDlg::Commit()
{
	CString strMessage;

	UpdateData();
	
    Hashes::Sha1Hash oSHA1;
    oSHA1.fromString( m_sSHA1 );
    Hashes::TigerHash oTiger;
    oTiger.fromString( m_sTiger );
    Hashes::Ed2kHash oED2K;
    oED2K.fromString( m_sED2K );
	
	if ( m_sSHA1.GetLength() > 0 && !oSHA1 )
	{
		LoadString( strMessage, IDS_DOWNLOAD_EDIT_BAD_SHA1 );
		AfxMessageBox( strMessage, MB_ICONEXCLAMATION );
		return FALSE;
	}
	else if ( m_sTiger.GetLength() > 0 && !oTiger )
	{
		LoadString( strMessage, IDS_DOWNLOAD_EDIT_BAD_TIGER );
		AfxMessageBox( strMessage, MB_ICONEXCLAMATION );
		return FALSE;
	}
	else if ( m_sED2K.GetLength() > 0 && !oED2K )
	{
		LoadString( strMessage, IDS_DOWNLOAD_EDIT_BAD_ED2K );
		AfxMessageBox( strMessage, MB_ICONEXCLAMATION );
		return FALSE;
	}

	CSingleLock pLock( &Transfers.m_pSection, TRUE );
    if ( ! Downloads.Check( m_pDownload ) || m_pDownload->IsMoving() ) return FALSE;

	if ( m_pDownload->m_sDisplayName != m_sName )
	{
		pLock.Unlock();
		LoadString( strMessage, IDS_DOWNLOAD_EDIT_RENAME );
		if ( AfxMessageBox( strMessage, MB_ICONQUESTION|MB_YESNO ) != IDYES ) return FALSE;
		pLock.Lock();
		if ( ! Downloads.Check( m_pDownload ) || m_pDownload->IsMoving() ) return FALSE;

		m_pDownload->Rename( m_sName );
	}

	CString strSize;
	strSize.Format( _T("%i"), m_pDownload->m_nSize );
    if ( strSize != m_sFileSize )
	{
		pLock.Unlock();
		LoadString( strMessage, IDS_DOWNLOAD_EDIT_CHANGE_SIZE );
		if ( AfxMessageBox( strMessage, MB_ICONQUESTION|MB_YESNO ) != IDYES ) return FALSE;
		pLock.Lock();
		if ( ! Downloads.Check( m_pDownload ) || m_pDownload->IsMoving() ) return FALSE;
		
		_stscanf( m_sFileSize, _T("%I64i"), &(m_pDownload->m_nSize) );
	}
	
	if ( m_pDownload->m_oSHA1.isValid() != oSHA1.isValid()
		|| validAndUnequal( m_pDownload->m_oSHA1, oSHA1 ) )
	{
		pLock.Unlock();
		LoadString( strMessage, IDS_DOWNLOAD_EDIT_CHANGE_SHA1 );
		if ( AfxMessageBox( strMessage, MB_ICONQUESTION|MB_YESNO ) != IDYES ) return FALSE;
		pLock.Lock();
		if ( ! Downloads.Check( m_pDownload ) || m_pDownload->IsMoving() ) return FALSE;
		
		m_pDownload->m_oSHA1 = oSHA1;
		if ( oSHA1 ) m_pDownload->m_oSHA1.signalTrusted();
		
		m_pDownload->CloseTransfers();
		m_pDownload->ClearVerification();
	}
	
	if ( m_pDownload->m_oTiger.isValid() != oTiger.isValid()
		|| validAndUnequal( m_pDownload->m_oTiger, oTiger ) )
	{
		pLock.Unlock();
		LoadString( strMessage, IDS_DOWNLOAD_EDIT_CHANGE_TIGER );
		if ( AfxMessageBox( strMessage, MB_ICONQUESTION|MB_YESNO ) != IDYES ) return FALSE;
		pLock.Lock();
		if ( ! Downloads.Check( m_pDownload ) || m_pDownload->IsMoving() ) return FALSE;
		
		m_pDownload->m_oTiger = oTiger;
		if ( oTiger ) m_pDownload->m_oTiger.signalTrusted();
		
		m_pDownload->CloseTransfers();
		m_pDownload->ClearVerification();
	}
	
	if ( m_pDownload->m_oED2K.isValid() != oED2K.isValid()
		|| validAndUnequal( m_pDownload->m_oED2K, oED2K ) )
	{
		pLock.Unlock();
		LoadString( strMessage, IDS_DOWNLOAD_EDIT_CHANGE_ED2K );
		if ( AfxMessageBox( strMessage, MB_ICONQUESTION|MB_YESNO ) != IDYES ) return FALSE;
		pLock.Lock();
		if ( ! Downloads.Check( m_pDownload ) || m_pDownload->IsMoving() ) return FALSE;
		
		m_pDownload->m_oED2K = oED2K;
		if ( oED2K ) m_pDownload->m_oED2K.signalTrusted();
		
		m_pDownload->CloseTransfers();
		m_pDownload->ClearVerification();
	}

	if ( m_bSHA1Trusted ) 
		m_pDownload->m_oSHA1.signalTrusted();
	else
		m_pDownload->m_oSHA1.signalUntrusted();

	if ( m_bTigerTrusted )
		m_pDownload->m_oTiger.signalTrusted();
	else
		m_pDownload->m_oTiger.signalUntrusted();

	if ( m_bED2KTrusted )
		m_pDownload->m_oED2K.signalTrusted();
	else
		m_pDownload->m_oED2K.signalUntrusted();

	return TRUE;
}
