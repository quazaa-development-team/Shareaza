//
// DlgTorrentSeed.cpp
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
#include "Network.h"
#include "Library.h"
#include "SharedFile.h"
#include "Transfers.h"
#include "Downloads.h"
#include "Download.h"
#include "ShareazaURL.h"
#include "HttpRequest.h"
#include "DlgTorrentSeed.h"

IMPLEMENT_DYNAMIC(CTorrentSeedDlg, CSkinDialog)

BEGIN_MESSAGE_MAP(CTorrentSeedDlg, CSkinDialog)
	ON_BN_CLICKED(IDC_DOWNLOAD, OnDownload)
	ON_BN_CLICKED(IDC_SEED, OnSeed)
	ON_WM_DESTROY()
	ON_WM_TIMER()
END_MESSAGE_MAP()

#define BUFFER_SIZE				(2*1024*1024)


/////////////////////////////////////////////////////////////////////////////
// CTorrentSeedDlg construction

CTorrentSeedDlg::CTorrentSeedDlg(LPCTSTR pszTorrent, CWnd* pParent) : CSkinDialog( CTorrentSeedDlg::IDD, pParent )
{
	m_hThread	= NULL;
	m_sTorrent	= pszTorrent;
}

CTorrentSeedDlg::~CTorrentSeedDlg()
{
	ASSERT( m_hThread == NULL );
}

void CTorrentSeedDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange( pDX );
	DDX_Control( pDX, IDC_DOWNLOAD, m_wndDownload );
	DDX_Control( pDX, IDC_SEED, m_wndSeed );
	DDX_Control( pDX, IDC_PROGRESS, m_wndProgress );
}

/////////////////////////////////////////////////////////////////////////////
// CTorrentSeedDlg message handlers

BOOL CTorrentSeedDlg::OnInitDialog()
{
	CSkinDialog::OnInitDialog();
	
	SkinMe( NULL, IDR_MAINFRAME );
	
	m_wndProgress.SetRange( 0, 1000 );
	m_wndProgress.SetPos( 0 );
	
	return TRUE;
}

void CTorrentSeedDlg::OnDownload()
{
	CWnd* pWnd = AfxGetMainWnd();
	CBTInfo* pTorrent = new CBTInfo();
	
	if ( pTorrent->LoadTorrentFile( m_sTorrent ) )
	{
		CShareazaURL* pURL = new CShareazaURL( pTorrent );
		if ( ! pWnd->PostMessage( WM_URL, (WPARAM)pURL ) ) delete pURL;
		EndDialog( IDOK );
		return;
	}
	
	delete pTorrent;
	theApp.Message( MSG_ERROR, IDS_BT_PREFETCH_ERROR, (LPCTSTR)m_sTorrent );
	EndDialog( IDOK );
}

void CTorrentSeedDlg::OnSeed()
{
	if ( ! Network.IsConnected() ) Network.Connect();
	
	m_wndDownload.EnableWindow( FALSE );
	m_wndSeed.EnableWindow( FALSE );
	m_bCancel = FALSE;
	
	if ( m_pInfo.LoadTorrentFile( m_sTorrent ) )
	{
		if ( Downloads.FindByBTH( &m_pInfo.m_pInfoSHA1 ) == NULL )
		{
			m_hThread = AfxBeginThread( ThreadStart, this,
				THREAD_PRIORITY_NORMAL )->m_hThread;
		}
		else
		{
			CString strFormat, strMessage;
			strFormat.LoadString( IDS_BT_SEED_ALREADY );
			strMessage.Format( strFormat, (LPCTSTR)m_pInfo.m_sName );
			AfxMessageBox( strMessage, MB_ICONEXCLAMATION );
			EndDialog( IDOK );
		}
	}
	else
	{
		CString strFormat, strMessage;
		strFormat.LoadString( IDS_BT_SEED_PARSE_ERROR );
		strMessage.Format( strFormat, (LPCTSTR)m_sTorrent );
		AfxMessageBox( strMessage, MB_ICONEXCLAMATION );
		EndDialog( IDOK );
	}
}

void CTorrentSeedDlg::OnCancel()
{
	if ( m_wndDownload.IsWindowEnabled() || m_bCancel )
	{
		CSkinDialog::OnCancel();
	}
	else
	{
		m_bCancel = TRUE;
	}
}

void CTorrentSeedDlg::OnDestroy()
{
	if ( m_hThread != NULL )
	{
		m_bCancel = TRUE;
		CHttpRequest::CloseThread( &m_hThread, _T("CTorrentSeedDlg") );
		ASSERT( m_hThread == NULL );
	}
	
	CSkinDialog::OnDestroy();
}

void CTorrentSeedDlg::OnTimer(UINT nIDEvent)
{
	CSkinDialog::OnTimer( nIDEvent );
	
	if ( nIDEvent == 1 )
	{
		EndDialog( IDOK );
	}
	else if ( nIDEvent == 2 )
	{
		if ( m_bCancel == FALSE ) AfxMessageBox( m_sMessage, MB_ICONEXCLAMATION );
		EndDialog( IDCANCEL );
	}
	else if ( nIDEvent == 3 )
	{
		if ( m_nScaled != m_nOldScaled )
		{
			m_nOldScaled = m_nScaled;
			m_wndProgress.SetPos( m_nScaled );
		}
	}
}

/////////////////////////////////////////////////////////////////////////////
// CTorrentSeedDlg thread run

UINT CTorrentSeedDlg::ThreadStart(LPVOID pParam)
{
	((CTorrentSeedDlg*)pParam)->OnRun();
	return 0;
}

void CTorrentSeedDlg::OnRun()
{
	if ( m_pInfo.m_nFiles == 1 )
	{
		RunSingleFile();
	}
	else
	{
		RunMultiFile();
	}
}

void CTorrentSeedDlg::RunSingleFile()
{
	m_sTarget = FindFile( &m_pInfo.m_pFiles[0] );
	
	if ( m_sTarget.IsEmpty() || GetFileAttributes( m_sTarget ) == 0xFFFFFFFF )
	{
		CString strFormat;
		strFormat.LoadString( IDS_BT_SEED_SOURCE_LOST );
		m_sMessage.Format( strFormat, (LPCTSTR)m_pInfo.m_pFiles[0].m_sPath );
		PostMessage( WM_TIMER, 2 );
		return;
	}
	
	if ( VerifySingle() && CreateDownload() )
	{
		PostMessage( WM_TIMER, 1 );
	}
	else
	{
		PostMessage( WM_TIMER, 2 );
	}
}

void CTorrentSeedDlg::RunMultiFile()
{
	HANDLE hTarget = CreateTarget();
	
	if ( hTarget != INVALID_HANDLE_VALUE )
	{
		BOOL bBuild = BuildFiles( hTarget );
		CloseHandle( hTarget );
		
		if ( bBuild && CreateDownload() )
		{
			PostMessage( WM_TIMER, 1 );
		}
		else
		{
			DeleteFile( m_sTarget );
			PostMessage( WM_TIMER, 2 );
		}
	}
	else
	{
		PostMessage( WM_TIMER, 2 );
	}
}

CString CTorrentSeedDlg::FindFile(LPVOID pVoid)
{
	CBTInfo::CBTFile* pFile = reinterpret_cast<CBTInfo::CBTFile*>(pVoid);
	CString strFile;
	
	CString strPath = m_sTorrent;
	int nSlash = strPath.ReverseFind( '\\' );
	if ( nSlash >= 0 ) strPath = strPath.Left( nSlash + 1 );
	
	if ( pFile->m_bSHA1 )
	{
		if ( CLibraryFile* pShared = LibraryMaps.LookupFileBySHA1( &pFile->m_pSHA1, TRUE, FALSE, TRUE ) )
		{
			strFile = pShared->GetPath();
			Library.Unlock();
			if ( GetFileAttributes( strFile ) != 0xFFFFFFFF ) return strFile;
		}
	}
	
	strFile = strPath + pFile->m_sPath;
	if ( GetFileAttributes( strFile ) != 0xFFFFFFFF ) return strFile;
	
	LPCTSTR pszName = _tcsrchr( pFile->m_sPath, '\\' );
	if ( pszName == NULL ) pszName = pFile->m_sPath; else pszName ++;
	strFile = strPath + pszName;
	if ( GetFileAttributes( strFile ) != 0xFFFFFFFF ) return strFile;
	
	strFile.Empty();
	return strFile;
}

BOOL CTorrentSeedDlg::VerifySingle()
{
	HANDLE hTarget = CreateFile( m_sTarget, GENERIC_READ, FILE_SHARE_READ, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
	
	if ( hTarget == INVALID_HANDLE_VALUE )
	{
		CString strFormat;
		strFormat.LoadString( IDS_BT_SEED_SOURCE_LOST );
		m_sMessage.Format( strFormat, (LPCTSTR)m_sTarget );
		return FALSE;
	}	
	
	DWORD nSizeHigh	= 0;
	DWORD nSizeLow	= GetFileSize( hTarget, &nSizeHigh );
	m_nTotal		= (QWORD)nSizeLow | ( (QWORD)nSizeHigh << 32 );
	
	m_pInfo.BeginBlockTest();
	m_nBlockNumber	= 0;
	m_nBlockLength	= m_pInfo.m_nBlockSize;
	
	BYTE* pBuffer	= new BYTE[ BUFFER_SIZE ];
	
	for ( m_nVolume = 0 ; m_nVolume < m_nTotal ; )
	{
		DWORD nBuffer	= (DWORD)min( ( m_nTotal - m_nVolume ), BUFFER_SIZE );
		DWORD tStart	= GetTickCount();
		
		ReadFile( hTarget, pBuffer, nBuffer, &nBuffer, NULL );
		if ( ! VerifyData( pBuffer, nBuffer, m_sTarget ) ) break;
		
		m_nVolume += nBuffer;
		m_nScaled = (int)( (double)m_nVolume / (double)m_nTotal * 1000.0f );
		if ( m_nScaled != m_nOldScaled ) PostMessage( WM_TIMER, 3 );
		
		if ( m_bCancel ) break;
		tStart = ( GetTickCount() - tStart ) / 2;
		Sleep( min( tStart, 50 ) );
		if ( m_bCancel ) break;
	}
	
	delete [] pBuffer;
	CloseHandle( hTarget );
	
	return ( m_nVolume >= m_nTotal ) && VerifyData( NULL, 0, m_sTarget );
}

HANDLE CTorrentSeedDlg::CreateTarget()
{
	m_sTarget = Settings.Downloads.IncompletePath + '\\';
	m_sTarget += CSHA::HashToHexString( &m_pInfo.m_pInfoSHA1, FALSE );
	
	HANDLE hTarget = CreateFile(	m_sTarget, GENERIC_WRITE, 0, NULL, CREATE_NEW,
									FILE_ATTRIBUTE_NORMAL, NULL );
	
	if ( hTarget == INVALID_HANDLE_VALUE )
	{
		CString strFormat;
		strFormat.LoadString( IDS_BT_SEED_CREATE_FAIL );
		m_sMessage.Format( strFormat, (LPCTSTR)m_sTarget );
	}
	
	return hTarget;
}

BOOL CTorrentSeedDlg::BuildFiles(HANDLE hTarget)
{
	m_nVolume = m_nTotal = 0;
	m_nScaled = m_nOldScaled = 0;
	
	for ( int nFile = 0 ; nFile < m_pInfo.m_nFiles ; nFile++ )
	{
		CBTInfo::CBTFile* pFile = &m_pInfo.m_pFiles[ nFile ];
		m_nTotal += pFile->m_nSize;
	}
	
	m_pInfo.BeginBlockTest();
	m_nBlockNumber	= 0;
	m_nBlockLength	= m_pInfo.m_nBlockSize;
	
	for ( nFile = 0 ; nFile < m_pInfo.m_nFiles ; nFile++ )
	{
		CBTInfo::CBTFile* pFile = &m_pInfo.m_pFiles[ nFile ];
		CString strSource = FindFile( pFile );
		HANDLE hSource = INVALID_HANDLE_VALUE;
		
		if ( strSource.GetLength() > 0 )
		{
			hSource = CreateFile( strSource, GENERIC_READ,
				FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
		}
		
		if ( hSource == INVALID_HANDLE_VALUE )
		{
			CString strFormat;
			strFormat.LoadString( IDS_BT_SEED_SOURCE_LOST );
			m_sMessage.Format( strFormat, (LPCTSTR)pFile->m_sPath );
			return FALSE;
		}
		
		DWORD nSizeHigh	= 0;
		DWORD nSizeLow	= GetFileSize( hSource, &nSizeHigh );
		QWORD nSize		= (QWORD)nSizeLow + ( (QWORD)nSizeHigh << 32 );
		
		if ( nSize != pFile->m_nSize )
		{
			CloseHandle( hSource );
			CString strFormat;
			strFormat.LoadString( IDS_BT_SEED_SOURCE_SIZE );
			m_sMessage.Format( strFormat, (LPCTSTR)pFile->m_sPath,
				(LPCTSTR)Settings.SmartVolume( pFile->m_nSize, FALSE ),
				(LPCTSTR)Settings.SmartVolume( nSize, FALSE ) );
			return FALSE;
		}
		
		BOOL bSuccess = CopyFile( hTarget, hSource, pFile->m_nSize, pFile->m_sPath );
		
		CloseHandle( hSource );
		
		if ( m_bCancel || ! bSuccess ) return FALSE;
	}
	
	return VerifyData( NULL, 0, m_pInfo.m_pFiles[ m_pInfo.m_nFiles - 1 ].m_sPath );
}

BOOL CTorrentSeedDlg::CopyFile(HANDLE hTarget, HANDLE hSource, QWORD nLength, LPCTSTR pszPath)
{
	BYTE* pBuffer = new BYTE[ BUFFER_SIZE ];
	
	while ( nLength )
	{
		DWORD nBuffer	= (DWORD)min( nLength, BUFFER_SIZE );
		DWORD nSuccess	= 0;
		DWORD tStart	= GetTickCount();
		
		ReadFile( hSource, pBuffer, nBuffer, &nBuffer, NULL );
		
		if ( ! VerifyData( pBuffer, nBuffer, pszPath ) )
		{
			delete [] pBuffer;
			return FALSE;
		}
		
		WriteFile( hTarget, pBuffer, nBuffer, &nSuccess, NULL );
		
		if ( nSuccess == nBuffer )
		{
			nLength -= nBuffer;
		}
		else
		{
			break;
		}
		
		m_nVolume += nBuffer;
		m_nScaled = (int)( (double)m_nVolume / (double)m_nTotal * 1000.0f );
		if ( m_nScaled != m_nOldScaled ) PostMessage( WM_TIMER, 3 );
		
		if ( m_bCancel ) break;
		tStart = ( GetTickCount() - tStart ) / 2;
		Sleep( min( tStart, 50 ) );
		if ( m_bCancel ) break;
	}
	
	delete [] pBuffer;
	
	if ( nLength == 0 )
	{
		return TRUE;
	}
	else
	{
		CString strFormat;
		strFormat.LoadString( IDS_BT_SEED_COPY_FAIL );
		m_sMessage.Format( strFormat, (LPCTSTR)pszPath );
		return FALSE;
	}
}

BOOL CTorrentSeedDlg::VerifyData(BYTE* pBuffer, DWORD nLength, LPCTSTR pszPath)
{
	if ( pBuffer == NULL )
	{
		if ( m_nBlockNumber >= m_pInfo.m_nBlockCount ) return TRUE;
		if ( m_pInfo.FinishBlockTest( m_nBlockNumber++ ) ) return TRUE;
		
		CString strFormat;
		strFormat.LoadString( IDS_BT_SEED_VERIFY_FAIL );
		m_sMessage.Format( strFormat, (LPCTSTR)pszPath );
		return FALSE;
	}
	
	while ( nLength > 0 )
	{
		DWORD nBlock = min( nLength, m_nBlockLength );
		
		m_pInfo.AddToTest( pBuffer, nBlock );
		
		pBuffer += nBlock;
		nLength -= nBlock;
		m_nBlockLength -= nBlock;
		
		if ( m_nBlockLength == 0 )
		{
			if ( ! m_pInfo.FinishBlockTest( m_nBlockNumber++ ) )
			{
				CString strFormat;
				strFormat.LoadString( IDS_BT_SEED_VERIFY_FAIL );
				m_sMessage.Format( strFormat, (LPCTSTR)pszPath );
				return FALSE;
			}
			
			if ( m_nBlockNumber < m_pInfo.m_nBlockCount )
			{
				m_nBlockLength = m_pInfo.m_nBlockSize;
				m_pInfo.BeginBlockTest();
			}
		}
	}
	
	return TRUE;
}

BOOL CTorrentSeedDlg::CreateDownload()
{
	CSingleLock pLock( &Transfers.m_pSection );
	if ( ! pLock.Lock( 2000 ) ) return FALSE;
	
	if ( Downloads.FindByBTH( &m_pInfo.m_pInfoSHA1 ) != NULL )
	{
		CString strFormat;
		strFormat.LoadString( IDS_BT_SEED_ALREADY );
		m_sMessage.Format( strFormat, (LPCTSTR)m_pInfo.m_sName );
		return FALSE;
	}
	
	CBTInfo* pInfo = new CBTInfo();
	pInfo->Copy( &m_pInfo );
	CShareazaURL pURL( pInfo );
	CDownload* pDownload = Downloads.Add( &pURL );
	
	if ( pDownload != NULL && pDownload->SeedTorrent( m_sTarget ) )
	{
		return TRUE;
	}
	else
	{
		CString strFormat;
		strFormat.LoadString( IDS_BT_SEED_ERROR );
		m_sMessage.Format( strFormat, (LPCTSTR)m_pInfo.m_sName );
		return FALSE;
	}
}