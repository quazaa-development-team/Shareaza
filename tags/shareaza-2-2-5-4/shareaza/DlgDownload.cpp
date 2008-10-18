//
// DlgDownload.cpp
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
#include "ShareazaURL.h"
#include "DlgDownload.h"
#include "Settings.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif


IMPLEMENT_DYNAMIC(CDownloadDlg, CSkinDialog)

BEGIN_MESSAGE_MAP(CDownloadDlg, CSkinDialog)
	ON_EN_CHANGE(IDC_URL, OnChangeURL)
	ON_BN_CLICKED(IDC_TORRENT_FILE, OnTorrentFile)
END_MESSAGE_MAP()


/////////////////////////////////////////////////////////////////////////////
// CDownloadDlg dialog

CDownloadDlg::CDownloadDlg(CWnd* pParent, CDownload* pDownload) : CSkinDialog( CDownloadDlg::IDD, pParent )
{
	m_pDownload = pDownload;
}

void CDownloadDlg::DoDataExchange(CDataExchange* pDX)
{
	CSkinDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_TORRENT_FILE, m_wndTorrentFile);
	DDX_Control(pDX, IDOK, m_wndOK);
	DDX_Control(pDX, IDC_URL, m_wndURL);
	DDX_Text(pDX, IDC_URL, m_sURL);
}

/////////////////////////////////////////////////////////////////////////////
// CDownloadDlg message handlers

BOOL CDownloadDlg::OnInitDialog() 
{
	CSkinDialog::OnInitDialog();
	
	SkinMe( NULL, IDR_DOWNLOADSFRAME );
	m_wndTorrentFile.EnableWindow( m_pDownload == NULL );
	
	if ( OpenClipboard() )
	{
		CString strClipboard;

		if ( theApp.m_bNT )
		{
			// These OSes can handle unicode file names
			if ( HGLOBAL hData = GetClipboardData( CF_UNICODETEXT ) )
			{
				size_t nData = GlobalSize( hData );
				LPVOID pData = GlobalLock( hData );
				
				LPTSTR pszData = strClipboard.GetBuffer( (int)( nData + 1 ) / 2 + 1 );
				CopyMemory( pszData, pData, nData );
				pszData[ ( nData + 1 ) / 2 ] = 0;
				strClipboard.ReleaseBuffer();
				GlobalUnlock( hData );
			}
		}
		else
		{
			// We need to have the file "%" encoded to display the names. 
			if ( HGLOBAL hData = GetClipboardData( CF_TEXT ) )
			{
				size_t nData = GlobalSize( hData );
				LPVOID pData = GlobalLock( hData );
				
				LPSTR pszData = new CHAR[ nData + 1 ];
				CopyMemory( pszData, pData, nData * sizeof( CHAR ) );
				pszData[ nData ] = 0;
				strClipboard = pszData;
				delete [] pszData;
				GlobalUnlock( hData );
			}	
		}
			
		// If we had something in the clipboard, see if it's a valid URL
		if ( ! strClipboard.IsEmpty() )
		{
			strClipboard.Trim( _T(" \t\r\n") );
					
			CShareazaURL pURL;
			if ( pURL.Parse( strClipboard ) )
			{
				m_sURL = strClipboard;
				UpdateData( FALSE );
				OnChangeURL();
			}
		}
		
		CloseClipboard();
	}
	
	return TRUE;
}

void CDownloadDlg::OnChangeURL() 
{
	UpdateData();

	CShareazaURL pURL;
	m_wndOK.EnableWindow( pURL.Parse( m_sURL, m_pURLs ) &&
		( m_pDownload == NULL ||
		pURL.m_nAction == CShareazaURL::uriSource ||
		pURL.m_nAction == CShareazaURL::uriDownload ) );
}

void CDownloadDlg::OnTorrentFile() 
{
	CFileDialog dlg( TRUE, _T("torrent"), ( Settings.Downloads.TorrentPath + "\\." ) , OFN_HIDEREADONLY,
		_T("Torrent Files|*.torrent|All Files|*.*||"), this );
	
	if ( dlg.DoModal() != IDOK ) return;
	
	CBTInfo* pTorrent = new CBTInfo();
	
	if ( pTorrent->LoadTorrentFile( dlg.GetPathName() ) )
	{
		CShareazaURL* pURL = new CShareazaURL( pTorrent );
		
		if ( AfxGetMainWnd()->PostMessage( WM_URL, (WPARAM)pURL ) )
		{
			EndDialog( IDCANCEL );
			return;
		}
		
		delete pURL;
	}
	else
		delete pTorrent;
}

void CDownloadDlg::OnOK() 
{
	UpdateData( TRUE );

	CShareazaURL pURL;
	if ( pURL.Parse( m_sURL, m_pURLs ) ) CSkinDialog::OnOK();
}