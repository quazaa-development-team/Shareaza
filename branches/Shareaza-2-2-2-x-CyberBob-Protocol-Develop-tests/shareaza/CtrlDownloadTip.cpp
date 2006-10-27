//
// CtrlDownloadTip.cpp
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
#include "CoolInterface.h"
#include "ShellIcons.h"
#include "Transfers.h"
#include "Downloads.h"
#include "Download.h"
#include "DownloadSource.h"
#include "DownloadTransfer.h"
#include "DownloadTransferBT.h"
#include "DownloadTransferED2K.h"
#include "EDClient.h"
#include "FragmentedFile.h"
#include "FragmentBar.h"
#include "Skin.h"
#include "SHA.h"
#include "GraphLine.h"
#include "GraphItem.h"
#include "CtrlDownloadTip.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

IMPLEMENT_DYNAMIC(CDownloadTipCtrl, CCoolTipCtrl)

BEGIN_MESSAGE_MAP(CDownloadTipCtrl, CCoolTipCtrl)
	//{{AFX_MSG_MAP(CDownloadTipCtrl)
	ON_WM_TIMER()
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()


/////////////////////////////////////////////////////////////////////////////
// CDownloadTipCtrl construction

CDownloadTipCtrl::CDownloadTipCtrl()
{
	m_pGraph	= NULL;
	m_nIcon		= 0;
}

CDownloadTipCtrl::~CDownloadTipCtrl()
{
	if ( m_pGraph ) delete m_pGraph;
}

/////////////////////////////////////////////////////////////////////////////
// CDownloadTipCtrl events

BOOL CDownloadTipCtrl::OnPrepare()
{
	CSingleLock pLock( &Transfers.m_pSection );
	if ( ! pLock.Lock( 100 ) ) return FALSE;

	CalcSizeHelper();

	return m_sz.cx > 0;
}

void CDownloadTipCtrl::OnCalcSize(CDC* pDC)
{
	if ( Downloads.Check( (CDownload*)m_pContext ) )
	{
		OnCalcSize( pDC, (CDownload*)m_pContext );
		m_sz.cx = max( m_sz.cx, 400 );
	}
	else if ( Downloads.Check( (CDownloadSource*)m_pContext ) )
	{
		OnCalcSize( pDC, (CDownloadSource*)m_pContext );
		m_sz.cx = max( m_sz.cx, 400 );
	}
}

void CDownloadTipCtrl::OnShow()
{
	if ( m_pGraph ) delete m_pGraph;

	m_pGraph	= CreateLineGraph();
	m_pItem		= new CGraphItem( 0, 0, RGB( 0xFF, 0, 0 ) );
	m_pGraph->AddItem( m_pItem );
}

void CDownloadTipCtrl::OnHide()
{
	if ( m_pGraph ) delete m_pGraph;
	m_pGraph = NULL;
	m_pItem = NULL;
}

void CDownloadTipCtrl::OnPaint(CDC* pDC)
{
	CSingleLock pLock( &Transfers.m_pSection );
	if ( ! pLock.Lock( 100 ) ) return;

	if ( Downloads.Check( (CDownload*)m_pContext ) )
	{
		OnPaint( pDC, (CDownload*)m_pContext );
	}
	else if ( Downloads.Check( (CDownloadSource*)m_pContext ) )
	{
		OnPaint( pDC, (CDownloadSource*)m_pContext );
	}
	else
	{
		Hide();
	}
}

/////////////////////////////////////////////////////////////////////////////
// CDownloadTipCtrl download case

void CDownloadTipCtrl::OnCalcSize(CDC* pDC, CDownload* pDownload)
{
	PrepareFileInfo( pDownload );

	AddSize( pDC, m_sName );
	m_sz.cy += TIP_TEXTHEIGHT;
	pDC->SelectObject( &CoolInterface.m_fntNormal );

	if ( m_sSHA1.GetLength() )
	{
		AddSize( pDC, m_sSHA1 );
		m_sz.cy += TIP_TEXTHEIGHT;
	}
	if ( m_sED2K.GetLength() )
	{
		AddSize( pDC, m_sED2K );
		m_sz.cy += TIP_TEXTHEIGHT;
	}
	if ( m_sBTH.GetLength() )
	{
		AddSize( pDC, m_sBTH );
		m_sz.cy += TIP_TEXTHEIGHT;
	}
	if ( m_sTiger.GetLength() )
	{
		AddSize( pDC, m_sTiger );
		m_sz.cy += TIP_TEXTHEIGHT;
	}
	if ( m_sMD5.GetLength() )
	{
		AddSize( pDC, m_sMD5 );
		m_sz.cy += TIP_TEXTHEIGHT;
	}

	m_sz.cy += TIP_RULE;
	AddSize( pDC, m_sSize, 80 );
	AddSize( pDC, m_sType, 80 );
	m_sz.cy += 36;
	m_sz.cy += TIP_RULE;

	// Torrent Tracker error
	if ( pDownload->m_bTorrentTrackerError && ( pDownload->m_sTorrentTrackerError ) )
	{
		m_bDrawError = TRUE;
		m_sz.cy += TIP_TEXTHEIGHT;
		m_sz.cy += TIP_RULE;
	}
	else
		m_bDrawError = FALSE;


	if ( pDownload->m_oBTH )
	{	//Torrent ratio
		m_sz.cy += TIP_TEXTHEIGHT;
	}

	if ( ! pDownload->IsSeeding() )
	{	// Seeding torrent display none of this
		if ( pDownload->IsCompleted() )
		{	// ETA and downloaded
			m_sz.cy += TIP_TEXTHEIGHT * 2;
		}
		else
		{	// Speed, ETA, Downloaded, No. Sources
			m_sz.cy += TIP_TEXTHEIGHT * 4;
		}
	}

	// Number of reviews
	if ( pDownload->GetReviewCount() > 0 )
		m_sz.cy += TIP_TEXTHEIGHT;

	// URL
	if ( m_sURL.GetLength() )
	{
		m_sz.cy += TIP_RULE;
		AddSize( pDC, m_sURL );
		m_sz.cy += TIP_TEXTHEIGHT;
	}

	// Progress bar (not applicable for seeding torrents)
	if ( ! pDownload->IsSeeding() )
	{
		m_sz.cy += 2;
		m_sz.cy += TIP_TEXTHEIGHT;
	}

	// Graph (Only for files in progress)
	if ( pDownload->IsCompleted() )
		m_bDrawGraph = FALSE;
	else
	{
		m_sz.cy += TIP_GAP;
		m_sz.cy += 40;
		m_bDrawGraph = TRUE;
	}

	CString str;
	LoadString( str, IDS_DLM_ESTIMATED_TIME );
	m_nStatWidth = pDC->GetTextExtent( str ).cx + 8;
}

void CDownloadTipCtrl::OnPaint(CDC* pDC, CDownload* pDownload)
{
	CPoint pt( 0, 0 );
	CString str, strOf, strAnother;
	LoadString( strOf, IDS_GENERAL_OF );

	DrawText( pDC, &pt, m_sName );
	pt.y += TIP_TEXTHEIGHT;
	pDC->SelectObject( &CoolInterface.m_fntNormal );

	if ( !m_sSHA1.IsEmpty() )
	{
		DrawText( pDC, &pt, m_sSHA1 );
		pt.y += TIP_TEXTHEIGHT;
	}
	if ( !m_sTiger.IsEmpty() )
	{
		DrawText( pDC, &pt, m_sTiger );
		pt.y += TIP_TEXTHEIGHT;
	}
	if ( !m_sED2K.IsEmpty() )
	{
		DrawText( pDC, &pt, m_sED2K );
		pt.y += TIP_TEXTHEIGHT;
	}
	if ( !m_sMD5.IsEmpty() )
	{
		DrawText( pDC, &pt, m_sMD5 );
		pt.y += TIP_TEXTHEIGHT;
	}
	if ( !m_sBTH.IsEmpty() )
	{
		DrawText( pDC, &pt, m_sBTH );
		pt.y += TIP_TEXTHEIGHT;
	}

	DrawRule( pDC, &pt );

	ImageList_DrawEx( ShellIcons.GetHandle( 32 ), m_nIcon, pDC->GetSafeHdc(),
		pt.x, pt.y, 32, 32, CoolInterface.m_crTipBack, CLR_NONE, ILD_NORMAL );
	pDC->ExcludeClipRect( pt.x, pt.y, pt.x + 32, pt.y + 32 );

	pt.y += 2;
	LoadString( str, IDS_TIP_SIZE );
	str.Append( _T(": ") );
	pt.x += 40;
	DrawText( pDC, &pt, str );
	CSize sz1 = pDC->GetTextExtent( str );
	LoadString( strAnother, IDS_TIP_TYPE );
	strAnother.Append( _T(": ") );
	CSize sz2 = pDC->GetTextExtent( strAnother );

	sz1.cx = max( sz1.cx, sz2.cx );

	pt.x += sz1.cx + 2;
	DrawText( pDC, &pt, m_sSize );
	pt.y += TIP_TEXTHEIGHT;
	pt.x -= sz1.cx + 2;
	DrawText( pDC, &pt, strAnother );
	pt.x += sz1.cx + 2;
	DrawText( pDC, &pt, m_sType );
	pt.x -= 40 + sz1.cx + 2;
	pt.y -= TIP_TEXTHEIGHT + 2;
	pt.y += 34;

	DrawRule( pDC, &pt );

	CString strFormat, strETA, strSpeed, strVolume, strSources, strReviews, strTorrentUpload;

	int nSourceCount	= pDownload->GetSourceCount();
	int nTransferCount	= pDownload->GetTransferCount();
	int nReviewCount	= pDownload->GetReviewCount();

	LoadString( strFormat, IDS_TIP_NA );

	if ( pDownload->IsMoving() )
	{
		LoadString( strETA, IDS_DLM_COMPLETED_WORD );
		strSpeed = strFormat;
		LoadString( strSources, IDS_DLM_COMPLETED_WORD );
	}
	else if ( pDownload->IsPaused() )
	{
		strETA = strFormat;
		strSpeed = strFormat;
		strSources.Format( _T("%i"), nSourceCount );
	}
	else if ( nTransferCount )
	{
		DWORD nTime = pDownload->GetTimeRemaining();

		if ( nTime != 0xFFFFFFFF )
		{
			if ( nTime > 86400 )
			{
				LoadString( strFormat, IDS_DLM_TIME_DAH );
				strETA.Format( strFormat, nTime / 86400, ( nTime / 3600 ) % 24 );
			}
			else if ( nTime > 3600 )
			{
				LoadString( strFormat, IDS_DLM_TIME_HAM );
				strETA.Format( strFormat, nTime / 3600, ( nTime % 3600 ) / 60 );
			}
			else if ( nTime > 60 )
			{
				LoadString( strFormat, IDS_DLM_TIME_MAS );
				strETA.Format( strFormat, nTime / 60, nTime % 60 );
			}
			else
			{
				LoadString( strFormat, IDS_DLM_TIME_S );
				strETA.Format( strFormat, nTime % 60 );
			}
		}

		strSpeed = Settings.SmartVolume( pDownload->GetAverageSpeed() * 8, FALSE, TRUE );

		strSources.Format( _T("%i %s %i"), nTransferCount, strOf, nSourceCount );
		if ( theApp.m_bRTL ) strSources = _T("\x202B") + strSources;
	}
	else if ( nSourceCount )
	{
		strETA		= strFormat;
		strSpeed	= strFormat;
		strSources.Format( _T("%i"), nSourceCount );
	}
	else
	{
		strETA		= strFormat;
		strSpeed	= strFormat;
		LoadString( strSources, IDS_DLM_NO_SOURCES );
	}

	if ( nReviewCount > 0 )
	{
		strReviews.Format( _T("%i"), nReviewCount );
	}

	if ( pDownload->IsStarted() )
	{
		if ( theApp.m_bRTL )
		{
			strVolume.Format( _T("(%.2f%%) %s %s %s"),
				pDownload->GetProgress() * 100.0,
				(LPCTSTR)Settings.SmartVolume( pDownload->m_nSize, FALSE ), strOf,
				(LPCTSTR)Settings.SmartVolume( pDownload->GetVolumeComplete(), FALSE ) );
		}
		else
		{
			strVolume.Format( _T("%s %s %s (%.2f%%)"),
				(LPCTSTR)Settings.SmartVolume( pDownload->GetVolumeComplete(), FALSE ),
				strOf, (LPCTSTR)Settings.SmartVolume( pDownload->m_nSize, FALSE ),
				pDownload->GetProgress() * 100.0 );
		}
	}
	else
	{
		LoadString( strVolume, IDS_TIP_NA );
	}

	if ( pDownload->m_nTorrentUploaded )
	{
		if ( theApp.m_bRTL )
		{
			strTorrentUpload.Format( _T("(%.2f%%) %s %s %s"),
				pDownload->GetRatio() * 100.0,
				(LPCTSTR)Settings.SmartVolume( pDownload->m_nTorrentDownloaded, FALSE ),
				strOf,
				(LPCTSTR)Settings.SmartVolume( pDownload->m_nTorrentUploaded, FALSE ) );
		}
		else
		{
			strTorrentUpload.Format( _T("%s %s %s (%.2f%%)"),
				(LPCTSTR)Settings.SmartVolume( pDownload->m_nTorrentUploaded, FALSE ),
				strOf,
				(LPCTSTR)Settings.SmartVolume( pDownload->m_nTorrentDownloaded, FALSE ),
				pDownload->GetRatio() * 100.0 );
		}
	}
	else
	{
		if ( theApp.m_bRTL )
		{
			strTorrentUpload.Format( _T("(%.2f%%) %s %s %s"), 0.0, 
				(LPCTSTR)Settings.SmartVolume( pDownload->m_nTorrentDownloaded, FALSE ), strOf, _T("0") );
		}
		else
		{
			strTorrentUpload.Format( _T("%s %s %s (%.2f%%)"), _T("0"), strOf,
				(LPCTSTR)Settings.SmartVolume( pDownload->m_nTorrentDownloaded, FALSE ), 0.0 );
		}
	}

	// Draw the pop-up box
	if ( m_bDrawError )
	{	// Tracker error
		DrawText( pDC, &pt, pDownload->m_sTorrentTrackerError, 3 );
		pt.y += TIP_TEXTHEIGHT;
		DrawRule( pDC, &pt );
	}

	if ( ! pDownload->IsCompleted() )
	{	// Speed. Not for completed files
		LoadString( strFormat, IDS_DLM_TOTAL_SPEED );
		DrawText( pDC, &pt, strFormat, 3 );
		DrawText( pDC, &pt, strSpeed, m_nStatWidth );
		pt.y += TIP_TEXTHEIGHT;
	}
	if ( ! pDownload->IsSeeding() )
	{	// ETA. Not applicable for seeding torrents.
		LoadString( strFormat, IDS_DLM_ESTIMATED_TIME );
		DrawText( pDC, &pt, strFormat, 3 );
		DrawText( pDC, &pt, strETA, m_nStatWidth );
		pt.y += TIP_TEXTHEIGHT;
	}
	if ( ! pDownload->IsSeeding() )
	{	// Volume downloaded. Not for seeding torrents
		LoadString( strFormat, IDS_DLM_VOLUME_DOWNLOADED );
		DrawText( pDC, &pt, strFormat, 3 );
		DrawText( pDC, &pt, strVolume, m_nStatWidth );
		pt.y += TIP_TEXTHEIGHT;
	}
	if ( pDownload->m_oBTH )
	{	// Upload ratio- only for torrents
		LoadString( strFormat, IDS_DLM_VOLUME_UPLOADED );
		DrawText( pDC, &pt, strFormat, 3 );
		DrawText( pDC, &pt, strTorrentUpload, m_nStatWidth );
		pt.y += TIP_TEXTHEIGHT;
	}
	if ( ! pDownload->IsCompleted() )
	{	// No. Sources- Not applicable for completed files.
		LoadString( strFormat, IDS_DLM_NUMBER_OF_SOURCES );
		DrawText( pDC, &pt, strFormat, 3 );
		DrawText( pDC, &pt, strSources, m_nStatWidth );
		pt.y += TIP_TEXTHEIGHT;
	}
	if ( nReviewCount > 0 )
	{	// No. Reviews
		LoadString( strFormat, IDS_DLM_NUMBER_OF_REVIEWS );
		DrawText( pDC, &pt, strFormat, 3 );
		DrawText( pDC, &pt, strReviews, m_nStatWidth );
		pt.y += TIP_TEXTHEIGHT;
	}
	if ( m_sURL.GetLength() )
	{	// Draw URL if present
		DrawRule( pDC, &pt );
		DrawText( pDC, &pt, m_sURL );
		pt.y += TIP_TEXTHEIGHT;
	}

	if ( ! pDownload->IsSeeding() )
	{	// Not applicable for seeding torrents.
		pt.y += 2;
		DrawProgressBar( pDC, &pt, pDownload );
		pt.y += TIP_GAP;
	}

	if ( m_bDrawGraph )
	{	// Don't draw empty graph.
		CRect rc( pt.x, pt.y, m_sz.cx, pt.y + 40 );
		pDC->Draw3dRect( &rc, CoolInterface.m_crTipBorder, CoolInterface.m_crTipBorder );
		rc.DeflateRect( 1, 1 );
		m_pGraph->BufferedPaint( pDC, &rc );
		rc.InflateRect( 1, 1 );
		pDC->ExcludeClipRect( &rc );
		pt.y += 40;
	}
	pt.y += TIP_GAP;
}

void CDownloadTipCtrl::PrepareFileInfo(CDownload* pDownload)
{
	m_sName = pDownload->m_sDisplayName;
	m_sSize = Settings.SmartVolume( pDownload->m_nSize, FALSE );
	if ( pDownload->m_nSize == SIZE_UNKNOWN ) m_sSize = _T("?");

	m_sSHA1.Empty();
	m_sTiger.Empty();
	m_sED2K.Empty();
	m_sMD5.Empty();
	m_sBTH.Empty();
	m_sURL.Empty();
	
	if ( Settings.General.GUIMode != GUI_BASIC )
	{
		// We also report on if we have a hashset, and if hash is trusted (Debug mode only)
		CString strNoHashset, strUntrusted;
		LoadString( strNoHashset, IDS_TIP_NOHASHSET );
		LoadString( strUntrusted, IDS_TIP_UNTRUSTED );

		m_sSHA1 = pDownload->m_oSHA1.toShortUrn();
		if ( m_sSHA1.GetLength() )
		{
			if ( ! pDownload->m_oSHA1.isTrusted() )
			{
				m_sSHA1 += _T(" (") + strUntrusted + _T(")");
			}
		}

		m_sTiger = pDownload->m_oTiger.toShortUrn();
		if ( m_sTiger.GetLength() )
		{
			if ( ! pDownload->m_pTigerBlock )
			{
				if ( pDownload->m_oTiger.isTrusted() )
				{
					m_sTiger += _T(" (") + strNoHashset + _T(")");
				}
				else
				{
					m_sTiger += _T(" (") + strNoHashset + _T(", ") + strUntrusted + _T(")");
				}
			}
			else if ( ! pDownload->m_oTiger.isTrusted() )
			{
				m_sTiger += _T(" (") + strUntrusted + _T(")");
			}
		}

		m_sED2K = pDownload->m_oED2K.toShortUrn();
		if ( m_sED2K.GetLength() )
		{
			if ( ! pDownload->m_pHashsetBlock )
			{
				if ( pDownload->m_oED2K.isTrusted() )
				{
					m_sED2K += _T(" (") + strNoHashset + _T(")");
				}
				else
				{
					m_sED2K += _T(" (") + strNoHashset + _T(", ") + strUntrusted + _T(")");
				}
			}
			else if ( ! pDownload->m_oED2K.isTrusted() )
			{
				m_sED2K += _T(" (") + strUntrusted + _T(")");
			}
		}

		m_sMD5 = pDownload->m_oMD5.toShortUrn();
		if ( m_sMD5.GetLength() )
		{
			if ( ! pDownload->m_oMD5.isTrusted() )
			{
				m_sMD5 += _T(" (") + strUntrusted + _T(")");
			}
		}

		m_sBTH = pDownload->m_oBTH.toShortUrn();
		if ( m_sBTH.GetLength() )
		{
			if ( ! pDownload->m_pTorrentBlock )
			{
				if ( pDownload->m_oBTH.isTrusted() )
				{
					m_sBTH += _T(" (") + strNoHashset + _T(")");
				}
				else
				{
					m_sBTH += _T(" (") + strNoHashset + _T(", ") + strUntrusted + _T(")");
				}
			}
			else if ( ! pDownload->m_oBTH.isTrusted() )
			{
				m_sBTH += _T(" (") + strUntrusted + _T(")");
			}
		}

		if ( pDownload->m_oBTH )
			m_sURL = pDownload->m_pTorrent.m_sTracker;
	}

	int nPeriod = m_sName.ReverseFind( '.' );

	m_sType.Empty();
	m_nIcon = 0;

	if ( nPeriod > 0 )
	{
		CString strType = m_sName.Mid( nPeriod );
		CString strName, strMime;

		ShellIcons.Lookup( strType, NULL, NULL, &strName, &strMime );
		m_nIcon = ShellIcons.Get( strType, 32 );

		if ( strName.GetLength() )
		{
			m_sType = strName;
			if ( strMime.GetLength() ) m_sType += _T(" (") + strMime + _T(")");
		}
		else
		{
			m_sType = strType.Mid( 1 );
		}
	}

	if ( m_sType.IsEmpty() ) m_sType = _T("Unknown");
}

/////////////////////////////////////////////////////////////////////////////
// CDownloadTipCtrl source case

void CDownloadTipCtrl::OnCalcSize(CDC* pDC, CDownloadSource* pSource)
{
//	CDownload* pDownload = pSource->m_pDownload;

	if ( pSource->m_sNick.GetLength() > 0 )
	{
		m_sName = pSource->m_sNick;
		if ( ( pSource->m_nProtocol == PROTOCOL_ED2K ) && ( pSource->m_bPushOnly == TRUE ) )
		{
			m_sName.AppendFormat( _T(" (%lu@%s:%u)"), pSource->m_pAddress.S_un.S_addr, 
				(LPCTSTR)CString( inet_ntoa( (IN_ADDR&)pSource->m_pServerAddress) ), pSource->m_nServerPort );
		}
		else if ( pSource->m_bPushOnly )
		{
			m_sName.AppendFormat( _T(" (%s)"), (LPCTSTR)CString( inet_ntoa( (IN_ADDR&)pSource->m_pAddress ) ) );
		}
		else
		{
			m_sName.AppendFormat( _T(" (%s:%u)"), (LPCTSTR)CString( inet_ntoa( (IN_ADDR&)pSource->m_pAddress ) ), pSource->m_nPort );
		}
	}
	else
	{
		if ( ( pSource->m_nProtocol == PROTOCOL_ED2K ) && ( pSource->m_bPushOnly == TRUE ) )
		{
			m_sName.Format( _T("%lu@%s:%u"), (DWORD)pSource->m_pAddress.S_un.S_addr,
				(LPCTSTR)CString( inet_ntoa( (IN_ADDR&)pSource->m_pServerAddress) ), pSource->m_nServerPort );
		}
		else
		{
			m_sName = inet_ntoa( pSource->m_pAddress );
			m_sName.AppendFormat( _T(":%u"), pSource->m_nPort );
		}
	}

	if ( pSource->m_bPushOnly )
	{
		m_sName += _T(" (push)");
	}


	m_sURL = pSource->m_sURL;

	if ( m_sURL.GetLength() > 128 )
	{
		if ( LPCTSTR pszSlash = _tcschr( (LPCTSTR)m_sURL + 7, '/' ) )
		{
			int nFirst = static_cast< int >( pszSlash - (LPCTSTR)m_sSize );
			m_sURL = m_sURL.Left( nFirst + 1 ) + _T("...") + m_sURL.Right( 10 );
		}
	}

	m_pHeaderName.RemoveAll();
	m_pHeaderValue.RemoveAll();

	if ( pSource->m_pTransfer != NULL && Settings.General.GUIMode != GUI_BASIC )
	{
		for ( int nHeader = 0 ; nHeader < pSource->m_pTransfer->m_pHeaderName.GetSize() ; nHeader++ )
		{
			CString strName		= pSource->m_pTransfer->m_pHeaderName.GetAt( nHeader );
			CString strValue	= pSource->m_pTransfer->m_pHeaderValue.GetAt( nHeader );

			if ( strValue.GetLength() > 64 ) strValue = strValue.Left( 64 ) + _T("...");

			m_pHeaderName.Add( strName );
			m_pHeaderValue.Add( strValue );
		}
	}

	AddSize( pDC, m_sName );
	pDC->SelectObject( &CoolInterface.m_fntNormal );
	m_sz.cy += TIP_TEXTHEIGHT + TIP_RULE;

	AddSize( pDC, m_sURL, 80 );
	m_sz.cy += TIP_TEXTHEIGHT * 6;

	m_sz.cy += TIP_GAP;
	m_sz.cy += TIP_TEXTHEIGHT;
	m_sz.cy += TIP_GAP;
	m_sz.cy += 40;
	m_sz.cy += TIP_GAP;

	int nValueWidth = 0;
	m_nHeaderWidth = 0;

	for ( int nHeader = 0 ; nHeader < m_pHeaderName.GetSize() ; nHeader++ )
	{
		CString strName		= m_pHeaderName.GetAt( nHeader );
		CString strValue	= m_pHeaderValue.GetAt( nHeader );
		CSize szKey			= pDC->GetTextExtent( strName + ':' );
		CSize szValue		= pDC->GetTextExtent( strValue );

		m_nHeaderWidth		= max( m_nHeaderWidth, int(szKey.cx) );
		nValueWidth			= max( nValueWidth, int(szValue.cx) );

		m_sz.cy += TIP_TEXTHEIGHT;
	}

	if ( m_nHeaderWidth ) m_nHeaderWidth += TIP_GAP;
	m_sz.cx = max( m_sz.cx, m_nHeaderWidth + nValueWidth );
}

void CDownloadTipCtrl::OnPaint(CDC* pDC, CDownloadSource* pSource)
{
//	CDownload* pDownload = pSource->m_pDownload;
	CPoint pt( 0, 0 );

	DrawText( pDC, &pt, m_sName );
	pDC->SelectObject( &CoolInterface.m_fntNormal );
	pt.y += TIP_TEXTHEIGHT;

	DrawRule( pDC, &pt );

	CString strStatus, strSpeed, strText;

	if ( pSource->m_pTransfer != NULL )
	{
		DWORD nLimit = pSource->m_pTransfer->m_mInput.pLimit != NULL ?
			*pSource->m_pTransfer->m_mInput.pLimit : 0;

		strStatus = pSource->m_pTransfer->GetStateText( TRUE );

		if ( nLimit > 0 )
		{
			CString strOf;
			LoadString( strOf, IDS_GENERAL_OF );
			strSpeed.Format( _T("%s %s %s"),
				(LPCTSTR)Settings.SmartVolume( pSource->m_pTransfer->GetMeasuredSpeed() * 8, FALSE, TRUE ),
				strOf, (LPCTSTR)Settings.SmartVolume( nLimit * 8, FALSE, TRUE ) );
		}
		else
		{
			strSpeed = Settings.SmartVolume( pSource->m_pTransfer->GetMeasuredSpeed() * 8, FALSE, TRUE );
		}
	}
	else
	{
		LoadString( strStatus, IDS_TIP_INACTIVE );
		LoadString( strSpeed, IDS_TIP_NA );
	}

	LoadString( strText, IDS_TIP_STATUS );
	DrawText( pDC, &pt, strText );
	DrawText( pDC, &pt, strStatus, 80 );
	pt.y += TIP_TEXTHEIGHT;

	LoadString( strText, IDS_TIP_SPEED );
	DrawText( pDC, &pt, strText );
	DrawText( pDC, &pt, strSpeed, 80 );
	pt.y += TIP_TEXTHEIGHT;

	LoadString( strText, IDS_TIP_URL );
	DrawText( pDC, &pt, strText );
	DrawText( pDC, &pt, m_sURL, 80 );
	pt.y += TIP_TEXTHEIGHT;

	LoadString( strText, IDS_TIP_USERAGENT );
	DrawText( pDC, &pt, strText );
	DrawText( pDC, &pt, pSource->m_sServer, 80 );
	pt.y += TIP_TEXTHEIGHT;

	strText = "Connection:";
	DrawText( pDC, &pt, strText );
	if ( pSource->m_pTransfer )
	{
		switch( pSource->m_nProtocol )
		{
			case PROTOCOL_HTTP:
			case PROTOCOL_G1:
			case PROTOCOL_G2:
				if ( !pSource->m_pTransfer->m_bConnected )
					DrawText( pDC, &pt, _T("Not Connected"), 80 );
				else if ( pSource->m_pTransfer->m_bInitiated )
					DrawText( pDC, &pt, _T("Locally Initiated"), 80 );
				else
					DrawText( pDC, &pt, _T("Remotely Initiated"), 80 );
				break;

			case PROTOCOL_ED2K:
				{
					CDownloadTransferED2K* pTransfer = reinterpret_cast< CDownloadTransferED2K* >(pSource->m_pTransfer);
					if ( pTransfer != NULL && pTransfer->m_pClient != NULL && pTransfer->m_pClient->m_bConnected )
					{
						if ( pTransfer->m_pClient->m_bInitiated )
							DrawText( pDC, &pt, _T("Locally Initiated"), 80 );
						else
							DrawText( pDC, &pt, _T("Remotely Initiated"), 80 );
					}
					else
						DrawText( pDC, &pt, _T("Not connected"), 80 );
				}
				break;

			case PROTOCOL_BT:
				DrawText( pDC, &pt, _T("Unknown"), 80 );
				break;
			default:
				DrawText( pDC, &pt, _T("Unknown"), 80 );
				break;
		}
	}
	else
	{
		DrawText( pDC, &pt, _T("Not connected"), 80 );
	}
	pt.y += TIP_TEXTHEIGHT;


	strText = "GUID:";
	DrawText( pDC, &pt, strText );

	if (pSource->m_oGUID.isValid())
	{
		Hashes::Guid oID( pSource->m_oGUID );
		// Compose the X-MyGUID string, which is like "X-MyGUID: " with two newlines at the end (do)
		// MFC's CString::Format is like sprintf, "%.2X" formats a byte into 2 hexidecimal characters like "ff"
		strText.Format(	_T("%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X%.2X"),
			int( oID[0] ),  int( oID[1] ),  int( oID[2] ),  int( oID[3] ),		// Our GUID
			int( oID[4] ),  int( oID[5] ),  int( oID[6] ),  int( oID[7] ),
			int( oID[8] ),  int( oID[9] ),  int( oID[10] ), int( oID[11] ),
			int( oID[12] ), int( oID[13] ), int( oID[14] ), int( oID[15] ) );
	}
	else
	{
		strText = _T("Invalid GUID");
	}

	DrawText( pDC, &pt, strText, 80 );
	pt.y += TIP_TEXTHEIGHT;


	pt.y += TIP_GAP;

	DrawProgressBar( pDC, &pt, pSource );
	pt.y += TIP_GAP;

	CRect rc( pt.x, pt.y, m_sz.cx, pt.y + 40 );
	pDC->Draw3dRect( &rc, CoolInterface.m_crTipBorder, CoolInterface.m_crTipBorder );
	rc.DeflateRect( 1, 1 );
	m_pGraph->BufferedPaint( pDC, &rc );
	rc.InflateRect( 1, 1 );
	pDC->ExcludeClipRect( &rc );
	pt.y += 40;
	pt.y += TIP_GAP;

	for ( int nHeader = 0 ; nHeader < m_pHeaderName.GetSize() ; nHeader++ )
	{
		CString strName		= m_pHeaderName.GetAt( nHeader );
		CString strValue	= m_pHeaderValue.GetAt( nHeader );

		DrawText( pDC, &pt, strName + ':' );
		DrawText( pDC, &pt, strValue, m_nHeaderWidth );
		pt.y += TIP_TEXTHEIGHT;
	}
}

/////////////////////////////////////////////////////////////////////////////
// CDownloadTipCtrl progress case

void CDownloadTipCtrl::DrawProgressBar(CDC* pDC, CPoint* pPoint, CDownload* pDownload)
{
	CRect rcCell( pPoint->x, pPoint->y, m_sz.cx, pPoint->y + TIP_TEXTHEIGHT );
	pPoint->y += TIP_TEXTHEIGHT;

	pDC->Draw3dRect( &rcCell, CoolInterface.m_crTipBorder, CoolInterface.m_crTipBorder );
	rcCell.DeflateRect( 1, 1 );

	CFragmentBar::DrawDownload( pDC, &rcCell, pDownload, CoolInterface.m_crTipBack );

	rcCell.InflateRect( 1, 1 );
	pDC->ExcludeClipRect( &rcCell );
}

void CDownloadTipCtrl::DrawProgressBar(CDC* pDC, CPoint* pPoint, CDownloadSource* pSource)
{
	CRect rcCell( pPoint->x, pPoint->y, m_sz.cx, pPoint->y + TIP_TEXTHEIGHT );
	pPoint->y += TIP_TEXTHEIGHT;

	pDC->Draw3dRect( &rcCell, CoolInterface.m_crTipBorder, CoolInterface.m_crTipBorder );
	rcCell.DeflateRect( 1, 1 );

	CFragmentBar::DrawSource( pDC, &rcCell, pSource, CoolInterface.m_crTipBack );

	rcCell.InflateRect( 1, 1 );
	pDC->ExcludeClipRect( &rcCell );
}

/////////////////////////////////////////////////////////////////////////////
// CDownloadTipCtrl timer

void CDownloadTipCtrl::OnTimer(UINT_PTR nIDEvent)
{
	CCoolTipCtrl::OnTimer( nIDEvent );

	if ( m_pGraph == NULL ) return;

	CSingleLock pLock( &Transfers.m_pSection );
	if ( ! pLock.Lock( 10 ) ) return;

	if ( Downloads.Check( (CDownload*)m_pContext ) )
	{
		CDownload* pDownload = (CDownload*)m_pContext;
		DWORD nSpeed = pDownload->GetMeasuredSpeed() * 8;
		m_pItem->Add( nSpeed );
		m_pGraph->m_nUpdates++;
		m_pGraph->m_nMaximum = max( m_pGraph->m_nMaximum, nSpeed );
		Invalidate();
	}
	else if ( Downloads.Check( (CDownloadSource*)m_pContext ) )
	{
		CDownloadSource* pSource = (CDownloadSource*)m_pContext;

		if ( pSource->m_pTransfer )
		{
			DWORD nSpeed = pSource->m_pTransfer->GetMeasuredSpeed() * 8;
			m_pItem->Add( nSpeed );
			m_pGraph->m_nUpdates++;
			m_pGraph->m_nMaximum = max( m_pGraph->m_nMaximum, nSpeed );
			Invalidate();
		}
	}
}
