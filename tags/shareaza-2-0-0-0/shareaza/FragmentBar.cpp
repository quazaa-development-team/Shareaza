//
// FragmentBar.cpp
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
#include "CoolInterface.h"
#include "FragmentBar.h"

#include "Download.h"
#include "DownloadSource.h"
#include "DownloadTransfer.h"
#include "DownloadTransferHTTP.h"
#include "DownloadTransferED2K.h"
#include "DownloadTransferBT.h"
#include "UploadFile.h"
#include "UploadTransfer.h"
#include "UploadTransferHTTP.h"
#include "UploadTransferED2K.h"
#include "FragmentedFile.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif


//////////////////////////////////////////////////////////////////////
// CFragmentBar fragment

void CFragmentBar::DrawFragment(CDC* pDC, CRect* prcBar, QWORD nTotal, QWORD nOffset, QWORD nLength, COLORREF crFill, BOOL b3D)
{
	CRect rcArea;
	
	rcArea.left		= prcBar->left + (int)( (double)( prcBar->Width() + 1 ) / (double)nTotal * (double)nOffset );
	rcArea.right	= prcBar->left + (int)( (double)( prcBar->Width() + 1 ) / (double)nTotal * (double)( nOffset + nLength ) );
	
	rcArea.top		= prcBar->top;
	rcArea.bottom	= prcBar->bottom;
	
	rcArea.left		= max( rcArea.left, prcBar->left );
	rcArea.right	= min( rcArea.right, prcBar->right );
	
	if ( rcArea.right <= rcArea.left ) return;
	
	if ( b3D && rcArea.Width() > 2 )
	{
		pDC->Draw3dRect( &rcArea,	CCoolInterface::CalculateColour( crFill, RGB(255,255,255), 75 ),
									CCoolInterface::CalculateColour( crFill, RGB(0,0,0), 75 ) );
		
		rcArea.DeflateRect( 1, 1 );
		pDC->FillSolidRect( &rcArea, crFill );
		rcArea.InflateRect( 1, 1 );
	}
	else
	{
		pDC->FillSolidRect( &rcArea, crFill );
	}
	
	pDC->ExcludeClipRect( &rcArea );
}

//////////////////////////////////////////////////////////////////////
// CFragmentBar state bar

void CFragmentBar::DrawStateBar(CDC* pDC, CRect* prcBar, QWORD nTotal, QWORD nOffset, QWORD nLength, COLORREF crFill, BOOL bTop)
{
	CRect rcArea;
	
	rcArea.left		= prcBar->left + (int)( (double)( prcBar->Width() + 1 ) / (double)nTotal * (double)nOffset );
	rcArea.right	= prcBar->left + (int)( (double)( prcBar->Width() + 1 ) / (double)nTotal * (double)( nOffset + nLength ) );
	rcArea.left		= max( rcArea.left, prcBar->left );
	rcArea.right	= min( rcArea.right, prcBar->right );
	
	if ( bTop )
	{
		rcArea.top		= prcBar->top;
		rcArea.bottom	= min( ( prcBar->top + prcBar->bottom ) / 2, prcBar->top + 2 ) - 1;
	}
	else
	{
		rcArea.top		= max( ( prcBar->top + prcBar->bottom ) / 2, prcBar->bottom - 3 ) + 1;
		rcArea.bottom	= prcBar->bottom;
	}
	
	if ( rcArea.right <= rcArea.left ) return;
	
	if ( rcArea.Width() > 2 )
	{
		rcArea.DeflateRect( 1, 0 );
		pDC->FillSolidRect( &rcArea, crFill );
		rcArea.InflateRect( 1, 0 );
		
		pDC->FillSolidRect( rcArea.left, rcArea.top, 1, rcArea.Height(),
			CCoolInterface::CalculateColour( crFill, RGB(255,255,255), 100 ) );
		pDC->FillSolidRect( rcArea.right - 1, rcArea.top, 1, rcArea.Height(),
			CCoolInterface::CalculateColour( crFill, RGB(0,0,0), 75 ) );
	}
	else
	{
		pDC->FillSolidRect( &rcArea, crFill );
	}
	
	if ( bTop )
	{
		pDC->FillSolidRect( rcArea.left, rcArea.bottom, rcArea.Width(), 1,
			CCoolInterface::CalculateColour( crFill, RGB(0,0,0), 100 ) );
		rcArea.bottom ++;
	}
	else
	{
		rcArea.top --;
		pDC->FillSolidRect( rcArea.left, rcArea.top, rcArea.Width(), 1,
			CCoolInterface::CalculateColour( crFill, RGB(255,255,255), 100 ) );
	}
	
	pDC->ExcludeClipRect( &rcArea );
}

//////////////////////////////////////////////////////////////////////
// CFragmentBar download

void CFragmentBar::DrawDownload(CDC* pDC, CRect* prcBar, CDownload* pDownload, COLORREF crNatural)
{
	QWORD nvOffset, nvLength;
	BOOL bvSuccess;
	
	if ( Settings.Downloads.ShowPercent && pDownload->IsStarted() )
	{
		DrawStateBar( pDC, prcBar, pDownload->m_nSize, 0, pDownload->GetVolumeComplete(),
			RGB( 0, 255, 0 ), TRUE );
	}
	
	for ( nvOffset = 0 ; pDownload->GetNextVerifyRange( nvOffset, nvLength, bvSuccess ) ; )
	{
		DrawStateBar( pDC, prcBar, pDownload->m_nSize, nvOffset, nvLength,
			bvSuccess ? RGB( 0, 220, 0 ) : RGB( 220, 0, 0 ) );
		nvOffset += nvLength;
	}
	
	for ( CFileFragment* pFragment = pDownload->GetFirstEmptyFragment() ; pFragment ; )
	{
		DrawFragment( pDC, prcBar, pDownload->m_nSize,
			pFragment->m_nOffset, pFragment->m_nLength, crNatural, FALSE );
		pFragment = pFragment->m_pNext;
	}
	
	for ( CDownloadSource* pSource = pDownload->GetFirstSource() ; pSource ; pSource = pSource->m_pNext )
	{
		DrawSourceImpl( pDC, prcBar, pSource );
	}
	
	pDC->FillSolidRect( prcBar, pDownload->IsStarted() ?
		GetSysColor( COLOR_ACTIVECAPTION ) : crNatural );
}

//////////////////////////////////////////////////////////////////////
// CFragmentBar download source

void CFragmentBar::DrawSource(CDC* pDC, CRect* prcBar, CDownloadSource* pSource, COLORREF crNatural)
{
	CFileFragment* pRequested = NULL;
	
	if (	pSource->m_pTransfer != NULL &&
			pSource->m_pTransfer->m_nProtocol == PROTOCOL_ED2K )
	{
		CDownloadTransferED2K* pED2K = (CDownloadTransferED2K*)pSource->m_pTransfer;
		pRequested = pED2K->m_pRequested;
	}
	else if (	pSource->m_pTransfer != NULL &&
				pSource->m_pTransfer->m_nProtocol == PROTOCOL_BT )
	{
		CDownloadTransferBT* pBT = (CDownloadTransferBT*)pSource->m_pTransfer;
		pRequested = pBT->m_pRequested;
	}
	
	if ( pSource->m_pTransfer != NULL &&
		 pSource->m_pTransfer->m_nLength < SIZE_UNKNOWN )
	{
		DrawStateBar( pDC, prcBar, pSource->m_pDownload->m_nSize,
			pSource->m_pTransfer->m_nOffset, pSource->m_pTransfer->m_nLength,
			RGB( 255, 255, 0 ), TRUE );
	}

	for ( ; pRequested ; pRequested = pRequested->m_pNext )
	{
		DrawStateBar( pDC, prcBar, pSource->m_pDownload->m_nSize,
			pRequested->m_nOffset, pRequested->m_nLength, RGB( 255, 255, 0 ), TRUE );
	}
	
	DrawSourceImpl( pDC, prcBar, pSource );
	
	if ( pSource->m_pAvailable != NULL )
	{
		CFileFragment* pFragment = pSource->m_pAvailable;
		
		for ( ; pFragment ; pFragment = pFragment->m_pNext )
		{
			DrawFragment( pDC, prcBar, pSource->m_pDownload->m_nSize,
				pFragment->m_nOffset, pFragment->m_nLength, crNatural, FALSE );
		}
		
		pDC->FillSolidRect( prcBar, GetSysColor( COLOR_BTNFACE ) );
	}
	else
	{
		pDC->FillSolidRect( prcBar, crNatural );
	}
}

void CFragmentBar::DrawSourceImpl(CDC* pDC, CRect* prcBar, CDownloadSource* pSource)
{
	static COLORREF crFill[] =
	{
		RGB( 0, 153, 255 ), RGB( 0, 153, 0 ), RGB( 255, 51, 0 ),
		RGB( 255, 204, 0 ), RGB( 153, 153, 255 ), RGB( 204, 153, 0 )
	};
	
	COLORREF crTransfer;
	
	if ( pSource->m_bReadContent )
	{
		crTransfer = crFill[ pSource->GetColour() ];
	}
	else
	{
		crTransfer = GetSysColor( COLOR_ACTIVECAPTION );
	}
	
	crTransfer = CCoolInterface::CalculateColour( crTransfer, CoolInterface.m_crHighlight, 90 );
	
	if ( pSource->m_pTransfer != NULL )
	{
		if ( pSource->m_pTransfer->m_nState == dtsDownloading &&
			 pSource->m_pTransfer->m_nOffset < SIZE_UNKNOWN )
		{
			if ( pSource->m_pTransfer->m_bRecvBackwards )
			{
				DrawFragment( pDC, prcBar, pSource->m_pDownload->m_nSize,
					pSource->m_pTransfer->m_nOffset + pSource->m_pTransfer->m_nLength - pSource->m_pTransfer->m_nPosition,
					pSource->m_pTransfer->m_nPosition, crTransfer, TRUE );
			}
			else
			{
				DrawFragment( pDC, prcBar, pSource->m_pDownload->m_nSize,
					pSource->m_pTransfer->m_nOffset,
					pSource->m_pTransfer->m_nPosition, crTransfer, TRUE );
			}
		}
	}
	
	for ( CFileFragment* pFragment = pSource->m_pPastFragment ; pFragment ; )
	{
		DrawFragment( pDC, prcBar, pSource->m_pDownload->m_nSize,
			pFragment->m_nOffset, pFragment->m_nLength, crTransfer, TRUE );
		pFragment = pFragment->m_pNext;
	}
}

//////////////////////////////////////////////////////////////////////
// CFragmentBar upload

void CFragmentBar::DrawUpload(CDC* pDC, CRect* prcBar, CUploadFile* pFile, COLORREF crNatural)
{
	CUploadTransfer* pUpload = pFile->GetActive();
	if ( pUpload == NULL ) return;
	
	for ( CFileFragment* pFragment = pFile->m_pFragments ; pFragment ; pFragment = pFragment->m_pNext )
	{
		DrawFragment( pDC, prcBar, pFile->m_nSize, pFragment->m_nOffset,
			pFragment->m_nLength, GetSysColor( COLOR_ACTIVECAPTION ), TRUE );
	}
	
	if ( pFile == pUpload->m_pBaseFile )
	{
		if ( pUpload->m_nProtocol == PROTOCOL_HTTP && ((CUploadTransferHTTP*)pUpload)->IsBackwards() )
		{
			DrawFragment( pDC, prcBar, pFile->m_nSize,
				pUpload->m_nOffset + pUpload->m_nLength - pUpload->m_nPosition,
				pUpload->m_nPosition, GetSysColor( COLOR_ACTIVECAPTION ), TRUE );
			
			DrawFragment( pDC, prcBar, pFile->m_nSize,
				pUpload->m_nOffset,
				pUpload->m_nLength - pUpload->m_nPosition, crNatural, FALSE );
		}
		else
		{
			DrawFragment( pDC, prcBar, pFile->m_nSize,
				pUpload->m_nOffset, pUpload->m_nPosition,
				GetSysColor( COLOR_ACTIVECAPTION ), TRUE );
			
			DrawFragment( pDC, prcBar, pFile->m_nSize,
				pUpload->m_nOffset + pUpload->m_nPosition,
				pUpload->m_nLength - pUpload->m_nPosition, crNatural, FALSE );
		}
	}
	
	pDC->FillSolidRect( prcBar, ( pFile == pUpload->m_pBaseFile )
		? GetSysColor( COLOR_BTNFACE ) : crNatural );
}
