//
// Downloads.cpp
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
#include "Downloads.h"
#include "Download.h"
#include "Transfers.h"
#include "Transfer.h"
#include "DownloadGroups.h"
#include "DownloadTransfer.h"
#include "DownloadTransferED2K.h"
#include "DownloadTransferBT.h"
#include "UploadQueues.h"

#include "Buffer.h"
#include "EDClient.h"
#include "QueryHit.h"
#include "MatchObjects.h"
#include "ShareazaURL.h"

#include "SHA.h"
#include "ED2K.h"
#include "TigerTree.h"

#include "WndMain.h"

#include "XML.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

CDownloads Downloads;

//////////////////////////////////////////////////////////////////////
// CITMQueryHit construction

CDownloads::CITMQueryHit::CITMQueryHit()
{
	m_pHits = NULL;
}

CDownloads::CITMQueryHit::CITMQueryHit( CQueryHit * pHits )
{

	if ( pHits != NULL )
	{
		CQueryHit* tempHits1 = pHits;
		CQueryHit* tempHits2 = NULL;

		m_pHits = new CQueryHit( PROTOCOL_NULL );
		m_pHits->Copy(pHits);
		tempHits2 = m_pHits;
		tempHits1 = tempHits1->m_pNext;

		for (; tempHits1 != NULL ; tempHits1 = tempHits1->m_pNext )
		{
			tempHits2->m_pNext = new CQueryHit( PROTOCOL_NULL );
			tempHits2 = tempHits2->m_pNext;
			tempHits2->Copy( tempHits1 );
		}
	}
}

CDownloads::CITMQueryHit::~CITMQueryHit()
{
	m_pHits->Delete();
}

//////////////////////////////////////////////////////////////////////
// CITMQueryHit Function member implementations

CDownloads::CITMQueryHit* CDownloads::CITMQueryHit::CreateMessage( CQueryHit * pHits )
{
	CITMQueryHit* pITMHit = NULL;

	if ( pHits != NULL )
	{
		pITMHit = new CITMQueryHit();
		
		CQueryHit* tempHits1 = pHits;
		CQueryHit* tempHits2 = NULL;

		pITMHit->m_pHits = new CQueryHit( PROTOCOL_NULL );
		pITMHit->m_pHits->Copy(pHits);
		tempHits2 = pITMHit->m_pHits;
		tempHits1 = tempHits1->m_pNext;

		for (; tempHits1 != NULL ; tempHits1 = tempHits1->m_pNext )
		{
			tempHits2->m_pNext = new CQueryHit( PROTOCOL_NULL );
			tempHits2 = tempHits2->m_pNext;
			tempHits2->Copy( tempHits1 );
			if ( tempHits1->m_pXML == NULL && tempHits2->m_pXML != NULL ) tempHits1->m_pXML = tempHits2->m_pXML->Clone();
		}
	}

	return pITMHit;

	//return ( (CITMQueue::CITMItem *) new CITMQueryHit( CQueryHit * pHits ) );
}

BOOL CDownloads::CITMQueryHit::OnProcess()
{
	if ( m_pHits == NULL ) return TRUE;

	CTransfers::Lock oLock;
	for ( POSITION pos = Downloads.GetIterator() ; pos ; )
	{
		CDownload* pDownload = Downloads.GetNext( pos );
		pDownload->OnQueryHits( m_pHits );
	}	

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CITMQueryHit construction

CDownloads::CITMQueryHits::CITMQueryHits()
: m_oHits()
{
}

CDownloads::CITMQueryHits::CITMQueryHits(CHitPtrs& oHits)
{
	m_oHits.assign( oHits.begin(), oHits.end() );
}

CDownloads::CITMQueryHits::~CITMQueryHits()
{
}

//////////////////////////////////////////////////////////////////////
// CITMQueryHit Function member implementations

CDownloads::CITMQueryHits* CDownloads::CITMQueryHits::CreateMessage(CHitPtrs& oHits)
{
	CITMQueryHits* pITMHit = NULL;

	if ( oHits.size() )
	{
		pITMHit = new CITMQueryHits();
		pITMHit->m_oHits.assign( oHits.begin(), oHits.end() );
	}

	return pITMHit;

	//return ( (CITMQueue::CITMItem *) new CITMQueryHit( CQueryHit * pHits ) );
}

BOOL CDownloads::CITMQueryHits::OnProcess()
{
	CTransfers::Lock oLock;
	for ( POSITION pos = Downloads.GetIterator() ; pos ; )
	{
		CDownload* pDownload = Downloads.GetNext( pos );
		pDownload->OnQueryHits( m_oHits );
	}	

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CDownloads construction

CDownloads::CDownloads()
: m_oActiveSearches()
, m_oPendingSearches()
{
	m_nLimitGeneric			= Settings.Bandwidth.Downloads;
	m_nLimitDonkey			= Settings.Bandwidth.Downloads;
	m_nTransfers			= 0;
	m_nBandwidth			= 0;
	m_nRunCookie			= 0;
	m_bClosing				= FALSE;
	m_tLastConnect			= 0;

	m_tBandwidthLastCalc	= 0;
	m_tBandwidthAtMax		= 0;
	m_tBandwidthAtMaxED2K	= 0;

	m_nLimitNew				= Settings.Bandwidth.Downloads;
}

CDownloads::~CDownloads()
{
}

//////////////////////////////////////////////////////////////////////
// CDownloads add an empty download (privilaged)

CDownload* CDownloads::Add()
{
	CDownload* pDownload = new CDownload();
	m_pList.AddTail( pDownload );
	m_oPendingSearches.push_back( pDownload );
	return pDownload;
}

//////////////////////////////////////////////////////////////////////
// CDownloads add download from a hit or from a file

CDownload* CDownloads::Add(CQueryHit* pHit, BOOL bAddToHead)
{
	CSingleLock pLock( &Transfers.m_pSection, TRUE );
	
	CDownload* pDownload = NULL;
	
	
	if ( pHit->m_oSHA1 || pHit->m_oTiger || pHit->m_oED2K || pHit->m_oMD5 || pHit->m_oBTH )
		pDownload = FindByHash( pHit->m_oSHA1, pHit->m_oTiger, pHit->m_oED2K, pHit->m_oMD5, pHit->m_oBTH, FALSE );
	
/*	if ( pDownload == NULL && pHit->m_oSHA1 && pHit->m_oTiger )
		pDownload = FindByBitprint( pHit->m_oSHA1, pHit->m_oTiger );
	else if ( pDownload == NULL && pHit->m_oSHA1 )
		pDownload = FindBySHA1( pHit->m_oSHA1 );
	else if ( pDownload == NULL && pHit->m_oTiger )
		pDownload = FindByTiger( pHit->m_oTiger );
	else if ( pDownload == NULL && pHit->m_oED2K )
		pDownload = FindByED2K( pHit->m_oED2K ); */
	
	if ( pDownload != NULL )
	{
		theApp.Message( MSG_DOWNLOAD, IDS_DOWNLOAD_ALREADY, (LPCTSTR)pHit->m_sName );
		
		pDownload->AddSourceHit( pHit );
		pDownload->Resume();
	}
	else
	{
		pDownload = new CDownload();
		pDownload->AddSourceHit( pHit, TRUE );

		if ( bAddToHead ) m_pList.AddHead( pDownload );
		else m_pList.AddTail( pDownload );
		m_oPendingSearches.push_back( pDownload );
		theApp.Message( MSG_DOWNLOAD, IDS_DOWNLOAD_ADDED,
			(LPCTSTR)pDownload->GetDisplayName(), pDownload->GetSourceCount() );

        if ( pDownload->m_oSHA1 ) pDownload->m_oSHA1.signalTrusted();
        if ( pDownload->m_oED2K ) pDownload->m_oED2K.signalTrusted();
		if ( pDownload->m_oTiger ) pDownload->m_oTiger.signalTrusted();
		if ( pDownload->m_oMD5 ) pDownload->m_oMD5.signalTrusted();
		if ( pDownload->m_oBTH ) pDownload->m_oBTH.signalTrusted();
	}

	pHit->m_bDownload = TRUE;
	
	DownloadGroups.Link( pDownload );
	Transfers.StartThread();

	if ( ( GetTryingCount() <= Settings.Downloads.MaxFiles ) || ( bAddToHead ) )
	{
		pDownload->SetStartTimer();
	}
	
	
	return pDownload;
}

CDownload* CDownloads::Add(CMatchFile* pFile, BOOL bAddToHead)
{
	CSingleLock pLock( &Transfers.m_pSection, TRUE );
	
	CDownload* pDownload = NULL;
	Hashes::BtHash	oBTH;


	if ( pDownload == NULL && ( pFile->m_oSHA1 || pFile->m_oTiger || pFile->m_oED2K || pFile->m_oMD5 ) )
		pDownload = FindByHash( pFile->m_oSHA1, pFile->m_oTiger, pFile->m_oED2K, pFile->m_oMD5, oBTH, FALSE );
	
	/*if ( pDownload == NULL && pFile->m_oSHA1 && pFile->m_oTiger )
		pDownload = FindByBitprint( pFile->m_oSHA1, pFile->m_oTiger );
	else if ( pDownload == NULL && pFile->m_oSHA1 )
		pDownload = FindBySHA1( pFile->m_oSHA1 );
	else if ( pDownload == NULL && pFile->m_oTiger )
		pDownload = FindByTiger( pFile->m_oTiger );
	else if ( pDownload == NULL && pFile->m_oED2K )
		pDownload = FindByED2K( pFile->m_oED2K ); */
	
	if ( pDownload != NULL )
	{
		theApp.Message( MSG_DOWNLOAD, IDS_DOWNLOAD_ALREADY, (LPCTSTR)pFile->m_pHits->m_sName );
		
		for ( CQueryHit* pHit = pFile->m_pHits ; pHit ; pHit = pHit->m_pNext )
		{
			pDownload->AddSourceHit( pHit );

			// Send any reviews to the download, so they can be viewed later
			if ( pHit->m_nRating || ! pHit->m_sComments.IsEmpty() )
			{
				pDownload->AddReview( &pHit->m_pAddress, 2, pHit->m_nRating, pHit->m_sNick, pHit->m_sComments );
			}
		}
		
		pDownload->Resume();
	}
	else
	{
		pDownload = new CDownload();
		if ( bAddToHead ) m_pList.AddHead( pDownload );
		else m_pList.AddTail( pDownload );
		m_oPendingSearches.push_back( pDownload );
		if ( pFile->m_pBest != NULL )
		{
			pDownload->AddSourceHit( pFile->m_pBest, TRUE );
		}
		
		for ( CQueryHit* pHit = pFile->m_pHits ; pHit ; pHit = pHit->m_pNext )
		{
			if ( pHit != pFile->m_pBest )
			{
				pDownload->AddSourceHit( pHit, TRUE );
			}

			// Send any reviews to the download, so they can be viewed later
			if ( pHit->m_nRating || ! pHit->m_sComments.IsEmpty() )
			{
				pDownload->AddReview( &pHit->m_pAddress, 2, pHit->m_nRating, pHit->m_sNick, pHit->m_sComments );
			}
		}
		
		theApp.Message( MSG_DOWNLOAD, IDS_DOWNLOAD_ADDED,
			(LPCTSTR)pDownload->GetDisplayName(), pDownload->GetSourceCount() );

        //if ( pDownload->m_oSHA1 ) pDownload->m_oSHA1.signalTrusted();
        //else if ( pDownload->m_oED2K ) pDownload->m_oED2K.signalTrusted();

		// instead of doing like the above commented out codes. should mark all the Hashes at adding time.
		if ( pDownload->m_oSHA1 ) pDownload->m_oSHA1.signalTrusted();
		if ( pDownload->m_oTiger ) pDownload->m_oTiger.signalTrusted();
        if ( pDownload->m_oED2K ) pDownload->m_oED2K.signalTrusted();
		if ( pDownload->m_oMD5 ) pDownload->m_oMD5.signalTrusted();
	}
	
	pFile->m_bDownload = TRUE;
	
	DownloadGroups.Link( pDownload );
	Transfers.StartThread();
	
	if ( ( GetTryingCount() < Settings.Downloads.MaxFiles ) || ( bAddToHead ) )
	{
		pDownload->SetStartTimer();

		if ( (pDownload->GetSourceCount( TRUE ) <= Settings.Downloads.MinSources ) &&
			( pDownload->m_oED2K || pDownload->m_oSHA1 ) )
		{
			//pDownload->FindMoreSources();
		}
	}
	
	return pDownload;
}

//////////////////////////////////////////////////////////////////////
// CDownloads add download from a URL

CDownload* CDownloads::Add(CShareazaURL* pURL)
{
	if ( pURL->m_nAction != CShareazaURL::uriDownload &&
		 pURL->m_nAction != CShareazaURL::uriSource ) return NULL;

	CSingleLock pLock( &Transfers.m_pSection, TRUE );
	CDownload* pDownload = NULL;

	if ( pDownload == NULL && ( pURL->m_oSHA1 || pURL->m_oTiger || pURL->m_oED2K || pURL->m_oMD5 || pURL->m_oBTH ) )
		pDownload = FindByHash( pURL->m_oSHA1, pURL->m_oTiger, pURL->m_oED2K,  pURL->m_oMD5, pURL->m_oBTH, FALSE );

/*	if ( pDownload == NULL && pURL->m_oSHA1 )
		pDownload = FindBySHA1( pURL->m_oSHA1 );
	if ( pDownload == NULL && pURL->m_oTiger )
		pDownload = FindByTiger( pURL->m_oTiger );
	if ( pDownload == NULL && pURL->m_oED2K )
		pDownload = FindByED2K( pURL->m_oED2K );
	if ( pDownload == NULL && pURL->m_oBTH )
		pDownload = FindByBTH( pURL->m_oBTH ); */

	if ( pDownload != NULL )
	{
		theApp.Message( MSG_DOWNLOAD, IDS_DOWNLOAD_ALREADY,
			(LPCTSTR)pDownload->GetDisplayName() );
		
		if ( pURL->m_sURL.GetLength() ) pDownload->AddSourceURLs( pURL->m_sURL, FALSE );
		
		return pDownload;
	}

	pDownload = new CDownload();

	if ( pURL->m_oSHA1 )
	{
		pDownload->m_oSHA1			= pURL->m_oSHA1;
        pDownload->m_oSHA1.signalTrusted();
	}
	if ( pURL->m_oTiger )
	{
		pDownload->m_oTiger			= pURL->m_oTiger;
        pDownload->m_oTiger.signalTrusted();
	}
    if ( pURL->m_oMD5 )
	{
		pDownload->m_oMD5			= pURL->m_oMD5;
        pDownload->m_oMD5.signalTrusted();
	}
	if ( pURL->m_oED2K )
	{
		pDownload->m_oED2K			= pURL->m_oED2K;
        pDownload->m_oED2K.signalTrusted();
		//pDownload->Share( TRUE );
	}
	if ( pURL->m_oBTH )
	{
		pDownload->m_oBTH			= pURL->m_oBTH;
		pDownload->m_oBTH.signalTrusted();
		//pDownload->Share( TRUE );
	}

	if ( pURL->m_sName.GetLength() )
	{
		pDownload->m_sDisplayName = pURL->m_sName;
	}

	if ( pURL->m_bSize )
	{
		pDownload->m_nSize = pURL->m_nSize;
	}

	if ( pURL->m_sURL.GetLength() )
	{
		if ( ! pDownload->AddSourceURLs( pURL->m_sURL, FALSE ) )
		{
			if ( pURL->m_nAction == CShareazaURL::uriSource )
			{
				delete pDownload;
				return NULL;
			}
		}
	}

	// Add sources from torrents - DWK
	pDownload->SetTorrent( pURL->m_pTorrent );
	if ( pURL->m_pTorrent && pURL->m_pTorrent->m_sURLs.GetCount() > 0 )
	{
		for ( POSITION pos = pURL->m_pTorrent->m_sURLs.GetHeadPosition() ; pos ; )
		{
			CString pCurrentUrl = pURL->m_pTorrent->m_sURLs.GetNext( pos );
			pDownload->AddSourceURLs( (LPCTSTR)pCurrentUrl, FALSE  );
		}
		pURL->m_pTorrent->m_sURLs.RemoveAll();
	}

	m_pList.AddTail( pDownload );
	m_oPendingSearches.push_back( pDownload );

	theApp.Message( MSG_DOWNLOAD, IDS_DOWNLOAD_ADDED,
		(LPCTSTR)pDownload->GetDisplayName(), pDownload->GetEffectiveSourceCount() );

	if ( (  pDownload->m_oBTH && ( GetTryingCount(TRUE)  < Settings.BitTorrent.DownloadTorrents ) ) ||
		 ( !pDownload->m_oBTH && ( GetTryingCount(FALSE) < Settings.Downloads.MaxFiles ) ) )
	{
		pDownload->SetStartTimer();
		//if ( pDownload->GetEffectiveSourceCount() <= 1 ) 
		//	pDownload->FindMoreSources();
	}

	DownloadGroups.Link( pDownload );
	Transfers.StartThread();

	return pDownload;
}

//////////////////////////////////////////////////////////////////////
// CDownloads commands

void CDownloads::PauseAll()
{
	CSingleLock pLock( &Transfers.m_pSection, TRUE );
	
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		GetNext( pos )->Pause( FALSE );
	}
}

void CDownloads::ClearCompleted()
{
	CSingleLock pLock( &Transfers.m_pSection, TRUE );
	
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		CDownload* pDownload = GetNext( pos );
		if ( ( pDownload->IsCompleted() ) && ( !pDownload->IsSeeding() ) ) pDownload->Remove();
	}
}

void CDownloads::ClearPaused()
{
	CSingleLock pLock( &Transfers.m_pSection, TRUE );

	for ( POSITION pos = GetIterator() ; pos ; )
	{
		CDownload* pDownload = GetNext( pos );
		if ( pDownload->IsPaused() ) pDownload->Remove();
	}
}

void CDownloads::Clear(BOOL bShutdown)
{
	CSingleLock pLock( &Transfers.m_pSection, TRUE );
	m_bClosing = TRUE;
	
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		Remove( GetNext( pos ) );
	}
	
	m_pList.RemoveAll();
	m_bClosing = bShutdown;
}

void CDownloads::CloseTransfers()
{
	CSingleLock pLock( &Transfers.m_pSection, TRUE );
	
	m_bClosing = TRUE;
	
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		GetNext( pos )->CloseTransfers();
	}
	
	m_bClosing = FALSE;
	m_nTransfers = 0;
	m_nBandwidth = 0;
}

//////////////////////////////////////////////////////////////////////
// CDownloads list access

int CDownloads::GetSeedCount() const
{
	int nCount = 0;
	
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		CDownload* pDownload = GetNext( pos );
		
		if ( pDownload->IsSeeding() )
			nCount++;		//Manually seeded Torrent
		else if ( pDownload->IsCompleted() && pDownload->m_oBTH && pDownload->IsFullyVerified() )
			nCount++;		//Torrent that has completed
	}
	
	return nCount;
}

int CDownloads::GetActiveTorrentCount() const
{
	int nCount = 0;
	
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		CDownload* pDownload = GetNext( pos );
		
		if ( pDownload->IsDownloading() && pDownload->m_oBTH &&
			! pDownload->IsSeeding()	&& ! pDownload->IsCompleted() &&
			! pDownload->IsMoving()		&& ! pDownload->IsPaused() )
				nCount++;
	}
	
	return nCount;
}

INT_PTR CDownloads::GetCount(BOOL bActiveOnly) const
{
	if ( ! bActiveOnly ) return m_pList.GetCount();
	
	INT_PTR nCount = 0;
	
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		CDownload* pDownload = GetNext( pos );
		
		if ( ! pDownload->IsMoving() && ! pDownload->IsPaused() &&
			 pDownload->GetEffectiveSourceCount() > 0 )
				nCount++;
	}
	
	return nCount;
}

int CDownloads::GetTransferCount() const
{
	int nCount = 0;
	
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		nCount += GetNext( pos )->GetTransferCount();
	}
	
	return nCount;
}

int CDownloads::GetTryingCount(BOOL bTorrentsOnly) const
{
	int nCount = 0;
	
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		CDownload* pDownload = GetNext( pos );
		
		if ( ( pDownload->IsTrying() ) && ( ! pDownload->IsCompleted() ) && ( ! pDownload->IsPaused() ) )
		{
			if ( ( pDownload->m_oBTH ) || ( ! bTorrentsOnly ) )
				nCount++;
		}
	}
	
	return nCount;
}

int CDownloads::GetConnectingTransferCount() const
{
	int nCount = 0;
	
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		CDownload* pDownload = GetNext( pos );
		
		nCount += pDownload->GetTransferCount( dtsConnecting );
	}
	
	return nCount;
}

void CDownloads::Remove(CDownload* pDownload)
{
	POSITION pos = m_pList.Find( pDownload );
	if ( pos != NULL ) m_pList.RemoveAt( pos );
	delete pDownload;
}

//////////////////////////////////////////////////////////////////////
// CDownloads find by pointer or hash

BOOL CDownloads::Check(CDownloadSource* pSource) const
{
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		if ( GetNext( pos )->CheckSource( pSource ) ) return TRUE;
	}
	return FALSE;
}

BOOL CDownloads::CheckActive(CDownload* pDownload, int nScope) const
{
	for ( POSITION pos = GetReverseIterator() ; pos && nScope > 0 ; )
	{
		CDownload* pTest = GetPrevious( pos );
		BOOL bActive = pTest->IsPaused() == FALSE && pTest->IsCompleted() == FALSE;
		
		if ( pDownload == pTest ) return bActive;
		if ( bActive ) nScope--;
	}
	
	return FALSE;
}

CDownload* CDownloads::FindByURN(LPCTSTR pszURN, BOOL bSharedOnly) const
{
	CDownload* pDownload;
    Hashes::TigerHash oTiger;
    Hashes::Sha1Hash oSHA1;
	Hashes::Ed2kHash oED2K;
	Hashes::Md5Hash oMD5;
	
	if ( oSHA1.fromUrn( pszURN ) && oTiger.fromUrn( pszURN ) )
	{
		if ( ( pDownload = FindByBitprint( oSHA1, oTiger, bSharedOnly ) ) != NULL ) return pDownload;
	}
	else
	{
		if ( oSHA1.fromUrn( pszURN ) )
		{
			if ( ( pDownload = FindBySHA1( oSHA1, bSharedOnly ) ) != NULL ) return pDownload;
		}

		if ( oTiger.fromUrn( pszURN ) )
		{
			if ( ( pDownload = FindByTiger( oTiger, bSharedOnly ) ) != NULL ) return pDownload;
		}
	}
	
	if ( oED2K.fromUrn( pszURN ) )
	{
		if ( ( pDownload = FindByED2K( oED2K, bSharedOnly, FALSE ) ) != NULL ) return pDownload;
	}

	if ( oMD5.fromUrn( pszURN ) )
	{
		if ( ( pDownload = FindByMD5( oMD5, bSharedOnly ) ) != NULL ) return pDownload;
	}

	return NULL;
}

CDownload* CDownloads::FindByHash(const Hashes::Sha1Hash& oSHA1, const Hashes::TigerHash& oTiger,
								  const Hashes::Ed2kHash& oED2K, const Hashes::Md5Hash& oMD5,
								  const Hashes::BtHash& oBTH, QWORD nMinSize,
								  QWORD nMaxSize, BOOL bSharedOnly) const
{
	if ( !oSHA1 && !oTiger && !oED2K && !oMD5 && !oBTH ) return NULL;

	bool bMinSize = !(nMinSize == SIZE_UNKNOWN) && !(nMinSize == 0);
	bool bMaxSize = !(nMaxSize == SIZE_UNKNOWN) && !(nMaxSize == 0);

	for ( POSITION pos = GetIterator() ; pos ; )
	{
		CDownload* pDownload = GetNext( pos );
		if ( ( ( pDownload->m_oSHA1 && oSHA1) ||
				( pDownload->m_oTiger && oTiger) ||
				( pDownload->m_oED2K && oED2K) ||
				( pDownload->m_oMD5 && oMD5) ||
				( pDownload->m_oBTH && oBTH ) ) &&
				( !validAndUnequal( pDownload->m_oSHA1, oSHA1 ) ) && 
				( !validAndUnequal( pDownload->m_oTiger, oTiger ) ) &&
				( !validAndUnequal( pDownload->m_oED2K, oED2K ) ) &&
				( !validAndUnequal( pDownload->m_oMD5, oMD5 ) ) &&
				( !validAndUnequal( pDownload->m_oBTH, oBTH ) ) )
		{
			if ( !pDownload->IsMoving() && ( !bSharedOnly || pDownload->IsShared() ) )
				if ( ( !bMinSize && !bMaxSize ) || 
					( !bMaxSize && nMinSize <= pDownload->m_nSize ) || 
					( !bMinSize && nMaxSize >= pDownload->m_nSize ) || 
					( nMinSize <= pDownload->m_nSize && nMaxSize >= pDownload->m_nSize ) )
				return pDownload;
		}
	}

	return NULL;
}

CDownload* CDownloads::FindByBitprint(const Hashes::Sha1Hash& oSHA1, const Hashes::TigerHash& oTiger, 
									  BOOL bSharedOnly) const
{
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		CDownload* pDownload = GetNext( pos );
		if ( ( pDownload->m_oSHA1 || pDownload->m_oTiger ) && 
			( !pDownload->m_oSHA1 || validAndEqual( pDownload->m_oSHA1, oSHA1 ) ) && 
			( !pDownload->m_oTiger || validAndEqual( pDownload->m_oTiger, oTiger ) ) )
		{
			if ( !pDownload->IsMoving() && ( !bSharedOnly || pDownload->IsShared() ) )
				return pDownload;
		}
	}

	return NULL;
}

CDownload* CDownloads::FindBySHA1(const Hashes::Sha1Hash& oSHA1, BOOL bSharedOnly) const
{
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		CDownload* pDownload = GetNext( pos );
		if ( validAndEqual( pDownload->m_oSHA1, oSHA1 ) )
		{
			if ( !pDownload->IsMoving() && ( !bSharedOnly || pDownload->IsShared() ) )
				return pDownload;
		}
	}
	
	return NULL;
}

CDownload* CDownloads::FindByTiger(const Hashes::TigerHash& oTiger, BOOL bSharedOnly) const
{
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		CDownload* pDownload = GetNext( pos );
		if ( validAndEqual( pDownload->m_oTiger, oTiger ) )
		{
			if ( !pDownload->IsMoving() && ( !bSharedOnly || pDownload->IsShared() ) )
				return pDownload;
		}
	}
	
	return NULL;
}

CDownload* CDownloads::FindByED2K(const Hashes::Ed2kHash& oED2K, BOOL bSharedOnly, BOOL bForceStarted) const
{
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		CDownload* pDownload = GetNext( pos );
		if ( validAndEqual( pDownload->m_oED2K, oED2K ) )
		{
			if ( !pDownload->IsMoving() && ( !bSharedOnly || pDownload->IsShared() ||
				( !pDownload->IsPaused() && bForceStarted )
				&& ( pDownload->m_nSize > ED2K_PART_SIZE || pDownload->IsCompleted() ) ) )
				return pDownload;
		}
	}

	return NULL;
}

CDownload* CDownloads::FindByMD5(const Hashes::Md5Hash& oMD5, BOOL bSharedOnly) const
{
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		CDownload* pDownload = GetNext( pos );
		if ( validAndEqual( pDownload->m_oMD5, oMD5 ) )
		{
			if ( !pDownload->IsMoving() && ( !bSharedOnly || pDownload->IsShared() ) )
				return pDownload;
		}
	}

	return NULL;
}

CDownload* CDownloads::FindByBTH(const Hashes::BtHash& oBTH, BOOL bSharedOnly, BOOL bForceStarted) const
{
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		CDownload* pDownload = GetNext( pos );
		if ( validAndEqual( pDownload->m_oBTH, oBTH ) )
		{
			if ( !pDownload->IsMoving() && ( ! bSharedOnly || pDownload->IsShared() ||
				( ( !pDownload->IsPaused() || pDownload->IsSeeding() ) && bForceStarted ) ) )
				return pDownload;
		}
	}
	
	return NULL;
}


//////////////////////////////////////////////////////////////////////
// CDownloads serialization ID

CDownload* CDownloads::FindBySID(DWORD nSerID) const
{
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		CDownload* pDownload = GetNext( pos );
		if ( pDownload->m_nSerID == nSerID ) return pDownload;
	}
	
	return NULL;
}

DWORD CDownloads::GetFreeSID()
{
	for ( ;; )
	{
		DWORD nSerID	= ( rand() & 0xFF ) + ( ( rand() & 0xFF ) << 8 )
						+ ( ( rand() & 0xFF ) << 16 ) + ( ( rand() & 0xFF ) << 24 );
		
		for ( POSITION pos = GetIterator() ; pos ; )
		{
			CDownload* pDownload = GetNext( pos );
			if ( pDownload->m_nSerID == nSerID ) { nSerID = 0; break; }
		}
		
		if ( nSerID ) return nSerID;
	}
	
//	ASSERT( FALSE );
//	return 0;
}

//////////////////////////////////////////////////////////////////////
// CDownloads ordering

BOOL CDownloads::Move(CDownload* pDownload, int nDelta)
{
	CSingleLock pLock( &Transfers.m_pSection, TRUE );
	
	POSITION posMe = m_pList.Find( pDownload );
	if ( posMe == NULL ) return FALSE;
	
	POSITION posOther = posMe;
	
	if ( nDelta < 0 )
		m_pList.GetPrev( posOther );
	else
		m_pList.GetNext( posOther );
	
	if ( posOther == NULL) return FALSE;
	
	if ( nDelta < 0 )
		m_pList.InsertBefore( posOther, pDownload );
	else
		m_pList.InsertAfter( posOther, pDownload );
	m_pList.RemoveAt( posMe );
	
	DownloadGroups.IncBaseCookie();
	
	return TRUE;
}

BOOL CDownloads::Swap(CDownload* p1, CDownload*p2)
{
	CSingleLock pLock( &Transfers.m_pSection, TRUE );
	
	POSITION pos1 = m_pList.Find( p1 );
	if (pos1 == NULL) return FALSE;
	
	POSITION pos2 = m_pList.Find( p2 );	
	if (pos2 == NULL) return FALSE;
	
	m_pList.InsertAfter(pos2, p1 );
	m_pList.RemoveAt( pos2);	
	m_pList.InsertAfter(pos1, p2 );
	m_pList.RemoveAt( pos1 );	
	return TRUE;
}

BOOL CDownloads::Reorder(CDownload* pDownload, CDownload* pBefore)
{
	CSingleLock pLock( &Transfers.m_pSection, TRUE );
	
	POSITION pos1 = m_pList.Find( pDownload );
	if ( pos1 == NULL ) return FALSE;
	
	if ( pBefore != NULL )
	{
		POSITION pos2 = m_pList.Find( pBefore );
		if ( pos2 == NULL || pos1 == pos2 ) return FALSE;
		m_pList.RemoveAt( pos1 );
		m_pList.InsertBefore( pos2, pDownload );
	}
	else
	{
		m_pList.RemoveAt( pos1 );
		m_pList.AddTail( pDownload );
	}
	
	DownloadGroups.IncBaseCookie();
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CDownloads find amount downloaded from a user

QWORD CDownloads::GetAmountDownloadedFrom(IN_ADDR* pAddress)
{
	QWORD nTotal = 0;

	if ( pAddress == NULL ) return 0;

	for ( POSITION pos = GetIterator() ; pos ; )
	{
		CDownload* pDownload = GetNext( pos );

		nTotal += pDownload->GetAmountDownloadedFrom(pAddress);
	}
	return nTotal;
}

//////////////////////////////////////////////////////////////////////
// CDownloads bandwidth

DWORD CDownloads::GetBandwidth() const
{
	DWORD nTotal = 0;
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		nTotal += GetNext( pos )->GetMeasuredSpeed();
	}
	return nTotal;
}

//////////////////////////////////////////////////////////////////////
// CDownloads limiting tests

void CDownloads::UpdateAllows(BOOL bNew)
{
	int nDownloads	= 0;
	int nTransfers	= 0;
	
	if ( bNew ) m_tLastConnect = GetTickCount();
	
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		CDownload* pDownload = GetNext( pos );
		int nTemp = pDownload->GetTransferCount();
		
		if ( nTemp )
		{
			nDownloads ++;
			nTransfers += nTemp;
		}
	}
	
	m_bAllowMoreDownloads = nDownloads < Settings.Downloads.MaxFiles;
	m_bAllowMoreTransfers = nTransfers < Settings.Downloads.MaxTransfers;
}

BOOL CDownloads::AllowMoreDownloads() const
{
	int nCount = 0;

	for ( POSITION pos = GetIterator() ; pos ; )
	{
		if ( GetNext( pos )->GetTransferCount() ) nCount++;
	}
	
	return nCount < Settings.Downloads.MaxFiles;
}

BOOL CDownloads::AllowMoreTransfers(IN_ADDR* pAddress) const
{
	int nCount = 0, nLimit = 0;
	
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		nCount += GetNext( pos )->GetTransferCount( dtsCountAll, pAddress );
	}
	
	if ( pAddress == NULL ) return nCount < Settings.Downloads.MaxTransfers;
	
	if ( m_pHostLimits.Lookup( pAddress->S_un.S_addr, nLimit ) )
	{
		return ( nCount < nLimit );
	}
	else
	{
		return ( nCount == 0 );
	}
}

void CDownloads::SetPerHostLimit(IN_ADDR* pAddress, int nLimit)
{
	m_pHostLimits.SetAt( pAddress->S_un.S_addr, nLimit );
}

//////////////////////////////////////////////////////////////////////
// CDownloads disk space helper

BOOL CDownloads::IsSpaceAvailable(QWORD nVolume, int nPath)
{
	QWORD nMargin = 10485760;
	
	if ( HINSTANCE hKernel = GetModuleHandle( _T("KERNEL32.DLL") ) )
	{
		 BOOL (WINAPI *pfnGetDiskFreeSpaceEx)(LPCTSTR, PULARGE_INTEGER, PULARGE_INTEGER, PULARGE_INTEGER); 
#ifdef UNICODE
		(FARPROC&)pfnGetDiskFreeSpaceEx = GetProcAddress( hKernel, "GetDiskFreeSpaceExW" );
#else
 		(FARPROC&)pfnGetDiskFreeSpaceEx = GetProcAddress( hKernel, "GetDiskFreeSpaceExA" );
#endif	
		if ( pfnGetDiskFreeSpaceEx != NULL )
		{
			ULARGE_INTEGER nFree, nNull;
			
			if ( ( ! nPath || nPath == dlPathIncomplete ) && (*pfnGetDiskFreeSpaceEx)( Settings.Downloads.IncompletePath, &nFree, &nNull, &nNull ) )
			{
				if ( nFree.QuadPart < nVolume + nMargin ) return FALSE;
			}

			if ( ( ! nPath || nPath == dlPathComplete ) && (*pfnGetDiskFreeSpaceEx)( Settings.Downloads.CompletePath, &nFree, &nNull, &nNull ) )
			{
				if ( nFree.QuadPart < nVolume + nMargin ) return FALSE;
			}

			return TRUE;
		}
	}

	DWORD nSPC, nBPS, nFree, nTotal;
	if ( ! nPath || nPath == dlPathIncomplete )
	{
		CString str = Settings.Downloads.IncompletePath.SpanExcluding( _T("\\") ) + '\\';
	
		if ( GetDiskFreeSpace( str, &nSPC, &nBPS, &nFree, &nTotal ) )
		{
			QWORD nBytes = (QWORD)nSPC * (QWORD)nBPS * (QWORD)nFree;
			if ( nBytes < nVolume + nMargin ) return FALSE;
		}
	}

	if ( ! nPath || nPath == dlPathComplete )
	{
		CString str = Settings.Downloads.CompletePath.SpanExcluding( _T("\\") ) + '\\';
	
		if ( GetDiskFreeSpace( str, &nSPC, &nBPS, &nFree, &nTotal ) )
		{
			QWORD nBytes = (QWORD)nSPC * (QWORD)nBPS * (QWORD)nFree;
			if ( nBytes < nVolume + nMargin ) return FALSE;
		}
	}

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CDownloads run callback (threaded)

void CDownloads::OnRun()
{
	DWORD tNow = GetTickCount();

	if ( (DWORD)m_oActiveSearches.size() < (DWORD)Settings.Downloads.MaxFileSearches )
	{
		if ( m_oPendingSearches.size() )
		{
			std::list<CDownload*>::iterator iIndex = m_oPendingSearches.begin();
			CDownload* pDownload = *iIndex;
			if ( pDownload->CanSearch() )
			{
				m_oPendingSearches.erase(iIndex);
				pDownload->StartAutomaticSearch(tNow);
			}
			else
			{
				m_oPendingSearches.erase(iIndex);
				m_oPendingSearches.push_back(pDownload);
			}
		}
	}

	// Re-calculating bandwidth may be a little CPU heavy if there are a lot of transfers- limit
	// it to 4 times per second
	if ( ( ( tNow - m_tBandwidthLastCalc ) < 250 ) && ( tNow > m_tBandwidthLastCalc ) )
	{
		// Just run the downloads, don't bother re-calulating bandwidth
		CTransfers::Lock oLock;

		m_nValidation = 0;
		++m_nRunCookie;
			
		for ( POSITION pos = GetIterator(); pos; )
		{
			CDownload* pDownload = GetNext( pos );
			pDownload->m_nRunCookie = m_nRunCookie;
			pDownload->OnRun();
		}
	}
	else
	{
		// Run downloads, update bandwidth settings and allows
		m_tBandwidthLastCalc = tNow;

		DWORD nActiveDownloads		= 0;	// Number of downloads that are doing something
		DWORD nActiveTransfers		= 0;	// Number of transfers that are in the downloading state
		DWORD nTotalTransfers		= 0;	// Total transfers
		DWORD nTotalBandwidth		= 0;	// Total bandwidth in use
		DWORD nRunningTransfers		= 0;	// Number of transfers that are downloading and transfering data
		DWORD nRunningTransfersED2K	= 0;	// Number of ed2k transfers that are downloading and transfering data
		DWORD nTotalBandwidthED2K	= 0;	// Total ed2k bandwidth in use.

		DWORD nBandwidthAvailable	= Settings.Bandwidth.Downloads;
		DWORD nBandwidthAvailableED2K = 0;
		BOOL bDonkeyRatioActive		= FALSE;

		{	// Lock transfers section
			CTransfers::Lock oLock;
			CList<CDownloadTransfer*> pTransfersToLimit;
			m_nValidation = 0;
			++m_nRunCookie;
				
			// Run all the downloads, select the transfers that need bandwidth limiting
			for ( POSITION pos = GetIterator(); pos; )
			{
				CDownload* pDownload = GetNext( pos );
				pDownload->m_nRunCookie = m_nRunCookie;
				pDownload->OnRun();
					
				int nTemp = 0;
					
				for ( CDownloadTransfer* pTransfer = pDownload->GetFirstTransfer() ; pTransfer ; pTransfer = pTransfer->m_pDlNext )
				{
					if ( pTransfer->m_nProtocol == PROTOCOL_ED2K )					
					{
						CDownloadTransferED2K* pED2K = (CDownloadTransferED2K*)pTransfer;
						if ( pED2K->m_pClient == NULL || pED2K->m_pClient->m_bConnected == FALSE ) continue;
						if ( pTransfer->m_nState == dtsQueued ) continue;
					}
					else if ( pTransfer->m_nProtocol == PROTOCOL_BT )
					{						
						CDownloadTransferBT* pBT = (CDownloadTransferBT*)pTransfer;
						if ( pBT->m_nState == dtsTorrent && pBT->m_bChoked ) continue;
					}
						
					nTemp ++;
						
					if ( pTransfer->m_nState == dtsDownloading )
					{
						DWORD nSpeed = pTransfer->GetMeasuredSpeed();
						nTotalBandwidth += nSpeed;
						nActiveTransfers ++;
						if ( nSpeed > 32 ) 
						{
							nRunningTransfers ++; 
							pTransfersToLimit.AddTail( pTransfer );
							if ( pTransfer->m_nProtocol == PROTOCOL_ED2K ) 
							{
								nTotalBandwidthED2K += nSpeed;
								nRunningTransfersED2K ++;
							}
							// Limit will be set below, once all data is collected
						}
						else
						{
							// This download is 'stalled'. It's probably not going to transfer 
							// anything, so we don't want to reserve bandwidth for it.
							pTransfer->m_nBandwidth = 0;
							// Don't bother limiting. If it starts to transfer then it
							// will be limited properly. For now, ignore since it's inactive.
						}
					}
				}
					
				if ( nTemp )
				{
					nActiveDownloads ++;
					nTotalTransfers += nTemp;
				}
			}

			// Set the ed2k ratio, bandwidth available
			if ( UploadQueues.IsDonkeyRatioActive() )
			{
				nBandwidthAvailableED2K = max( UploadQueues.GetMinimumDonkeyBandwidth(), UploadQueues.GetCurrentDonkeyBandwidth() );
				if ( nBandwidthAvailableED2K < 10240 )
				{
					bDonkeyRatioActive = TRUE;
					// ED2K 3:1 ratio if you aren't uploading at 10KB/s
					nBandwidthAvailableED2K *= 3;	
				}
				else
					nBandwidthAvailableED2K = 0;
			}

			// Limit the transfers. Faster transfers get a bigger share of the bandwidth
			for ( POSITION pos = pTransfersToLimit.GetHeadPosition() ; pos ; )
			{
				CDownloadTransfer* pTransfer = pTransfersToLimit.GetNext( pos );

				DWORD nCurrentSpeed = pTransfer->GetMeasuredSpeed();
				DWORD nLimit;

				if ( nTotalBandwidth == 0 )
				{
					nLimit = nBandwidthAvailable / (DWORD)pTransfersToLimit.GetCount();
				}
				else
				{
					double nPercentageUsed = (double)nCurrentSpeed / (double)nTotalBandwidth;
					nPercentageUsed = min(nPercentageUsed, 0.90);
					nLimit = (DWORD)(nBandwidthAvailable * nPercentageUsed);
				}
					
				// eDonkey ratio
				if ( bDonkeyRatioActive && ( pTransfer->m_nProtocol == PROTOCOL_ED2K ) )
				{
					DWORD nLimitED2K;
					if ( nRunningTransfersED2K == 0 )
					{
						nLimitED2K = nBandwidthAvailableED2K;
					}
					else if ( nTotalBandwidthED2K == 0 )
					{
						nLimitED2K = nBandwidthAvailableED2K / nRunningTransfersED2K;
					}
					else
					{
						double nPercentageUsed = (double)nCurrentSpeed / (double)nTotalBandwidthED2K;
						nPercentageUsed = min(nPercentageUsed, 0.90);
						nLimitED2K = (DWORD)(nBandwidthAvailableED2K * nPercentageUsed );
					}

					if ( nLimit ) nLimit = min( nLimit, nLimitED2K );
					else nLimit = nLimitED2K;
				}

				// Minimum allocation- 64 bytes / second to prevent time-outs.
				if ( ( nLimit ) && ( nLimit < 64 ) ) nLimit = 64;

				pTransfer->m_nBandwidth = nLimit;
			}

		} 	// End of transfers section lock

		// Update limit assigned to new transfers
		if ( nBandwidthAvailable > nTotalBandwidth ) m_nLimitNew = nBandwidthAvailable - nTotalBandwidth;
		else m_nLimitNew = Settings.Bandwidth.Request;

		// Save bandwidth stats, Update allows
		m_nTransfers = nActiveTransfers;
		m_nBandwidth = nTotalBandwidth;
				
		m_bAllowMoreDownloads = nActiveDownloads < (DWORD)Settings.Downloads.MaxFiles;
		m_bAllowMoreTransfers = nTotalTransfers < (DWORD)Settings.Downloads.MaxTransfers;

		// Set "bandwidth use is near maximum" timers
		// beware that the MAX setting uses a limit of 0 internally,
		// so we need to catch that case first
		if ( nBandwidthAvailable != 0 && ( nTotalBandwidth * 1.1 ) >= nBandwidthAvailable )
			m_tBandwidthAtMax = tNow;
		if ( nBandwidthAvailableED2K != 0 && ( nTotalBandwidthED2K * 1.1 ) >= nBandwidthAvailableED2K )
			m_tBandwidthAtMaxED2K = tNow;

		DownloadGroups.Save( FALSE );
	}
}

//////////////////////////////////////////////////////////////////////
// CDownloads query hit handler

void CDownloads::OnQueryHits(CQueryHit* pHits)
{

/*	CSingleLock pLock( &Transfers.m_pSection );
	
	if ( ! pLock.Lock( 50 ) ) return;
	
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		CDownload* pDownload = GetNext( pos );
		if ( pDownload->IsMoving() == FALSE ) pDownload->OnQueryHits( pHits );
	}	
*/

	if ( pHits != NULL )
		Transfers.m_pMessageQueue.PushMessage( (CITMQueue::CITMItem*)CITMQueryHit::CreateMessage(pHits) );

}

void CDownloads::OnQueryHits(CHitPtrs& oHits)
{

	/*	CSingleLock pLock( &Transfers.m_pSection );

	if ( ! pLock.Lock( 50 ) ) return;

	for ( POSITION pos = GetIterator() ; pos ; )
	{
	CDownload* pDownload = GetNext( pos );
	if ( pDownload->IsMoving() == FALSE ) pDownload->OnQueryHits( pHits );
	}	
	*/

	if ( oHits.size() )
		Transfers.m_pMessageQueue.PushMessage( (CITMQueue::CITMItem*)CITMQueryHits::CreateMessage(oHits) );

}

//////////////////////////////////////////////////////////////////////
// CDownloads push handler

BOOL CDownloads::OnPush(const Hashes::Guid& oGUID, CConnection* pConnection, DWORD nFileIndex)
{
	CSingleLock pLock( &Transfers.m_pSection );
	if ( ! pLock.Lock( 250 ) ) return FALSE;

	for ( POSITION pos = GetIterator() ; pos ; )
	{
		CDownload* pDownload = GetNext( pos );
		if ( pDownload->OnAcceptPush( oGUID, pConnection, nFileIndex ) ) return TRUE;
	}

	return FALSE;
}

//////////////////////////////////////////////////////////////////////
// CDownloads eDonkey2000 callback handler

BOOL CDownloads::OnDonkeyCallback(CEDClient* pClient, CDownloadSource* pExcept, CDownload* pSeekDownloadAfterThis)
{
	CSingleLock pLock( &Transfers.m_pSection );
	if ( ! pLock.Lock( 250 ) ) return FALSE;

	if ( m_bClosing ) return FALSE;

	// if pSeekDownloadAfterThis is not NULL, then need to make sure that download look up does not look and try attach
	// to same source which has been tried to connect within same lookup session.
	// NOTE: one session: lookup -> attach -> failure -> look up, which does not happen in one loop because try attach
	// result is depending on the answer from download source too. so when the first try resulted with failure it should
	// try second, then when second failed, the third has to be tried, not going back to the first one. it include
	// the situation when last one failed, the first one should not be tried until next connect event happen.
	if ( pSeekDownloadAfterThis ) // Exception is set
	{
		bool bFound =false;
		for ( POSITION pos = GetIterator() ; pos ; )
		{
			CDownload* pDownload = GetNext( pos );
			if ( bFound )	// has found the CDownload object match to pSeekDownloadAfterThis
			{
				// try callback on pDownload. (check ED2K source count first because no good trying if no ed2k sources)
				if ( pDownload->m_nEdSourceCount && pDownload->OnDonkeyCallback( pClient, pExcept ) ) return TRUE;
			}
			else	// has not found CDownload object which match to pSeekDownloadAfterThis yet.
			{
				// check if pDownload is equal to pSeekDownloadAfterThis or not. if it is, set bFound.
				if ( pSeekDownloadAfterThis == pDownload ) bFound = true;
			}
		}
	}
	else	// no exception.
	{
		for ( POSITION pos = GetIterator() ; pos ; )
		{
			CDownload* pDownload = GetNext( pos );
			// try callback on pDownload. (check ED2K source count first because no good trying if no ed2k sources)
			if ( pDownload->m_nEdSourceCount && pDownload->OnDonkeyCallback( pClient, pExcept ) ) return TRUE;
		}
	}

	return FALSE;
}

//////////////////////////////////////////////////////////////////////
// CDownloads verification handler

void CDownloads::OnVerify(LPCTSTR pszPath, BOOL bVerified)
{
	CSingleLock pLock( &Transfers.m_pSection );
	if ( ! pLock.Lock( 500 ) ) return;
	
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		if ( GetNext( pos )->OnVerify( pszPath, bVerified ) ) break;
	}	
}

//////////////////////////////////////////////////////////////////////
// CDownloads load and save

void CDownloads::Load()
{
	CSingleLock pLock( &Transfers.m_pSection, TRUE );
	WIN32_FIND_DATA pFind;
	CString strPath;
	HANDLE hSearch;
	
	PurgeDeletes();
	PurgePreviews();
	
	DownloadGroups.CreateDefault();
	LoadFromCompoundFiles();
	
	strPath = Settings.Downloads.IncompletePath + _T("\\*.sd");
	hSearch = FindFirstFile( strPath, &pFind );
	
	if ( hSearch != INVALID_HANDLE_VALUE )
	{
		do
		{
			CDownload* pDownload = new CDownload();
			
			strPath.Format( _T("%s\\%s"), (LPCTSTR)Settings.Downloads.IncompletePath, pFind.cFileName );
			
			if ( pDownload->Load( strPath ) )
			{
				if ( pDownload->m_bSeeding )
				{
					if ( !Settings.BitTorrent.AutoSeed || 
						 GetFileAttributes( pDownload->m_sServingFileName ) == INVALID_FILE_ATTRIBUTES )
					{
						::DeleteFile( strPath );
						delete pDownload;
						continue;
					}
					pDownload->m_bComplete = TRUE;
					pDownload->m_bVerify = TS_TRUE;
				}
				else if ( !pDownload->m_bTempPaused )
				{
					m_oPendingSearches.push_back(pDownload);
				}
				m_pList.AddTail( pDownload );
			}
			else
			{
				theApp.Message( MSG_ERROR, _T("Error loading %s"), strPath );
				pDownload->ClearSources();
				delete pDownload;
			}
		}
		while ( FindNextFile( hSearch, &pFind ) );

		FindClose( hSearch );
	}
	
	Save( FALSE );
	DownloadGroups.Load();
	Transfers.StartThread();
}

void CDownloads::Save(BOOL bForce)
{
	CSingleLock pLock( &Transfers.m_pSection, TRUE );
	
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		CDownload* pDownload = GetNext( pos );
		if ( bForce || pDownload->m_nCookie != pDownload->m_nSaveCookie ) pDownload->Save( TRUE );
	}
}

//////////////////////////////////////////////////////////////////////
// CDownloads load all the old compound file formats

void CDownloads::LoadFromCompoundFiles()
{
	if ( LoadFromCompoundFile( Settings.Downloads.IncompletePath + _T("\\Shareaza Downloads.dat") ) )
	{
		// Good
	}
	else if ( LoadFromCompoundFile( Settings.Downloads.IncompletePath + _T("\\Shareaza Downloads.bak") ) )
	{
		// Good
	}
	else if ( LoadFromTimePair() )
	{
		// Good
	}
	
	DeleteFile( Settings.Downloads.IncompletePath + _T("\\Shareaza Downloads.dat") );
	DeleteFile( Settings.Downloads.IncompletePath + _T("\\Shareaza Downloads.bak") );
	DeleteFile( Settings.Downloads.IncompletePath + _T("\\Shareaza.dat") );
	DeleteFile( Settings.Downloads.IncompletePath + _T("\\Shareaza1.dat") );
	DeleteFile( Settings.Downloads.IncompletePath + _T("\\Shareaza2.dat") );
}

BOOL CDownloads::LoadFromCompoundFile(LPCTSTR pszFile)
{
	CFile pFile;
	
	if ( ! pFile.Open( pszFile, CFile::modeRead ) ) return FALSE;
	
	CArchive ar( &pFile, CArchive::load );
	
	try
	{
		SerializeCompound( ar );
	}
	catch ( CException* pException )
	{
		pException->Delete();
		Clear();
		return FALSE;
	}
	
	return TRUE;
}

BOOL CDownloads::LoadFromTimePair()
{
	FILETIME pFileTime1 = { 0, 0 }, pFileTime2 = { 0, 0 };
	CFile pFile1, pFile2;
	BOOL bFile1, bFile2;
	CString strFile;
	
	strFile	= Settings.Downloads.IncompletePath + _T("\\Shareaza");
	bFile1	= pFile1.Open( strFile + _T("1.dat"), CFile::modeRead );
	bFile2	= pFile2.Open( strFile + _T("2.dat"), CFile::modeRead );
	
	if ( bFile1 || bFile2 )
	{
		if ( bFile1 ) bFile1 = pFile1.Read( &pFileTime1, sizeof(FILETIME) ) == sizeof(FILETIME);
		if ( bFile2 ) bFile2 = pFile2.Read( &pFileTime2, sizeof(FILETIME) ) == sizeof(FILETIME);
	}
	else
	{
		if ( ! pFile1.Open( strFile + _T(".dat"), CFile::modeRead ) ) return FALSE;
		pFileTime1.dwHighDateTime++;
	}
	
	CFile* pNewest = ( CompareFileTime( &pFileTime1, &pFileTime2 ) >= 0 ) ? &pFile1 : &pFile2;
	
	try
	{
		CArchive ar( pNewest, CArchive::load );
		SerializeCompound( ar );
		ar.Close();
	}
	catch ( CException* pException )
	{
		pException->Delete();
		Clear();
		
		if ( pNewest == &pFile1 && bFile2 )
			pNewest = &pFile2;
		else if ( pNewest == &pFile2 && bFile1 )
			pNewest = &pFile1;
		else
			pNewest = NULL;

		if ( pNewest != NULL )
		{
			try
			{
				CArchive ar( pNewest, CArchive::load );
				SerializeCompound( ar );
				ar.Close();
			}
			catch ( CException* pException )
			{
				pException->Delete();
				Clear();
				return FALSE;
			}
		}
	}
	
	return TRUE;
}

void CDownloads::SerializeCompound(CArchive& ar)
{
	ASSERT( ar.IsLoading() );

	int nVersion;
	ar >> nVersion;
	if ( nVersion < 4 ) return;

	for ( DWORD_PTR nCount = ar.ReadCount() ; nCount > 0 ; nCount-- )
	{
		CDownload* pDownload = new CDownload();
		m_pList.AddTail( pDownload );
		pDownload->Serialize( ar, nVersion );
		if ( !pDownload->m_bPaused )
		{
			m_oPendingSearches.push_back(pDownload);
		}
	}
}

//////////////////////////////////////////////////////////////////////
// CDownloads left over file purge operations

void CDownloads::PurgeDeletes()
{
	CList< CString > pRemove;
	HKEY hKey = NULL;
	
	if ( ERROR_SUCCESS != RegOpenKeyEx( HKEY_CURRENT_USER,
		_T("Software\\Shareaza\\Shareaza\\Delete"), 0, KEY_ALL_ACCESS, &hKey ) ) return;
	
	for ( DWORD nIndex = 0 ; nIndex < 1000 ; nIndex ++ )
	{
		DWORD nPath = MAX_PATH*2;
		TCHAR szPath[MAX_PATH*2];
		
		if ( ERROR_SUCCESS != RegEnumValue( hKey, nIndex, szPath, &nPath, NULL,
			NULL, NULL, NULL ) ) break;
		
		if ( GetFileAttributes( szPath ) == 0xFFFFFFFF || DeleteFile( szPath ) )
		{
			pRemove.AddTail( szPath );
		}
	}
	
	while ( ! pRemove.IsEmpty() )
	{
		RegDeleteValue( hKey, pRemove.RemoveHead() );
	}
	
	RegCloseKey( hKey );
}

void CDownloads::PurgePreviews()
{
	WIN32_FIND_DATA pFind;
	HANDLE hSearch;
	CString strPath;
	
	strPath = Settings.Downloads.IncompletePath + _T("\\Preview of *.*");
	hSearch = FindFirstFile( strPath, &pFind );
	if ( hSearch == INVALID_HANDLE_VALUE ) return;
	
	do
	{
		if ( _tcsnicmp( pFind.cFileName, _T("Preview of "), 11 ) == 0 )
		{
			strPath = Settings.Downloads.IncompletePath + '\\' + pFind.cFileName;
			DeleteFile( strPath );
		}
	}
	while ( FindNextFile( hSearch, &pFind ) );
	
	FindClose( hSearch );
}
