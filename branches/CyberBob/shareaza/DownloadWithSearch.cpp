//
// DownloadWithSearch.cpp
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
#include "DownloadWithSearch.h"
#include "SearchManager.h"
#include "ManagedSearch.h"
#include "QuerySearch.h"
#include "Download.h"
#include "Downloads.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif


//////////////////////////////////////////////////////////////////////
// CDownloadWithSearch construction

CDownloadWithSearch::CDownloadWithSearch()
{
	m_pSearch			= NULL;
	m_tSearchTime		= 0;
	m_tSearchCheck		= 0;
	m_tLastED2KGlobal	= 0;
	m_tLastED2KLocal	= 0;
	m_tSearchStart		= 0;
	m_tSearchDuration	= 0;
	m_bSearchActive		= FALSE;
}

CDownloadWithSearch::~CDownloadWithSearch()
{
	if ( m_pSearch ) delete m_pSearch;
}


//////////////////////////////////////////////////////////////////////
// CDownloadWithSearch Can Find Sources

BOOL CDownloadWithSearch::FindSourcesAllowed(DWORD tNow) const
{
	if ( tNow > m_tSearchTime && tNow - m_tSearchTime > 60*1000 )
		return TRUE;
	else
		return FALSE;
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithSearch find additional sources

BOOL CDownloadWithSearch::FindMoreSources()
{
	BOOL bSuccess = CDownloadWithTiger::FindMoreSources();

	// allow 4 extra Searchs for manual starting.
	if ( !m_bSearchActive && DWORD( Downloads.m_oActiveSearches.size() ) > DWORD( Settings.Downloads.MaxFileSearches + 4 ) )
		return bSuccess;

	if ( CanSearch() )
	{
		DWORD tNow = GetTickCount();
		if ( tNow - m_tSearchTime > ( Settings.Downloads.SearchPeriod / 4 ) )
		{
			m_tSearchTime = tNow;
			if ( m_pSearch != NULL ) StopSearch( tNow, FALSE );
			m_tSearchStart		= 0;
			PrepareSearch( TRUE, TRUE, TRUE );
			if ( m_pSearch != NULL ) StartManualSearch( tNow );
			bSuccess = TRUE;
		}
	}

	return bSuccess;
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithSearch run process

void CDownloadWithSearch::RunSearch(DWORD tNow)
{
	if ( ! CanSearch() )	// if this item is not searchable anymore,
	{
		if ( m_bSearchActive ) StopSearch( tNow, FALSE );				// stop search now
		return;
	}
	else if ( m_bSearchActive )
	{
		if ( m_tSearchDuration == 0 || tNow - m_tSearchStart > m_tSearchDuration )
		{
			StopSearch( tNow, TRUE );
		}
	}
/*	else if ( DWORD(Downloads.m_oActiveSearches.size()) > DWORD(Settings.Downloads.MaxFileSearches) )
	{
		return;
	}
	else if ( m_tLastSearchTime && tNow - m_tLastSearchTime < Downloads.m_tSearchThrottle )
	{
		return;
	}
	else if ( tNow > m_tSearchCheck && tNow - m_tSearchCheck >= 1000 )
	{
		// BOOL bFewSources = GetSourceCount( FALSE, TRUE ) < Settings.Downloads.MinSources;
		//int nHTTP = 0, nG1 = 0, nG2 = 0, nED2K = 0, nBT = 0;
		BOOL bFewSources = GetEffectiveSourceCount() < Settings.Downloads.MinSources;
		BOOL bG1 = FALSE, bG2 = FALSE, bED2K = FALSE;

		//GetMultiSourceCount( TRUE, &nHTTP, &nG1, &nG2, &nED2K, &nBT );
		BOOL bDataStarve = ( tNow > m_tReceived ? tNow - m_tReceived : 0 ) > Settings.Downloads.StarveTimeout * 1000;

		bG1 = ( m_nG1SourceCount < Settings.Downloads.MinSources ) && Settings.Gnutella1.EnableToday && m_oSHA1;
		bG2 = ( m_nG2SourceCount < Settings.Downloads.MinSources ) && Settings.Gnutella2.EnableToday;
		bED2K = ( m_nEdSourceCount < Settings.Downloads.MinSources ) && Settings.eDonkey.EnableToday && m_oED2K;

		bFewSources = bFewSources || bG1 || bG2 || bED2K;

		m_tSearchCheck = tNow;

		if ( IsPaused() == FALSE && ( bFewSources || bDataStarve ) )
		{
			StartAutomaticSearch( tNow, bG1, bG2, bED2K );
		}
		else
		{
			StopSearch(tNow);
		}
	}*/
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithSearch start (or continue) a manual search

void CDownloadWithSearch::StartManualSearch(DWORD tNow)
{
	CSingleLock pLock( &SearchManager.m_pSection );
	if ( ! pLock.Lock( 50 ) ) return;

	PrepareSearch();

	m_pSearch->m_nPriority = CManagedSearch::spHighest;
	m_pSearch->Start();
	Downloads.m_oPendingSearches.remove( static_cast<CDownload*>(this) );
	Downloads.m_oActiveSearches.push_back( static_cast<CDownload*>(this) );
	m_bSearchActive		= TRUE;
	m_tSearchStart = tNow;
	m_tSearchDuration = Settings.Downloads.ManualSearchDuration;
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithSearch start (or continue) an automatic search

void CDownloadWithSearch::StartAutomaticSearch( DWORD tNow, BOOL bG1, BOOL bG2, BOOL bED2K )
{
	CSingleLock pLock( &SearchManager.m_pSection );
	if ( ! pLock.Lock( 10 ) ) return;

	PrepareSearch( bG1, bG2, bED2K );
	Downloads.m_oPendingSearches.remove( static_cast<CDownload*>(this) );
	Downloads.m_oActiveSearches.push_back( static_cast<CDownload*>(this) );
	//m_pSearch->m_nPriority = CManagedSearch::spLowest;
	m_pSearch->m_nPriority = CManagedSearch::spMedium;
	m_pSearch->Start();
	m_bSearchActive		= TRUE;
	m_tSearchStart = tNow;
	m_tSearchDuration = Settings.Downloads.AutoSearchDuration;
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithSearch check if we can actually search

BOOL CDownloadWithSearch::CanSearch() const
{
	return m_pFile != NULL && 
		( m_oSHA1  && ( Settings.Gnutella1.EnableToday || Settings.Gnutella2.EnableToday ) ||
		  ( m_oED2K && ( Settings.Gnutella2.EnableToday || Settings.eDonkey.EnableToday ) ) || 
		  ( ( m_oBTH || m_oMD5 || m_oTiger ) && Settings.Gnutella2.EnableToday ) );
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithSearch prepare a managed search object

void CDownloadWithSearch::PrepareSearch( BOOL bG1, BOOL bG2, BOOL bED2K )
{
	if ( m_pSearch == NULL ) m_pSearch = new CManagedSearch();
	CQuerySearch* pSearch = m_pSearch->m_pSearch.get();

	m_pSearch->m_bAllowG1 = Settings.Gnutella1.EnableToday && bG1;
	m_pSearch->m_bAllowG2 = Settings.Gnutella2.EnableToday && bG2;

	pSearch->m_bAndG1 = m_pSearch->m_bAllowG1;

	if ( pSearch->m_bAndG1 )
	{

		// Need to Clear Keyword first in case the keyword built in Previous Search session.
		// unless it has been cleared, and change in file name or Keyword for the file never change
		// if previous CManagedSearch object is left in m_pSearch.
		pSearch->m_sKeywords.Empty();

		// check if it has Keyword Overriding set for search
		// this is quite important for G1(LimeWire) search, because G1 don't use URNs for search.
		if ( !m_sSearchKeyword.IsEmpty() ) 
		{
			pSearch->m_sSearch = m_sSearchKeyword;
		}
		else
		{
			pSearch->m_sSearch = m_sDisplayName;		
		}
	}

	if ( m_oSHA1 )
	{
		pSearch->m_oSHA1 = m_oSHA1;
	}
	else
	{
		pSearch->m_oSHA1.clear();
		pSearch->m_bAndG1 = FALSE;
	}

	if ( m_oTiger )
	{
		pSearch->m_oTiger = m_oTiger;
	}
	else
	{
		pSearch->m_oTiger.clear();
	}

	if ( m_oED2K )
	{
		pSearch->m_oED2K = m_oED2K;
		m_pSearch->m_bAllowED2K = bED2K && Settings.eDonkey.EnableToday;
	}
	else
	{
		pSearch->m_oED2K.clear();
		m_pSearch->m_bAllowED2K = FALSE;
	}

	if ( m_oMD5 )
	{
		pSearch->m_oMD5 = m_oMD5;
	}
	else
	{
		pSearch->m_oMD5.clear();
	}

	if ( m_oBTH )
	{
		pSearch->m_oBTH = m_oBTH;
	}
	else
	{
		pSearch->m_oBTH.clear();
	}

	pSearch->m_bWantURL	= TRUE;
	pSearch->m_bWantDN	= ( m_sDisplayName.GetLength() == 0 );
	pSearch->m_bWantXML	= FALSE;
	pSearch->m_bWantPFS	= TRUE;
	pSearch->m_bWantCOM = FALSE;

	if ( m_nSize == SIZE_UNKNOWN )
	{
		pSearch->m_nMinSize = 0;
		pSearch->m_nMaxSize = SIZE_UNKNOWN;
		pSearch->m_bWantDN	= TRUE;
	}
	else
	{
		pSearch->m_nMinSize = m_nSize;
		pSearch->m_nMaxSize = m_nSize;
	}

	CQuerySearch::PrepareCheck(pSearch);
	pSearch->CheckValid( true );
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithSearch stop searching

void CDownloadWithSearch::StopSearch(DWORD tNow, BOOL bQueuePending)
{
	UNUSED_ALWAYS(tNow);
	if ( m_pSearch != NULL )
	{
		m_pSearch->Stop();
		delete m_pSearch;
		m_pSearch = NULL;
	}
	m_bSearchActive		= FALSE;
	Downloads.m_oActiveSearches.remove( static_cast<CDownload*>(this) );
	if ( bQueuePending )
		Downloads.m_oPendingSearches.push_back( static_cast<CDownload*>(this) );
	else
		Downloads.m_oPendingSearches.remove( static_cast<CDownload*>(this) );
	m_tSearchStart = 0;			// set the started time to 0
	m_tSearchDuration = 0;		// reset Search duration.
}
