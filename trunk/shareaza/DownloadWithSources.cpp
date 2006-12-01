//
// DownloadWithSources.cpp
//
//	Date:			"$Date: 2006/04/04 23:48:54 $"
//	Revision:		"$Revision: 1.31 $"
//  Last change by:	"$Author: rolandas $"
//
// Copyright (c) Shareaza Development Team, 2002-2006.
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
#include "DownloadWithSources.h"
#include "DownloadTransfer.h"
#include "DownloadSource.h"
#include "Network.h"
#include "Neighbours.h"
#include "Transfer.h"
#include "QueryHit.h"
#include "SourceURL.h"
#include "Schema.h"
#include "SchemaCache.h"
#include "Library.h"
#include "SharedFile.h"
#include "XML.h"
#include "SHA.h"
#include "MD4.h"
#include "TigerTree.h"
#include "QueryHashMaster.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif


//////////////////////////////////////////////////////////////////////
// CDownloadWithSources construction

CDownloadWithSources::CDownloadWithSources()
: m_pSourceFirst(NULL)
, m_pSourceLast(NULL)
, m_nSourceCount(0)
, m_pXML(NULL)
, m_nBTSourceCount(0)
, m_nG1SourceCount(0)
, m_nG2SourceCount(0)
, m_nEdSourceCount(0)
, m_nHTTPSourceCount(0)
, m_nFTPSourceCount(0)
{
}

CDownloadWithSources::~CDownloadWithSources()
{
	ClearSources();
	if ( m_pXML != NULL ) delete m_pXML;
	
	for ( POSITION pos = m_pFailedSources.GetHeadPosition() ; pos ; )
		delete m_pFailedSources.GetNext( pos );

	m_pFailedSources.RemoveAll();
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithSources list access

int CDownloadWithSources::GetSourceCount(BOOL bNoPush, BOOL bSane) const
{
	if ( ! bNoPush && ! bSane ) return m_nSourceCount;
	
	DWORD tNow = GetTickCount();
	int nCount = 0;
	
	for ( CDownloadSource* pSource = m_pSourceFirst ; pSource ; pSource = pSource->m_pNext )
	{
		if ( ! bNoPush || ! pSource->m_bPushOnly )
		{
			if ( ! bSane ||
				 pSource->m_tAttempt < tNow ||
				 pSource->m_tAttempt - tNow <= 900000 )
			{
				nCount++;
			}
		}
	}
	
	return nCount;
}

int	CDownloadWithSources::GetEffectiveSourceCount() const
{
	int nResult = 0;
	if ( Settings.IsG1Allowed() )
		nResult += m_nG1SourceCount;
	if ( Settings.IsG2Allowed() )
		nResult += m_nG2SourceCount;
	if ( Settings.IsEdAllowed() )
		nResult += m_nEdSourceCount;
	if ( Settings.IsG1Allowed() || Settings.IsG2Allowed() )
		nResult += m_nHTTPSourceCount;
	return nResult + m_nBTSourceCount + m_nFTPSourceCount;
}

int CDownloadWithSources::GetBTSourceCount(BOOL bNoPush) const
{
	DWORD tNow = GetTickCount();
	int nCount = 0;
	
	for ( CDownloadSource* pSource = m_pSourceFirst ; pSource ; pSource = pSource->m_pNext )
	{
		if ( ( pSource->m_nProtocol == PROTOCOL_BT ) &&									// Only counting BT sources
			 ( pSource->m_tAttempt < tNow || pSource->m_tAttempt - tNow <= 900000 ) &&	// Don't count dead sources
			 ( ! pSource->m_bPushOnly || ! bNoPush ) )									// Push sources might not be counted
		{
			nCount++;
		}
	}
	
	/*
	CString strT;
	strT.Format(_T("BT sources: %i"), nCount);
	theApp.Message( MSG_DEBUG, strT );
	*/
	return nCount;
}

int CDownloadWithSources::GetED2KCompleteSourceCount() const
{

	DWORD tNow = GetTickCount();
	int nCount = 0;
	
	for ( CDownloadSource* pSource = m_pSourceFirst ; pSource ; pSource = pSource->m_pNext )
	{
		if ( ( ! pSource->m_bPushOnly ) &&						// Push sources shouldn't be counted since you often cannot reach them
			 ( pSource->m_tAttempt < tNow || pSource->m_tAttempt - tNow <= 900000 ) &&	// Only count sources that are probably active
			 ( pSource->m_nProtocol == PROTOCOL_ED2K ) &&		// Only count ed2k sources
             ( pSource->m_oAvailable.empty() && pSource->IsOnline() ) )	// Only count complete sources
			
		{
			nCount++;
		}
	}
	
	/*
	CString strT;
	strT.Format(_T("Complete ed2k sources: %i"), nCount);
	theApp.Message( MSG_DEBUG, strT );
	*/
	return nCount;
}

BOOL CDownloadWithSources::CheckSource(CDownloadSource* pCheck) const
{
	for ( CDownloadSource* pSource = m_pSourceFirst ; pSource ; pSource = pSource->m_pNext )
	{
		if ( pSource == pCheck ) return TRUE;
	}
	
	return FALSE;
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithSources clear

void CDownloadWithSources::ClearSources()
{
	for ( CDownloadSource* pSource = GetFirstSource() ; pSource ; )
	{
		CDownloadSource* pNext = pSource->m_pNext;
		delete pSource;
		pSource = pNext;
	}

	m_pSourceFirst = m_pSourceLast = NULL;
	m_nSourceCount = m_nEdSourceCount = m_nG1SourceCount = m_nFTPSourceCount = 0;
	m_nG2SourceCount = m_nHTTPSourceCount = m_nBTSourceCount = 0;
	
	SetModified();
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithSources add a query-hit source

BOOL CDownloadWithSources::AddSourceHit(CQueryHit* pHit, BOOL bForce)
{
	BOOL bHash = FALSE;
	BOOL bUpdated = FALSE;
	
	if ( ! bForce )
	{
		if ( m_oSHA1 && pHit->m_oSHA1 )
		{
			if ( m_oSHA1 != pHit->m_oSHA1 ) return FALSE;
			bHash = TRUE;
		}
		// We should check Tiger as well as others. This is because
		// there exist some hash combinations, even for Shareaza 2.2.0.0 
		// installer file, i.e. with the same SHA1 but different Tiger (CyberBob).

		if ( m_oTiger && pHit->m_oTiger )
		{
			if ( m_oTiger != pHit->m_oTiger ) return FALSE;
			bHash = TRUE;
		}
        if ( m_oED2K && pHit->m_oED2K )
		{
			if ( m_oED2K != pHit->m_oED2K ) return FALSE;
			bHash = TRUE;
		}
		if ( m_oBTH && pHit->m_oBTH )
		{
			if ( m_oBTH != pHit->m_oBTH ) return FALSE;
			bHash = TRUE;
		}
	}
	
	if ( ! bHash && ! bForce )
	{
		if ( Settings.General.HashIntegrity ) return FALSE;
		
		if ( m_sDisplayName.IsEmpty() || pHit->m_sName.IsEmpty() ) return FALSE;
		if ( m_nSize == SIZE_UNKNOWN || ! pHit->m_bSize ) return FALSE;
		
		if ( m_nSize != pHit->m_nSize ) return FALSE;
		if ( m_sDisplayName.CompareNoCase( pHit->m_sName ) ) return FALSE;
	}
	
	if ( !m_oSHA1 && pHit->m_oSHA1 )
	{
		m_oSHA1 = pHit->m_oSHA1;
		bUpdated = TRUE;
	}
    if ( !m_oTiger && pHit->m_oTiger )
	{
		m_oTiger = pHit->m_oTiger;
		bUpdated = TRUE;
	}
    if ( !m_oED2K && pHit->m_oED2K )
	{
		m_oED2K = pHit->m_oED2K;
		bUpdated = TRUE;
	}
	if ( !m_oBTH && pHit->m_oBTH )
	{
		m_oBTH = pHit->m_oBTH;
		bUpdated = TRUE;
	}
	
	if ( m_nSize == SIZE_UNKNOWN && pHit->m_bSize )
	{
		m_nSize = pHit->m_nSize;
	}
	else if ( m_nSize != SIZE_UNKNOWN && pHit->m_bSize && m_nSize != pHit->m_nSize )
	{
		return FALSE;
	}

	if ( m_sDisplayName.IsEmpty() && pHit->m_sName.GetLength() )
	{
		m_sDisplayName = pHit->m_sName;
	}
	
	if ( Settings.Downloads.Metadata && m_pXML == NULL )
	{
		if ( pHit->m_pXML != NULL && pHit->m_sSchemaPlural.GetLength() )
		{
			m_pXML = new CXMLElement( NULL, pHit->m_sSchemaPlural );
			m_pXML->AddAttribute( _T("xmlns:xsi"), CXMLAttribute::xmlnsInstance );
			m_pXML->AddAttribute( CXMLAttribute::schemaName, pHit->m_sSchemaURI );
			m_pXML->AddElement( pHit->m_pXML->Clone() );
			
			if ( CSchema* pSchema = SchemaCache.Get( pHit->m_sSchemaURI ) )
			{
				pSchema->Validate( m_pXML, TRUE );
			}
		}
	}

	/*
	if ( pHit->m_nProtocol == PROTOCOL_ED2K )
	{
		Neighbours.FindDonkeySources( pHit->m_oED2K,
			(IN_ADDR*)pHit->m_oClientID.begin(), (WORD)pHit->m_oClientID.begin()[1] );
	}
	*/

	// No URL, stop now with success
	if ( ! pHit->m_sURL.IsEmpty() )
	{	
		if ( ! AddSourceInternal( new CDownloadSource( (CDownload*)this, pHit ) ) )
		{
			return FALSE;
		}
	}

	if ( bUpdated )	QueryHashMaster.Invalidate();

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithSources add miscellaneous sources

BOOL CDownloadWithSources::AddSourceED2K(DWORD nClientID, WORD nClientPort, DWORD nServerIP, WORD nServerPort, const Hashes::Guid& oGUID)
{
	return AddSourceInternal( new CDownloadSource( (CDownload*)this, nClientID, nClientPort, nServerIP, nServerPort, oGUID ) );
}

BOOL CDownloadWithSources::AddSourceBT(const Hashes::BtGuid& oGUID, IN_ADDR* pAddress, WORD nPort)
{
	// Unreachable (Push) BT sources should never be added.
	if ( Network.IsFirewalledAddress( pAddress, Settings.Connection.IgnoreOwnIP ) )
		return FALSE;
	
	// Check for own IP, in case IgnoreLocalIP is not set
	if ( ( Settings.Connection.IgnoreOwnIP ) && ( pAddress->S_un.S_addr == Network.m_pHost.sin_addr.S_un.S_addr ) ) 
		return FALSE;

	return AddSourceInternal( new CDownloadSource( (CDownload*)this, oGUID, pAddress, nPort ) );
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithSources add a single URL source

BOOL CDownloadWithSources::AddSourceURL(LPCTSTR pszURL, BOOL bURN, FILETIME* pLastSeen, int nRedirectionCount, BOOL bFailed)
{
	if ( pszURL == NULL ) return FALSE;
	if ( *pszURL == 0 ) return FALSE;
	if ( nRedirectionCount > 5 ) return FALSE; // No more than 5 redirections
	
	BOOL bHashAuth = FALSE;
	CSourceURL pURL;
	
	if ( *pszURL == '@' )
	{
		bHashAuth = TRUE;
		pszURL++;
	}
	
	if ( ! pURL.Parse( pszURL ) ) return FALSE;
	
	if ( bURN )
	{
		if ( pURL.m_pAddress.S_un.S_addr == Network.m_pHost.sin_addr.S_un.S_addr ) return FALSE;
		if ( Network.IsFirewalledAddress( &pURL.m_pAddress, TRUE ) || 
			 Network.IsReserved( &pURL.m_pAddress ) ) return FALSE;
	}

	if ( CFailedSource* pBadSource = LookupFailedSource( pszURL ) )
	{
		// Add a positive vote, add to the downloads if the negative votes compose
		// less than 2/3 of total.
		INT_PTR nTotal = pBadSource->m_nPositiveVotes + pBadSource->m_nNegativeVotes + 1;
		if ( bFailed )
			pBadSource->m_nNegativeVotes++;
		else
			pBadSource->m_nPositiveVotes++;

		if ( nTotal > 30 && pBadSource->m_nNegativeVotes / nTotal > 2 / 3 )
			return FALSE;
	}
	else if ( bFailed )
	{
		AddFailedSource( pszURL, false );
		VoteSource( pszURL, false );
		return TRUE;
	}
	
	if ( pURL.m_oSHA1 && m_oSHA1 )
	{
		if ( m_oSHA1 != pURL.m_oSHA1 ) return FALSE;
	}
	
	if ( m_sDisplayName.IsEmpty() && _tcslen( pszURL ) > 9 )
	{
		m_sDisplayName = &pszURL[8];
		
		int nPos = m_sDisplayName.ReverseFind( '/' );
		
		if ( nPos >= 0 )
		{
			m_sDisplayName = m_sDisplayName.Mid( nPos + 1 ).SpanExcluding( _T("?") );
			m_sDisplayName = CTransfer::URLDecode( m_sDisplayName );
		}
		else
		{
			m_sDisplayName.Empty();
		}
		
		if ( m_sDisplayName.IsEmpty() ) m_sDisplayName = _T("default.htm");
	}
	
	return AddSourceInternal( new CDownloadSource( (CDownload*)this, pszURL, bURN, bHashAuth, pLastSeen, nRedirectionCount ) );
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithSources add several URL sources

int CDownloadWithSources::AddSourceURLs(LPCTSTR pszURLs, BOOL bURN, BOOL bFailed)
{
	if ( IsCompleted() || IsMoving() )
	{
		ClearSources();
		return 0;
	}
	else if ( IsPaused() )
		return 0;
			
	CString strURLs( pszURLs );
	BOOL bQuote = FALSE;
	
	for ( int nScan = 0 ; nScan < strURLs.GetLength() ; nScan++ )
	{
		if ( strURLs[ nScan ] == '\"' )
		{
			bQuote = ! bQuote;
			strURLs.SetAt( nScan, ' ' );
		}
		else if ( strURLs[ nScan ] == ',' && bQuote )
		{
			strURLs.SetAt( nScan, '`' );
		}
	}
	
	strURLs += ',';
	
    int nCount = 0;
	for ( ; ; )
	{
		int nPos = strURLs.Find( ',' );
		if ( nPos < 0 ) break;
		
		CString strURL	= strURLs.Left( nPos );
		strURLs			= strURLs.Mid( nPos + 1 );
		strURL.TrimLeft();
		
		FILETIME tSeen = { 0, 0 };
		BOOL bSeen = FALSE;
		
		if ( _tcsistr( strURL, _T("://") ) != NULL )
		{
			nPos = strURL.ReverseFind( ' ' );
			
			if ( nPos > 0 )
			{
				CString strTime = strURL.Mid( nPos + 1 );
				strURL = strURL.Left( nPos );
				strURL.TrimRight();
				bSeen = TimeFromString( strTime, &tSeen );
			}
			
			for ( int nScan = 0 ; nScan < strURL.GetLength() ; nScan++ )
			{
				if ( strURL[ nScan ] == '`' ) strURL.SetAt( nScan, ',' );
			}
		}
		else
		{
			nPos = strURL.Find( ':' );
			if ( nPos < 1 ) continue;
			
			int nPort = 0;
			_stscanf( strURL.Mid( nPos + 1 ), _T("%i"), &nPort );
			strURL.Truncate( nPos );
			USES_CONVERSION;
			DWORD nAddress = inet_addr( T2CA( strURL ) );
			strURL.Empty();
			
			if ( ! Network.IsFirewalledAddress( &nAddress, TRUE ) && 
				 ! Network.IsReserved( (IN_ADDR*)&nAddress ) && nPort != 0 && nAddress != INADDR_NONE )
			{
				if ( m_oSHA1 )
				{
					strURL.Format( _T("http://%s:%i/uri-res/N2R?%s"),
						(LPCTSTR)CString( inet_ntoa( *(IN_ADDR*)&nAddress ) ),
						nPort, (LPCTSTR)m_oSHA1.toUrn() );
				}
			}
		}
		
		if ( AddSourceURL( strURL, bURN, bSeen ? &tSeen : NULL, 0, bFailed ) )
		{
			if ( bFailed )
			{
				theApp.Message( MSG_DEBUG, L"Adding X-NAlt: %s", (LPCTSTR)strURL );
			}
			else
			{
				theApp.Message( MSG_DEBUG, L"Adding X-Alt: %s", (LPCTSTR)strURL );
			}
			nCount++;
		}
	}
	
	return nCount;
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithSources internal source adder

BOOL CDownloadWithSources::AddSourceInternal(CDownloadSource* pSource)
{
	//Check/Reject if source is invalid
	if ( ! pSource->m_bPushOnly )
	{
		//Reject invalid IPs (Sometimes ed2k sends invalid 0.x.x.x sources)
		if ( pSource->m_pAddress.S_un.S_un_b.s_b1 == 0 || pSource->m_nPort == 0 )
		{
			delete pSource;
			return FALSE;
		}

		//Reject if source is the local IP/port
		if ( Network.m_pHost.sin_addr.S_un.S_addr == pSource->m_pAddress.S_un.S_addr )
		{
			if ( ( ( pSource->m_nServerPort == 0 ) && (Settings.Connection.InPort == pSource->m_nPort ) )
				|| ( Settings.Connection.IgnoreOwnIP ) )
			{	
				delete pSource;
				return FALSE;
			}
		}
	}
	else if ( pSource->m_nProtocol == PROTOCOL_ED2K )
	{
		//Reject invalid server IPs (Sometimes ed2k sends invalid 0.x.x.x sources)
		if ( pSource->m_pServerAddress.S_un.S_un_b.s_b1 == 0 )
		{
			delete pSource;
			return FALSE;
		}
	}
	
	bool bG2Exists = false;
	bool bExistingIsRaza = false;
	bool bDeleteSource = false;
	CDownloadSource* pCopy = NULL;

	if ( pSource->m_nRedirectionCount == 0 ) // Don't check for existing sources if source is a redirection
	{
		for ( CDownloadSource* pExisting = m_pSourceFirst ; pExisting ; )
		{	
			bool bSkip = false;

			if ( pExisting->Equals( pSource ) ) // IPs and ports are equal
			{	
				if ( !bExistingIsRaza )
					bExistingIsRaza = ( _tcsncmp( pExisting->m_sServer, _T("Shareaza"), 8 ) == 0 );

				if ( !bG2Exists )
					bG2Exists = ( pExisting->m_nProtocol == PROTOCOL_HTTP || pExisting->m_nProtocol == PROTOCOL_G2 );

				// Point to non-HTTP source which is Shareaza
				if ( bExistingIsRaza )
					pCopy = bG2Exists ? NULL : pExisting;
				
				if ( pExisting->m_nProtocol == pSource->m_nProtocol )
					bDeleteSource = true;

				if ( pExisting->m_pTransfer != NULL ) // We already downloading
				{
					// Remove new source which is not HTTP and return
					if ( ( pExisting->m_nProtocol == PROTOCOL_HTTP || pExisting->m_nProtocol == PROTOCOL_G2 ) && 
						 ( pSource->m_nProtocol != PROTOCOL_HTTP && pSource->m_nProtocol != PROTOCOL_G2 ) )
						bDeleteSource = true;
				}
				else // We are not downloading
				{
					// Replace non-HTTP source with a new one (we will add it later)
					if ( ( pExisting->m_nProtocol != PROTOCOL_HTTP && pExisting->m_nProtocol != PROTOCOL_G2 ) && 
						 ( pSource->m_nProtocol == PROTOCOL_HTTP || pSource->m_nProtocol == PROTOCOL_G2 ) )
					{
						// Set connection delay the same as for the old source
						pSource->m_tAttempt = pExisting->m_tAttempt;
						pCopy = NULL;	// We are adding HTTP source, thus no need to make G2
						bSkip = true;	// Don't go to the next source

						if ( pExisting->m_pNext )
						{
							pExisting = pExisting->m_pNext;
							pExisting->m_pPrev->Remove( TRUE, FALSE );
						}
						else
						{
							pExisting->Remove( TRUE, FALSE );
							pExisting = NULL;
						}
					}
				}
			}

			if ( !bSkip )
				pExisting = pExisting->m_pNext;
		}
	}

	// We don't need to make G2 source
	if ( pCopy && !pCopy->m_bPushOnly && bExistingIsRaza && bG2Exists )
		pCopy = NULL;

	// Make G2 source from the existing non-HTTP Shareaza source
	if ( pCopy && Settings.Gnutella2.EnableToday )
	{
		CString strURL;
		if ( m_oSHA1 )
		{
			strURL.Format( _T("http://%s:%i/uri-res/N2R?%s"),
				(LPCTSTR)CString( inet_ntoa( pCopy->m_pAddress ) ),
				pCopy->m_nPort, (LPCTSTR)m_oSHA1.toUrn() );
		}
		else if ( m_oED2K )
		{
			strURL.Format( _T("http://%s:%i/uri-res/N2R?%s"),
				(LPCTSTR)CString( inet_ntoa( pCopy->m_pAddress ) ),
				pCopy->m_nPort, (LPCTSTR)m_oED2K.toUrn() );
		}
		//else if ( m_oBTH )
		//{
		//	strURL.Format( _T("http://%s:%i/uri-res/N2R?%s"),
		//		(LPCTSTR)CString( inet_ntoa( pCopy->m_pAddress ) ),
		//		pCopy->m_nPort, (LPCTSTR)m_oBTH.toUrn() );
		//}
		else if ( m_oMD5 )
		{
			strURL.Format( _T("http://%s:%i/uri-res/N2R?%s"),
				(LPCTSTR)CString( inet_ntoa( pCopy->m_pAddress ) ),
				pCopy->m_nPort, (LPCTSTR)m_oMD5.toUrn() );
		}

		if ( strURL.GetLength() )
		{
			CDownloadSource* pG2Source  = new CDownloadSource( (CDownload*)this, strURL );
			pG2Source->m_sServer = pCopy->m_sServer;	// Copy user-agent
			pG2Source->m_tAttempt = pCopy->m_tAttempt;	// Set the same connection delay
			pG2Source->m_nProtocol = pCopy->m_nProtocol;

			m_nSourceCount++;
			if ( pCopy->m_nProtocol == PROTOCOL_HTTP )
				m_nHTTPSourceCount++;
			else if ( pCopy->m_nProtocol == PROTOCOL_G2 )
				m_nG2SourceCount++;

			pG2Source->m_pPrev = m_pSourceLast;
			pG2Source->m_pNext = NULL;
				
			if ( m_pSourceLast != NULL )
			{
				m_pSourceLast->m_pNext = pG2Source;
				m_pSourceLast = pG2Source;
			}
			else
			{
				m_pSourceFirst = m_pSourceLast = pG2Source;
			}

			if ( pG2Source->m_pTransfer == NULL )
			{
				if ( CDownloadTransfer* pTransfer = pG2Source->CreateTransfer() )
					pTransfer->Initiate();
			}
		}
	}
	
	if ( bDeleteSource )
	{
		delete pSource;
		return FALSE;
	}

	m_nSourceCount++;

	if ( pSource->m_nProtocol == PROTOCOL_G1 )
		m_nG1SourceCount++;
	else if ( pSource->m_nProtocol == PROTOCOL_G2 )
		m_nG2SourceCount++;
	else if ( pSource->m_nProtocol == PROTOCOL_ED2K )
		m_nEdSourceCount++;
	else if ( pSource->m_nProtocol == PROTOCOL_HTTP )
		m_nHTTPSourceCount++;
	else if ( pSource->m_nProtocol == PROTOCOL_BT )
		m_nBTSourceCount++;
	else if ( pSource->m_nProtocol == PROTOCOL_FTP )
		m_nFTPSourceCount++;

	pSource->m_pPrev = m_pSourceLast;
	pSource->m_pNext = NULL;
		
	if ( m_pSourceLast != NULL )
	{
		m_pSourceLast->m_pNext = pSource;
		m_pSourceLast = pSource;
	}
	else
	{
		m_pSourceFirst = m_pSourceLast = pSource;
	}
	
	SetModified();
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithSources query for URLs

CString CDownloadWithSources::GetSourceURLs(CList< CString >* pState, int nMaximum, PROTOCOLID nProtocol, CDownloadSource* pExcept)
{
	CString strSources, strURL;
	
	for ( CDownloadSource* pSource = GetFirstSource() ; pSource ; pSource = pSource->m_pNext )
	{
		if ( pSource != pExcept && pSource->m_bPushOnly == FALSE &&
			 pSource->m_nFailures == 0 && pSource->m_bReadContent &&
			 ( pSource->m_bSHA1 || pSource->m_bED2K ) &&
			 ( pState == NULL || pState->Find( pSource->m_sURL ) == NULL ) )
		{
			if ( pState != NULL ) pState->AddTail( pSource->m_sURL );
			
			
			// Only return appropriate sources
			if ( ( nProtocol == PROTOCOL_HTTP ) && ( pSource->m_nProtocol != PROTOCOL_HTTP ) ) continue;
			if ( ( nProtocol == PROTOCOL_G1 ) && ( pSource->m_nGnutella != 1 ) ) continue;

			//if ( bHTTP && pSource->m_nProtocol != PROTOCOL_HTTP ) continue;
			
			if ( nProtocol == PROTOCOL_G1 )
			{
				if ( strSources.GetLength() ) 
					strSources += ',';
				strSources += CString( inet_ntoa( pSource->m_pAddress ) );
				if ( pSource->m_nPort != GNUTELLA_DEFAULT_PORT )
				{
					strURL.Format( _T("%hu"), pSource->m_nPort );
					strSources += ':' + strURL;
				}
			}
			else
			{
				strURL = pSource->m_sURL;
				Replace( strURL, _T(","), _T("%2C") );

				if ( strSources.GetLength() > 0 ) strSources += _T(", ");
				strSources += strURL;
				strSources += ' ';
				strSources += TimeToString( &pSource->m_tLastSeen );
			}
			
			if ( nMaximum == 1 ) break;
			else if ( nMaximum > 1 ) nMaximum --;
		}
	}
	
	if ( strSources.Find( _T("Zhttp://") ) >= 0 ) strSources.Empty();
	
	return strSources;
}

// Returns a string containing the most recent failed sources
CString	CDownloadWithSources::GetTopFailedSources(int nMaximum, PROTOCOLID nProtocol)
{
	// Currently we return only the string for G1, in X-NAlt format
	if ( nProtocol != PROTOCOL_G1 ) return CString();

	CString strSources, str;
	CFailedSource* pResult = NULL;

	for ( POSITION pos = m_pFailedSources.GetHeadPosition() ; pos ; )
	{
		pResult = m_pFailedSources.GetNext( pos );
		// Only return sources which we detected as failed
		if ( pResult && pResult->m_bLocal )
		{
			if ( _tcsistr( pResult->m_sURL, _T("http://") ) != NULL )
			{
				int nPos = pResult->m_sURL.Find( ':', 8 );
				if ( nPos < 0 ) continue;
				str = pResult->m_sURL.Mid( 7, nPos - 7 );
				int nPosSlash = pResult->m_sURL.Find( '/', nPos );
				if ( nPosSlash < 0 ) continue;

				if ( strSources.GetLength() ) 
					strSources += ',';

				strSources += str;
				str = pResult->m_sURL.Mid( nPos + 1, nPosSlash - nPos - 1 );
				if ( str != _T("6346") )
				{
					strSources += ':';
					strSources += str;
				}

				if ( nMaximum == 1 ) break;
				else if ( nMaximum > 1 ) nMaximum--;
			}
		}
	}
	return strSources;
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithSources query hit handler

BOOL CDownloadWithSources::OnQueryHits(CQueryHit* pHits)
{
	for ( ; pHits ; pHits = pHits->m_pNext )
	{
		if ( pHits->m_sURL.GetLength() ) AddSourceHit( pHits );
	}

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithSources remove overlapping sources

void CDownloadWithSources::RemoveOverlappingSources(QWORD nOffset, QWORD nLength)
{
	for ( CDownloadSource* pSource = GetFirstSource() ; pSource ; )
	{
		CDownloadSource* pNext = pSource->m_pNext;
		
		if ( pSource->TouchedRange( nOffset, nLength ) )
		{
			theApp.Message( MSG_ERROR, IDS_DOWNLOAD_VERIFY_DROP,
				(LPCTSTR)CString( inet_ntoa( pSource->m_pAddress ) ),
				(LPCTSTR)pSource->m_sServer, (LPCTSTR)m_sDisplayName,
				nOffset, nOffset + nLength - 1 );
			pSource->Remove( TRUE, TRUE );
		}
		
		pSource = pNext;
	}
}

// The function takes an URL and finds a failed source in the list;
// If bReliable is true, it checks only localy checked failed sources
// and those which have more than 30 votes from other users and negative
// votes compose 2/3 of the total number of votes.
CFailedSource* CDownloadWithSources::LookupFailedSource(LPCTSTR pszUrl, bool bReliable)
{
	CFailedSource* pResult = NULL;

	for ( POSITION pos = m_pFailedSources.GetHeadPosition() ; pos ; )
	{
		pResult = m_pFailedSources.GetNext( pos );
		if ( pResult && pResult->m_sURL.Compare( pszUrl ) == 0 )
		{
#ifndef NDEBUG
			theApp.Message( MSG_DEBUG, _T("Votes for file %s: negative - %i, positive - %i; offline status: %i"), 
				pszUrl, pResult->m_nNegativeVotes, 
				pResult->m_nPositiveVotes, 
				pResult->m_bOffline );
#endif
			if ( pResult->m_bLocal )
				break;
			
			if ( bReliable )
			{
				INT_PTR nTotalVotes = pResult->m_nNegativeVotes + pResult->m_nPositiveVotes;
				if ( nTotalVotes > 30 && pResult->m_nNegativeVotes / nTotalVotes > 2 / 3 )
					break;
			}
		}
		else
			pResult = NULL;
	}
	return pResult;
}

void CDownloadWithSources::AddFailedSource(CDownloadSource* pSource, bool bLocal, bool bOffline)
{
	CString strURL;
	if ( pSource->m_nProtocol == PROTOCOL_BT && pSource->m_oGUID )
	{
		strURL.Format( _T("btc://%s/%s/"),
            (LPCTSTR)pSource->m_oGUID.toString(),
			(LPCTSTR)m_oBTH.toString() );
	}
	else
		strURL = pSource->m_sURL;

	if ( LookupFailedSource( (LPCTSTR)strURL ) == NULL )
	{
		CFailedSource* pBadSource = new CFailedSource( strURL, bLocal, bOffline );
		m_pFailedSources.AddTail( pBadSource );
		theApp.Message( MSG_DEBUG, L"Bad sources count for \"%s\": %i", m_sDisplayName, m_pFailedSources.GetCount() );
	}
}

void CDownloadWithSources::AddFailedSource(LPCTSTR pszUrl, bool bLocal, bool bOffline)
{
	if ( LookupFailedSource( pszUrl ) == NULL )
	{
		CFailedSource* pBadSource = new CFailedSource( pszUrl, bLocal, bOffline );
		m_pFailedSources.AddTail( pBadSource );
		theApp.Message( MSG_DEBUG, L"Bad sources count for \"%s\": %i", m_sDisplayName, m_pFailedSources.GetCount() );
	}
}

void CDownloadWithSources::VoteSource(LPCTSTR pszUrl, bool bPositively)
{
	if ( CFailedSource* pBadSource = LookupFailedSource( pszUrl ) )
	{
		if ( bPositively )
			pBadSource->m_nPositiveVotes++;
		else
			pBadSource->m_nNegativeVotes++;
	}
}

void CDownloadWithSources::ExpireFailedSources()
{
	CSingleLock pLock( &m_pSection, TRUE );
	DWORD tNow = GetTickCount();
	for ( POSITION pos = m_pFailedSources.GetHeadPosition() ; pos ; )
	{
		POSITION posThis = pos;
		CFailedSource* pBadSource = m_pFailedSources.GetNext( pos );
		if ( m_pFailedSources.GetAt( posThis ) == pBadSource )
		{
			// Expire bad sources added more than 2 hours ago
			if ( tNow - pBadSource->m_nTimeAdded > 2 * 3600 * 1000 )
			{
				delete pBadSource;
				m_pFailedSources.RemoveAt( posThis );
			}
			else break; // We appended to tail, so we do not need to move further
		}
	}
}

void CDownloadWithSources::ClearFailedSources()
{
	CSingleLock pLock( &m_pSection, TRUE );
	for ( POSITION pos = m_pFailedSources.GetHeadPosition() ; pos ; )
	{
		POSITION posThis = pos;
		CFailedSource* pBadSource = m_pFailedSources.GetNext( pos );
		if ( m_pFailedSources.GetAt( posThis ) == pBadSource )
		{
			delete pBadSource;
			m_pFailedSources.RemoveAt( posThis );
		}
	}
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithSources remove a source

void CDownloadWithSources::RemoveSource(CDownloadSource* pSource, BOOL bBan)
{
	if ( bBan && pSource->m_sURL.GetLength() )
	{
		AddFailedSource( pSource );
	}
	
	ASSERT( m_nSourceCount > 0 );
	m_nSourceCount --;

	if ( pSource->m_nProtocol == PROTOCOL_G1 )
		m_nG1SourceCount--;
	else if ( pSource->m_nProtocol == PROTOCOL_G2 )
		m_nG2SourceCount--;
	else if ( pSource->m_nProtocol == PROTOCOL_ED2K )
		m_nEdSourceCount--;
	else if ( pSource->m_nProtocol == PROTOCOL_HTTP )
		m_nHTTPSourceCount--;
	else if ( pSource->m_nProtocol == PROTOCOL_BT )
		m_nBTSourceCount--;
	else if ( pSource->m_nProtocol == PROTOCOL_FTP )
		m_nFTPSourceCount--;

	if ( pSource->m_pPrev != NULL )
		pSource->m_pPrev->m_pNext = pSource->m_pNext;
	else
		m_pSourceFirst = pSource->m_pNext;
	
	if ( pSource->m_pNext != NULL )
		pSource->m_pNext->m_pPrev = pSource->m_pPrev;
	else
		m_pSourceLast = pSource->m_pPrev;
	
	delete pSource;
	SetModified();
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithSources sort a source

void CDownloadWithSources::SortSource(CDownloadSource* pSource, BOOL bTop)
{
	ASSERT( m_nSourceCount > 0 );
	
	if ( pSource->m_pPrev != NULL )
		pSource->m_pPrev->m_pNext = pSource->m_pNext;
	else
		m_pSourceFirst = pSource->m_pNext;
	
	if ( pSource->m_pNext != NULL )
		pSource->m_pNext->m_pPrev = pSource->m_pPrev;
	else
		m_pSourceLast = pSource->m_pPrev;
	
	if ( ! bTop )
	{
		pSource->m_pPrev = m_pSourceLast;
		pSource->m_pNext = NULL;
		
		if ( m_pSourceLast != NULL )
		{
			m_pSourceLast->m_pNext = pSource;
			m_pSourceLast = pSource;
		}
		else
		{
			m_pSourceFirst = m_pSourceLast = pSource;
		}
	}
	else
	{
		pSource->m_pPrev = NULL;
		pSource->m_pNext = m_pSourceFirst;
		
		if ( m_pSourceFirst != NULL )
		{
			m_pSourceFirst->m_pPrev = pSource;
			m_pSourceFirst = pSource;
		}
		else
		{
			m_pSourceFirst = m_pSourceLast = pSource;
		}
	}
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithSources sort a source by state (Downloading, etc...)

void CDownloadWithSources::SortSource(CDownloadSource* pSource)
{
	ASSERT( m_nSourceCount > 0 );

	//Remove source from current position. (It's unsorted, and would interfere with sort)
	if ( pSource->m_pPrev != NULL )
		pSource->m_pPrev->m_pNext = pSource->m_pNext;
	else
		m_pSourceFirst = pSource->m_pNext;
	
	if ( pSource->m_pNext != NULL )
		pSource->m_pNext->m_pPrev = pSource->m_pPrev;
	else
		m_pSourceLast = pSource->m_pPrev;
	


	if ( ( m_pSourceFirst == NULL ) || ( m_pSourceLast == NULL ) )
	{	//Only one source
		m_pSourceFirst = m_pSourceLast = pSource;
		pSource->m_pNext = pSource->m_pPrev = NULL;
	}
	else
	{	//Sort sources
		CDownloadSource* pCompare = m_pSourceFirst;

		while ( ( pCompare != NULL ) && (pCompare->m_nSortOrder < pSource->m_nSortOrder) )
			pCompare = pCompare->m_pNext; //Run through the sources to the correct position

		if ( pCompare == NULL )
		{	//Source is last on list
			m_pSourceLast->m_pNext = pSource;
			pSource->m_pPrev = m_pSourceLast;
			pSource->m_pNext = NULL;
			m_pSourceLast = pSource;
		}
		else
		{	//Insert source in front of current compare source
			if ( pCompare->m_pPrev == NULL )
				m_pSourceFirst = pSource;
			else
				pCompare->m_pPrev->m_pNext = pSource;

			pSource->m_pNext = pCompare;
			pSource->m_pPrev = pCompare->m_pPrev;
			pCompare->m_pPrev= pSource;
		}

	}
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithSources source colour selector

#define SRC_COLOURS 6

int CDownloadWithSources::GetSourceColour()
{
	BOOL bTaken[SRC_COLOURS] = {};
	int nFree = SRC_COLOURS;
	
	for ( CDownloadSource* pSource = GetFirstSource() ; pSource ; pSource = pSource->m_pNext )
	{
		if ( pSource->m_nColour >= 0 )
		{
			if ( bTaken[ pSource->m_nColour ] == FALSE )
			{
				bTaken[ pSource->m_nColour ] = TRUE;
				nFree--;
			}
		}
	}
	
	if ( nFree == 0 ) return rand() % SRC_COLOURS;
	
	nFree = rand() % nFree;
	
	for ( int nColour = 0 ; nColour < SRC_COLOURS ; nColour++ )
	{
		if ( bTaken[ nColour ] == FALSE )
		{
			if ( nFree-- == 0 ) return nColour;
		}
	}
	
	return rand() % SRC_COLOURS;
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithSources serialize

void CDownloadWithSources::Serialize(CArchive& ar, int nVersion)
{
	CDownloadBase::Serialize( ar, nVersion );
	
	if ( ar.IsStoring() )
	{
		ar.WriteCount( GetSourceCount() );
		
		for ( CDownloadSource* pSource = GetFirstSource() ; pSource ; pSource = pSource->m_pNext )
		{
			pSource->Serialize( ar, nVersion );
		}
		
		ar.WriteCount( m_pXML != NULL ? 1 : 0 );
		if ( m_pXML ) m_pXML->Serialize( ar );
	}
	else
	{
		for ( DWORD_PTR nSources = ar.ReadCount() ; nSources ; nSources-- )
		{
			// Create new source
			CDownloadSource* pSource = new CDownloadSource( (CDownload*)this );
			
			// Add to the list
			m_nSourceCount++;

			pSource->m_pPrev = m_pSourceLast;
			pSource->m_pNext = NULL;
			
			if ( m_pSourceLast != NULL )
			{
				m_pSourceLast->m_pNext = pSource;
				m_pSourceLast = pSource;
			}
			else
			{
				m_pSourceFirst = m_pSourceLast = pSource;
			}

			// Load details from disk
			pSource->Serialize( ar, nVersion );

			if ( pSource->m_nProtocol == PROTOCOL_G1 )
				m_nG1SourceCount++;
			else if ( pSource->m_nProtocol == PROTOCOL_G2 )
				m_nG2SourceCount++;
			else if ( pSource->m_nProtocol == PROTOCOL_ED2K )
				m_nEdSourceCount++;
			else if ( pSource->m_nProtocol == PROTOCOL_HTTP )
				m_nHTTPSourceCount++;
			else if ( pSource->m_nProtocol == PROTOCOL_BT )
				m_nBTSourceCount++;
			else if ( pSource->m_nProtocol == PROTOCOL_FTP )
				m_nFTPSourceCount++;

			// Extract ed2k client ID from url (m_pAddress) because it wasn't saved
			if ( ( !pSource->m_nPort ) && ( _tcsnicmp( pSource->m_sURL, _T("ed2kftp://"), 10 ) == 0 )  )
			{
				CString strURL = pSource->m_sURL.Mid(10);
				if ( strURL.GetLength())
					_stscanf( strURL, _T("%lu"), &pSource->m_pAddress.S_un.S_addr );
			}
		}
		
		if ( ar.ReadCount() )
		{
			m_pXML = new CXMLElement();
			m_pXML->Serialize( ar );
		}
	}
}
