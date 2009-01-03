//
// DownloadWithTransfers.cpp
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
#include "Download.h"
#include "Downloads.h"
#include "Transfers.h"
#include "DownloadWithTransfers.h"
#include "DownloadSource.h"
#include "DownloadTransferHTTP.h"
//#include "DownloadTransferFTP.h"
#include "DownloadTransferED2K.h"
#include "DownloadTransferBT.h"
#include "Network.h"
#include "EDClient.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif


//////////////////////////////////////////////////////////////////////
// CDownloadWithTransfers construction

CDownloadWithTransfers::CDownloadWithTransfers()
{
	m_pTransferFirst	= NULL;
	m_pTransferLast		= NULL;
	m_nTransferCount	= 0;
	m_tTransferStart	= 0;
}

CDownloadWithTransfers::~CDownloadWithTransfers()
{
	CloseTransfers();
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithTransfers counting

int CDownloadWithTransfers::GetTransferCount() const 
{ 
	int nCount = 0; 
    
	for ( CDownloadTransfer* pTransfer = m_pTransferFirst; pTransfer; pTransfer = pTransfer->m_pDlNext ) 
	{ 
		if ( ( pTransfer->m_nProtocol != PROTOCOL_ED2K ) || 
		     ( static_cast< CDownloadTransferED2K* >( pTransfer )->m_pClient && 
			   static_cast< CDownloadTransferED2K* >( pTransfer )->m_pClient->m_bConnected ) ) 
		{ 
			++nCount; 
		} 
	} 
	return nCount; 
} 


// This macro is used to clean up the function below and make it more readable. It's the first 
// condition in any IF statement that checks if the current transfer should be counted
#define VALID_TRANSFER ( ! pAddress || pAddress->S_un.S_addr == pTransfer->m_pHost.sin_addr.S_un.S_addr ) &&	\
					   ( ( pTransfer->m_nProtocol != PROTOCOL_ED2K ) ||											\
						 ( static_cast< CDownloadTransferED2K* >( pTransfer )->m_pClient &&						\
						   static_cast< CDownloadTransferED2K* >( pTransfer )->m_pClient->m_bConnected ) )


int CDownloadWithTransfers::GetTransferCount(int nState, IN_ADDR* pAddress) const
{
    int nCount = 0;

    switch ( nState )
    {
    case dtsCountAll:
        for ( CDownloadTransfer* pTransfer = m_pTransferFirst; pTransfer; pTransfer = pTransfer->m_pDlNext )
        {
		    if ( VALID_TRANSFER )
            {
                ++nCount;
            }
        }
        return nCount;
    case dtsCountNotQueued:
	    for ( CDownloadTransfer* pTransfer = m_pTransferFirst ; pTransfer ; pTransfer = pTransfer->m_pDlNext )
	    {	
		    if ( VALID_TRANSFER && ( ( pTransfer->m_nState != dtsQueued ) && 
				( ! ( pTransfer->m_nState == dtsTorrent && static_cast< CDownloadTransferBT* >(pTransfer)->m_bChoked ) ) ) )
                 
            {
                ++nCount;
            }
        }
        return nCount;
    case dtsCountNotConnecting:
	    for ( CDownloadTransfer* pTransfer = m_pTransferFirst ; pTransfer ; pTransfer = pTransfer->m_pDlNext )
	    {	
		    if ( ( ! pAddress || pAddress->S_un.S_addr == pTransfer->m_pHost.sin_addr.S_un.S_addr ) && 
				 ( pTransfer->m_nState > dtsConnecting ) )
            {
                ++nCount;
            }
        }
        return nCount;
    case dtsCountTorrentAndActive:
	    for ( CDownloadTransfer* pTransfer = m_pTransferFirst ; pTransfer ; pTransfer = pTransfer->m_pDlNext )
	    {	
		    if ( VALID_TRANSFER )
		    {
                switch( pTransfer->m_nState )
                {
                case dtsTorrent:
                case dtsRequesting:
                case dtsDownloading:
                    ++nCount;
                }
            }
        }
        return nCount;
    default:
	    for ( CDownloadTransfer* pTransfer = m_pTransferFirst ; pTransfer ; pTransfer = pTransfer->m_pDlNext )
	    {	
		    if ( VALID_TRANSFER && ( pTransfer->m_nState == nState ) )
            {
                ++nCount;
			}
		}
    	return nCount;
	}
}

//////////////////////////////////////////////////////////////////////
// GetAmountDownloadedFrom total volume from an IP

QWORD CDownloadWithTransfers::GetAmountDownloadedFrom(IN_ADDR* pAddress) const
{
	QWORD nTotal = 0;

	for ( CDownloadTransfer* pTransfer = m_pTransferFirst ; pTransfer ; pTransfer = pTransfer->m_pDlNext )
	{	
		if ( pAddress->S_un.S_addr == pTransfer->m_pHost.sin_addr.S_un.S_addr )
			nTotal += pTransfer->m_nDownloaded;
	}

	return nTotal;
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithTransfers consider starting more transfers

// This function checks if it's okay to try opening a new download. (Download throttle, etc)
BOOL CDownloadWithTransfers::CanStartTransfers(DWORD tNow)
{
	if ( tNow == 0 ) tNow = GetTickCount();
	
	if ( tNow - m_tTransferStart < 100 ) return FALSE;
	m_tTransferStart = tNow;

	// Make sure the network is ready
	if ( ! Network.ReadyToTransfer( tNow ) ) return FALSE;
	
	// Limit the connection rate
	if ( Settings.Downloads.ConnectThrottle != 0 )
	{
		if ( tNow < Downloads.m_tLastConnect ) return FALSE;
		if ( tNow - Downloads.m_tLastConnect <= Settings.Downloads.ConnectThrottle ) return FALSE;
	}

	// Limit the amount of connecting (half-open) sources. (Very important for XP sp2)
	if ( Downloads.GetConnectingTransferCount() >= Settings.Downloads.MaxConnectingSources )
	{
		return FALSE;
	}

	return TRUE;
}

// This functions starts a new download transfer if needed and allowed.
BOOL CDownloadWithTransfers::StartTransfersIfNeeded(DWORD tNow, BOOL bSeeding)
{
	if ( tNow == 0 ) tNow = GetTickCount();

	// Check connection throttles, max open connections, etc
	if ( ! CanStartTransfers( tNow ) ) return FALSE;
	
	//BitTorrent limiting
	if ( m_oBTH )
	{
		if ( bSeeding && StartNewTransfer( tNow, bSeeding ) )
		{
			Downloads.UpdateAllows( TRUE );
			return TRUE;
		}

		// Max connections
		if ( ( GetTransferCount( dtsCountTorrentAndActive ) ) > Settings.BitTorrent.DownloadConnections ) return FALSE;	
	}

	int nTransfers = GetTransferCount( dtsDownloading );

	if ( nTransfers < Settings.Downloads.MaxFileTransfers &&
		 ( ! Settings.Downloads.StaggardStart ||
		 nTransfers == GetTransferCount( dtsCountAll ) ) )
	{
		// If we can start new downloads, or this download is already running
		if ( Downloads.m_bAllowMoreDownloads || m_pTransferFirst != NULL )
		{
			// If we can start new transfers
			if ( Downloads.m_bAllowMoreTransfers )
			{
				// If download bandwidth isn't at max
				if ( ( ( tNow - Downloads.m_tBandwidthAtMax ) > 5000 ) ) 
				{
					// Start a new download
					if ( StartNewTransfer( tNow, bSeeding ) )
					{
						Downloads.UpdateAllows( TRUE );
						return TRUE;
					}
				}
			}
		}
	}
	
	return FALSE;
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithTransfers start a new transfer

BOOL CDownloadWithTransfers::StartNewTransfer(DWORD tNow, BOOL bSeeding)
{
	if ( tNow == 0 ) tNow = GetTickCount();
	
	BOOL bConnected = Network.IsConnected();
	CDownloadSource* pConnectHead = NULL;

	// If BT preferencing is on, check them first
	if ( ( m_oBTH ) && ( Settings.BitTorrent.PreferenceBTSources || bSeeding ) )
	{
		for ( CDownloadSource* pSource = m_pSourceFirst ; pSource ; )
		{
			CDownloadSource* pNext = pSource->m_pNext;
			
			if ( ( pSource->m_pTransfer == NULL ) &&						// does not have a transfer
				 ( pSource->m_bPushOnly == FALSE ) &&						// Not push
				 ( pSource->m_nProtocol == PROTOCOL_BT ) &&					// Is a BT source
				 ( pSource->m_tAttempt == 0 ||								// Is a "fresh" source from the tracker
				 ( ( tNow - pSource->m_tAttempt ) >= 0 && bSeeding ) ) )	// or Seeding.
			{
				if ( pSource->CanInitiate( bConnected, FALSE ) )
				{
					CDownloadTransfer* pTransfer = pSource->CreateTransfer();
					return pTransfer != NULL && pTransfer->Initiate();
				}
			}
			pSource = pNext;
		}
	}

	if ( bSeeding ) return FALSE;
	
	BOOL bStable = ( Network.GetStableTime() >= 15 );

	for ( CDownloadSource* pSource = m_pSourceFirst ; pSource ; )
	{
		CDownloadSource* pNext = pSource->m_pNext;
		
		if ( pSource->m_pTransfer )
		{
			// Already has a transfer
		}
		else if ( ( pSource->m_nProtocol == PROTOCOL_ED2K ) && ( ( tNow - Downloads.m_tBandwidthAtMaxED2K ) < 5000 ) ) 
		{
			// ED2K use (Ratio) is maxed out, no point in starting new transfers
		}
		else if ( pSource->m_bPushOnly == FALSE || pSource->m_nProtocol == PROTOCOL_ED2K )
		{
			if ( pSource->m_tAttempt == 0 )
			{
				if ( pSource->CanInitiate( bConnected, FALSE ) )
				{
					pConnectHead = pSource;
					break;
				}
			}
			else if ( pSource->m_tAttempt > 0 && int32( tNow - pSource->m_tAttempt ) > 0 )
			{
				if ( pConnectHead == NULL && pSource->CanInitiate( bConnected, FALSE ) ) pConnectHead = pSource;
			}
		}
		else if ( bStable )
		{
			if ( ! Settings.Downloads.NeverDrop && pSource->m_nPushAttempted > 10 )
			{
				pSource->Remove( TRUE, FALSE );
			}
			else if ( pSource->m_tAttempt == 0 )
			{
				if ( pSource->CanInitiate( bConnected, FALSE ) )
				{
					pConnectHead = pSource;
					break;
				}
			}
			else if ( pConnectHead == NULL && tNow - pSource->m_tAttempt > 0 && int32( tNow - pSource->m_tAttempt ) > 0 )
			{
				if ( pSource->m_oHubList.size() || pSource->m_oPushProxyList.size() )
				{
					if ( pSource->CanInitiate( bConnected, FALSE ) ) pConnectHead = pSource;
				}
				else pSource->Remove( TRUE, FALSE );
			}
		}
		pSource = pNext;
	}
	
	if ( pConnectHead != NULL )
	{
		CDownloadTransfer* pTransfer = pConnectHead->CreateTransfer();
		return ( pTransfer != NULL && pTransfer->Initiate() );
	}
	
	return FALSE;
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithTransfers close

void CDownloadWithTransfers::CloseTransfers()
{
	BOOL bBackup = Downloads.m_bClosing;
	Downloads.m_bClosing = TRUE;
	
	for ( CDownloadTransfer* pTransfer = m_pTransferFirst ; pTransfer ; )
	{
		CDownloadTransfer* pNext = pTransfer->m_pDlNext;
		pTransfer->m_pSource->m_bReConnect = FALSE;
		pTransfer->m_pSource->m_bCloseConn = FALSE;
		pTransfer->Close( TS_TRUE );
		pTransfer = pNext;
	}
	
	ASSERT( m_nTransferCount == 0 );
	
	Downloads.m_bClosing = bBackup;
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithTransfers average speed

DWORD CDownloadWithTransfers::GetAverageSpeed() const
{
	DWORD nSpeed = 0;
	
	for ( CDownloadTransfer* pTransfer = m_pTransferFirst ; pTransfer ; pTransfer = pTransfer->m_pDlNext )
	{
		if ( pTransfer->m_nState == dtsDownloading ) nSpeed += pTransfer->GetAverageSpeed();
	}
	
	return nSpeed;
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithTransfers measured speed

DWORD CDownloadWithTransfers::GetMeasuredSpeed() const
{
	DWORD nSpeed = 0;
	
	for ( CDownloadTransfer* pTransfer = m_pTransferFirst ; pTransfer ; pTransfer = pTransfer->m_pDlNext )
	{
		if ( pTransfer->m_nState == dtsDownloading )
			nSpeed += pTransfer->GetMeasuredSpeed();
	}
	
	return nSpeed;
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithTransfers push handler

BOOL CDownloadWithTransfers::OnAcceptPush(const Hashes::Guid& oClientID, CConnection* pConnection, DWORD nFileIndex)
{
	CDownload* pDownload = (CDownload*)this;
	if ( pDownload->IsMoving() || pDownload->IsPaused() || pDownload->IsCompleted() ) return FALSE;
	
	CDownloadSource* pSource = NULL;
	
	for ( pSource = GetFirstSource() ; pSource ; pSource = pSource->m_pNext )
	{
		if ( ( pSource->m_nProtocol == PROTOCOL_G1 || pSource->m_nProtocol == PROTOCOL_G2 ||
			pSource->m_nProtocol == PROTOCOL_HTTP ) && pSource->CheckPush( oClientID ) && 
			( nFileIndex == 0 || pSource->m_nIndex == nFileIndex ) ) break;
	}
	
	// if incoming CONNECTION has invalid socket, or else, could not find any source for this PUSH connection.
	if ( pConnection->m_hSocket == INVALID_SOCKET || pSource == NULL ) return FALSE;

	// Found PUSH source matches to condition.
	CDownloadTransferHTTP* pTransfer = NULL;

	// cast CDownloadTransfer to CDownloadTransferHTTP if exist.
	ASSERT( pSource->m_nProtocol == PROTOCOL_G1 || pSource->m_nProtocol == PROTOCOL_G2 || pSource->m_nProtocol == PROTOCOL_HTTP );
	if ( pSource->m_pTransfer )
	{
		pTransfer = static_cast<CDownloadTransferHTTP*>(pSource->m_pTransfer);
		if ( pTransfer && pTransfer->m_bPushWaiting )	// Cast succeed and transfer is waiting for PUSH connection.
		{
			return pTransfer->AcceptPush( pConnection );	// Accept Connection if it can
		}
	}
	else if ( nFileIndex && pSource->m_nIndex == nFileIndex )
	{
		pTransfer = (CDownloadTransferHTTP*)pSource->CreateTransfer();
		if ( pTransfer )
		{
			ASSERT( pTransfer->m_nProtocol == PROTOCOL_HTTP );
			pTransfer->CTransfer::AttachTo( NULL );
			return pTransfer->AcceptPush( pConnection );	// Accept Connection if it can
		}

	}

	// no CConnection object (not ready to accept incoming connection, maybe the one sent PUSH signal is some other download)
	return FALSE;

}

//////////////////////////////////////////////////////////////////////
// CDownloadWithTransfers eDonkey2000 callback handler

BOOL CDownloadWithTransfers::OnDonkeyCallback(CEDClient* pClient, CDownloadSource* pExcept)
{
	CDownload* pDownload = (CDownload*)this;
	if ( pDownload->IsMoving() || pDownload->IsPaused() || pDownload->IsCompleted() ) return FALSE;
	
	CDownloadSource* pSource = NULL;
//	DWORD tNow = GetTickCount();
	
	for ( pSource = GetFirstSource() ; pSource ; pSource = pSource->m_pNext )
	{
		if ( pExcept != pSource && pSource->CheckDonkey( pClient ) ) break;
	}
	
	if ( pSource == NULL ) return FALSE;
	
	if ( pSource->m_pTransfer )
	{
		// this code seems something bad, or something which never possible to be executed.
		//if ( pSource->m_pTransfer->m_nState > dtsConnecting ) return FALSE;
		//pSource->m_pTransfer->Close( TS_TRUE );
	}
	else
	{
		CDownloadTransferED2K* pTransfer = (CDownloadTransferED2K*)pSource->CreateTransfer();
		if ( pTransfer )
		{
			ASSERT( pTransfer->m_nProtocol == PROTOCOL_ED2K );
			return pTransfer->Initiate();
		}
	}

	return FALSE;
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithTransfers add and remove transfers

void CDownloadWithTransfers::AddTransfer(CDownloadTransfer* pTransfer)
{
	m_nTransferCount ++;
	pTransfer->m_pDlPrev = m_pTransferLast;
	pTransfer->m_pDlNext = NULL;
	
	if ( m_pTransferLast != NULL )
	{
		m_pTransferLast->m_pDlNext = pTransfer;
		m_pTransferLast = pTransfer;
	}
	else
	{
		m_pTransferFirst = m_pTransferLast = pTransfer;
	}
}

void CDownloadWithTransfers::RemoveTransfer(CDownloadTransfer* pTransfer)
{
	ASSERT( m_nTransferCount > 0 );
	m_nTransferCount --;
	
	if ( pTransfer->m_pDlPrev != NULL )
		pTransfer->m_pDlPrev->m_pDlNext = pTransfer->m_pDlNext;
	else
		m_pTransferFirst = pTransfer->m_pDlNext;
	
	if ( pTransfer->m_pDlNext != NULL )
		pTransfer->m_pDlNext->m_pDlPrev = pTransfer->m_pDlPrev;
	else
		m_pTransferLast = pTransfer->m_pDlPrev;
	
	delete pTransfer;
}