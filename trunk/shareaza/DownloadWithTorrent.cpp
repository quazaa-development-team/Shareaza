//
// DownloadWithTorrent.cpp
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
#include "Network.h"
#include "BTPacket.h"
#include "BTClient.h"
#include "BTClients.h"
#include "Download.h"
#include "DownloadTask.h"
#include "DownloadSource.h"
#include "DownloadWithTorrent.h"
#include "DownloadTransferBT.h"
#include "UploadTransferBT.h"
#include "BTTrackerRequest.h"
#include "FragmentedFile.h"
#include "Buffer.h"
#include "SHA.h"
#include "LibraryFolders.h"
#include "GProfile.h"
#include "Uploads.h"
#include "UploadTransfer.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif


//////////////////////////////////////////////////////////////////////
// CDownloadWithTorrent construction

CDownloadWithTorrent::CDownloadWithTorrent()
{
	m_bTorrentRequested		= FALSE;
	m_bTorrentStarted		= FALSE;
	m_tTorrentTracker		= 0;
	m_nTorrentUploaded		= 0;
	m_nTorrentDownloaded	= 0;
	m_bTorrentEndgame		= FALSE;
	m_bTorrentTrackerError	= FALSE;
	m_nTorrentTrackerErrors = 0;
	
	m_pTorrentBlock			= NULL;
	m_nTorrentBlock			= 0;
	m_nTorrentSize			= 0;
	m_nTorrentSuccess		= 0;
	m_bSeeding				= FALSE;
	
	m_tTorrentChoke			= 0;
	m_tTorrentSources		= 0;

	// Generate random Key value
	m_sKey = _T("");
	srand( GetTickCount() );
	for ( int nChar = 1 ; nChar < 6 ; nChar++ ) 
	{
		m_sKey += GenerateCharacter();
	}
}

CDownloadWithTorrent::~CDownloadWithTorrent()
{
	if ( m_bTorrentRequested ) CBTTrackerRequest::SendStopped( this );
	CloseTorrentUploads();
	if ( m_pTorrentBlock != NULL ) delete [] m_pTorrentBlock;
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithTorrent serialize

void CDownloadWithTorrent::Serialize(CArchive& ar, int nVersion)
{
	CDownloadWithFile::Serialize( ar, nVersion );
	
	if ( nVersion < 22 ) return;
	
	m_pTorrent.Serialize( ar );
	
	if ( ar.IsLoading() && m_pTorrent.IsAvailable() )
	{
		m_oBTH = m_pTorrent.m_oInfoBTH;
        m_oBTH.signalTrusted();
	}

	if ( nVersion >= 23 && m_pTorrent.IsAvailable() )
	{
		if ( ar.IsStoring() )
		{
			ar << m_nTorrentSuccess;
			ar.Write( m_pTorrentBlock, sizeof(BYTE) * m_nTorrentBlock );
		}
		else
		{
			m_nTorrentSize	= m_pTorrent.m_nBlockSize;
			m_nTorrentBlock	= m_pTorrent.m_nBlockCount;
			
			ar >> m_nTorrentSuccess;
			m_pTorrentBlock = new BYTE[ m_nTorrentBlock ];
			ar.Read( m_pTorrentBlock, sizeof(BYTE) * m_nTorrentBlock );
		}
	}
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithTorrent set torrent

BOOL CDownloadWithTorrent::SetTorrent(CBTInfo* pTorrent)
{
	if ( pTorrent == NULL ) return FALSE;
	if ( m_pTorrent.IsAvailable() ) return FALSE;
	if ( ! pTorrent->IsAvailable() ) return FALSE;
	
	m_pTorrent.Copy( pTorrent );
	
	m_oBTH = m_pTorrent.m_oInfoBTH;
	
	m_nTorrentSize	= m_pTorrent.m_nBlockSize;
	m_nTorrentBlock	= m_pTorrent.m_nBlockCount;
	m_pTorrentBlock	= new BYTE[ m_nTorrentBlock ];
	
	ZeroMemory( m_pTorrentBlock, sizeof(BYTE) * m_nTorrentBlock );
	SetModified();
	
	CreateDirectory( Settings.Downloads.TorrentPath, NULL );//Create/set up torrents folder
	LibraryFolders.AddFolder( Settings.Downloads.TorrentPath, FALSE );
	pTorrent->SaveTorrentFile( Settings.Downloads.TorrentPath );

	if ( ! Settings.BitTorrent.AdvancedInterfaceSet )
	{
		// If this is the first time the user has downloaded a torrent, turn the extra interface on.
		Settings.BitTorrent.AdvancedInterfaceSet	= TRUE;
		Settings.BitTorrent.AdvancedInterface		= TRUE;
	}
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithTorrent run

BOOL CDownloadWithTorrent::RunTorrent(DWORD tNow)
{
	if ( ! m_pTorrent.IsAvailable() ) return TRUE;
	if ( m_bDiskFull ) return FALSE;
	
	if ( tNow > m_tTorrentChoke && tNow - m_tTorrentChoke >= 10000 ) ChokeTorrent( tNow );
	
	if ( m_pFile != NULL && m_pFile->IsOpen() == FALSE )
	{
		BOOL bCreated = ( m_sDiskName.IsEmpty() ||
						GetFileAttributes( m_sDiskName ) == 0xFFFFFFFF );
		
		if ( ! PrepareFile() ) return FALSE;
		
		ASSERT( m_pTask == NULL );
		if ( bCreated ) m_pTask = new CDownloadTask( (CDownload*)this, CDownloadTask::dtaskAllocate );
	}
	
	if ( m_pTask != NULL ) return FALSE;
	
	BOOL bLive = ( ! IsPaused() ) && ( IsTrying() ) && ( Network.IsConnected() );
	
	if ( bLive && ! m_bTorrentStarted )
	{
		if ( ! m_bTorrentRequested || tNow > m_tTorrentTracker )
		{
			theApp.Message( MSG_DEFAULT, _T("Sending initial announce for %s"), m_pTorrent.m_sName );

			GenerateTorrentDownloadID();

			m_bTorrentRequested		= TRUE;
			m_bTorrentStarted		= FALSE;
			m_tTorrentTracker		= tNow + Settings.BitTorrent.DefaultTrackerPeriod;
			m_nTorrentUploaded		= 0;
			m_nTorrentDownloaded	= 0;
			
			if ( GetSourceCount(TRUE, TRUE) < Settings.BitTorrent.DownloadConnections + 10 )
				CBTTrackerRequest::SendStarted( this, WORD( Settings.BitTorrent.DownloadConnections + 10 ) );
			else
				CBTTrackerRequest::SendStarted( this );
		}
	}
	else if ( ! bLive && m_bTorrentRequested )
	{
		theApp.Message( MSG_DEFAULT, _T("Sending final announce for %s"), m_pTorrent.m_sName );

		CBTTrackerRequest::SendStopped( this );
		
		m_bTorrentRequested = m_bTorrentStarted = FALSE;
		m_tTorrentTracker = 0;
		//ZeroMemory(m_pPeerID.n, sizeof m_pPeerID.n );	// Okay to use the same one in a single session
	}
	
	if ( m_bTorrentStarted && tNow > m_tTorrentTracker )
	{
		// Regular tracker update
		theApp.Message( MSG_DEFAULT, _T("Performing tracker update for %s"), m_pTorrent.m_sName );

		int nSources = GetBTSourceCount();
		int nSourcesWanted = (int)( Settings.BitTorrent.DownloadConnections * 1.5 );
		nSourcesWanted = max( nSourcesWanted, Settings.Downloads.SourcesWanted / 10 );
		m_tTorrentTracker = tNow + Settings.BitTorrent.DefaultTrackerPeriod;
		if ( IsMoving() )
		{	// We are seeding or completed, base requests on BT uploads
			// If we're still moving the file, not firewalled, have enough sources or have maxxed out uploads
			CBTTrackerRequest::SendUpdate( this,
				!IsCompleted() || Settings.Connection.FirewallStatus == CONNECTION_OPEN
					|| nSources > nSourcesWanted / 2
					|| Uploads.GetTorrentUploadCount() >= Settings.BitTorrent.UploadCount
					? 0					// We don't need to request peers.
					: 10 );				// We might need more peers to 'push seed' to.
		}
		else if ( ( GetTransferCount( dtsCountTorrentAndActive ) ) > ( Settings.BitTorrent.DownloadConnections ) ) 
		{	// We have enough transfers
			if ( nSources > nSourcesWanted )
				CBTTrackerRequest::SendUpdate( this, 0 );	// we have enough sources and transfers, don't get any more.
			else
				CBTTrackerRequest::SendUpdate( this, 10 );	// We should request a few sources, just in case some existing ones drop. 
		}
		else
		{	// We need more transfers
			if ( nSources > nSourcesWanted )
				CBTTrackerRequest::SendUpdate( this, 5 );	// We have many sources, but not enough transfers. Get a few new ones, so we have some fresh ones. 
			else
				CBTTrackerRequest::SendUpdate( this );		// We need source and transfers. Take the tracker default. (It should be an appropriate number.)
		}

	}
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithTorrent GenerateTorrentDownloadID (Called 'Peer ID', but seperate for each download and *not* retained between sessions)

BOOL CDownloadWithTorrent::GenerateTorrentDownloadID()
{
	theApp.Message( MSG_DEBUG, _T("Creating BitTorrent Peer ID") );

	int nByte;

	//Check ID is not in use
	if ( m_pPeerID ) 
	{
		theApp.Message( MSG_DEBUG, _T("Attempted to re-create an in-use Peer ID") );
		return FALSE;
	}

	// Client ID
	if ( Settings.BitTorrent.StandardPeerID )
	{
		// Use the new (but not official) peer ID style.
		m_pPeerID[ 0 ] = '-';
		m_pPeerID[ 1 ] = BT_ID1;
		m_pPeerID[ 2 ] = BT_ID2;
		m_pPeerID[ 3 ] = (BYTE)theApp.m_nVersion[0] + '0';
		m_pPeerID[ 4 ] = (BYTE)theApp.m_nVersion[1] + '0';
		m_pPeerID[ 5 ] = (BYTE)theApp.m_nVersion[2] + '0';
		m_pPeerID[ 6 ] = (BYTE)theApp.m_nVersion[3] + '0';
		m_pPeerID[ 7 ] = '-';

		// Random characters for ID
		srand( GetTickCount() );
		for ( nByte = 8 ; nByte < 16 ; nByte++ ) 
		{
			m_pPeerID[ nByte ] = uchar( m_pPeerID[ nByte ] + rand() );
		}
		for ( nByte = 16 ; nByte < 20 ; nByte++ )
		{
			m_pPeerID[ nByte ]	= m_pPeerID[ nByte % 16 ]
								^ m_pPeerID[ 15 - ( nByte % 16 ) ];
		}
	}
	else
	{
		// Old style ID 
		for ( nByte = 0 ; nByte < 20 ; nByte++ )
		{
			m_pPeerID[ nByte ] = uchar( m_pPeerID[ nByte ] + rand() );
		}
	}
	m_pPeerID.validate();
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithTorrent tracker event handler

void CDownloadWithTorrent::OnTrackerEvent(BOOL bSuccess, LPCTSTR pszReason)
{
	if ( bSuccess )
	{
		// Success! Reset and error conditions
		m_bTorrentTrackerError = FALSE;
		m_sTorrentTrackerError.Empty();
		m_nTorrentTrackerErrors = 0;

		// Lock on this tracker if we were searching for one
		if ( m_pTorrent.m_nTrackerMode == tMultiFinding ) 
		{
			theApp.Message( MSG_DEBUG , _T("Locked on to tracker %s"), m_pTorrent.m_sTracker );
			m_pTorrent.m_nTrackerMode = tMultiFound;
		}
	}
	else
	{
		DWORD tNow = GetTickCount();

		// There was a problem with the tracker
		m_bTorrentTrackerError = TRUE;
		m_sTorrentTrackerError.Empty();
		m_nTorrentTrackerErrors ++;
		
		
		if ( m_pTorrent.m_nTrackerMode == tMultiFinding )
		{
			// We're still finding a tracker
		}
		if ( pszReason != NULL )
		{
			// If the tracker responded with an error, don't bother retrying
			if ( m_pTorrent.m_nTrackerMode == tMultiFound )
			{
				// Start looking for another tracker
				m_pTorrent.m_nTrackerMode = tMultiFinding;
			}
			else
			{
				// Display reason, and back off for an hour
				m_sTorrentTrackerError = pszReason;
				m_tTorrentTracker = tNow + 60 * 60 * 1000;
			}
		}
		else
		{
			// If we couldn't contact the tracker, check if we should re-try
			if ( m_nTorrentTrackerErrors <= Settings.BitTorrent.MaxTrackerRetry )
			{
				// Tracker or connection may have just glitched. Re-try in 10-30 seconds.
				DWORD tRetryTime;
				if ( m_nTorrentTrackerErrors <= 3 )
					tRetryTime = m_nTorrentTrackerErrors * 10 * 1000;		// nErrors * 10 seconds
				else if ( m_nTorrentTrackerErrors <= 6 )
					tRetryTime = m_nTorrentTrackerErrors * 1 * 60 * 1000;	// nErrors * 1 minute
				else if ( m_nTorrentTrackerErrors <= 15 )
					tRetryTime = m_nTorrentTrackerErrors * 2 * 60 * 1000;	// nErrors * 2 minutes
				else
					tRetryTime = 30 * 60 * 1000;							// 30 minutes
				m_tTorrentTracker = tNow + tRetryTime;

				// Load the error message string
				CString strErrorMessage;
				LoadString( strErrorMessage, IDS_BT_TRACKER_RETRY );
				m_sTorrentTrackerError.Format( strErrorMessage, m_nTorrentTrackerErrors, Settings.BitTorrent.MaxTrackerRetry );
			}
			else
			{
				// This tracker is probably down. Don't hammer it.
				if ( m_pTorrent.m_nTrackerMode == tMultiFound )
				{
					// Start looking for another tracker if we can
					m_pTorrent.m_nTrackerMode = tMultiFinding;
				}
				else
				{
					// Otherwise, back off for an hour
					m_tTorrentTracker = tNow + 60 * 60 * 1000;
					LoadString( m_sTorrentTrackerError, IDS_BT_TRACKER_DOWN );
				}
			}
		}

		if ( m_pTorrent.m_nTrackerMode == tMultiFinding )
		{
			ASSERT ( m_pTorrent.IsMultiTracker() );

			// This is a multitracker torrent and we're finding, then try the next one.
			m_pTorrent.SetTrackerFailed(tNow);
			m_pTorrent.SetTrackerNext();

			m_tTorrentTracker = ( tNow + ( m_pTorrent.GetTrackerFailures() * 2 * 1000 ) ) + 2000;
			
			// Load the error message string
			CString strErrorMessage;
			LoadString( strErrorMessage, IDS_BT_TRACKER_MULTI );
			m_sTorrentTrackerError.Format( strErrorMessage, m_pTorrent.m_nTrackerIndex + 1, m_pTorrent.m_pTrackerList.GetCount() );
			theApp.Message( MSG_ERROR, m_sTorrentTrackerError );
		}
	}
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithTorrent download transfer linking

CDownloadTransferBT* CDownloadWithTorrent::CreateTorrentTransfer(CBTClient* pClient)
{
	if ( IsMoving() || IsPaused() ) return NULL;
	
	CDownloadSource* pSource = NULL;
	
	Hashes::Guid tmp = transformGuid( pClient->m_oGUID );
	for ( pSource = GetFirstSource() ; pSource ; pSource = pSource->m_pNext )
	{
		if ( pSource->m_nProtocol == PROTOCOL_BT &&
			validAndEqual( pSource->m_oGUID, tmp ) ) break;
	}
	
	if ( pSource == NULL )
	{
		pSource = new CDownloadSource( (CDownload*)this, pClient->m_oGUID,
			&pClient->m_pHost.sin_addr, htons( pClient->m_pHost.sin_port ) );
		pSource->m_bPushOnly = TRUE;
		
		if ( ! AddSourceInternal( pSource ) ) return NULL;
	}
		
	if ( pSource->m_pTransfer != NULL ) 
	{
		// A download transfer already exists
		return NULL;
	}
	
	pSource->m_pTransfer = new CDownloadTransferBT( pSource, pClient );
	
	return (CDownloadTransferBT*)pSource->m_pTransfer;
}

void CDownloadWithTorrent::OnFinishedTorrentBlock(DWORD nBlock)
{
	for ( CDownloadTransferBT* pTransfer = (CDownloadTransferBT*)GetFirstTransfer() ; pTransfer ; pTransfer = (CDownloadTransferBT*)pTransfer->m_pDlNext )
	{
		if ( pTransfer->m_nProtocol == PROTOCOL_BT )
		{
			pTransfer->SendFinishedBlock( nBlock );
		}
	}
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithTorrent create bitfield

CBTPacket* CDownloadWithTorrent::CreateBitfieldPacket()
{
	ASSERT( m_pTorrent.IsAvailable() );
	
	CBTPacket* pPacket = CBTPacket::New( BT_PACKET_BITFIELD );
	int nCount = 0;
	
	for ( QWORD nBlock = 0 ; nBlock < m_nTorrentBlock ; )
	{
		BYTE nByte = 0;
		
		for ( int nBit = 7 ; nBit >= 0 && nBlock < m_nTorrentBlock ; nBit--, nBlock++ )
		{
			if ( m_pTorrentBlock[ nBlock ] )
			{
				nByte |= ( 1 << nBit );
				nCount++;
			}
		}
		
		pPacket->WriteByte( nByte );
	}
	
	if ( nCount > 0 ) return pPacket;
	pPacket->Release();
	
	return NULL;
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithTorrent upload linking

void CDownloadWithTorrent::AddUpload(CUploadTransferBT* pUpload)
{
	if ( m_pTorrentUploads.Find( pUpload ) == NULL )
		m_pTorrentUploads.AddTail( pUpload );
}

void CDownloadWithTorrent::RemoveUpload(CUploadTransferBT* pUpload)
{
	if ( POSITION pos = m_pTorrentUploads.Find( pUpload ) )
		m_pTorrentUploads.RemoveAt( pos );
}

void CDownloadWithTorrent::CloseTorrentUploads()
{
	for ( POSITION pos = m_pTorrentUploads.GetHeadPosition() ; pos ; )
	{
		CUploadTransferBT* pUpload = m_pTorrentUploads.GetNext( pos );
		pUpload->Close();
	}
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithTorrent choking

void CDownloadWithTorrent::ChokeTorrent(DWORD tNow)
{
	BOOL bChooseRandom = TRUE;
	int nTotalRandom = 0;
	CList< void* > pSelected;
	
	if ( ! tNow ) tNow = GetTickCount();
	if ( tNow > m_tTorrentChoke && tNow - m_tTorrentChoke < 2000 ) return;
	m_tTorrentChoke = tNow;

	// Check if a firewalled seeding client needs to start some new connections
	if ( IsCompleted() && Settings.Connection.FirewallStatus == CONNECTION_FIREWALLED )
	{
		// We might need to 'push' a connection if we don't have enough upload connections
		if ( m_pTorrentUploads.GetCount() < max( Settings.BitTorrent.UploadCount * 2, 5 ) )
		{
			if ( CanStartTransfers( tNow ) )
			{
				theApp.Message( MSG_DEBUG, _T("Attempting to push-start a BitTorrent upload")  ); 
				StartNewTransfer( tNow );
			}
		}
	}

	
	for ( POSITION pos = m_pTorrentUploads.GetHeadPosition() ; pos ; )
	{
		CUploadTransferBT* pTransfer = m_pTorrentUploads.GetNext( pos );
		if ( pTransfer->m_nProtocol != PROTOCOL_BT ) continue;
		
		if ( pTransfer->m_nRandomUnchoke == 2 )
		{
			if ( tNow - pTransfer->m_tRandomUnchoke >= Settings.BitTorrent.RandomPeriod )
			{
				pTransfer->m_nRandomUnchoke = 1;
			}
			else
			{
				bChooseRandom = FALSE;
			}
		}
		
		if ( pTransfer->m_bInterested )
			nTotalRandom += ( pTransfer->m_nRandomUnchoke == 0 ) ? 3 : 1;
	}
	
	if ( bChooseRandom && nTotalRandom > 0 )
	{
		nTotalRandom = rand() % nTotalRandom;
		
		for ( POSITION pos = m_pTorrentUploads.GetHeadPosition() ; pos ; )
		{
			CUploadTransferBT* pTransfer = m_pTorrentUploads.GetNext( pos );
			if ( pTransfer->m_nProtocol != PROTOCOL_BT ) continue;
			if ( pTransfer->m_bInterested == FALSE ) continue;
			
			int nWeight = ( pTransfer->m_nRandomUnchoke == 0 ) ? 3 : 1;
			
			if ( nTotalRandom < nWeight )
			{
				pTransfer->m_nRandomUnchoke = 2;
				pTransfer->m_tRandomUnchoke = tNow;
				pSelected.AddTail( pTransfer );
				break;
			}
			else
			{
				nTotalRandom -= nWeight;
			}
		}
	}
	
	while ( pSelected.GetCount() < Settings.BitTorrent.UploadCount )
	{
		CUploadTransferBT* pBest = NULL;
		DWORD nBest = 0;
		
		for ( POSITION pos = m_pTorrentUploads.GetHeadPosition() ; pos ; )
		{
			CUploadTransferBT* pTransfer = m_pTorrentUploads.GetNext( pos );
			
			if (	pTransfer->m_nProtocol == PROTOCOL_BT &&
					pTransfer->m_bInterested &&
					pSelected.Find( pTransfer->m_pClient ) == NULL &&
					pTransfer->GetAverageSpeed() >= nBest )
			{
				pBest = pTransfer;
				nBest = pTransfer->GetAverageSpeed();
			}
		}
		
		if ( pBest == NULL ) break;
		pSelected.AddTail( pBest->m_pClient );
	}
	
	while ( pSelected.GetCount() < Settings.BitTorrent.UploadCount )
	{
		CDownloadTransferBT* pBest = NULL;
		DWORD nBest = 0;
		
		for ( CDownloadTransferBT* pTransfer = (CDownloadTransferBT*)GetFirstTransfer()
				; pTransfer ; pTransfer = (CDownloadTransferBT*)pTransfer->m_pDlNext )
		{
			if (	pTransfer->m_nProtocol == PROTOCOL_BT &&
					pSelected.Find( pTransfer->m_pClient ) == NULL &&
					pTransfer->m_nState == dtsDownloading &&
					pTransfer->m_pClient->m_pUpload->m_bInterested &&
					pTransfer->GetAverageSpeed() >= nBest )
			{
				pBest = pTransfer;
				nBest = pTransfer->GetAverageSpeed();
			}
		}
		
		if ( pBest == NULL ) break;
		pSelected.AddTail( pBest->m_pClient );
	}
	
	for ( POSITION pos = m_pTorrentUploads.GetHeadPosition() ; pos ; )
	{
		CUploadTransferBT* pTransfer = m_pTorrentUploads.GetNext( pos );
		if ( pTransfer->m_nProtocol != PROTOCOL_BT ) continue;
		
		pTransfer->SetChoke(	pTransfer->m_bInterested == TRUE &&
								pSelected.Find( pTransfer->m_pClient ) == NULL );
	}
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithTorrent search -> tracker link

BOOL CDownloadWithTorrent::FindMoreSources()
{
	if ( m_pFile != NULL && m_bTorrentRequested )
	{
		ASSERT( m_pTorrent.IsAvailable() );
		
		if ( GetTickCount() - m_tTorrentSources > 15000 )
		{
			m_tTorrentTracker = GetTickCount() + Settings.BitTorrent.DefaultTrackerPeriod;
			m_tTorrentSources = GetTickCount();
			CBTTrackerRequest::SendUpdate( this, WORD( min( Settings.BitTorrent.DownloadConnections * 2, 100 ) ) );
			return TRUE;
		}
	}
	
	return FALSE;
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithTorrent seed

BOOL CDownloadWithTorrent::SeedTorrent(LPCTSTR pszTarget)
{
	CDownload* pDownload = reinterpret_cast<CDownload*>(this);
	
	if ( IsMoving() || IsCompleted() ) return FALSE;
	if ( m_sDiskName == pszTarget ) return FALSE;
	
	ASSERT( m_pFile != NULL );
	if ( m_pFile == NULL ) return FALSE;
	ASSERT( m_pFile->IsOpen() == FALSE );
	if ( m_pFile->IsOpen() ) return FALSE;
	delete m_pFile;
	m_pFile = NULL;

	GenerateTorrentDownloadID();
	
	pDownload->m_bSeeding	= TRUE;
	pDownload->m_bComplete	= TRUE;
	pDownload->m_tCompleted	= GetTickCount();
	
	memset( m_pTorrentBlock, TS_TRUE, m_nTorrentBlock );
	m_nTorrentSuccess = m_nTorrentBlock;
	
	if ( m_sDiskName.GetLength() > 0 )
	{
		ASSERT( FALSE );
		::DeleteFile( m_sDiskName );
		::DeleteFile( m_sDiskName + _T(".sd") );
	}
	
	m_sDiskName = pszTarget;
	SetModified();
	
	m_tTorrentTracker		= GetTickCount() + ( 60 * 1000 );
	m_bTorrentRequested		= TRUE;
	m_bTorrentStarted		= FALSE;
	m_nTorrentUploaded		= 0;
	m_nTorrentDownloaded	= 0;

	if ( Settings.Connection.FirewallStatus == CONNECTION_FIREWALLED && GetSourceCount() < 40 )
		CBTTrackerRequest::SendStarted( this );
	else
		CBTTrackerRequest::SendStarted( this, 0 );	
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithTorrent Close

void CDownloadWithTorrent::CloseTorrent()
{
	if ( m_bTorrentRequested ) CBTTrackerRequest::SendStopped( this );
	m_bTorrentRequested		= FALSE;
	m_bTorrentStarted		= FALSE;
	CloseTorrentUploads();
    m_pPeerID.clear();
}


//////////////////////////////////////////////////////////////////////
// CDownloadWithTorrent stats

float CDownloadWithTorrent::GetRatio() const
{
	if ( m_nTorrentUploaded == 0 || m_nTorrentDownloaded == 0 ) return 0;
	return (float)m_nTorrentUploaded / (float)m_nTorrentDownloaded;
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithTorrent Check if it's okay to start a new download transfer

BOOL CDownloadWithTorrent::CheckTorrentRatio() const
{
	if ( !m_oBTH ) return TRUE;									// Not a torrent
	
	if ( m_pTorrent.m_nStartDownloads == dtAlways ) return TRUE;// Torrent is set to download as needed

	if ( m_pTorrent.m_nStartDownloads == dtWhenRatio )			// Torrent is set to download only when ratio is okay
	{
		if ( m_nTorrentUploaded > m_nTorrentDownloaded ) return TRUE;	// Ratio OK
		if ( GetVolumeComplete() < 5 * 1024 * 1024 ) return TRUE;		// Always get at least 5 MB so you have something to upload	
	}

	return FALSE;
}

//////////////////////////////////////////////////////////////////////
// CDownloadWithTorrent check if upload exists

BOOL CDownloadWithTorrent::UploadExists(in_addr* pIP) const
{
	for ( POSITION pos = m_pTorrentUploads.GetHeadPosition() ; pos ; )
	{
		CUploadTransferBT* pTransfer = m_pTorrentUploads.GetNext( pos );

		if ( ( pTransfer->m_nProtocol == PROTOCOL_BT ) &&
			 ( pTransfer->m_nState != upsNull ) &&
			 ( pTransfer->m_pHost.sin_addr.S_un.S_addr == pIP->S_un.S_addr ) )
			return TRUE;
	}
	return FALSE;
}

BOOL CDownloadWithTorrent::UploadExists(const Hashes::BtGuid& oGUID) const
{
	for ( POSITION pos = m_pTorrentUploads.GetHeadPosition() ; pos ; )
	{
		CUploadTransferBT* pTransfer = m_pTorrentUploads.GetNext( pos );

		if ( ( pTransfer->m_nProtocol == PROTOCOL_BT ) &&
			 ( pTransfer->m_nState != upsNull ) &&
			 validAndEqual( oGUID, pTransfer->m_pClient->m_oGUID ) )
			return TRUE;
	}
	return FALSE;
}
