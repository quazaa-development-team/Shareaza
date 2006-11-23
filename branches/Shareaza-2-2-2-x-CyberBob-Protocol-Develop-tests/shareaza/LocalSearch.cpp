//
// LocalSearch.cpp
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
#include "LocalSearch.h"

#include "Library.h"
#include "LibraryFolders.h"
#include "SharedFile.h"
#include "SharedFolder.h"
#include "AlbumFolder.h"

#include "QuerySearch.h"
#include "GProfile.h"
#include "Network.h"
#include "Neighbours.h"
#include "Neighbour.h"
#include "Datagrams.h"
#include "G1Packet.h"
#include "G2Packet.h"
#include "Buffer.h"
#include "ZLib.h"
#include "GGEP.h"
#include "BTClients.h"

#include "Transfers.h"
#include "Downloads.h"
#include "Download.h"
#include "Uploads.h"
#include "UploadQueue.h"
#include "UploadQueues.h"
#include "ImageServices.h"

#include "XML.h"
#include "Schema.h"
#include "SchemaCache.h"

#include "SHA.h"
#include "TigerTree.h"
#include "ED2K.h"
#include "MD5.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif


//////////////////////////////////////////////////////////////////////
// CLocalSearch construction

CLocalSearch::CLocalSearch(CQuerySearch* pSearch, CNeighbour* pNeighbour, BOOL bWrapped)
{
	m_pSearch		= pSearch;
	m_pNeighbour	= pNeighbour;
	m_pEndpoint		= NULL;
	m_pBuffer		= NULL;
	m_nTTL			= Settings.Gnutella1.MaximumTTL - 3;
	m_nProtocol		= pNeighbour->m_nProtocol;
	m_bWrapped		= bWrapped;
	m_pPacket		= NULL;

	if ( m_bWrapped ) m_nProtocol = PROTOCOL_G1;
}

CLocalSearch::CLocalSearch(CQuerySearch* pSearch, SOCKADDR_IN* pEndpoint)
{
	m_pSearch		= pSearch;
	m_pNeighbour	= NULL;
	m_pEndpoint		= pEndpoint;
	m_pBuffer		= NULL;
	m_nTTL			= Settings.Gnutella1.MaximumTTL - 3;
	m_nProtocol		= PROTOCOL_G2;
	m_bWrapped		= FALSE;
	m_pPacket		= NULL;
}

CLocalSearch::CLocalSearch(CQuerySearch* pSearch, CBuffer* pBuffer, PROTOCOLID nProtocol)
{
	m_pSearch		= pSearch;
	m_pNeighbour	= NULL;
	m_pEndpoint		= NULL;
	m_pBuffer		= pBuffer;
	m_nTTL			= Settings.Gnutella1.MaximumTTL - 3;
	m_nProtocol		= nProtocol;
	m_bWrapped		= FALSE;
	m_pPacket		= NULL;
}

CLocalSearch::~CLocalSearch()
{
	GetXMLString();
}

//////////////////////////////////////////////////////////////////////
// CLocalSearch execute

INT_PTR CLocalSearch::Execute(INT_PTR nMaximum)
{
	if ( m_pBuffer == NULL )
	{
		if ( UploadQueues.GetQueueRemaining() == 0 ) return 0;
	}

	if ( nMaximum == -1 )
		nMaximum = 0;
	else
		nMaximum = Settings.Gnutella.MaxHits;

	if ( m_pSearch )
	{
		m_oGUID = m_pSearch->m_oGUID;
	}
	else
	{
		Network.CreateID( m_oGUID );
	}

	INT_PTR nCount = ExecuteSharedFiles( nMaximum );

	if ( m_pSearch != NULL && m_pSearch->m_bWantPFS && m_nProtocol == PROTOCOL_G2 )
	{
		if ( nMaximum == 0 || nCount < nMaximum )
		{
			nCount += ExecutePartialFiles( nMaximum ? nMaximum - nCount : 0 );
		}
	}

	return nCount;
}

//////////////////////////////////////////////////////////////////////
// CLocalSearch execute shared files

INT_PTR CLocalSearch::ExecuteSharedFiles(INT_PTR nMaximum)
{
	CQuickLock oLock( Library.m_pSection );
	CList< CLibraryFile* >* pFiles = Library.Search( m_pSearch, static_cast< int >( nMaximum ) );
	if ( pFiles == NULL ) return 0;

	INT_PTR nHits = pFiles->GetCount();

	while ( pFiles->GetCount() )
	{
		int nInThisPacket = (int)min( pFiles->GetCount(), (int)Settings.Gnutella.HitsPerPacket );

		CreatePacket( nInThisPacket );

		int nHitB = 0;
		for ( int nHitA = 0 ; nHitA < nInThisPacket ; nHitA++ )
		{
			CLibraryFile* pFile = (CLibraryFile*)pFiles->RemoveHead();
			if ( AddHit( pFile, nHitB ) ) nHitB ++;
		}

		WriteTrailer();
		if ( nHitB > 0 ) DispatchPacket(); else DestroyPacket();
	}

	delete pFiles;

	return nHits;
}

//////////////////////////////////////////////////////////////////////
// CLocalSearch add file hit

BOOL CLocalSearch::AddHit(CLibraryFile* pFile, int nIndex)
{
	ASSERT( m_pPacket != NULL );

	if ( m_nProtocol == PROTOCOL_G1 )
	{
		if ( ! Settings.Gnutella1.EnableToday ) 
		{
			theApp.Message( MSG_ERROR, _T("CLocalSearch::AddHit() dropping G1 hit G1- network not enabled ") );
			return FALSE;
		}
		if ( ! AddHitG1( pFile, nIndex ) ) return FALSE;
	}
	else
	{
		if ( ! AddHitG2( pFile, nIndex ) ) return FALSE;
	}

	return TRUE;
}

BOOL CLocalSearch::AddHitG1(CLibraryFile* pFile, int /* nIndex */ )
{
	// Check that the file is actually available. (We must not return ghost hits to G1!)
	if ( ! pFile->IsAvailable() ) return FALSE;

	// Check that a queue that can upload this file exists, and isn't insanely long.
	if ( UploadQueues.QueueRank( PROTOCOL_HTTP, pFile ) > Settings.Gnutella1.HitQueueLimit ) return FALSE;
	// Normally this isn't a problem- the default queue length is 8 to 10, so this check (50) will
	// never be activated. However, sometimes users configure bad settings, such as a 2000 user HTTP
	// queue. Although the remote client could/should handle this by itself, we really should give
	// Gnutella some protection against 'extreme' settings (if only to reduce un-necessary traffic.)


	// CyberBob's comment.
	// above comment is just a complain but it is because the main developer, not gonna mention the name, never
	// gonna support PARQ queue.

	m_pPacket->WriteLongLE( pFile->m_nIndex );
	m_pPacket->WriteLongLE( (DWORD)min( pFile->GetSize(), 0xFFFFFFFF ) );
	if ( Settings.Gnutella1.QueryHitUTF8 ) //Support UTF-8 Query
	{
		m_pPacket->WriteStringUTF8( pFile->m_sName );
	}
	else
	{
		m_pPacket->WriteString( pFile->m_sName );
	}
	
	CGGEPBlock pBlock;
	BOOL	bHuge	= FALSE;
	CString strHash;

	if ( pFile->m_oSHA1 &&  pFile->m_oTiger )
	{
		//strHash = "urn:bitprint:" + pFile->m_oSHA1.toString() + "." + pFile->m_oTiger.toString();
		strHash = pFile->m_oSHA1.toUrn();
		m_pPacket->WriteString( strHash, FALSE );
		bHuge	= TRUE;

		CGGEPItem* pItem = pBlock.Add( _T("H") );
		pItem->SetCOBS();
		pItem->SetSmall();
		pItem->WriteByte( 2 );
		pItem->Write( &pFile->m_oSHA1[ 0 ], 20 );
		pItem->Write( &pFile->m_oTiger[ 0 ], 24 );

	}
	else if ( pFile->m_oSHA1 )
	{
		strHash = pFile->m_oSHA1.toUrn();
		m_pPacket->WriteString( strHash, FALSE );
		bHuge	= TRUE;

		CGGEPItem* pItem = pBlock.Add( _T("H") );
		pItem->SetCOBS();
		pItem->SetSmall();
		pItem->WriteByte( 1 );
		pItem->Write( &pFile->m_oSHA1[ 0 ], 20 );
	}
	else if ( pFile->m_oTiger )
	{
		strHash = "urn:tth:" + pFile->m_oTiger.toString();
		m_pPacket->WriteString( strHash, FALSE );
		bHuge	= TRUE;
	}

	if ( pFile->m_oED2K )
	{
		if ( !bHuge )
		{
			strHash = "urn:ed2k:" + pFile->m_oED2K.toString();
			m_pPacket->WriteString( strHash, FALSE );
			bHuge	= TRUE;
		}
		else
		{
			CGGEPItem* pItem;
			pItem = pBlock.Add( L"u" );
			pItem->SetCOBS();
			pItem->SetSmall();
			strHash = "ed2k:"+ pFile->m_oED2K.toString();
			pItem->WriteUTF8(strHash);
		}
	}

	if ( pFile->m_oMD5 )
	{
		if ( !bHuge )
		{
			strHash = pFile->m_oMD5.toUrn();
			m_pPacket->WriteString( strHash, FALSE );
			bHuge	= TRUE;
		}
		else
		{
			CGGEPItem* pItem = pBlock.Add( _T("H") );
			pItem->SetCOBS();
			pItem->SetSmall();
			pItem->WriteByte( 3 );
			pItem->Write( &pFile->m_oMD5[ 0 ], 16 );
		}
	}
	
	/* if ( pFile->m_pSchema != NULL && pFile->m_pMetadata != NULL && ( m_pSearch == NULL || m_pSearch->m_bWantXML ) )
	{
		AddMetadata( pFile->m_pSchema, pFile->m_pMetadata, nIndex );
	} */

	if ( !pBlock.IsEmpty() )
	{
		if ( bHuge ) m_pPacket->WriteByte( 0x1C );
		pBlock.Write( m_pPacket );
	}

	m_pPacket->WriteByte( 0 );

	return TRUE;
}

BOOL CLocalSearch::AddHitG2(CLibraryFile* pFile, int /*nIndex*/)
{
	CG2Packet* pPacket = (CG2Packet*)m_pPacket;
	CString strMetadata, strComment, strFolderName;
	BOOL bCollection = FALSE;
	BOOL bPreview = FALSE;
	DWORD nGroup = 0;

	// Pass 1: Calculate child group size
	
	if ( pFile->m_oTiger && pFile->m_oSHA1 )
	{
        nGroup += 5 + 3 + Hashes::Sha1Hash::byteCount + Hashes::TigerHash::byteCount;
	}
	else if ( pFile->m_oTiger )
	{
		nGroup += 5 + 4 + Hashes::TigerHash::byteCount;
	}
	else if ( pFile->m_oSHA1 )
	{
		nGroup += 5 + 5 + Hashes::Sha1Hash::byteCount;
	}
	
	if ( pFile->m_oED2K )
	{
		nGroup += 5 + 5 + Hashes::Ed2kHash::byteCount;
	}

	if ( pFile->m_oMD5 )
	{
		nGroup += 5 + 4 + Hashes::Md5Hash::byteCount;
	}

	strFolderName = pFile->GetFolderName();

	if (strFolderName.GetLength() > 0)
	{
		nGroup += 4 + pPacket->GetStringLen( strFolderName );
	}

	if ( m_pSearch == NULL || m_pSearch->m_bWantDN )
	{
		if ( pFile->GetSize() <= 0xFFFFFFFF )
		{
			nGroup += 8 + pPacket->GetStringLen( pFile->m_sName );
		}
		else
		{
			nGroup += 4 + 8;
			nGroup += 4 + pPacket->GetStringLen( pFile->m_sName );
		}

		if ( LPCTSTR pszType = _tcsrchr( pFile->m_sName, '.' ) )
		{
			if ( _tcsicmp( pszType, _T(".co") ) == 0 ||
				 _tcsicmp( pszType, _T(".collection") ) == 0 )
			{
				if ( ! pFile->m_bBogus )
				{
					nGroup += 2 + 7;
					bCollection = TRUE;
				}
			}
		}
	}

	if ( pFile->IsAvailable() && ( m_pSearch == NULL || m_pSearch->m_bWantURL ) )
	{
		nGroup += 5;
		if ( pFile->m_pSources.GetCount() ) nGroup += 7;

		if ( Settings.Uploads.SharePreviews )
		{
			CImageServices pServices;
			bool bPreviewEnabled = pServices.IsFileViewable( (LPCTSTR)pFile->m_sName ) == TRUE;

			if ( pFile->m_bCachedPreview || Settings.Uploads.DynamicPreviews && bPreviewEnabled )
			{
				bPreview = TRUE;
			}
		}

		if ( bPreview ) nGroup += 5;
	}

	if ( pFile->m_pMetadata != NULL && ( m_pSearch == NULL || m_pSearch->m_bWantXML ) )
	{
		strMetadata = pFile->m_pMetadata->ToString();
		int nMetadata = pPacket->GetStringLen( strMetadata );
		nGroup += 4 + nMetadata;
		if ( nMetadata > 0xFF )
		{
			nGroup ++;
			if ( nMetadata > 0xFFFF ) nGroup ++;
		}
	}

	if ( m_pSearch == NULL || m_pSearch->m_bWantCOM )
	{
		if ( pFile->m_nRating > 0 || pFile->m_sComments.GetLength() > 0 )
		{
			if ( pFile->m_nRating > 0 )
			{
				strComment.Format( _T("<comment rating=\"%i\">"), pFile->m_nRating - 1 );
				CXMLNode::ValueToString( pFile->m_sComments, strComment );
				if ( strComment.GetLength() > 2048 ) strComment = strComment.Left( 2048 );
				strComment += _T("</comment>");
			}
			else
			{
				strComment = _T("<comment>");
				CXMLNode::ValueToString( pFile->m_sComments, strComment );
				if ( strComment.GetLength() > 2048 ) strComment = strComment.Left( 2048 );
				strComment += _T("</comment>");
			}

			Replace( strComment, _T("\r\n"), _T("{n}") );
			int nComment = pPacket->GetStringLen( strComment );
			nGroup += 5 + nComment;
			if ( nComment > 0xFF )
			{
				nGroup ++;
				if ( nComment > 0xFFFF ) nGroup ++;
			}
		}

		if ( pFile->m_bBogus ) nGroup += 7;
	}
	else
	{
		if ( ! pFile->IsAvailable() ) return FALSE;
	}

	if ( m_pSearch == NULL ) nGroup += 8;

	nGroup += 4;

	// Pass 2: Write the child packet

	pPacket->WritePacket( "H", nGroup, TRUE );
	
	if ( pFile->m_oTiger && pFile->m_oSHA1 ) //Send Bitprint hash
	{
		pPacket->WritePacket( "URN", 3 + Hashes::Sha1Hash::byteCount + Hashes::TigerHash::byteCount );
		pPacket->WriteString( "bp" );
		pPacket->Write( pFile->m_oSHA1 );
		pPacket->Write( pFile->m_oTiger );
	}
	else if ( pFile->m_oTiger ) // send Tiger hash
	{
		pPacket->WritePacket( "URN", 4 + Hashes::TigerHash::byteCount );
		pPacket->WriteString( "ttr" );
		pPacket->Write( pFile->m_oTiger );
	}
	else if ( pFile->m_oSHA1 ) // Send SHA1 hash
	{
		pPacket->WritePacket( "URN", 5 + Hashes::Sha1Hash::byteCount );
		pPacket->WriteString( "sha1" );
		pPacket->Write( pFile->m_oSHA1 );
	}
	
	if ( pFile->m_oED2K ) // Send ED2K hash
	{
		pPacket->WritePacket( "URN", 5 + Hashes::Ed2kHash::byteCount );
		pPacket->WriteString( "ed2k" );
		pPacket->Write( pFile->m_oED2K );
	}

	if ( pFile->m_oMD5 ) // Send MD5 hash
	{
		pPacket->WritePacket( "URN", 4 + Hashes::Md5Hash::byteCount );
		pPacket->WriteString( "md5" );
		pPacket->Write( pFile->m_oMD5 );
	}

	if (strFolderName.GetLength() > 0 ) // Send Folder name in Hit packet
	{
		pPacket->WritePacket( "FN", pPacket->GetStringLen( strFolderName ) );
		pPacket->WriteString( strFolderName, FALSE );
	}

	if ( m_pSearch == NULL || m_pSearch->m_bWantDN ) // want File name or File Size
	{
		if ( pFile->GetSize() <= 0xFFFFFFFF ) // Filesize is less than 4GB so it will be stored in first 4Byte of DN
		{
			pPacket->WritePacket( "DN", pPacket->GetStringLen( pFile->m_sName ) + 4 ); // size of packet is 4byte plus String length
			pPacket->WriteLongBE( (DWORD)pFile->GetSize() ); // Put file size in 4byte length (less than 4GB)
			pPacket->WriteString( pFile->m_sName, FALSE ); // put File name on remaining field
		}
		else // File size is bigger than 4GB so File size has to be in SZ with 8Byte length
		{
			pPacket->WritePacket( "SZ", 8 );  // Size of packet is 8Byte for 64Bit file size field
			pPacket->WriteInt64( pFile->GetSize() ); // put filesize in 64bit(8byte) QWORD
			pPacket->WritePacket( "DN", pPacket->GetStringLen( pFile->m_sName ) ); // packet length of DN is length of filename
			pPacket->WriteString( pFile->m_sName, FALSE ); // put file name in the field
		}

		if ( bCollection ) pPacket->WritePacket( "COLLECT", 0 ); // if it is Collection then put blank packet "COLLECT"
	}

	{
		CSingleLock pQueueLock( &UploadQueues.m_pSection, TRUE ); // lock up Upload Queue to prevent crash on queue check

		CUploadQueue* pQueue = UploadQueues.SelectQueue( PROTOCOL_HTTP, pFile ); // get Queue which the file can be uploaded
		pPacket->WritePacket( "G", 1 );
		pPacket->WriteByte( BYTE( pQueue ? pQueue->m_nIndex + 1 : 0 ) );
	}

	if ( pFile->IsAvailable() && ( m_pSearch == NULL || m_pSearch->m_bWantURL ) )
	{
		pPacket->WritePacket( "URL", 0 );

		if ( INT_PTR nCount = pFile->m_pSources.GetCount() )
		{
			pPacket->WritePacket( "CSC", 2 );
			pPacket->WriteShortBE( (WORD)nCount );
		}

		if ( bPreview )
		{
			pPacket->WritePacket( "PVU", 0 );
		}
	}

	if ( strMetadata.GetLength() )
	{
		pPacket->WritePacket( "MD", pPacket->GetStringLen( strMetadata ) );
		pPacket->WriteString( strMetadata, FALSE );
	}

	if ( m_pSearch == NULL || m_pSearch->m_bWantCOM )
	{
		if ( strComment.GetLength() )
		{
			pPacket->WritePacket( "COM", pPacket->GetStringLen( strComment ) );
			pPacket->WriteString( strComment, FALSE );
		}

		if ( pFile->m_bBogus ) pPacket->WritePacket( "BOGUS", 0 );
	}

	if ( m_pSearch == NULL )
	{
		pPacket->WritePacket( "ID", 4 );
		pPacket->WriteLongBE( pFile->m_nIndex );
	}

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CLocalSearch execute partial files

int CLocalSearch::ExecutePartialFiles(INT_PTR nMaximum)
{
	ASSERT( m_nProtocol == PROTOCOL_G2 );
	ASSERT( m_pSearch != NULL );
	
	if ( !m_pSearch->m_oTiger && !m_pSearch->m_oSHA1 &&
		 !m_pSearch->m_oED2K && !m_pSearch->m_oBTH ) return 0;
	
	CSingleLock pLock( &Transfers.m_pSection );
	if ( ! pLock.Lock( 50 ) ) return 0;

	int nCount = 0;
	m_pPacket = NULL;

	for ( POSITION pos = Downloads.GetIterator() ; pos && ( nMaximum == 0 || nCount < nMaximum ); )
	{
		CDownload* pDownload = Downloads.GetNext( pos );

		if ( ! pDownload->IsShared() ) continue;
		
		if (	validAndEqual( m_pSearch->m_oTiger, pDownload->m_oTiger )
			||	validAndEqual( m_pSearch->m_oSHA1, pDownload->m_oSHA1 )
			||	validAndEqual( m_pSearch->m_oED2K, pDownload->m_oED2K )
			||	validAndEqual( m_pSearch->m_oMD5, pDownload->m_oMD5 ) 
			||	validAndEqual( m_pSearch->m_oBTH, pDownload->m_oBTH ) )
		{
			if ( pDownload->m_oBTH || pDownload->IsStarted() )
			{
				if ( m_pPacket == NULL ) CreatePacketG2();
				AddHit( pDownload, nCount++ );
			}
		}
	}

	if ( m_pPacket != NULL )
	{
		WriteTrailerG2();
		DispatchPacket();
	}

	return nCount;
}

//////////////////////////////////////////////////////////////////////
// CLocalSearch add download hit

void CLocalSearch::AddHit(CDownload* pDownload, int /*nIndex*/)
{
	ASSERT( m_pPacket != NULL );
	CG2Packet* pPacket = (CG2Packet*)m_pPacket;
	DWORD nGroup = 2 + 4 + 4;
	CString strURL;
	
    if ( pDownload->m_oTiger && pDownload->m_oSHA1 )
	{
        nGroup += 5 + 3 + Hashes::Sha1Hash::byteCount + Hashes::TigerHash::byteCount;
	}
	else if ( pDownload->m_oSHA1 )
	{
		nGroup += 5 + 5 + Hashes::Sha1Hash::byteCount;
	}
    else if ( pDownload->m_oTiger )
	{
		nGroup += 5 + 4 + Hashes::TigerHash::byteCount;
	}
	
	if ( pDownload->m_oED2K )
	{
		nGroup += 5 + 5 + Hashes::Ed2kHash::byteCount;
	}

	if ( pDownload->m_oMD5 )
	{
		nGroup += 5 + 4 + Hashes::Md5Hash::byteCount;
	}

	if ( pDownload->m_oBTH )
	{
		nGroup += 5 + 5 + Hashes::BtHash::byteCount;
	}

	if ( m_pSearch->m_bWantDN )
	{
		nGroup += 8 + pPacket->GetStringLen( pDownload->m_sDisplayName );
	}

	if ( m_pSearch->m_bWantURL )
	{
		nGroup += 5;

		// if ( m_pSearch->m_bBTH && pDownload->m_pTorrent.IsAvailable() && Network.IsListening() )
		
		if ( m_pSearch->m_oBTH && pDownload->m_pTorrent.IsAvailable() && Network.m_pHost.sin_addr.S_un.S_addr != 0 )
		{
			strURL.Format( _T("btc://%s:%i/%s/%s/"),
				(LPCTSTR)CString( inet_ntoa( Network.m_pHost.sin_addr ) ),
				htons( Network.m_pHost.sin_port ),
				(LPCTSTR)pDownload->m_pPeerID.toString(),
				(LPCTSTR)pDownload->m_oBTH.toString() );
			nGroup += pPacket->GetStringLen( strURL );
		}
	}

	pPacket->WritePacket( "H", nGroup, TRUE );
	
    if ( pDownload->m_oTiger && pDownload->m_oSHA1 )
	{
        pPacket->WritePacket( "URN", 3 + Hashes::Sha1Hash::byteCount + Hashes::TigerHash::byteCount );
		pPacket->WriteString( "bp" );
		pPacket->Write( pDownload->m_oSHA1 );
		pPacket->Write( pDownload->m_oTiger );
	}
    else if ( pDownload->m_oTiger )
	{
		pPacket->WritePacket( "URN", 4 + Hashes::TigerHash::byteCount );
		pPacket->WriteString( "ttr" );
		pPacket->Write( pDownload->m_oTiger );
	}
	else if ( pDownload->m_oSHA1 )
	{
		pPacket->WritePacket( "URN", 5 + Hashes::Sha1Hash::byteCount );
		pPacket->WriteString( "sha1" );
		pPacket->Write( pDownload->m_oSHA1 );
	}
	
	if ( pDownload->m_oED2K )
	{
		pPacket->WritePacket( "URN", 5 + Hashes::Ed2kHash::byteCount );
		pPacket->WriteString( "ed2k" );
		pPacket->Write( pDownload->m_oED2K );
	}

	if ( pDownload->m_oMD5 )
	{
		pPacket->WritePacket( "URN", 4 + Hashes::Ed2kHash::byteCount );
		pPacket->WriteString( "md5" );
		pPacket->Write( pDownload->m_oMD5 );
	}

	if ( pDownload->m_oBTH )
	{
        pPacket->WritePacket( "URN", 5 + Hashes::BtHash::byteCount );
		pPacket->WriteString( "btih" );
		pPacket->Write( pDownload->m_oBTH );
	}

	if ( m_pSearch->m_bWantDN )
	{
		if ( pDownload->m_nSize <= 0xFFFFFFFF )
		{
			pPacket->WritePacket( "DN", pPacket->GetStringLen( pDownload->m_sDisplayName ) + 4 );
			pPacket->WriteLongBE( (DWORD)pDownload->m_nSize );
			pPacket->WriteString( pDownload->m_sDisplayName, FALSE );
		}
		else
		{
			pPacket->WritePacket( "SZ", 8 );
			pPacket->WriteInt64( pDownload->m_nSize );
			pPacket->WritePacket( "DN", pPacket->GetStringLen( pDownload->m_sDisplayName ) );
			pPacket->WriteString( pDownload->m_sDisplayName, FALSE );
		}
	}

	if ( m_pSearch->m_bWantURL )
	{
		if ( strURL.GetLength() > 0 )
		{
			pPacket->WritePacket( "URL", pPacket->GetStringLen( strURL ) );
			pPacket->WriteString( strURL, FALSE );
		}
		else
		{
			pPacket->WritePacket( "URL", 0 );
		}
	}

	QWORD nComplete = pDownload->GetVolumeComplete();

	if ( nComplete <= 0xFFFFFFFF )
	{
		pPacket->WritePacket( "PART", 4 );
		pPacket->WriteLongBE( (DWORD)nComplete );
	}
	else
	{
		pPacket->WritePacket( "PART", 8 );
		pPacket->WriteInt64( nComplete );
	}
}

//////////////////////////////////////////////////////////////////////
// CLocalSearch create packet

void CLocalSearch::CreatePacket(int nCount)
{
	ASSERT( m_pPacket == NULL );

	if ( m_nProtocol == PROTOCOL_G1 )
		CreatePacketG1( nCount );
	else
		CreatePacketG2();

	if ( m_pSchemas.GetCount() ) GetXMLString();
}

void CLocalSearch::CreatePacketG1(int nCount)
{
	m_pPacket = CG1Packet::New( G1_PACKET_HIT, m_nTTL, m_oGUID );
	
	m_pPacket->WriteByte( BYTE( nCount ) );
	m_pPacket->WriteShortLE( htons( Network.m_pHost.sin_port ) );
	m_pPacket->WriteLongLE( Network.m_pHost.sin_addr.S_un.S_addr );

	if ( Uploads.m_bStable )
	{
		m_pPacket->WriteLongLE( Uploads.m_nBestSpeed * 8 / 1024 );
	}
	else
	{
		m_pPacket->WriteLongLE( Settings.Connection.OutSpeed );
	}
}

void CLocalSearch::CreatePacketG2()
{
	CG2Packet* pPacket = CG2Packet::New( G2_PACKET_HIT, TRUE );
	m_pPacket = pPacket;

	pPacket->WritePacket( "GU", 16 );
	pPacket->Write( Hashes::Guid( MyProfile.oGUID ) );
	
	if ( TRUE /* Network.IsListening() */ )
	{
		pPacket->WritePacket( "NA", 6 );
		pPacket->WriteLongLE( Network.m_pHost.sin_addr.S_un.S_addr );
		pPacket->WriteShortBE( htons( Network.m_pHost.sin_port ) );
	}

	pPacket->WritePacket( "V", 4 );
	pPacket->WriteString( SHAREAZA_VENDOR_A, FALSE );

	if ( ! Network.IsStable() || ! Datagrams.IsStable() ||  Network.IsFirewalled() )
	{
		pPacket->WritePacket( "FW", 0 );
	}

	{
		CSingleLock pNetLock( &Network.m_pSection );

		if ( pNetLock.Lock( 50 ) )
		{
			for ( POSITION pos = Neighbours.GetIterator() ; pos ; )
			{
				CNeighbour* pNeighbour = Neighbours.GetNext( pos );

				if ( pNeighbour->m_nNodeType != ntLeaf &&
					 pNeighbour->m_nProtocol == PROTOCOL_G2 )
				{
					pPacket->WritePacket( "NH", 6 );
					pPacket->WriteLongLE( pNeighbour->m_pHost.sin_addr.S_un.S_addr );
					pPacket->WriteShortBE( htons( pNeighbour->m_pHost.sin_port ) );
				}
			}
		}
	}

	if ( ! Uploads.m_bStable ) pPacket->WritePacket( "UNSTA", 0 );

	CSingleLock pQueueLock( &UploadQueues.m_pSection );
	int nQueue = 1;

	if ( pQueueLock.Lock() )
	{
		for ( POSITION pos = UploadQueues.GetIterator() ; pos ; nQueue++ )
		{
			CUploadQueue* pQueue = UploadQueues.GetNext( pos );
			pPacket->WritePacket( "HG", ( 4 + 7 ) + 2, TRUE );
			pPacket->WritePacket( "SS", 7 );
			pPacket->WriteShortBE( WORD( pQueue->GetQueuedCount() + pQueue->GetTransferCount() ) );
			pPacket->WriteByte( BYTE( pQueue->GetTransferCount( TRUE ) ) );
			pPacket->WriteLongBE( pQueue->GetPredictedBandwidth() * 8 / 1024 );
			pPacket->WriteByte( 0 );
			pPacket->WriteByte( BYTE( nQueue ) );
		}

		pQueueLock.Unlock();
	}

	CString strNick = MyProfile.GetNick();
	if ( strNick.GetLength() > 32 ) strNick = strNick.Left( 32 );

	if ( strNick.GetLength() )
	{
		int nNick = pPacket->GetStringLen( strNick );
		pPacket->WritePacket( "UPRO", nNick + 6, TRUE );
		pPacket->WritePacket( "NICK", nNick );
		pPacket->WriteString( strNick, FALSE );
	}

	if ( Settings.Community.ServeProfile ) pPacket->WritePacket( "BUP", 0 );
	if ( Settings.Community.ServeFiles ) pPacket->WritePacket( "BH", 0 );
	if ( Settings.Community.ChatEnable ) pPacket->WritePacket( "PCH", 0 );
}

//////////////////////////////////////////////////////////////////////
// CLocalSearch meta data

void CLocalSearch::AddMetadata(CSchema* pSchema, CXMLElement* pXML, int nIndex)
{
	ASSERT( pSchema != NULL );
	ASSERT( pXML != NULL );
	ASSERT( pXML->GetParent() == NULL );

	CXMLElement* pGroup;

	if ( ! m_pSchemas.Lookup( pSchema, pGroup ) )
	{
		pGroup = pSchema->Instantiate();
		m_pSchemas.SetAt( pSchema, pGroup );
	}

	CString strIndex;
	strIndex.Format( _T("%lu"), nIndex );

	pXML->AddAttribute( _T("index"), strIndex );
	pGroup->AddElement( pXML );
}

//////////////////////////////////////////////////////////////////////
// CLocalSearch XML to string

CString CLocalSearch::GetXMLString()
{
	CString strXML;

	for ( POSITION pos1 = m_pSchemas.GetStartPosition() ; pos1 ; )
	{
		CXMLElement* pGroup;
		CSchema* pSchema;

		m_pSchemas.GetNextAssoc( pos1, pSchema, pGroup );

		strXML += _T("<?xml version=\"1.0\"?>\r\n");
		pGroup->ToString( strXML, TRUE );

		for ( POSITION pos2 = pGroup->GetElementIterator() ; pos2 ; )
		{
			CXMLElement* pChild = pGroup->GetNextElement( pos2 );
			pChild->DeleteAttribute( _T("index") );
			pChild->Detach();
		}

		delete pGroup;
	}

	m_pSchemas.RemoveAll();

	return strXML;
}

//////////////////////////////////////////////////////////////////////
// CLocalSearch core trailer

void CLocalSearch::WriteTrailer()
{
	ASSERT( m_pPacket != NULL );

	if ( m_nProtocol == PROTOCOL_G1 )
		WriteTrailerG1();
	else
		WriteTrailerG2();
}

void CLocalSearch::WriteTrailerG1()
{
	m_pPacket->WriteString( SHAREAZA_VENDOR_T, FALSE );

	BYTE nFlags[2] = { 0, 0 };

	nFlags[0] |= G1_QHD_BUSY|G1_QHD_STABLE|G1_QHD_SPEED;
	nFlags[1] |= G1_QHD_PUSH;

	if ( ! Network.IsListening() ) nFlags[0] |= G1_QHD_PUSH;
	if ( Uploads.m_bStable ) nFlags[1] |= G1_QHD_STABLE;
	if ( Uploads.m_bStable ) nFlags[1] |= G1_QHD_SPEED;
	if ( ! UploadQueues.IsTransferAvailable() ) nFlags[1] |= G1_QHD_BUSY;

	if ( Settings.Community.ServeFiles && Settings.Gnutella1.EnableGGEP )
	{
		nFlags[0] |= G1_QHD_GGEP;
		nFlags[1] |= G1_QHD_GGEP;
	}

	CString strXML		= GetXMLString();
	DWORD nCompressed	= 0;
	auto_array< BYTE > pCompressed;

	m_pPacket->WriteByte( strXML.IsEmpty() ? 2 : 4 );
	m_pPacket->WriteByte( nFlags[0] );
	m_pPacket->WriteByte( nFlags[1] );

	LPSTR pszXML = NULL;
	int nXML = 0;

	if ( strXML.GetLength() > 0 )
	{
		nXML = WideCharToMultiByte( CP_ACP, 0, strXML, -1, NULL, 0, NULL, NULL );
		pszXML = new CHAR[ nXML ];
		WideCharToMultiByte( CP_ACP, 0, strXML, -1, pszXML, nXML, NULL, NULL );
		if ( nXML > 0 ) nXML --;

		pCompressed = CZLib::Compress( pszXML, nXML, &nCompressed );

		if ( nCompressed + 9 < (DWORD)nXML + 11 && pCompressed.get() != NULL )
		{
			m_pPacket->WriteShortLE( (WORD)( nCompressed + 9 + 1 ) );
		}
		else
		{
			m_pPacket->WriteShortLE( WORD( nXML + 11 + 1 ) );
			pCompressed.reset();
		}
	}

	m_pPacket->WriteByte( Settings.Community.ChatEnable ? 1 : 0 );

	if ( Settings.Community.ServeFiles && Settings.Gnutella1.EnableGGEP )
	{
		m_pPacket->WriteByte( GGEP_MAGIC );
		m_pPacket->WriteByte( GGEP_HDR_LAST | 2 );
		m_pPacket->WriteByte( 'B' );
		m_pPacket->WriteByte( 'H' );
		m_pPacket->WriteByte( GGEP_LEN_LAST );
	}

	if ( pCompressed.get() != NULL )
	{
		m_pPacket->Write( "{deflate}", 9 );
		m_pPacket->Write( pCompressed.get(), nCompressed );
		m_pPacket->WriteByte( 0 );
	}
	else if ( pszXML != NULL )
	{
		m_pPacket->Write( "{plaintext}", 11 );
		m_pPacket->Write( pszXML, nXML );
	}

	if ( pszXML != NULL ) delete [] pszXML;

	m_pPacket->Write( Hashes::Guid( MyProfile.oGUID ) );
}

void CLocalSearch::WriteTrailerG2()
{
	CG2Packet* pPacket = (CG2Packet*)m_pPacket;

	pPacket->WriteByte( 0 );
	pPacket->WriteByte( 0 );
	pPacket->Write( m_oGUID );
}

//////////////////////////////////////////////////////////////////////
// CLocalSearch dispatch packet

void CLocalSearch::DispatchPacket()
{
	ASSERT( m_pPacket != NULL );

	if ( m_pNeighbour != NULL )
	{
		if ( m_bWrapped )
		{
			// ****Debug
			theApp.Message( MSG_DEFAULT, _T("CLocalSearch::DispatchPacket() Wrapped query hit created") );
			// ****

			CG2Packet* pG2 = CG2Packet::New( G2_PACKET_HIT_WRAP, (CG1Packet*)m_pPacket );
			m_pPacket->Release();
			m_pPacket = pG2;
		}

		m_pNeighbour->Send( m_pPacket, FALSE, TRUE );
	}

	if ( m_pEndpoint != NULL )
	{
		Datagrams.Send( m_pEndpoint, (CG2Packet*)m_pPacket, FALSE );
	}

	if ( m_pBuffer != NULL )
	{
		m_pPacket->ToBuffer( m_pBuffer );
	}

	m_pPacket->Release();
	m_pPacket = NULL;
}

void CLocalSearch::DestroyPacket()
{
	if ( m_pPacket != NULL )
	{
		m_pPacket->Release();
		m_pPacket = NULL;
	}
}

//////////////////////////////////////////////////////////////////////
// CLocalSearch physical and virtual folder tree

void CLocalSearch::WriteVirtualTree()
{
	CSingleLock oLock( &Library.m_pSection );
	if ( oLock.Lock( 100 ) )
	{
		m_pPacket = AlbumToPacket( Library.GetAlbumRoot() );
		oLock.Unlock();
		if ( m_pPacket != NULL ) DispatchPacket();
	}

	if ( oLock.Lock( 100 ) )
	{
		m_pPacket = FoldersToPacket();
		oLock.Unlock();
		if ( m_pPacket != NULL ) DispatchPacket();
	}
}

CG2Packet* CLocalSearch::AlbumToPacket(CAlbumFolder* pFolder)
{
	if ( pFolder == NULL ) return NULL;

	if ( pFolder->m_pSchema != NULL && pFolder->m_pSchema->m_bPrivate ) return NULL;
	if ( pFolder->GetSharedCount() == 0 ) return NULL;

	CG2Packet* pPacket = CG2Packet::New( "VF", TRUE );

	if ( pFolder->m_pSchema != NULL )
	{
		CXMLElement* pXML = pFolder->m_pSchema->Instantiate( TRUE );

		if ( pFolder->m_pXML != NULL )
		{
			pXML->AddElement( pFolder->m_pXML->Clone() );
		}
		else
		{
			CXMLElement* pBody = pXML->AddElement( pFolder->m_pSchema->m_sSingular );
			pBody->AddAttribute( pFolder->m_pSchema->GetFirstMemberName(), pFolder->m_sName );
		}

		CString strXML = pXML->ToString();
		delete pXML;

		pPacket->WritePacket( "MD", pPacket->GetStringLen( strXML ) );
		pPacket->WriteString( strXML, FALSE );
	}

	for ( POSITION pos = pFolder->GetFolderIterator() ; pos ; )
	{
		if ( CG2Packet* pChild = AlbumToPacket( pFolder->GetNextFolder( pos ) ) )
		{
			pPacket->WritePacket( pChild );
			pChild->Release();
		}
	}

	pPacket->WritePacket( "FILES", static_cast< DWORD >( pFolder->GetFileCount() * 4 ) );

	for ( POSITION pos = pFolder->GetFileIterator() ; pos ; )
	{
		CLibraryFile* pFile = pFolder->GetNextFile( pos );
		pPacket->WriteLongBE( pFile->m_nIndex );
	}

	return pPacket;
}

CG2Packet* CLocalSearch::FoldersToPacket()
{
	CG2Packet* pPacket = CG2Packet::New( "PF", TRUE );

	for ( POSITION pos = LibraryFolders.GetFolderIterator() ; pos ; )
	{
		if ( CG2Packet* pChild = FolderToPacket( LibraryFolders.GetNextFolder( pos ) ) )
		{
			pPacket->WritePacket( pChild );
			pChild->Release();
		}
	}

	return pPacket;
}

CG2Packet* CLocalSearch::FolderToPacket(CLibraryFolder* pFolder)
{
	if ( pFolder == NULL ) return NULL;

	if ( pFolder->GetSharedCount() == 0 ) return NULL;

	CG2Packet* pPacket = CG2Packet::New( "PF", TRUE );

	pPacket->WritePacket( "DN", pPacket->GetStringLen( pFolder->m_sName ) );
	pPacket->WriteString( pFolder->m_sName, FALSE );

	for ( POSITION pos = pFolder->GetFolderIterator() ; pos ; )
	{
		if ( CG2Packet* pChild = FolderToPacket( pFolder->GetNextFolder( pos ) ) )
		{
			pPacket->WritePacket( pChild );
			pChild->Release();
		}
	}

	pPacket->WritePacket( "FILES", static_cast< DWORD >( pFolder->GetFileCount() * 4 ) );

	for ( POSITION pos = pFolder->GetFileIterator() ; pos ; )
	{
		CLibraryFile* pFile = pFolder->GetNextFile( pos );
		pPacket->WriteLongBE( pFile->m_nIndex );
	}

	return pPacket;
}
