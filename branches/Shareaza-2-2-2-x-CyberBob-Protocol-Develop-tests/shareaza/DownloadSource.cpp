//
// DownloadSource.cpp
//
//	Date:			"$Date: 2006/03/27 01:36:17 $"
//	Revision:		"$Revision: 1.16 $"
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
#include "Download.h"
#include "Downloads.h"
#include "DownloadSource.h"
#include "DownloadTransferHTTP.h"
#include "DownloadTransferFTP.h"
#include "DownloadTransferED2K.h"
#include "DownloadTransferBT.h"
#include "FragmentedFile.h"

#include "Neighbours.h"
#include "QueryHit.h"
#include "VendorCache.h"
#include "EDClients.h"
#include "EDClient.h"
#include "EDPacket.h"
#include "SourceURL.h"
#include "SHA.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif


//////////////////////////////////////////////////////////////////////
// CDownloadSource construction

CDownloadSource::CDownloadSource(CDownload* pDownload)
: m_oAvailable( pDownload->m_nSize ), m_oPastFragments( pDownload->m_nSize )
{
	Construct( pDownload );
	m_bCloseConn	= FALSE;
	m_bReConnect	= FALSE;			// No Initial Reconnect setting
	m_nPushAttempted	= 0;
	m_nBusyCount	= 0;
}

void CDownloadSource::Construct(CDownload* pDownload)
{
	ASSERT( pDownload != NULL );
	
	m_pDownload		= pDownload;
	m_pPrev			= NULL;
	m_pNext			= NULL;
	m_pTransfer		= NULL;
	m_bSelected		= FALSE;
	
	m_nProtocol		= PROTOCOL_NULL;
	m_nPort			= 0;
	m_nServerPort	= 0;
	
	m_nIndex		= 0;
	m_bHashAuth		= FALSE;
	m_bSHA1			= FALSE;
	m_bTiger		= FALSE;
	m_bED2K			= FALSE;
	
	m_nSpeed		= 0;
	m_bPushOnly		= FALSE;
	m_bCloseConn	= FALSE;
	m_bReadContent	= FALSE;
	m_nGnutella		= 0;
	m_bClientExtended=FALSE;
	
	m_nSortOrder	= 0xFFFFFFFF;
	m_nColour		= -1;
	m_tAttempt		= 0;
	m_nFailures		= 0;
	m_nRedirectionCount = 0;

	SYSTEMTIME pTime;
	GetSystemTime( &pTime );
	SystemTimeToFileTime( &pTime, &m_tLastSeen );

	m_bReConnect		= FALSE;			// No Initial Reconnect setting
	m_nPushAttempted	= 0;
	m_nBusyCount	= 0;

}

CDownloadSource::~CDownloadSource()
{
//	m_pPastFragment->DeleteChain();
//	m_pAvailable->DeleteChain();
}

//////////////////////////////////////////////////////////////////////
// CDownloadSource construction from a query hit

CDownloadSource::CDownloadSource(CDownload* pDownload, CQueryHit* pHit)
: m_oAvailable( pDownload->m_nSize ), m_oPastFragments( pDownload->m_nSize )
{
	Construct( pDownload );
	
	m_bPushOnly	= pHit->m_bPush == TS_TRUE ? TRUE : FALSE;
	
	m_sURL		= pHit->m_sURL;
	m_pAddress	= pHit->m_pAddress;	// Not needed? , m_pAddress is set in ResolveURL() again
	m_nPort		= pHit->m_nPort;	// Not needed?
	m_nSpeed	= pHit->m_bMeasured == TS_TRUE ? ( pHit->m_nSpeed * 128 ) : 0;
	m_sServer	= pHit->m_pVendor->m_sName;
	m_sName		= pHit->m_sName;
	m_nIndex	= pHit->m_nIndex;
	m_bSHA1		= bool( pHit->m_oSHA1 );
	m_bTiger	= bool( pHit->m_oTiger );
	m_bED2K		= bool( pHit->m_oED2K );
	m_bMD5		= bool( pHit->m_oMD5 );
	m_oHubList	= pHit->m_oHubList;
	m_oPushProxyList	= pHit->m_oPushProxyList;
	
	if ( pHit->m_nProtocol == PROTOCOL_G1 || pHit->m_nProtocol == PROTOCOL_G2 )
	{
		m_oGUID = pHit->m_oClientID;
		m_bClientExtended = TRUE;
	}
	else if ( pHit->m_nProtocol == PROTOCOL_ED2K )
	{
		if ( ( m_sURL.Right( 3 ) == _T("/0/") ) && ( pDownload->m_nSize ) )
		{	//Add the size if it was missing.
			CString strTemp =  m_sURL.Left( m_sURL.GetLength() - 2 );
			m_sURL.Format( _T("%s%I64i/"), strTemp, pDownload->m_nSize );
		}
	}
	
	ResolveURL();

	if ( pHit->m_nProtocol == PROTOCOL_G1 || pHit->m_nProtocol == PROTOCOL_G2 )
	{
		m_nProtocol = pHit->m_nProtocol;
	}

	m_bCloseConn	= FALSE;
	m_bReConnect	= FALSE;			// No Initial Reconnect setting
	m_nPushAttempted	= 0;
	m_nBusyCount	= 0;
}

//////////////////////////////////////////////////////////////////////
// CDownloadSource construction from eDonkey source transfer

CDownloadSource::CDownloadSource(CDownload* pDownload, DWORD nClientID, WORD nClientPort, DWORD nServerIP, WORD nServerPort, const Hashes::Guid& oGUID)
: m_oAvailable( pDownload->m_nSize ), m_oPastFragments( pDownload->m_nSize )
{
	Construct( pDownload );
	
	if ( ( m_bPushOnly = CEDPacket::IsLowID( nClientID ) ) != FALSE )
	{
		m_sURL.Format( _T("ed2kftp://%lu@%s:%i/%s/%I64i/"),
			nClientID,
			(LPCTSTR)CString( inet_ntoa( (IN_ADDR&)nServerIP ) ), nServerPort,
            (LPCTSTR)m_pDownload->m_oED2K.toString(), m_pDownload->m_nSize );
	}
	else
	{
		m_sURL.Format( _T("ed2kftp://%s:%i/%s/%I64i/"),
			(LPCTSTR)CString( inet_ntoa( (IN_ADDR&)nClientID ) ), nClientPort,
            (LPCTSTR)m_pDownload->m_oED2K.toString(), m_pDownload->m_nSize );
	}
	
	m_oGUID = oGUID;
	
	m_bED2K		= TRUE;
	m_sServer	= _T("eDonkey2000");

	m_pAddress = (IN_ADDR&)nClientID;
	m_nPort = nClientPort;
	m_pServerAddress = (IN_ADDR&)nServerIP;
	m_nServerPort = nServerPort;
	
	ResolveURL();

	m_bCloseConn	= FALSE;
	m_bReConnect	= FALSE;			// No Initial Reconnect setting
	m_nPushAttempted	= 0;
	m_nBusyCount	= 0;
}

//////////////////////////////////////////////////////////////////////
// CDownloadSource construction from BitTorrent

CDownloadSource::CDownloadSource(CDownload* pDownload, const Hashes::BtGuid& oGUID, IN_ADDR* pAddress, WORD nPort)
: m_oAvailable( pDownload->m_nSize ), m_oPastFragments( pDownload->m_nSize )
{
	Construct( pDownload );
	
	if ( oGUID )
	{
		m_sURL.Format( _T("btc://%s:%i/%s/%s/"),
			(LPCTSTR)CString( inet_ntoa( *pAddress ) ), nPort,
            (LPCTSTR)oGUID.toString(),
			(LPCTSTR)pDownload->m_oBTH.toString() );
	}
	else
	{
		m_sURL.Format( _T("btc://%s:%i//%s/"),
			(LPCTSTR)CString( inet_ntoa( *pAddress ) ), nPort,
			(LPCTSTR)pDownload->m_oBTH.toString() );
	}
	
	m_oGUID	= transformGuid( oGUID );
	m_sServer	= _T("BitTorrent");
	
	ResolveURL();

	m_bCloseConn	= FALSE;
	m_bReConnect	= FALSE;			// No Initial Reconnect setting
	m_nPushAttempted	= 0;
	m_nBusyCount	= 0;
}

//////////////////////////////////////////////////////////////////////
// CDownloadSource construction from URL

CDownloadSource::CDownloadSource(CDownload* pDownload, LPCTSTR pszURL, BOOL /*bSHA1*/, BOOL bHashAuth, FILETIME* pLastSeen, int nRedirectionCount,
								 PROTOCOLID nProtocol)
: m_oAvailable( pDownload->m_nSize ), m_oPastFragments( pDownload->m_nSize )
{
	Construct( pDownload );
	
	ASSERT( pszURL != NULL );
	m_sURL = pszURL;
	
	if ( ! ResolveURL() ) return;
	
	//m_bSHA1			= bSHA1; //Done in ResolveURL now
	m_bHashAuth		= bHashAuth;
	
	if ( pLastSeen != NULL )
	{
		FILETIME tNow = m_tLastSeen;
		(LONGLONG&)tNow += 10000000;
		if ( CompareFileTime( pLastSeen, &tNow ) <= 0 ) m_tLastSeen = *pLastSeen;
	}

	m_nRedirectionCount = nRedirectionCount;

	m_bCloseConn	= FALSE;
	m_bReConnect	= FALSE;			// No Initial Reconnect setting
	m_nPushAttempted	= 0;
	if ( nProtocol == PROTOCOL_G1 || nProtocol == PROTOCOL_G2 )
	{
		m_nProtocol		= nProtocol;
	}
	m_nBusyCount	= 0;
}

//////////////////////////////////////////////////////////////////////
// CDownloadSource URL resolver

BOOL CDownloadSource::ResolveURL()
{
	CSourceURL pURL;
	
	if ( ! pURL.Parse( m_sURL ) )
	{
		theApp.Message( MSG_ERROR, _T("Unable to parse URL: %s"), (LPCTSTR)m_sURL );
		return FALSE;
	}
	
	m_bSHA1		|= static_cast< BOOL >( bool( pURL.m_oSHA1 ) );
	m_bTiger	|= static_cast< BOOL >( bool( pURL.m_oTiger ) );
	m_bED2K		|= static_cast< BOOL >( bool( pURL.m_oED2K ) );
	m_bMD5		|= static_cast< BOOL >( bool( pURL.m_oMD5 ) );

	m_nProtocol	= pURL.m_nProtocol;
	m_pAddress	= pURL.m_pAddress;
	m_nPort		= pURL.m_nPort;
	
	if ( m_nProtocol == PROTOCOL_ED2K )
	{
		m_pServerAddress	= pURL.m_pServerAddress;
		m_nServerPort		= pURL.m_nServerPort;
		if ( m_nServerPort ) m_bPushOnly = TRUE;
	}
	else if ( m_nProtocol == PROTOCOL_BT )
	{
		if ( pURL.m_oBTC )
		{
			m_oGUID = transformGuid( pURL.m_oBTC );
		}
	}
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CDownloadSource serialize

void CDownloadSource::Serialize(CArchive& ar, int nVersion)
{
	if ( ar.IsStoring() )
	{
		ar << m_sURL;
		ar << m_nProtocol;
		
		SerializeOut( ar, m_oGUID );
		
		ar << m_nPort;
		if ( m_nPort ) ar.Write( &m_pAddress, sizeof(m_pAddress) );
		ar << m_nServerPort;
		if ( m_nServerPort ) ar.Write( &m_pServerAddress, sizeof(m_pServerAddress) );
		
		ar << m_sName;
		ar << m_nIndex;
		ar << m_bHashAuth;
		ar << m_bSHA1;
		ar << m_bTiger;
		ar << m_bED2K;
		
		ar << m_sServer;
		ar << m_sNick;
		ar << m_nSpeed;
		ar << m_bPushOnly;
		ar << m_bCloseConn;
		ar << m_bReadContent;
		ar.Write( &m_tLastSeen, sizeof(FILETIME) );
		
        SerializeOut2( ar, m_oPastFragments );
	}
	else if ( nVersion >= 21 )
	{
		ar >> m_sURL;
		ar >> m_nProtocol;
		
		SerializeIn( ar, m_oGUID, nVersion);
		
		ar >> m_nPort;
		if ( m_nPort ) ar.Read( &m_pAddress, sizeof(m_pAddress) );
		ar >> m_nServerPort;
		if ( m_nServerPort ) ar.Read( &m_pServerAddress, sizeof(m_pServerAddress) );
		
		ar >> m_sName;
		ar >> m_nIndex;
		ar >> m_bHashAuth;
		ar >> m_bSHA1;
		ar >> m_bTiger;
		ar >> m_bED2K;
		
		ar >> m_sServer;
		if ( nVersion >= 24 ) ar >> m_sNick;
		ar >> m_nSpeed;
		ar >> m_bPushOnly;
		ar >> m_bCloseConn;
		ar >> m_bReadContent;
		ar.Read( &m_tLastSeen, sizeof(FILETIME) );
		
        SerializeIn2( ar, m_oPastFragments, nVersion );

		// Should probably save this instead...
		if ( _tcsncmp( m_sServer, _T("Shareaza"), 8 ) == 0 )
			m_bClientExtended = TRUE;
		if ( _tcsncmp( m_sServer, _T("RAZA"), 4 ) == 0 )
			m_bClientExtended = TRUE;
		//
	}
	else
	{
		DWORD nIndex;
		ar.Read( &m_pAddress, sizeof(m_pAddress) );
		ar >> m_nPort;
		ar >> m_nSpeed;
		ar >> nIndex;
		ar >> m_sName;
		if ( nVersion >= 4 ) ar >> m_sURL;
		if ( nVersion >= 21 ) ar >> m_nProtocol;
		ar >> m_bSHA1;
		if ( nVersion >= 13 ) ar >> m_bTiger;
		if ( nVersion >= 13 ) ar >> m_bED2K;
		if ( nVersion >= 10 ) ar >> m_bHashAuth;
		
		if ( nVersion == 8 )
		{
			DWORD nV;
			ar >> nV;
			m_sServer.Format( _T("%c%c%c%c"), nV & 0xFF, ( nV >> 8 ) & 0xFF, ( nV >> 16 ) & 0xFF, nV >> 24 );
		}
		else if ( nVersion >= 9 )
		{
			ar >> m_sServer;
		}
		
		ar >> m_bPushOnly;
		ar >> m_bReadContent;
		if ( nVersion >= 7 ) ar >> m_bCloseConn;
		if ( nVersion >= 12 ) ar.Read( &m_tLastSeen, sizeof(FILETIME) );
		
		ar.Read( &m_oGUID[ 0 ], Hashes::Guid::byteCount );
		ar.Read( &m_oGUID[ 0 ], Hashes::Guid::byteCount );
		m_oGUID.validate();
		
        SerializeIn2( ar, m_oPastFragments, nVersion );
		
		ResolveURL();
	}
}

//////////////////////////////////////////////////////////////////////
// CDownloadSource create transfer

CDownloadTransfer* CDownloadSource::CreateTransfer()
{
	ASSERT( m_pTransfer == NULL );
	
	switch ( m_nProtocol )
	{
	case PROTOCOL_G1:	return ( m_pTransfer = new CDownloadTransferHTTP( this ) );
	case PROTOCOL_G2:	return ( m_pTransfer = new CDownloadTransferHTTP( this ) );
	case PROTOCOL_ED2K:	return ( m_pTransfer = new CDownloadTransferED2K( this ) );
	case PROTOCOL_HTTP:	return ( m_pTransfer = new CDownloadTransferHTTP( this ) );
	case PROTOCOL_FTP:	return ( m_pTransfer = new CDownloadTransferFTP( this ) );
	case PROTOCOL_BT:	return ( m_pTransfer = new CDownloadTransferBT( this, NULL ) );
	default:			theApp.Message( MSG_ERROR, _T("Invalid protocol in CDownloadSource::CreateTransfer()") );
						return ( NULL );
	}
}

//////////////////////////////////////////////////////////////////////
// CDownloadSource remove

void CDownloadSource::Remove(BOOL bCloseTransfer, BOOL bBan)
{
	if ( m_pTransfer != NULL )
	{
		if ( bCloseTransfer )
		{
			m_pTransfer->Close( TS_TRUE );
			ASSERT( m_pTransfer == NULL );
		}
		else
		{
			m_pTransfer->m_pSource = NULL;
			m_pTransfer = NULL;
		}
	}
	
	m_pDownload->RemoveSource( this, bBan );
}

//////////////////////////////////////////////////////////////////////
// CDownloadSource failure handler

void CDownloadSource::OnFailure(BOOL bNondestructive, DWORD nRetryAfter)
{
	if ( m_pTransfer != NULL )
	{
		m_pTransfer->SetState(dtsNull);
		m_pTransfer->m_pSource = NULL;
		m_pTransfer = NULL;
	}
	
	DWORD nDelayFactor = max( ( m_nBusyCount != 0 ) ? (m_nBusyCount - 1) : 0, m_nFailures );

	DWORD nDelay = Settings.Downloads.RetryDelay * ( 1u << nDelayFactor );

	if ( m_nProtocol == PROTOCOL_ED2K && nDelay < ( Settings.eDonkey.ReAskTime * 1000 ) )
	{
		nDelay = Settings.eDonkey.ReAskTime * 1000;
	}

	if ( nRetryAfter != 0 )
	{
		nDelay = nRetryAfter * 1000;
	}
	else
	{
		if ( nDelayFactor < 20 )
		{
			if ( nDelay > 3600000 ) nDelay = 3600000;
		}
		else if ( nDelayFactor < 40 )
		{
			if ( nDelay > 7200000 ) nDelay = 7200000;
		}
		else if ( nDelayFactor < 80 )
		{
			if ( nDelay > 14400000 ) nDelay = 14400000;
		}
		else  // I think it is nasty to set 1 day delay
		{
			//if ( nDelay > 86400000 ) nDelay = 86400000;
			// it is more than 80 Failure/Busy reply, thus just purge this node.
			if ( !Settings.Downloads.NeverDrop ) m_pDownload->RemoveSource( this, TRUE );
			return;
		}
	}
	
	nDelay += GetTickCount();
	
	// This is not too good because if the source has Uploaded even 1Byte data, Max failure gets set to 40
	//int nMaxFailures = ( m_bReadContent ? 40 : 3 );

	int nMaxFailures = Settings.Downloads.MaxAllowedFailures;

	if ( nMaxFailures < 20 && m_pDownload->GetSourceCount() > 20 ) nMaxFailures = 0;

	m_pDownload->SetModified();

	if ( bNondestructive || ( ++m_nFailures < nMaxFailures ) )
	{
		m_tAttempt = max( m_tAttempt, nDelay );
	}
	else
	{
		if ( Settings.Downloads.NeverDrop )
		{
			m_tAttempt = nDelay;
		}
		else
		{
			// Add to the bad sources list (X-NAlt)
			m_pDownload->RemoveSource( this, TRUE );
		}
	}
}

//////////////////////////////////////////////////////////////////////
// CDownloadSource resume handler

void CDownloadSource::OnResume()
{
	m_tAttempt = 0;
}

//////////////////////////////////////////////////////////////////////
// CDownloadSource closed connection resume handler

BOOL CDownloadSource::OnResumeClosed()
{
	if ( m_pTransfer != NULL )
	{
		m_pTransfer->SetState(dtsNull);
		m_pTransfer->CTransfer::Close();
		if ( m_pTransfer->Initiate() ) return TRUE;
	}
	else
	{
		m_tAttempt = 0;	
		m_pDownload->SetModified();
	}
	return FALSE;
}

//////////////////////////////////////////////////////////////////////
// CDownloadSource status

void CDownloadSource::SetValid()
{
	m_bReadContent = TRUE;
	m_nFailures = 0;
	m_pDownload->SetModified();
}

void CDownloadSource::SetLastSeen()
{
	SYSTEMTIME pTime;
	GetSystemTime( &pTime );
	SystemTimeToFileTime( &pTime, &m_tLastSeen );
	m_pDownload->SetModified();
}

void CDownloadSource::SetGnutella(int nGnutella)
{
	m_nGnutella |= nGnutella;
	m_pDownload->SetModified();
}

//////////////////////////////////////////////////////////////////////
// CDownloadSource hash check and learn

BOOL CDownloadSource::CheckHash(const Hashes::Sha1Hash& oSHA1)
{
	if ( m_pDownload->m_oSHA1 && ! m_bHashAuth )
	{
		if ( validAndUnequal( m_pDownload->m_oSHA1, oSHA1 ) ) return FALSE;
	}
	else
	{
		if ( m_pDownload->m_pTorrent.IsAvailable() ) return TRUE;
		
		m_pDownload->m_oSHA1 = oSHA1;
	}
	
	m_bSHA1 = TRUE;
	m_pDownload->SetModified();
	
	return TRUE;
}

BOOL CDownloadSource::CheckHash(const Hashes::TigerHash& oTiger)
{
    if ( m_pDownload->m_oTiger && ! m_bHashAuth )
	{
		if ( validAndUnequal( m_pDownload->m_oTiger, oTiger ) ) return FALSE;
	}
	else
	{
		if ( m_pDownload->m_pTorrent.IsAvailable() ) return TRUE;
		
		m_pDownload->m_oTiger = oTiger;
	}
	
	m_bTiger = TRUE;
	m_pDownload->SetModified();
	
	return TRUE;
}

BOOL CDownloadSource::CheckHash(const Hashes::Ed2kHash& oED2K)
{
	if ( m_pDownload->m_oED2K && ! m_bHashAuth )
	{
		if ( validAndUnequal( m_pDownload->m_oED2K, oED2K ) ) return FALSE;
	}
	else
	{
		if ( m_pDownload->m_pTorrent.IsAvailable() ) return TRUE;

		m_pDownload->m_oED2K = oED2K;
	}

	m_bED2K = TRUE;
	m_pDownload->SetModified();

	return TRUE;
}

BOOL CDownloadSource::CheckHash(const Hashes::Md5Hash& oMD5)
{
	if ( m_pDownload->m_oMD5 && ! m_bHashAuth )
	{
		if ( validAndUnequal( m_pDownload->m_oMD5, oMD5 ) ) return FALSE;
	}
	else
	{
		if ( m_pDownload->m_pTorrent.IsAvailable() ) return TRUE;

		m_pDownload->m_oMD5 = oMD5;
	}

	m_bED2K = TRUE;
	m_pDownload->SetModified();

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CDownloadSource push request

BOOL CDownloadSource::PushRequest()
{
	if ( m_nProtocol == PROTOCOL_BT )
	{
		return FALSE;
	}
	else if ( m_nProtocol == PROTOCOL_ED2K )
	{
		// in order to make ED2K callback (push source) connection needs Server address and port
		if ( m_nServerPort == 0 ) return FALSE;
		if ( m_pServerAddress.S_un.S_addr == 0 ) return FALSE;

		// In order to accept in-coming ed2k callback connection, need to have non-connected CEDClient linked up
		// with CDownloadSource and CDownloadTransferED2K, should be placed in array "CEDClients"
		// Note: this might not be the best way, but currently only this is the work around to make ed2k PUSH download connection

		// check if clients array is full or not, if it is full, do not request
		if ( EDClients.IsFull() ) return TRUE;

		CDownloadTransferED2K* pTransfer = NULL;
		// if ed2k PUSH source do not have transfer object, make blank one and assign
		if ( m_pTransfer == NULL )
		{
			pTransfer = new CDownloadTransferED2K(this);
			m_pTransfer = dynamic_cast<CDownloadTransfer*>( pTransfer );
			if ( m_pTransfer == NULL ) delete pTransfer;
		}

		// if already had Transfer object, Try cast it to ED2K transfer
		if ( m_pTransfer != NULL ) pTransfer = dynamic_cast<CDownloadTransferED2K*>(m_pTransfer);

		// if source does not have transfer object, can not get EDClient object so skip
		if ( pTransfer != NULL )
		{
			// check if m_pTransfer is CDownloadTransferED2K object or not.
			if ( pTransfer->m_pClient == NULL ) // if it was ED2K transfer, and it did not have any EDClient
			{
				// create blank CEDClient object and assign it to ED2K transfer.
				pTransfer->m_pClient = new CEDClient();
				pTransfer->m_pClient->m_pDownload = pTransfer;
				// set ClientID, ServerAddress:Port and GUID to CEDClient object.
				pTransfer->m_pClient->ConnectTo( m_pAddress.S_un.S_addr, m_nPort, &m_pServerAddress, m_nServerPort, m_oGUID );
			}

			// if everything are ready, send callback request to server.
			if ( pTransfer->m_pClient != NULL && ( pTransfer->m_nState == dtsNull || pTransfer->m_nState == dtsQueued ) &&
				Neighbours.PushDonkey( m_pAddress.S_un.S_addr, &m_pServerAddress, m_nServerPort ) )
			{
				// when it succeed to send call back request, set next attempt time to re-ask time
				theApp.Message( MSG_DEFAULT, IDS_DOWNLOAD_PUSH_SENT, (LPCTSTR)m_pDownload->m_sDisplayName );
				m_tAttempt = GetTickCount() + ( Settings.eDonkey.ReAskTime * 1000 );
				return TRUE;
			}
		}
	}
	else
	{
		if ( ! m_oGUID ) return FALSE;
		
		if ( Network.SendPush( m_oGUID, m_nIndex, m_nProtocol, m_pAddress, m_nPort, m_oPushProxyList, m_oHubList ) )
		{
			m_tAttempt = GetTickCount() + Settings.Downloads.PushTimeout;
			m_nPushAttempted++;
			return TRUE;
		}
	}

	return FALSE;
}

BOOL CDownloadSource::CheckPush(const Hashes::Guid& oClientID)
{
	return validAndEqual( m_oGUID, oClientID );
}

BOOL CDownloadSource::CheckDonkey(CEDClient* pClient)
{
	if ( m_nProtocol != PROTOCOL_ED2K ) return FALSE;
	
	if ( m_oGUID && pClient->m_oGUID ) return m_oGUID == pClient->m_oGUID;
	
	if ( m_bPushOnly )
	{
		return	m_pServerAddress.S_un.S_addr == pClient->m_pServer.sin_addr.S_un.S_addr &&
				m_pAddress.S_un.S_addr == pClient->m_nClientID;
	}
	else
	{
		return m_pAddress.S_un.S_addr == pClient->m_pHost.sin_addr.S_un.S_addr;
	}
}

//////////////////////////////////////////////////////////////////////
// CDownloadSource past fragments

void CDownloadSource::AddFragment(QWORD nOffset, QWORD nLength, BOOL /*bMerge*/)
{
	m_bReadContent = TRUE;
	m_oPastFragments.insert( Fragments::Fragment( nOffset, nOffset + nLength ) );
	m_pDownload->SetModified();
}

//////////////////////////////////////////////////////////////////////
// CDownloadSource available ranges

void CDownloadSource::SetAvailableRanges(LPCTSTR pszRanges)
{
    m_oAvailable.clear();
	
	if ( ! pszRanges || ! *pszRanges ) return;
	if ( _tcsnicmp( pszRanges, _T("bytes"), 5 ) ) return;
	
	CString strRanges( pszRanges + 6 );
	
	for ( strRanges += ',' ; strRanges.GetLength() ; )
	{
		CString strRange = strRanges.SpanExcluding( _T(", \t") );
		strRanges = strRanges.Mid( strRange.GetLength() + 1 );
		
		strRange.TrimLeft();
		strRange.TrimRight();
		if ( strRange.Find( '-' ) < 0 ) continue;
		
		QWORD nFirst = 0, nLast = 0;
		
		// 0 - 0 has special meaning
		if ( _stscanf( strRange, _T("%I64i-%I64i"), &nFirst, &nLast ) == 2 && nLast > nFirst )
		{
            if( nFirst < m_oAvailable.limit() ) // Sanity check
            {
				// perhaps the file size we expect is incorrect or the source is erronous
				// in either case we make sure the range fits - so we chop off the end if necessary
				m_oAvailable.insert( Fragments::Fragment( nFirst, min( nLast + 1, m_oAvailable.limit() ) ) );
            }
		}
	}
	
	m_pDownload->SetModified();
}

//////////////////////////////////////////////////////////////////////
// CDownloadSource range intersection test

BOOL CDownloadSource::HasUsefulRanges() const
{
	if ( m_oAvailable.empty() )
    {
        return m_pDownload->IsRangeUseful( 0, m_pDownload->m_nSize );
    }
    return m_pDownload->AreRangesUseful( m_oAvailable );
}

//////////////////////////////////////////////////////////////////////
// CDownloadSource range intersection

BOOL CDownloadSource::TouchedRange(QWORD nOffset, QWORD nLength) const
{
	if ( m_pTransfer != NULL && m_pTransfer->m_nState == dtsDownloading )
	{
		if ( m_pTransfer->m_nOffset + m_pTransfer->m_nLength > nOffset &&
			 m_pTransfer->m_nOffset < nOffset + nLength )
		{
			return TRUE;
		}
	}
	
	return m_oPastFragments.overlaps( Fragments::Fragment( nOffset, nOffset + nLength ) );
}

//////////////////////////////////////////////////////////////////////
// CDownloadSource colour

int CDownloadSource::GetColour()
{
	if ( m_nColour >= 0 ) return m_nColour;
	m_nColour = m_pDownload->GetSourceColour();
	return m_nColour;
}
