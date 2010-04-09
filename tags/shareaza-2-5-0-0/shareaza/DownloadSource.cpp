//
// DownloadSource.cpp
//
// Copyright (c) Shareaza Development Team, 2002-2009.
// This file is part of SHAREAZA (shareaza.sourceforge.net)
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
#include "Download.h"
#include "DownloadSource.h"
#include "DownloadTransferBT.h"
#include "DownloadTransferED2K.h"
#include "DownloadTransferFTP.h"
#include "DownloadTransferHTTP.h"
#include "Downloads.h"
#include "EDClient.h"
#include "EDClients.h"
#include "EDPacket.h"
#include "FragmentBar.h"
#include "FragmentedFile.h"
#include "Neighbours.h"
#include "Network.h"
#include "QueryHit.h"
#include "ShareazaURL.h"
#include "Transfers.h"
#include "VendorCache.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif


//////////////////////////////////////////////////////////////////////
// CDownloadSource construction

CDownloadSource::CDownloadSource(const CDownload* pDownload)
: m_oAvailable( pDownload->m_nSize ), m_oPastFragments( pDownload->m_nSize )
{
	Construct( pDownload );
}

void CDownloadSource::Construct(const CDownload* pDownload)
{
	ASSERT( pDownload != NULL );

	SYSTEMTIME pTime;
	GetSystemTime( &pTime );

	m_pDownload		= const_cast< CDownload* >( pDownload );
	m_pTransfer		= NULL;
	m_bSelected		= FALSE;

	m_nProtocol		= PROTOCOL_NULL;
	ZeroMemory( &m_pAddress, sizeof( m_pAddress ) );
	m_nPort			= 0;
	ZeroMemory( &m_pServerAddress, sizeof( m_pServerAddress ) );
	m_nServerPort	= 0;
	
	m_nIndex		= 0;
	m_bHashAuth		= FALSE;
	m_bSHA1			= FALSE;
	m_bTiger		= FALSE;
	m_bED2K			= FALSE;
	m_bBTH			= FALSE;
	m_bMD5			= FALSE;
	
	m_nSpeed		= 0;
	m_bPushOnly		= FALSE;
	m_bCloseConn	= FALSE;
	m_bReadContent	= FALSE;

	ASSERT( SystemTimeToFileTime( &pTime, &m_tLastSeen ) );

	m_nGnutella		= 0;
	m_bClientExtended=FALSE;
	
	m_nSortOrder	= 0xFFFFFFFF;
	m_nColour		= -1;
	m_tAttempt		= 0;
	m_bKeep			= FALSE;
	m_nFailures		= 0;
	m_nBusyCount	= 0;
	m_nRedirectionCount = 0;
	m_bPreviewRequestSent = FALSE;
	m_bPreview = FALSE;
}

CDownloadSource::~CDownloadSource()
{
	ASSUME_LOCK( Transfers.m_pSection );
	ASSERT( m_pTransfer == NULL );
}

//////////////////////////////////////////////////////////////////////
// CDownloadSource construction from a query hit

CDownloadSource::CDownloadSource(const CDownload* pDownload, const CQueryHit* pHit)
: m_oAvailable( pDownload->m_nSize ), m_oPastFragments( pDownload->m_nSize )
{
	Construct( pDownload );
	
	m_bPushOnly	= pHit->m_bPush == TRI_TRUE ? TRUE : FALSE;
	
	m_sURL		= pHit->m_sURL;
	m_pAddress	= pHit->m_pAddress;	// Not needed? , m_pAddress is set in ResolveURL() again
	m_nPort		= pHit->m_nPort;	// Not needed?
	m_nSpeed	= pHit->m_bMeasured == TRI_TRUE ? ( pHit->m_nSpeed * 128 ) : 0;
	m_sServer	= pHit->m_pVendor->m_sName;
	m_sName		= pHit->m_sName;
	m_sNick		= pHit->m_sNick;
	m_nIndex	= pHit->m_nIndex;
	m_bSHA1		= bool( pHit->m_oSHA1 );
	m_bTiger	= bool( pHit->m_oTiger );
	m_bED2K		= bool( pHit->m_oED2K );
	m_bBTH		= bool( pHit->m_oBTH );
	m_bMD5		= bool( pHit->m_oMD5 );
	
	if ( pHit->m_nProtocol == PROTOCOL_G1 || pHit->m_nProtocol == PROTOCOL_G2 )
	{
		m_oGUID = pHit->m_oClientID;
		m_bClientExtended = TRUE;
		if ( pHit->m_nProtocol == PROTOCOL_G2 )
		{
			m_bPreview = pHit->m_bPreview;
			m_sPreview = pHit->m_sPreview;
		}
		else
			m_bPreview = FALSE;
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

	// If we got hit with BitTorrent hash
	if ( pHit->m_oBTH &&
	// ... and url now looks like btc://
		m_nProtocol == PROTOCOL_BT &&
	// ... but hit was received from G1/G2 search
		( pHit->m_nProtocol == PROTOCOL_G1 || pHit->m_nProtocol == PROTOCOL_G2 ) &&
	// ... and download is a single file torrent or isnt a torrent
		( pDownload->IsSingleFileTorrent() || ! pDownload->IsTorrent() ) )
	// ... then change (back) hit to G1/G2 protocol
	{
		m_nProtocol = pHit->m_nProtocol;
		m_sURL = pHit->GetURL( m_pAddress, m_nPort );
	}
}

//////////////////////////////////////////////////////////////////////
// CDownloadSource construction from eDonkey source transfer

CDownloadSource::CDownloadSource(const CDownload* pDownload, DWORD nClientID, WORD nClientPort, DWORD nServerIP, WORD nServerPort, const Hashes::Guid& oGUID)
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
	
	ResolveURL();
}

//////////////////////////////////////////////////////////////////////
// CDownloadSource construction from BitTorrent

CDownloadSource::CDownloadSource(const CDownload* pDownload, const Hashes::BtGuid& oGUID, IN_ADDR* pAddress, WORD nPort)
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

	m_bBTH		= TRUE;
	m_oGUID	= transformGuid( oGUID );
	m_sServer	= _T("BitTorrent");
	
	ResolveURL();
}

//////////////////////////////////////////////////////////////////////
// CDownloadSource construction from URL

CDownloadSource::CDownloadSource(const CDownload* pDownload, LPCTSTR pszURL, BOOL /*bSHA1*/, BOOL bHashAuth, FILETIME* pLastSeen, int nRedirectionCount)
: m_oAvailable( pDownload->m_nSize ), m_oPastFragments( pDownload->m_nSize )
{
	Construct( pDownload );
	
	ASSERT( pszURL != NULL );
	m_sURL = pszURL;
	
	if ( ! ResolveURL() ) return;
	
	m_bHashAuth		= bHashAuth;
	
	if ( pLastSeen != NULL )
	{
		FILETIME tNow = m_tLastSeen;
		(LONGLONG&)tNow += 10000000;
		if ( CompareFileTime( pLastSeen, &tNow ) <= 0 ) m_tLastSeen = *pLastSeen;
	}

	m_nRedirectionCount = nRedirectionCount;
}

//////////////////////////////////////////////////////////////////////
// CDownloadSource URL resolver

BOOL CDownloadSource::ResolveURL()
{
	CShareazaURL pURL;
	
	if ( ! pURL.Parse( m_sURL ) )
	{
		theApp.Message( MSG_ERROR, _T("Unable to parse URL: %s"), (LPCTSTR)m_sURL );
		return FALSE;
	}
	
	m_bSHA1		|= static_cast< BOOL >( bool( pURL.m_oSHA1 ) );
	m_bTiger	|= static_cast< BOOL >( bool( pURL.m_oTiger ) );
	m_bED2K		|= static_cast< BOOL >( bool( pURL.m_oED2K ) );
	m_bBTH		|= static_cast< BOOL >( bool( pURL.m_oBTH ) );
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
	
	m_sCountry		= theApp.GetCountryCode( m_pAddress );
	m_sCountryName	= theApp.GetCountryName( m_pAddress );

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CDownloadSource serialize

void CDownloadSource::Serialize(CArchive& ar, int nVersion /* DOWNLOAD_SER_VERSION */)
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
		ar << m_bBTH;
		ar << m_bMD5;
		
		ar << m_sServer;
		ar << m_sNick;
		ar << m_sCountry;
		ar << m_sCountryName;
		ar << m_nSpeed;
		ar << m_bPushOnly;
		ar << m_bCloseConn;
		ar << m_bReadContent;
		ar.Write( &m_tLastSeen, sizeof(FILETIME) );
		
        SerializeOut2( ar, m_oPastFragments );

		ar << m_bClientExtended;
	}
	else if ( nVersion >= 21 )
	{
		ar >> m_sURL;
		ar >> m_nProtocol;
		
		SerializeIn( ar, m_oGUID, nVersion);
		
		ar >> m_nPort;
		if ( m_nPort ) ReadArchive( ar, &m_pAddress, sizeof(m_pAddress) );
		ar >> m_nServerPort;
		if ( m_nServerPort ) ReadArchive( ar, &m_pServerAddress, sizeof(m_pServerAddress) );
		
		ar >> m_sName;
		ar >> m_nIndex;
		ar >> m_bHashAuth;
		ar >> m_bSHA1;
		ar >> m_bTiger;
		ar >> m_bED2K;
		if ( nVersion >= 37 )
		{
			ar >> m_bBTH;
			ar >> m_bMD5;
		}
		
		ar >> m_sServer;
		if ( nVersion >= 24 ) ar >> m_sNick;

		if ( nVersion >= 36 ) 
			ar >> m_sCountry;
		else
			m_sCountry = theApp.GetCountryCode( m_pAddress );

		if ( nVersion >= 38 ) 
			ar >> m_sCountryName;
		else
			m_sCountryName = theApp.GetCountryName( m_pAddress );

		ar >> m_nSpeed;
		ar >> m_bPushOnly;
		ar >> m_bCloseConn;
		ar >> m_bReadContent;
		ReadArchive( ar, &m_tLastSeen, sizeof(FILETIME) );
		
        SerializeIn2( ar, m_oPastFragments, nVersion );

		if ( nVersion >= 39 )
			ar >> m_bClientExtended;
		else
			m_bClientExtended = VendorCache.IsExtended( m_sServer );
	}
	else
	{
		DWORD nIndex;
		ReadArchive( ar, &m_pAddress, sizeof(m_pAddress) );
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
		if ( nVersion >= 12 ) ReadArchive( ar, &m_tLastSeen, sizeof(FILETIME) );
		
		ReadArchive( ar, &m_oGUID[ 0 ], Hashes::Guid::byteCount );
		ReadArchive( ar, &m_oGUID[ 0 ], Hashes::Guid::byteCount );
		m_oGUID.validate();
		
        SerializeIn2( ar, m_oPastFragments, nVersion );
		
		ResolveURL();
	}
}

//////////////////////////////////////////////////////////////////////
// CDownloadSource create transfer

CDownloadTransfer* CDownloadSource::CreateTransfer(LPVOID pParam)
{
	ASSUME_LOCK( Transfers.m_pSection );
	ASSERT( m_pTransfer == NULL );
	
	switch ( m_nProtocol )
	{
	case PROTOCOL_G1:
		return ( m_pTransfer = new CDownloadTransferHTTP( this ) );
	case PROTOCOL_G2:
		return ( m_pTransfer = new CDownloadTransferHTTP( this ) );
	case PROTOCOL_ED2K:
		return ( m_pTransfer = new CDownloadTransferED2K( this ) );
	case PROTOCOL_HTTP:
		return ( m_pTransfer = new CDownloadTransferHTTP( this ) );
	case PROTOCOL_FTP:
		return ( m_pTransfer = new CDownloadTransferFTP( this ) );
	case PROTOCOL_BT:
		return ( m_pTransfer = new CDownloadTransferBT( this, (CBTClient*)pParam ) );
	default:
		return NULL;
	}
}

//////////////////////////////////////////////////////////////////////
// CDownloadSource check

BOOL CDownloadSource::CanInitiate(BOOL bNetwork, BOOL bEstablished)
{
	if( !Network.IsConnected() ) return FALSE;

	if ( Settings.Connection.RequireForTransfers )
	{
		switch ( m_nProtocol )
		{
		case PROTOCOL_G1:
			if ( ! Settings.Gnutella1.EnableToday ) return FALSE;
			break;
		case PROTOCOL_G2:
			if ( ! Settings.Gnutella2.EnableToday ) return FALSE;
			break;
		case PROTOCOL_ED2K:
			if ( ! Settings.eDonkey.EnableToday || ! bNetwork ) return FALSE;
			break;
		case PROTOCOL_HTTP:
			switch( m_nGnutella )
			{
			case 0:
				// Pure HTTP source
				if ( ! bNetwork ) return FALSE;
				break;
			case 1:
				// Pure G1 source
				if ( ! Settings.Gnutella1.EnableToday ) return FALSE;
				break;
			case 2:
				// Pure G2 source
				if ( ! Settings.Gnutella2.EnableToday ) return FALSE;
				break;
			case 3:
				// Mixed G1/G2 source
				if ( ! Settings.Gnutella1.EnableToday &&
					 ! Settings.Gnutella2.EnableToday ) return FALSE;
				break;
			}
			break;
		case PROTOCOL_FTP:
			if ( ! bNetwork ) return FALSE;
			break;
		case PROTOCOL_BT:
			if ( ! Settings.BitTorrent.EnableToday || ! bNetwork ) return FALSE;
			break;
		case PROTOCOL_NULL:
		case PROTOCOL_ANY:
		default:
			return FALSE;
		}
	}

	if ( ! bEstablished && m_pDownload->LookupFailedSource( m_sURL ) != NULL )
	{
		// Don't try to connect to sources which we determined were bad
		// We will check them later after 2 hours cleanup
		Close();

		if ( Settings.Downloads.NeverDrop )
		{
			m_bKeep = TRUE;
			m_tAttempt = CalcFailureDelay();

			m_pDownload->SetModified();
		}
		else
			Remove( TRUE, TRUE );

		return FALSE;
	}

	if ( ( Settings.Connection.IgnoreOwnIP ) && Network.IsSelfIP( m_pAddress ) ) 
		return FALSE;
	
	return bEstablished || Downloads.AllowMoreTransfers( (IN_ADDR*)&m_pAddress );
}

bool CDownloadSource::IsPreviewCapable() const
{
	ASSUME_LOCK( Transfers.m_pSection );

	switch ( m_nProtocol )
	{
	case PROTOCOL_HTTP:
		return ( m_bPreview != FALSE );

	case PROTOCOL_ED2K:
		return ( m_pTransfer &&
			static_cast< CDownloadTransferED2K* >( m_pTransfer )->m_pClient->m_bEmPreview );

	default:
		return false;
	}	
}

//////////////////////////////////////////////////////////////////////
// CDownloadSource remove

void CDownloadSource::Remove(BOOL bCloseTransfer, BOOL bBan)
{
	ASSUME_LOCK( Transfers.m_pSection );

	if ( m_pTransfer != NULL )
	{
		if ( bCloseTransfer )
		{
			Close();
			ASSERT( m_pTransfer == NULL );
		}
		else
		{
			// Transfer already closed
			ASSERT( m_pTransfer->GetSource() == NULL );
			m_pTransfer = NULL;
		}
	}
	
	m_pDownload->RemoveSource( this, m_pDownload->IsSeeding() ? FALSE : bBan );

	delete this;
}

//////////////////////////////////////////////////////////////////////
// CDownloadSource failure handler

void CDownloadSource::OnFailure(BOOL bNondestructive, DWORD nRetryAfter)
{
	ASSUME_LOCK( Transfers.m_pSection );

	if ( m_pTransfer != NULL )
	{
		// Transfer already closed
		ASSERT( m_pTransfer->GetSource() == NULL );
		m_pTransfer = NULL;
	}

	DWORD nDelay = CalcFailureDelay(nRetryAfter);

	// This is not too good because if the source has Uploaded even 1Byte data, Max failure gets set to 40
	//int nMaxFailures = ( m_bReadContent ? 40 : 3 );

	int nMaxFailures = Settings.Downloads.MaxAllowedFailures;

	if ( nMaxFailures < 20 &&
		m_pDownload->GetSourceCount() > Settings.Downloads.StartDroppingFailedSourcesNumber )
		nMaxFailures = 0;

	if ( bNondestructive || ( ++m_nFailures < nMaxFailures ) )
	{
		m_tAttempt = max( m_tAttempt, nDelay );
		m_pDownload->SetModified();
	}
	else
	{
		if ( Settings.Downloads.NeverDrop )
		{
			// Keep source
			m_bKeep = TRUE;
			m_tAttempt = CalcFailureDelay();
			m_pDownload->SetModified();
		}
		else
			Remove( TRUE, TRUE );
	}
}

DWORD CDownloadSource::CalcFailureDelay(DWORD nRetryAfter) const
{
	DWORD nDelayFactor = max( ( m_nBusyCount != 0 ) ? (m_nBusyCount - 1) : 0, m_nFailures );

	DWORD nDelay = Settings.Downloads.RetryDelay * ( 1u << nDelayFactor );

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
		else  // I think it is nasty to set 1 Day delay
		{
			if ( nDelay > 86400000 ) nDelay = 86400000; 
		}
	}

	nDelay += GetTickCount();

	return nDelay;
}

//////////////////////////////////////////////////////////////////////
// CDownloadSource resume handler

void CDownloadSource::OnResume()
{
	m_tAttempt = 0;
}

//////////////////////////////////////////////////////////////////////
// CDownloadSource closed connection resume handler

void CDownloadSource::OnResumeClosed()
{
	ASSUME_LOCK( Transfers.m_pSection );

	if ( m_pTransfer != NULL )
	{
		// Transfer already closed
		ASSERT( m_pTransfer->GetSource() == NULL );
		m_pTransfer = NULL;
	}

	m_tAttempt = 0;	
	m_pDownload->SetModified();
}

//////////////////////////////////////////////////////////////////////
// CDownloadSource status

void CDownloadSource::SetValid()
{
	m_bReadContent = TRUE;
	m_nFailures = 0;
	m_bKeep = FALSE;
	m_pDownload->SetModified();
}

void CDownloadSource::SetLastSeen()
{
	SYSTEMTIME pTime;
	GetSystemTime( &pTime );
	SystemTimeToFileTime( &pTime, &m_tLastSeen );
	m_bKeep = FALSE;
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
		if ( m_pDownload->IsTorrent() && ! m_pDownload->IsSingleFileTorrent() ) return TRUE;
		
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
		if ( m_pDownload->IsTorrent() && ! m_pDownload->IsSingleFileTorrent() ) return TRUE;
		
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
		if ( m_pDownload->IsTorrent() && ! m_pDownload->IsSingleFileTorrent() ) return TRUE;
		
		m_pDownload->m_oED2K = oED2K;
	}
	
	m_bED2K = TRUE;
	m_pDownload->SetModified();
	
	return TRUE;
}

BOOL CDownloadSource::CheckHash(const Hashes::BtHash& oBTH)
{
	if ( m_pDownload->m_oBTH && ! m_bHashAuth )
	{
		if ( validAndUnequal( m_pDownload->m_oBTH, oBTH ) ) return FALSE;
	}
	else
	{
		if ( m_pDownload->IsTorrent() ) return TRUE;

		m_pDownload->m_oBTH = oBTH;
	}

	m_bBTH = TRUE;
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
		if ( m_pDownload->IsTorrent() && ! m_pDownload->IsSingleFileTorrent() ) return TRUE;

		m_pDownload->m_oMD5 = oMD5;
	}

	m_bMD5 = TRUE;
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
		if ( m_nServerPort == 0 ) return FALSE;
		if ( EDClients.IsFull() ) return TRUE;
		
		CEDClient* pClient = EDClients.Connect( m_pAddress.S_un.S_addr, m_nPort,
			&m_pServerAddress, m_nServerPort, m_oGUID );
		
		if ( pClient != NULL && pClient->m_bConnected )
		{
			pClient->SeekNewDownload();
			return TRUE;
		}
		
		if ( Neighbours.PushDonkey( m_pAddress.S_un.S_addr, &m_pServerAddress, m_nServerPort ) )
		{
			theApp.Message( MSG_INFO, IDS_DOWNLOAD_PUSH_SENT, (LPCTSTR)m_pDownload->m_sName );
			m_tAttempt = GetTickCount() + Settings.Downloads.PushTimeout;
			return TRUE;
		}
	}
	else
	{
		if ( ! m_oGUID ) return FALSE;
		
		if ( Network.SendPush( m_oGUID, m_nIndex ) )
		{
			theApp.Message( MSG_INFO, IDS_DOWNLOAD_PUSH_SENT, (LPCTSTR)m_pDownload->m_sName );
			m_tAttempt = GetTickCount() + Settings.Downloads.PushTimeout;
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

void CDownloadSource::Close()
{
	ASSUME_LOCK( Transfers.m_pSection );

	if ( m_pTransfer )
	{
		m_pTransfer->Close( TRI_TRUE );
		ASSERT( m_pTransfer == NULL );
	}
}

void CDownloadSource::Draw(CDC* pDC, CRect* prcBar, COLORREF crNatural)
{
	if ( ! IsIdle() )
	{
		if ( m_pTransfer->m_nLength < SIZE_UNKNOWN )
		{
			CFragmentBar::DrawStateBar( pDC, prcBar, m_pDownload->m_nSize,
				m_pTransfer->m_nOffset, m_pTransfer->m_nLength,
				CoolInterface.m_crFragmentRequest, TRUE );
		}

		switch( GetTransferProtocol() )
		{
		case PROTOCOL_ED2K:
			for ( Fragments::Queue::const_iterator pRequested
				= static_cast< CDownloadTransferED2K* >( m_pTransfer )->m_oRequested.begin();
				pRequested
				!= static_cast< CDownloadTransferED2K* >( m_pTransfer )->m_oRequested.end();
				++pRequested )
			{
				CFragmentBar::DrawStateBar( pDC, prcBar, m_pDownload->m_nSize,
					pRequested->begin(), pRequested->size(), CoolInterface.m_crFragmentRequest, TRUE );
			}
			break;

		case PROTOCOL_BT:
			for ( Fragments::Queue::const_iterator pRequested
				= static_cast< CDownloadTransferBT* >( m_pTransfer )->m_oRequested.begin();
				pRequested
				!= static_cast< CDownloadTransferBT* >( m_pTransfer )->m_oRequested.end();
				++pRequested )
			{
				CFragmentBar::DrawStateBar( pDC, prcBar, m_pDownload->m_nSize,
					pRequested->begin(), pRequested->size(), CoolInterface.m_crFragmentRequest, TRUE );
			}
			break;

		default:
			// Do nothing more
			;
		}
	}

	Draw( pDC, prcBar );

	if ( ! m_oAvailable.empty() )
	{
		for ( Fragments::List::const_iterator pFragment = m_oAvailable.begin();
			pFragment != m_oAvailable.end(); ++pFragment )
		{
			CFragmentBar::DrawFragment( pDC, prcBar, m_pDownload->m_nSize,
				pFragment->begin(), pFragment->size(), crNatural, FALSE );
		}
		
		pDC->FillSolidRect( prcBar, CoolInterface.m_crWindow );
	}
	else if ( IsOnline() && HasUsefulRanges() || !m_oPastFragments.empty() )
	{
		pDC->FillSolidRect( prcBar, crNatural );
	}
	else
	{
		pDC->FillSolidRect( prcBar, CoolInterface.m_crWindow );
	}
}

void CDownloadSource::Draw(CDC* pDC, CRect* prcBar)
{
	ASSUME_LOCK( Transfers.m_pSection );

	static COLORREF crFill[] =
	{
		CoolInterface.m_crFragmentSource1, CoolInterface.m_crFragmentSource2,
		CoolInterface.m_crFragmentSource3, CoolInterface.m_crFragmentSource4,
		CoolInterface.m_crFragmentSource5, CoolInterface.m_crFragmentSource6
	};
	
	COLORREF crTransfer;
	
	if ( m_bReadContent )
	{
		crTransfer = crFill[ GetColour() ];
	}
	else
	{
		crTransfer = CoolInterface.m_crFragmentComplete;
	}
	
	crTransfer = CCoolInterface::CalculateColour( crTransfer, CoolInterface.m_crHighlight, 90 );
	
	if ( ! IsIdle() )
	{
		if ( GetState() == dtsDownloading &&
			 m_pTransfer->m_nOffset < SIZE_UNKNOWN )
		{
			if ( m_pTransfer->m_bRecvBackwards )
			{
				CFragmentBar::DrawFragment( pDC, prcBar, m_pDownload->m_nSize,
					m_pTransfer->m_nOffset + m_pTransfer->m_nLength - m_pTransfer->m_nPosition,
					m_pTransfer->m_nPosition, crTransfer, TRUE );
			}
			else
			{
				CFragmentBar::DrawFragment( pDC, prcBar, m_pDownload->m_nSize,
					m_pTransfer->m_nOffset,
					m_pTransfer->m_nPosition, crTransfer, TRUE );
			}
		}
	}
	
	for ( Fragments::List::const_iterator pFragment = m_oPastFragments.begin();
		pFragment != m_oPastFragments.end(); ++pFragment )
	{
		CFragmentBar::DrawFragment( pDC, prcBar, m_pDownload->m_nSize,
			pFragment->begin(), pFragment->size(), crTransfer, TRUE );
	}
}