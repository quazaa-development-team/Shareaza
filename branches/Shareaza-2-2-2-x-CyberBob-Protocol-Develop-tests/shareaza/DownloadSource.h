//
// DownloadSource.h
//
//	Date:			"$Date: 2006/01/11 20:32:05 $"
//	Revision:		"$Revision: 1.10 $"
//  Last change by:	"$Author: spooky23 $"
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

#if !defined(AFX_DOWNLOADSOURCE_H__F0391D3E_0376_4F0F_934A_2E80260C4ECA__INCLUDED_)
#define AFX_DOWNLOADSOURCE_H__F0391D3E_0376_4F0F_934A_2E80260C4ECA__INCLUDED_

#pragma once

#include "FileFragments.hpp"
#include "Network.h"
#include "Download.h"
#include "Downloads.h"

class CDownload;
class CDownloads;
class CDownloadTransfer;
class CQueryHit;
class CEDClient;

class CDownloadSource
{
// typedef
public:
	typedef std::list<SOCKADDR_IN> HubList;
	typedef std::list<SOCKADDR_IN>::iterator HubIndex;
// Construction
public:
	CDownloadSource(CDownload* pDownload);
	CDownloadSource(CDownload* pDownload, CQueryHit* pHit);
	CDownloadSource(CDownload* pDownload, DWORD nClientID, WORD nClientPort, DWORD nServerIP, WORD nServerPort, const Hashes::Guid& oGUID);
    CDownloadSource(CDownload* pDownload, const Hashes::BtGuid& oGUID, IN_ADDR* pAddress, WORD nPort);
	CDownloadSource(CDownload* pDownload, LPCTSTR pszURL, BOOL bSHA1 = FALSE, BOOL bHashAuth = FALSE, FILETIME* pLastSeen = NULL, int nRedirectionCount = 0);
	virtual ~CDownloadSource();
private:
	inline void Construct(CDownload* pDownload);

// Attributes
public:
	CDownload*			m_pDownload;
	CDownloadSource*	m_pPrev;
	CDownloadSource*	m_pNext;
	CDownloadTransfer*	m_pTransfer;
	BOOL				m_bSelected;
public:
	CString				m_sURL;
	PROTOCOLID			m_nProtocol;
	Hashes::Guid		m_oGUID;
	IN_ADDR				m_pAddress;
	WORD				m_nPort;
	IN_ADDR				m_pServerAddress;
	WORD				m_nServerPort;
public:
	CString				m_sName;
	DWORD				m_nIndex;
	BOOL				m_bHashAuth;
	BOOL				m_bSHA1;
	BOOL				m_bTiger;
	BOOL				m_bED2K;
	BOOL				m_bMD5;
public:
	CString				m_sServer;
	CString				m_sNick;
	DWORD				m_nSpeed;
	BOOL				m_bPushOnly;
	BOOL				m_bCloseConn;
	BOOL				m_bReadContent;
	FILETIME			m_tLastSeen;
	int					m_nGnutella;
	BOOL				m_bClientExtended;		// Does the user support extended (G2) functions? (In practice, this means can we use G2 chat, browse, etc...)
public:
	DWORD				m_nSortOrder;			// How should this source be sorted in the list?
	int					m_nColour;
	DWORD				m_tAttempt;
	int					m_nFailures;
	int					m_nRedirectionCount;
	Fragments::List		m_oAvailable;
	Fragments::List		m_oPastFragments;
	BOOL				m_bReConnect;			// Reconnect Flag for HTTP close connection
	HubList				m_oPushProxyList;		// Local PUSH Proxy List Storage for RouteCache backup (G1)
	HubList				m_oHubList;				// Local PUSH HubList Storage for RouteCache backup (G2)
	int					m_nPushAttempted;		// number of times PushRequest has been t

// Operations
public:
	BOOL		ResolveURL();
	void		Serialize(CArchive& ar, int nVersion);
public:
	void		Remove(BOOL bCloseTransfer, BOOL bBan);
	void		OnFailure(BOOL bNondestructive, DWORD nRetryAfter = 0);
	void		OnResume();
	BOOL		OnResumeClosed();
public:
	void		SetValid();
	void		SetLastSeen();
	void		SetGnutella(int nGnutella);
    BOOL		CheckHash(const Hashes::Sha1Hash& oSHA1);
    BOOL		CheckHash(const Hashes::TigerHash& oTiger);
	BOOL		CheckHash(const Hashes::Ed2kHash& oED2K);
	BOOL		CheckHash(const Hashes::Md5Hash& oMD5);
public:
	BOOL		PushRequest();
	BOOL		CheckPush(const Hashes::Guid& oClientID);
	BOOL		CheckDonkey(CEDClient* pClient);
public:
	void		AddFragment(QWORD nOffset, QWORD nLength, BOOL bMerge = FALSE);
	void		SetAvailableRanges(LPCTSTR pszRanges);
	BOOL		HasUsefulRanges() const;
	BOOL		TouchedRange(QWORD nOffset, QWORD nLength) const;
	int			GetColour();

	CDownloadTransfer*	CreateTransfer();

// Inlines
public:
	inline bool CDownloadSource::Equals(CDownloadSource* pSource) const
	{
		BOOL bSameProtocol = FALSE;

		if (	m_nProtocol == PROTOCOL_G1 ||
				m_nProtocol == PROTOCOL_G2 ||
				m_nProtocol == PROTOCOL_HTTP	)
		{
			if (	pSource->m_nProtocol == PROTOCOL_G1 ||
					pSource->m_nProtocol == PROTOCOL_G2 ||
					pSource->m_nProtocol == PROTOCOL_HTTP	)
			{
				bSameProtocol = TRUE;
			}
		}

		if ( m_nProtocol == pSource->m_nProtocol )
		{
			bSameProtocol = TRUE;
		}

		if ( !bSameProtocol ) return FALSE;

		if ( !m_bPushOnly && !pSource->m_bPushOnly )
		{
			if ( m_pAddress.S_un.S_addr == pSource->m_pAddress.S_un.S_addr )
				if ( m_nPort == pSource->m_nPort ) return TRUE;
		}
		else if ( m_bPushOnly && pSource->m_bPushOnly )
		{
			if ( m_nServerPort > 0 )
			{
				if ( m_pAddress.S_un.S_addr == pSource->m_pAddress.S_un.S_addr )
					if ( m_pServerAddress.S_un.S_addr == pSource->m_pServerAddress.S_un.S_addr ) return TRUE;
			}
		}

		if ( bSameProtocol && validAndEqual( m_oGUID, pSource->m_oGUID ) )
		{
			if ( m_oGUID != NULL )
				return TRUE;
		}

		return FALSE;
	}

	inline BOOL	CanInitiate(BOOL bNetwork, BOOL bEstablished) const
	{
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
				if ( ! Settings.eDonkey.EnableToday ) return FALSE;
				if ( ! bNetwork ) return FALSE;
				break;
			case PROTOCOL_HTTP:
				if ( m_nGnutella == 2 )
				{
					if ( ! Settings.Gnutella2.EnableToday ) return FALSE;
				}
				else if ( m_nGnutella == 1 )
				{
					if ( ! Settings.Gnutella1.EnableToday ) return FALSE;
				}
				else
				{
					if ( ! Settings.Gnutella1.EnableToday &&
						! Settings.Gnutella2.EnableToday ) return FALSE;
				}
				break;
			case PROTOCOL_FTP:
				if ( ! bNetwork ) return FALSE;
				break;
			case PROTOCOL_BT:
				if ( ! bNetwork ) return FALSE;
				break;
			default:
				theApp.Message( MSG_ERROR, _T("Source with invalid protocol found") );
				return FALSE;
			}
		}

		// Since this Function gets called from Connected Transaction too, need to use Flag bEstablished to determine if the
		// it is connected or not. if connected, not removing source here so no points to look up the source.
		// note: have included !Settings.Downloads.NeverDrop in condition but not sure if it is needed, since the state
		//       Bad Source is not unknown why the source has been marked as bad, but if it has been added because the source
		//       gave the wrong file(bad chunk, or bad combination of hashes), then it should be dropped in order to reduce damage
		//       to network. so this should be discussed and the Close() function need more different state such as NoReply(source
		//       is out of service), BadChunk(gave broken chunk), WrongFileSize|WrongHashes(basically anything indicating it is wrong
		//       file), Busy(just busy does not mean it should be removed), NoInterested(This should not remove the source either), 
		//       for indicating reason for marking as bad source.
		if ( !bEstablished && !Settings.Downloads.NeverDrop && m_pDownload->LookupFailedSource( m_sURL ) != NULL )
		{
			m_pDownload->RemoveSource( (CDownloadSource*)this, TRUE );
			return FALSE;
		}

		if ( ( Settings.Connection.IgnoreOwnIP ) && ( m_pAddress.S_un.S_addr == Network.m_pHost.sin_addr.S_un.S_addr ) ) 
			return FALSE;

		return bEstablished || Downloads.AllowMoreTransfers( (IN_ADDR*)&m_pAddress );
	}


};

#endif // !defined(AFX_DOWNLOADSOURCE_H__F0391D3E_0376_4F0F_934A_2E80260C4ECA__INCLUDED_)
