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

class CDownload;
class CDownloadTransfer;
class CQueryHit;
class CEDClient;

class CDownloadSource
{
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
	int					m_nFailures;			// failure count.
	int					m_nBusyCount;			// busy count. (used for incrementing RetryDelay)
	int					m_nRedirectionCount;
	Fragments::List		m_oAvailable;
	Fragments::List		m_oPastFragments;

// Operations
public:
	BOOL		ResolveURL();
	void		Serialize(CArchive& ar, int nVersion);
public:
	inline BOOL	CanInitiate(BOOL bNetwork, BOOL bEstablished) const;
	void		Remove(BOOL bCloseTransfer, BOOL bBan);
	void		OnFailure(BOOL bNondestructive, DWORD nRetryAfter = 0);
	void		OnResume();
	void		OnResumeClosed();
public:
	void		SetValid();
	void		SetLastSeen();
	void		SetGnutella(int nGnutella);
    BOOL		CheckHash(const Hashes::Sha1Hash& oSHA1);
    BOOL		CheckHash(const Hashes::TigerHash& oTiger);
    BOOL		CheckHash(const Hashes::Ed2kHash& oED2K);
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
		if ( m_oGUID.isValid() && pSource->m_oGUID.isValid() )
			return m_oGUID == pSource->m_oGUID;
		
		if ( m_nServerPort != pSource->m_nServerPort )
		{
			return FALSE;
		}
		else if ( m_nServerPort > 0 )
		{
			if ( m_pServerAddress.S_un.S_addr != pSource->m_pServerAddress.S_un.S_addr ) return FALSE;
			if ( m_pAddress.S_un.S_addr != pSource->m_pAddress.S_un.S_addr ) return FALSE;
		}
		else
		{
			if ( m_pAddress.S_un.S_addr != pSource->m_pAddress.S_un.S_addr ) return FALSE;
			if ( m_nPort != pSource->m_nPort ) return FALSE;
		}

		return TRUE;
	}

};

#endif // !defined(AFX_DOWNLOADSOURCE_H__F0391D3E_0376_4F0F_934A_2E80260C4ECA__INCLUDED_)
