//
// DownloadWithSources.h
//
//	Date:			"$Date: 2006/04/04 23:54:15 $"
//	Revision:		"$Revision: 1.11 $"
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

#if !defined(AFX_DOWNLOADWITHSOURCES_H__D6932F45_0557_4098_B2F3_AE35BC43ECC0__INCLUDED_)
#define AFX_DOWNLOADWITHSOURCES_H__D6932F45_0557_4098_B2F3_AE35BC43ECC0__INCLUDED_

#pragma once

#include "DownloadBase.h"

class CDownloads;
class CDownloadSource;
class CQueryHit;
class CXMLElement;

typedef boost::shared_ptr<CQueryHit>	CHitPtr;
typedef std::list<CHitPtr>				CHitPtrs;

#pragma pack(1)
class CFailedSource
{
public:
	CFailedSource(LPCTSTR pszURL, bool bLocal=true, bool bOffline=false)
		: m_nTimeAdded( GetTickCount() )
		, m_nPositiveVotes( 0 )
		, m_nNegativeVotes( 0 )
		, m_sURL( pszURL )
		, m_bLocal( bLocal )
		, m_bOffline( bOffline ) { }

	virtual ~CFailedSource() { };

	DWORD_PTR	m_nTimeAdded;
	INT_PTR		m_nPositiveVotes;
	INT_PTR		m_nNegativeVotes;
	CString		m_sURL;
	bool		m_bLocal;
	bool		m_bOffline;
};
#pragma pack()

class CDownloadWithSources : public CDownloadBase
{
// Construction
protected:
	CDownloadWithSources();
	virtual ~CDownloadWithSources();
	
// Attributes
protected:
	CDownloadSource*	m_pSourceFirst;
	CCriticalSection	m_pSection;
	CList< CFailedSource* >	m_pFailedSources; // Failed source with a timestamp when added

private:
	CDownloadSource*	m_pSourceLast;

public:
	CXMLElement*		m_pXML;
	int					m_nSourceCount;

private:
	int					m_nG1SourceCount;
	int					m_nG2SourceCount;
	int					m_nEdSourceCount;
	int					m_nHTTPSourceCount;
	int					m_nBTSourceCount;
	int					m_nFTPSourceCount;

// Operations
public:
	CString				GetSourceURLs(CList< CString >* pState, int nMaximum, PROTOCOLID nProtocol, CDownloadSource* pExcept);
	CString				GetTopFailedSources(int nMaximum, PROTOCOLID nProtocol);
	int					GetEffectiveSourceCount() const;
	int					GetSourceCount(BOOL bNoPush = FALSE, BOOL bSane = FALSE) const;
	int					GetG2SourceCount(BOOL bNoPush = FALSE, BOOL bSane = FALSE) const;
	int					GetBTSourceCount(BOOL bNoPush = FALSE) const;
	int					GetED2KCompleteSourceCount() const;
	void				GetMultiSourceCount(BOOL bSane, int* nHTTPSources = NULL, int* nG1Sources = NULL, int* nG2Sources = NULL, int* nED2KSources = NULL, int* nBTSources = NULL);
	BOOL				CheckSource(CDownloadSource* pSource) const;
	void				AddFailedSource(CDownloadSource* pSource, bool bLocal = true, bool bOffline = false);
	void				AddFailedSource(LPCTSTR pszUrl, bool bLocal = true, bool bOffline = false);
	CFailedSource*		LookupFailedSource(LPCTSTR pszUrl, bool bReliable = false);
	void				ExpireFailedSources();
	void				VoteSource(LPCTSTR pszUrl, bool bPositively);
	void				ClearSources();
	void				ClearOldSources();
	void				ClearFailedSources();
public:
	BOOL				AddSourceHit(CQueryHit* pHit, BOOL bForce = FALSE);
	BOOL				AddSourceED2K(DWORD nClientID, WORD nClientPort, DWORD nServerIP, WORD nServerPort, const Hashes::Guid& oGUID);
    BOOL				AddSourceBT(const Hashes::BtGuid& oGUID, IN_ADDR* pAddress, WORD nPort);
	BOOL				AddSourceURL(LPCTSTR pszURL, BOOL bURN = FALSE, FILETIME* pLastSeen = NULL, int nRedirectionCount = 0,
									BOOL bFailed = FALSE, PROTOCOLID nProtocol = PROTOCOL_HTTP);
	int					AddSourceURLs(LPCTSTR pszURLs, BOOL bURN = FALSE, BOOL bFailed = FALSE, PROTOCOLID nProtocol = PROTOCOL_HTTP);
	virtual BOOL		OnQueryHits(CQueryHit* pHits);
	virtual BOOL		OnQueryHits(CHitPtrs& m_oHits);
	virtual void		Serialize(CArchive& ar, int nVersion);

// Implementation
protected:
	void            RemoveOverlappingSources(QWORD nOffset, QWORD nLength);
	BOOL		    AddSourceInternal(CDownloadSource* pSource);
private:
	void		    RemoveSource(CDownloadSource* pSource, BOOL bBan);
protected:
	void		    SortSource(CDownloadSource* pSource, BOOL bTop);
	void		    SortSource(CDownloadSource* pSource);
private:
	int			    GetSourceColour();

public:
	CDownloadSource* GetFirstSource() const
	{
		return m_pSourceFirst;
	}
	
	friend class CDownloads; // access to m_n[G1|G2|Ed|HTTP|BT|FTP]SourceCount
	friend class CDownloadSource; // RemoveSource && GetSourceColour
	friend class CDownloadTransfer; // SortSource
	friend class CDownloadWithSearch; // access to m_n[G1|G2|Ed|HTTP|BT|FTP]SourceCount
};

#endif // !defined(AFX_DOWNLOADWITHSOURCES_H__D6932F45_0557_4098_B2F3_AE35BC43ECC0__INCLUDED_)
