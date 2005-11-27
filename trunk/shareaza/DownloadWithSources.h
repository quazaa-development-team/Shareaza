//
// DownloadWithSources.h
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

#if !defined(AFX_DOWNLOADWITHSOURCES_H__D6932F45_0557_4098_B2F3_AE35BC43ECC0__INCLUDED_)
#define AFX_DOWNLOADWITHSOURCES_H__D6932F45_0557_4098_B2F3_AE35BC43ECC0__INCLUDED_

#pragma once

#include "DownloadBase.h"

class CDownloadSource;
class CQueryHit;
class CXMLElement;


class CDownloadWithSources : public CDownloadBase
{
// Construction
protected:
	CDownloadWithSources();
	virtual ~CDownloadWithSources();
	
// Attributes
protected:
	CDownloadSource*	m_pSourceFirst;
private:
	CDownloadSource*	m_pSourceLast;
	CList< CString >			m_pFailedSources;
public:
	CXMLElement*		m_pXML;
	int					m_nSourceCount;

// Operations
public:
	CString				GetSourceURLs(CList< CString >* pState, int nMaximum, PROTOCOLID nProtocol, CDownloadSource* pExcept);
	int					GetSourceCount(BOOL bNoPush = FALSE, BOOL bSane = FALSE) const;
	int					GetBTSourceCount(BOOL bNoPush = FALSE) const;
	int					GetED2KCompleteSourceCount() const;
	BOOL				CheckSource(CDownloadSource* pSource) const;
	void				ClearSources();
public:
	BOOL				AddSourceHit(CQueryHit* pHit, BOOL bForce = FALSE);
	BOOL				AddSourceED2K(DWORD nClientID, WORD nClientPort, DWORD nServerIP, WORD nServerPort, const Hashes::Guid& oGUID);
    BOOL				AddSourceBT(const Hashes::BtGuid& oGUID, IN_ADDR* pAddress, WORD nPort);
	BOOL				AddSourceURL(LPCTSTR pszURL, BOOL bURN = FALSE, FILETIME* pLastSeen = NULL);
	int					AddSourceURLs(LPCTSTR pszURLs, BOOL bURN = FALSE);
	virtual BOOL		OnQueryHits(CQueryHit* pHits);
	virtual void		Serialize(CArchive& ar, int nVersion);

// Implementation
protected:
	void            RemoveOverlappingSources(QWORD nOffset, QWORD nLength);
	BOOL		    AddSourceInternal(CDownloadSource* pSource);
private:
	void		    RemoveSource(CDownloadSource* pSource, BOOL bBan);
	void		    SortSource(CDownloadSource* pSource, BOOL bTop);
	void		    SortSource(CDownloadSource* pSource);
	int			    GetSourceColour();

public:
	CDownloadSource* GetFirstSource() const
	{
		return m_pSourceFirst;
	}
	
	friend class CDownloadSource; // RemoveSource && GetSourceColour
	friend class CDownloadTransfer; // SortSource
};

#endif // !defined(AFX_DOWNLOADWITHSOURCES_H__D6932F45_0557_4098_B2F3_AE35BC43ECC0__INCLUDED_)
