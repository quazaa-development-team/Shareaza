//
// Downloads.h
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

#if !defined(AFX_DOWNLOADS_H__0C075423_D022_4530_8B45_6B7EF79712CB__INCLUDED_)
#define AFX_DOWNLOADS_H__0C075423_D022_4530_8B45_6B7EF79712CB__INCLUDED_

#pragma once

#include "ITMQueue.h"

class CDownload;
class CDownloadSource;
class CConnection;
class CQueryHit;
class CMatchFile;
class CBuffer;
class CShareazaURL;
class CEDClient;

class CDownloads
{
// Construction
public:
	CDownloads();
	virtual ~CDownloads();

// Attributes
public:
	DWORD			m_tBandwidthLastCalc;		// The last time the bandwidth was calculated
	DWORD			m_tBandwidthAtMax;			// The last time download bandwidth was all in use
	DWORD			m_tBandwidthAtMaxED2K;		// The last time all ed2k bandwidth was used

	DWORD			m_nLimitNew;				// Bandwidth assigned to new transfers

	DWORD			m_nLimitGeneric;
	DWORD			m_nLimitDonkey;
	DWORD			m_nTransfers;
	DWORD			m_nBandwidth;
	DWORD			m_nValidation;
	BOOL			m_bAllowMoreDownloads;
	BOOL			m_bAllowMoreTransfers;
	BOOL			m_bClosing;
	DWORD			m_tLastConnect;
protected:
	CList< CDownload* >				m_pList;
	CMap< ULONG, ULONG, int, int >	m_pHostLimits;
	int								m_nRunCookie;
	std::list<CDownload*>			m_oActiveSearches;
	std::list<CDownload*>			m_oPendingSearches;

public:
	enum
	{
		dlPathNull, dlPathComplete, dlPathIncomplete
	};

	class CITMQueryHit : CITMQueue::CITMItem
	{
		// Constructor
	public:
		CITMQueryHit();
		CITMQueryHit( CQueryHit * pHits );
		~CITMQueryHit();

		// Data Members
	public:
		CQueryHit*	m_pHits;

		// function members
	public:
		static CITMQueryHit* CreateMessage( CQueryHit * pHits );
		virtual BOOL OnProcess();

	};
	
// Operations
public:
	CDownload*	Add();
	CDownload*	Add(CQueryHit* pHit, BOOL bAddToHead = FALSE);
	CDownload*	Add(CMatchFile* pFile, BOOL bAddToHead = FALSE);
	CDownload*	Add(CShareazaURL* pURL);
	void		PauseAll();
	void		ClearCompleted();
	void		ClearPaused();
	void		Clear(BOOL bClosing = FALSE);
	void		CloseTransfers();
public:
	int			GetSeedCount() const;
	int			GetActiveTorrentCount() const;
	INT_PTR		GetCount(BOOL bActiveOnly = FALSE) const;
	int			GetTransferCount() const;
	int			GetTryingCount(BOOL bTorrentsOnly = FALSE) const;
	int			GetConnectingTransferCount() const;
	BOOL		Check(CDownloadSource* pSource) const;
	BOOL		CheckActive(CDownload* pDownload, int nScope) const;
	BOOL		Move(CDownload* pDownload, int nDelta);
	BOOL		Reorder(CDownload* pDownload, CDownload* pBefore);
	BOOL		Swap(CDownload* p1, CDownload* p2);
	CDownload*	FindByURN(LPCTSTR pszURN, BOOL bSharedOnly = FALSE) const;
	CDownload*	FindByHash(const Hashes::Sha1Hash& oSHA1, const Hashes::TigerHash& oTiger, const Hashes::Ed2kHash& oED2K,
							const Hashes::Md5Hash& oMD5, const Hashes::BtHash& oBTH, QWORD nMinSize = SIZE_UNKNOWN,
							QWORD nMaxSize = SIZE_UNKNOWN, BOOL bSharedOnly = FALSE) const;
	CDownload*	FindByBitprint(const Hashes::Sha1Hash& oSHA1, const Hashes::TigerHash& oTiger, BOOL bSharedOnly = FALSE) const;
    CDownload*	FindBySHA1(const Hashes::Sha1Hash& oSHA1, BOOL bSharedOnly = FALSE) const;
    CDownload*	FindByTiger(const Hashes::TigerHash& oTiger, BOOL bSharedOnly = FALSE) const;
	CDownload*	FindByED2K(const Hashes::Ed2kHash& oED2K, BOOL bSharedOnly /*= FALSE*/, BOOL bForceStarted /*= TRUE*/) const;
	CDownload*	FindByMD5(const Hashes::Md5Hash& oMD5, BOOL bSharedOnly = FALSE) const;
    CDownload*	FindByBTH(const Hashes::BtHash& oBTH, BOOL bSharedOnly /*= FALSE*/, BOOL bForceStarted /*= TRUE*/) const;
	CDownload*	FindBySID(DWORD nSerID) const;
	DWORD		GetFreeSID();
	QWORD		GetAmountDownloadedFrom(IN_ADDR* pAddress);
	DWORD		GetBandwidth() const;
public:
	void		Load();
	void		Save(BOOL bForce = TRUE);
	void		OnRun();
	BOOL		OnPush(const Hashes::Guid& oGUID, CConnection* pConnection, DWORD nFileIndex = 0);
	BOOL		OnDonkeyCallback(CEDClient* pClient, CDownloadSource* pExcept = NULL);
	void		OnQueryHits(CQueryHit* pHits);
	void		OnVerify(LPCTSTR pszPath, BOOL bVerified);
	void		SetPerHostLimit(IN_ADDR* pAddress, int nLimit);
	BOOL		IsSpaceAvailable(QWORD nVolume, int nPath = dlPathNull);
protected:
	void		UpdateAllows(BOOL bNew);
	BOOL		AllowMoreDownloads() const;
	BOOL		AllowMoreTransfers(IN_ADDR* pAdress = NULL) const;
	void		Remove(CDownload* pDownload);
	void		LoadFromCompoundFiles();
	BOOL		LoadFromCompoundFile(LPCTSTR pszFile);
	BOOL		LoadFromTimePair();
	void		SerializeCompound(CArchive& ar);
	void		PurgeDeletes();
	void		PurgePreviews();

// Inlines
public:
	inline POSITION CDownloads::GetIterator() const
	{
		return m_pList.GetHeadPosition();
	}

	inline POSITION CDownloads::GetReverseIterator() const
	{
		return m_pList.GetTailPosition();
	}

	inline CDownload* CDownloads::GetNext(POSITION& pos) const
	{
		return m_pList.GetNext( pos );
	}

	inline CDownload* CDownloads::GetPrevious(POSITION& pos) const
	{
		return m_pList.GetPrev( pos );
	}

	inline BOOL CDownloads::Check(CDownload* pDownload) const
	{
		return m_pList.Find( pDownload ) != NULL;
	}

	friend class CDownload;
	friend class CDownloadBase;
	friend class CDownloadWithTransfers;
	friend class CDownloadWithSearch;
	friend class CDownloadSource;
};

extern CDownloads Downloads;


#endif // !defined(AFX_DOWNLOADS_H__0C075423_D022_4530_8B45_6B7EF79712CB__INCLUDED_)
