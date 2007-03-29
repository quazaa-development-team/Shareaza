//
// DownloadTransferHTTP.h
//
//	Date:			"$Date: 2006/01/11 20:32:05 $"
//	Revision:		"$Revision: 1.7 $"
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

#if !defined(AFX_DOWNLOADTRANSFERHTTP_H__EE18C980_54B9_40EF_A55B_42FC2AAEA3B0__INCLUDED_)
#define AFX_DOWNLOADTRANSFERHTTP_H__EE18C980_54B9_40EF_A55B_42FC2AAEA3B0__INCLUDED_

#pragma once

#include "DownloadTransfer.h"


class CDownloadTransferHTTP : public CDownloadTransfer
{
// Construction
public:
	CDownloadTransferHTTP(CDownloadSource* pSource);
	virtual ~CDownloadTransferHTTP();

// Attributes
protected:
	DWORD			m_nRequests;
	DWORD			m_tRequest;
	DWORD			m_tContent;
	CString			m_sTigerTree;
	CString			m_sMetadata;
	QWORD			m_nContentLength;
	CString			m_sContentType;
	DWORD			m_nRetryDelay;
	CString			m_sRedirectionURL;
	DWORD			m_nRetryAfter;
	// members below are just 1Bit BOOLs thus no need to use 32bit for each.
	BOOL			m_bBadResponse	:1;
	BOOL			m_bBusyFault	:1;
	BOOL			m_bRangeFault	:1;
	BOOL			m_bKeepAlive	:1;
	BOOL			m_bHashMatch	:1;
	BOOL			m_bTigerFetch	:1;
	BOOL			m_bTigerIgnore	:1;
	BOOL			m_bMetaFetch	:1;
	BOOL			m_bMetaIgnore	:1;
	BOOL			m_bGotRange		:1;
	BOOL			m_bGotRanges	:1;
	BOOL			m_bQueueFlag	:1;
	BOOL			m_bRedirect		:1;
	BOOL			m_bTigerForced	:1;
	BOOL			m_bTigerFailed	:1;
	BOOL			m_bHeadRequest	:1;
	BOOL			m_bGUIDSent		:1;
	BOOL			m_bPushWaiting	:1;

// Operations
public:
	virtual BOOL	Initiate();
	BOOL			AcceptPush(CConnection* pConnection);
	virtual void	Close( TRISTATE bKeepSource, DWORD nRetryAfter = 0 );
	virtual void	Boost();
	virtual DWORD	GetAverageSpeed();
	virtual BOOL	SubtractRequested(Fragments::List& ppFragments);
	virtual BOOL	OnRun();
protected:
	BOOL			StartNextFragment();
	BOOL			SendRequest();
	BOOL			ReadResponseLine();
	BOOL			ReadContent();
	BOOL			ReadTiger();
	BOOL			ReadMetadata();
	BOOL			ReadFlush();
protected:
	virtual BOOL	OnConnected();
	virtual BOOL	OnRead();
	virtual void	OnDropped(BOOL bError);
	virtual BOOL	OnHeaderLine(CString& strHeader, CString& strValue);
	virtual BOOL	OnHeadersComplete();

	friend CDownloadWithTransfers;
};

#endif // !defined(AFX_DOWNLOADTRANSFERHTTP_H__EE18C980_54B9_40EF_A55B_42FC2AAEA3B0__INCLUDED_)
