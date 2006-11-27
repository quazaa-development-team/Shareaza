//
// HTTPClient.h
//
//  Authour:	"$Author: CyberBob $"
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

#if !defined(HTTPCLIENT_H)
#define HTTPCLIENT_H

#pragma once

#include "Connection.h"


class CHTTPClient : public CConnection
{
// TypeDefs, Enums, and Structures
public:
	enum cnState
	{
		cnNull,				// not doing anything yet
		cnConnecting,		// Connecting
		cnRequesting,		// Requesting
		cnUploading,		// Sending content like contents gets sent by POST command
		cnResponce,			// Waiting for response to Request
		cnHeaders,			// Reading Headers on response
		cnDownloading		// Receiving Content
	};

	struct HeaderTag
	{
		CString	Tag;
		CString Value;
	};

	typedef	std::list<HeaderTag>	TagList;
	class CEventHandler
	{
		public:
			virtual void	OnConnected( CHTTPClient* pObj );
			virtual void	OnRun( CHTTPClient* pObj );
			virtual BOOL	OnWriteContent( CHTTPClient* pObj, CBuffer* pBuffer );
			virtual	BOOL	OnResponceLine( CHTTPClient* pObj, CString & pRawString, 
							CString & pProtocol, CString & pCode, CString & pMessage );
			virtual BOOL	OnHeaderLine(CHTTPClient* pObj, CString& strHeader, CString& strValue);
			virtual	BOOL	OnHeadersComplete( CHTTPClient* pObj );
			virtual BOOL	OnReadContent( CHTTPClient* pObj, LPBYTE pDATA, QWORD nLength);
			virtual	BOOL	OnTransactionComplete( CHTTPClient* pObj );
			virtual void	OnDropped( CHTTPClient* pObj, BOOL bError );
			virtual void	OnClose( CHTTPClient* pObj );
			virtual void	OnClosed( CHTTPClient* pObj );

		// friend definition
		friend class CHTTPClient;
	};
	
// Construction
public:
	CHTTPClient(CEventHandler* pEvent = NULL);
	CHTTPClient(CString & sRawRequestString, TagList * pTags = NULL, CEventHandler* pEvent = NULL);
	CHTTPClient(CString & sRequestCommand, CString & sURI, CString & sProtocolString, DWORD & nProtocolMajorVersion,
				DWORD & nProtocolminorVersion, TagList * pTags = NULL, CEventHandler* pEvent = NULL);
	CHTTPClient(CConnection & pConnection, CEventHandler* pEvent = NULL);
	CHTTPClient(CConnection & pConnection, CString & sRawRequestString, TagList * pTags = NULL, CEventHandler* pEvent = NULL);
	CHTTPClient(CConnection & pConnection, CString & sRequestCommand, CString & sURI, CString & sProtocolString,
				DWORD & nProtocolMajorVersion, DWORD & nProtocolminorVersion, TagList * pTags = NULL,
				CEventHandler* pEvent = NULL);
	virtual ~CHTTPClient();

// Attributes
public:
	// comment example will make request string like
	// GET /index.html HTTP/1.0

	CString 				m_sRequestCommand;			// e.g. GET
	CString 				m_sURI;						// e.g. /index.html
	CString 				m_sProtocolString;			// e.g. HTTP
	DWORD					m_nProtocolMajorVersion;	// e.g. 1
	DWORD					m_nProtocolminorVersion;	// e.g. 0

	CString					m_sRawRequestString;		// e.g. GET /index.html HTTP/1.0
														// can be something like below too:
														// GNUTELLA CONNECT/0.6


protected:
	CEventHandler*			m_pEvent;
	DWORD					m_tConnected;
	DWORD					m_tRequest;
	DWORD					m_tLastInput;
	DWORD					m_tLastOutput;
	BOOL					m_bKeepAlive;
	BOOL					m_bHead;
	CString					m_sResponce;
	CString					m_sResponceCode;
	DWORD					m_nResponceCode;
	CString					m_sResponceProtocol;
	CString					m_sResponceMessage;
	QWORD					m_nContentLength;
	DWORD					m_nUnderRunNotify;

	QWORD					m_nOffset;
	QWORD					m_nLength;
	QWORD					m_nPosition;
	QWORD					m_nDownloaded;

	
	CString					m_sContentType;
	cnState					m_nState;
	TagList*				m_pSendTags;	
	TagList*				m_pReceivedTags;
// Operations
public:

	virtual BOOL	ConnectTo( SOCKADDR_IN & pAddr );
	virtual void	Close();
	virtual BOOL	OnConnected();
	virtual	BOOL	SendRequest();
	virtual BOOL	OnRun();
	virtual BOOL	OnRead();
	virtual BOOL	OnWrite();
	virtual	BOOL	ReadResponseLine();
	virtual	BOOL	OnHeaderLine(CString& strHeader, CString& strValue);
	virtual	BOOL	OnHeadersComplete();
	virtual	BOOL	ReadContent();
	virtual BOOL	OnWriteContent();
	virtual	BOOL	OnTransactionComplete();
	virtual	void	OnDropped(BOOL bError = FALSE);
	
private:
	
protected:

// friend definition	
	friend class CEventHandler;
};

#endif // !defined(HTTPCLIENT_H)
