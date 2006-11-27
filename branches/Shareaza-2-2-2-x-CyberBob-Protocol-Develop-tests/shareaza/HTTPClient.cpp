//
// HTTPClient.cpp
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

#include "StdAfx.h"
#include "Shareaza.h"
#include "Settings.h"
#include "Buffer.h"
#include "Connection.h"
#include "HTTPClient.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif


//////////////////////////////////////////////////////////////////////
// CHTTPClient construction

CHTTPClient::CHTTPClient( CEventHandler* pEvent ) : CConnection()
{
	// comment example will make request string like
	// GET /index.html HTTP/1.0
	m_sRequestCommand	= _T("");	// e.g. GET
	m_sURI				= _T("");	// e.g. /index.html
	m_sProtocolString	= _T("");	// e.g. HTTP
	m_nProtocolMajorVersion = 0;	// e.g. 1
	m_nProtocolminorVersion = 0;	// e.g. 0

	m_sRawRequestString	= _T("");	// e.g. GET /index.html HTTP/1.0
	// can be something like below too:
	// GNUTELLA CONNECT/0.6

	m_pEvent			= pEvent;
	m_nState			= cnNull;
	m_sResponce			= "";
	m_nResponceCode		= 0;
	m_sResponceCode		= "";
	m_sResponceProtocol	= "";
	m_sResponceMessage	= "";
	m_nContentLength	= 0;

	m_nLength			= 0;
	m_nPosition			= 0;
	m_sContentType		= "";

	m_tRequest			= 0;
	m_tLastInput		= 0;
	m_tLastOutput		= 0;
	m_tConnected		= 0;

	m_bKeepAlive		= FALSE;
	m_pSendTags			= NULL;	
	m_pReceivedTags		= NULL;

}

CHTTPClient::CHTTPClient(CString & sRawRequestString, TagList * pTags, CEventHandler* pEvent ) : CConnection()
{
	// comment example will make request string like
	// GET /index.html HTTP/1.0
	m_sRequestCommand	= _T("");	// e.g. GET
	m_sURI				= _T("");	// e.g. /index.html
	m_sProtocolString	= _T("");	// e.g. HTTP
	m_nProtocolMajorVersion = 0;	// e.g. 1
	m_nProtocolminorVersion = 0;	// e.g. 0

	m_sRawRequestString	= sRawRequestString;	// e.g. GET /index.html HTTP/1.0
	// can be something like below too:
	// GNUTELLA CONNECT/0.6

	m_pEvent			= pEvent;
	m_nState			= cnNull;
	m_sResponce			= "";
	m_nResponceCode		= 0;
	m_sResponceCode		= "";
	m_sResponceProtocol	= "";
	m_sResponceMessage	= "";
	m_nContentLength	= 0;

	m_nLength			= 0;
	m_nPosition			= 0;
	m_sContentType		= "";

	m_tRequest			= 0;
	m_tLastInput		= 0;
	m_tLastOutput		= 0;
	m_tConnected		= 0;

	m_bKeepAlive		= FALSE;
	m_pSendTags			= pTags;	
	m_pReceivedTags		= NULL;

}

CHTTPClient::CHTTPClient(CString & sRequestCommand, CString & sURI, CString & sProtocolString, DWORD & nProtocolMajorVersion,
						 DWORD & nProtocolminorVersion, TagList * pTags, CEventHandler* pEvent) : CConnection()
{
	// comment example will make request string like
	// GET /index.html HTTP/1.0
	m_sRequestCommand	= sRequestCommand;	// e.g. GET
	m_sURI				= sURI;	// e.g. /index.html
	m_sProtocolString	= sProtocolString;	// e.g. HTTP
	m_nProtocolMajorVersion = nProtocolMajorVersion;	// e.g. 1
	m_nProtocolminorVersion = nProtocolminorVersion;	// e.g. 0

	m_sRawRequestString	= _T("");	// e.g. GET /index.html HTTP/1.0
	// can be something like below too:
	// GNUTELLA CONNECT/0.6

	m_pEvent			= pEvent;
	m_nState			= cnNull;
	m_sResponce			= "";
	m_nResponceCode		= 0;
	m_sResponceCode		= "";
	m_sResponceProtocol	= "";
	m_sResponceMessage	= "";
	m_nContentLength	= 0;

	m_nLength			= 0;
	m_nPosition			= 0;
	m_sContentType		= "";

	m_tRequest			= 0;
	m_tLastInput		= 0;
	m_tLastOutput		= 0;
	m_tConnected		= 0;

	m_bKeepAlive		= FALSE;
	m_pSendTags			= pTags;	
	m_pReceivedTags		= NULL;

}

CHTTPClient::CHTTPClient( CConnection& pConnection, CEventHandler* pEvent ) : CConnection( pConnection )
{
	// comment example will make request string like
	// GET /index.html HTTP/1.0
	m_sRequestCommand	= _T("");	// e.g. GET
	m_sURI				= _T("");	// e.g. /index.html
	m_sProtocolString	= _T("");	// e.g. HTTP
	m_nProtocolMajorVersion = 0;	// e.g. 1
	m_nProtocolminorVersion = 0;	// e.g. 0

	m_sRawRequestString	= _T("");	// e.g. GET /index.html HTTP/1.0
	// can be something like below too:
	// GNUTELLA CONNECT/0.6

	m_pEvent			= pEvent;
	m_nState			= cnNull;
	m_sResponce			= "";
	m_nResponceCode		= 0;
	m_sResponceCode		= "";
	m_sResponceProtocol	= "";
	m_sResponceMessage	= "";
	m_nContentLength	= 0;

	m_nLength			= 0;
	m_nPosition			= 0;
	m_sContentType		= "";

	m_tRequest			= 0;
	m_tLastInput		= 0;
	m_tLastOutput		= 0;
	m_tConnected		= 0;

	m_bKeepAlive		= FALSE;
	m_pSendTags			= NULL;	
	m_pReceivedTags		= NULL;

}

CHTTPClient::CHTTPClient(CConnection& pConnection, CString & sRawRequestString, TagList * pTags, CEventHandler* pEvent )
						: CConnection(pConnection)
{
	// comment example will make request string like
	// GET /index.html HTTP/1.0
	m_sRequestCommand	= _T("");	// e.g. GET
	m_sURI				= _T("");	// e.g. /index.html
	m_sProtocolString	= _T("");	// e.g. HTTP
	m_nProtocolMajorVersion = 0;	// e.g. 1
	m_nProtocolminorVersion = 0;	// e.g. 0

	m_sRawRequestString	= sRawRequestString;	// e.g. GET /index.html HTTP/1.0
												// can be something like below too:
												// GNUTELLA CONNECT/0.6

	m_pEvent			= pEvent;
	m_nState			= cnNull;
	m_sResponce			= "";
	m_nResponceCode		= 0;
	m_sResponceCode		= "";
	m_sResponceProtocol	= "";
	m_sResponceMessage	= "";
	m_nContentLength	= 0;

	m_nLength			= 0;
	m_nPosition			= 0;
	m_sContentType		= "";

	m_tRequest			= 0;
	m_tLastInput		= 0;
	m_tLastOutput		= 0;
	m_tConnected		= 0;

	m_bKeepAlive		= FALSE;
	m_pSendTags			= pTags;	
	m_pReceivedTags		= NULL;

}

CHTTPClient::CHTTPClient(CConnection& pConnection, CString & sRequestCommand, CString & sURI, CString & sProtocolString, 
						DWORD & nProtocolMajorVersion, DWORD & nProtocolminorVersion, TagList * pTags, CEventHandler* pEvent)
						: CConnection(pConnection)
{
	// comment example will make request string like
	// GET /index.html HTTP/1.0
	m_sRequestCommand	= sRequestCommand;	// e.g. GET
	m_sURI				= sURI;	// e.g. /index.html
	m_sProtocolString	= sProtocolString;	// e.g. HTTP
	m_nProtocolMajorVersion = nProtocolMajorVersion;	// e.g. 1
	m_nProtocolminorVersion = nProtocolminorVersion;	// e.g. 0

	m_sRawRequestString	= _T("");	// e.g. GET /index.html HTTP/1.0
									// can be something like below too:
									// GNUTELLA CONNECT/0.6

	m_pEvent			= pEvent;
	m_nState			= cnNull;
	m_sResponce			= "";
	m_nResponceCode		= 0;
	m_sResponceCode		= "";
	m_sResponceProtocol	= "";
	m_sResponceMessage	= "";
	m_nContentLength	= 0;

	m_nLength			= 0;
	m_nPosition			= 0;
	m_sContentType		= "";

	m_tRequest			= 0;
	m_tLastInput		= 0;
	m_tLastOutput		= 0;
	m_tConnected		= 0;

	m_bKeepAlive		= FALSE;
	m_pSendTags			= pTags;	
	m_pReceivedTags		= NULL;

}

CHTTPClient::~CHTTPClient()
{
}

//////////////////////////////////////////////////////////////////////
// CHTTPClient initiate connection

BOOL CHTTPClient::ConnectTo( SOCKADDR_IN & pAddr )
{
	if ( ConnectTo( pAddr ) )
	{
		m_nState	= cnConnecting;
		// m_mInput.pLimit = m_mOutput.pLimit = &m_nBandwidth;
		return TRUE;
	}
	return FALSE;
}

//////////////////////////////////////////////////////////////////////
// CHTTPClient close

void CHTTPClient::Close()
{
	// was gonna make check for function existence, but looks like it is not possible.
	//if ( m_pEvent != NULL && m_pEvent->OnClose != NULL ) m_pEvent->OnClose( this );
	if ( m_pEvent != NULL ) m_pEvent->OnClose( this );

	CConnection::Close();

	if ( m_pEvent != NULL ) m_pEvent->OnClosed( this );
}

//////////////////////////////////////////////////////////////////////
// CHTTPClient connection handler

BOOL CHTTPClient::OnConnected()
{
	m_tConnected = GetTickCount();
	if ( m_pEvent != NULL ) m_pEvent->OnConnected( this );
	return SendRequest();
}

//////////////////////////////////////////////////////////////////////
// CHTTPClient send request

BOOL CHTTPClient::SendRequest()
{
	CString strLine;
	
	if ( !m_sRawRequestString.IsEmpty() && m_sRequestCommand.IsEmpty() && m_sURI.IsEmpty() && m_sProtocolString.IsEmpty() )
	{
		m_pOutput->Print( m_sRawRequestString );
		m_pOutput->Print( "\r\n" );
	}
	else
	{
		if ( m_sRequestCommand.IsEmpty() ) return FALSE;
		m_sRawRequestString = m_sRequestCommand;
		if ( m_sRequestCommand == "HEAD") m_bHead = TRUE;
		if ( !m_sURI.IsEmpty() ) m_sRawRequestString += " " + m_sURI;
		if ( m_sProtocolString.IsEmpty() ) return FALSE;
		m_sRawRequestString.AppendFormat(_T(" %s/%i.%i\r\n"), m_sProtocolString, m_nProtocolMajorVersion, m_nProtocolminorVersion );
		m_pOutput->Print( m_sRawRequestString );
		if ( m_sProtocolString == "HTTP" && m_nProtocolMajorVersion == 1 && 
			m_nProtocolminorVersion == 1 ) m_bKeepAlive = TRUE;
	}

	for ( TagList::iterator pTagItem = m_pSendTags->begin() ; pTagItem == m_pSendTags->end() ; pTagItem++ )
	{
		if ( pTagItem->Tag.CompareNoCase( _T("Connection") ) == 0 )
		{
			if ( pTagItem->Value.CompareNoCase( _T("Keep-Alive") ) == 0 ) 
			{
				m_bKeepAlive = TRUE;
			}
			if ( pTagItem->Value.CompareNoCase( _T("close") ) == 0 ) 
			{
				m_bKeepAlive = FALSE;
			}
		}
		else if ( pTagItem->Tag.CompareNoCase( _T("Content-Length") ) == 0 )
		{
			_stscanf( pTagItem->Value, _T("%I64i"), &m_nContentLength );
		}
		strLine = pTagItem->Tag + ": " + pTagItem->Value + "\r\n";
		m_pOutput->Print( strLine );
	}
	
	m_tRequest	= GetTickCount();
	m_pOutput->Print( "\r\n" );

	m_nState	= cnRequesting;

	if ( !CConnection::OnWrite() ) return FALSE;

	if ( m_nContentLength == 0 )
	{
		m_nState	= cnResponce;
	}
	else
	{
		m_nState	= cnUploading;
	}
	

	return TRUE;
}

BOOL CHTTPClient::OnWriteContent()
{
	if ( m_pOutput->m_nLength > 0 ) return OnWrite();
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CHTTPClient run handler

BOOL CHTTPClient::OnRun()
{
	CConnection::OnRun();

	if ( m_pEvent != NULL ) m_pEvent->OnRun( this );
	
	DWORD tNow = GetTickCount();
	
	// ToD need to implement Timeouts
	switch ( m_nState )
	{
		case cnNull:
			break;
		case cnConnecting:
			if ( tNow - m_tConnected > Settings.Connection.TimeoutConnect )
				Close();
			break;
		case cnRequesting:
			if (tNow - m_tRequest > Settings.Connection.TimeoutTraffic * 2)
				Close();
			break;
		case cnUploading:
			if ( m_nContentLength > 0 )
			{
				DWORD nLength = 0;
				if ( m_pOutput->m_nLength <= m_nUnderRunNotify && m_pEvent != NULL && !m_pEvent->OnWriteContent( this, m_pOutput )) return FALSE;
				nLength = m_pOutput->m_nLength;
				if ( m_pOutput->m_nLength > 0 && !OnWriteContent() ) return FALSE;
				m_nContentLength = m_nContentLength - ( nLength - m_pOutput->m_nLength );
				return TRUE;
			}
			else
			{
				m_tRequest	= GetTickCount();	// Quick hack to prevent being Uploading State makes timeout for response
				m_nState = cnResponce;
			}
			break;

		case cnResponce:
			if (tNow - m_tRequest > Settings.Connection.TimeoutTraffic * 2)
				Close();
			break;
		case cnHeaders:
			if (tNow - m_tLastInput > Settings.Connection.TimeoutTraffic * 2)
				Close();
			break;
		case cnDownloading:
			if (tNow - m_tLastInput > Settings.Connection.TimeoutTraffic * 2)
				Close();
			break;
	}

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CHTTPClient read handler

BOOL CHTTPClient::OnRead()
{
	CConnection::OnRead();
	
	m_tLastInput = GetTickCount();

	switch ( m_nState )
	{
		case cnNull:
			break;
		case cnConnecting:
			break;
		case cnRequesting:
			return FALSE;
			break;
		case cnUploading:
			break;
		case cnResponce:
			if ( ! ReadResponseLine() ) return FALSE;
			if ( m_nState != cnHeaders ) break;

		case cnHeaders:
			if ( ! ReadHeaders() ) return FALSE;
			if ( m_nState != cnDownloading ) break;

		case cnDownloading:
			return ReadContent();
	}

	return TRUE;
}

BOOL CHTTPClient::OnWrite()
{
	m_tLastOutput  = GetTickCount();
	return CConnection::OnWrite();
}

//////////////////////////////////////////////////////////////////////
// CHTTPClient read response line

BOOL CHTTPClient::ReadResponseLine()
{

	if ( ! m_pInput->ReadLine( m_sResponce ) ) return TRUE;
	if ( m_sResponce.IsEmpty() ) return TRUE;

	m_sResponce = _T("");
	m_sResponceProtocol = _T("");
	m_sResponceCode = _T("");
	m_sResponceMessage = _T("");

	if ( m_sResponce.GetLength() > 512 ) m_sResponce = _T("#LINE_TOO_LONG#");
	
	theApp.Message( MSG_DEBUG, _T("%s: DOWNLOAD RESPONSE: %s"), (LPCTSTR)m_sAddress, (LPCTSTR)m_sResponce );
	
	if ( m_sResponce.GetLength() >= 12 && m_sResponce.Left( 9 ) == _T("HTTP/1.1 ") )
	{
		m_sResponceProtocol	= m_sResponce.Left( 9 );
		m_sResponceCode		= m_sResponce.Mid( 9, 3 );
		m_sResponceMessage	= m_sResponce.Mid( 12 );
		_stscanf( m_sResponceCode, _T("%I64i"), &m_nResponceCode );
		m_bKeepAlive = TRUE;
		if ( m_pEvent != NULL )
		{
			if ( m_pEvent->OnResponceLine( this, m_sResponce, m_sResponceProtocol, m_sResponceCode, m_sResponceMessage ) )
			{
			}
			else
			{
				m_bKeepAlive = FALSE;
				Close();
				return FALSE;
			}
		}
	}
	else if ( m_sResponce.GetLength() >= 12 && m_sResponce.Left( 9 ) == _T("HTTP/1.0 ") )
	{
		m_sResponceProtocol	= m_sResponce.Left( 9 );
		m_sResponceCode		= m_sResponce.Mid( 9, 3 );
		m_sResponceMessage	= m_sResponce.Mid( 12 );
		_stscanf( m_sResponceCode, _T("%I64i"), &m_nResponceCode );
		if ( m_pEvent != NULL )
		{
			if ( m_pEvent->OnResponceLine( this, m_sResponce, m_sResponceProtocol, m_sResponceCode, m_sResponceMessage ) )
			{
			}
			else
			{
				Close();
				return FALSE;
			}
		}
	}
	else if ( m_sResponce.GetLength() >= 8 && m_sResponce.Left( 4 ) == _T("HTTP") )
	{
		m_sResponceProtocol	= m_sResponce.Left( 4 );
		m_sResponceCode		= m_sResponce.Mid( 5, 3 );
		m_sResponceMessage	= m_sResponce.Mid( 8 );
		_stscanf( m_sResponceCode, _T("%I64i"), &m_nResponceCode );
		if ( m_pEvent != NULL )
		{
			if ( m_pEvent->OnResponceLine( this, m_sResponce, m_sResponceProtocol, m_sResponceCode, m_sResponceMessage ) )
			{
			}
			else
			{
				Close();
				return FALSE;
			}
		}
	}
	else
	{
		if ( m_pEvent != NULL )
		{
			if ( !m_pEvent->OnResponceLine( this, m_sResponce, m_sResponceProtocol, m_sResponceCode, m_sResponceMessage ) )
			{
				m_bKeepAlive = FALSE;
				Close();
				return FALSE;
			}
		}
		else
		{
			Close();
			return FALSE;
		}
	}
	
	if ( m_sResponceCode == _T("200") || m_sResponceCode == _T("206") )
	{
	}
	else if ( m_sResponceCode == _T("503") )
	{
	}
	else if ( m_sResponceCode == _T("416") )
	{
	}
	else if ( m_sResponceCode == _T("301") || m_sResponceCode == _T("302") )
	{
	}
	else if ( m_sResponceCode == _T("404") )
	{
	}
	else
	{
	}

	m_nState	= cnHeaders;
	
	if ( m_pReceivedTags != NULL ) m_pReceivedTags->clear();
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CHTTPClient read header lines

BOOL CHTTPClient::OnHeaderLine(CString& strHeader, CString& strValue)
{
	if ( m_pReceivedTags != NULL )
	{
		HeaderTag	pTag;
		pTag.Tag	= strHeader;
		pTag.Value	= strValue;
		m_pReceivedTags->push_back( pTag );
	}

	if ( m_pEvent != NULL && !m_pEvent->OnHeaderLine( this, strHeader, strValue ) ) return FALSE;

	if ( strHeader.CompareNoCase( _T("Connection") ) == 0 )
	{
		if ( strValue.CompareNoCase( _T("Keep-Alive") ) == 0 ) 
		{
			m_bKeepAlive = TRUE;
		}
		if ( strValue.CompareNoCase( _T("close") ) == 0 ) 
		{
			m_bKeepAlive = FALSE;
		}
	}
	else if ( strHeader.CompareNoCase( _T("Content-Length") ) == 0 )
	{
		_stscanf( strValue, _T("%I64i"), &m_nContentLength );
	}
	else if ( strHeader.CompareNoCase( _T("Content-Type") ) == 0 )
	{
		m_sContentType = strValue;
	}

	return CConnection::OnHeaderLine( strHeader, strValue );
}

//////////////////////////////////////////////////////////////////////
// CHTTPClient end of headers

BOOL CHTTPClient::OnHeadersComplete()
{
	m_nLength = m_nContentLength;
	if ( m_bHead == TRUE ) m_nContentLength = 0;
	if ( m_pEvent != NULL && !m_pEvent->OnHeadersComplete( this ) ) return FALSE;
	if ( m_nContentLength == 0 && m_pEvent != NULL && !m_pEvent->OnTransactionComplete ( this ) ) return FALSE;
	m_nOffset = 0;
	m_nPosition = 0;
	m_nState = cnDownloading;
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CHTTPClient read content

BOOL CHTTPClient::ReadContent()
{
	if ( m_pInput->m_nLength > 0 )
	{
		DWORD nLength	= m_pInput->m_nLength;
		BOOL bSubmit	= FALSE;

		if ( m_pEvent != NULL )
		{
			bSubmit = m_pEvent->OnReadContent( this, m_pInput->m_pBuffer, nLength );
			m_pInput->Clear();	// Clear the buffer, we don't want any crap
			m_nPosition += nLength;

			if ( ! bSubmit )
			{
				return FALSE;
			}
		}
		else
		{

		}
	}	

	if ( ! (m_nPosition < m_nLength) )
	{
		return OnTransactionComplete();
	}
	
	return TRUE;
}

BOOL CHTTPClient::OnTransactionComplete()
{
	if ( m_pEvent != NULL && m_pEvent->OnTransactionComplete( this ) && m_bKeepAlive )
	{
		return TRUE;
	}
	else
	{
		Close();
		return FALSE;
	}
}

//////////////////////////////////////////////////////////////////////
// CHTTPClient dropped connection handler

void CHTTPClient::OnDropped(BOOL bError)
{
	if ( m_pEvent != NULL ) m_pEvent->OnDropped( this, bError );
	CConnection::OnDropped(bError);
	return;
}

//////////////////////////////////////////////////////////////////////
// default event handlers for CEventHandler

void CHTTPClient::CEventHandler::OnConnected( CHTTPClient* pObj )
{
	UNUSED_ALWAYS(pObj);
}

void CHTTPClient::CEventHandler::OnRun( CHTTPClient* pObj )
{
	UNUSED_ALWAYS(pObj);
}

BOOL CHTTPClient::CEventHandler::OnWriteContent( CHTTPClient* pObj, CBuffer* pBuffer )
{
	UNUSED_ALWAYS(pObj);
	UNUSED_ALWAYS(pBuffer);
	return TRUE;
}

BOOL CHTTPClient::CEventHandler::OnResponceLine( CHTTPClient* pObj, CString & pRawString, 
												CString & pProtocol, CString & pCode, CString & pMessage )
{
	UNUSED_ALWAYS(pObj);
	UNUSED_ALWAYS(pRawString);
	UNUSED_ALWAYS(pProtocol);
	UNUSED_ALWAYS(pCode);
	UNUSED_ALWAYS(pMessage);
	return TRUE;
}

BOOL CHTTPClient::CEventHandler::OnHeaderLine( CHTTPClient* pObj, CString& strHeader, CString& strValue )
{
	UNUSED_ALWAYS(pObj);
	UNUSED_ALWAYS(strHeader);
	UNUSED_ALWAYS(strValue);
	return TRUE;
}

BOOL CHTTPClient::CEventHandler::OnHeadersComplete( CHTTPClient* pObj )
{
	UNUSED_ALWAYS(pObj);
	return TRUE;
}

BOOL CHTTPClient::CEventHandler::OnReadContent( CHTTPClient* pObj, LPBYTE pDATA, QWORD nLength)
{
	UNUSED_ALWAYS(pObj);
	UNUSED_ALWAYS(pDATA);
	UNUSED_ALWAYS(nLength);
	return TRUE;
}

BOOL CHTTPClient::CEventHandler::OnTransactionComplete( CHTTPClient* pObj )
{
	UNUSED_ALWAYS(pObj);
	return TRUE;
}

void CHTTPClient::CEventHandler::OnDropped( CHTTPClient* pObj, BOOL bError )
{
	UNUSED_ALWAYS(pObj);
	UNUSED_ALWAYS(bError);
}

void CHTTPClient::CEventHandler::OnClose( CHTTPClient* pObj )
{
	UNUSED_ALWAYS(pObj);
}

void CHTTPClient::CEventHandler::OnClosed( CHTTPClient* pObj )
{
	UNUSED_ALWAYS(pObj);
}
