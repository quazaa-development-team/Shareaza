//
// MetaList.cpp
//
// Copyright (c) Shareaza Development Team, 2002-2004.
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
#include "MetaList.h"
#include "Schema.h"
#include "XML.h"
#include "Library.h"
#include "LibraryFolders.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif


//////////////////////////////////////////////////////////////////////
// CMetaList construction

CMetaList::CMetaList()
{
}

CMetaList::~CMetaList()
{
	Clear();
}

//////////////////////////////////////////////////////////////////////
// CMetaList clear (remove all)

void CMetaList::Clear()
{
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		delete GetNext( pos );
	}

	m_pItems.RemoveAll();
}

//////////////////////////////////////////////////////////////////////
// CMetaList add simple item

CMetaItem* CMetaList::Add(LPCTSTR pszKey, LPCTSTR pszValue)
{
	CMetaItem* pItem = new CMetaItem( NULL );
	pItem->m_sKey	= pszKey;
	pItem->m_sValue	= pszValue;
	m_pItems.AddTail( pItem );
	return pItem;
}

//////////////////////////////////////////////////////////////////////
// CMetaList find a key by name

CMetaItem* CMetaList::Find(LPCTSTR pszKey) const
{
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		CMetaItem* pItem = GetNext( pos );
		if ( pItem->m_sKey.CompareNoCase( pszKey ) == 0 ) return pItem;
	}
	
	return NULL;
}

//////////////////////////////////////////////////////////////////////
// CMetaList remove a key by name

void CMetaList::Remove(LPCTSTR pszKey)
{
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		POSITION posCur = pos;
		
		CMetaItem* pItem = GetNext( pos );
		
		if ( pItem->m_sKey.CompareNoCase( pszKey ) == 0 )
		{
			m_pItems.RemoveAt( posCur );
			delete pItem;
		}
	}
}

//////////////////////////////////////////////////////////////////////
// CMetaList shuffle

void CMetaList::Shuffle()
{
	if ( m_pItems.GetCount() < 2 ) return;
	
	CMetaItem* pItem = (CMetaItem*)m_pItems.RemoveHead();
	m_pItems.AddTail( pItem );
}

//////////////////////////////////////////////////////////////////////
// CMetaList setup schema

void CMetaList::Setup(CSchema* pSchema, BOOL bClear)
{
	if ( bClear ) Clear();
	if ( ! pSchema ) return;
	
	for ( POSITION pos = pSchema->GetMemberIterator() ; pos ; )
	{
		CSchemaMember* pMember = pSchema->GetNextMember( pos );
		m_pItems.AddTail( new CMetaItem( pMember ) );
	}
}

//////////////////////////////////////////////////////////////////////
// CMetaList combination

void CMetaList::Combine(CXMLElement* pXML)
{
	if ( pXML == NULL ) return;
	
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		GetNext( pos )->Combine( pXML );
	}
}

//////////////////////////////////////////////////////////////////////
// CMetaList vote (common)

void CMetaList::Vote()
{
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		GetNext( pos )->Vote();
	}
}

//////////////////////////////////////////////////////////////////////
// CMetaList identify links

void CMetaList::CreateLinks()
{
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		CMetaItem* pItem = GetNext( pos );
		pItem->CreateLink();
		
		int nLink = pItem->m_sKey.Find( _T("Link") );

		if ( nLink > 0 )
		{
			CString strBase( pItem->m_sKey.Left( nLink ) );
			strBase.TrimRight();
			
			if ( CMetaItem* pBase = Find( strBase ) )
			{
				if ( pBase->m_sValue.GetLength() )
				{
					pItem->m_sKey	= pBase->m_sKey;
					pItem->m_sValue = pBase->m_sValue;
					pBase->m_sKey.Empty();
					pBase->m_sValue.Empty();
				}
			}
		}
	}
}

//////////////////////////////////////////////////////////////////////
// CMetaList clean (remove empty)

void CMetaList::Clean(int nMaxLength)
{
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		POSITION posCur = pos;
		CMetaItem* pItem = GetNext( pos );
		
		if ( ! pItem->Limit( nMaxLength ) )
		{
			m_pItems.RemoveAt( posCur );
			delete pItem;
		}
	}
}

//////////////////////////////////////////////////////////////////////
// CMetaList compute the combined widths of the meta information

void CMetaList::ComputeWidth(CDC* pDC, int& nKeyWidth, int& nValueWidth)
{
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		CMetaItem* pItem	= GetNext( pos );

		CSize szKey			= pDC->GetTextExtent( pItem->m_sKey + ':' );
		CSize szValue		= pDC->GetTextExtent( pItem->m_sValue );

		nKeyWidth			= max( nKeyWidth, szKey.cx );
		nValueWidth			= max( nValueWidth, szValue.cx );
	}
}

//////////////////////////////////////////////////////////////////////
// CMetaList hit testing

CMetaItem* CMetaList::HitTest(const CPoint& point, BOOL bLinksOnly)
{
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		CMetaItem* pItem = GetNext( pos );
		if ( pItem->m_rect.PtInRect( point ) )
		{
			if ( bLinksOnly && ! pItem->m_bLink ) return NULL;
			return pItem;
		}
	}

	return NULL;
}

//////////////////////////////////////////////////////////////////////
// CMetaList pre-built set cursor handler

BOOL CMetaList::OnSetCursor(CWnd* pWnd)
{
	CPoint point;
	GetCursorPos( &point );
	pWnd->ScreenToClient( &point );
	
	if ( HitTest( point, TRUE ) == NULL ) return FALSE;
	
	SetCursor( AfxGetApp()->LoadCursor( IDC_HAND ) );
	return TRUE;
}


//////////////////////////////////////////////////////////////////////
// CMetaItem construction

CMetaItem::CMetaItem(CSchemaMember* pMember) : m_rect( 0, 0, 0, 0 )
{
	m_pMember	= pMember;
	m_bLink		= FALSE;
	
	if ( m_pMember ) m_sKey = m_pMember->m_sTitle;
}

//////////////////////////////////////////////////////////////////////
// CMetaItem combination

BOOL CMetaItem::Combine(CXMLElement* pXML)
{
	if ( ! m_pMember ) return FALSE;
	
	CString strValue = m_pMember->GetValueFrom( pXML, NULL, TRUE );
	
	strValue.TrimLeft();
	strValue.TrimRight();
	
	if ( strValue.IsEmpty() ) return FALSE;
	
	if ( m_sValue.IsEmpty() )
	{
		m_sValue = strValue;
	}
	else if ( m_sValue != strValue )
	{
		m_sValue = _T("Multiple");
	}
	
	int nVote = 1;
	if ( m_pVote.Lookup( strValue, (void*&)nVote ) ) nVote ++;
	m_pVote.SetAt( strValue, (void*)nVote );
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CMetaItem voting

void CMetaItem::Vote()
{
	if ( m_sValue != _T("Multiple") ) return;
	
	int nBest = 0;
	
	for ( POSITION pos = m_pVote.GetStartPosition() ; pos ; )
	{
		CString strValue;
		int nVote;
		
		m_pVote.GetNextAssoc( pos, strValue, (void*&)nVote );
		
		if ( nVote > nBest )
		{
			nBest = nVote;
			m_sValue = strValue;
		}
	}
	
	m_pVote.RemoveAll();
}

//////////////////////////////////////////////////////////////////////
// CMetaItem cleaning

BOOL CMetaItem::Limit(int nMaxLength)
{
	if ( m_sValue.IsEmpty() )
	{
		return FALSE;
	}
	else if ( nMaxLength > 0 && m_sValue.GetLength() > nMaxLength )
	{
		m_sValue = m_sValue.Left( nMaxLength ) + _T("...");
	}
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CMetaItem linking

BOOL CMetaItem::CreateLink()
{
	if ( m_sValue.Find( _T("http://") ) == 0 || m_sValue.Find( _T("www.") ) == 0 ) 
	{
		m_bLink = TRUE;
		m_sLink = m_sValue;
		return TRUE;
	}

	if ( m_pMember == NULL ) return FALSE;
	
	if ( m_pMember->m_sLinkURI.IsEmpty() ) return FALSE;
	if ( m_pMember->m_sLinkName.IsEmpty() ) return FALSE;
	
	m_bLink = LibraryFolders.GetAlbumTarget(	m_pMember->m_sLinkURI,
												m_pMember->m_sLinkName,
												m_sValue ) != NULL;
	
	if ( m_bLink ) m_sLink = m_sValue;
	
	return m_bLink;
}

//////////////////////////////////////////////////////////////////////
// CMetaItem link targets

CAlbumFolder* CMetaItem::GetLinkTarget(BOOL bHTTP) const
{
	if ( bHTTP )
	{
		if ( m_sLink.Find( _T("http://") ) == 0 )
		{
			ShellExecute( AfxGetMainWnd()->GetSafeHwnd(), _T("open"), m_sLink,
				NULL, NULL, SW_SHOWNORMAL );
			return NULL;
		}
		else if ( m_sLink.Find( _T("www.") ) == 0 )
		{
			ShellExecute( AfxGetMainWnd()->GetSafeHwnd(), _T("open"),
				_T("http://") + m_sLink, NULL, NULL, SW_SHOWNORMAL );
			return NULL;
		}
	}

	if ( m_pMember == NULL || ! m_bLink ) return NULL;
	if ( m_pMember->m_sLinkURI.IsEmpty() ) return NULL;
	if ( m_pMember->m_sLinkName.IsEmpty() ) return NULL;

	return LibraryFolders.GetAlbumTarget(	m_pMember->m_sLinkURI,
											m_pMember->m_sLinkName,
											m_sLink );
}
