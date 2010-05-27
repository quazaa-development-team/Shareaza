//
// MetaList.h
//
// Copyright (c) Shareaza Development Team, 2002-2008.
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

#pragma once

#include "Schema.h"

class CMetaList;
class CMetaItem;
class CXMLElement;
class CAlbumFolder;

class CMetaList  
{
// Construction
public:
	CMetaList();
	virtual ~CMetaList();

// Attributes
protected:
	CList< CMetaItem* >	m_pItems;
	BOOL	m_bMusicBrainz;

// Operations
public:
	CMetaItem*	Add(LPCTSTR pszKey, LPCTSTR pszValue);
	CMetaItem*	Find(LPCTSTR pszKey) const;
	void		Remove(LPCTSTR pszKey);
	void		Shuffle();
	void		Setup(CSchemaPtr pSchema, BOOL bClear = TRUE);
	void		Setup(CMetaList* pMetaList);					// For copying data from the external list
	void		Combine(CXMLElement* pXML);
	void		Vote();
	void		CreateLinks();
	void		Clean(int nMaxLength = 128);
	void		ComputeWidth(CDC* pDC, int& nKeyWidth, int& nValueWidth);
	CMetaItem*	HitTest(const CPoint& point, BOOL bLinksOnly = FALSE);
	BOOL		OnSetCursor(CWnd* pWnd);
	BOOL		IsMusicBrainz() const;

	virtual BOOL IsWorking() const { return FALSE; }
	virtual void Start() {}
	virtual void Stop() {}
	virtual void Clear();

// Inline Operations
public:
	inline POSITION GetIterator() const
	{
		return m_pItems.GetHeadPosition();
	}

	inline CMetaItem* GetNext(POSITION& pos) const
	{
		return pos ? m_pItems.GetNext( pos ) : NULL;
	}

	inline INT_PTR GetCount() const
	{
		return m_pItems.GetCount();
	}

	inline CMetaItem* GetFirst() const
	{
		return m_pItems.IsEmpty() ? NULL : m_pItems.GetHead();
	}

	INT_PTR	GetCount(BOOL bVisibleOnly) const;
};


class CMetaItem
{
// Construction
public:
	CMetaItem(CSchemaMember* pMember = NULL);

// Attributes
public:
	CSchemaMember*	m_pMember;
	CString			m_sKey;
	CString			m_sValue;
	BOOL			m_bValueDefined;
	CMap< CString, const CString&, int, int > m_pVote;
public:
	CRect			m_rect;
	BOOL			m_bLink;
	CString			m_sLink;
	CString			m_sLinkName;
public:
	BOOL			m_bFullWidth;
	int				m_nHeight;
	
// Operations
public:
	BOOL			Combine(CXMLElement* pXML);
	void			Vote();
	BOOL			Limit(int nMaxLength);
	BOOL			CreateLink();
	CAlbumFolder*	GetLinkTarget(BOOL bHTTP = TRUE) const;
	CString			GetMusicBrainzLink() const;

	inline void SetRect(int x1, int y1, int x2, int y2)
	{
		m_rect.left		= x1;
		m_rect.top		= y1;
		m_rect.right	= x2;
		m_rect.bottom	= y2;
	}

	inline CString GetDisplayValue() const
	{
		if ( m_bLink && m_sLinkName.GetLength() )
			return m_sLinkName;
		return m_sValue;
	}
};