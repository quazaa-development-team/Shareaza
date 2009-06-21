//
// SchemaMember.h
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

#if !defined(AFX_SCHEMAMEMBER_H__0168BCBB_F511_4752_A529_78BF75A74777__INCLUDED_)
#define AFX_SCHEMAMEMBER_H__0168BCBB_F511_4752_A529_78BF75A74777__INCLUDED_

#pragma once

class CSchema;
class CXMLElement;


class CSchemaMember
{
// Construction
public:
	CSchemaMember(CSchema* pSchema);
	virtual ~CSchemaMember();

// Attributes
public:
	CSchema*	m_pSchema;
	CString		m_sName;
	CString		m_sType;
	CString		m_sTitle;
	BOOL		m_bElement;
	BOOL		m_bNumeric;
	BOOL		m_bIndexed;
	BOOL		m_bSearched;
public:
	int			m_nMinOccurs;
	int			m_nMaxOccurs;
	int			m_nMaxLength;
public:
	BOOL		m_bPrompt;
	int			m_nFormat;
	int			m_nColumnWidth;
	int			m_nColumnAlign;
public:
	CString		m_sLinkURI;
	CString		m_sLinkName;
public:
	CStringList	m_pItems;

// Operations
public:
	POSITION	GetItemIterator() const;
	CString		GetNextItem(POSITION& pos) const;
	int			GetItemCount() const;
	CString		GetValueFrom(CXMLElement* pElement, LPCTSTR pszDefault = NULL, BOOL bFormat = FALSE) const;
	void		SetValueTo(CXMLElement* pBase, LPCTSTR pszValue);
protected:
	BOOL		LoadSchema(CXMLElement* pRoot, CXMLElement* pElement);
	BOOL		LoadType(CXMLElement* pType);
	BOOL		LoadDescriptor(CXMLElement* pXML);
	BOOL		LoadDisplay(CXMLElement* pXML);

	friend class CSchema;
};

enum
{
	smfNone, smfTimeMMSS, smfBitrate, smfFrequency, smfTimeHHMMSSdec
};

#endif // !defined(AFX_SCHEMAMEMBER_H__0168BCBB_F511_4752_A529_78BF75A74777__INCLUDED_)