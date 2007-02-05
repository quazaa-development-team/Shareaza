//
// Security.h
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

#if !defined(AFX_SECURITY_H__85BE0E66_93D0_44B1_BEE1_E2C3C81CB8AF__INCLUDED_)
#define AFX_SECURITY_H__85BE0E66_93D0_44B1_BEE1_E2C3C81CB8AF__INCLUDED_

#pragma once

class CSecureRule;
class CXMLElement;


class CSecurity
{
// Construction
public:
	CSecurity();
	virtual ~CSecurity();

// Attributes
public:
	BOOL		m_bDenyPolicy;
protected:
	CList< CSecureRule* >	m_pRules;
public:
	static LPCTSTR xmlns;

// Operations
public:
	POSITION		GetIterator() const;
	CSecureRule*	GetNext(POSITION& pos) const;
	INT_PTR			GetCount();
	BOOL			Check(CSecureRule* pRule) const;
private:
	CSecureRule*	GetGUID(const GUID& oGUID) const;
public:
	void			Add(CSecureRule* pRule);
	void			Remove(CSecureRule* pRule);
	void			MoveUp(CSecureRule* pRule);
	void			MoveDown(CSecureRule* pRule);
	void			Ban(IN_ADDR* pAddress, int nBanLength, BOOL bMessage = TRUE);
public:
	void			Clear();
	BOOL			IsDenied(IN_ADDR* pAddress, LPCTSTR pszContent = NULL);
	BOOL			IsAccepted(IN_ADDR* pAddress, LPCTSTR pszContent = NULL);
	void			Expire();
public:
	BOOL			Load();
	BOOL			Save(BOOL bLock = FALSE);
	BOOL			Import(LPCTSTR pszFile);
	CXMLElement*	ToXML(BOOL bRules = TRUE);
	BOOL			FromXML(CXMLElement* pXML);
protected:
	void			Serialize(CArchive& ar);

};

enum
{
	banSession, ban5Mins, ban30Mins, ban2Hours, banWeek, banForever 
};

class CSecureRule
{
// Construction
public:
	CSecureRule(BOOL bCreate = TRUE);
	virtual ~CSecureRule();

// Attributes
public:
	int			m_nType;
	BYTE		m_nAction;
	CString		m_sComment;
	GUID		m_pGUID;
public:
	DWORD		m_nExpire;
	DWORD		m_nToday;
	DWORD		m_nEver;
public:
	BYTE		m_nIP[4];
	BYTE		m_nMask[4];
	TCHAR*		m_pContent;

	enum { srAddress, srContent };
	enum { srNull, srAccept, srDeny };
	enum { srIndefinite = 0, srSession = 1 };

// Operations
public:
	void	Remove();
	void	Reset();
	void	MaskFix();
	BOOL	IsExpired(DWORD nNow, BOOL bSession = FALSE);
	BOOL	Match(IN_ADDR* pAddress, LPCTSTR pszContent = NULL);
	void	SetContentWords(const CString& strContent);
	CString	GetContentWords();
public:
	void			Serialize(CArchive& ar, int nVersion);
	CXMLElement*	ToXML();
	BOOL			FromXML(CXMLElement* pXML);
	CString			ToGnucleusString();
	BOOL			FromGnucleusString(CString& str);

};

// An adult filter class, used in searches, chat, etc
class CAdultFilter
{
// Construction
public:
	CAdultFilter();
	virtual ~CAdultFilter();

// Attributes
private:
	LPTSTR		m_pszBlockedWords;			// Definitely adult content
	LPTSTR		m_pszDubiousWords;			// Possibly adult content

// Operations
public:
	void		Load();
	BOOL		IsHitAdult( LPCTSTR );		// Does this search result have adult content?
	BOOL		IsSearchFiltered( LPCTSTR );// Check if search is filtered
	BOOL		IsChatFiltered( LPCTSTR );	// Check filter for chat
	BOOL		Censor( TCHAR* );			// Censor (remove) bad words from a string
private:
	BOOL		IsFiltered( LPCTSTR );
};

// A message filter class for chat messages. (Spam protection)
class CMessageFilter
{
// Construction
public:
	CMessageFilter();
	virtual ~CMessageFilter();

// Attributes
private:
	LPTSTR		m_pszED2KSpam;				// Known ED2K spam phrases
	LPTSTR		m_pszFilteredPhrases;		// Known spam phrases

// Operations
public:
	void		Load();
	BOOL		IsED2KSpam( LPCTSTR );		// ED2K message spam filter (ED2K only, always on)
	BOOL		IsFiltered( LPCTSTR );		// Chat message spam filter
};

extern CMessageFilter MessageFilter;
extern CAdultFilter AdultFilter;
extern CSecurity Security;

#endif // !defined(AFX_SECURITY_H__85BE0E66_93D0_44B1_BEE1_E2C3C81CB8AF__INCLUDED_)
