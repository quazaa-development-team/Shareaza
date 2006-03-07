//
// QuerySearch.h
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

#if !defined(AFX_QUERYSEARCH_H__2141B926_3F6B_4A5D_9FBD_C67FD0A5C46C__INCLUDED_)
#define AFX_QUERYSEARCH_H__2141B926_3F6B_4A5D_9FBD_C67FD0A5C46C__INCLUDED_

#pragma once

class CPacket;
class CSchema;
class CXMLElement;
class CSearchWnd;
class CG1Packet;
class CG2Packet;
class CEDPacket;


class CQuerySearch : private boost::noncopyable
{
// Construction
public:
	CQuerySearch(BOOL bGUID = TRUE);
	~CQuerySearch();
private:
	CQuerySearch(const CQuerySearch* pOrigin);
public:
	auto_ptr< CQuerySearch > clone() const;

// Attributes
public:
	Hashes::Guid	m_oGUID;
public:
	CString			m_sSearch;		// search string, transformed by lowercase table
	CString			m_sKeywords;	// valid search keywords (stems, minus words, split asian phrase etc.)
	CSchema*		m_pSchema;
	CXMLElement*	m_pXML;
	QWORD			m_nMinSize;
	QWORD			m_nMaxSize;
public:
	Hashes::Sha1Hash	m_oSHA1;
	Hashes::TigerHash	m_oTiger;
	Hashes::Ed2kHash	m_oED2K;
	Hashes::BtHash		m_oBTH;
	Hashes::Ed2kHash	m_oSimilarED2K;
public:
	BOOL			m_bWantURL;
	BOOL			m_bWantDN;
	BOOL			m_bWantXML;
	BOOL			m_bWantCOM;
	BOOL			m_bWantPFS;
	BOOL			m_bAndG1;
public:
	BOOL			m_bUDP;
	SOCKADDR_IN		m_pEndpoint;
	DWORD			m_nKey;
	BOOL			m_bFirewall;
private:
	typedef std::pair< LPCTSTR, size_t > WordEntry;
	struct CompareWordEntries
	{
		bool operator()(const WordEntry& lhs, const WordEntry& rhs) const
		{
			int cmp = _tcsnicmp( lhs.first, rhs.first, min( lhs.second, rhs.second ) );
			return cmp < 0 || cmp == 0 && lhs.second < rhs.second;
		}
	};
	struct FindStr
	{
		const WordEntry& m_entry;
		FindStr(const WordEntry& entry) : m_entry( entry ) {}
		bool operator()(const LPCTSTR& arg) const
		{
			//! \todo verify this - this will succeed for every arg that starts withthe search string
			//!                     it doesn't have to be an exact match
			return _tcsnicmp( arg, m_entry.first, m_entry.second ) == 0;
		}
	};
public:
	typedef std::set< WordEntry, CompareWordEntries > WordTable;
	typedef WordTable::iterator iterator;
	typedef WordTable::const_iterator const_iterator;
	const_iterator begin() const { return m_oWords.begin(); }
	const_iterator end()   const { return m_oWords.end(); }
	size_t tableSize() const { return m_oWords.size(); }
private:
	WordTable m_oWords;

// Packet Operations
public:
	CG1Packet*				ToG1Packet();
	CG2Packet*				ToG2Packet(SOCKADDR_IN* pUDP, DWORD nKey);
	CEDPacket*				ToEDPacket(BOOL bUDP, DWORD nServerFlags = 0);
	static CQuerySearch*	FromPacket(CPacket* pPacket, SOCKADDR_IN* pEndpoint = NULL);
private:
	BOOL					ReadG1Packet(CPacket* pPacket);
	BOOL					ReadG2Packet(CG2Packet* pPacket, SOCKADDR_IN* pEndpoint = NULL);

// Operations
public:
	BOOL		Match(LPCTSTR pszFilename, QWORD nSize, LPCTSTR pszSchemaURI, CXMLElement* pXML, const Hashes::Sha1Hash& oSHA1, const Hashes::TigerHash& oTiger, const Hashes::Ed2kHash& oED2K);
	TRISTATE	MatchMetadata(LPCTSTR pszSchemaURI, CXMLElement* pXML);
	BOOL		MatchMetadataShallow(LPCTSTR pszSchemaURI, CXMLElement* pXML, bool* bReject=NULL);
	void		BuildWordList(bool bExpression=true, bool bLocal=false);
	void		Serialize(CArchive& ar);
	static CSearchWnd* OpenWindow(auto_ptr< CQuerySearch > pSearch);
	BOOL		CheckValid(bool bExpression=true);
private:
	void		AddStringToWordList(LPCTSTR pszString);
	void		MakeKeywords(CString& strPhrase, bool bExpression=true);
	void		SlideKeywords(CString& strPhrase);
	BOOL		WriteHashesToEDPacket( CEDPacket* pPacket, BOOL bUDP );

// Utilities
public:
	static BOOL	WordMatch(LPCTSTR pszString, LPCTSTR pszFind, bool* bReject=NULL);
	static BOOL	NumberMatch(const CString& strValue, const CString& strRange);
};

#endif // !defined(AFX_QUERYSEARCH_H__2141B926_3F6B_4A5D_9FBD_C67FD0A5C46C__INCLUDED_)
