//
// LibraryDictionary.cpp
//
// Copyright (c) Shareaza Development Team, 2002-2009.
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

#include "StdAfx.h"
#include "Shareaza.h"

#include "LibraryDictionary.h"
#include "SharedFile.h"
#include "QueryHashMaster.h"
#include "QueryHashTable.h"
#include "QuerySearch.h"

#include "Library.h"
#include "LibraryMaps.h"
#include "Schema.h"
#include "Settings.h"
#include "UploadQueues.h"


#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

CLibraryDictionary LibraryDictionary;


//////////////////////////////////////////////////////////////////////
// CLibraryDictionary construction

CLibraryDictionary::CLibraryDictionary() :
	m_pTable		( NULL )
,	m_bValid		( false )
,	m_nSearchCookie	( 1ul )
{
}

CLibraryDictionary::~CLibraryDictionary()
{
	Clear();
	delete m_pTable;
}

//////////////////////////////////////////////////////////////////////
// CLibraryDictionary add and remove

void CLibraryDictionary::AddFile(const CLibraryFile& oFile)
{
	const bool bCanUpload = oFile.IsShared();

	ProcessFile( oFile, true, bCanUpload );

	if ( bCanUpload && m_bValid )
		m_pTable->AddHashes( oFile );
}

void CLibraryDictionary::RemoveFile(const CLibraryFile& oFile)
{
	ProcessFile( oFile, false, oFile.IsShared() );

	// Always invalidate the table when removing a hashed file
	if ( oFile.IsHashed() )
		Invalidate();
}

//////////////////////////////////////////////////////////////////////
// CLibraryDictionary process file

void CLibraryDictionary::ProcessFile(
	const CLibraryFile& oFile, bool bAdd, bool bCanUpload)
{
	ProcessPhrase( oFile, oFile.GetSearchName(), bAdd, bCanUpload );
	ProcessPhrase( oFile, oFile.GetMetadataWords(), bAdd, bCanUpload );
}

//////////////////////////////////////////////////////////////////////
// CLibraryDictionary phrase parser

void CLibraryDictionary::ProcessPhrase(
	const CLibraryFile& oFile, const CString& strPhrase, bool bAdd,
	bool bCanUpload)
{
	if ( strPhrase.IsEmpty() )
		return;

	CStringList oKeywords;
	CQueryHashTable::MakeKeywords( strPhrase, oKeywords );
	for ( POSITION pos = oKeywords.GetHeadPosition(); pos; )
	{
		ProcessWord( oFile, oKeywords.GetNext( pos ), bAdd, bCanUpload );
	}
}

//////////////////////////////////////////////////////////////////////
// CLibraryDictionary word add and remove

void CLibraryDictionary::ProcessWord(
	const CLibraryFile& oFile, const CString& strWord, bool bAdd,
	bool bCanUpload)
{
	CWord oWord;
	if ( m_oWordMap.Lookup( strWord, oWord ) )
	{
		if ( bAdd )
		{
			if ( oWord.m_pList->GetTail() != &oFile )
			{
				oWord.m_pList->AddTail( &oFile );
				if ( bCanUpload && m_bValid && ! m_pTable->CheckString( strWord ) )
					m_pTable->AddExactString( strWord );
			}
		}
		else
		{
			POSITION pos = oWord.m_pList->Find( &oFile );
			if ( pos )
			{
				oWord.m_pList->RemoveAt( pos );

				if ( oWord.m_pList->IsEmpty() )
				{
					m_oWordMap.RemoveKey( strWord );
					delete oWord.m_pList;

					if ( bCanUpload )
						Invalidate();
				}
			}
		}
	}
	else if ( bAdd )
	{
		oWord.m_pList = new CFilePtrList;
		oWord.m_pList->AddTail( &oFile );
		m_oWordMap.SetAt( strWord, oWord );

		if ( bCanUpload && m_bValid )
			m_pTable->AddExactString( strWord );
	}
}

//////////////////////////////////////////////////////////////////////
// CLibraryDictionary build hash table

void CLibraryDictionary::BuildHashTable()
{
	if ( m_bValid )
		return;

	if ( !m_pTable )
	{
		m_pTable = new CQueryHashTable();
		if ( m_pTable )
			m_pTable->Create();
		else
			return;
	}

	m_pTable->Clear();

	// Add words to hash table
	for ( POSITION pos = m_oWordMap.GetStartPosition() ; pos ; )
	{
		CString strWord;
		CWord oWord;
		m_oWordMap.GetNextAssoc( pos, strWord, oWord );

		for ( POSITION pos = oWord.m_pList->GetHeadPosition() ; pos ; )
		{
			const CLibraryFile& oFile = *oWord.m_pList->GetNext( pos );

			// Check if the file can be uploaded
			if ( oFile.IsShared() )
			{
				// Add the keyword to the table
				m_pTable->AddExactString( strWord );
				break;
			}
		}
	}

	// Add sha1/ed2k hashes to hash table
	for ( POSITION pos = LibraryMaps.GetFileIterator() ; pos ; )
	{
		const CLibraryFile& oFile = *LibraryMaps.GetNextFile( pos );

		// Check if the file can be uploaded
		if ( oFile.IsShared() )
			m_pTable->AddHashes( oFile );
	}

	m_bValid = true;
}

//////////////////////////////////////////////////////////////////////
// CLibraryDictionary rebuild hash table
//
// Force hash table to re-build.

void CLibraryDictionary::Invalidate()
{
	m_bValid = false;

	QueryHashMaster.Invalidate();
}

//////////////////////////////////////////////////////////////////////
// CLibraryDictionary retrieve hash table

const CQueryHashTable* CLibraryDictionary::GetHashTable()
{
	BuildHashTable();

	return m_pTable;
}

//////////////////////////////////////////////////////////////////////
// CLibraryDictionary clear

void CLibraryDictionary::Clear()
{
	for ( POSITION pos = m_oWordMap.GetStartPosition() ; pos ; )
	{
		CString strWord;
		CWord oWord;
		m_oWordMap.GetNextAssoc( pos, strWord, oWord );
		delete oWord.m_pList;
	}
	m_oWordMap.RemoveAll();

	if ( m_pTable )
	{
		m_pTable->Clear();
		m_bValid = true;
	}
}

//////////////////////////////////////////////////////////////////////
// CLibraryDictionary search

CFilePtrList* CLibraryDictionary::Search(
	const CQuerySearch& oSearch, const int nMaximum, const bool bLocal,
	const bool bAvailableOnly)
{
	if ( !m_bValid )
	{
		BuildHashTable();
		if ( !m_bValid )
			return NULL;
	}

	// Only check the hash when a search comes from other client.
	if ( !bLocal && !m_pTable->Check( oSearch ) )
		return NULL;

	++m_nSearchCookie;
	const CLibraryFile* pHit = NULL;

	CQuerySearch::const_iterator pWordEntry = oSearch.begin();
	const CQuerySearch::const_iterator pLastWordEntry = oSearch.end();
	for ( ; pWordEntry != pLastWordEntry ; ++pWordEntry )
	{
		if ( pWordEntry->first[ 0 ] == _T('-') )
			continue;

		CString strWord( pWordEntry->first, static_cast< int >( pWordEntry->second ) );
		CWord oWord;
		if ( m_oWordMap.Lookup( strWord, oWord ) )
		{
			for ( POSITION pos = oWord.m_pList->GetHeadPosition() ; pos ; )
			{
				const CLibraryFile* pFile = oWord.m_pList->GetNext( pos );

				if ( bAvailableOnly && pFile->IsGhost() )
					continue;

				if ( !bLocal && !pFile->IsShared() )
					continue;

				if ( pFile->m_nSearchCookie == m_nSearchCookie )
				{
					++pFile->m_nSearchWords;
				}
				else
				{
					pFile->m_nSearchCookie	= m_nSearchCookie;
					pFile->m_nSearchWords	= 1;
					pFile->m_pNextHit		= pHit;
					pHit = pFile;
				}
			}
		}
	}

	size_t nLowerBound = ( oSearch.tableSize() >= 3 )
		? ( oSearch.tableSize() * 2 / 3 ) : oSearch.tableSize();

	CFilePtrList* pHits = NULL;
	for ( ; pHit ; pHit = pHit->m_pNextHit )
	{
		ASSERT( pHit->m_nSearchCookie == m_nSearchCookie );

		if ( pHit->m_nSearchWords < nLowerBound )
			continue;

		if ( oSearch.Match( pHit->GetSearchName(), pHit->m_nSize,
			pHit->m_pSchema ? (LPCTSTR)pHit->m_pSchema->GetURI() : NULL,
			pHit->m_pMetadata, pHit->m_oSHA1, pHit->m_oTiger, pHit->m_oED2K,
			pHit->m_oBTH, pHit->m_oMD5 ) )
		{
			if ( !pHits )
				pHits = new CFilePtrList;

			pHits->AddTail( pHit );

			if ( !bLocal )
			{
				++pHit->m_nHitsToday;
				++pHit->m_nHitsTotal;
			}

			if ( pHit->m_nCollIndex )
			{
				const CLibraryFile* pCollection = LibraryMaps.LookupFile(
					pHit->m_nCollIndex, !bLocal, bAvailableOnly );

				if ( pCollection )
				{
					if ( pCollection->m_nSearchCookie != m_nSearchCookie )
					{
						pCollection->m_nSearchCookie = m_nSearchCookie;
						pHits->AddHead( pCollection );
					}
				}
				else
				{
					// Collection removed without deleting indexes
					pHit->m_nCollIndex = 0ul;
				}
			}

			if ( nMaximum > 0 && pHits->GetCount() >= nMaximum )
				break;
		}
	}

	return pHits;
}

void CLibraryDictionary::Serialize(CArchive& ar, const int nVersion)
{
	if ( ar.IsStoring() )
	{
		ar << (UINT)m_oWordMap.GetCount();
	}
	else
	{
		if ( nVersion >= 29 )
		{
			UINT nWordsCount = 0u;
			ar >> nWordsCount;
			m_oWordMap.InitHashTable( GetBestHashTableSize( nWordsCount ) );
		}
	}
}
