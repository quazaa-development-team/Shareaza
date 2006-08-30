//
// LibraryMaps.cpp
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

#include "StdAfx.h"
#include "Shareaza.h"
#include "Library.h"
#include "LibraryMaps.h"
#include "SharedFile.h"

#include "Application.h"
#include "QuerySearch.h"

#include "SHA.h"
#include "MD5.h"
#include "ED2K.h"
#include "TigerTree.h"

IMPLEMENT_DYNAMIC(CLibraryMaps, CComObject)

BEGIN_INTERFACE_MAP(CLibraryMaps, CComObject)
	INTERFACE_PART(CLibraryMaps, IID_ILibraryFiles, LibraryFiles)
END_INTERFACE_MAP()

#undef HASH_SIZE
#undef HASH_MASK
#define HASH_SIZE	512
#define HASH_MASK	0x1FF

CLibraryMaps LibraryMaps;


//////////////////////////////////////////////////////////////////////
// CLibraryMaps construction

CLibraryMaps::CLibraryMaps()
{
	EnableDispatch( IID_ILibraryFiles );
	
	m_pSHA1Map		= new CLibraryFile*[HASH_SIZE];
	m_pTigerMap		= new CLibraryFile*[HASH_SIZE];
	m_pED2KMap		= new CLibraryFile*[HASH_SIZE];
	m_pMD5Map		= new CLibraryFile*[HASH_SIZE];
	
	ZeroMemory( m_pSHA1Map, HASH_SIZE * sizeof( CLibraryFile* ) );
	ZeroMemory( m_pTigerMap, HASH_SIZE * sizeof( CLibraryFile* ) );
	ZeroMemory( m_pED2KMap, HASH_SIZE * sizeof( CLibraryFile* ) );
	ZeroMemory( m_pMD5Map, HASH_SIZE * sizeof( CLibraryFile* ) );
	
	m_nNextIndex	= 4;
	m_nFiles		= 0;
	m_nVolume		= 0;
}

CLibraryMaps::~CLibraryMaps()
{
	delete [] m_pED2KMap;
	delete [] m_pTigerMap;
	delete [] m_pSHA1Map;
	delete [] m_pMD5Map;
}

//////////////////////////////////////////////////////////////////////
// CLibraryMaps file list

POSITION CLibraryMaps::GetFileIterator() const
{
	return m_pIndexMap.GetStartPosition();
}

CLibraryFile* CLibraryMaps::GetNextFile(POSITION& pos) const
{
	DWORD pIndex;
	CLibraryFile* pFile = NULL;
	m_pIndexMap.GetNextAssoc( pos, pIndex, pFile );
	return pFile;
}

void CLibraryMaps::GetStatistics(DWORD* pnFiles, QWORD* pnVolume)
{
	if ( pnFiles ) *pnFiles = m_nFiles;
	if ( pnVolume ) *pnVolume = m_nVolume;
}

//////////////////////////////////////////////////////////////////////
// CLibraryMaps lookup file by index

CLibraryFile* CLibraryMaps::LookupFile(DWORD nIndex, BOOL bSharedOnly, BOOL bAvailableOnly)
{
	if ( ! nIndex ) return NULL;
	
	CLibraryFile* pFile = NULL;
	
	CQuickLock oLock( Library.m_pSection );
	
	if ( m_pIndexMap.Lookup( nIndex, pFile ) && ( ! bSharedOnly || pFile->IsShared() ) && ( ! bAvailableOnly || pFile->IsAvailable() ) )
	{
		return pFile;
	}
	
	return NULL;
}

//////////////////////////////////////////////////////////////////////
// CLibraryMaps lookup file by name and/or path

CLibraryFile* CLibraryMaps::LookupFileByName(LPCTSTR pszName, BOOL bSharedOnly, BOOL bAvailableOnly)
{
	CLibraryFile* pFile = NULL;
	CString strName( pszName );
	
	CQuickLock oLock( Library.m_pSection );
	CharLower( strName.GetBuffer() );
	strName.ReleaseBuffer();
	
	if ( m_pNameMap.Lookup( strName, pFile ) && ( ! bSharedOnly || pFile->IsShared() ) && ( ! bAvailableOnly || pFile->IsAvailable() ) )
	{
		return pFile;
	}
	
	return NULL;
}

CLibraryFile* CLibraryMaps::LookupFileByPath(LPCTSTR pszPath, BOOL bSharedOnly, BOOL bAvailableOnly)
{
	CLibraryFile* pFile = NULL;
	
	CQuickLock oLock( Library.m_pSection );
	
	if ( m_pPathMap.Lookup( pszPath, pFile ) && ( ! bSharedOnly || pFile->IsShared() ) && ( ! bAvailableOnly || pFile->IsAvailable() ) )
	{
		return pFile;
	}
	
	return NULL;
}

//////////////////////////////////////////////////////////////////////
// CLibraryMaps lookup file by URN

CLibraryFile* CLibraryMaps::LookupFileByURN(LPCTSTR pszURN, BOOL bSharedOnly, BOOL /*bAvailableOnly*/)
{
	CLibraryFile* pFile;
    Hashes::TigerHash oTiger;
    Hashes::Sha1Hash oSHA1;
    Hashes::Ed2kHash oED2K;
	Hashes::Md5Hash oMD5;
	
	if ( oSHA1.fromUrn( pszURN ) && oTiger.fromUrn( pszURN ) )
	{
		if ( ( pFile = LookupFileByBitprint( oSHA1, oTiger, bSharedOnly ) ) != NULL ) return pFile;
	}

	if ( oSHA1.fromUrn( pszURN ) )
	{
		if ( ( pFile = LookupFileBySHA1( oSHA1, bSharedOnly ) ) != NULL ) return pFile;
	}
	
	if ( oTiger.fromUrn( pszURN ) )
	{
		if ( ( pFile = LookupFileByTiger( oTiger, bSharedOnly ) ) != NULL ) return pFile;
	}
	
	if ( oED2K.fromUrn( pszURN ) )
	{
		if ( ( pFile = LookupFileByED2K( oED2K, bSharedOnly ) ) != NULL ) return pFile;
	}

	if ( oMD5.fromUrn( pszURN ) )
	{
		if ( ( pFile = LookupFileByMD5( oMD5, bSharedOnly ) ) != NULL ) return pFile;
	}
	
	return NULL;
}

//////////////////////////////////////////////////////////////////////
// CLibraryMaps lookup file by individual hash types

CLibraryFile* CLibraryMaps::LookupFileByBitprint(const Hashes::Sha1Hash& oSHA1, const Hashes::TigerHash& oTiger, BOOL bSharedOnly, BOOL bAvailableOnly)
{
	if ( !oTiger || !oSHA1 ) return NULL;

	CQuickLock oLock( Library.m_pSection );

	CLibraryFile* pFile = m_pTigerMap[ oTiger[ 0 ] & HASH_MASK ];

	for ( ; pFile ; pFile = pFile->m_pNextTiger )
	{
		if ( validAndEqual( oSHA1, pFile->m_oSHA1 ) && validAndEqual( oTiger, pFile->m_oTiger ) )
		{
			if ( ( ! bSharedOnly || pFile->IsShared() ) && ( ! bAvailableOnly || pFile->IsAvailable() ) )
			{
				return pFile;
			}
		}
	}

	return NULL;
}

CLibraryFile* CLibraryMaps::LookupFileBySHA1(const Hashes::Sha1Hash& oSHA1, BOOL bSharedOnly, BOOL bAvailableOnly)
{
	if ( !oSHA1 ) return NULL;

	CQuickLock oLock( Library.m_pSection );
	
	CLibraryFile* pFile = m_pSHA1Map[ oSHA1[ 0 ] & HASH_MASK ];
	
	for ( ; pFile ; pFile = pFile->m_pNextSHA1 )
	{
		if ( validAndEqual( oSHA1, pFile->m_oSHA1 ) )
		{
			if ( ( ! bSharedOnly || pFile->IsShared() ) && ( ! bAvailableOnly || pFile->IsAvailable() ) )
			{
				return pFile;
			}
			else
			{
				// This can cause some problem if there are some Duplicate files in library
				// in any reason, and if one of them has been set to not-share.
				// because if the first one this code find is set to not-share,
				// even if you have same exactly same file set to share, this code will not return true result.
				// return NULL;
			}
		}
	}
	
	return NULL;
}

CLibraryFile* CLibraryMaps::LookupFileByTiger(const Hashes::TigerHash& oTiger, BOOL bSharedOnly, BOOL bAvailableOnly)
{
	if ( !oTiger ) return NULL;

	CQuickLock oLock( Library.m_pSection );
	
	CLibraryFile* pFile = m_pTigerMap[ oTiger[ 0 ] & HASH_MASK ];
	
	for ( ; pFile ; pFile = pFile->m_pNextTiger )
	{
		if ( validAndEqual( oTiger, pFile->m_oTiger ) )
		{
			if ( ( ! bSharedOnly || pFile->IsShared() ) && ( ! bAvailableOnly || pFile->IsAvailable() ) )
			{
				return pFile;
			}
			else
			{
				// same reason as above
				// return NULL;
			}
		}
	}
	
	return NULL;
}

CLibraryFile* CLibraryMaps::LookupFileByED2K(const Hashes::Ed2kHash& oED2K, BOOL bSharedOnly, BOOL bAvailableOnly)
{
	if ( !oED2K ) return NULL;

	CQuickLock oLock( Library.m_pSection );

	CLibraryFile* pFile = m_pED2KMap[ oED2K[ 0 ] & HASH_MASK ];

	for ( ; pFile ; pFile = pFile->m_pNextED2K )
	{
		if ( validAndEqual( oED2K, pFile->m_oED2K ) )
		{
			if ( ( ! bSharedOnly || pFile->IsShared() ) && ( ! bAvailableOnly || pFile->IsAvailable() ) )
			{
				return pFile;
			}
			{
				// same reason as above
				// return NULL;
			}
		}
	}

	return NULL;
}

CLibraryFile* CLibraryMaps::LookupFileByMD5(const Hashes::Md5Hash& oMD5, BOOL bSharedOnly, BOOL bAvailableOnly)
{
	if ( !oMD5 ) return NULL;

	CQuickLock oLock( Library.m_pSection );

	CLibraryFile* pFile = m_pMD5Map[ oMD5[ 0 ] & HASH_MASK ];

	for ( ; pFile ; pFile = pFile->m_pNextED2K )
	{
		if ( validAndEqual( oMD5, pFile->m_oMD5 ) )
		{
			if ( ( ! bSharedOnly || pFile->IsShared() ) && ( ! bAvailableOnly || pFile->IsAvailable() ) )
			{
				return pFile;
			}
			{
				// same reason as above
				// return NULL;
			}
		}
	}

	return NULL;
}

//////////////////////////////////////////////////////////////////////
// CLibraryMaps clear

void CLibraryMaps::Clear()
{
	for ( POSITION pos = GetFileIterator() ; pos ; ) delete GetNextFile( pos );
	
	ASSERT( m_pIndexMap.GetCount() == 0 );
	ASSERT( m_pNameMap.GetCount() == 0 );
	ASSERT( m_pPathMap.GetCount() == 0 );
	
	ZeroMemory( m_pSHA1Map, HASH_SIZE * sizeof *m_pSHA1Map );
	ZeroMemory( m_pTigerMap, HASH_SIZE * sizeof *m_pTigerMap );
	ZeroMemory( m_pED2KMap, HASH_SIZE * sizeof *m_pED2KMap );
	ZeroMemory( m_pMD5Map, HASH_SIZE * sizeof *m_pMD5Map );
	
	m_nFiles  = 0;
	m_nVolume = 0;
}

//////////////////////////////////////////////////////////////////////
// CLibraryMaps index manager

DWORD CLibraryMaps::AllocateIndex()
{
	while ( ( m_nNextIndex & 3 ) == 0 || LookupFile( m_nNextIndex ) ) m_nNextIndex++;
	return m_nNextIndex;
}

//////////////////////////////////////////////////////////////////////
// CLibraryMaps add a file to the maps

void CLibraryMaps::OnFileAdd(CLibraryFile* pFile)
{
	BOOL bSkipStats = FALSE;
	if ( pFile->m_nIndex )
	{
		if ( CLibraryFile* pOld = LookupFile( pFile->m_nIndex ) )
		{
			if ( pOld != pFile )
			{
				pFile->m_nIndex = AllocateIndex();
				m_pIndexMap.SetAt( pFile->m_nIndex, pFile );
			}
			else
			{
				bSkipStats = TRUE;
			}
		}
		else
		{
			m_pIndexMap.SetAt( pFile->m_nIndex, pFile );
		}
	}
	else
	{
		pFile->m_nIndex = AllocateIndex();
		m_pIndexMap.SetAt( pFile->m_nIndex, pFile );
	}

	if ( ( pFile->m_pFolder != NULL ) && ( ! bSkipStats ) )
	{
		m_nVolume += ( pFile->m_nSize >> 10 );
		m_nFiles ++;
	}
	
	m_pNameMap.SetAt( pFile->GetNameLC(), pFile );
	
	if ( pFile->m_pFolder != NULL )
	{
		m_pPathMap.SetAt( pFile->GetPath(), pFile );
	}
	else if ( m_pDeleted.Find( pFile ) == NULL )
	{
		m_pDeleted.AddTail( pFile );
	}
	
	if ( pFile->m_oSHA1 )
	{
		CLibraryFile** pHash = &m_pSHA1Map[ pFile->m_oSHA1[ 0 ] & HASH_MASK ];
		pFile->m_pNextSHA1 = *pHash;
		*pHash = pFile;
	}
	
	if ( pFile->m_oTiger )
	{
		CLibraryFile** pHash = &m_pTigerMap[ pFile->m_oTiger[ 0 ] & HASH_MASK ];
		pFile->m_pNextTiger = *pHash;
		*pHash = pFile;
	}
	
	if ( pFile->m_oED2K )
	{
		CLibraryFile** pHash = &m_pED2KMap[ pFile->m_oED2K[ 0 ] & HASH_MASK ];
		pFile->m_pNextED2K = *pHash;
		*pHash = pFile;
	}

	if ( pFile->m_oMD5 )
	{
		CLibraryFile** pHash = &m_pMD5Map[ pFile->m_oMD5[ 0 ] & HASH_MASK ];
		pFile->m_pNextMD5 = *pHash;
		*pHash = pFile;
	}
}

//////////////////////////////////////////////////////////////////////
// CLibraryMaps remove a file from the maps

void CLibraryMaps::OnFileRemove(CLibraryFile* pFile)
{
	CLibraryFile* pOld;
	
	if ( pFile->m_nIndex )
	{
		pOld = LookupFile( pFile->m_nIndex );
		
		if ( pOld == pFile )
		{
			m_pIndexMap.RemoveKey( pFile->m_nIndex );
			
			if ( pOld->m_pFolder != NULL )
			{
				m_nFiles --;
				m_nVolume -= ( pFile->m_nSize >> 10 );
			}
		}
	}
	
	pOld = LookupFileByName( pFile->GetNameLC() );
	if ( pOld == pFile ) m_pNameMap.RemoveKey( pFile->GetNameLC() );
	
	if ( pFile->m_pFolder != NULL )
	{
		pOld = LookupFileByPath( pFile->GetPath() );
		if ( pOld == pFile ) m_pPathMap.RemoveKey( pFile->GetPath() );
	}
	
	if ( POSITION pos = m_pDeleted.Find( pFile ) )
		m_pDeleted.RemoveAt( pos );
	
	if ( pFile->m_oSHA1 )
	{
		CLibraryFile** pPrev = &m_pSHA1Map[ pFile->m_oSHA1[ 0 ] & HASH_MASK ];
		
		for ( CLibraryFile* pOther = *pPrev ; pOther ; pOther = pOther->m_pNextSHA1 )
		{
			if ( pOther == pFile )
			{
				*pPrev = pOther->m_pNextSHA1;
				break;
			}
			pPrev = &pOther->m_pNextSHA1;
		}
		
		pFile->m_pNextSHA1 = NULL;
	}
	
	if ( pFile->m_oTiger )
	{
		CLibraryFile** pPrev = &m_pTigerMap[ pFile->m_oTiger[ 0 ] & HASH_MASK ];
		
		for ( CLibraryFile* pOther = *pPrev ; pOther ; pOther = pOther->m_pNextTiger )
		{
			if ( pOther == pFile )
			{
				*pPrev = pOther->m_pNextTiger;
				break;
			}
			pPrev = &pOther->m_pNextTiger;
		}
		
		pFile->m_pNextTiger = NULL;
	}
	
	if ( pFile->m_oED2K )
	{
		CLibraryFile** pPrev = &m_pED2KMap[ pFile->m_oED2K[ 0 ] & HASH_MASK ];
		
		for ( CLibraryFile* pOther = *pPrev ; pOther ; pOther = pOther->m_pNextED2K )
		{
			if ( pOther == pFile )
			{
				*pPrev = pOther->m_pNextED2K;
				break;
			}
			pPrev = &pOther->m_pNextED2K;
		}
		
		pFile->m_pNextED2K = NULL;
	}

	if ( pFile->m_oMD5 )
	{
		CLibraryFile** pPrev = &m_pMD5Map[ pFile->m_oMD5[ 0 ] & HASH_MASK ];

		for ( CLibraryFile* pOther = *pPrev ; pOther ; pOther = pOther->m_pNextMD5 )
		{
			if ( pOther == pFile )
			{
				*pPrev = pOther->m_pNextMD5;
				break;
			}
			pPrev = &pOther->m_pNextMD5;
		}

		pFile->m_pNextMD5 = NULL;
	}
}

//////////////////////////////////////////////////////////////////////
// CLibraryMaps cull deleted files

void CLibraryMaps::CullDeletedFiles(CLibraryFile* pMatch)
{
	CSingleLock oLock( &Library.m_pSection );
	if ( !oLock.Lock( 100 ) ) return;
	CLibraryFile* pFile;
	
	if ( pMatch->m_oSHA1 )
	{
		if ( ( pFile = LookupFileBySHA1( pMatch->m_oSHA1 ) ) != NULL )
		{
			if ( ! pFile->IsAvailable() ) pFile->Delete();
		}
	}
	
	if ( pMatch->m_oTiger )
	{
		if ( ( pFile = LookupFileByTiger( pMatch->m_oTiger ) ) != NULL )
		{
			if ( ! pFile->IsAvailable() ) pFile->Delete();
		}
	}
	
	if ( pMatch->m_oED2K )
	{
		if ( ( pFile = LookupFileByED2K( pMatch->m_oED2K ) ) != NULL )
		{
			if ( ! pFile->IsAvailable() ) pFile->Delete();
		}
	}
	
	if ( pMatch->m_oMD5 )
	{
		if ( ( pFile = LookupFileByMD5( pMatch->m_oMD5 ) ) != NULL )
		{
			if ( ! pFile->IsAvailable() ) pFile->Delete();
		}
	}

}

//////////////////////////////////////////////////////////////////////
// CLibraryMaps search

CList< CLibraryFile* >* CLibraryMaps::Search(CQuerySearch* pSearch, int nMaximum, BOOL bLocal)
{
	CList< CLibraryFile* >* pHits = NULL;
	int nHit = 0;

	if ( pSearch == NULL )
	{
		for ( POSITION pos = GetFileIterator() ; pos && ( nMaximum == 0 || nHit <= nMaximum ) ;)
		{
			CLibraryFile* pFile = GetNextFile( pos );
			
			if ( pFile->IsAvailable() )
			{
				if ( bLocal || ( pFile->IsShared() && pFile->m_oSHA1 ) )
				{
					if ( ! pHits ) pHits = new CList< CLibraryFile* >( 64 );
					pHits->AddTail( pFile );
					nHit++;
				}
			}
		}
	}
	else if ( pSearch->m_oSHA1 || pSearch->m_oTiger || pSearch->m_oED2K || pSearch->m_oMD5 )
	{
		for ( POSITION pos = GetFileIterator() ; pos && ( 	nMaximum == 0 || nHit <= nMaximum ) ;)
		{
			CLibraryFile* pFile = GetNextFile( pos );
			
			if (!validAndUnequal( pFile->m_oSHA1, pSearch->m_oSHA1 ) && 
				!validAndUnequal( pFile->m_oTiger, pSearch->m_oTiger ) && 
				!validAndUnequal( pFile->m_oED2K, pSearch->m_oED2K ) && 
				!validAndUnequal( pFile->m_oMD5, pSearch->m_oMD5 ) )
			{
				if ( bLocal || pFile->IsShared() && pFile->m_oSHA1 )
				{
					if ( ! pHits ) pHits = new CList< CLibraryFile* >( 64 );
					pHits->AddTail( pFile );
					nHit++;
					if ( ! bLocal && (pSearch->m_oSHA1 || pSearch->m_oTiger) )
					{
						pFile->m_nHitsToday++;
						pFile->m_nHitsTotal++;
					}
				}
			}
		}
	}
	
	return pHits;
}

//////////////////////////////////////////////////////////////////////
// CLibraryMaps serialize

void CLibraryMaps::Serialize1(CArchive& ar, int /*nVersion*/)
{
	if ( ar.IsStoring() )
	{
		ar << static_cast< DWORD >( m_nNextIndex );
	}
	else
	{
		DWORD nNextIndex;
		ar >> nNextIndex;
		m_nNextIndex = nNextIndex;
	}
}

void CLibraryMaps::Serialize2(CArchive& ar, int nVersion)
{
	if ( nVersion < 18 ) return;
	
	if ( ar.IsStoring() )
	{
		ar.WriteCount( m_pDeleted.GetCount() );
		
		for ( POSITION pos = m_pDeleted.GetHeadPosition() ; pos ; )
		{
			CLibraryFile* pFile = m_pDeleted.GetNext( pos );
			pFile->Serialize( ar, nVersion );
		}
	}
	else
	{
		for ( DWORD_PTR nCount = ar.ReadCount() ; nCount > 0 ; nCount-- )
		{
			CLibraryFile* pFile = new CLibraryFile( NULL );
			pFile->Serialize( ar, nVersion );
		}
	}
}

//////////////////////////////////////////////////////////////////////
// CLibrary ILibraryFiles

IMPLEMENT_DISPATCH(CLibraryMaps, LibraryFiles)

STDMETHODIMP CLibraryMaps::XLibraryFiles::get_Application(IApplication FAR* FAR* ppApplication)
{
	METHOD_PROLOGUE( CLibraryMaps, LibraryFiles )
	*ppApplication = Application.GetApp();
	return S_OK;
}

STDMETHODIMP CLibraryMaps::XLibraryFiles::get_Library(ILibrary FAR* FAR* ppLibrary)
{
	METHOD_PROLOGUE( CLibraryMaps, LibraryFiles )
	*ppLibrary = (ILibrary*)Library.GetInterface( IID_ILibrary, TRUE );
	return S_OK;
}

STDMETHODIMP CLibraryMaps::XLibraryFiles::get__NewEnum(IUnknown FAR* FAR* /*ppEnum*/)
{
	METHOD_PROLOGUE( CLibraryMaps, LibraryFiles )
	return E_NOTIMPL;
}

STDMETHODIMP CLibraryMaps::XLibraryFiles::get_Item(VARIANT vIndex, ILibraryFile FAR* FAR* ppFile)
{
	METHOD_PROLOGUE( CLibraryMaps, LibraryFiles )

	CLibraryFile* pFile = NULL;
	*ppFile = NULL;
	
	if ( vIndex.vt == VT_BSTR )
	{
		CString strName( vIndex.bstrVal );
		if ( strName.Find( '\\' ) >= 0 )
			pFile = pThis->LookupFileByPath( strName );
		else
			pFile = pThis->LookupFileByName( strName );
	}
	else
	{
		VARIANT va;
		VariantInit( &va );

		if ( FAILED( VariantChangeType( &va, (VARIANT FAR*)&vIndex, 0, VT_I4 ) ) )
			return E_INVALIDARG;
		if ( va.lVal < 0 || va.lVal >= pThis->GetFileCount() )
			return E_INVALIDARG;
		
		for ( POSITION pos = pThis->GetFileIterator() ; pos ; )
		{
			pFile = pThis->GetNextFile( pos );
			if ( va.lVal-- == 0 ) break;
			pFile = NULL;
		}
	}
	
	*ppFile = pFile ? (ILibraryFile*)pFile->GetInterface( IID_ILibraryFile, TRUE ) : NULL;
	
	return S_OK;
}

STDMETHODIMP CLibraryMaps::XLibraryFiles::get_Count(LONG FAR* pnCount)
{
	METHOD_PROLOGUE( CLibraryMaps, LibraryFiles )
	*pnCount = static_cast< int >( pThis->GetFileCount() );
	return S_OK;
}
