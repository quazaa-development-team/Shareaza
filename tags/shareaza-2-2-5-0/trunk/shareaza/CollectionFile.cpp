//
// ColletionFile.cpp
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
#include "CollectionFile.h"

#include "ZIPFile.h"
#include "Buffer.h"
#include "XML.h"
#include "Schema.h"
#include "SchemaCache.h"

#include "Library.h"
#include "Downloads.h"
#include "ShareazaURL.h"
#include "SharedFile.h"

#include "SHA.h"
#include "MD5.h"
#include "ED2K.h"
#include "TigerTree.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

IMPLEMENT_DYNAMIC(CCollectionFile, CComObject)


/////////////////////////////////////////////////////////////////////////////
// CCollectionFile construction

CCollectionFile::CCollectionFile()
{
	m_pMetadata = NULL;
}

CCollectionFile::~CCollectionFile()
{
	Close();
}

/////////////////////////////////////////////////////////////////////////////
// CCollectionFile open a collection file

BOOL CCollectionFile::Open(LPCTSTR pszFile)
{
	Close();
	CZIPFile pZIP;
	return pZIP.Open( pszFile ) && LoadManifest( pZIP );
}

BOOL CCollectionFile::Attach(HANDLE hFile)
{
	Close();
	CZIPFile pZIP;
	return pZIP.Attach( hFile ) && LoadManifest( pZIP );
}

/////////////////////////////////////////////////////////////////////////////
// CCollectionFile close a collection file

void CCollectionFile::Close()
{
	for ( POSITION pos = GetFileIterator() ; pos ; ) delete GetNextFile( pos );
	m_pFiles.RemoveAll();

	if ( m_pMetadata != NULL ) delete m_pMetadata;
	m_pMetadata = NULL;

	m_sTitle.Empty();
	m_sThisURI.Empty();
	m_sParentURI.Empty();
}

/////////////////////////////////////////////////////////////////////////////
// CCollectionFile find a file by URN

CCollectionFile::File* CCollectionFile::FindByURN(LPCTSTR pszURN)
{
    Hashes::Sha1Hash oSHA1;
    Hashes::TigerHash oTiger;
    Hashes::Md5Hash oMD5;
    Hashes::Ed2kHash oED2K;
	
	oSHA1.fromUrn( pszURN );
    oMD5.fromUrn( pszURN );
    oTiger.fromUrn( pszURN );
    oED2K.fromUrn( pszURN );
	
	for ( POSITION pos = GetFileIterator() ; pos ; )
	{
		File* pFile = GetNextFile( pos );
		
		if ( validAndEqual( oSHA1, pFile->m_oSHA1 ) ) return pFile;
		if ( validAndEqual( oMD5, pFile->m_oMD5 ) ) return pFile;
		if ( validAndEqual( oTiger, pFile->m_oTiger ) ) return pFile;
		if ( validAndEqual( oED2K, pFile->m_oED2K ) ) return pFile;
	}

	return NULL;
}

/////////////////////////////////////////////////////////////////////////////
// CCollectionFile find a shared file

CCollectionFile::File* CCollectionFile::FindFile(CLibraryFile* pShared, BOOL bApply)
{
	File* pFile = NULL;

	for ( POSITION pos = GetFileIterator() ; pos ; )
	{
		pFile = GetNextFile( pos );
		if ( validAndEqual( pShared->m_oSHA1, pFile->m_oSHA1 ) ) break;
		if ( validAndEqual( pShared->m_oMD5, pFile->m_oMD5 ) ) break;
		if ( validAndEqual( pShared->m_oTiger, pFile->m_oTiger ) ) break;
		if ( validAndEqual( pShared->m_oED2K, pFile->m_oED2K ) ) break;
		pFile = NULL;
	}

	if ( bApply && pFile != NULL ) pFile->ApplyMetadata( pShared );

	return pFile;
}

/////////////////////////////////////////////////////////////////////////////
// CCollectionFile get count

int CCollectionFile::GetMissingCount()
{
	int nCount =0;

	for ( POSITION pos = GetFileIterator() ; pos ; )
	{
		File* pFile = GetNextFile( pos );
		if ( ! pFile->IsComplete() && ! pFile->IsDownloading() ) nCount++;
	}

	return nCount;
}

/////////////////////////////////////////////////////////////////////////////
// CCollectionFile load the manifest

BOOL CCollectionFile::LoadManifest(CZIPFile& pZIP)
{
	CZIPFile::File* pFile = pZIP.GetFile( _T("Collection.xml"), TRUE );
	if ( pFile == NULL ) return FALSE;

	CBuffer* pBuffer = pFile->Decompress();
	if ( pBuffer == NULL ) return FALSE;

	CXMLElement* pXML = CXMLElement::FromString( pBuffer->ReadString( pBuffer->m_nLength, CP_UTF8 ), TRUE );
	delete pBuffer;

	if ( pXML == NULL ) return FALSE;
	if ( ! pXML->IsNamed( _T("collection") ) ) return FALSE;

	CXMLElement* pProperties = pXML->GetElementByName( _T("properties") );
	if ( pProperties == NULL ) return FALSE;
	CXMLElement* pContents = pXML->GetElementByName( _T("contents") );
	if ( pContents == NULL ) return FALSE;

	for ( POSITION pos = pContents->GetElementIterator() ; pos ; )
	{
		File* pFile = new File( this );

		if ( pFile->Parse( pContents->GetNextElement( pos ) ) )
		{
			m_pFiles.AddTail( pFile );
		}
		else
		{
			delete pFile;
			Close();
			return FALSE;
		}
	}

	if ( CXMLElement* pMetadata = pProperties->GetElementByName( _T("metadata") ) )
	{
		m_pMetadata = CloneMetadata( pMetadata );
		if ( m_pMetadata != NULL ) m_sThisURI = m_pMetadata->GetAttributeValue( CXMLAttribute::schemaName );
	}

	if ( CXMLElement* pTitle = pProperties->GetElementByName( _T("title") ) )
	{
		m_sTitle = pTitle->GetValue();
	}

	if ( CXMLElement* pMounting = pProperties->GetElementByName( _T("mounting") ) )
	{
		if ( CXMLElement* pParent = pMounting->GetElementByName( _T("parent") ) )
		{
			m_sParentURI = pParent->GetAttributeValue( _T("uri") );
		}
		if ( CXMLElement* pThis = pMounting->GetElementByName( _T("this") ) )
		{
			m_sThisURI = pThis->GetAttributeValue( _T("uri") );
		}
	}

	delete pXML;
	return TRUE;
}

/////////////////////////////////////////////////////////////////////////////
// CCollectionFile clone metadata

CXMLElement* CCollectionFile::CloneMetadata(CXMLElement* pMetadata)
{
	CString strURI = pMetadata->GetAttributeValue( _T("xmlns:s") );
	if ( strURI.IsEmpty() ) return NULL;

	CXMLElement* pCore = pMetadata->GetFirstElement();
	if ( pCore == NULL ) return NULL;

	if ( CSchema* pSchema = SchemaCache.Get( strURI ) )
	{
		pMetadata = pSchema->Instantiate();
	}
	else
	{
		pMetadata = new CXMLElement( NULL, pCore->GetName() + 's' );
		pMetadata->AddAttribute( CXMLAttribute::schemaName, strURI );
	}

	pCore = pCore->Clone();
	pMetadata->AddElement( pCore );

	CString strName = pMetadata->GetName();
	if ( _tcsnicmp( strName, _T("s:"), 2 ) == 0 ) pMetadata->SetName( strName.Mid( 2 ) );

	strName = pCore->GetName();
	if ( _tcsnicmp( strName, _T("s:"), 2 ) == 0 ) pCore->SetName( strName.Mid( 2 ) );

	for ( POSITION pos = pCore->GetElementIterator() ; pos ; )
	{
		CXMLNode* pNode = pCore->GetNextElement( pos );
		CString strName = pNode->GetName();
		if ( _tcsnicmp( strName, _T("s:"), 2 ) == 0 ) pNode->SetName( strName.Mid( 2 ) );
	}

	for ( POSITION pos = pCore->GetAttributeIterator() ; pos ; )
	{
		CXMLNode* pNode = pCore->GetNextAttribute( pos );
		CString strName = pNode->GetName();
		if ( _tcsnicmp( strName, _T("s:"), 2 ) == 0 ) pNode->SetName( strName.Mid( 2 ) );
	}

	return pMetadata;
}


/////////////////////////////////////////////////////////////////////////////
// CCollectionFile::File construction

CCollectionFile::File::File(CCollectionFile* pParent)
{
	m_pParent	= pParent;
//	m_bSHA1		= FALSE;
//	m_bMD5		= FALSE;
//	m_bTiger	= FALSE;
//	m_bED2K		= FALSE;
	m_nSize		= SIZE_UNKNOWN;
	m_pMetadata	= NULL;
}

CCollectionFile::File::~File()
{
	if ( m_pMetadata != NULL ) delete m_pMetadata;
}

/////////////////////////////////////////////////////////////////////////////
// CCollectionFile::File parse

BOOL CCollectionFile::File::Parse(CXMLElement* pRoot)
{
	if ( ! pRoot->IsNamed( _T("file") ) ) return FALSE;

	for ( POSITION pos = pRoot->GetElementIterator() ; pos ; )
	{
		CXMLElement* pXML = pRoot->GetNextElement( pos );

		if ( pXML->IsNamed( _T("id") ) )
		{
			if ( !m_oSHA1 ) m_oSHA1.fromUrn( pXML->GetValue() );
            if ( !m_oMD5 ) m_oMD5.fromUrn( pXML->GetValue() );
			if ( !m_oTiger ) m_oTiger.fromUrn( pXML->GetValue() );
			if ( !m_oED2K ) m_oED2K.fromUrn( pXML->GetValue() );
		}
		else if ( pXML->IsNamed( _T("description") ) )
		{
			if ( CXMLElement* pName = pXML->GetElementByName( _T("name") ) )
			{
				m_sName = pName->GetValue();
			}
			if ( CXMLElement* pSize = pXML->GetElementByName( _T("size") ) )
			{
				_stscanf( pSize->GetValue(), _T("%I64i"), &m_nSize );
			}
		}
		else if ( pXML->IsNamed( _T("metadata") ) )
		{
			if ( m_pMetadata != NULL ) delete m_pMetadata;
			m_pMetadata = CCollectionFile::CloneMetadata( pXML );
		}
		else if ( pXML->IsNamed( _T("packaged") ) )
		{
			if ( CXMLElement* pSource = pXML->GetElementByName( _T("source") ) )
			{
				m_sSource = pSource->GetValue();
			}
		}
	}
	
	return m_oSHA1 || m_oMD5 || m_oTiger || m_oED2K;
}

/////////////////////////////////////////////////////////////////////////////
// CCollectionFile::File state

BOOL CCollectionFile::File::IsComplete() const
{
	return LibraryMaps.LookupFileBySHA1( m_oSHA1, FALSE, TRUE )
		|| LibraryMaps.LookupFileByTiger( m_oTiger, FALSE, TRUE )
		|| LibraryMaps.LookupFileByED2K( m_oED2K, FALSE, TRUE );
}

BOOL CCollectionFile::File::IsDownloading() const
{
	return Downloads.FindBySHA1( m_oSHA1 )
		|| Downloads.FindByTiger( m_oTiger )
		|| Downloads.FindByED2K( m_oED2K );
}

/////////////////////////////////////////////////////////////////////////////
// CCollectionFile::File download

BOOL CCollectionFile::File::Download()
{
	CShareazaURL pURL;

	if ( IsComplete() || IsDownloading() ) return FALSE;

	pURL.m_nAction	= CShareazaURL::uriDownload;
	pURL.m_oSHA1 = m_oSHA1;
    pURL.m_oMD5 = m_oMD5;
	pURL.m_oTiger = m_oTiger;
	pURL.m_oED2K = m_oED2K;
	pURL.m_sName	= m_sName;
	pURL.m_bSize	= ( m_nSize != SIZE_UNKNOWN );
	pURL.m_nSize	= m_nSize;

	return Downloads.Add( &pURL ) != NULL;
}

/////////////////////////////////////////////////////////////////////////////
// CCollectionFile::File apply metadata to a shared file

BOOL CCollectionFile::File::ApplyMetadata(CLibraryFile* pShared)
{
	ASSERT( pShared != NULL );
	if ( m_pMetadata == NULL ) return FALSE;

	CXMLElement* pXML = m_pMetadata->Clone();
	BOOL bResult = pShared->SetMetadata( pXML );
	delete pXML;

	return bResult;
}
