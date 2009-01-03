//
// SharedFile.cpp
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
#include "Settings.h"
#include "SharedFile.h"
#include "SharedFolder.h"
#include "Library.h"
#include "HashDatabase.h"

#include "Network.h"
#include "Uploads.h"
#include "Downloads.h"
#include "SourceURL.h"
#include "FileExecutor.h"
#include "Buffer.h"

#include "XML.h"
#include "XMLCOM.h"
#include "Schema.h"
#include "SchemaCache.h"

#include "SHA.h"
#include "MD5.h"
#include "ED2K.h"
#include "TigerTree.h"

#include "Application.h"
#include "VersionChecker.h"
#include "DlgFolderScan.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

IMPLEMENT_DYNAMIC(CLibraryFile, CComObject)

BEGIN_INTERFACE_MAP(CLibraryFile, CComObject)
	INTERFACE_PART(CLibraryFile, IID_ILibraryFile, LibraryFile)
END_INTERFACE_MAP()


//////////////////////////////////////////////////////////////////////
// CLibraryFile construction

CLibraryFile::CLibraryFile(CLibraryFolder* pFolder, LPCTSTR pszName) :
	m_pNextSHA1( NULL ),
	m_pNextTiger( NULL ),
	m_pNextED2K( NULL ),
	m_pNextMD5( NULL ),
	m_nScanCookie( 0 ),
	m_nUpdateCookie( 0 ),
	m_nSelectCookie( 0 ),
	m_nListCookie( 0 ),
	m_pFolder( pFolder ),
	m_sName( pszName ? pszName : _T("") ),
	m_nIndex( 0 ),
	m_bShared( TS_UNKNOWN ),
	m_nSize( 0 ),
	m_nVirtualBase( 0 ),
	m_nVirtualSize( 0 ),
	m_bVerify( TS_UNKNOWN ),
	m_pSchema( NULL ),
	m_pMetadata( NULL ),
	m_bMetadataAuto( FALSE ),
	m_nRating( 0 ),
	m_nHitsToday( 0 ),
	m_nHitsTotal( 0 ),
	m_nUploadsToday( 0 ),
	m_nUploadsTotal( 0 ),
	m_bCachedPreview( FALSE ),
	m_bBogus( FALSE ),
	m_nSearchCookie( 0 ),
	m_nSearchWords( 0 ),
	m_pNextHit( NULL ),
	m_nCollIndex( 0 ),
	m_nIcon16( -1 )
{
	ZeroMemory( &m_pTime, sizeof(m_pTime) );
	ZeroMemory( &m_pMetadataTime, sizeof(m_pMetadataTime) );
	EnableDispatch( IID_ILibraryFile );
	
}

CLibraryFile::~CLibraryFile()
{
	Library.RemoveFile( this );
	
	if ( m_pMetadata != NULL ) delete m_pMetadata;
	
	for ( POSITION pos = m_pSources.GetHeadPosition() ; pos ; )
	{
		delete m_pSources.GetNext( pos );
	}
}

//////////////////////////////////////////////////////////////////////
// CLibraryFile path computation

CString CLibraryFile::GetPath() const
{
	if ( m_pFolder != NULL )
		return m_pFolder->m_sPath + '\\' + m_sName;
	else
		return CString();
}

CString CLibraryFile::GetFolderName() const
{
	int nBase = 0;
	CString str = "";

	if ( m_pFolder != NULL && m_pFolder->m_pParent != NULL )
	{
		for ( CLibraryFolder* pFolder = m_pFolder ; ; pFolder = pFolder->m_pParent )
		{
			if ( pFolder->m_pParent == NULL )
			{
				nBase = pFolder->m_sPath.GetLength();
				break;
			}
		}
	}
	else
	{
		return str;
	}

	if ( nBase <= 0 )
	{
		str = m_sName;
	}
	else
	{
		ASSERT( m_pFolder->m_sPath.GetLength() > nBase );
		str = m_pFolder->m_sPath.Mid( nBase + 1 );
	}

	return str;
}

CString CLibraryFile::GetSearchName() const
{
	int nBase = 0;
	CString str;
	
	if ( m_pFolder != NULL && m_pFolder->m_pParent != NULL )
	{
		for ( CLibraryFolder* pFolder = m_pFolder ; ; pFolder = pFolder->m_pParent )
		{
			if ( pFolder->m_pParent == NULL )
			{
				nBase = pFolder->m_sPath.GetLength();
				break;
			}
		}
	}
	
	if ( nBase <= 0 )
	{
		str = m_sName;
	}
	else
	{
		ASSERT( m_pFolder->m_sPath.GetLength() > nBase );
		str = m_pFolder->m_sPath.Mid( nBase + 1 ) + '\\' + m_sName;
	}
	
	ToLower( str );
	return str;
}

//////////////////////////////////////////////////////////////////////
// CLibraryFile shared check

BOOL CLibraryFile::IsShared() const
{
	if ( m_bVerify == TS_FALSE ) return FALSE;	// verified and file has been marked as bad.
	if ( m_bShared == TS_FALSE ) return FALSE;

	if ( LPCTSTR pszExt = _tcsrchr( m_sName, '.' ) )
	{
		pszExt++;
		
		if ( LPCTSTR pszFind = _tcsistr( Settings.Library.PrivateTypes, pszExt ) )
		{
			if ( pszFind[ _tcslen( pszExt ) ] == 0 ||
				 pszFind[ _tcslen( pszExt ) ] == '|' )
			{
				if ( pszFind == Settings.Library.PrivateTypes ||
					 pszFind[-1] == '|' )
				{
					return FALSE;
				}
			}
		}
	}
	
	if ( m_bShared == TS_TRUE ) return TRUE;
	
	for ( CLibraryFolder* pFolder = m_pFolder ; pFolder ; pFolder = pFolder->m_pParent )
	{
		if ( pFolder->m_bShared )
		{
			if ( pFolder->m_bShared == TS_TRUE ) return TRUE;
			if ( pFolder->m_bShared == TS_FALSE ) return FALSE;
		}
	}
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CLibraryFile schema URI test

BOOL CLibraryFile::IsSchemaURI(LPCTSTR pszURI) const
{
	if ( m_pSchema == NULL )
	{
		return ( pszURI == NULL || *pszURI == NULL );
	}
	else
	{
		return m_pSchema->CheckURI( pszURI );
	}
}

//////////////////////////////////////////////////////////////////////
// CLibraryFile rebuild hashes and metadata

BOOL CLibraryFile::Rebuild()
{
	if ( m_pFolder == NULL ) return FALSE;
	
	Library.RemoveFile( this );
	
	m_oSHA1.clear();
    m_oTiger.clear();
    m_oMD5.clear();
    m_oED2K.clear();
	m_nVirtualBase = m_nVirtualSize = 0;
	
	if ( m_pMetadata != NULL && m_bMetadataAuto )
	{
		delete m_pMetadata;
		m_pSchema	= NULL;
		m_pMetadata	= NULL;
	}
	
	Library.AddFile( this );
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CLibraryFile rename

BOOL CLibraryFile::Rename(LPCTSTR pszName)
{
	if ( m_pFolder == NULL ) return FALSE;
	if ( ! pszName || ! *pszName ) return FALSE;
	if ( _tcschr( pszName, '\\' ) ) return FALSE;
	
	CString strNew = m_pFolder->m_sPath + '\\' + pszName;
	
	Uploads.OnRename( GetPath() );
	
	if ( MoveFile( GetPath(), strNew ) )
	{
		Uploads.OnRename( GetPath(), strNew );
	}
	else
	{
		Uploads.OnRename( GetPath(), GetPath() );
		return FALSE;
	}
	
	if ( m_pMetadata != NULL )
	{
		CString strMetaFolder	= m_pFolder->m_sPath + _T("\\Metadata");
		CString strMetaOld		= strMetaFolder + '\\' + m_sName + _T(".xml");
		CString strMetaNew		= strMetaFolder + '\\' + pszName + _T(".xml");
		
		MoveFile( strMetaOld, strMetaNew );
	}
	
	Library.RemoveFile( this );
	
	m_sName = pszName;
	
	m_pFolder->OnFileRename( this );
	
	Library.AddFile( this );
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CLibraryFile delete

BOOL CLibraryFile::Delete(BOOL bDeleteGhost)
{
	if ( m_pFolder != NULL )
	{
		Uploads.OnRename( GetPath(), NULL, TRUE );
		
		// Should be double zeroed path
		TCHAR szPath[MAX_PATH] = { 0 };
		_tcsncpy( szPath, GetPath(), MAX_PATH - 2 );
		
		SHFILEOPSTRUCT pOp = { 0 };
		pOp.wFunc	= FO_DELETE;
		pOp.pFrom	= szPath;
		pOp.fFlags	= FOF_ALLOWUNDO|FOF_NOCONFIRMATION;
		
		if ( GetAsyncKeyState( VK_SHIFT ) & 0x8000 ) pOp.fFlags &= ~FOF_ALLOWUNDO;
		
		int nReturn = SHFileOperation( &pOp );

		if ( nReturn != 0 )
		{
			Uploads.OnRename( GetPath(), GetPath() );
			return FALSE;
		}
		
		if ( m_pMetadata != NULL || m_sComments.GetLength() || m_nRating > 0 )
		{
			CString strMetaFolder	= m_pFolder->m_sPath + _T("\\Metadata");
			CString strMetaFile		= strMetaFolder + '\\' + m_sName + _T(".xml");
			
			if ( DeleteFile( strMetaFile ) )
			{
				RemoveDirectory( strMetaFolder );
			}
		}
	}
	else
	{
		OnDelete( bDeleteGhost );
	}
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CLibraryFile metadata access

BOOL CLibraryFile::SetMetadata(CXMLElement* pXML)
{
	// if ( m_pFolder == NULL ) return FALSE;
	if ( m_pMetadata == NULL && pXML == NULL ) return TRUE;
	
	CSchema* pSchema = NULL;
	
	if ( pXML != NULL )
	{
		pSchema = SchemaCache.Get( pXML->GetAttributeValue( CXMLAttribute::schemaName ) );
		if ( pSchema == NULL ) return FALSE;
		if ( ! pSchema->Validate( pXML, TRUE ) ) return FALSE;
		
		if ( m_pMetadata != NULL && m_pSchema == pSchema )
		{
			if ( m_pMetadata->Equals( pXML->GetFirstElement() ) ) return TRUE;
		}
	}
	
	Library.RemoveFile( this );
	
	if ( m_pMetadata != NULL )
	{
		delete m_pMetadata;
		m_pSchema		= NULL;
		m_pMetadata		= NULL;
		m_bMetadataAuto	= FALSE;
	}
	
	m_pSchema		= pSchema;
	m_pMetadata		= pXML ? pXML->GetFirstElement()->Detach() : NULL;
	m_bMetadataAuto	= FALSE;
	
	if ( m_pMetadata == NULL )
	{
        m_oSHA1.clear();
        m_oTiger.clear();
        m_oMD5.clear();
        m_oED2K.clear();
	}
	
	Library.AddFile( this );
	
	SaveMetadata();
	
	return TRUE;
}

CString CLibraryFile::GetMetadataWords() const
{
	if ( m_pSchema != NULL && m_pMetadata != NULL )
	{
		return m_pSchema->GetIndexedWords( m_pMetadata );
	}
	else
	{
		return CString();
	}
}

//////////////////////////////////////////////////////////////////////
// CLibraryFile hash volume lookups

CTigerTree* CLibraryFile::GetTigerTree()
{
	if ( !m_oTiger ) return NULL;
	if ( m_pFolder == NULL ) return NULL;
	
	CTigerTree* pTiger = new CTigerTree();
	
	if ( LibraryHashDB.GetTiger( m_nIndex, pTiger ) )
	{
		Hashes::TigerHash oRoot;
		pTiger->GetRoot( oRoot );
		if ( ! m_oTiger || m_oTiger == oRoot ) return pTiger;
		
		LibraryHashDB.DeleteTiger( m_nIndex );
		
		Library.RemoveFile( this );
		m_oTiger.clear();
		Library.AddFile( this );
	}
	
	delete pTiger;
	return NULL;
}

CED2K* CLibraryFile::GetED2K()
{
	if ( !m_oED2K ) return NULL;
	if ( m_pFolder == NULL ) return NULL;
	
	CED2K* pED2K = new CED2K();
	
	if ( LibraryHashDB.GetED2K( m_nIndex, pED2K ) )
	{
        Hashes::Ed2kHash oRoot;
		pED2K->GetRoot( oRoot );
		if ( m_oED2K == oRoot ) return pED2K;
		
		LibraryHashDB.DeleteED2K( m_nIndex );
	}
	
	delete pED2K;
	Library.RemoveFile( this );
	m_oED2K.clear();
	Library.AddFile( this );
	
	return NULL;
}

//////////////////////////////////////////////////////////////////////
// CLibraryFile alternate sources

CSharedSource* CLibraryFile::AddAlternateSources(LPCTSTR pszURL)
{
	CString strURLs( pszURL );
	CSharedSource* pFirst = NULL;
	BOOL bQuote = FALSE;
	
	for ( int nScan = 0 ; nScan < strURLs.GetLength() ; nScan++ )
	{
		if ( strURLs[ nScan ] == '\"' )
		{
			bQuote = ! bQuote;
			strURLs.SetAt( nScan, ' ' );
		}
		else if ( strURLs[ nScan ] == ',' && bQuote )
		{
			strURLs.SetAt( nScan, '`' );
		}
	}
	
	strURLs += ',';
	
	for ( int nCount = 0 ; ; )
	{
		int nPos = strURLs.Find( ',' );
		if ( nPos < 0 ) break;
		
		CString strURL	= strURLs.Left( nPos );
		strURLs			= strURLs.Mid( nPos + 1 );
		strURL.TrimLeft();
		
		if ( _tcsistr( strURL, _T("://") ) != NULL )
		{
			for ( int nScan = 0 ; nScan < strURL.GetLength() ; nScan++ )
			{
				if ( strURL[ nScan ] == '`' ) strURL.SetAt( nScan, ',' );
			}
		}
		else
		{
			nPos = strURL.Find( ':' );
			if ( nPos < 1 ) continue;
			
			int nPort = 0;
			_stscanf( strURL.Mid( nPos + 1 ), _T("%i"), &nPort );
			strURL.Truncate( nPos );
			USES_CONVERSION;
			DWORD nAddress = inet_addr( T2CA( strURL ) );
			strURL.Empty();
			
			if ( ! Network.IsFirewalledAddress( &nAddress, TRUE ) && 
				 ! Network.IsReserved( (IN_ADDR*)&nAddress ) && nPort != 0 && nAddress != INADDR_NONE )
			{
				if ( m_oSHA1 )
				{
					strURL.Format( _T("http://%s:%i/uri-res/N2R?%s"),
						(LPCTSTR)CString( inet_ntoa( *(IN_ADDR*)&nAddress ) ),
						nPort, (LPCTSTR)m_oSHA1.toUrn() );
				}
			}
		}
		
		if ( CSharedSource* pSource = AddAlternateSource( strURL, FALSE ) )
		{
			pFirst = pSource;
			nCount++;
		}
	}
	
	return pFirst;
}

CSharedSource* CLibraryFile::AddAlternateSource(LPCTSTR pszURL, BOOL /*bForce*/)
{
	if ( pszURL == NULL ) return NULL;
	if ( *pszURL == 0 ) return NULL;
	
	CString strURL( pszURL );
	CSourceURL pURL;
	
	FILETIME tSeen = { 0, 0 };
	BOOL bSeen = FALSE;
	
	int nPos = strURL.ReverseFind( ' ' );
	
	if ( nPos > 0 )
	{
		CString strTime = strURL.Mid( nPos + 1 );
		strURL = strURL.Left( nPos );
		strURL.TrimRight();
		bSeen = TimeFromString( strTime, &tSeen );
	}
	
	// if ( ! bSeen && ! bForce ) return NULL;
	if ( ! pURL.Parse( strURL ) ) return NULL;
	
	if ( memcmp( &pURL.m_pAddress, &Network.m_pHost.sin_addr,
		 sizeof(IN_ADDR) ) == 0 ) return NULL;
	
	if ( Network.IsFirewalledAddress( &pURL.m_pAddress, TRUE ) ||
		 Network.IsReserved( (IN_ADDR*)&pURL.m_pAddress ) ) return FALSE;
	
	if ( validAndUnequal( pURL.m_oSHA1, m_oSHA1 ) ) return NULL;
	
	for ( POSITION pos = m_pSources.GetHeadPosition() ; pos ; )
	{
		CSharedSource* pSource = m_pSources.GetNext( pos );
		
		if ( pSource->m_sURL.CompareNoCase( strURL ) == 0 )
		{
			pSource->Freshen( bSeen ? &tSeen : NULL );
			return pSource;
		}
	}
	
	CSharedSource* pSource = new CSharedSource( strURL, bSeen ? &tSeen : NULL );
	m_pSources.AddTail( pSource );
	
	return pSource;
}

CString CLibraryFile::GetAlternateSources(CList< CString >* pState, int nMaximum, PROTOCOLID nProtocol)
{
	CString strSources;
	SYSTEMTIME stNow;
	FILETIME ftNow;
	
	GetSystemTime( &stNow );
	SystemTimeToFileTime( &stNow, &ftNow );
	
	for ( POSITION pos = m_pSources.GetHeadPosition() ; pos ; )
	{
		CSharedSource* pSource = m_pSources.GetNext( pos );
		
		if ( ! pSource->IsExpired( ftNow ) &&
			 ( pState == NULL || pState->Find( pSource->m_sURL ) == NULL ) )
		{
			if ( pState != NULL ) pState->AddTail( pSource->m_sURL );
			
			if ( ( nProtocol == PROTOCOL_HTTP ) && ( _tcsncmp( pSource->m_sURL, _T("http://"), 7 ) != 0 ) )
				continue;
			
			CString strURL = pSource->m_sURL;
			Replace( strURL, _T(","), _T("%2C") );

			if ( strSources.GetLength() ) strSources += _T(", ");
			strSources += strURL;
			strSources += ' ';
			strSources += TimeToString( &pSource->m_pTime );

			if ( nMaximum == 1 ) break;
			else if ( nMaximum > 1 ) nMaximum --;
		}
	}
	
	if ( strSources.Find( _T("Zhttp://") ) >= 0 ) strSources.Empty();
	
	return strSources;
}

//////////////////////////////////////////////////////////////////////
// CLibraryFile serialize

void CLibraryFile::Serialize(CArchive& ar, int nVersion)
{
	if ( ar.IsStoring() )
	{
		ASSERT( m_sName.GetLength() );
		ar << m_sName;
		ar << m_nIndex;
		ar << m_nSize;
		ar.Write( &m_pTime, sizeof(m_pTime) );
		ar << m_bShared;
		
		ar << m_nVirtualSize;
		if ( m_nVirtualSize > 0 ) ar << m_nVirtualBase;
		
//		ar << m_bSHA1;
//		if ( m_bSHA1 ) ar.Write( &m_pSHA1, sizeof(SHA1) );
        SerializeOut( ar, m_oSHA1 );
//		ar << m_bTiger;
//		if ( m_bTiger ) ar.Write( &m_pTiger, sizeof(TIGEROOT) );
        SerializeOut( ar, m_oTiger );
//		ar << m_bMD5;
//		if ( m_bMD5 ) ar.Write( &m_pMD5, sizeof(MD5) );
        SerializeOut( ar, m_oMD5 );
//		ar << m_bED2K;
//		if ( m_bED2K ) ar.Write( &m_pED2K, sizeof(MD4) );
        SerializeOut( ar, m_oED2K );
		ar << m_bVerify;
		
		if ( m_pSchema != NULL && m_pMetadata != NULL )
		{
			ar << m_pSchema->m_sURI;
			ar << m_bMetadataAuto;
			if ( ! m_bMetadataAuto ) ar.Write( &m_pMetadataTime, sizeof(m_pMetadataTime) );
			m_pMetadata->Serialize( ar );
		}
		else
		{
			CString strURI;
			ar << strURI;
		}
		
		ar << m_nRating;
		ar << m_sComments;
		ar << m_sShareTags;
		
		if ( m_bMetadataAuto && ( m_nRating || m_sComments.GetLength() ) )
		{
			ar.Write( &m_pMetadataTime, sizeof(m_pMetadataTime) );
		}
		
		ar << m_nHitsTotal;
		ar << m_nUploadsTotal;
		ar << m_bCachedPreview;
		ar << m_bBogus;
		
		ar.WriteCount( m_pSources.GetCount() );
		
		for ( POSITION pos = m_pSources.GetHeadPosition() ; pos ; )
		{
			CSharedSource* pSource = m_pSources.GetNext( pos );
			pSource->Serialize( ar, nVersion );
		}
	}
	else
	{
		ar >> m_sName;
		ASSERT( m_sName.GetLength() );

		ar >> m_nIndex;
		
		if ( nVersion >= 17 )
		{
            ar >> m_nSize;
		}
		else
		{
			DWORD nSize;
			ar >> nSize;
			m_nSize = nSize;
		}
		
		ar.Read( &m_pTime, sizeof(m_pTime) );
		
		if ( nVersion >= 5 )
		{
			ar >> m_bShared;
		}
		else
		{
			BYTE bShared;
			ar >> bShared;
			m_bShared = bShared ? TS_UNKNOWN : TS_FALSE;
		}
		
		if ( nVersion >= 21 )
		{
			ar >> m_nVirtualSize;
			if ( m_nVirtualSize > 0 ) ar >> m_nVirtualBase;
		}
		
//		ar >> m_bSHA1;
//		if ( m_bSHA1 ) ar.Read( &m_pSHA1, sizeof(SHA1) );
        SerializeIn( ar, m_oSHA1, nVersion );
//		if ( nVersion >= 8 ) ar >> m_bTiger; else m_bTiger = FALSE;
//		if ( m_bTiger ) ar.Read( &m_pTiger, sizeof(TIGEROOT) );
        if ( nVersion >= 8 )
        {
            SerializeIn( ar, m_oTiger, nVersion );
        }
        else
        {
            m_oTiger.clear();
        }
//		if ( nVersion >= 11 ) ar >> m_bMD5; else m_bMD5 = FALSE;
//		if ( m_bMD5 ) ar.Read( &m_pMD5, sizeof(MD5) );
        if ( nVersion >= 11 )
        {
            SerializeIn( ar, m_oMD5, nVersion );
        }
        else
        {
            m_oMD5.clear();
        }
		if ( nVersion >= 11 )
        {
            SerializeIn( ar, m_oED2K, nVersion );
        }
        else
        {
            m_oED2K.clear();
        }
		
		if ( nVersion >= 4 ) ar >> m_bVerify;
		
		CString strURI;
		ar >> strURI;
		
		if ( strURI.GetLength() )
		{
			ar >> m_bMetadataAuto;
			if ( ! m_bMetadataAuto ) ar.Read( &m_pMetadataTime, sizeof(m_pMetadataTime) );
			
			m_pMetadata = new CXMLElement();
			m_pMetadata->Serialize( ar );
			m_pSchema = SchemaCache.Get( strURI );
			
			if ( m_pSchema == NULL )
			{
				delete m_pMetadata;
				m_pMetadata = NULL;
			}
		}
		
		if ( nVersion >= 13 )
		{
			ar >> m_nRating;
			ar >> m_sComments;
			if ( nVersion >= 16 ) ar >> m_sShareTags;
			
			if ( m_bMetadataAuto && ( m_nRating || m_sComments.GetLength() ) )
			{
				ar.Read( &m_pMetadataTime, sizeof(m_pMetadataTime) );
			}
		}
		
		ar >> m_nHitsTotal;
		ar >> m_nUploadsTotal;

		if ( nVersion >= 14 ) ar >> m_bCachedPreview;
		if ( nVersion >= 20 ) ar >> m_bBogus;
		
		if ( nVersion >= 2 )
		{
			SYSTEMTIME stNow;
			FILETIME ftNow;
			
			GetSystemTime( &stNow );
			SystemTimeToFileTime( &stNow, &ftNow );
			
			for ( DWORD_PTR nSources = ar.ReadCount() ; nSources > 0 ; nSources-- )
			{
				CSharedSource* pSource = new CSharedSource();
				if ( pSource == NULL )
				{
					theApp.Message( MSG_ERROR, _T("Memory allocation error in CLibraryFile::Serialize") );
					break;
				}
				pSource->Serialize( ar, nVersion );
				
				if ( pSource->IsExpired( ftNow ) )
					delete pSource;
				else
					m_pSources.AddTail( pSource );
			}
		}
		
		// Rehash pre-version-22 audio files
		
		if ( nVersion < 22 && m_pSchema != NULL && m_pSchema->m_sURI.CompareNoCase( CSchema::uriAudio ) == 0 )
		{
			m_oSHA1.clear();
            m_oTiger.clear();
            m_oMD5.clear();
            m_oED2K.clear();
		}
		
		Library.AddFile( this );
	}
}

//////////////////////////////////////////////////////////////////////
// CLibraryFile threaded scan

BOOL CLibraryFile::ThreadScan(CSingleLock& pLock, DWORD nScanCookie, QWORD nSize, FILETIME* pTime, LPCTSTR pszMetaData)
{
	BOOL bChanged = FALSE;
	
	ASSERT( m_pFolder != NULL );
	m_nScanCookie = nScanCookie;
	
	if ( m_nSize != nSize || CompareFileTime( &m_pTime, pTime ) != 0 )
	{
		bChanged = TRUE;
		pLock.Lock();
		Library.RemoveFile( this );
		
		CopyMemory( &m_pTime, pTime, sizeof(FILETIME) );
		m_nSize = nSize;
		
        m_oSHA1.clear();
        m_oTiger.clear();
        m_oMD5.clear();
        m_oED2K.clear();
		
		if ( m_pMetadata != NULL && m_bMetadataAuto )
		{
			delete m_pMetadata;
			m_pSchema		= NULL;
			m_pMetadata		= NULL;
			m_bMetadataAuto	= FALSE;
		}
	}
	
	HANDLE hFile	= INVALID_HANDLE_VALUE;
	BOOL bMetaData	= FALSE;
	FILETIME pMetaDataTime = { 0 };
	
	if ( pszMetaData != NULL )
	{
		CString strMetaData = pszMetaData + m_sName + _T(".xml");
		
		if ( Library.m_pfnGFAEW != NULL && theApp.m_bNT )
		{
			USES_CONVERSION;
			WIN32_FILE_ATTRIBUTE_DATA pInfo = { 0 };
			bMetaData = (*Library.m_pfnGFAEW)( T2CW( (LPCTSTR)strMetaData ), GetFileExInfoStandard, &pInfo );
			pMetaDataTime = pInfo.ftLastWriteTime;
		}
		else if ( Library.m_pfnGFAEA != NULL )
		{
			USES_CONVERSION;
			WIN32_FILE_ATTRIBUTE_DATA pInfo = { 0 };
			bMetaData = (*Library.m_pfnGFAEA)( T2CA( (LPCTSTR)strMetaData ), GetFileExInfoStandard, &pInfo );
			pMetaDataTime = pInfo.ftLastWriteTime;
		}
		else
		{
			hFile = CreateFile( strMetaData, GENERIC_READ, FILE_SHARE_READ,
				NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
			
			if ( hFile != INVALID_HANDLE_VALUE )
			{
				bMetaData = TRUE;
				GetFileTime( hFile, NULL, NULL, &pMetaDataTime );
			}
		}
	}
	
	if ( bMetaData )
	{
		if ( CompareFileTime( &m_pMetadataTime, &pMetaDataTime ) != 0 )
		{
			CopyMemory( &m_pMetadataTime, &pMetaDataTime, sizeof(FILETIME) );
			
			if ( hFile == INVALID_HANDLE_VALUE )
			{
				hFile = CreateFile( pszMetaData + m_sName + _T(".xml"),
					GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
					FILE_ATTRIBUTE_NORMAL, NULL );
			}
			
			if ( hFile != INVALID_HANDLE_VALUE )
			{
				if ( ! bChanged )
				{
					bChanged = TRUE;
					pLock.Lock();
					Library.RemoveFile( this );
				}
				
				LoadMetadata( hFile );
			}
		}
		
		if ( hFile != INVALID_HANDLE_VALUE ) CloseHandle( hFile );
	}
	else if ( m_pMetadata != NULL && ! m_bMetadataAuto )
	{
		BOOL bLocked = ! bChanged;
		if ( bLocked ) pLock.Lock();
		
		if ( m_pMetadata != NULL && ! m_bMetadataAuto )
		{
			if ( ! bChanged )
			{
				bChanged = TRUE;
				bLocked = FALSE;
				Library.RemoveFile( this );
			}
			
			ZeroMemory( &m_pMetadataTime, sizeof(FILETIME) );
			LoadMetadata( INVALID_HANDLE_VALUE );
			
			m_oSHA1.clear();
            m_oTiger.clear();
            m_oMD5.clear();
            m_oED2K.clear();
		}
		
		if ( bLocked ) pLock.Unlock();
	}
	
	if ( bChanged )
	{
		Library.AddFile( this );
		CFolderScanDlg::Update( m_sName,
			( m_nSize == SIZE_UNKNOWN ) ? 0 : (DWORD)( m_nSize / 1024 ) );
		pLock.Unlock();
		m_nUpdateCookie++;
	}
	else
	{
		CFolderScanDlg::Update( m_sName,
			( m_nSize == SIZE_UNKNOWN ) ? 0 : (DWORD)( m_nSize / 1024 ) );
	}
	
	return bChanged;
}

//////////////////////////////////////////////////////////////////////
// CLibraryFile metadata file I/O

BOOL CLibraryFile::LoadMetadata(HANDLE hFile)
{
	ASSERT( m_pFolder != NULL );
	
	if ( m_bMetadataAuto == FALSE )
	{
		if ( m_pMetadata != NULL ) delete m_pMetadata;
		m_pSchema	= NULL;
		m_pMetadata	= NULL;
	}
	
	if ( hFile == INVALID_HANDLE_VALUE ) return FALSE;
	
	CXMLElement* pXML = CXMLElement::FromFile( hFile );
	if ( pXML == NULL ) return FALSE;
	
	if ( CXMLElement* pComment = pXML->GetElementByName( _T("comment") ) )
	{
		m_nRating = -1;
		CString strRating = pComment->GetAttributeValue( _T("rating") );
		_stscanf( strRating, _T("%i"), &m_nRating );
		m_nRating	= max( 0, min( 6, m_nRating + 1 ) );
		m_sComments	= pComment->GetValue();
		Replace( m_sComments, _T("{n}"), _T("\r\n") );
		pComment->Delete();
	}
	
	CSchema* pSchema = SchemaCache.Get( pXML->GetAttributeValue( CXMLAttribute::schemaName, _T("") ) );
	
	if ( pSchema == NULL || pXML->GetFirstElement() == NULL )
	{
		delete pXML;
		return FALSE;
	}
	
	pSchema->Validate( pXML, TRUE );
	
	if ( m_pMetadata != NULL ) delete m_pMetadata;
	
	m_pSchema		= pSchema;
	m_pMetadata		= pXML->GetFirstElement()->Detach();
	m_bMetadataAuto	= FALSE;
	
	delete pXML;
	
	return TRUE;
}

BOOL CLibraryFile::SaveMetadata()
{
	CXMLElement* pXML = NULL;
	
	m_nUpdateCookie++;
	
	if ( m_pFolder == NULL ) return TRUE;
	
	if ( m_pSchema != NULL && m_pMetadata != NULL && ! m_bMetadataAuto )
	{
		pXML = m_pSchema->Instantiate( TRUE );
		pXML->AddElement( m_pMetadata->Clone() );
	}
	
	if ( m_nRating > 0 || m_sComments.GetLength() > 0 )
	{
		if ( pXML == NULL )
		{
			pXML = new CXMLElement( NULL, _T("comments") );
		}
		
		CXMLElement* pComment = pXML->AddElement( _T("comment") );
		
		if ( m_nRating > 0 )
		{
			CString strRating;
			strRating.Format( _T("%i"), m_nRating - 1 );
			pComment->AddAttribute( _T("rating"), strRating );
		}
		
		if ( m_sComments.GetLength() > 0 )
		{
			CString strComments( m_sComments );
			Replace( strComments, _T("\r\n"), _T("{n}") );
			pComment->SetValue( strComments );
		}
	}
	
	CString strMetaFolder	= m_pFolder->m_sPath + _T("\\Metadata");
	CString strMetaFile		= strMetaFolder + _T("\\") + m_sName + _T(".xml");
	
	if ( pXML != NULL )
	{
		pXML->AddAttribute( _T("xmlns:xsi"), CXMLAttribute::xmlnsInstance );
		
		HANDLE hFile = CreateFile( strMetaFile, GENERIC_WRITE, FILE_SHARE_READ, NULL,
			CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL );
		
		if ( hFile == INVALID_HANDLE_VALUE )
		{
			CreateDirectory( strMetaFolder, NULL );
			SetFileAttributes( strMetaFolder, FILE_ATTRIBUTE_HIDDEN );
			
			hFile = CreateFile( strMetaFile, GENERIC_WRITE, FILE_SHARE_READ, NULL,
				CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL );
			
			if ( hFile == INVALID_HANDLE_VALUE ) return FALSE;
		}
		
		CString strXML = pXML->ToString( TRUE, TRUE );
		DWORD nWritten;
		delete pXML;
		
		int nASCII = WideCharToMultiByte( CP_UTF8, 0, strXML, strXML.GetLength(), NULL, 0, NULL, NULL );
		LPSTR pszASCII = new CHAR[ nASCII ];
		WideCharToMultiByte( CP_UTF8, 0, strXML, strXML.GetLength(), pszASCII, nASCII, NULL, NULL );
		WriteFile( hFile, pszASCII, nASCII, &nWritten, NULL );
		delete [] pszASCII;
		
		GetFileTime( hFile, NULL, NULL, &m_pMetadataTime );
		CloseHandle( hFile );
	}
	else
	{
		DeleteFile( strMetaFile );
		RemoveDirectory( strMetaFolder );
		ZeroMemory( &m_pMetadataTime, sizeof(FILETIME) );
	}
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CLibraryFile delete handler
// bDeleteGhost is used only when deleting ghost files

void CLibraryFile::OnDelete(BOOL bDeleteGhost, TRISTATE bCreateGhost)
{
	if ( m_pFolder != NULL )
	{
		if ( bCreateGhost == TS_TRUE )
		{
			if ( m_nRating == 0 && m_sComments.IsEmpty() )
			{
				m_bShared = TS_FALSE;
				m_sComments = L"Ghost File";
			}
			Ghost();
			return;
		}
		else if ( ( m_nRating > 0 || m_sComments.GetLength() > 0 ) && bCreateGhost != TS_FALSE )
		{
			Ghost();
			return;
		}
	}
	
	Library.OnFileDelete( this, bDeleteGhost );
	
	delete this;
}

void CLibraryFile::Ghost()
{
	SYSTEMTIME pTime;
	GetSystemTime( &pTime );
	SystemTimeToFileTime( &pTime, &m_pTime );
	Library.RemoveFile( this );
	m_pFolder = NULL;
	Library.AddFile( this );
	Library.OnFileDelete( this );
}

//////////////////////////////////////////////////////////////////////
// CLibraryFile download verification

BOOL CLibraryFile::OnVerifyDownload(const Hashes::Sha1Hash& oSHA1, const Hashes::Ed2kHash& oED2K, LPCTSTR pszSources)
{
	if ( m_pFolder == NULL ) return FALSE;
	
	if ( Settings.Downloads.VerifyFiles && m_bVerify == TS_UNKNOWN && m_nVirtualSize == 0 )
	{
		if ( m_oSHA1 && oSHA1 )
		{
			m_bVerify = ( m_oSHA1 == oSHA1 ) ? TS_TRUE : TS_FALSE;
		}

		if ( m_oED2K && oED2K )
		{
			m_bVerify = ( m_oED2K == oED2K ) ? TS_TRUE : TS_FALSE;
		}
		
		if ( m_bVerify == TS_TRUE )
		{
			theApp.Message( MSG_SYSTEM, IDS_DOWNLOAD_VERIFY_SUCCESS, (LPCTSTR)m_sName );
			Downloads.OnVerify( GetPath(), TRUE );
		}
		else if ( m_bVerify == TS_FALSE )
		{
			m_bShared = TS_FALSE;
			
			theApp.Message( MSG_ERROR, IDS_DOWNLOAD_VERIFY_FAIL, (LPCTSTR)m_sName );
			Downloads.OnVerify( GetPath(), FALSE );
			
			return FALSE;
		}
	}
	
	if ( m_oSHA1 && m_nVirtualSize == 0 && VersionChecker.m_bUpgrade )
	{
		VersionChecker.CheckUpgradeHash( m_oSHA1, GetPath() );
	}
	
	if ( pszSources != NULL && *pszSources != 0 )
	{
		AddAlternateSources( pszSources );
	}
	return TRUE;
}


//////////////////////////////////////////////////////////////////////
// CSharedSource construction

CSharedSource::CSharedSource(LPCTSTR pszURL, FILETIME* pTime)
{
	ZeroMemory( &m_pTime, sizeof( m_pTime ) );

	if ( pszURL != NULL )
	{
		m_sURL = pszURL;
		Freshen( pTime );
	}
}

void CSharedSource::Serialize(CArchive& ar, int nVersion)
{
	if ( ar.IsStoring() )
	{
		ar << m_sURL;
		ar.Write( &m_pTime, sizeof(FILETIME) );
	}
	else
	{
		ar >> m_sURL;

		if ( nVersion >= 10 )
		{
			ar.Read( &m_pTime, sizeof(FILETIME) );
		}
		else
		{
			DWORD nTemp;
			ar >> nTemp;
			Freshen();
		}
	}
}

void CSharedSource::Freshen(FILETIME* pTime)
{
	SYSTEMTIME tNow1;
	GetSystemTime( &tNow1 );
	
	if ( pTime != NULL )
	{
		FILETIME tNow2;
		
		SystemTimeToFileTime( &tNow1, &tNow2 );
		(LONGLONG&)tNow2 += 10000000;
		
		if ( CompareFileTime( pTime, &tNow2 ) <= 0 )
		{
			m_pTime = *pTime;
		}
		else
		{
			SystemTimeToFileTime( &tNow1, &m_pTime );
		}
	}
	else
	{
		SystemTimeToFileTime( &tNow1, &m_pTime );
	}
}

BOOL CSharedSource::IsExpired(FILETIME& tNow)
{
	LONGLONG nElapse = *((LONGLONG*)&tNow) - *((LONGLONG*)&m_pTime);
	return nElapse > (LONGLONG)Settings.Library.SourceExpire * 10000000;
}


CSharedSourceAddr::CSharedSourceAddr( NodeType nType, CString pNode, FILETIME* pTime, FILETIME* pMinLastTime)
{
	if ( nType != PROTOCOL_NULL && !pNode.IsEmpty() )
	{
		m_nType = nType;
		m_pNode = pNode;
		Freshen( pTime );
		m_pMinLastTime = *pMinLastTime;
	}
}

void CSharedSourceAddr::Serialize(CArchive& ar, int nVersion)
{
	if ( ar.IsStoring() )
	{
		ar << (DWORD)m_nType;
		ar << m_pNode;
		ar.Write( &m_pTime, sizeof(FILETIME) );
		ar.Write( &m_pMinLastTime, sizeof(FILETIME) );
	}
	else
	{
		if ( nVersion >= 24 )
		{
			DWORD nNodeTypeTemp;
			ar >> nNodeTypeTemp;
			m_nType = (NodeType)nNodeTypeTemp;
			ar >> m_pNode;
			ar.Read( &m_pTime, sizeof(FILETIME) );
			ar.Read( &m_pMinLastTime, sizeof(FILETIME) );
		}
		else if ( nVersion >= 10 )
		{
			m_nType = PROTOCOL_URL;
			ar >> m_pNode;
			ar.Read( &m_pTime, sizeof(FILETIME) );
		}
		else
		{
			DWORD nTemp;
			m_nType = PROTOCOL_URL;
			ar >> m_pNode;
			ar >> nTemp;
			Freshen();
		}
	}
}

void CSharedSourceAddr::Freshen(FILETIME* pTime)
{
	SYSTEMTIME tNow1;
	GetSystemTime( &tNow1 );

	if ( pTime != NULL )
	{
		FILETIME tNow2;

		SystemTimeToFileTime( &tNow1, &tNow2 );
		(LONGLONG&)tNow2 += 10000000;

		if ( CompareFileTime( pTime, &tNow2 ) <= 0 )
		{
			m_pTime = *pTime;
		}
		else
		{
			SystemTimeToFileTime( &tNow1, &m_pTime );
		}
	}
	else
	{
		SystemTimeToFileTime( &tNow1, &m_pTime );
	}
}

BOOL CSharedSourceAddr::IsExpired(FILETIME& tNow)
{
	LONGLONG nElapse = *((LONGLONG*)&tNow) - *((LONGLONG*)&m_pTime);
	return ! ( (nElapse <= (LONGLONG)Settings.Library.SourceExpire * 10000000) || 
				*((LONGLONG*)&tNow) >= *((LONGLONG*)&m_pMinLastTime) );
}

//////////////////////////////////////////////////////////////////////
// CLibraryFile automation

IMPLEMENT_DISPATCH(CLibraryFile, LibraryFile)

STDMETHODIMP CLibraryFile::XLibraryFile::get_Application(IApplication FAR* FAR* ppApplication)
{
	METHOD_PROLOGUE( CLibraryFile, LibraryFile )
	*ppApplication = Application.GetApp();
	return S_OK;
}

STDMETHODIMP CLibraryFile::XLibraryFile::get_Library(ILibrary FAR* FAR* ppLibrary)
{
	METHOD_PROLOGUE( CLibraryFile, LibraryFile )
	*ppLibrary = (ILibrary*)Library.GetInterface( IID_ILibrary, TRUE );
	return S_OK;
}

STDMETHODIMP CLibraryFile::XLibraryFile::get_Folder(ILibraryFolder FAR* FAR* ppFolder)
{
	METHOD_PROLOGUE( CLibraryFile, LibraryFile )
	if ( pThis->m_pFolder == NULL )
		*ppFolder = NULL;
	else
		*ppFolder = (ILibraryFolder*)pThis->m_pFolder->GetInterface( IID_ILibraryFolder, TRUE );
	return *ppFolder != NULL ? S_OK : S_FALSE;
}

STDMETHODIMP CLibraryFile::XLibraryFile::get_Path(BSTR FAR* psPath)
{
	METHOD_PROLOGUE( CLibraryFile, LibraryFile )
	pThis->GetPath().SetSysString( psPath );
	return S_OK;
}

STDMETHODIMP CLibraryFile::XLibraryFile::get_Name(BSTR FAR* psPath)
{
	METHOD_PROLOGUE( CLibraryFile, LibraryFile )
	pThis->m_sName.SetSysString( psPath );
	return S_OK;
}

STDMETHODIMP CLibraryFile::XLibraryFile::get_Shared(STRISTATE FAR* pnValue)
{
	METHOD_PROLOGUE( CLibraryFile, LibraryFile )
	*pnValue = (STRISTATE)pThis->m_bShared;
	return S_OK;
}

STDMETHODIMP CLibraryFile::XLibraryFile::put_Shared(STRISTATE nValue)
{
	METHOD_PROLOGUE( CLibraryFile, LibraryFile )
	pThis->m_bShared = nValue;
	return S_OK;
}

STDMETHODIMP CLibraryFile::XLibraryFile::get_EffectiveShared(VARIANT_BOOL FAR* pbValue)
{
	METHOD_PROLOGUE( CLibraryFile, LibraryFile )
	*pbValue = pThis->IsShared() ? VARIANT_TRUE : VARIANT_FALSE;
	return S_OK;
}

STDMETHODIMP CLibraryFile::XLibraryFile::get_Size(LONG FAR* pnSize)
{
	METHOD_PROLOGUE( CLibraryFile, LibraryFile )
	*pnSize = (LONG)pThis->GetSize();
	return S_OK;
}

STDMETHODIMP CLibraryFile::XLibraryFile::get_Index(LONG FAR* pnIndex)
{
	METHOD_PROLOGUE( CLibraryFile, LibraryFile )
	*pnIndex = (LONG)pThis->m_nIndex;
	return S_OK;
}

STDMETHODIMP CLibraryFile::XLibraryFile::get_URN(BSTR sURN, BSTR FAR* psURN)
{
	METHOD_PROLOGUE( CLibraryFile, LibraryFile )
	CString strURN( sURN );
	
	if ( strURN.IsEmpty() )
	{
		if ( pThis->m_oTiger && pThis->m_oSHA1 )
			strURN = _T("urn:bitprint");
		else if ( pThis->m_oTiger )
			strURN = _T("urn:tree:tiger/");
		else if ( pThis->m_oSHA1 )
			strURN = _T("urn:sha1");
		else if ( pThis->m_oED2K )
			strURN = _T("urn:ed2khash");
		else if ( pThis->m_oMD5 )
			strURN = _T("urn:md5");
		else
			return E_FAIL;
	}
	
	if ( strURN.CompareNoCase( _T("urn:bitprint") ) == 0 )
	{
		if ( !pThis->m_oSHA1 || ! pThis->m_oTiger ) return E_FAIL;
		strURN	= _T("urn:bitprint:")
                + pThis->m_oSHA1.toString() + '.'
                + pThis->m_oTiger.toString();
	}
	else if ( strURN.CompareNoCase( _T("urn:sha1") ) == 0 )
	{
		if ( !pThis->m_oSHA1 ) return E_FAIL;
		strURN = pThis->m_oSHA1.toUrn();
	}
	else if ( strURN.CompareNoCase( _T("urn:tree:tiger/") ) == 0 )
	{
		if ( ! pThis->m_oTiger ) return E_FAIL;
        strURN = pThis->m_oTiger.toUrn();
	}
	else if ( strURN.CompareNoCase( _T("urn:md5") ) == 0 )
	{
        if ( ! pThis->m_oMD5 ) return E_FAIL;
        strURN = pThis->m_oMD5.toUrn();
	}
	else if ( strURN.CompareNoCase( _T("urn:ed2k") ) == 0 )
	{
		if ( ! pThis->m_oED2K ) return E_FAIL;
        strURN = pThis->m_oED2K.toUrn();
	}
	else
	{
		return E_FAIL;
	}
	
	strURN.SetSysString( psURN );
	
	return S_OK;
}

STDMETHODIMP CLibraryFile::XLibraryFile::get_MetadataAuto(VARIANT_BOOL FAR* pbValue)
{
	METHOD_PROLOGUE( CLibraryFile, LibraryFile )
	*pbValue = pThis->m_bMetadataAuto ? VARIANT_TRUE : VARIANT_FALSE;
	return S_OK;
}

STDMETHODIMP CLibraryFile::XLibraryFile::get_Metadata(ISXMLElement FAR* FAR* ppXML)
{
	METHOD_PROLOGUE( CLibraryFile, LibraryFile )
	*ppXML = NULL;

	if ( pThis->m_pSchema == NULL || pThis->m_pMetadata == NULL ) return S_OK;
	
	CXMLElement* pXML	= pThis->m_pSchema->Instantiate( TRUE );
	*ppXML				= (ISXMLElement*)CXMLCOM::Wrap( pXML, IID_ISXMLElement );
	
	pXML->AddElement( pThis->m_pMetadata->Clone() );
	
	return S_OK;
}

STDMETHODIMP CLibraryFile::XLibraryFile::put_Metadata(ISXMLElement FAR* pXML)
{
	METHOD_PROLOGUE( CLibraryFile, LibraryFile )
	
	if ( CXMLElement* pReal = CXMLCOM::Unwrap( pXML ) )
	{
		return pThis->SetMetadata( pReal ) ? S_OK : E_FAIL;
	}
	else
	{
		pThis->SetMetadata( NULL );
		return S_OK;
	}
}

STDMETHODIMP CLibraryFile::XLibraryFile::Execute()
{
	METHOD_PROLOGUE( CLibraryFile, LibraryFile )
	return CFileExecutor::Execute( pThis->GetPath(), TRUE ) ? S_OK : E_FAIL;
}

STDMETHODIMP CLibraryFile::XLibraryFile::SmartExecute()
{
	METHOD_PROLOGUE( CLibraryFile, LibraryFile )
	return CFileExecutor::Execute( pThis->GetPath(), FALSE ) ? S_OK : E_FAIL;
}

STDMETHODIMP CLibraryFile::XLibraryFile::Delete()
{
	METHOD_PROLOGUE( CLibraryFile, LibraryFile )
	return pThis->Delete() ? S_OK : E_FAIL;
}

STDMETHODIMP CLibraryFile::XLibraryFile::Rename(BSTR sNewName)
{
	METHOD_PROLOGUE( CLibraryFile, LibraryFile )
	return pThis->Rename( CString( sNewName ) ) ? S_OK : E_FAIL;
}

STDMETHODIMP CLibraryFile::XLibraryFile::Copy(BSTR /*sNewPath*/)
{
	METHOD_PROLOGUE( CLibraryFile, LibraryFile )
	return E_NOTIMPL;
}

STDMETHODIMP CLibraryFile::XLibraryFile::Move(BSTR /*sNewPath*/)
{
	METHOD_PROLOGUE( CLibraryFile, LibraryFile )
	return E_NOTIMPL;
}
