//
// LibraryBuilder.cpp
//
// Copyright (c) Shareaza Development Team, 2002-2007.
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
#include "Settings.h"
#include "SharedFile.h"
#include "Library.h"
#include "LibraryBuilder.h"
#include "LibraryBuilderInternals.h"
#include "LibraryBuilderPlugins.h"
#include "HashDatabase.h"
#include "Security.h"
#include "ThumbCache.h"

#include "XML.h"
#include "Schema.h"
#include "SchemaCache.h"
#include "ID3.h"

#include "SHA.h"
#include "TigerTree.h"
#include "MD5.h"
#include "ED2K.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

CLibraryBuilder LibraryBuilder;


//////////////////////////////////////////////////////////////////////
// CLibraryBuilder construction

CLibraryBuilder::CLibraryBuilder() :
	m_hThread( NULL ),
	m_bThread( FALSE ),
	m_bPriority( FALSE ),
	m_nReaded( 0 ),
	m_nElapsed( 0 )
{
	QueryPerformanceFrequency( &m_nFreq );
	QueryPerformanceCounter( &m_nLastCall );
}

CLibraryBuilder::~CLibraryBuilder()
{
	StopThread();
}

//////////////////////////////////////////////////////////////////////
// CLibraryBuilder add and remove

void CLibraryBuilder::Add(CLibraryFile* pFile)
{
	ASSERT( pFile );
	ASSERT( pFile->m_nIndex );

	CQuickLock pLock( m_pSection );
	if ( std::find( m_pFiles.begin(), m_pFiles.end(), pFile->m_nIndex ) == m_pFiles.end() )
	{
		m_pFiles.push_back( pFile->m_nIndex );

		StartThread();
	}
}

void CLibraryBuilder::Remove(DWORD nIndex)
{
	ASSERT( nIndex );

	CQuickLock oLock( m_pSection );
	CFileInfoList::iterator i = std::find( m_pFiles.begin(), m_pFiles.end(), nIndex );
	if ( i != m_pFiles.end() )
	{
		m_pFiles.erase( i );
	}
}

void CLibraryBuilder::Remove(CLibraryFile* pFile)
{
	ASSERT( pFile );

	Remove( pFile->m_nIndex );
}

void CLibraryBuilder::Remove(LPCTSTR szPath)
{
	ASSERT( szPath );

	DWORD nIndex = 0;
	{
		CQuickLock oLibraryLock( Library.m_pSection );
		CLibraryFile* pFile = LibraryMaps.LookupFileByPath( szPath );
		if ( pFile )
			nIndex = pFile->m_nIndex;
	}
	if ( nIndex )
	{
		Remove( nIndex );
	}
}

int CLibraryBuilder::GetRemaining() const
{
	CQuickLock oLock( m_pSection );
	return (int)m_pFiles.size();
}

CString CLibraryBuilder::GetCurrent() const
{
	CQuickLock oLock( m_pSection );
	return m_sPath;
}

void CLibraryBuilder::RequestPriority(LPCTSTR pszPath)
{
	ASSERT( pszPath );

	DWORD nIndex = 0;
	{
		CQuickLock oLibraryLock( Library.m_pSection );
		CLibraryFile* pFile = LibraryMaps.LookupFileByPath( pszPath );
		if ( pFile )
			nIndex = pFile->m_nIndex;
	}
	if ( nIndex )
	{
		CQuickLock oLock( m_pSection );
		CFileInfoList::iterator i = std::find( m_pFiles.begin(), m_pFiles.end(), nIndex );
		if ( i != m_pFiles.end() )
		{
			m_pFiles.erase( i );

			m_pFiles.push_front( nIndex );
		}
	}
}

//////////////////////////////////////////////////////////////////////
// CLibraryBuilder rotate queue

void CLibraryBuilder::Skip(DWORD nIndex)
{
	ASSERT( nIndex );

	CQuickLock oLock( m_pSection );
	CFileInfoList::iterator i = std::find( m_pFiles.begin(), m_pFiles.end(), nIndex );
	if ( i != m_pFiles.end() )
	{
		CFileInfo fi( *i );

		m_pFiles.erase( i );

		FILETIME ftCurrentTime;
		GetSystemTimeAsFileTime( &ftCurrentTime );
		fi.nNextAccessTime = MAKEQWORD( ftCurrentTime.dwLowDateTime,
			ftCurrentTime.dwHighDateTime ) + 50000000;	// + 5 sec

		m_pFiles.push_back( fi );
	}
}

//////////////////////////////////////////////////////////////////////
// CLibraryBuilder get best file to hash

DWORD CLibraryBuilder::GetNextFileToHash(CString& sPath)
{
	DWORD nIndex = 0;
	sPath.Empty();

	CSingleLock oLock( &m_pSection );
	if ( oLock.Lock( 100 ) )
	{
		if ( m_pFiles.empty() )
		{
			// No files left
			m_bThread = FALSE;
		}
		else
		{
			// Get next candidate
			FILETIME ftCurrentTime;
			GetSystemTimeAsFileTime( &ftCurrentTime );
			QWORD nCurrentTime = MAKEQWORD( ftCurrentTime.dwLowDateTime,
				ftCurrentTime.dwHighDateTime );
			for ( CFileInfoList::iterator i = m_pFiles.begin(); i != m_pFiles.end(); i++ )
			{
				if ( (*i).nNextAccessTime < nCurrentTime )
				{
					nIndex = (*i).nIndex;
					break;
				}
			}
		}
		oLock.Unlock();
	}

	if ( nIndex )
	{
		CSingleLock oLibraryLock( &Library.m_pSection );
		if ( oLibraryLock.Lock( 100 ) )
		{
			CLibraryFile* pFile = LibraryMaps.LookupFile( nIndex );
			if ( pFile )
			{
				sPath = pFile->GetPath();
			}
			oLibraryLock.Unlock();

			if ( ! pFile )
			{
				// Unknown file
				Remove( nIndex );
				nIndex = 0;
			}
		}
		else
			// Library locked
			nIndex = 0;

		if ( nIndex )
		{
			WIN32_FILE_ATTRIBUTE_DATA wfad;
			if ( GetFileAttributesEx( sPath, GetFileExInfoStandard, &wfad ) )
			{
				int nSlash = sPath.ReverseFind( _T('\\') );
				if ( CLibrary::IsBadFile( sPath.Mid( nSlash + 1 ), sPath.Left( nSlash ),
					wfad.dwFileAttributes ) )
				{
					// Remove bad file
					Remove( nIndex );
					nIndex = 0;
				}
			}
			else
			{
				DWORD err = GetLastError();
				if ( err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND )
				{
					// Remove if error is fatal
					Remove( nIndex );
				}
				else
				{
					// Ignore if error is not fatal (for example access violation)
					Skip( nIndex );
				}
				nIndex = 0;
			}
		}
	}

	return nIndex;
}

//////////////////////////////////////////////////////////////////////
// CLibraryBuilder thread control

void CLibraryBuilder::StartThread()
{
	CQuickLock pLock( m_pSection );

	if ( ! m_bThread && ! m_pFiles.empty() )
	{
		m_bThread = TRUE;
		m_hThread = BeginThread( "LibraryBuilder", ThreadStart, this, m_bPriority ?
			THREAD_PRIORITY_BELOW_NORMAL : THREAD_PRIORITY_IDLE );
	}
}

void CLibraryBuilder::StopThread()
{
	{
		CQuickLock pLock( m_pSection );

		if ( m_hThread == NULL )
			// Already stopped
			return;

		// Request termination
		m_bThread = FALSE;
	}

	// Wait
	CloseThread( &m_hThread );
}

BOOL CLibraryBuilder::IsAlive() const
{
	CQuickLock pLock( m_pSection );

	return m_bThread;
}

//////////////////////////////////////////////////////////////////////
// CLibraryBuilder priority control

void CLibraryBuilder::BoostPriority(BOOL bPriority)
{
	CQuickLock pLock( m_pSection );

	if ( m_bPriority == bPriority ) return;
	m_bPriority = bPriority;

	if ( m_bThread && m_hThread )
	{
		SetThreadPriority( m_hThread, m_bPriority ?
			THREAD_PRIORITY_BELOW_NORMAL : THREAD_PRIORITY_IDLE );
	}
}

BOOL CLibraryBuilder::GetBoostPriority() const
{
	CQuickLock pLock( m_pSection );

	return m_bPriority;
}

//////////////////////////////////////////////////////////////////////
// CLibraryBuilder thread run (threaded)

UINT CLibraryBuilder::ThreadStart(LPVOID pParam)
{
	((CLibraryBuilder*)pParam)->OnRun();
	return 0;
}

void CLibraryBuilder::OnRun()
{
	while ( IsAlive() )
	{
		Sleep( 100 );	// Max 10 files per second

		CString sPath;
		DWORD nIndex = GetNextFileToHash( sPath );
		if ( nIndex )
		{
			{
				CQuickLock pLock( m_pSection );
				m_sPath = sPath;
			}

			HANDLE hFile = CreateFile( sPath, GENERIC_READ,
				FILE_SHARE_READ | ( theApp.m_bNT ? FILE_SHARE_DELETE : 0 ), NULL,
				OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL );
			VERIFY_FILE_ACCESS( hFile, sPath )
			if ( hFile != INVALID_HANDLE_VALUE )
			{
				theApp.Message( MSG_DEBUG, _T("Hashing: %s"), (LPCTSTR)sPath );

				// ToDo: We need MD5 hash of the audio file without tags...
				if ( HashFile( sPath, hFile, nIndex ) )
				{
					SetFilePointer( hFile, 0, NULL, FILE_BEGIN );
					CLibraryBuilderInternals::ExtractMetadata( nIndex, sPath, hFile );

					SetFilePointer( hFile, 0, NULL, FILE_BEGIN );
					CLibraryBuilderPlugins::ExtractMetadata( nIndex, sPath, hFile );

					CSize Size( Settings.Library.ThumbSize, Settings.Library.ThumbSize );
					CThumbCache::Cache( sPath, &Size, nIndex );

					// Done
					Remove( nIndex );
				}
				else
					Skip( nIndex );

				CloseHandle( hFile );
			}
			else
			{
				DWORD err = GetLastError();
				if ( err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND )
					// Fatal error
					Remove( nIndex );
				else
					Skip( nIndex );
			}

			{
				CQuickLock pLock( m_pSection );
				m_sPath.Empty();
			}
		}
	}

	Settings.Live.NewFile = FALSE;

	CQuickLock pLock( m_pSection );
	m_bThread = FALSE;
	m_hThread = NULL;
}

//////////////////////////////////////////////////////////////////////
// CLibraryBuilder file hashing (threaded)

#define MAX_HASH_BUFFER_SIZE	1024ul*256ul	// 256 Kb

BOOL CLibraryBuilder::HashFile(LPCTSTR szPath, HANDLE hFile, DWORD nIndex)
{
	DWORD nSizeHigh	= 0;
	DWORD nSizeLow	= GetFileSize( hFile, &nSizeHigh );
	QWORD nFileSize	= (QWORD)nSizeLow | ( (QWORD)nSizeHigh << 32 );
	QWORD nFileBase	= 0;

	BOOL bVirtual = FALSE;

	if ( Settings.Library.VirtualFiles )
		bVirtual = DetectVirtualFile( szPath, hFile, nFileBase, nFileSize );

	nSizeLow	= (DWORD)( nFileBase & 0xFFFFFFFF );
	nSizeHigh	= (DWORD)( nFileBase >> 32 );
	SetFilePointer( hFile, nSizeLow, (PLONG)&nSizeHigh, FILE_BEGIN );

	CTigerTree pTiger;
	CED2K pED2K;
	CSHA pSHA1;
	CMD5 pMD5;

	pTiger.BeginFile( Settings.Library.TigerHeight, nFileSize );
	pED2K.BeginFile( nFileSize );

	// Reset statistics if passed more than 10 seconds
	LARGE_INTEGER count1;
	QueryPerformanceCounter( &count1 );
	if ( ( ( ( count1.QuadPart - m_nLastCall.QuadPart ) * 1000000ull ) /
		m_nFreq.QuadPart) > 10000 )
	{
		m_nLastCall.QuadPart = count1.QuadPart;
		m_nElapsed = 0;
		m_nReaded = 0;
	}

	void* pBuffer = VirtualAlloc( NULL, MAX_HASH_BUFFER_SIZE, MEM_COMMIT, PAGE_READWRITE );
	DWORD nBlock;
	QWORD nLength = nFileSize;
	for ( ; nLength > 0 ; nLength -= nBlock )
	{
		nBlock	= min( nLength, MAX_HASH_BUFFER_SIZE );

		if ( ! m_bThread )
			// Termination request
			break;

		if( ! ::ReadFile( hFile, pBuffer, nBlock, &nBlock, NULL ) )
			// Read error
			break;

		QueryPerformanceCounter( &count1 );
		m_nElapsed += ( ( ( count1.QuadPart - m_nLastCall.QuadPart ) * 1000000ull ) /
			m_nFreq.QuadPart);	// mks
		m_nLastCall.QuadPart = count1.QuadPart;
		m_nReaded += nBlock;

		if ( m_nElapsed > 0 && m_nReaded > 0 )
		{
			// Calculation of compensation delay
			QWORD nSpeed = ( m_nReaded * 1000000ull ) / m_nElapsed;	// B/s
			QWORD nMaxSpeed = 1024 * 1024 * (  m_bPriority ?
				Settings.Library.HighPriorityHashing :
				Settings.Library.LowPriorityHashing );				// B/s
			if ( nMaxSpeed > 0 && nSpeed > nMaxSpeed )
			{
				DWORD nDelay = (DWORD) ( ( ( ( nSpeed * m_nElapsed ) / nMaxSpeed ) -
					m_nElapsed ) / 1000ull );	// ms
				if ( nDelay > 1000 )
					nDelay = 1000;	// 1 s
				else if ( nDelay < 1 )
					nDelay = 1;		// 1 ms

				// Compensation
				Sleep( nDelay );
			}

			m_nElapsed = 0;	// mks
			m_nReaded = 0;	
		}

		if ( ! nBlock )
			// EOF
			break;

		pSHA1.Add( pBuffer, nBlock );
		pMD5.Add( pBuffer, nBlock );
		pTiger.AddToFile( pBuffer, nBlock );
		pED2K.AddToFile( pBuffer, nBlock );
	}

	VirtualFree( pBuffer, 0, MEM_RELEASE );

	if ( nLength != 0 )
		return FALSE;

	pSHA1.Finish();
	pMD5.Finish();
	pTiger.FinishFile();
	pED2K.FinishFile();

	{
		CQuickLock oLibraryLock( Library.m_pSection );
		CLibraryFile* pFile = Library.LookupFile( nIndex );
		if ( pFile == NULL ) return FALSE;

		Library.RemoveFile( pFile );

		pFile->m_bBogus			= FALSE;
		pFile->m_nVirtualBase	= bVirtual ? nFileBase : 0;
		pFile->m_nVirtualSize	= bVirtual ? nFileSize : 0;
		
		pSHA1.GetHash( pFile->m_oSHA1 );
		pMD5.GetHash( pFile->m_oMD5 );
		pTiger.GetRoot( pFile->m_oTiger );
		pED2K.GetRoot( pFile->m_oED2K );
		
		LibraryMaps.CullDeletedFiles( pFile );
		Library.AddFile( pFile );

		// child pornography check
		if ( Settings.Search.AdultFilter &&
			( AdultFilter.IsChildPornography( pFile->GetSearchName() ) ||
			  AdultFilter.IsChildPornography( pFile->GetMetadataWords() ) ) )
		{
			pFile->m_bVerify = pFile->m_bShared = TRI_FALSE;
		}

		theApp.Message( MSG_DEBUG, _T("Hashing completed: %s"), szPath );

		Library.Update();
	}

	LibraryHashDB.StoreTiger( nIndex, &pTiger );
	LibraryHashDB.StoreED2K( nIndex, &pED2K );

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CLibraryBuilder metadata submission (threaded)

int CLibraryBuilder::SubmitMetadata(DWORD nIndex, LPCTSTR pszSchemaURI, CXMLElement*& pXML)
{
	int nAttributeCount = 0;
	CSchema* pSchema = SchemaCache.Get( pszSchemaURI );

	if ( pSchema == NULL )
	{
		delete pXML;
		return nAttributeCount;
	}

	CXMLElement* pBase = pSchema->Instantiate( TRUE );
	pBase->AddElement( pXML );

	if ( ! pSchema->Validate( pBase, TRUE ) )
	{
		delete pBase;
		return nAttributeCount;
	}

	pXML->Detach();
	delete pBase;

	nAttributeCount = pXML->GetAttributeCount();

	CQuickLock oLibraryLock( Library.m_pSection );
	if ( CLibraryFile* pFile = Library.LookupFile( nIndex ) )
	{
		if ( pFile->m_pMetadata )
			// Merge new with old metadata
			pXML->Merge( pFile->m_pMetadata );
		else
			pFile->m_bMetadataAuto	= TRUE;

		Library.RemoveFile( pFile );

		// Delete old one
		delete pFile->m_pMetadata;

		// Set new matadata
		pFile->m_pSchema		= pSchema;
		pFile->m_pMetadata		= pXML;
		pFile->ModifyMetadata();

		Library.AddFile( pFile );
		Library.Update();

		return nAttributeCount;
	}

	delete pXML;

	return nAttributeCount;
}

//////////////////////////////////////////////////////////////////////
// CLibraryBuilder bogus/corrupted state submission (threaded)

BOOL CLibraryBuilder::SubmitCorrupted(DWORD nIndex)
{
	CQuickLock oLibraryLock( Library.m_pSection );
	if ( CLibraryFile* pFile = Library.LookupFile( nIndex ) )
	{
		pFile->m_bBogus = TRUE;
		return TRUE;
	}

	return FALSE;
}

//////////////////////////////////////////////////////////////////////
// CLibraryBuilder virtual file detection (threaded)

BOOL CLibraryBuilder::DetectVirtualFile(LPCTSTR szPath, HANDLE hFile, QWORD& nOffset, QWORD& nLength)
{
	BOOL bVirtual = FALSE;

	if ( _tcsistr( szPath, _T(".mp3") ) != NULL )
	{
		bVirtual |= DetectVirtualID3v2( hFile, nOffset, nLength );
		bVirtual |= DetectVirtualID3v1( hFile, nOffset, nLength );
	}

	return bVirtual;
}

BOOL CLibraryBuilder::DetectVirtualID3v1(HANDLE hFile, QWORD& nOffset, QWORD& nLength)
{
	ID3V1 pInfo;
	DWORD nRead;

	if ( nLength <= 128 ) return FALSE;

	LONG nPosLow	= (LONG)( ( nOffset + nLength - 128 ) & 0xFFFFFFFF );
	LONG nPosHigh	= (LONG)( ( nOffset + nLength - 128 ) >> 32 );
	SetFilePointer( hFile, nPosLow, &nPosHigh, FILE_BEGIN );

	if ( ! ReadFile( hFile, &pInfo, sizeof(pInfo), &nRead, NULL ) ) return FALSE;
	if ( nRead != sizeof(pInfo) ) return FALSE;
	if ( memcmp( pInfo.szTag, ID3V1_TAG, 3 ) ) return FALSE;

	nLength -= 128;

	return TRUE;
}

BOOL CLibraryBuilder::DetectVirtualID3v2(HANDLE hFile, QWORD& nOffset, QWORD& nLength)
{
	ID3V2_HEADER pHeader;
	DWORD nRead;

	LONG nPosLow	= (LONG)( ( nOffset ) & 0xFFFFFFFF );
	LONG nPosHigh	= (LONG)( ( nOffset ) >> 32 );
	SetFilePointer( hFile, nPosLow, &nPosHigh, FILE_BEGIN );

	if ( ! ReadFile( hFile, &pHeader, sizeof(pHeader), &nRead, NULL ) ) return FALSE;
	if ( nRead != sizeof(pHeader) ) return FALSE;

	if ( strncmp( pHeader.szTag, ID3V2_TAG, 3 ) ) return FALSE;
	if ( pHeader.nMajorVersion < 2 || pHeader.nMajorVersion > 4 ) return FALSE;
	if ( pHeader.nFlags & ~ID3V2_KNOWNMASK ) return FALSE;
	if ( pHeader.nFlags & ID3V2_UNSYNCHRONISED ) return FALSE;

	DWORD nTagSize = swapEndianess( pHeader.nSize );
	ID3_DESYNC_SIZE( nTagSize );

	if ( pHeader.nFlags & ID3V2_FOOTERPRESENT ) nTagSize += 10;
	nTagSize += sizeof(pHeader);

	if ( nLength <= nTagSize ) return FALSE;

	nOffset += nTagSize;
	nLength -= nTagSize;

	return TRUE;
}

BOOL CLibraryBuilder::RefreshMetadata(const CString& sPath)
{
	CWaitCursor wc;
	DWORD nIndex;

	{
		CQuickLock oLibraryLock( Library.m_pSection );
		CLibraryFile* pFile = LibraryMaps.LookupFileByPath( sPath );
		if ( ! pFile )
			return FALSE;
		nIndex = pFile->m_nIndex;
	}

	BOOL bResult = FALSE;
	HANDLE hFile = CreateFile( sPath, GENERIC_READ,
		 FILE_SHARE_READ | ( theApp.m_bNT ? FILE_SHARE_DELETE : 0 ), NULL,
		 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL );
	VERIFY_FILE_ACCESS( hFile, sPath )
	if ( hFile != INVALID_HANDLE_VALUE )
	{
		theApp.Message( MSG_DEBUG, _T("Refreshing: %s"), (LPCTSTR)sPath );

		SetFilePointer( hFile, 0, NULL, FILE_BEGIN );
		bResult = CLibraryBuilderInternals::ExtractMetadata( nIndex, sPath, hFile ) ||
			bResult;

		SetFilePointer( hFile, 0, NULL, FILE_BEGIN );
		bResult = CLibraryBuilderPlugins::ExtractMetadata( nIndex, sPath, hFile ) ||
			bResult;

		CloseHandle( hFile );
	}

	return bResult;
}