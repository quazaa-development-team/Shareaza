//
// LibraryBuilderInternals.cpp
//
// Copyright (c) Shareaza Development Team, 2002-2007.
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
#include "LibraryFolders.h"
#include "LibraryBuilder.h"
#include "LibraryBuilderInternals.h"

#define _ID3_DEFINE_GENRES
#include "Buffer.h"
#include "Schema.h"
#include "XML.h"
#include "ID3.h"
#include "CollectionFile.h"
#include <MsiDefs.h>

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif


//////////////////////////////////////////////////////////////////////
// CLibraryBuilderInternals construction

CLibraryBuilderInternals::CLibraryBuilderInternals()
{
}

CLibraryBuilderInternals::~CLibraryBuilderInternals()
{
}

//////////////////////////////////////////////////////////////////////
// CLibraryBuilderInternals load settings

void CLibraryBuilderInternals::LoadSettings()
{
	m_bEnableMP3	= theApp.GetProfileInt( _T("Library"), _T("ScanMP3"), TRUE );
	m_bEnableEXE	= theApp.GetProfileInt( _T("Library"), _T("ScanEXE"), TRUE );

	// Check if Windows installer library is present
	HINSTANCE hMSI = LoadLibrary( _T("Msi.dll") );

	if ( !hMSI )
		m_bEnableMSI = FALSE;
	else
	{
		m_bEnableMSI	= theApp.GetProfileInt( _T("Library"), _T("ScanMSI"), TRUE );
		FreeLibrary( hMSI );
	}

	m_bEnableImage	= theApp.GetProfileInt( _T("Library"), _T("ScanImage"), TRUE );
	m_bEnableASF	= theApp.GetProfileInt( _T("Library"), _T("ScanASF"), TRUE );
	m_bEnableOGG	= theApp.GetProfileInt( _T("Library"), _T("ScanOGG"), TRUE );
	m_bEnableAPE	= theApp.GetProfileInt( _T("Library"), _T("ScanAPE"), TRUE );
	m_bEnableMPC	= theApp.GetProfileInt( _T("Library"), _T("ScanMPC"), TRUE );
	m_bEnableAVI	= theApp.GetProfileInt( _T("Library"), _T("ScanAVI"), TRUE );
	m_bEnablePDF	= theApp.GetProfileInt( _T("Library"), _T("ScanPDF"), TRUE );
	m_bEnableCHM	= theApp.GetProfileInt( _T("Library"), _T("ScanCHM"), TRUE );
}

//////////////////////////////////////////////////////////////////////
// CLibraryBuilderInternals extract metadata (threaded)

BOOL CLibraryBuilderInternals::ExtractMetadata(DWORD nIndex, CString& strPath, HANDLE hFile, Hashes::Sha1Hash& oSHA1, Hashes::Md5Hash& oMD5)
{
	CString strType;
	
	int nExtPos = strPath.ReverseFind( '.' );
	if ( nExtPos != -1 ) strType = strPath.Mid( nExtPos );
	
	ToLower( strType );
	
	if ( strType == _T(".mp3") )
	{
		if ( ! m_bEnableMP3 ) return FALSE;
		if ( Settings.Library.PreferAPETags )
		{
			if ( ReadAPE( nIndex, hFile, oMD5, true ) ) return TRUE;
			if ( ReadID3v2( nIndex, hFile ) ) return TRUE;
		}
		else
		{
			if ( ReadID3v2( nIndex, hFile ) ) return TRUE;
			if ( ReadAPE( nIndex, hFile, oMD5, true ) ) return TRUE;
		}
		if ( ReadID3v1( nIndex, hFile ) ) return TRUE;
		if ( ReadMP3Frames( nIndex, hFile ) ) return TRUE;
		return CLibraryBuilder::SubmitCorrupted( nIndex );
	}
	else if ( strType == _T(".exe") || strType == _T(".dll") )
	{
		if ( ! m_bEnableEXE ) return FALSE;
		return ReadVersion( nIndex, strPath );
	}
	else if ( strType == _T(".msi") )
	{
		if ( ! m_bEnableMSI ) return FALSE;
		return ReadMSI( nIndex, strPath );
	}
	else if ( strType == _T(".asf") || strType == _T(".wma") || strType == _T(".wmv") )
	{
		if ( ! m_bEnableASF ) return FALSE;
		return ReadASF( nIndex, hFile );
	}
	else if ( strType == _T(".avi") )
	{
		if ( ! m_bEnableAVI ) return FALSE;
		return ReadAVI( nIndex, hFile );
	}
	else if ( strType == _T(".mpg") || strType == _T(".mpeg") )
	{
		if ( ! m_bEnableASF ) return FALSE;
		return ReadMPEG( nIndex, hFile );
	}
	else if ( strType == _T(".ogg") )
	{
		if ( ! m_bEnableOGG ) return FALSE;
        return ReadOGG( nIndex, hFile );
	}
	else if ( strType == _T(".ape") || strType == _T(".mac") || strType == _T(".apl") )
	{
		if ( ! m_bEnableAPE ) return FALSE;
		return ReadAPE( nIndex, hFile, oMD5 );
	}
	else if ( strType == _T(".mpc") || strType == _T(".mpp") || strType == _T(".mp+") )
	{
		if ( ! m_bEnableMPC ) return FALSE;
		if ( Settings.Library.PreferAPETags )
		{
			if ( ReadMPC( nIndex, hFile, oMD5 ) ) return TRUE;
			if ( ReadID3v2( nIndex, hFile ) ) return TRUE;
		}
		else
		{
			if ( ReadID3v2( nIndex, hFile ) ) return TRUE;
			if ( ReadMPC( nIndex, hFile, oMD5 ) ) return TRUE;
		}
		return ReadID3v1( nIndex, hFile );
	}
	else if ( strType == _T(".jpg") || strType == _T(".jpeg") )
	{
		if ( ! m_bEnableImage ) return FALSE;
		return ReadJPEG( nIndex, hFile );
	}
	else if ( strType == _T(".gif") )
	{
		if ( ! m_bEnableImage ) return FALSE;
		return ReadGIF( nIndex, hFile );
	}
	else if ( strType == _T(".png") )
	{
		if ( ! m_bEnableImage ) return FALSE;
		return ReadPNG( nIndex, hFile );
	}
	else if ( strType == _T(".bmp") )
	{
		if ( ! m_bEnableImage ) return FALSE;
		return ReadBMP( nIndex, hFile );
	}
	else if ( strType == _T(".pdf") )
	{
		if ( ! m_bEnablePDF ) return FALSE;
		return ReadPDF( nIndex, hFile, strPath );
	}
	else if ( strType == _T(".co") || strType == _T(".collection") )
	{
		return ReadCollection( nIndex, hFile, oSHA1 );
	}
	else if ( strType == _T(".chm") )
	{
		if ( ! m_bEnableCHM ) return FALSE;
		return ReadCHM( nIndex, hFile, strPath );
	}
	return FALSE;
}

//////////////////////////////////////////////////////////////////////
// CLibraryBuilderInternals ID3v1 (threaded)

BOOL CLibraryBuilderInternals::ReadID3v1(DWORD nIndex, HANDLE hFile, CXMLElement* pXML)
{
	if ( GetFileSize( hFile, NULL ) < 128 ) return FALSE;
	
	ID3V1 pInfo;
	DWORD nRead;

	SetFilePointer( hFile, -128, NULL, FILE_END );
	ReadFile( hFile, &pInfo, sizeof(pInfo), &nRead, NULL );
	
	if ( nRead != sizeof(pInfo) ) return FALSE;
	if ( strncmp( pInfo.szTag, ID3V1_TAG, 3 ) ) return FALSE;
	
	BOOL bIsMP3 = ( pXML == NULL );
	if ( bIsMP3 ) pXML = new CXMLElement( NULL, _T("audio") );
	
	CopyID3v1Field( pXML, _T("title"), pInfo.szSongname, 30 );
	CopyID3v1Field( pXML, _T("artist"), pInfo.szArtist, 30 );
	CopyID3v1Field( pXML, _T("album"), pInfo.szAlbum, 30 );
	CopyID3v1Field( pXML, _T("year"), pInfo.szYear, 4 );
	
	if ( pInfo.nGenre < ID3_GENRES )
	{
		pXML->AddAttribute( _T("genre"), pszID3Genre[ pInfo.nGenre ] );
	}
	
	if ( pInfo.szComment[28] == 0 && pInfo.szComment[29] > 0 )
	{
		CString strTrack;
		strTrack.Format( _T("%i"), (int)pInfo.szComment[29] );
		pXML->AddAttribute( _T("track"), strTrack );
		CopyID3v1Field( pXML, _T("description"), pInfo.szComment, 28 );
	}
	else
	{
		CopyID3v1Field( pXML, _T("description"), pInfo.szComment, 30 );
	}
	
	SetFilePointer( hFile, 0, NULL, FILE_BEGIN );
	
	int nAttributeCount = pXML->GetAttributeCount();
	if ( bIsMP3 )
	{
		ScanMP3Frame( pXML, hFile, sizeof(pInfo) );
		nAttributeCount = CLibraryBuilder::SubmitMetadata( nIndex, CSchema::uriAudio, pXML );
	}
	
	return nAttributeCount > 0;
}

BOOL CLibraryBuilderInternals::CopyID3v1Field(CXMLElement* pXML, LPCTSTR pszAttribute, LPCSTR pszValue, int nLength)
{
	CString strValue;
	int nWide = MultiByteToWideChar( CP_ACP, 0, pszValue, nLength, NULL, 0 );
    LPWSTR pszOutput = strValue.GetBuffer( nWide + 1 );
	MultiByteToWideChar( CP_ACP, 0, pszValue, nLength, pszOutput, nWide );
	pszOutput[ nWide ] = 0;
	strValue.ReleaseBuffer();
	
	strValue.Trim();
	strValue.Replace( L"\r\n", L"; " ); // Windows style replacement
	strValue.Replace( L"\n", L"; " ); // Unix style replacement
	strValue.Replace( L"\r", L"; " ); // Mac style replacement
	if ( strValue.IsEmpty() ) return FALSE;
	
	pXML->AddAttribute( pszAttribute, strValue );
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CLibraryBuilderInternals ID3v2 (threaded)

BOOL CLibraryBuilderInternals::ReadID3v2(DWORD nIndex, HANDLE hFile)
{
	ID3V2_HEADER pHeader;
	DWORD nRead;
	
	SetFilePointer( hFile, 0, NULL, FILE_BEGIN );
	ReadFile( hFile, &pHeader, sizeof(pHeader), &nRead, NULL );
	if ( nRead != sizeof(pHeader) ) return FALSE;
	
	if ( strncmp( pHeader.szTag, ID3V2_TAG, 3 ) ) return FALSE;
	if ( pHeader.nMajorVersion < 2 || pHeader.nMajorVersion > 4 ) return FALSE;
	if ( pHeader.nFlags & ~ID3V2_KNOWNMASK ) return FALSE;
	if ( pHeader.nFlags & ID3V2_UNSYNCHRONISED ) return FALSE;
	
	DWORD nBuffer = swapEndianess( pHeader.nSize );
	ID3_DESYNC_SIZE( nBuffer );
	
	if ( nBuffer > 1024 * 1024 * 2 ) return FALSE;
	
	BYTE* pBuffer	= new BYTE[ nBuffer ];
	BYTE* pRelease	= pBuffer;
	
	ReadFile( hFile, pBuffer, nBuffer, &nRead, NULL );
	if ( nRead != nBuffer )
	{
		delete [] pRelease;
		return FALSE;
	}
	
	if ( ( pHeader.nFlags & ID3V2_EXTENDEDHEADER ) && pHeader.nMajorVersion == 3 )
	{
		if ( nBuffer < sizeof(ID3V2_EXTENDED_HEADER_1) )
		{
			delete [] pRelease;
			return FALSE;
		}
		
		ID3V2_EXTENDED_HEADER_1* pExtended = (ID3V2_EXTENDED_HEADER_1*)pBuffer;
		pBuffer += sizeof(ID3V2_EXTENDED_HEADER_1);
		nBuffer -= sizeof(ID3V2_EXTENDED_HEADER_1);
		
		pExtended->nSize = swapEndianess( pExtended->nSize );
		
		if ( nBuffer < pExtended->nSize )
		{
			delete [] pRelease;
			return FALSE;
		}
		
		pBuffer += pExtended->nSize;
		nBuffer -= pExtended->nSize;
	}
	else if ( ( pHeader.nFlags & ID3V2_EXTENDEDHEADER ) && pHeader.nMajorVersion == 4 )
	{
		if ( nBuffer < sizeof(ID3V2_EXTENDED_HEADER_2) )
		{
			delete [] pRelease;
			return FALSE;
		}
		
		ID3V2_EXTENDED_HEADER_2* pExtended = (ID3V2_EXTENDED_HEADER_2*)pBuffer;
		pBuffer += sizeof(ID3V2_EXTENDED_HEADER_2);
		nBuffer -= sizeof(ID3V2_EXTENDED_HEADER_2);
		
		pExtended->nSize = swapEndianess( pExtended->nSize );
		ID3_DESYNC_SIZE( pExtended->nSize );
		pExtended->nSize -= 6;
		
		if ( nBuffer < pExtended->nSize )
		{
			delete [] pRelease;
			return FALSE;
		}
		
		pBuffer += pExtended->nSize;
		nBuffer -= pExtended->nSize;
	}
	
	CXMLElement* pXML = new CXMLElement( NULL, _T("audio") );
	BOOL bBugInFrameSize = FALSE;

	while ( TRUE )
	{
		DWORD nFrameSize = 0;
		CHAR szFrameTag[5];
		
		if ( pHeader.nMajorVersion > 2 )
		{
			ID3V2_FRAME* pFrame = (ID3V2_FRAME*)pBuffer;
			
			if ( nBuffer < sizeof(*pFrame) ) break;
			pBuffer += sizeof(*pFrame);
			nBuffer -= sizeof(*pFrame);
			
			szFrameTag[0] = pFrame->szID[0];
			szFrameTag[1] = pFrame->szID[1];
			szFrameTag[2] = pFrame->szID[2];
			szFrameTag[3] = pFrame->szID[3];
			szFrameTag[4] = 0;
			
			nFrameSize = swapEndianess( pFrame->nSize );
//			DWORD nOldFramesize = nFrameSize;

			if ( pHeader.nMajorVersion >= 4 && ! bBugInFrameSize )
			{
				ID3_DESYNC_SIZE( nFrameSize );
				if ( nBuffer < nFrameSize ) break;
				// iTunes uses old style of size for v.2.4 when converting.
				// TODO: Add a code here to find the correct frame size?
				// Report and solution: http://www.sacredchao.net/quodlibet/ticket/180
			}
			if ( pFrame->nFlags2 & ~ID3V2_KNOWNFRAME ) szFrameTag[0] = 0;
		}
		else
		{
			ID3V2_FRAME_2* pFrame = (ID3V2_FRAME_2*)pBuffer;
			
			if ( nBuffer < sizeof(*pFrame) ) break;
			pBuffer += sizeof(*pFrame);
			nBuffer -= sizeof(*pFrame);
			
			szFrameTag[0] = pFrame->szID[0];
			szFrameTag[1] = pFrame->szID[1];
			szFrameTag[2] = pFrame->szID[2];
			szFrameTag[3] = szFrameTag[4] = 0;
			nFrameSize = ( pFrame->nSize[0] << 16 ) | ( pFrame->nSize[1] << 8 ) | pFrame->nSize[2];
		}
		
		if ( nBuffer < nFrameSize || ! szFrameTag[0] ) break;
		
		if ( strcmp( szFrameTag, "TIT2" ) == 0 || strcmp( szFrameTag, "TT2" ) == 0)
		{
			CopyID3v2Field( pXML, _T("title"), pBuffer, nFrameSize );
		}
		else if ( strcmp( szFrameTag, "TPE1" ) == 0 || strcmp( szFrameTag, "TP1" ) == 0 || strcmp( szFrameTag, "TPE2" ) == 0 || strcmp( szFrameTag, "TP2" ) == 0 )
		{
			CopyID3v2Field( pXML, _T("artist"), pBuffer, nFrameSize );
		}
		else if ( strcmp( szFrameTag, "TOPE" ) == 0 || strcmp( szFrameTag, "TOA" ) == 0 )
		{
			CopyID3v2Field( pXML, _T("origArtist"), pBuffer, nFrameSize );
		}
		else if ( strcmp( szFrameTag, "TALB" ) == 0 || strcmp( szFrameTag, "TAL" ) == 0 )
		{
			CopyID3v2Field( pXML, _T("album"), pBuffer, nFrameSize );
		}
		else if ( strcmp( szFrameTag, "TOAL" ) == 0 || strcmp( szFrameTag, "TOT" ) == 0 )
		{
			CopyID3v2Field( pXML, _T("origAlbum"), pBuffer, nFrameSize );
		}
		else if ( strcmp( szFrameTag, "TRCK" ) == 0 || strcmp( szFrameTag, "TRK" ) == 0 )
		{
			CopyID3v2Field( pXML, _T("track"), pBuffer, nFrameSize );
		}
		else if ( pHeader.nMajorVersion < 4 && 
			( strcmp( szFrameTag, "TYER" ) == 0 || strcmp( szFrameTag, "TYE" ) == 0 ) )
		{
			CopyID3v2Field( pXML, _T("year"), pBuffer, nFrameSize );
		}
		else if ( strcmp( szFrameTag, "COMM" ) == 0 || strcmp( szFrameTag, "COM" ) == 0 )
		{
			if ( CopyID3v2Field( pXML, _T("description"), pBuffer, nFrameSize, TRUE ) )
			{
				if ( CXMLAttribute* pDescr = pXML->GetAttribute( _T("description") ) )
				{
					CString strDescr = pDescr->GetValue();
					
					// Remove iTune crap
					if ( strDescr.GetLength() && _tcsncmp( strDescr, L"iTunNORM", 8 ) == 0 )
						pXML->RemoveAttribute( pDescr );
				}
			}
		}
		else if ( strcmp( szFrameTag, "TLEN" ) == 0 || strcmp( szFrameTag, "TLE" ) == 0 )
		{
			if ( CopyID3v2Field( pXML, _T("seconds"), pBuffer, nFrameSize ) )
			{
				CString strMS = pXML->GetAttributeValue( _T("seconds"), _T("0") );
				int nMS;
				_stscanf( strMS, _T("%lu"), &nMS );
				strMS.Format( _T("%lu"), nMS / 1000 );
				pXML->AddAttribute( _T("seconds"), strMS );
			}
		}
		else if ( strcmp( szFrameTag, "TCOP" ) == 0 || strcmp( szFrameTag, "TCR" ) == 0 )
		{
			CopyID3v2Field( pXML, _T("copyright"), pBuffer, nFrameSize );
		}
		else if ( strcmp( szFrameTag, "TCON" ) == 0 || strcmp( szFrameTag, "TCO" ) == 0 )
		{
			if ( CopyID3v2Field( pXML, _T("genre"), pBuffer, nFrameSize ) )
			{
				CString strGenre = pXML->GetAttributeValue( _T("genre"), _T("") );
				
				while ( TRUE )
				{
					int nPos1 = strGenre.Find( '(' );
					if ( nPos1 < 0 ) break;
					int nPos2 = strGenre.Find( ')' );
					if ( nPos2 <= nPos1 ) break;
					
					CString strValue = strGenre.Mid( nPos1 + 1, nPos2 - nPos1 - 1 );
					int nGenre = 0;
					
					if ( strValue.CompareNoCase( _T("RX") ) == 0 )
					{
						strValue = _T("Remix");
					}
					else if ( strValue.CompareNoCase( _T("CR") ) == 0 )
					{
						strValue = _T("Cover");
					}
					else if ( _stscanf( strValue, _T("%i"), &nGenre ) == 1 && nGenre < ID3_GENRES )
					{
						if ( _tcsistr( strGenre, pszID3Genre[ nGenre ] ) == NULL )
						{
							strValue = pszID3Genre[ nGenre ];
						}
						else
						{
							strValue.Empty();
						}
					}
					else
					{
						strValue = _T("[") + strValue + _T("]");
					}
					
					strGenre = strGenre.Left( nPos1 ) + strValue + strGenre.Mid( nPos2 + 1 );
				}
				
				Replace( strGenre, _T("["), _T("(") );
				Replace( strGenre, _T("]"), _T(")") );
				
				pXML->AddAttribute( _T("genre"), strGenre );
			}
		}
		else if ( strcmp( szFrameTag, "TENC" ) == 0 || strcmp( szFrameTag, "TEN" ) == 0 )
		{
			CopyID3v2Field( pXML, _T("encodedby"), pBuffer, nFrameSize );
		}
		else if ( strcmp( szFrameTag, "TSSE" ) == 0 || strcmp( szFrameTag, "TSS" ) == 0 )
		{
			CopyID3v2Field( pXML, _T("encodedby"), pBuffer, nFrameSize );
		}
		else if ( strcmp( szFrameTag, "TCOM" ) == 0 || strcmp( szFrameTag, "TCM" ) == 0 )
		{
			CopyID3v2Field( pXML, _T("composer"), pBuffer, nFrameSize );
		}
		else if ( strcmp( szFrameTag, "WXXX" ) == 0 || strcmp( szFrameTag, "WXX" ) == 0 )
		{
			CopyID3v2Field( pXML, _T("link"), pBuffer, nFrameSize );
		}
		else if ( pHeader.nMajorVersion == 4 && strcmp( szFrameTag, "TDRC" ) == 0 )
		{
			BYTE* pScan = pBuffer;
			DWORD nLength = nFrameSize;
			for ( ; *pScan != '-' && nLength > 0 ; nLength-- ) pScan++;
			nLength = nFrameSize - nLength;
			BYTE* pszYear = new BYTE[ nLength + 1 ];
			memcpy( pszYear, pBuffer, nLength );
			CopyID3v2Field( pXML, _T("year"), pszYear, nLength );
			delete [] pszYear;
		}
		else if ( strcmp( szFrameTag, "TPUB" ) == 0 )
		{
			CopyID3v2Field( pXML, _T("publisher"), pBuffer, nFrameSize );
		}
		else if ( strcmp( szFrameTag, "TORY" ) == 0 )
		{
			CopyID3v2Field( pXML, _T("origYear"), pBuffer, nFrameSize );
		}
		// MusicBrainz.org stuff goes here
		else if ( strcmp( szFrameTag, "TXXX" ) == 0 )
		{
			CopyID3v2Field( pXML, L"", pBuffer, nFrameSize );
		}
/*		else
		{
			CopyID3v2Field( pXML, _T("temp"), pBuffer, nFrameSize );
		}
*/
		pBuffer += nFrameSize;
		nBuffer -= nFrameSize;
	}
	
	delete [] pRelease;
	
	ScanMP3Frame( pXML, hFile, 0 );

	return CLibraryBuilder::SubmitMetadata( nIndex, CSchema::uriAudio, pXML ) > 0;
}

BOOL CLibraryBuilderInternals::CopyID3v2Field(CXMLElement* pXML, LPCTSTR pszAttribute, BYTE* pBuffer, DWORD nLength, BOOL bSkipLanguage)
{
	CString strResult, strValue;
	
	BYTE nEncoding = *pBuffer++;
	nLength--;
	
	if ( bSkipLanguage )
	{
		if ( nLength < 3 ) return FALSE;
		pBuffer += 3;
		nLength -= 3;
		if ( nLength > 0 && pBuffer[ 0 ] == 0 )
		{
			pBuffer += 1;
			nLength -= 1;
		}
	}
	
	DWORD nOffset = 0;

	while ( nOffset < nLength )
	{
		if ( nEncoding == 0 )
		{
			LPTSTR pszOutput = strValue.GetBuffer( nLength - nOffset + 1 );

			DWORD nOut = 0, nChar = 0;
			for ( ; nChar < nLength - nOffset ; nChar++, nOut++ )
			{
				pszOutput[ nOut ] = (TCHAR)pBuffer[ nOffset + nChar ];
				if ( pszOutput[ nOut ] == 0 )
				{
					nOffset += nOut + 1;
					break;
				}
			}
			strValue.ReleaseBuffer( nOut );
			if ( nChar == nLength - nOffset )
				nOffset += nLength - nOffset;
		}
		else if ( nEncoding == 1 && ( ( nLength - nOffset ) & 1 ) == 0 && nLength - nOffset >= 2 )
		{
			DWORD nNewLength = ( nLength - nOffset - 2 ) / 2;
			LPTSTR pszOutput = strValue.GetBuffer( nNewLength + 1 );

			if ( pBuffer[0] == 0xFF && pBuffer[1] == 0xFE )
			{
				pBuffer += 2;
				DWORD nOut = 0, nChar = 0;
				for ( ; nChar < nNewLength ; nChar++, nOut++ )
				{
					pszOutput[ nOut ] = (TCHAR)pBuffer[ nOffset + nChar*2+0 ] | ( (TCHAR)pBuffer[ nOffset + nChar*2+1 ] << 8 );
					if ( pszOutput[ nOut ] == 0 ) 
					{
						nOffset += ( nOut + 1 ) * 2;
						break;
					}
				}
				strValue.ReleaseBuffer( nOut );
				pBuffer -= 2;
				if ( nChar == nNewLength )
					nOffset += nLength - nOffset;
			}
			else if ( pBuffer[0] == 0xFE && pBuffer[1] == 0xFF )
			{
				pBuffer += 2;
				DWORD nOut = 0, nChar = 0;
				for ( ; nChar < nLength - nOffset ; nChar++, nOut++ )
				{
					pszOutput[ nOut ] = (TCHAR)pBuffer[ nOffset + nChar*2+1 ] | ( (TCHAR)pBuffer[ nOffset + nChar*2+0 ] << 8 );
					if ( pszOutput[ nOut ] == 0 )
					{
						nOffset += ( nOut + 1 ) * 2;
						break;
					}
				}
				strValue.ReleaseBuffer( nOut );
				pBuffer -= 2;
				if ( nChar == nLength - nOffset )
					nOffset += nLength - nOffset;
			}
			else
			{
				strValue.ReleaseBuffer( 0 );
				return FALSE;
			}
		}
		else if ( nEncoding == 2 && ( ( nLength - nOffset ) & 1 ) == 0 )
		{
			DWORD nNewLength = ( nLength - nOffset ) / 2;
			LPTSTR pszOutput = strValue.GetBuffer( nNewLength + 1 );

			DWORD nOut = 0, nChar = 0;
			for ( ; nChar < nNewLength ; nChar++, nOut++ )
			{
				pszOutput[ nOut ] = (TCHAR)pBuffer[ nOffset + nChar*2+1 ] | ( (TCHAR)pBuffer[ nOffset + nChar*2+0 ] << 8 );
				if ( pszOutput[ nOut ] == 0 ) 
				{
					nOffset += ( nOut + 1 ) * 2;
					break;
				}
			}
			if ( nChar == nNewLength )
				nOffset += nLength - nOffset;

			strValue.ReleaseBuffer( nOut );
		}
		else if ( nEncoding == 3 )
		{
			int nWide = MultiByteToWideChar( CP_UTF8, 0, (LPCSTR)pBuffer + nOffset, nLength - nOffset, NULL, 0 );
			LPTSTR pszOutput = strValue.GetBuffer( nWide + 1 );
			MultiByteToWideChar( CP_UTF8, 0, (LPCSTR)pBuffer + nOffset, nLength - nOffset, pszOutput, nWide );
			pszOutput[ nWide ] = 0;
			strValue.ReleaseBuffer();
			nOffset += (DWORD)strlen( (LPCSTR)pBuffer + nOffset ) + 1;
		}

		strValue.Trim();
		strValue.Replace( L"\r\n", L"; " ); // Windows style replacement
		strValue.Replace( L"\n", L"; " ); // Unix style replacement
		strValue.Replace( L"\r", L"; " ); // Mac style replacement

		if ( strResult.GetLength() == 0 && ( strValue.GetLength() == 0 || _tcslen( strValue ) == 0 ) ) 
			return FALSE;
		else if ( strResult.GetLength() && strValue.GetLength() )
		{
			strResult += '/';
			strResult.Append( strValue );
		}
		else if ( strValue.GetLength() )
		{
			strResult = strValue;
		}
		else
			break;
	}
	
	if ( !*pszAttribute )
	{
		int nSlash = strResult.Find( '/' );
		if ( nSlash > 0 )
		{
			strValue = strResult.Mid( nSlash + 1 );
			if ( _tcsnicmp( strResult, L"musicbrainz ", 12 ) == 0 )
			{
				CString strField = strResult.Mid( 12, nSlash - 12 );
				if ( strField.CompareNoCase( L"Artist Id" ) == 0 )
					pXML->AddAttribute( L"mbartistid", strValue );
				else if ( strField.CompareNoCase( L"Album Id" ) == 0 )
					pXML->AddAttribute( L"mbalbumid", strValue );
				else if ( strField.CompareNoCase( L"Album Type" ) == 0 )
					pXML->AddAttribute( L"type", strValue );
				else if ( strField.CompareNoCase( L"Album Status" ) == 0 )
					pXML->AddAttribute( L"albumStatus", strValue );
				else if ( strField.CompareNoCase( L"Album Artist Id" ) == 0 )
					pXML->AddAttribute( L"mbalbumartistid", strValue );

				// "Album Artist", "Album Artist Sortname", "Album Release Country", "Non-Album"
				// ToDo: find field names for mbtrmid, mbuniquefileid and cddb
				return TRUE;
			}
			else if ( _tcsnicmp( strResult, L"musicip ", 8 ) == 0 )
			{
				CString strField = strResult.Mid( 8, nSlash - 8 );
				if ( strField.CompareNoCase( L"PUID" ) == 0 )
					pXML->AddAttribute( L"mbpuid", strValue );

				return TRUE;
			}
		}
	}

	pXML->AddAttribute( pszAttribute, strResult );
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CLibraryBuilderInternals MP3 scan (threaded)

BOOL CLibraryBuilderInternals::ReadMP3Frames(DWORD nIndex, HANDLE hFile)
{
	SetFilePointer( hFile, 0, NULL, FILE_BEGIN );
	
	CXMLElement* pXML = new CXMLElement( NULL, _T("audio") );
	
	if ( ScanMP3Frame( pXML, hFile, 0 ) )
	{
		return CLibraryBuilder::SubmitMetadata( nIndex, CSchema::uriAudio, pXML ) > 0;
	}
	else
	{
		delete pXML;
		return FALSE;
	}
}

//
// Refer to this doc: http://www.mp3-tech.org/programmer/frame_header.html
//
BOOL CLibraryBuilderInternals::ScanMP3Frame(CXMLElement* pXML, HANDLE hFile, DWORD nIgnore)
{
	// Bitrate index
	static DWORD nBitrateTable[16][5] =
	{
		// L1 - Layer I
		// L2 - Layer II
		// L3 - Layer III
		// V1 - MPEG Version 1
		// V2 - MPEG Version 2 and Version 2.5

		// Row data:
		// V1,L1	V1,L2	V1,L3  	V2,L1	V2, L2 & L3
		// The first row with zeros is for "free" bitrate (the constant bitrate not higher than value)
		{ 0, 0, 0, 0, 0 },				{ 32, 32, 32, 32, 8 },		{ 64, 48, 40, 48, 16 },
		{ 96, 56, 48, 56, 24 },			{ 128, 64, 56, 64, 32 },	{ 160, 80, 64, 80, 40 },
		{ 192, 96, 80, 96, 48 },		{ 224, 112, 96, 112, 56 },	{ 256, 128, 112, 128, 64 },
		{ 288, 160, 128, 144, 80 },		{ 320, 192, 160, 160, 96 },	{ 352, 224, 192, 176, 112 },
		{ 384, 256, 224, 192, 128 },	{ 416, 320, 256, 224, 144 },{ 448, 384, 320, 256, 160 },
		{ 0, 0, 0, 0, 0 }
		// The last row with zeros is for "bad" bitrate (no value)
	};

	// Sampling rate frequency index
	static DWORD nFrequencyTable[4][4] =
	{
		// Row data:
		// MPEG1	?	MPEG2  	MPEG2.5
		{ 11025, 0, 22050, 44100 },
		{ 12000, 0,  24000, 48000 },
		{ 8000, 0, 16000, 32000 },
		{ 0, 0, 0, 0 }
	};

	static int nChannelTable[4]		= { 2, 2, 2, 1 };
	static CString strSoundType[4]	= { "Stereo", "Joint Stereo", "Dual Channel", "Single Channel" };

	BYTE nLayer					= 0;
	BOOL bVariable				= FALSE;
	__int64 nTotalBitrate		= 0;
	DWORD nBaseBitrate			= 0;
	DWORD nBaseFrequency		= 0;
	int nBaseChannel			= 0;
	CString strBaseSoundType;
	DWORD nFrameCount			= 0;
	DWORD nFrameSize			= 0;
	DWORD nHeader				= 0;

	DWORD nRead;
	ReadFile( hFile, &nHeader, 4, &nRead, NULL );
	if ( nRead != 4 ) return FALSE;
	nHeader = swapEndianess( nHeader );

	for ( DWORD nSeek = 0 ; bVariable || ( nFrameCount < 16 && nSeek < 4096 * 2  ) ; nSeek++ )
	{
		DWORD nTime = GetTickCount();
		
		// "frame sync"
		// First 11 bits must have bit 1 for MPEG 2.5 extension
		// For other versions--first 12 bits

		if ( ( nHeader & 0xFFE00000 ) == 0xFFE00000 )
		{
			// Version: MPEG Audio version ID
			// 0: MPEG Version 2.5 (later extension of MPEG 2)
			// 1: reserved
			// 2: MPEG Version 2 (ISO/IEC 13818-3)
			// 3: MPEG Version 1 (ISO/IEC 11172-3)

			// We are taking 2 bits at position 20-21 (or 19-20 counting from 0)
			// hex 0x00180000 = binary 110000000000000000000
			BYTE nVersion	= (BYTE)( ( nHeader & 0x00180000 ) >> 19 );
			// Layer description:
			// 0: reserved
			// 1: L3
			// 2: L2
			// 3: L1
			nLayer			= (BYTE)( ( nHeader & 0x00060000 ) >> 17 ); // 1100000000000000000
			BYTE nBitIndex	= (BYTE)( ( nHeader & 0x0000F000 ) >> 12 ); // 1111000000000000
			BYTE nFreqIndex	= (BYTE)( ( nHeader & 0x00000C00 ) >> 10 ); // 110000000000
			BYTE nChannels	= (BYTE)( ( nHeader & 0x000000C0 ) >> 6 );  // 11000000
			BOOL bPadding	= (BOOL)( nHeader & 0x0200 ) ? TRUE : FALSE;// 1000000000
			// Is audio copyrighted?
			BOOL bCopyRight = (BOOL)( ( nHeader & 0x8 ) >> 3 ) ? TRUE: FALSE; // 1000
			UNUSED_ALWAYS( bCopyRight );
			
			int nBitColumn = 0;
			
			if ( nVersion == 3 )
			{
				if ( nLayer == 3 ) nBitColumn = 0;
				else if ( nLayer == 2 ) nBitColumn = 1;
				else if ( nLayer == 1 ) nBitColumn = 2;
			}
			else
			{
				if ( nLayer == 3 ) nBitColumn = 3;
				else nBitColumn = 4;
			}
			
			DWORD nBitrate		= nBitrateTable[ nBitIndex ][ nBitColumn ] * 1000;
			DWORD nFrequency	= nFrequencyTable[ nFreqIndex ][ nVersion ];
			
			if ( ! nFrequency ) return FALSE;
			
			if ( nBaseBitrate )
			{
				if ( nBaseBitrate != nBitrate ) bVariable = TRUE;
			}
			else
			{
				nBaseBitrate	= nBitrate;
				nBaseFrequency	= nFrequency;
			}

			nBaseChannel = nChannelTable[nChannels];
			strBaseSoundType = strSoundType[nChannels];

			nFrameSize = ( nLayer == 3 ) ? ( 12 * nBitrate / nFrequency + bPadding ) * 4
				: ( 144 * nBitrate / nFrequency + bPadding );
			
			if ( ! nFrameSize ) return FALSE;
			
			// Skip frame when it has reserved layer
			if ( nLayer )
			{
				nTotalBitrate += nBitrate / 1000;
				nFrameCount++;
			}
			else if ( nFrameCount == 0 ) // reset base values if it was the first frame
			{
				nBaseBitrate = nBaseFrequency = 0;
			}
			
			SetFilePointer( hFile, nFrameSize - 4, NULL, FILE_CURRENT );
			ReadFile( hFile, &nHeader, 4, &nRead, NULL );
			if ( nRead != 4 ) break;
			nHeader = swapEndianess( nHeader );
		}
		else
		{
			nHeader <<= 8;
			ReadFile( hFile, &nHeader, 1, &nRead, NULL );
			if ( nRead != 1 ) break;
		}

		m_nSleep = ( GetTickCount() - nTime ) * 3;
		if ( m_nSleep > 0 ) Sleep( m_nSleep );
		if ( ! LibraryBuilder.IsAlive() ) 
			return FALSE;
	}
	
	if ( nFrameCount < 16 || ! nFrameSize ) return FALSE;
	
	if ( bVariable )
	{
		nBaseBitrate = (DWORD)( nTotalBitrate / nFrameCount ) * 1000;
	}
	else
	{
		DWORD dwFilePosition	= SetFilePointer( hFile, 0, NULL, FILE_CURRENT );
		DWORD dwFileSize		= GetFileSize( hFile, NULL );
		DWORD dwMusicSize		= dwFileSize - dwFilePosition - nIgnore + 4;
		nFrameCount += ( dwMusicSize / nFrameSize ) - 1;
	}
	
	DWORD nFrameTime	= ( nLayer == 3 ? 384 : 1152 ) * 100000 / nBaseFrequency;
	DWORD nTotalTime	= (DWORD)( (__int64)nFrameCount * (__int64)nFrameTime / 100000 );
	
	CString strValue;
	
	strValue.Format( bVariable ? _T("%lu~") : _T("%lu"), nBaseBitrate / 1000 );
	pXML->AddAttribute( _T("bitrate"), strValue );
	
	strValue.Format( _T("%lu"), nTotalTime );
	pXML->AddAttribute( _T("seconds"), strValue );
	
	strValue.Format( _T("%lu"), nBaseFrequency );
	pXML->AddAttribute( _T("sampleRate"), strValue );

	strValue.Format( _T("%lu"), nBaseChannel );
	pXML->AddAttribute( _T("channels"), strValue );
	
	pXML->AddAttribute( _T("soundType"), strBaseSoundType );
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CLibraryBuilderInternals version information (threaded)

BOOL CLibraryBuilderInternals::ReadVersion(DWORD nIndex, LPCTSTR pszPath)
{
	DWORD dwSize = GetFileVersionInfoSize( (LPTSTR)pszPath, &dwSize );
	if ( dwSize <= 152 ) return FALSE;
	
	BYTE* pBuffer = new BYTE[ dwSize ];
	
	if ( ! GetFileVersionInfo( (LPTSTR)pszPath, NULL, dwSize, pBuffer ) )
	{
		delete [] pBuffer;
		return FALSE;
	}
	
	DWORD nLangId = GetBestLanguageId( pBuffer );
	
	CXMLElement* pXML = new CXMLElement( NULL, _T("application") );
	
	pXML->AddAttribute( _T("os"), _T("Windows") );
	CopyVersionField( pXML, _T("title"), pBuffer, _T("ProductName"), nLangId );
	CopyVersionField( pXML, _T("version"), pBuffer, _T("ProductVersion"), nLangId, TRUE );
	CopyVersionField( pXML, _T("fileDescription"), pBuffer, _T("FileDescription"), nLangId );
	CopyVersionField( pXML, _T("fileVersion"), pBuffer, _T("FileVersion"), nLangId, TRUE );
	CopyVersionField( pXML, _T("originalFileName"), pBuffer, _T("OriginalFilename"), nLangId );
	CopyVersionField( pXML, _T("company"), pBuffer, _T("CompanyName"), nLangId );
	CopyVersionField( pXML, _T("copyright"), pBuffer, _T("LegalCopyright"), nLangId );
	CopyVersionField( pXML, _T("comments"), pBuffer, _T("comments"), nLangId );
	
	delete [] pBuffer;

	return CLibraryBuilder::SubmitMetadata( nIndex, CSchema::uriApplication, pXML );
}

BOOL CLibraryBuilderInternals::CopyVersionField(CXMLElement* pXML, LPCTSTR pszAttribute, BYTE* pBuffer, 
												LPCTSTR pszKey, DWORD nLangId, BOOL bCommaToDot)
{
	CString strValue = GetVersionKey( pBuffer, pszKey, nLangId );

	if ( strValue.IsEmpty() ) return FALSE;
	
	if ( bCommaToDot )
	{
		for ( int nPos = -1 ; ( nPos = strValue.Find( _T(", ") ) ) >= 0 ; )
		{
			strValue = strValue.Left( nPos ) + '.' + strValue.Mid( nPos + 2 );
		}
	}

	pXML->AddAttribute( pszAttribute, strValue );

	return TRUE;
}

CString CLibraryBuilderInternals::GetVersionKey(BYTE* pBuffer, LPCTSTR pszKey, DWORD nLangId)
{
	CString strKey, strValue;

	strKey.Format( L"\\StringFileInfo\\%04x%04x\\", nLangId & 0x0000FFFF, ( nLangId & 0xFFFF0000 ) >> 16 );
	strKey += pszKey;

	BYTE* pValue = NULL;
	DWORD dwSize = 0;

	if ( ! VerQueryValue( pBuffer, (LPTSTR)(LPCTSTR)strKey, (void**)&pValue, (UINT*)&dwSize ) )
		return strValue;
	
	if ( pValue && pValue[1] )
		strValue = (LPCSTR)pValue;
	else
		strValue = (LPCTSTR)pValue;

	return strValue.Trim();
}

DWORD CLibraryBuilderInternals::GetBestLanguageId(LPVOID pBuffer)
{
	DWORD nLangCode = 0;
	UINT nLength = 0;
	LPVOID	pTranslation = NULL;

	VerQueryValue( pBuffer, L"\\VarFileInfo\\Translation", &pTranslation, &nLength );

	if ( pTranslation == NULL ) // No Translation block is available
	{
		VerQueryValue( pBuffer, L"\\StringFileInfo\\", &pTranslation, &nLength );
		if ( pTranslation != NULL )
		{
			WCHAR* pLanguage = (WCHAR*)pTranslation + 3;
			if ( wcslen( pLanguage ) != 8 )
				return 0;
			else
			{
				DWORD nSublang = 0;
				// Read the langid just after StringFileInfo block
				swscanf( pLanguage, L"%4x%4x", &nLangCode, &nSublang );
				nLangCode += ( nSublang << 16 );
				return nLangCode;
			}
		}
		else
			return 0;
	}
	// ToDo: get LANGID of the Shareaza user interface
	if ( !GetLanguageId( pTranslation, nLength, GetUserDefaultLangID(), nLangCode, false ) )
	{
		if ( !GetLanguageId( pTranslation, nLength, GetSystemDefaultLangID(), nLangCode, true ) )
		{
			if ( !GetLanguageId( pTranslation, nLength, MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), nLangCode, true ) )
			{
				if ( !GetLanguageId( pTranslation, nLength, MAKELANGID(LANG_ENGLISH, SUBLANG_NEUTRAL), nLangCode, true ) )
					nLangCode = *(DWORD*)pTranslation; // Use the first one
			}
		}
	}
	return nLangCode;
}

BOOL CLibraryBuilderInternals::GetLanguageId(LPVOID pBuffer, UINT nSize, WORD nLangId, DWORD &nId, bool bOnlyPrimary)
{
	LPWORD pData = NULL;
	for ( pData = (LPWORD)pBuffer ; (LPBYTE)pData < ( (LPBYTE)pBuffer ) + nSize ; pData += 2 )
	{
		if ( *pData == nLangId )
		{
			nId = *(DWORD*)pData;
			return TRUE;
		}
	}

	if ( !bOnlyPrimary )
		return FALSE;

	for ( pData = (LPWORD)pBuffer ; (LPBYTE)pData < ( (LPBYTE)pBuffer ) + nSize ; pData += 2 )
	{
		if ( ( *pData & 0x00FF ) == ( nLangId & 0x00FF ) )
		{
			nId = *(DWORD*)pData;
			return TRUE;
		}
	}

	return FALSE;
}

//////////////////////////////////////////////////////////////////////
// CLibraryBuilderInternals MSI (threaded)

BOOL CLibraryBuilderInternals::ReadMSI(DWORD nIndex, LPCTSTR pszPath)
{
	MSIHANDLE hSummaryInfo;

	int nError = MsiGetSummaryInformation( NULL, pszPath, 0, &hSummaryInfo );

	if ( nError == ERROR_INSTALL_PACKAGE_INVALID ) 
		return CLibraryBuilder::SubmitCorrupted( nIndex );
	else if ( nError != ERROR_SUCCESS )
		return FALSE;

	CXMLElement* pXML = new CXMLElement( NULL, _T("application") );
	
	pXML->AddAttribute( _T("os"), _T("Windows") );

	CString strSubject;
	CString str = GetSummaryField( hSummaryInfo, PID_TITLE );
	if ( str.IsEmpty() || str == _T("Installation Database") )
	{
		str = GetSummaryField( hSummaryInfo, PID_SUBJECT );
	}
	else
	{
		strSubject = GetSummaryField( hSummaryInfo, PID_SUBJECT );
		if ( strSubject != str )
			pXML->AddAttribute( _T("fileDescription"), strSubject );
	}

	pXML->AddAttribute( _T("title"), str );
	pXML->AddAttribute( _T("company"), GetSummaryField( hSummaryInfo, PID_AUTHOR ) );

	str = GetSummaryField( hSummaryInfo, PID_KEYWORDS );
	if ( str.Find( _T("Installer,MSI,Database") ) == -1  )
	{
		pXML->AddAttribute( _T("keywords"), str );
	}

	str = GetSummaryField( hSummaryInfo, PID_COMMENTS );
	if ( str != strSubject )
	{
		pXML->AddAttribute( _T("releaseNotes"), str );
	}
	
	return CLibraryBuilder::SubmitMetadata( nIndex, CSchema::uriApplication, pXML );
}

CString CLibraryBuilderInternals::GetSummaryField(MSIHANDLE hSummaryInfo, UINT nProperty)
{
	CString strValue;
	UINT nPropType = VT_LPSTR;
	DWORD dwSize = 0;

	if ( MsiSummaryInfoGetProperty( hSummaryInfo, nProperty, &nPropType, 
			0, NULL, L"", &dwSize ) == ERROR_MORE_DATA )
	{
		dwSize++;
		LPTSTR pszValue = new TCHAR[ dwSize ];

		if ( MsiSummaryInfoGetProperty( hSummaryInfo, nProperty, &nPropType, 
						0, NULL, pszValue, &dwSize ) == 0 )
			strValue = pszValue;

		delete [] pszValue;
	}

	return strValue;
}

//////////////////////////////////////////////////////////////////////
// CLibraryBuilderInternals JPEG (threaded)

BOOL CLibraryBuilderInternals::ReadJPEG(DWORD nIndex, HANDLE hFile)
{
	DWORD nRead	= 0;
	WORD wMagic	= 0;
	BYTE nByte	= 0;
	
	SetFilePointer( hFile, 0, NULL, FILE_BEGIN );
	ReadFile( hFile, &wMagic, 2, &nRead, NULL );
	if ( nRead != 2 || wMagic != 0xD8FF ) return CLibraryBuilder::SubmitCorrupted( nIndex );
	
	BYTE nBits = 0, nComponents = 0;
	WORD nWidth = 0, nHeight = 0;
	CString strComment;
	
	for ( DWORD nSeek = 512 ; nSeek > 0 ; nSeek-- )
	{
		ReadFile( hFile, &nByte, 1, &nRead, NULL );
		if ( nRead != 1 ) return FALSE;
		if ( nByte != 0xFF ) continue;

		while ( nByte == 0xFF )
		{
			ReadFile( hFile, &nByte, 1, &nRead, NULL );
			if ( nRead != 1 ) return FALSE;
		}
		
		ReadFile( hFile, &wMagic, 2, &nRead, NULL );
		wMagic = ( wMagic >> 8 ) | ( wMagic << 8 );
		if ( nRead != 2 || wMagic < 2 ) return FALSE;

		switch ( nByte )
		{
		case 0xC0: case 0xC1: case 0xC2: case 0xC3: case 0xC5: case 0xC6: case 0xC7:
		case 0xC9: case 0xCA: case 0xCB: case 0xCD: case 0xCE: case 0xCF:
			ReadFile( hFile, &nBits, 1, &nRead, NULL );
			if ( nRead != 1 ) return FALSE;
			ReadFile( hFile, &nHeight, 2, &nRead, NULL );
			if ( nRead != 2 ) return FALSE;
			nHeight = ( nHeight >> 8 ) | ( nHeight << 8 );
			ReadFile( hFile, &nWidth, 2, &nRead, NULL );
			if ( nRead != 2 ) return FALSE;
			nWidth = ( nWidth >> 8 ) | ( nWidth << 8 );
			ReadFile( hFile, &nComponents, 1, &nRead, NULL );
			if ( nRead != 1 ) return FALSE;
			if ( wMagic < 8 ) return FALSE;
			SetFilePointer( hFile, wMagic - 8, NULL, FILE_CURRENT );
			break;
		case 0xFE: case 0xEC:
			if ( wMagic > 2 )
			{
				CBuffer pComment;
				pComment.EnsureBuffer( wMagic - 2 );
				pComment.m_nLength = (DWORD)wMagic - 2;
				ReadFile( hFile, pComment.m_pBuffer, wMagic - 2, &nRead, NULL );
				strComment = pComment.ReadString( nRead );
			}
			break;
		case 0xD9: case 0xDA:
			nSeek = 1;
			break;
		default:
			SetFilePointer( hFile, wMagic - 2, NULL, FILE_CURRENT );
			break;
		}
	}

	if ( nWidth == 0 || nHeight == 0 ) return FALSE;

	strComment.TrimLeft();
	strComment.TrimRight();

	for ( int nChar = 0 ; nChar < strComment.GetLength() ; nChar++ )
	{
		if ( strComment[ nChar ] < 32 ) strComment.SetAt( nChar, '?' );
	}

	CXMLElement* pXML = new CXMLElement( NULL, _T("image") );
	CString strItem;
	
	strItem.Format( _T("%lu"), nWidth );
	pXML->AddAttribute( _T("width"), strItem );
	strItem.Format( _T("%lu"), nHeight );
	pXML->AddAttribute( _T("height"), strItem );
	
	if ( nComponents == 3 ) pXML->AddAttribute( _T("colors"), _T("16.7M") );
	else if ( nComponents == 1 ) pXML->AddAttribute( _T("colors"), _T("Greyscale") );
	
	if ( strComment.GetLength() ) pXML->AddAttribute( _T("description"), strComment );
	
	return CLibraryBuilder::SubmitMetadata( nIndex, CSchema::uriImage, pXML );
}

//////////////////////////////////////////////////////////////////////
// CLibraryBuilderInternals GIF (threaded)

BOOL CLibraryBuilderInternals::ReadGIF(DWORD nIndex, HANDLE hFile)
{
	CHAR szMagic[6];
	DWORD nRead;
	
	SetFilePointer( hFile, 0, NULL, FILE_BEGIN );
	ReadFile( hFile, szMagic, 6, &nRead, NULL );
	
	if ( nRead != 6 || ( strncmp( szMagic, "GIF87a", 6 ) && strncmp( szMagic, "GIF89a", 6 ) ) )
		return CLibraryBuilder::SubmitCorrupted( nIndex );
	
	WORD nWidth, nHeight;
	
	ReadFile( hFile, &nWidth, 2, &nRead, NULL );
	if ( nRead != 2 || nWidth == 0 ) return FALSE;
	ReadFile( hFile, &nHeight, 2, &nRead, NULL );
	if ( nRead != 2 || nHeight == 0 ) return FALSE;
	
	CXMLElement* pXML = new CXMLElement( NULL, _T("image") );
	CString strItem;
	
	strItem.Format( _T("%lu"), nWidth );
	pXML->AddAttribute( _T("width"), strItem );
	strItem.Format( _T("%lu"), nHeight );
	pXML->AddAttribute( _T("height"), strItem );
	
	pXML->AddAttribute( _T("colors"), _T("256") );
	
	return CLibraryBuilder::SubmitMetadata( nIndex, CSchema::uriImage, pXML );
}

//////////////////////////////////////////////////////////////////////
// CLibraryBuilderInternals PNG (threaded)

BOOL CLibraryBuilderInternals::ReadPNG(DWORD nIndex, HANDLE hFile)
{
	BYTE nMagic[8];
	DWORD nRead;
	
	if ( GetFileSize( hFile, NULL ) < 33 ) return CLibraryBuilder::SubmitCorrupted( nIndex );
	SetFilePointer( hFile, 0, NULL, FILE_BEGIN );
	
	ReadFile( hFile, nMagic, 8, &nRead, NULL );
	if ( nRead != 8 ) return CLibraryBuilder::SubmitCorrupted( nIndex );
	if ( nMagic[0] != 137 || nMagic[1] != 80 || nMagic[2] != 78 ) return CLibraryBuilder::SubmitCorrupted( nIndex );
	if ( nMagic[3] != 71 || nMagic[4] != 13 || nMagic[5] != 10 ) return CLibraryBuilder::SubmitCorrupted( nIndex );
	if ( nMagic[6] != 26 || nMagic[7] != 10 ) return CLibraryBuilder::SubmitCorrupted( nIndex );
	
	DWORD nLength, nIHDR;
	
	ReadFile( hFile, &nLength, 4, &nRead, NULL );
	nLength = swapEndianess( nLength );
	if ( nRead != 4 || nLength < 10 ) return FALSE;
	ReadFile( hFile, &nIHDR, 4, &nRead, NULL );
	if ( nRead != 4 || nIHDR != 'RDHI' ) return FALSE;

	DWORD nWidth, nHeight;
	BYTE nBits, nColors;

	ReadFile( hFile, &nWidth, 4, &nRead, NULL );
	nWidth = swapEndianess( nWidth );
	if ( nRead != 4 || nWidth <= 0 || nWidth > 0xFFFF ) return FALSE;
	ReadFile( hFile, &nHeight, 4, &nRead, NULL );
	nHeight = swapEndianess( nHeight );
	if ( nRead != 4 || nHeight <= 0 || nHeight > 0xFFFF ) return FALSE;

	ReadFile( hFile, &nBits, 1, &nRead, NULL );
	if ( nRead != 1 ) return FALSE;
	ReadFile( hFile, &nColors, 1, &nRead, NULL );
	if ( nRead != 1 ) return FALSE;

	CXMLElement* pXML = new CXMLElement( NULL, _T("image") );
	CString strItem;
	
	strItem.Format( _T("%lu"), nWidth );
	pXML->AddAttribute( _T("width"), strItem );
	strItem.Format( _T("%lu"), nHeight );
	pXML->AddAttribute( _T("height"), strItem );

	/*
	if ( nColors == 2 || nColors == 4 )
	{
		pXML->AddAttribute( _T("colors"), _T("Greyscale") );
	}
	else
	*/
	{
		switch ( nBits )
		{
		case 1:
			pXML->AddAttribute( _T("colors"), _T("2") );
			break;
		case 2:
			pXML->AddAttribute( _T("colors"), _T("4") );
			break;
		case 4:
			pXML->AddAttribute( _T("colors"), _T("16") );
			break;
		case 8:
			pXML->AddAttribute( _T("colors"), _T("256") );
			break;
		case 16:
			pXML->AddAttribute( _T("colors"), _T("64K") );
			break;
		}
	}
	
	return CLibraryBuilder::SubmitMetadata( nIndex, CSchema::uriImage, pXML );
}

//////////////////////////////////////////////////////////////////////
// CLibraryBuilderInternals BMP (threaded)

BOOL CLibraryBuilderInternals::ReadBMP(DWORD nIndex, HANDLE hFile)
{
	BITMAPFILEHEADER pBFH;
	BITMAPINFOHEADER pBIH;
	DWORD nRead;
	
	if ( GetFileSize( hFile, NULL ) < sizeof(pBFH) + sizeof(pBIH) ) return CLibraryBuilder::SubmitCorrupted( nIndex );
	
	SetFilePointer( hFile, 0, NULL, FILE_BEGIN );
	ReadFile( hFile, &pBFH, sizeof(pBFH), &nRead, NULL );
	if ( nRead != sizeof(pBFH) || pBFH.bfType != 'MB' ) return CLibraryBuilder::SubmitCorrupted( nIndex );
	
	ReadFile( hFile, &pBIH, sizeof(pBIH), &nRead, NULL );
	if ( nRead != sizeof(pBIH) || pBIH.biSize != sizeof(pBIH) ) return FALSE;
	
	CXMLElement* pXML = new CXMLElement( NULL, _T("image") );
	CString strItem;
	
	strItem.Format( _T("%lu"), pBIH.biWidth );
	pXML->AddAttribute( _T("width"), strItem );
	strItem.Format( _T("%lu"), pBIH.biHeight );
	pXML->AddAttribute( _T("height"), strItem );
	
	switch ( pBIH.biBitCount )
	{
	case 4:
		pXML->AddAttribute( _T("colors"), _T("16") );
		break;
	case 8:
		pXML->AddAttribute( _T("colors"), _T("256") );
		break;
	case 24:
		pXML->AddAttribute( _T("colors"), _T("16.7M") );
		break;
	}

	return CLibraryBuilder::SubmitMetadata( nIndex, CSchema::uriImage, pXML );
}

//////////////////////////////////////////////////////////////////////
// CLibraryBuilderInternals ASF (threaded)

static const CLSID asfHeader1 =
{ 0x75B22630, 0x668E, 0x11CF, { 0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C } };

static const CLSID asfContent1 =
{ 0x75B22633, 0x668E, 0x11CF, { 0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE, 0x6C } };

static const CLSID asfProperties1 =	// ???
{ 0x8CABDCA1, 0xA947, 0x11CF, { 0x8E, 0xE4, 0x00, 0xC0, 0x0C, 0x20, 0x53, 0x65 } };

static const CLSID asfStream1 =
{ 0xB7DC0791, 0xA9B7, 0x11CF, { 0x8E, 0xE6, 0x00, 0xC0, 0x0C, 0x20, 0x53, 0x65 } };

static const CLSID asfVideo1 =
{ 0xBC19EFC0, 0x5B4D, 0x11CF, { 0xA8, 0xFD, 0x00, 0x80, 0x5F, 0x5C, 0x44, 0x2B } };

static const CLSID asfData1 =
{ 0x75b22636, 0x668e, 0x11cf, { 0xa6, 0xd9, 0x00, 0xaa, 0x00, 0x62, 0xce, 0x6c } };

// {D6E229D1-35DA-11d1-9034-00A0C90349BE}
static const CLSID asfHeader2 =
{ 0xD6E229D1, 0x35DA, 0x11d1, { 0x90, 0x34, 0x00, 0xA0, 0xC9, 0x03, 0x49, 0xBE } };

// {D6E229D2-35DA-11d1-9034-00A0C90349BE}
static const CLSID asfData2 =
{ 0xD6E229D2, 0x35DA, 0x11d1, { 0x90, 0x34, 0x00, 0xA0, 0xC9, 0x03, 0x49, 0xBE } };

// {D6E229D0-35DA-11d1-9034-00A0C90349BE}
static const CLSID asfProperties2 =
{ 0xD6E229D0, 0x35DA, 0x11d1, { 0x90, 0x34, 0x00, 0xA0, 0xC9, 0x03, 0x49, 0xBE } };

// {D6E229D4-35DA-11d1-9034-00A0C90349BE}
static const CLSID asfStream2 =
{ 0xD6E229D4, 0x35DA, 0x11d1, { 0x90, 0x34, 0x00, 0xA0, 0xC9, 0x03, 0x49, 0xBE } };

// {D6E229D5-35DA-11d1-9034-00A0C90349BE}
static const CLSID asfContent2 =
{ 0xD6E229D5, 0x35DA, 0x11d1, { 0x90, 0x34, 0x00, 0xA0, 0xC9, 0x03, 0x49, 0xBE } };

// {D6E229E2-35DA-11d1-9034-00A0C90349BE}
static const CLSID asfAudio2 =
{ 0xD6E229E2, 0x35DA, 0x11d1, { 0x90, 0x34, 0x00, 0xA0, 0xC9, 0x03, 0x49, 0xBE } };

// {D6E229E3-35DA-11d1-9034-00A0C90349BE}
static const CLSID asfVideo2 =
{ 0xD6E229E3, 0x35DA, 0x11d1, { 0x90, 0x34, 0x00, 0xA0, 0xC9, 0x03, 0x49, 0xBE } };

// {2211B3FB-BD23-11D2-B4B7-00A0C955FC6E}
static const CLSID asfDRM1 =
{ 0x2211B3FB, 0xBD23, 0x11D2, { 0xB4, 0xB7, 0x00, 0xA0, 0xC9, 0x55, 0xFC, 0x6E } };

// {1EFB1A30-0B62-11D0-A39B-00A0C90348F6}
static const CLSID asfDRM2 =
{ 0x1EFB1A30, 0x0B62, 0x11D0, { 0xA3, 0x9B, 0x00, 0xA0, 0xC9, 0x03, 0x48, 0xF6 } };

BOOL CLibraryBuilderInternals::ReadASF(DWORD nIndex, HANDLE hFile)
{
	QWORD nSize;
	DWORD nRead;
	GUID pGUID;
	
	SetFilePointer( hFile, 0, NULL, FILE_BEGIN );
	ReadFile( hFile, &pGUID, sizeof(pGUID), &nRead, NULL );
	if ( nRead != sizeof(pGUID) || ( pGUID != asfHeader1 && pGUID != asfHeader2 ) )
		return CLibraryBuilder::SubmitCorrupted( nIndex );
	ReadFile( hFile, &nSize, sizeof(nSize), &nRead, NULL );
	if ( nRead != sizeof(nSize) ) return CLibraryBuilder::SubmitCorrupted( nIndex );
	
	if ( pGUID == asfHeader1 ) SetFilePointer( hFile, 6, NULL, FILE_CURRENT );
	
	CString strTitle, strAuthor, strCopyright, strDescription, strRating;
	DWORD nBitrate = 0, nVideoWidth = 0, nVideoHeight = 0;
	QWORD nContentLength = 0;
	BOOL bVideo = FALSE;
	BOOL bDRM = FALSE;
	
	while ( TRUE )
	{
		DWORD dwPosition = SetFilePointer( hFile, 0, NULL, FILE_CURRENT );
		
		ReadFile( hFile, &pGUID, sizeof(pGUID), &nRead, NULL );
		if ( nRead != sizeof(pGUID) ) break;
		ReadFile( hFile, &nSize, sizeof(nSize), &nRead, NULL );
		if ( nRead != sizeof(nSize) || nSize >= 0x80000000 ) break;
		
		if ( pGUID == asfProperties1 )
		{
			SetFilePointer( hFile, 48, NULL, FILE_CURRENT );
			ReadFile( hFile, &nContentLength, sizeof(nContentLength), &nRead, NULL );
			if ( nRead != sizeof(nContentLength) ) return FALSE;
		}
		else if ( pGUID == asfProperties2 )
		{
			SetFilePointer( hFile, 40, NULL, FILE_CURRENT );
			ReadFile( hFile, &nContentLength, sizeof(nContentLength), &nRead, NULL );
			if ( nRead != sizeof(nContentLength) ) return FALSE;
			SetFilePointer( hFile, 8, NULL, FILE_CURRENT );
			ReadFile( hFile, &nBitrate, sizeof(nBitrate), &nRead, NULL );
			if ( nRead != sizeof(nBitrate) ) return FALSE;
		}
		else if ( pGUID == asfStream1 )
		{
			ReadFile( hFile, &pGUID, sizeof(pGUID), &nRead, NULL );
			if ( nRead != sizeof(pGUID) ) return FALSE;
			
			if ( pGUID == asfVideo1 )
			{
				bVideo = TRUE;
				SetFilePointer( hFile, 38, NULL, FILE_CURRENT );
				ReadFile( hFile, &nVideoWidth, sizeof(nVideoWidth), &nRead, NULL );
				if ( nRead != sizeof(nVideoWidth) ) return FALSE;
				ReadFile( hFile, &nVideoHeight, sizeof(nVideoHeight), &nRead, NULL );
				if ( nRead != sizeof(nVideoHeight) ) return FALSE;
			}
		}
		else if ( pGUID == asfStream2 )
		{
			ReadFile( hFile, &pGUID, sizeof(pGUID), &nRead, NULL );
			if ( nRead != sizeof(pGUID) ) return FALSE;

			if ( pGUID == asfVideo2 )
			{
				bVideo = TRUE;
				/*
				SetFilePointer( hFile, 68, NULL, FILE_CURRENT );
				ReadFile( hFile, &nVideoWidth, sizeof(nVideoWidth), &nRead, NULL );
				if ( nRead != sizeof(nVideoWidth) ) return FALSE;
				nVideoHeight = nVideoWidth >> 16;
				nVideoWidth &= 0xFFFF;
				*/
			}
		}
		else if ( pGUID == asfContent1 )
		{
			WORD nStrLen[5];
			ReadFile( hFile, nStrLen, sizeof(nStrLen), &nRead, NULL );
			if ( nRead != sizeof(nStrLen) ) break;
			
			for ( int nStr = 0 ; nStr < 5 ; nStr++ )
			{
				if ( ! nStrLen[ nStr ] || nStrLen[ nStr ] & 1 ) continue;
				WCHAR* pStr = new WCHAR[ nStrLen[ nStr ] / 2 ];
				ReadFile( hFile, pStr, nStrLen[ nStr ], &nRead, NULL );
				if ( nRead != nStrLen[ nStr ] ) return FALSE;
				pStr[ nStrLen[ nStr ] / 2 - 1 ] = 0;
				
				switch ( nStr )
				{
				case 0:
					strTitle = pStr;
					break;
				case 1:
					strAuthor = pStr;
					break;
				case 2:
					strCopyright = pStr;
					break;
				case 3:
					strDescription = pStr;
					break;
				case 4:
					strRating = pStr;
					break;
				}
				
				delete [] pStr;
			}
		}
		else if ( pGUID == asfContent2 )
		{
			WORD nCount;
			ReadFile( hFile, &nCount, sizeof(nCount), &nRead, NULL );
			if ( nRead != sizeof(nCount) ) break;
			
			while ( nCount-- )
			{
				WORD nLanguageID, nStreamID, nNameLen, nValueLen;
				BYTE nFieldType;
				WCHAR* pStr;

				ReadFile( hFile, &nFieldType, sizeof(nFieldType), &nRead, NULL );
				if ( nRead != sizeof(nFieldType) ) return FALSE;
				ReadFile( hFile, &nLanguageID, sizeof(nLanguageID), &nRead, NULL );
				if ( nRead != sizeof(nLanguageID) ) return FALSE;
				ReadFile( hFile, &nStreamID, sizeof(nStreamID), &nRead, NULL );
				if ( nRead != sizeof(nStreamID) ) return FALSE;
				ReadFile( hFile, &nNameLen, sizeof(nNameLen), &nRead, NULL );
				if ( nRead != sizeof(nNameLen) ) return FALSE;
				ReadFile( hFile, &nValueLen, sizeof(nValueLen), &nRead, NULL );
				if ( nRead != sizeof(nValueLen) ) return FALSE;
				
				pStr = new WCHAR[ nNameLen + 1 ];
				ReadFile( hFile, pStr, nNameLen * 2, &nRead, NULL );
				if ( nRead != (DWORD)nNameLen * 2 ) return FALSE;
				pStr[ nNameLen ] = 0;
				delete [] pStr;

				pStr = new WCHAR[ nValueLen + 1 ];
				ReadFile( hFile, pStr, nValueLen * 2, &nRead, NULL );
				if ( nRead != (DWORD)nValueLen * 2 ) return FALSE;
				pStr[ nValueLen ] = 0;

				switch ( nFieldType )
				{
				case 1:
					strAuthor = pStr;
					break;
				case 2: case 20:
					strTitle = pStr;
					break;
				case 3:
					strCopyright = pStr;
					break;
				case 4:
					strDescription = pStr;
					break;
				}

				delete [] pStr;
			}
		}
		else if ( pGUID == asfDRM1 || pGUID == asfDRM2 )
		{
			bDRM = TRUE;
		}
		else if ( pGUID == asfData1 || pGUID == asfData2 )
		{
			break;
		}
		
		SetFilePointer( hFile, dwPosition + (DWORD)nSize, NULL, FILE_BEGIN );
	}
	
	CXMLElement* pXML = new CXMLElement( NULL, bVideo ? _T("video") : _T("audio") );
	CString strItem;
	
	if ( strTitle.GetLength() ) pXML->AddAttribute( _T("title"), strTitle );
	
	if ( strDescription.GetLength() ) pXML->AddAttribute( _T("description"), strDescription );
	
	if ( bDRM )
	{
		pXML->AddAttribute( _T("drm"), _T("true") );
	}
	
	if ( bVideo )
	{
		if ( strAuthor.GetLength() ) pXML->AddAttribute( _T("producer"), strAuthor );

		if ( strRating.GetLength() ) pXML->AddAttribute( _T("rating"), strRating );

		if ( nContentLength > 0 )
		{
			DWORD nSeconds = (DWORD)( nContentLength / 10000000 );
			strItem.Format( _T("%lu.%lu"), nSeconds / 60, ( ( nSeconds % 60 ) * 10 / 60 ) );
			pXML->AddAttribute( _T("minutes"), strItem );
		}

		if ( nVideoWidth > 0 && nVideoHeight > 0 )
		{
			strItem.Format( _T("%lu"), nVideoWidth );
			pXML->AddAttribute( _T("width"), strItem );
			strItem.Format( _T("%lu"), nVideoHeight );
			pXML->AddAttribute( _T("height"), strItem );
		}
	}
	else
	{
		if ( strAuthor.GetLength() ) pXML->AddAttribute( _T("artist"), strAuthor );

		if ( nContentLength > 0 )
		{
			strItem.Format( _T("%lu"), (DWORD)( nContentLength / 10000000 ) );
			pXML->AddAttribute( _T("seconds"), strItem );
		}

		if ( nBitrate > 0 )
		{
			strItem.Format( _T("%lu"), nBitrate / 1000 );
			pXML->AddAttribute( _T("bitrate"), strItem );
		}
	}
	
	pXML->AddAttribute( _T("codec"), _T("WM") );
	
	return CLibraryBuilder::SubmitMetadata( nIndex, bVideo ? CSchema::uriVideo : CSchema::uriAudio, pXML );
}

//////////////////////////////////////////////////////////////////////
// CLibraryBuilderInternals MPEG (threaded)

BOOL CLibraryBuilderInternals::ReadMPEG(DWORD nIndex, HANDLE hFile)
{
	SetFilePointer( hFile, 0, NULL, FILE_BEGIN );
	
	DWORD nHeader = 0;
	
    DWORD nSeek = 8192;
	for ( ; nSeek > 0 ; nSeek--, nHeader <<= 8 )
	{
		DWORD nRead = 0;
		ReadFile( hFile, &nHeader, 1, &nRead, NULL );
		if ( nRead != 1 ) break;
		
		if ( nHeader == 0x000001B3 ) break;
	}
	
	if ( ! nSeek ) return FALSE;
	
	BYTE nBuffer[7];

	ReadFile( hFile, nBuffer, 7, &nHeader, NULL );
	if ( nHeader != 7 ) return FALSE;
	
	CXMLElement* pXML = new CXMLElement( NULL, _T("video") );
	CString strItem;
	
	DWORD nWidth, nHeight;
	nWidth = ( (DWORD)nBuffer[0] << 4 ) | (DWORD)nBuffer[1] >> 4;
	nHeight = ( ( (DWORD)nBuffer[1] & 0x0F ) << 8 ) | (DWORD)nBuffer[2];
	
	strItem.Format( _T("%lu"), nWidth );
	pXML->AddAttribute( _T("width"), strItem );
	strItem.Format( _T("%lu"), nHeight );
	pXML->AddAttribute( _T("height"), strItem );
	pXML->AddAttribute( _T("codec"), _T("MPEG") );
	
	LPCTSTR pszFPS[] = { _T("23.976"), _T("24"), _T("25"), _T("29.97"), _T("30"), _T("50"), _T("59.94"), _T("60") };
	int nFrameIndex = ( nBuffer[3] & 0x0F );
	
	if ( nFrameIndex >= 1 && nFrameIndex < 9 )
	{
		pXML->AddAttribute( _T("frameRate"), pszFPS[ nFrameIndex - 1 ] );
	}
	
	return CLibraryBuilder::SubmitMetadata( nIndex, CSchema::uriVideo, pXML );
}

//////////////////////////////////////////////////////////////////////
// CLibraryBuilderInternals OGG VORBIS (threaded)

BOOL CLibraryBuilderInternals::ReadOGG(DWORD nIndex, HANDLE hFile)
{
	SetFilePointer( hFile, 0, NULL, FILE_BEGIN );
	
	DWORD nDummy, nHeader = 0;
	ReadFile( hFile, &nHeader, 4, &nDummy, NULL );
	
	for ( DWORD nSeek = 0 ; nSeek < 16384 ; nSeek++ )
	{
		if ( nHeader == 'SggO' ) break;
		nHeader >>= 8;
		ReadFile( hFile, (BYTE*)&nHeader + 3, 1, &nDummy, NULL );
	}
	
	if ( nHeader != 'SggO' ) return CLibraryBuilder::SubmitCorrupted( nIndex );
	SetFilePointer( hFile, -4, NULL, FILE_CURRENT );
	
	DWORD nOGG = 0;
	BYTE* pOGG = ReadOGGPage( hFile, nOGG, 0x02, 0, 0x1E );
	
	if ( ! pOGG ) return FALSE;
	
	BYTE  nChannels		= pOGG[ 11 ];
	DWORD nFrequency	= *(DWORD*)&pOGG[12];
	DWORD nBitrate		= *(DWORD*)&pOGG[20];
	
	delete [] pOGG;
	BYTE* prOGG = pOGG = ReadOGGPage( hFile, nOGG, 0x00, 1, 1+6+4+4 );
	
	if ( ! pOGG ) return FALSE;
	pOGG += 1 + 6;
	nOGG -= 1 + 6;
	
	CString strComment;
	
	if ( ! ReadOGGString( pOGG, nOGG, strComment ) || nOGG < 4 )
	{
		free( pOGG );
		return FALSE;
	}
	
	DWORD nComments = *(DWORD*)pOGG;
	pOGG += 4; nOGG -= 4;
	
	CXMLElement* pXML = new CXMLElement( NULL, L"audio" );
	
	for ( ; nComments && nOGG > 4 ; nComments-- )
	{
		if ( ! ReadOGGString( pOGG, nOGG, strComment ) ) break;
		
		int nEquals = strComment.Find( '=' );
		if ( nEquals <= 0 ) continue;
		
		CString strKey		= strComment.Left( nEquals );
		CString strValue	= strComment.Mid( nEquals + 1 );
		
		strKey.TrimLeft(); strKey.TrimRight(); 
		CharUpper( strKey.GetBuffer() );
		strKey.ReleaseBuffer();

		// decode UTF-8 string
		int nLength = strValue.GetLength();

		LPTSTR pszSource = new TCHAR[ nLength + 1 ]; 
		CHAR* pszDest = new CHAR[ nLength + 1 ];

		_tcscpy( pszSource, strValue.GetBuffer() );
		for ( UINT nLen = 0 ; nLen < _tcslen( pszSource ) ; nLen++ )
			pszDest[ nLen ] = (CHAR) pszSource[ nLen ];
		delete pszSource;

		int nWide = MultiByteToWideChar( CP_UTF8, 0, pszDest, nLength, NULL, 0 );
		LPWSTR pszWide = new WCHAR[ nWide + 1 ];
		MultiByteToWideChar( CP_UTF8, 0, pszDest, nLength, pszWide, nWide );
		pszWide[ nWide ] = 0;
		strValue = pszWide;
		
		delete [] pszWide;
		delete pszDest;

		strValue.TrimLeft(); strValue.TrimRight();

		if ( strValue.IsEmpty() ) continue;
		
		if ( strKey == L"TITLE" )
		{
			pXML->AddAttribute( L"title", strValue );
		}
		else if ( strKey == L"ALBUM" )
		{
			pXML->AddAttribute( L"album", strValue );
		}
		else if ( strKey == L"ORIGINALALBUM" )
		{
			pXML->AddAttribute( L"origAlbum", strValue );
		}
		else if ( strKey == L"TRACKNUMBER" )
		{
			pXML->AddAttribute( L"track", strValue );
		}
		else if ( strKey == L"ARTIST" )
		{
			pXML->AddAttribute( L"artist", strValue );
		}
		else if ( strKey == L"ORIGINALARTIST" )
		{
			pXML->AddAttribute( L"origArtist", strValue );
		}
		else if ( strKey == L"DESCRIPTION" || strKey == L"COMMENT" )
		{
			pXML->AddAttribute( L"description", strValue );
		}
		else if ( strKey == L"GENRE" )
		{
			pXML->AddAttribute( L"genre", strValue );
		}
		else if ( strKey == L"DATE" )
		{
			pXML->AddAttribute( L"year", strValue );
		}
		else if ( strKey == L"COPYRIGHT" )
		{
			pXML->AddAttribute( L"copyright", strValue );
		}
		else if ( strKey == L"ENCODED-BY" || strKey == L"ENCODEDBY" || strKey == L"ENCODED BY" )
		{
			pXML->AddAttribute( L"encodedby", strValue );
		}
		else if ( strKey == L"COMPOSER" )
		{
			pXML->AddAttribute( L"composer", strValue );
		}
		else if ( strKey == L"ENCODERSETTINGS" || strKey == L"ENCODER" || strKey == L"ENCODING" )
		{
			pXML->AddAttribute( L"qualitynotes", strValue );
		}
		else if ( strKey == L"USERURL" || strKey == L"USER DEFINED URL LINK" )
		{
			pXML->AddAttribute( L"link", strValue );
		}
	}
	
	delete [] prOGG;
	
	if ( nComments )
	{
		if ( pXML ) delete pXML;
		return FALSE;
	}
	
	DWORD nLength = 0;
	
	for ( nComments = 2 ; ; nComments++ )
	{
		DWORD nTime = GetTickCount();
		if ( ! ReadOGGPage( hFile, nOGG, 0xFF, nComments, 0xFFFFFFFF ) ) break;
		nLength = max( nLength, nOGG );
		m_nSleep = ( GetTickCount() - nTime ) * 3;
		if ( m_nSleep > 0 ) Sleep( m_nSleep );
		if ( ! LibraryBuilder.IsAlive() ) break;
	}
	
	if ( ! LibraryBuilder.IsAlive() )
	{
		delete pXML;
		return FALSE;
	}
	
	if ( nFrequency > 0 && nLength > 0 && ( nLength / nFrequency ) > 0 )
	{
		strComment.Format( L"%lu", nLength / nFrequency );
		pXML->AddAttribute( L"seconds", strComment );

		nBitrate = GetFileSize( hFile, NULL ) / ( nLength / nFrequency ) * 8;
	}
	
	strComment.Format( L"%lu", nBitrate / 1000 );
	pXML->AddAttribute( L"bitrate", strComment );
	
	strComment.Format( L"%lu", nFrequency );
	pXML->AddAttribute( L"sampleRate", strComment );
	
	strComment.Format( L"%lu", nChannels );
	pXML->AddAttribute( L"channels", strComment );
	
	return CLibraryBuilder::SubmitMetadata( nIndex, CSchema::uriAudio, pXML );
}

BYTE* CLibraryBuilderInternals::ReadOGGPage(HANDLE hFile, DWORD& nBuffer, BYTE nFlags, DWORD nSequence, DWORD nMinSize)
{
	DWORD nMagic, nRead, nSample;
	BYTE nByte, nChunk;
	
	nBuffer = 0;
	
	ReadFile( hFile, &nMagic, 4, &nRead, NULL );
	if ( nRead != 4 || nMagic != 'SggO' ) return NULL;
	
	ReadFile( hFile, &nByte, 1, &nRead, NULL );
	if ( nRead != 1 || nByte != 0 ) return NULL;
	
	ReadFile( hFile, &nByte, 1, &nRead, NULL );
	if ( nRead != 1 ) return NULL;
	if ( nFlags < 0xFF && nByte != nFlags ) return NULL;
	
	ReadFile( hFile, &nSample, 4, &nRead, NULL );
	if ( nRead != 4 ) return NULL;
	
	SetFilePointer( hFile, 4 + 4, NULL, FILE_CURRENT );
	
	ReadFile( hFile, &nMagic, 4, &nRead, NULL );
	if ( nRead != 4 || nMagic != nSequence ) return NULL;
	
	ReadFile( hFile, &nMagic, 4, &nRead, NULL );
	if ( nRead != 4 ) return NULL;
	
	ReadFile( hFile, &nByte, 1, &nRead, NULL );
	if ( nRead != 1 ) return NULL;
	
	for ( ; nByte ; nByte-- )
	{
		ReadFile( hFile, &nChunk, 1, &nRead, NULL );
		if ( nRead != 1 ) break;
		nBuffer += nChunk;
	}
	
	if ( nByte ) return NULL;
	
	if ( nMinSize < 0xFFFFFFFF )
	{
		if ( nBuffer < nMinSize ) return NULL;
		
		BYTE* pBuffer = new BYTE[ nBuffer ];
		
		ReadFile( hFile, pBuffer, nBuffer, &nRead, NULL );
		
		if ( nRead == nBuffer ) return pBuffer;
		
		delete [] pBuffer;
	}
	else
	{
		SetFilePointer( hFile, nBuffer, NULL, FILE_CURRENT );
		nBuffer = nSample;
		return (BYTE*)TRUE;
	}
	
	return NULL;
}

BOOL CLibraryBuilderInternals::ReadOGGString(BYTE*& pOGG, DWORD& nOGG, CString& str)
{
	if ( nOGG < 4 ) return FALSE;
	
	DWORD nLen = *(DWORD*)pOGG;
	pOGG += 4; nOGG -= 4;
	
	if ( nOGG < nLen ) return FALSE;
	
	LPTSTR pszOut = str.GetBuffer( nLen + 1 );
	for ( ; nLen ; nLen--, nOGG-- ) *pszOut++ = (TCHAR)*pOGG++;
	*pszOut++ = 0;
	str.ReleaseBuffer();
	
	return TRUE;
}

BOOL CLibraryBuilderInternals::ReadMPC(DWORD nIndex, HANDLE hFile, Hashes::Md5Hash& oMD5)
{
	return ReadAPE( nIndex, hFile, oMD5, true );
}

//////////////////////////////////////////////////////////////////////
// CLibraryBuilderInternals APE Monkey's Audio (threaded)

BOOL CLibraryBuilderInternals::ReadAPE(DWORD nIndex, HANDLE hFile, Hashes::Md5Hash& /*oMD5*/, bool bPreferFooter)
{
	DWORD nFileSize = GetFileSize( hFile, NULL );
	if ( nFileSize < sizeof(APE_TAG_FOOTER) ) return CLibraryBuilder::SubmitCorrupted( nIndex );

	DWORD nRead;
	APE_TAG_FOOTER pFooter;

	CXMLElement* pXML = new CXMLElement( NULL, L"audio" );

	SetFilePointer( hFile, -(LONG)sizeof(pFooter), NULL, FILE_END );
	ReadFile( hFile, &pFooter, sizeof(pFooter), &nRead, NULL );

	if ( nRead != sizeof(pFooter) || strncmp( pFooter.cID, "APETAGEX", 8 ) ||
		( pFooter.nVersion != 1000 && pFooter.nVersion != 2000 ) )
	{
		if ( bPreferFooter )
			// Invalid footer, try to validate header only
			pFooter.nFields = -1;
	}

	SetFilePointer( hFile, -(LONG)pFooter.nSize, NULL, FILE_END );

	bool bHasTotalDiscsField = false, bHasDiscField = false;
	bool bHasTotalTracksField = false, bHasTrackField = false;
	CString strTotalDiscsField, strTotalTracksField, strKeyWords, strArtist;
	CString strDiscField, strTrackField;

	for ( int nTag = 0 ; nTag < pFooter.nFields ; nTag++ )
	{
		DWORD nLength, nFlags;

		ReadFile( hFile, &nLength, 4, &nRead, NULL );
		if ( nRead != 4 || nLength > 1024 * 4 ) break;
		ReadFile( hFile, &nFlags, 4, &nRead, NULL );
		if ( nRead != 4 ) break;

		CString strKey, strValue;

		while ( strKey.GetLength() < 255 )
		{
			BYTE nChar;
			ReadFile( hFile, &nChar, 1, &nRead, NULL );
			if ( nRead != 1 || nChar == 0 ) break;
			strKey += (TCHAR)nChar;
		}

		if ( nRead != 1 || strKey.GetLength() >= 255 ) break;

		LPSTR pszInput = new CHAR[ nLength ];
		ReadFile( hFile, pszInput, nLength, &nRead, NULL );
		if ( nLength != nRead ) break;

		int nWide = MultiByteToWideChar( CP_UTF8, 0, pszInput, nLength, NULL, 0 );
		LPWSTR pszWide = new WCHAR[ nWide + 1 ];
		MultiByteToWideChar( CP_UTF8, 0, pszInput, nLength, pszWide, nWide );
		pszWide[ nWide ] = 0;
		strValue = pszWide;

		delete [] pszWide;
		delete [] pszInput;

		strKey.TrimLeft(); strKey.TrimRight();
		strValue.TrimLeft(); strValue.TrimRight();

		if ( strKey.GetLength() && strValue.GetLength() )
		{
			ToLower( strKey );

			if ( strKey == L"title" )
			{
				pXML->AddAttribute( L"title", strValue );
			}
			else if ( strKey == L"artist" )
			{
				pXML->AddAttribute( L"artist", strValue );
				strArtist = strValue;
			}
			else if ( strKey == L"album" )
			{
				pXML->AddAttribute( L"album", strValue );
			}
			else if ( strKey == L"comment" )
			{
				pXML->AddAttribute( L"description", strValue );
			}
			else if ( strKey == L"year" )
			{
				if ( strValue.GetLength() > 4 && strValue.Find( L"-" ) != -1 )
				{
					pXML->AddAttribute( L"year", strValue.Left( 4 ) );
					pXML->AddAttribute( L"releaseDate", strValue );
				}
				else
					pXML->AddAttribute( L"year", strValue );
			}
			else if ( strKey == L"track" )
			{
				bHasTrackField = true; 
				int intSlashPosition = strValue.Find( L"/" );
				if ( strValue.Find( L"/" ) != -1 ) 
				{
					bHasTotalTracksField = true;
					strTrackField = strValue.Left( intSlashPosition );
					strTotalTracksField = strValue.Right( strValue.GetLength() - intSlashPosition - 1 );
				}
				else
					strTrackField = strValue;
			}
			else if ( strKey == L"totaltracks" )
			{
				bHasTotalTracksField = true;
				strTotalTracksField = strValue;
			}
			else if ( strKey == L"genre" )
			{
				pXML->AddAttribute( L"genre", strValue );
			}
			else if ( strKey.Find( L" url" ) > 0 ) // are there any tag fields containing that?
			{
				pXML->AddAttribute( L"link", strValue );
			}
			else if ( strKey == L"composer" )
			{
				pXML->AddAttribute( L"composer", strValue );
			}
			else if ( strKey == L"publisher" )
			{
				pXML->AddAttribute( L"publisher", strValue );
			}
			else if ( strKey == L"copyright" )
			{
				pXML->AddAttribute( L"copyright", strValue );
			}
			else if ( strKey == L"producer" )
			{
				pXML->AddAttribute( L"producer", strValue );
			}
			else if ( strKey == L"lyricist" )
			{
				pXML->AddAttribute( L"lyricist", strValue );
			}
			else if ( strKey == L"arranger" )
			{
				pXML->AddAttribute( L"arranger", strValue );
			}
			else if ( strKey == L"performer" )
			{
				pXML->AddAttribute( L"performer", strValue );
			}
			else if ( strKey == L"conductor" )
			{
				pXML->AddAttribute( L"conductor", strValue );
			}
			else if ( strKey == L"language" )
			{
				pXML->AddAttribute( L"language", strValue );
			}
			else if ( strKey == L"disc" )
			{
				bHasDiscField = true;
				int intSlashPosition = strValue.Find( L"/" );
				if ( intSlashPosition != -1 ) 
				{
					bHasTotalDiscsField = true;
					strDiscField = strValue.Left( intSlashPosition );
					strTotalDiscsField = strValue.Right( strValue.GetLength() - intSlashPosition - 1 );
				}
				else
					strDiscField = strValue;
			}
			else if ( strKey == L"totaldiscs" )
			{
				bHasTotalDiscsField = true;
				strTotalDiscsField = strValue;
			}
			else if ( strKey == L"date" )
			{
				pXML->AddAttribute( L"releaseDate", strValue );
			}
			else if ( strKey == L"encoded-by" || strKey == L"encodedby" || strKey == L"encoded by" )
			{
				pXML->AddAttribute( L"encodedby", strValue );
			}
			else if ( strKey == L"involvedpeople" )
			{
				if ( strKeyWords.GetLength() > 0 )
					strKeyWords += L"; " + strValue;
				else
					strKeyWords = strValue;
			}
			else if ( strKey == L"lyrics" || strKey == L"unsyncedlyrics" || strKey == L"unsynced lyrics" )
			{
				// pXML->AddAttribute( L"unsyncedlyrics", strValue );
			}
			else if ( strValue != strArtist && ( strKey == L"musicbrainz album artist" || strKey == L"musicbrainz albumartist" || strKey == L"album artist" || strKey == L"albumartist" ) )
			{
				pXML->AddAttribute( L"albumArtist", strValue );
			}
			else if ( strKey == L"musicbrainz album id" )
			{
				pXML->AddAttribute( L"mbalbumid", strValue );
			}
			else if ( strKey == L"musicbrainz album type" )
			{
				pXML->AddAttribute( L"type", strValue );
			}
			else if ( strKey == L"musicbrainz album artist id" )
			{
				pXML->AddAttribute( L"mbalbumartistid", strValue );
			}
			else if ( strKey == L"musicbrainz album status" )
			{
				pXML->AddAttribute( L"albumStatus", strValue );
			}
			else if ( strKey == L"musicbrainz aritst id" )
			{
				pXML->AddAttribute( L"mbartistid", strValue );
			}
			else if ( strKey == L"musicbrainz non-album" && strValue == L"1" )
			{
				pXML->AddAttribute( L"type", L"Non-Album Track" );
			}
			else if ( strKey == L"musicip puid" )
			{
				pXML->AddAttribute( L"mbpuid", strValue );
			}
			else if ( strKey == L"musicbrainz trm id" )
			{
				pXML->AddAttribute( L"mbtrmid", strValue );
			}
			else if ( strKey == L"performersortorder" )
			{
				if ( strKeyWords.GetLength() > 0 )
					strKeyWords += L"; " + strValue;
				else
					strKeyWords = strValue;
			}
			else if ( strKey == L"releasetime" )
			{
				pXML->AddAttribute( L"releaseDate", strValue );
			}
			else if ( strKey == L"uniquefileid" )
			{
				pXML->AddAttribute( L"mbuniquefileid", strValue );
			}
			else if ( strKey == L"contentgroup" )
			{
				pXML->AddAttribute( L"releasegroup", strValue );
			}
			else if ( strKey == L"encodersettings" )
			{
				pXML->AddAttribute( L"qualitynotes", strValue );
			}
			else if ( strKey == L"origalbum" )
			{
				pXML->AddAttribute( L"origAlbum", strValue );
			}
			else if ( strKey == L"origartist" )
			{
				pXML->AddAttribute( L"origArtist", strValue );
			}
			else if ( strKey == L"origfilename" )
			{
				pXML->AddAttribute( L"origFilename", strValue );
			}
			else if ( strKey == L"origlyricist" )
			{
				pXML->AddAttribute( L"origLyricist", strValue );
			}
			else if ( strKey == _T("origyear") )
			{
				pXML->AddAttribute( L"origYear", strValue );
			}
			else if ( strKey == L"wwwaudiosource" || strKey == L"wwwaudiofile" )
			{
				pXML->AddAttribute( L"releasegroupLink", strValue );
			}
			else if ( strKey == L"cddbdiscid" )
			{
				pXML->AddAttribute( L"cddb", strValue );
			}
		}
	}

	pXML->AddAttribute( L"keywords", strKeyWords );

	if ( bHasDiscField )
	{
		if ( bHasTotalDiscsField )
			pXML->AddAttribute( L"disc", strDiscField + "/" + strTotalDiscsField );
		else
			pXML->AddAttribute( L"disc", strDiscField );
	}

	if ( bHasTrackField == true )
	{
		if ( bHasTotalTracksField )
			pXML->AddAttribute( L"track", strTrackField + "/" + strTotalTracksField );
		else
			pXML->AddAttribute( L"track", strTrackField );
	}

	if ( nFileSize < sizeof(APE_HEADER) )
	{
		delete pXML;
		return CLibraryBuilder::SubmitCorrupted( nIndex );
	}

	SetFilePointer( hFile, 0, NULL, FILE_BEGIN );
	APE_HEADER pAPE = {0};
	APE_HEADER_NEW pNewAPE = {0};
	int nValidSize = sizeof(pAPE);
	
	ReadFile( hFile, &pAPE, nValidSize, &nRead, NULL );

	// We checked if the file size is bigger than the footer, so no check is needed
	// here for the nRead bytes.

	// Signatures we handle although the headers may be invalid.
	// APE tags usually are placed in footer (it's recommended).
	bool bMAC = pAPE.cID[0] == 'M' && pAPE.cID[1] == 'A' && pAPE.cID[2] == 'C';
	bool bMPC = pAPE.cID[0] == 'M' && pAPE.cID[1] == 'P' && pAPE.cID[2] == '+';
	bool bNewAPE = false;

	if ( bMAC && pAPE.nVersion >= 3980 )
	{
		SetFilePointer( hFile, 0, NULL, FILE_BEGIN );
		nValidSize = sizeof(pNewAPE);
		ReadFile( hFile, &pNewAPE, nValidSize, &nRead, NULL );
		bNewAPE = true;
	}
	else
	{
		// just copy data to new format header and we will use it for the tests
		pNewAPE.nVersion = pAPE.nVersion;
		pNewAPE.nSampleRate = pAPE.nSampleRate;
		pNewAPE.nTotalFrames = pAPE.nTotalFrames;
		pNewAPE.nCompressionLevel = pAPE.nCompressionLevel;
		pNewAPE.nFormatFlags = pAPE.nFormatFlags;
		pNewAPE.nFinalFrameBlocks = pAPE.nFinalFrameBlocks;
		pNewAPE.nChannels = pAPE.nChannels;
		pNewAPE.nHeaderBytes = pAPE.nHeaderBytes;
		ZeroMemory( &pAPE, nValidSize ); // just in case if someone messes up the code below
	}

	bool bValidSignature = bMAC || bMPC;

	if ( (int)nRead != nValidSize || !bValidSignature || pNewAPE.nSampleRate == 0 || bPreferFooter )
	{
		// APE tags in MP3 or MPC footer
		if ( pFooter.nFields > 0 && bPreferFooter )
		{
			if ( !bValidSignature ) ScanMP3Frame( pXML, hFile, 0 );
			return CLibraryBuilder::SubmitMetadata( nIndex, CSchema::uriAudio, pXML ) > 0;
		}
		else // No APE footer and no header in MP3 or invalid APE file
		{
			delete pXML;
			return bPreferFooter ? FALSE : CLibraryBuilder::SubmitCorrupted( nIndex );
		}
	}

	DWORD nSamplesPerFrame;

	if ( bNewAPE )
		nSamplesPerFrame = pNewAPE.nBlocksPerFrame;
	else
	{
		nSamplesPerFrame = ( ( pNewAPE.nVersion >= 3900 ) || 
			( pNewAPE.nVersion >= 3800 && pNewAPE.nCompressionLevel == 4000 ) ) ? 73728 : 9216;
		if ( pNewAPE.nVersion >= 3950 )
			nSamplesPerFrame = 73728 * 4;
	}

	DWORD nSamples = 0;
	if ( pNewAPE.nTotalFrames != 0 ) 
		nSamples = ( pNewAPE.nTotalFrames - 1 ) * nSamplesPerFrame + pNewAPE.nFinalFrameBlocks;

	if ( pNewAPE.nSampleRate == 0 )
	{
		delete pXML;
		return CLibraryBuilder::SubmitCorrupted( nIndex );
	}

	DWORD nDuration = nSamples / pNewAPE.nSampleRate;

	if ( nDuration <= 0.0 )
	{
		delete pXML;
		return CLibraryBuilder::SubmitCorrupted( nIndex );
	}

	DWORD nBitRate = ( nFileSize * 8 / nDuration + 500 ) / 1000;
	DWORD nBitsPerSample = 0;

	if ( bNewAPE )
	{
		Hashes::Md5Hash	oApeMD5;
		std::memcpy( &oApeMD5, pNewAPE.cFileMD5, sizeof(pNewAPE.cFileMD5) );
		if ( !oApeMD5.validate() )
		{
			delete pXML;
			return CLibraryBuilder::SubmitCorrupted( nIndex );
		}

		nBitsPerSample = pNewAPE.nBitsPerSample;

		// ToDo: We need MD5 hash of the file without tags...
/*
		if ( validAndUnequal( oApeMD5, oMD5 ) )
		{
			delete pXML;
			return CLibraryBuilder::SubmitCorrupted( nIndex );
		}
*/
	}
	else
	{
		nBitsPerSample = ( pNewAPE.nFormatFlags & 1 ) ? 8 : ( pNewAPE.nFormatFlags & 8 ) ? 24 : 16;
	}

	if ( nBitsPerSample == 0 )
	{
		delete pXML;
		return CLibraryBuilder::SubmitCorrupted( nIndex );
	}

	DWORD nUncompressedSize = nSamples * pNewAPE.nChannels * ( nBitsPerSample / 8 );
	if ( nUncompressedSize == 0 )
	{
		delete pXML;
		return CLibraryBuilder::SubmitCorrupted( nIndex );
	}

	CString strItem;
	
	strItem.Format( L"%lu", nBitRate );
	pXML->AddAttribute( L"bitrate", strItem );

	strItem.Format( L"%lu", nDuration );
	pXML->AddAttribute( L"seconds", strItem );
	
	strItem.Format( L"%lu", pNewAPE.nSampleRate );
	pXML->AddAttribute( L"sampleRate", strItem );
	
	strItem.Format( L"%lu", pNewAPE.nChannels );
	pXML->AddAttribute( L"channels", strItem );
	
	ReadID3v1( nIndex, hFile, pXML );
	
	return CLibraryBuilder::SubmitMetadata( nIndex, CSchema::uriAudio, pXML ) > 0;
}

//////////////////////////////////////////////////////////////////////
// CLibraryBuilderInternals AVI (threaded)

BOOL CLibraryBuilderInternals::ReadAVI(DWORD nIndex, HANDLE hFile)
{
	if ( GetFileSize( hFile, NULL ) < sizeof(AVI_HEADER) + 16 ) return CLibraryBuilder::SubmitCorrupted( nIndex );
	SetFilePointer( hFile, 0, NULL, FILE_BEGIN );
	
	CHAR szID[5] = { 0, 0, 0, 0, 0 };
	DWORD nRead, nNextOffset, nPos;
	CString strCodec;
	
	ReadFile( hFile, szID, 4, &nRead, NULL );
	if ( nRead != 4 || strncmp( szID, "RIFF", 4 ) ) return CLibraryBuilder::SubmitCorrupted( nIndex );
	ReadFile( hFile, szID, 4, &nRead, NULL );
	if ( nRead != 4 ) return CLibraryBuilder::SubmitCorrupted( nIndex );
	ReadFile( hFile, szID, 4, &nRead, NULL );
	if ( nRead != 4 || strncmp( szID, "AVI ", 4 ) ) return CLibraryBuilder::SubmitCorrupted( nIndex );
	ReadFile( hFile, szID, 4, &nRead, NULL );
	
	// AVI files include two mandatory LIST chunks ('hdrl' and 'movi')
	// So, treat file as corrupted if they are missing
	if ( nRead != 4 || strncmp( szID, "LIST", 4 ) ) return CLibraryBuilder::SubmitCorrupted( nIndex );
	// Get next outer LIST offset
	ReadFile( hFile, &nNextOffset, sizeof(DWORD), &nRead, NULL );
	if ( nRead != 4 ) return CLibraryBuilder::SubmitCorrupted( nIndex );	
	
	// Remember position
	nPos = SetFilePointer( hFile, 0, NULL, FILE_CURRENT );

	ReadFile( hFile, szID, 4, &nRead, NULL );
	if ( nRead != 4 || strncmp( szID, "hdrl", 4 ) ) return CLibraryBuilder::SubmitCorrupted( nIndex );
	ReadFile( hFile, szID, 4, &nRead, NULL );
	if ( nRead != 4 || strncmp( szID, "avih", 4 ) ) return CLibraryBuilder::SubmitCorrupted( nIndex );
	ReadFile( hFile, szID, 4, &nRead, NULL );
	if ( nRead != 4 ) return CLibraryBuilder::SubmitCorrupted( nIndex );
	
	AVI_HEADER pHeader;
	ReadFile( hFile, &pHeader, sizeof(pHeader), &nRead, NULL );
	if ( nRead != sizeof(pHeader) ) return CLibraryBuilder::SubmitCorrupted( nIndex );
	
	// One or more 'strl' chunks must follow the main header
	ReadFile( hFile, szID, 4, &nRead, NULL );
	if ( nRead != 4 || strncmp( szID, "LIST", 4 ) ) return CLibraryBuilder::SubmitCorrupted( nIndex );
	ReadFile( hFile, szID, 4, &nRead, NULL );
	if ( nRead != 4 ) return CLibraryBuilder::SubmitCorrupted( nIndex );
	ReadFile( hFile, szID, 4, &nRead, NULL );
	if ( nRead != 4 || strncmp( szID, "strl", 4 ) ) return CLibraryBuilder::SubmitCorrupted( nIndex );
	ReadFile( hFile, szID, 4, &nRead, NULL );
	if ( nRead != 4 || strncmp( szID, "strh", 4 ) ) return CLibraryBuilder::SubmitCorrupted( nIndex );
	ReadFile( hFile, szID, 4, &nRead, NULL );
	if ( nRead != 4 ) return CLibraryBuilder::SubmitCorrupted( nIndex );
	ReadFile( hFile, szID, 4, &nRead, NULL );
	if ( nRead != 4 || strncmp( szID, "vids", 4 ) ) return CLibraryBuilder::SubmitCorrupted( nIndex );
	ReadFile( hFile, szID, 4, &nRead, NULL );
	if ( nRead != 4 ) return CLibraryBuilder::SubmitCorrupted( nIndex );
	strCodec = CString( szID );

	BOOL bMoviFound = FALSE;
	do
	{
		nPos += nNextOffset;
		if ( SetFilePointer( hFile, nPos, NULL, FILE_BEGIN ) == INVALID_SET_FILE_POINTER )
			return CLibraryBuilder::SubmitCorrupted( nIndex );
		ReadFile( hFile, szID, 4, &nRead, NULL );
		if ( nRead != 4 ) return CLibraryBuilder::SubmitCorrupted( nIndex );
		nNextOffset = 0;
		ReadFile( hFile, &nNextOffset, 4, &nRead, NULL );
		if ( nRead != 4 ) return CLibraryBuilder::SubmitCorrupted( nIndex );
		nPos = SetFilePointer( hFile, 0, NULL, FILE_CURRENT );
		if ( strncmp( szID, "LIST", 4 ) == 0 )
		{
			ReadFile( hFile, szID, 4, &nRead, NULL );
			if ( nRead != 4 ) return CLibraryBuilder::SubmitCorrupted( nIndex );
			if ( strncmp( szID, "movi", 4 ) == 0 ) bMoviFound = TRUE;
		}
	}
	while ( ! bMoviFound && nNextOffset );

	if ( ! bMoviFound ) return CLibraryBuilder::SubmitCorrupted( nIndex );
	
	CXMLElement* pXML = new CXMLElement( NULL, L"video" );
	CString strItem;
	
	double nTime = (double)pHeader.dwMicroSecPerFrame / 1000000.0f;
	nTime *= (double)pHeader.dwTotalFrames;
	nTime /= 60.0f;
	
	double nRate = 1000000.0f / (double)pHeader.dwMicroSecPerFrame;
	
	strItem.Format( L"%lu", pHeader.dwWidth );
	pXML->AddAttribute( L"width", strItem );
	strItem.Format( L"%lu", pHeader.dwHeight );
	pXML->AddAttribute( L"height", strItem );
	strItem.Format( L"%.3f", nTime );
	pXML->AddAttribute( L"minutes", strItem );
	strItem.Format( L"%.2f", nRate );
	pXML->AddAttribute( L"frameRate", strItem );
	pXML->AddAttribute( L"codec", strCodec );
	
	return CLibraryBuilder::SubmitMetadata( nIndex, CSchema::uriVideo, pXML );
}

//////////////////////////////////////////////////////////////////////
// CLibraryBuilderInternals PDF (threaded)

BOOL CLibraryBuilderInternals::ReadPDF(DWORD nIndex, HANDLE hFile, LPCTSTR pszPath)
{
	DWORD nOffset, nCount, nCountStart, nPages, nOffsetPrev, nFileLength, nVersion;
	CString strLine, strSeek;
	
	// Make sure this is the only thread doing this right now
	CSingleLock pWindowLock( &theApp.m_pSection );
	SetFilePointer( hFile, 0, NULL, FILE_BEGIN );
	strLine = ReadLine( hFile );
	// TODO: Header should be within the first 1024 KB by specs
	if ( strLine.Find( _T("%PDF") ) == 0 ) 
		nCount = 7;
	else if ( strLine.Find( _T("%!PS-Adobe") ) == 0 )
		nCount = 21;
	else return FALSE;
	_stscanf( strLine.Mid( nCount ), _T("%lu"), &nVersion );
	if ( nVersion > 5 ) return FALSE;
	
	BOOL bLinearized = FALSE;
	nPages = nFileLength = nCount = 0;
	//strLine = ReadLine( hFile );
	strLine = ReadLine( hFile, (LPCTSTR)_T("<") );
	strLine = ReadLine( hFile, (LPCTSTR)_T("<") );

	// We are after the 1st object
	if ( !ReadLine( hFile, (LPCTSTR)_T("/") ).IsEmpty() )
		return FALSE;
	strLine = ReadLine( hFile, (LPCTSTR)_T("/>") );
	nCount = 0;
	while ( !strLine.IsEmpty() && nCount < 9 && nVersion > 1 ) //read dictionary entries only from 8 lines max
	{
		CString strEntry;
		int nData = 0;
		nData = strLine.Find( _T(" ") );
		strEntry = strLine.Left( nData ).MakeLower();
		if ( strEntry != _T("h") && nData > 0 )
		{
			if ( _stscanf( strLine.Mid( nData + 1 ), _T("%lu"), &nData ) != 1 ) break;
			if ( strEntry == _T("linearized") ) 
				bLinearized = TRUE;
			else if ( strEntry == _T("n") )
				nPages = nData;
			else if ( strEntry == _T("l") )
				nFileLength = nData;
		}
		strLine = ReadLine( hFile, (LPCTSTR)_T("/>") );
		nCount++;
	}

	if ( bLinearized )
	{ 
		// remember position
		nOffset = SetFilePointer( hFile, 0, NULL, FILE_CURRENT );
		// if file length is not the same as in L data, the document is treated as non-linearized
		DWORD nError;
		if ( SetFilePointer( hFile, nFileLength, NULL, FILE_BEGIN ) == INVALID_SET_FILE_POINTER && 
			 ( nError = GetLastError() ) != NO_ERROR )
		{
			bLinearized = FALSE;
			nPages = 0;
		}
		else // return back
			SetFilePointer( hFile, nOffset, NULL, FILE_BEGIN );
	}

	// nOffset - the first reference position to which we will go
	// First we validate reference table and find a total number of objects
	nOffset = nOffsetPrev = 0;

	// Linearized document validation
	if ( bLinearized )
	{
		// get total object count
		if ( ReadLine( hFile ).IsEmpty() ) strLine = ReadLine( hFile );
		if ( strLine != _T("endobj") ) return FALSE;
		nOffset = SetFilePointer( hFile, 0, NULL, FILE_CURRENT );
		strLine = ReadLine( hFile );
		if ( strLine.IsEmpty() ) strLine = ReadLine( hFile );

		if ( strLine != _T("xref") ) return FALSE;
		strLine = ReadLine( hFile );
		if ( _stscanf( strLine, _T("%lu %lu"), &nCountStart, &nCount ) != 2 ) return FALSE;

		for ( int nLines = 0 ; nLines < (int)nCount ; nLines++ ) ReadLine( hFile );
		nCount += nCountStart; // total number of objects

		// read trailer dictionary
		if ( ReadLine( hFile ) != _T("trailer") ) return FALSE;

		strLine = ReadLine( hFile, (LPCTSTR)_T("<") );
		strLine = ReadLine( hFile, (LPCTSTR)_T("<") );
		if ( !ReadLine( hFile, (LPCTSTR)_T("/") ).IsEmpty() )
			return FALSE;
		strLine = ReadLine( hFile, (LPCTSTR)_T("/>") );
		while ( !strLine.IsEmpty() ) 
		{
			CString strEntry;
			DWORD nData = 0;
			nData = strLine.Find( _T(" ") );
			strEntry = strLine.Left( nData ).MakeLower();
			if ( strEntry == _T("size") ) 
			{
				_stscanf( strLine.Mid( nData + 1 ), _T("%lu"), &nData );
				if ( nData != nCount ) return FALSE;
			}
			else if ( strEntry == _T("prev") )
			{
				if ( _stscanf( strLine.Mid( nData + 1 ), _T("%lu"), &nData ) != 1 ) return FALSE;
				nOffsetPrev = nData;
			}
			else if ( strEntry == _T("encrypt") )
			{
				// if document encrypted skip it
				if ( strLine.Mid( nData + 1 ).CompareNoCase( _T("null") ) != 0 ) return FALSE;
			}
			strLine = ReadLine( hFile, (LPCTSTR)_T("/>") );
		}
		if ( !ReadLine( hFile ).IsEmpty() ) return FALSE;
		if ( ReadLine( hFile ) != _T("startxref") ) return FALSE;
		if ( ReadLine( hFile ) != _T("0") ) return FALSE;
		if ( nOffsetPrev == 0 ) return FALSE; // Linearized docs should have non-zero value
	}
	
	// Non-linearized document validation
	if ( ! bLinearized ) {
		SetFilePointer( hFile, -1, NULL, FILE_END );
		strLine = ReadLineReverse( hFile );
		if ( strLine.IsEmpty() ) strLine = ReadLineReverse( hFile );
		
		// TODO: %%EOF should be within the last 1024 KB by specs
		if ( strLine != _T("%%EOF") ) return FALSE;

		strLine = ReadLineReverse( hFile );
		if ( ReadLineReverse( hFile ) != _T("startxref") ) return FALSE;

		// get last reference object number
		if ( _stscanf( strLine, _T("%lu"), &nOffset ) != 1 ) return FALSE;
		if ( !ReadLineReverse( hFile, (LPCTSTR)_T(">") ).IsEmpty() ||
			 !ReadLineReverse( hFile, (LPCTSTR)_T(">") ).IsEmpty() )
			return FALSE;
		// read no more than 10 lines backwards
		for ( int nLines = 0 ; nLines < 10; nLines++ )
		{
			strLine = ReadLineReverse( hFile, (LPCTSTR)_T("/<") );
			if ( strLine.IsEmpty() ) break;
			CString strEntry;
			int nData = 0;
			nData = strLine.Find( _T(" ") );
			strEntry = strLine.Left( nData ).MakeLower();
			if ( strEntry == _T("size") ) 
			{
				_stscanf( strLine.Mid( nData + 1 ), _T("%lu"), &nCount );
			}
			else if ( strEntry == _T("encrypt") )
			{
				// if document encrypted skip it
				if ( strLine.Mid( nData + 1 ).CompareNoCase( _T("null") ) != 0 ) return FALSE;
			}
		}
		if ( ReadLineReverse( hFile ) != _T("<") ||
			 ReadLineReverse( hFile ) != _T("trailer") ) return FALSE;
	}

	if ( ! bLinearized ) 
	{
		// TODO: find total number of non-deleted objects
	}
	
	DWORD* pOffset = NULL;
	try
	{
		pOffset = new DWORD[ nCount ];
	}
	catch ( ... )
	{
		return FALSE;
	}

	ZeroMemory( pOffset, sizeof(DWORD) * nCount );
	
	// The main part: an array is filled with the locations of objects from refrence tables 
	DWORD nOffsetInfo, nOffsetRoot;
	nOffsetInfo = nOffsetRoot = 0;
	while ( nOffset != 0 )
	{
		DWORD nTemp;
		// return back and cycle through all references
		SetFilePointer( hFile, nOffset, NULL, FILE_BEGIN );
		strLine = ReadLine( hFile );
		if ( strLine.IsEmpty() ) strLine = ReadLine( hFile );
		if ( strLine != _T("xref") ) 
		{
			delete [] pOffset;
			return FALSE;
		}
		strLine = ReadLine( hFile );
		if ( _stscanf( strLine, _T("%lu %lu"), &nCountStart, &nTemp ) != 2 ) 
		{
			delete [] pOffset;		
			return FALSE;
		}

		// collect objects positions from the references
		for ( int nObjectNo = nCountStart ; nObjectNo < (int)(nCountStart + nTemp) ; nObjectNo++ )
		{
			strLine = ReadLine( hFile );
			strLine.TrimLeft();
			strLine.TrimRight();
			
			if ( strLine.GetLength() != 18 || strLine.GetAt( 10 ) != ' ' )
			{
				delete [] pOffset;
				return FALSE;
			}
			if ( strLine.GetAt( 17 ) == 'n' )
			{
				LPCTSTR pszInt = strLine;
				for ( ; *pszInt == '0' ; pszInt++ );
				if ( *pszInt != 0 ) _stscanf( pszInt, _T("%lu"), &pOffset[ nObjectNo ] );
			}
		}
		if ( ReadLine( hFile ) != _T("trailer") ) 
		{
			delete [] pOffset;
			return FALSE;
		}
		// Only the last data from trailers are used for /Info and /Root positions
		nOffsetPrev = 0; 

		strLine = ReadLine( hFile, (LPCTSTR)_T("<") );
		strLine = ReadLine( hFile, (LPCTSTR)_T("<") );
		if ( !ReadLine( hFile, (LPCTSTR)_T("/") ).IsEmpty() )
		{
			delete [] pOffset;
			return FALSE;
		}
		strLine = ReadLine( hFile, (LPCTSTR)_T("/>") );
		while ( !strLine.IsEmpty() ) 
		{
			CString strEntry;
			int nData = 0;
			nData = strLine.Find( _T(" ") );
			strEntry = strLine.Left( nData ).MakeLower();
			if ( strEntry == _T("info") ) 
				_stscanf( strLine.Mid( nData + 1 ), _T("%lu"), &nOffsetInfo );
			else if ( strEntry == _T("prev") ) 
				_stscanf( strLine.Mid( nData + 1 ), _T("%lu"), &nOffsetPrev );
			else if ( strEntry == _T("root") ) 
				_stscanf( strLine.Mid( nData + 1 ), _T("%lu"), &nOffsetRoot );
			strLine = ReadLine( hFile, (LPCTSTR)_T("/>") );
		}
		nOffset = nOffsetPrev;
	}

	// collect author, title if file name contains "book" keyword
	BOOL bBook = ( _tcsistr( pszPath, _T("book") ) != NULL );
	
	CXMLElement* pXML = new CXMLElement( NULL, bBook ? _T("book") : _T("wordprocessing") );
	
	if ( LPCTSTR pszName = _tcsrchr( pszPath, '\\' ) )
	{
		pszName++;
		
		if ( _tcsnicmp( pszName, _T("ebook - "), 8 ) == 0 )
		{
			strLine = pszName + 8;
			strLine = strLine.SpanExcluding( _T(".") );
			strLine.TrimLeft();
			strLine.TrimRight();
			pXML->AddAttribute( _T("title"), strLine );
		}
		else if ( _tcsnicmp( pszName, _T("(ebook"), 6 ) == 0 )
		{
			if ( ( pszName = _tcschr( pszName, ')' ) ) != NULL )
			{
				if ( _tcsncmp( pszName, _T(") - "), 4 ) == 0 )
					strLine = pszName + 4;
				else
					strLine = pszName + 1;
				strLine = strLine.SpanExcluding( _T(".") );
				strLine.TrimLeft();
				strLine.TrimRight();
				pXML->AddAttribute( _T("title"), strLine );
			}
		}
	}

	// document information is not available--exit
	if ( nOffsetInfo == 0 && nOffsetRoot == 0 && !bBook ) 
	{
		delete [] pOffset;
		return FALSE;
	}

/*	// Get XMP metadata; Not implemented, we should prefer XMP if the file creation time was less
	// than metadata timestamp
	// Get matadata from catalog dictionary if available
	DWORD nOffsetMeta = 0;
	if ( nOffsetRoot != 0 ) 
	{
		strSeek.Format( _T("%lu 0 obj"), nOffsetRoot );
		SetFilePointer( hFile, pOffset[ nOffsetRoot ], NULL, FILE_BEGIN );
		strLine = ReadLine( hFile, (LPCTSTR)_T("<") );
		if ( strLine == strSeek )
		{
			if ( ReadLine( hFile, (LPCTSTR)_T("<") ).IsEmpty() &&
				 ReadLine( hFile, (LPCTSTR)_T("/") ).IsEmpty() &&
				 ReadLine( hFile, (LPCTSTR)_T("/") ).MakeLower() == _T("type") &&
				 ReadLine( hFile, (LPCTSTR)_T("/") ).MakeLower() == _T("catalog") )
			{
				strLine = ReadLine( hFile, (LPCTSTR)_T("/>") );
				while ( !strLine.IsEmpty() )
				{
					CString strEntry;
					int nData = 0;
					nData = strLine.Find( _T(" ") );
					strEntry = ToLower( strLine.Left( nData ) );
					if ( strEntry == _T("metadata") )
					{
						_stscanf( strLine.Mid( nData + 1 ), _T("%lu"), &nOffsetMeta );
					}
					strLine = ReadLine( hFile, (LPCTSTR)_T("/>") );
				}
			}
		}
	}

	if ( nOffsetMeta != 0 ) 
	{
		SetFilePointer( hFile, pOffset[ nOffsetMeta ], NULL, FILE_BEGIN );
		strLine = ReadLine( hFile ); //xxx 0 obj
		strLine = ReadLine( hFile ); //<</Type /Matadata /Subtype /XML /Length xxx
		strLine = ReadLine( hFile ); //stream
		strLine = ReadLine( hFile ); //XML metadata 
		strLine = ReadLine( hFile ); //endstream
		strLine = ReadLine( hFile ); //endobj
	}*/

	// No page number in info, count manually
	if ( nPages == 0 ) 
	{
		int nObjPos = 0;
		for ( nOffset = 0 ; nOffset < nCount ; nOffset++ )
		{
			if ( pOffset[ nOffset ] == 0 ) continue;
			SetFilePointer( hFile, pOffset[ nOffset ], NULL, FILE_BEGIN );
			
			strLine = ReadLine( hFile, (LPCTSTR)_T("<") );
			nObjPos = strLine.Find( _T("obj") );
			if ( nObjPos < 0 ) break;
		
			// object after object, so we read more than one
			if ( strLine.Find( _T("obj"), nObjPos + 1 ) != -1 )
				continue;

			if ( ReadLine( hFile, (LPCTSTR)_T("<") ).IsEmpty() && 
				 ReadLine( hFile, (LPCTSTR)_T("/") ).IsEmpty() )
			{
				if ( ReadLine( hFile, (LPCTSTR)_T("/") ).MakeLower() == _T("type") )
				{
					if ( ReadLine( hFile, (LPCTSTR)_T("/") ).MakeLower() == _T("page") )
						nPages++;
				}
			}
		}
	}
	// get matadata from info object if available
	if ( nOffsetInfo != 0 )
	{
		strSeek.Format( _T("%lu 0 obj"), nOffsetInfo );
		SetFilePointer( hFile, pOffset[ nOffsetInfo ], NULL, FILE_BEGIN );
		strLine = ReadLine( hFile, (LPCTSTR)_T("<") );
		if ( strLine == strSeek ) 
		{	
			if ( !ReadLine( hFile, (LPCTSTR)_T("<") ).IsEmpty() ||
				 !ReadLine( hFile, (LPCTSTR)_T("/") ).IsEmpty() )
			{
				delete [] pOffset;
				return FALSE;
			}
			strLine = ReadLine( hFile, (LPCTSTR)_T("/>") );
			while ( !strLine.IsEmpty() )
			{
				CString strEntry;
				int nData = strLine.Find( _T("(") );
				if ( nData > 0 )
				{
					strEntry = strLine.Left( nData ).Trim().MakeLower();
					strLine = strLine.Mid( nData );
				}
				else
				{
					nData = strLine.Find( _T("<") );
					if ( nData > 0 )
					{
						strEntry = strLine.Left( nData ).Trim().MakeLower();
						strLine = strLine.Mid( nData );
					}
				}
				BOOL bHex = ( strLine.GetAt( 0 ) == '<' );
				// read further if string reading was stopped at /> characters inside parantheses
				// and restore missing character
				if ( strLine.GetAt( 0 ) == '(' && strLine.Right( 1 ) != ')' )
				{
					DWORD nRead = 1;
					while ( nRead )
					{
						CHAR cChar;
						SetFilePointer( hFile, -1, NULL, FILE_CURRENT );
						ReadFile( hFile, &cChar, 1, &nRead, NULL );
						strLine += cChar + ReadLine( hFile, (LPCTSTR)_T("/>") );
						if ( strLine.Right( 1 ) == ')' ) break;
					}
				}
				if ( strEntry == _T("title") ) 
					pXML->AddAttribute( _T("title"), DecodePDFText( strLine ) );
				else if ( strEntry == _T("author") ) 
					pXML->AddAttribute( _T("author"), DecodePDFText( strLine ) );
				else if ( strEntry == _T("subject") ) 
					pXML->AddAttribute( _T("subject"), DecodePDFText( strLine ) );
				else if ( strEntry == _T("keywords") ) 
					pXML->AddAttribute( _T("keywords"), DecodePDFText( strLine ) );
				else if ( strEntry == _T("company") )
				{
					if ( bBook )
						pXML->AddAttribute( _T("publisher"), DecodePDFText( strLine ) );
					else
						pXML->AddAttribute( _T("copyright"), DecodePDFText( strLine ) );
				}
				// if meta data hex encoded read one line more (we skipped '\r\n's )
				if ( bHex ) strLine = ReadLine( hFile, (LPCTSTR)_T("/") );
				strLine = ReadLine( hFile, (LPCTSTR)_T("/>") );
			}
		}
	}
	delete [] pOffset;	
	
	if ( nPages > 0 )
	{
		strLine.Format( _T("%lu"), nPages );
		pXML->AddAttribute( _T("pages"), strLine );
	}
	
	if ( bBook )
	{
		pXML->AddAttribute( _T("format"), _T("PDF") );
		pXML->AddAttribute( _T("back"), _T("Digital") );
		return CLibraryBuilder::SubmitMetadata( nIndex, CSchema::uriBook, pXML );
	}
	else
	{
		pXML->AddAttribute( _T("format"), _T("Adobe Acrobat PDF") );
		CString strTemp;
		strTemp.Format( _T("1.%i"), nVersion );
		pXML->AddAttribute( _T("formatVersion"), strTemp );
		return CLibraryBuilder::SubmitMetadata( nIndex, CSchema::uriDocument, pXML );
	}
}

CString	CLibraryBuilderInternals::DecodePDFText(CString& strInput)
{
	if ( strInput.GetLength() < 2 ) return strInput;

	BOOL bHex = FALSE;
	CHAR nFactor = 1;

	if ( strInput.GetAt( 0 ) == '(' && strInput.Right( 1 ) == _T(")") )
	{
		strInput = strInput.Mid( 1, strInput.GetLength() - 2 );
		// Acrobat Reader doesn't decode (<XX>) strings created 
		// by Acrobat Distiller 6 but we do
		if ( strInput.GetAt( 0 ) == '<' && strInput.Right( 1 ) == _T(">") )
		{
			bHex = TRUE; // hexadecimal encoding
			nFactor = 2;
			strInput.Replace( L"\\ ", L"" );
			strInput = strInput.Mid( 1, strInput.GetLength() - 2 );
			if ( strInput.GetLength() % 2 != 0 ) strInput.Append( _T("0") );
		}
	}
	else if ( strInput.GetAt( 0 ) == '<' )
	{
		bHex = TRUE; // hexadecimal encoding
		nFactor = 2;
		strInput.Replace( L"\\ ", L"" );
		strInput = strInput.Mid( 1, strInput.GetLength() - 1 ); // closing > was not included
		// the last zero can be omitted
		if ( strInput.GetLength() % 2 != 0 ) strInput.Append( _T("0") );
	}
	else return strInput;
	
	if ( strInput.IsEmpty() ) return strInput;

	CString strResult, strTemp;
	union U_CHAR
	{
		CHAR c[ sizeof(WCHAR) / sizeof(CHAR) ];
		WCHAR w;
	};

	bool bWide = false;
	DWORD nByte = strInput.GetLength() / nFactor; // string length in bytes

	if ( bHex && strInput.Left( 4 ) == L"FEFF" )
	{
		bWide = true;
	}

	U_CHAR* pByte = new U_CHAR[ nByte + 1 ];

	if ( bHex )
	{
		int nChar = 0;
		for ( DWORD nHex = 0 ; nHex < nByte / ( bWide ? 2 : 1 ); nHex++ )
		{
			if ( bWide )
			{
				_stscanf( strInput.Mid( nHex * 4, 4 ), _T("%x"), &nChar );
			}
			else
			{
				_stscanf( strInput.Mid( nHex * 2, 2 ), _T("%x"), &nChar );
			}
			pByte[ nHex ].w = (WCHAR)nChar;
		}
		pByte[ nByte / ( bWide ? 2 : 1 ) ].w = 0;
	}
	else
	{
		DWORD nShift = 0;
		for ( DWORD nChar = 0 ; nChar < nByte ; nChar++ )
		{
			register WCHAR nTemp = strInput.GetAt( nChar );
			if ( nTemp == '\\' && nChar + 1 < nByte )
			{
				nTemp = strInput.GetAt( nChar + 1 );
				if ( nTemp == 't' )
					pByte[ nChar - nShift ].w = '\t';
				else if ( nTemp == 'r' )
					pByte[ nChar - nShift ].w = '\r';
				else if ( nTemp == 'n' )
					pByte[ nChar - nShift ].w = '\n';
				else if ( nTemp == 'f' )
					pByte[ nChar - nShift ].w = '\f';
				else if ( nTemp == 'b' )
					pByte[ nChar - nShift ].w = '\b';
				else if ( nTemp == '\\' )
					pByte[ nChar - nShift ].w = '\\';
				else if ( nTemp == '(' )
					pByte[ nChar - nShift ].w = '(';
				else if ( nTemp == ')' )
					pByte[ nChar - nShift ].w = ')';
				else
				{
					// Octal encoding tests
					int nWChar = 0;
					if ( nChar + 3 < nByte && 
						_stscanf( strInput.Mid( nChar + 1, 3 ), _T("%o"), &nWChar ) )
					{
						pByte[ nChar - nShift ].w = WCHAR(nWChar);
						nShift += 2;
						nChar += 2;
					}
					else if ( nChar + 2 < nByte && 
						_stscanf( strInput.Mid( nChar + 1, 2 ), _T("%o"), &nWChar ) )
					{
						pByte[ nChar - nShift ].w = WCHAR(nWChar);
						nShift++;
						nChar++;
					}
					else if ( _stscanf( strInput.Mid( nChar + 1, 1 ), _T("%o"), &nWChar ) )
					{
						pByte[ nChar - nShift ].w = WCHAR(nWChar);
					}
					// backslash with a space is ignored--the backslash at the end just breaks a line
					// (we replaced separators while reading a file)
					else if ( strInput.Mid( nChar + 1, 1 ) != L" " )
					{
						// if everything else only backslash is ignored
						nShift++;
						continue;
					}
					else nShift++;
				}
				nShift++;
				nChar++;
			}
			else
				pByte[ nChar - nShift ].w = nTemp;
		}
		nByte -= nShift;
	}

	short bCharsToMove = 0;

	if ( nByte > 2 )
	{
		if ( ( pByte[0].c[0] == 0xFE && pByte[0].c[1] == 0xFF ) )
			bCharsToMove = 1;
		else if ( ( pByte[0].w == 0xFE && pByte[1].w == 0xFF ) )
			bCharsToMove = 2;
	}

	// Unicode decoding -- only Big Endian encoding is available and no UTF-8 ?
	// At least I couldn't find and it's not mentioned in specs (Rolandas)
	if ( bCharsToMove )
	{
		pByte += bCharsToMove;

		if ( bWide )
		{
			nByte = nByte - bCharsToMove;
			CopyMemory( strResult.GetBuffer( nByte ), (LPCSTR)pByte, nByte * sizeof(TCHAR) );
			strResult.ReleaseBuffer( nByte );
		}
		else
		{
			nByte = ( nByte - bCharsToMove ) / 2;
			U_CHAR* pszDest = new U_CHAR[ nByte + 1 ];

			for ( DWORD nPos = 0 ; nPos < nByte ; nPos++ )
			{
				pszDest[ nPos ].c[ 0 ] = pByte[ ( nPos << 1 ) + 1 ].c[ 0 ];
				pszDest[ nPos ].c[ 1 ] = pByte[ ( nPos << 1 ) ].c[ 0 ];
			}

			CopyMemory( strResult.GetBuffer( nByte ), (LPCSTR)pszDest, nByte * sizeof(TCHAR) );
			strResult.ReleaseBuffer( nByte );
			delete [] pszDest;
		}

		pByte -= bCharsToMove;
	}
	else 
	{
		CopyMemory( strResult.GetBuffer( nByte ), (LPCSTR)pByte, nByte * 2 );
		strResult.ReleaseBuffer( nByte );
	}
	if ( pByte ) delete [] pByte;

	// strip off language and country codes
	// could be usefull in the future...
	int nEscapeStart = 0;
	do
	{
		nEscapeStart = strResult.Find( L"\x001B" );
		if ( nEscapeStart != -1 )
		{
			int nEscapeEnd = strResult.Find( L"\x001B", nEscapeStart + 1 );
			if ( nEscapeEnd != -1 )
				strResult = strResult.Left( nEscapeStart - 1 ) + strResult.Mid( nEscapeEnd + 1 );
			else
				strResult = strResult.Mid( nEscapeStart + 1 );
		}
	}
	while ( nEscapeStart != -1 );

	return strResult.Trim();
}

CString CLibraryBuilderInternals::ReadLine(HANDLE hFile, LPCTSTR pszSeparators)
{
	DWORD nRead, nLength;
	TCHAR cChar = 0;
	CString str;

	for ( nLength = 0 ; ReadFile( hFile, &cChar, 1, &nRead, NULL ) && nRead == 1 && nLength++ < 4096 ; )
	{
		if ( !pszSeparators )
		{
			// lines can end with \r, \n or \r\n
			if ( cChar == '\n' ) break;
			if ( cChar == '\r' )
			{
				ReadFile( hFile, &cChar, 1, &nRead, NULL );
				if ( cChar != '\n' ) 
					SetFilePointer( hFile, -1, NULL, FILE_CURRENT );
				break;
			}
		}
		else
		{
			if ( cChar && _tcschr( pszSeparators, cChar ) != NULL ) break;
			if ( cChar == '\n' || cChar == '\r' ) cChar = ' ';
		}
		str += cChar;
	}

	str.TrimLeft();

	// workaround to trim from right if zero bytes are present
	// between the beginning and the end
	nLength = str.GetLength();
	while ( nLength && str.GetAt( nLength - 1 ) == ' ' )
	{
		str = str.Left( nLength - 1 );
		nLength--;
	}
	return str;
}

CString CLibraryBuilderInternals::ReadLineReverse(HANDLE hFile, LPCTSTR pszSeparators)
{
	DWORD nRead, nLength;
	TCHAR cChar;
	CString str;
	
	ZeroMemory( &cChar, sizeof(cChar) );
	for ( nLength = 0 ; ReadFile( hFile, &cChar, 1, &nRead, NULL ) && nRead == 1 && nLength++ < 4096 ; )
	{
		if ( SetFilePointer( hFile, -2, NULL, FILE_CURRENT ) == 0 ) break;
		if ( !pszSeparators )
		{
			// lines can end with \r, \n or \r\n
			if ( cChar == '\r' ) break;
			if ( cChar == '\n' )
			{
				ReadFile( hFile, &cChar, 1, &nRead, NULL );
				if ( cChar == '\r' ) 
					SetFilePointer( hFile, -2, NULL, FILE_CURRENT );
				else
					SetFilePointer( hFile, -1, NULL, FILE_CURRENT );
				break;
			}
		}
		else
		{
			if ( cChar && _tcschr( pszSeparators, cChar ) != NULL ) break;
			if ( cChar == '\n' || cChar == '\r' ) cChar = ' ';
		}
		str = cChar + str;
	}
	
	str.TrimLeft();

	// workaround to trim from right if zero bytes are present
	// between the beginning and the end
	nLength = str.GetLength();
	while ( nLength && str.GetAt( nLength - 1 ) == ' ' )
	{
		str = str.Left( nLength - 1 );
		nLength--;
	}
	return str;
}

//////////////////////////////////////////////////////////////////////
// CLibraryBuilderInternals Collection (threaded)

BOOL CLibraryBuilderInternals::ReadCollection(DWORD nIndex, HANDLE hFile, const Hashes::Sha1Hash& oSHA1)
{
	CCollectionFile pCollection;
	if ( ! pCollection.Attach( hFile ) ) return FALSE;
	
	LibraryFolders.MountCollection( oSHA1, &pCollection );
	
	if ( CXMLElement* pMetadata = pCollection.GetMetadata() )
	{
		pMetadata = pMetadata->GetFirstElement()->Clone();
		return CLibraryBuilder::SubmitMetadata( nIndex, pCollection.GetThisURI(), pMetadata );
	}
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CLibraryBuilderInternals CHM (threaded)

BOOL CLibraryBuilderInternals::ReadCHM(DWORD nIndex, HANDLE hFile, LPCTSTR pszPath)
{
	CHAR szMagic[4];
	DWORD nVersion, nIHDRSize, nLCID, nRead, nPos, nComprVersion;
	QWORD nContentOffset;
	const DWORD MAX_LENGTH_ALLOWED = 8192;
	
	SetFilePointer( hFile, 0, NULL, FILE_BEGIN );
	ReadFile( hFile, szMagic, 4, &nRead, NULL );
	
	if ( nRead != 4 || strncmp( szMagic, "ITSF", 4 ) )
		return CLibraryBuilder::SubmitCorrupted( nIndex );
	if ( GetFileSize( hFile, NULL ) < 510 ) return CLibraryBuilder::SubmitCorrupted( nIndex );

	// Get CHM file version number
	ReadFile( hFile, &nVersion, sizeof(nVersion), &nRead, NULL );
	if ( nRead != sizeof(nVersion) || nVersion < 3 )
		return FALSE; // In Version 2 files, content section data offset is not there

	// Get initial header size
	ReadFile( hFile, &nIHDRSize, sizeof(nIHDRSize), &nRead, NULL );
	if ( nRead != sizeof(nIHDRSize) || nIHDRSize == 0 ) return CLibraryBuilder::SubmitCorrupted( nIndex );
	nPos = nIHDRSize - sizeof(nContentOffset);

	// Get Windows LCID of machine on which the file was compiled;
	// Always located at offset 20
	SetFilePointer( hFile, 20, NULL, FILE_BEGIN );
	ReadFile( hFile, &nLCID, sizeof(nLCID), &nRead, NULL );
	if ( nRead != sizeof(nLCID) ) return CLibraryBuilder::SubmitCorrupted( nIndex );
	if ( !IsValidLocale( nLCID, LCID_SUPPORTED ) ) nLCID = 1033;

	// Read the last qword from the end of header; it contains content section data offset
	SetFilePointer( hFile, nPos, NULL, FILE_BEGIN );
	ReadFile( hFile, &nContentOffset, sizeof(nContentOffset), &nRead, NULL );
	if ( nRead != sizeof(nContentOffset) ) return CLibraryBuilder::SubmitCorrupted( nIndex );
	if ( nContentOffset == 0 ) return FALSE;

	// Go to compressed control data and check version;
	// Content section data always takes 110 bytes (?)
	nContentOffset += 110;
	DWORD nError = NO_ERROR;
	DWORD nSizeLow	= (DWORD)( nContentOffset & 0xFFFFFFFF );
	DWORD nSizeHigh	= (DWORD)( nContentOffset >> 32 );

	nSizeLow = SetFilePointer( hFile, nSizeLow, (long*)&nSizeHigh, FILE_BEGIN );
	if ( nSizeLow == INVALID_SET_FILE_POINTER && 
		 ( nError = GetLastError() ) != NO_ERROR ) return CLibraryBuilder::SubmitCorrupted( nIndex );
	ReadFile( hFile, szMagic, 4, &nRead, NULL );
	if ( nRead != 4 || strncmp( szMagic, "LZXC", 4 ) ) // compression method
		return FALSE;
	ReadFile( hFile, &nComprVersion, sizeof(nComprVersion), &nRead, NULL );
	if ( nRead != sizeof(nComprVersion) || nComprVersion != 2 ) // Note: MS Reader books has version 3
		return FALSE;

	// Read no more than 8192 bytes to find "HHA Version" string
	CHAR szByte[1];
	CHAR szFragment[10] = {}; // // "HA Version" string
	BOOL bCorrupted = FALSE;
	BOOL bHFound = FALSE;
	int nFragmentPos = 0;

	for ( nPos = 0; ReadFile( hFile, &szByte, 1, &nRead, NULL ) && nPos++ < MAX_LENGTH_ALLOWED ; )
	{
		if ( nRead != 1 ) 
		{
			bCorrupted = TRUE;
			break;
		}
		if ( szByte[0] == 'H' )
		{
			nFragmentPos = 0;
			szFragment[0] = 'H';
			bHFound = TRUE;
		}
		else
		{
			nFragmentPos++;
			if ( bHFound ) 
			{
				if ( IsCharacter( szByte[0] ) ) 
					szFragment[ nFragmentPos ] = szByte[0];
				else
					szFragment[ nFragmentPos ] = ' ';
			}
		}
		if ( nFragmentPos == 9 )
		{
			if ( !strncmp( szFragment, "HA Version", 10 ) ) 
			{
				// Remember position two words before; 
				// the second word is data entry length
				nPos = SetFilePointer( hFile, 0, NULL, FILE_CURRENT ) - 15;
				break;
			}
			else
			{
				nFragmentPos = 0;
				bHFound = FALSE;
			}
		}
	}
	if ( bCorrupted ) 
	{
		return CLibraryBuilder::SubmitCorrupted( nIndex );
	}
	if ( strncmp( szFragment, "HA Version", 10 ) && nPos == MAX_LENGTH_ALLOWED + 1 )
	{
		return FALSE;
	}

	// Collect author, title if file name contains "book" keyword
	CString strLine;
	BOOL bBook = ( _tcsistr( pszPath, _T("book") ) != NULL );
	
	CXMLElement* pXML = new CXMLElement( NULL, bBook ? _T("book") : _T("wordprocessing") );
	
	if ( LPCTSTR pszName = _tcsrchr( pszPath, '\\' ) )
	{
		pszName++;
		
		if ( _tcsnicmp( pszName, _T("ebook - "), 8 ) == 0 )
		{
			strLine = pszName + 8;
			strLine = strLine.SpanExcluding( _T(".") );
			strLine.TrimLeft();
			strLine.TrimRight();
			pXML->AddAttribute( _T("title"), strLine );
		}
		else if ( _tcsnicmp( pszName, _T("(ebook"), 6 ) == 0 )
		{
			if ( ( pszName = _tcschr( pszName, ')' ) ) != NULL )
			{
				if ( _tcsncmp( pszName, _T(") - "), 4 ) == 0 )
					strLine = pszName + 4;
				else
					strLine = pszName + 1;
				strLine = strLine.SpanExcluding( _T(".") );
				strLine.TrimLeft();
				strLine.TrimRight();
				pXML->AddAttribute( _T("title"), strLine );
			}
		}
	}

	// Meta data extraction
	WORD nData;
	CHARSETINFO csInfo;
	CString strTemp;
	TCHAR *pszBuffer = NULL;
	UINT nCodePage = CP_ACP;
	DWORD nCwc;
	DWORD_PTR charSet = DEFAULT_CHARSET;
	BOOL bHasTitle = FALSE;

	// Find default ANSI codepage for given LCID
	DWORD nLength = GetLocaleInfo( nLCID, LOCALE_IDEFAULTANSICODEPAGE, NULL, 0 );
	pszBuffer = (TCHAR*)LocalAlloc( LPTR, ( nLength + 1 ) * sizeof(TCHAR) );
	nCwc = GetLocaleInfo( nLCID, LOCALE_IDEFAULTANSICODEPAGE, pszBuffer, nLength );
	if ( nCwc > 0 )
	{	
		CString strTemp = pszBuffer;
		strTemp = strTemp.Left( nCwc - 1 );
		_stscanf( strTemp, _T("%lu"), &charSet );
		if ( TranslateCharsetInfo( (LPDWORD)charSet, &csInfo, TCI_SRCCODEPAGE ) )
			nCodePage = csInfo.ciACP;
	}
	SetFilePointer( hFile, nPos, NULL, FILE_BEGIN );

	for ( int nCount = 1 ; nCount < 5 && !bCorrupted ; nCount++ ) // nCount may be up to 6
	{
		// Unknown data
		ReadFile( hFile, &nData, sizeof(nData), &nRead, NULL );
		if ( nRead != sizeof(nData) ) bCorrupted = TRUE;

		// Entry length
		ReadFile( hFile, &nData, sizeof(nData), &nRead, NULL );
		if ( nRead != sizeof(nData) ) bCorrupted = TRUE;
		if ( nData == 0 ) break;
		if ( bCorrupted ) nData = 1;

		CHAR* szMetadata = new CHAR[ nData ];
		ReadFile( hFile, szMetadata, nData, &nRead, NULL );
		if ( nRead != nData ) bCorrupted = TRUE;

		if ( nCount == 2 ) 
		{
			delete [] szMetadata;
			continue;
		}
		
		// Convert meta data string from ANSI to unicode
		int nWide = MultiByteToWideChar( nCodePage, 0, szMetadata, nData, NULL, 0 );
		LPWSTR pszOutput = strLine.GetBuffer( nWide + 1 );
		MultiByteToWideChar( nCodePage, 0, szMetadata, nData, pszOutput, nWide );
		pszOutput[ nWide ] = 0;
		strLine.ReleaseBuffer();
		strLine.Trim();

		int nPos;

		switch ( nCount )
		{
			case 1: // version number
				nPos = strLine.ReverseFind( ' ' );
				strLine = strLine.Mid( nPos + 1 );
				if ( !bBook ) pXML->AddAttribute( _T("formatVersion"), strLine );
			break;
			case 2: // unknown data
			break;
			case 3: // redirection url
				ToLower( strLine );
				if ( strLine.Left( 7 ) == _T("ms-its:") )
				{
					nPos = strLine.Find( _T("::"), 7 );
					strTemp = _tcsrchr( pszPath, '\\' );
					strTemp = strTemp.Mid( 1 );
					ToLower( strTemp );
					if ( strLine.Mid( 7, nPos - 7 ).Trim() != strTemp )
						bCorrupted = TRUE; // it requires additional file
				}
				else if ( strLine.Left( 7 ) == _T("http://") )
					bCorrupted = TRUE; // redirects to external resource; may be dangerous
			break;
			case 4: // title
				if ( strLine.IsEmpty() ) break;
				nPos = strLine.Find( ',' );
				strTemp = strLine.Left( nPos );
				ToLower( strTemp );
				if ( strLine.CompareNoCase( _T("htmlhelp") ) != 0 &&
					 strTemp != _T("arial") && strTemp != _T("tahoma") &&
					 strTemp != _T("times new roman") && strTemp != _T("verdana") &&
					 strLine.CompareNoCase( _T("windows") ) != 0 )
				{
					bHasTitle = TRUE;
					nPos = strLine.ReverseFind( '\\' ); // remove paths in title
					strLine = strLine.Mid( nPos + 1 );
					pXML->AddAttribute( _T("title"), strLine );
				}
			break;
		}
		delete [] szMetadata;
		if ( bCorrupted ) 
		{
			delete pXML;
			return CLibraryBuilder::SubmitCorrupted( nIndex );
		}
	}

	if ( !bHasTitle ) 
	{
		delete pXML;
		return FALSE;
	}

	pXML->AddAttribute( _T("format"), _T("Compiled HTML Help") );
	if ( bBook )
	{
		pXML->AddAttribute( _T("back"), _T("Digital") );
		strTemp = CSchema::uriBook;
	}
	else
		strTemp = CSchema::uriDocument;

	return CLibraryBuilder::SubmitMetadata( nIndex, strTemp, pXML );
}