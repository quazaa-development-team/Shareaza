//
// Strings.cpp
//
// Copyright (c) Shareaza Development Team, 2010-2011.
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
#include "Strings.h"

bool IsCharacter(const WCHAR nChar)
{
	WORD nCharType = 0;

	if ( GetStringTypeW( CT_CTYPE3, &nChar, 1, &nCharType ) )
		return ( nCharType & C3_ALPHA
			|| ( ( nCharType & ( C3_KATAKANA | C3_HIRAGANA ) ) && ( nCharType & C3_DIACRITIC ) )
			|| iswdigit( nChar ) );

	return false;
}

bool IsHiragana(const WCHAR nChar)
{
	WORD nCharType = 0;

	if ( GetStringTypeW( CT_CTYPE3, &nChar, 1, &nCharType ) )
		return ( nCharType & C3_HIRAGANA ) != 0;

	return false;
}

bool IsKatakana(const WCHAR nChar)
{
	WORD nCharType = 0;

	if ( GetStringTypeW( CT_CTYPE3, &nChar, 1, &nCharType ) )
		return ( nCharType & C3_KATAKANA ) != 0;

	return false;
}

bool IsKanji(const WCHAR nChar)
{
	WORD nCharType = 0;

	if ( GetStringTypeW( CT_CTYPE3, &nChar, 1, &nCharType ) )
		return ( nCharType & C3_IDEOGRAPH ) != 0;

	return false;
}

bool IsWord(LPCTSTR pszString, size_t nStart, size_t nLength)
{
	for ( pszString += nStart ; *pszString && nLength ; ++pszString, --nLength )
	{
		if ( _istdigit( *pszString ) )
			return false;
	}
	return true;
}

void IsType(LPCTSTR pszString, size_t nStart, size_t nLength, bool& bWord, bool& bDigit, bool& bMix)
{
	bWord = false;
	bDigit = false;
	for ( pszString += nStart ; *pszString && nLength ; ++pszString, --nLength )
	{
		if ( _istdigit( *pszString ) )
			bDigit = true;
		else if ( IsCharacter( *pszString ) )
			bWord = true;
	}

	bMix = bWord && bDigit;
	if ( bMix )
	{
		bWord = false;
		bDigit = false;
	}
}

const CLowerCaseTable ToLower;

CLowerCaseTable::CLowerCaseTable()
{
	for ( size_t i = 0; i < 65536; ++i ) cTable[ i ] = TCHAR( i );
	VERIFY( CharLowerBuff( cTable, 65536 ) == 65536 );
	
	cTable[ 0x0130 ] = 0x0069;	// Turkish Capital I with dot above to Latin Small I

	cTable[ 0x03A3 ] = 0x03C3;	// Greek Capital Sigma to Greek Small Sigma
	cTable[ 0x03C2 ] = 0x03C3;	// Greek Small Final Sigma to Greek Small Sigma

	cTable[ 0x0401 ] = 0x0435;	// Russian Capital Io to Russian Small Ie
	cTable[ 0x0451 ] = 0x0435;	// Russian Small Io to Russian Small Ie
	cTable[ 0x0419 ] = 0x0438;	// Russian Capital Short I to Russian Small I
	cTable[ 0x0439 ] = 0x0438;	// Russian Small Short I to Russian Small I

	// Convert fullwidth latin characters to halfwidth
	for ( size_t i = 65281 ; i < 65313 ; ++i ) cTable[ i ] = TCHAR( i - 65248 );
	for ( size_t i = 65313 ; i < 65339 ; ++i ) cTable[ i ] = TCHAR( i - 65216 );
	for ( size_t i = 65339 ; i < 65375 ; ++i ) cTable[ i ] = TCHAR( i - 65248 );

	// Convert circled katakana to ordinary katakana
	for ( size_t i = 13008 ; i < 13028 ; ++i ) cTable[ i ] = TCHAR( 2 * i - 13566 );
	for ( size_t i = 13028 ; i < 13033 ; ++i ) cTable[ i ] = TCHAR( i - 538 );
	for ( size_t i = 13033 ; i < 13038 ; ++i ) cTable[ i ] = TCHAR( 3 * i - 26604 );
	for ( size_t i = 13038 ; i < 13043 ; ++i ) cTable[ i ] = TCHAR( i - 528 );
	for ( size_t i = 13043 ; i < 13046 ; ++i ) cTable[ i ] = TCHAR( 2 * i - 13571 );
	for ( size_t i = 13046 ; i < 13051 ; ++i ) cTable[ i ] = TCHAR( i - 525 );
	cTable[ 13051 ] = TCHAR( 12527 );
	for ( size_t i = 13052 ; i < 13055 ; ++i ) cTable[ i ] = TCHAR( i - 524 );

	// Map Katakana middle dot to space, since no API identifies it as a punctuation
	cTable[ 12539 ] = cTable[ 65381 ] = L' ';

	// Map CJK Fullwidth space to halfwidth space
	cTable[ 12288 ] = L' ';

	// Convert japanese halfwidth sound marks to fullwidth
	// all forms should be mapped; we need NFKD here
	cTable[ 65392 ] = TCHAR( 12540 );
	cTable[ 65438 ] = TCHAR( 12443 );
	cTable[ 65439 ] = TCHAR( 12444 );
}

TCHAR CLowerCaseTable::operator()(TCHAR cLookup) const
{
	if ( cLookup <= 127 )
	{
		// A..Z -> a..z
		if ( cLookup >= _T('A') && cLookup <= _T('Z') )
			return (TCHAR)( cLookup + 32 );
		else
			return cLookup;
	}
	else
		return cTable[ cLookup ];
}

CString& CLowerCaseTable::operator()(CString& strSource) const
{
	const int nLength = strSource.GetLength();
	LPTSTR str = strSource.GetBuffer();
	for ( int i = 0; i < nLength; ++i, ++str )
	{
		TCHAR cLookup = *str;
		if ( cLookup <= 127 )
		{
			// A..Z -> a..z
			if ( cLookup >= _T('A') && cLookup <= _T('Z') )
				*str = (TCHAR)( cLookup + 32 );
		}
		else
			*str = cTable[ cLookup ];
	}
	strSource.ReleaseBuffer( nLength );

	return strSource;
}

CStringA UTF8Encode(__in const CStringW& strInput)
{
	return UTF8Encode( strInput, strInput.GetLength() );
}

CStringA UTF8Encode(__in_bcount(nInput) LPCWSTR psInput, __in int nInput)
{
	CStringA strUTF8;
	int nUTF8 = ::WideCharToMultiByte( CP_UTF8, 0, psInput, nInput,
		strUTF8.GetBuffer( nInput * 4 + 1 ), nInput * 4 + 1, NULL, NULL );

	if ( nUTF8 == 0 && GetLastError() == ERROR_INSUFFICIENT_BUFFER )
	{
		nUTF8 = ::WideCharToMultiByte( CP_UTF8, 0, psInput, nInput,
			NULL, 0, NULL, NULL );

		nUTF8 = ::WideCharToMultiByte( CP_UTF8, 0, psInput, nInput,
			strUTF8.GetBuffer( nUTF8 ), nUTF8, NULL, NULL );
	}
	strUTF8.ReleaseBuffer( nUTF8 );

	return strUTF8;
}

CStringW UTF8Decode(__in const CStringA& strInput)
{
	return UTF8Decode( strInput, strInput.GetLength() );
}

CStringW UTF8Decode(__in_bcount(nInput) LPCSTR psInput, __in int nInput)
{
	CStringW strWide;

	// Try UTF-8
	int nWide = ::MultiByteToWideChar( CP_UTF8, MB_ERR_INVALID_CHARS,
		psInput, nInput, NULL, 0 );
	if ( nWide > 0 )
	{
		nWide = ::MultiByteToWideChar( CP_UTF8, 0, psInput, nInput,
			strWide.GetBuffer( nWide ), nWide );
		strWide.ReleaseBuffer( nWide );
		return strWide;
	}

	// Try ANSI
	nWide = ::MultiByteToWideChar( CP_ACP, MB_ERR_INVALID_CHARS,
		psInput, nInput, NULL, 0 );
	if ( nWide > 0 )
	{
		nWide = ::MultiByteToWideChar( CP_ACP, 0, psInput, nInput,
			strWide.GetBuffer( nWide ), nWide );
		strWide.ReleaseBuffer( nWide );
		return strWide;
	}

	// As-is
	return CString( psInput, nInput );
}

// Encodes unsafe characters in a string, turning "hello world" into "hello%20world", for instance
// Takes text and returns a string
CString URLEncode(LPCTSTR pszInputT)
{
	// Setup two strings, one with all the hexidecimal digits, the other with all the characters to find and encode
	static LPCTSTR pszHex	= _T("0123456789ABCDEF");	// A string with all the hexidecimal digits
	static LPCSTR pszUnsafe	= "<>\"#%{}|\\^~[]+?&@=:,$";// A string with all the characters unsafe for a URL

	// The output string starts blank
	CString strOutput;

	// If the input character pointer points to null or points to the null terminator, just return the blank output string
	if ( pszInputT == NULL || *pszInputT == 0 ) return strOutput;

	// Map the wide character string to a new character set
	int nUTF8 = WideCharToMultiByte(
		CP_UTF8,	// Translate using UTF-8, the default encoding for Unicode
		0,			// Must be 0 for UTF-8 encoding
		pszInputT,	// Points to the wide character string to be converted
		-1,			// The string is null terminated
		NULL,		// We just want to find out how long the buffer for the output string needs to be
		0,
		NULL,		// Both must be NULL for UTF-8 encoding
		NULL );

	// If the converted text would take less than 2 bytes, which is 1 character, just return blank
	if ( nUTF8 < 2 ) return strOutput;

	// Make a new array of CHARs which is nUTF8 bytes long
	LPSTR pszUTF8 = new CHAR[ static_cast< UINT>( nUTF8 ) ];

	// Call WideCharToMultiByte again, this time it has the output buffer and will actually do the conversion
	WideCharToMultiByte( CP_UTF8, 0, pszInputT, -1, pszUTF8, nUTF8, NULL, NULL );

	// Set the null terminator in pszUTF8 to right where you think it should be, and point a new character pointer at it
	pszUTF8[ nUTF8 - 1 ] = 0;
	LPCSTR pszInput = pszUTF8;

	// Get the character buffer inside the output string, specifying how much larger to make it
	LPTSTR pszOutput = strOutput.GetBuffer( static_cast< int >( ( nUTF8 - 1 ) * 3 + 1 ) ); // Times 3 in case every character gets encoded

	// Loop for each character of input text
	for ( ; *pszInput ; pszInput++ )
	{
		// If the character code is 32 or less, more than 127, or in the unsafe list
		if ( *pszInput <= 32 || *pszInput > 127 || strchr( pszUnsafe, *pszInput ) != NULL )
		{
			// Write a three letter code for it like %20 in the output text
			*pszOutput++ = _T('%');
			*pszOutput++ = pszHex[ ( *pszInput >> 4 ) & 0x0F ];
			*pszOutput++ = pszHex[ *pszInput & 0x0F ];

		} // The character doesn't need to be encoded
		else
		{
			// Just copy it across
			*pszOutput++ = (TCHAR)*pszInput;
		}
	}

	// Null terminate the output text, and then close our direct manipulation of the string
	*pszOutput = 0;
	strOutput.ReleaseBuffer(); // This closes the string so Windows can again start managing its memory for us

	// Free the memory we allocated with the new keyword above
	delete [] pszUTF8;


	// Return the URL-encoded, %20-filled text
	return strOutput;
}

CString URLDecode(__in_bcount(nInput) LPCSTR psInput, __in int nInput)
{
	return URLDecode( (LPCTSTR)UTF8Decode( psInput, nInput ) );
}

CString URLDecode(__in const CStringA& strInput)
{
	return URLDecode( (LPCTSTR)UTF8Decode( strInput ) );
}

// Decodes unsafe characters in a string, turning "hello%20world" into "hello world", for instance
// Takes text and returns a string
CString URLDecode(LPCTSTR pszInput)
{
	LPCTSTR pszLoop = pszInput;
	// Check each character of input text
	for ( ; *pszLoop ; pszLoop++ )
	{
		if ( *pszLoop > 255 )
		{
			// This URI is not properly encoded, and has unicode characters in it. URL-decode only
			return URLDecodeUnicode( pszInput );
		}
	}

	// This is a correctly formatted URI, which must be url-decoded, then UTF-8 decoded.
	return URLDecodeANSI( pszInput );
}

// Decodes a properly formatted URI, then UTF-8 decodes it
CString URLDecodeANSI(LPCTSTR pszInput)
{
	TCHAR szHex[3] = { 0, 0, 0 };	// A 3 character long array filled with 3 null terminators
	CStringA strOutput;				// The output string, which starts out blank
	int nHex;						// The hex code of the character we found

	int nLength = (int)_tcslen( pszInput );
	LPSTR pszOutput = strOutput.GetBuffer( nLength + 1 );

	// Loop for each character of input text
	for ( ; *pszInput ; pszInput++ )
	{
		// We hit a %, which might be the start of something like %20
		if ( *pszInput == '%' )
		{
			if ( ( szHex[0] = pszInput[1] ) != 0 &&
				 ( szHex[1] = pszInput[2] ) != 0 &&
				 _stscanf( szHex, _T("%x"), &nHex ) == 1 &&
				 nHex > 0 )
			{
				*pszOutput++ = (CHAR)nHex;
				pszInput += 2;
			}
			else
			{
				*pszOutput++ = '%';
			}
		} // We hit a +, which is shorthand for space
		else if ( *pszInput == '+' )
		{
			// Add a space to the output text, and move the pointer forward
			*pszOutput++ = ' ';
		}
		else if ( *pszInput == '&' )
		{
			if ( _tcsnicmp( pszInput + 1, _T("amp;"), 4 ) == 0 )
			{
				*pszOutput++ = '&';
				pszInput += 4;
			}
			else if ( _tcsnicmp( pszInput + 1, _T("lt;"), 3 ) == 0 )
			{
				*pszOutput++ = '<';
				pszInput += 3;
			}
			else if ( _tcsnicmp( pszInput + 1, _T("gt;"), 3 ) == 0 )
			{
				*pszOutput++ = '>';
				pszInput += 3;
			}
			else if ( _tcsnicmp( pszInput + 1, _T("quot;"), 5 ) == 0 )
			{
				*pszOutput++ = '\"';
				pszInput += 5;
			}
			else if ( _tcsnicmp( pszInput + 1, _T("apos;"), 5 ) == 0 )
			{
				*pszOutput++ = '\'';
				pszInput += 5;
			}
			else if ( _tcsnicmp( pszInput + 1, _T("nbsp;"), 5 ) == 0 )
			{
				*pszOutput++ = ' ';
				pszInput += 5;
			}
			else if ( pszInput[ 1 ] == '#' &&
				_stscanf( pszInput + 2, _T("%lu;"), &nHex ) == 1 &&
				nHex > 0 )
			{
				*pszOutput++ = (CHAR)nHex;
				while ( *pszInput && *pszInput != ';' ) ++pszInput;
			}
			else
			{
				*pszOutput++ = '&';
			}
		} // The input pointer is just on a normal character
		else
		{
			// Copy it across
			*pszOutput++ = (CHAR)*pszInput;
		}
	}

	*pszOutput = 0;
	strOutput.ReleaseBuffer();
	return UTF8Decode( strOutput );
}

// Decodes encoded characters in a unicode string
CString URLDecodeUnicode(LPCTSTR pszInput)
{
	TCHAR szHex[3] = { 0, 0, 0 };	// A 3 character long array filled with 3 null terminators
	CString strOutput;				// The output string, which starts out blank
	int nHex;						// The hex code of the character we found

	int nLength = (int)_tcslen( pszInput );
	LPTSTR pszOutput = strOutput.GetBuffer( nLength + 1 );

	for ( ; *pszInput ; ++pszInput )
	{
		// We hit a %, which might be the start of something like %20
		if ( *pszInput == '%' )
		{
			if ( ( szHex[0] = pszInput[1] ) != 0 &&
				( szHex[1] = pszInput[2] ) != 0 &&
				_stscanf( szHex, _T("%x"), &nHex ) == 1 &&
				nHex > 0 )
			{
				*pszOutput++ = (TCHAR)nHex;
				pszInput += 2;
			}
			else
			{
				*pszOutput++ = '%';
			}
		} // We hit a +, which is shorthand for space
		else if ( *pszInput == '+' )
		{
			// Add a space to the output text, and move the pointer forward
			*pszOutput++ = ' ';
		}
		else if ( *pszInput == '&' )
		{
			if ( _tcsnicmp( pszInput + 1, _T("amp;"), 4 ) == 0 )
			{
				*pszOutput++ = '&';
				pszInput += 4;
			}
			else if ( _tcsnicmp( pszInput + 1, _T("lt;"), 3 ) == 0 )
			{
				*pszOutput++ = '<';
				pszInput += 3;
			}
			else if ( _tcsnicmp( pszInput + 1, _T("gt;"), 3 ) == 0 )
			{
				*pszOutput++ = '>';
				pszInput += 3;
			}
			else if ( _tcsnicmp( pszInput + 1, _T("quot;"), 5 ) == 0 )
			{
				*pszOutput++ = '\"';
				pszInput += 5;
			}
			else if ( _tcsnicmp( pszInput + 1, _T("apos;"), 5 ) == 0 )
			{
				*pszOutput++ = '\'';
				pszInput += 5;
			}
			else if ( _tcsnicmp( pszInput + 1, _T("nbsp;"), 5 ) == 0 )
			{
				*pszOutput++ = ' ';
				pszInput += 5;
			}
			else if ( pszInput[ 1 ] == '#' &&
				_stscanf( pszInput + 2, _T("%lu;"), &nHex ) == 1 &&
				nHex > 0 )
			{
				*pszOutput++ = (TCHAR)nHex;
				while ( *pszInput && *pszInput != ';' ) ++pszInput;
			}
			else
			{
				*pszOutput++ = '&';
			}
		} // The input pointer is just on a normal character
		else
		{
			// Copy it across
			*pszOutput++ = (TCHAR)*pszInput;
		}
	}

	*pszOutput = 0;
	strOutput.ReleaseBuffer();
	return strOutput;
}

LPCTSTR _tcsistr(LPCTSTR pszString, LPCTSTR pszSubString)
{
	// Return null if string or substring is empty
	if ( !*pszString || !*pszSubString )
		return NULL;

	// Return if string is too small to hold the substring
	size_t nString( _tcslen( pszString ) );
	size_t nSubString( _tcslen( pszSubString ) );
	if ( nString < nSubString )
		return NULL;

	// Get the first character from the substring and lowercase it
	const TCHAR cFirstPatternChar = ToLower( *pszSubString );

	// Loop over the part of the string that the substring could fit into
	LPCTSTR pszCutOff = pszString + nString - nSubString;
	while ( pszString <= pszCutOff )
	{
		// Search for the start of the substring
		while ( pszString <= pszCutOff
			&& ToLower( *pszString ) != cFirstPatternChar )
		{
			++pszString;
		}

		// Exit loop if no match found
		if ( pszString > pszCutOff )
			break;

		// Check the rest of the substring
		size_t nChar( 1 );
		while ( pszSubString[nChar]
			&& ToLower( pszString[nChar] ) == ToLower( pszSubString[nChar] ) )
		{
			++nChar;
		}

		// If the substring matched return a pointer to the start of the match
		if ( !pszSubString[nChar] )
			return pszString;

		// Move on to the next character and continue search
		++pszString;
	}

	// No match found, return a null pointer
	return NULL;
}

LPCTSTR _tcsnistr(LPCTSTR pszString, LPCTSTR pszSubString, size_t nlen)
{
	if ( ! *pszString || ! *pszSubString || ! nlen ) return NULL;

	const TCHAR cFirstPatternChar = ToLower( *pszSubString );

	for ( ; ; ++pszString )
	{
		while ( *pszString && ToLower( *pszSubString )
			!= cFirstPatternChar ) ++pszString;

		if ( !*pszString )
			return NULL;

		DWORD i = 0;
		while ( ++i < nlen )
		{
			if ( const TCHAR cStringChar = ToLower( pszString[ i ] ) )
			{
				if ( cStringChar != ToLower( pszSubString[ i ] ) )
					break;
			}
			else
			{
				return NULL;
			}
		}

		if ( i == nlen )
			return pszString;
	}
}

__int64 atoin(__in_bcount(nLen) const char* pszString, __in size_t nLen)
{
	__int64 nNum = 0;
	for ( size_t i = 0; i < nLen; ++i )
	{
		if ( pszString[ i ] < '0' || pszString[ i ] > '9' )
			return -1;
		nNum = nNum * 10 + ( pszString[ i ] - '0' );
	}
	return nNum;
}

void Split(const CString& strSource, TCHAR cDelimiter, CStringArray& pAddIt, BOOL bAddFirstEmpty)
{
	for ( LPCTSTR start = strSource; *start; start++ )
	{
		LPCTSTR c = _tcschr( start, cDelimiter );
		int len = c ? (int) ( c - start ) : (int) _tcslen( start );
		if ( len > 0 )
			pAddIt.Add( CString( start, len ) );
		else
			if ( bAddFirstEmpty && ( start == strSource ) )
				pAddIt.Add( CString() );
		if ( ! c )
			break;
		start = c;
	}
}

BOOL StartsWith(const CString& sInput, LPCTSTR pszText, size_t nLen)
{
	return ( (size_t)sInput.GetLength() >= nLen ) &&
		! _tcsnicmp( (LPCTSTR)sInput, pszText, nLen );
}

CString LoadFile(LPCTSTR pszPath)
{
	CString strXML;

	CFile pFile;
	if ( ! pFile.Open( pszPath, CFile::modeRead ) )
		// File open error
		return strXML;

	DWORD nByte = (DWORD)pFile.GetLength();
	if ( nByte > 4096 * 1024 )
		// Too big file (> 4 MB)
		return strXML;

	BYTE* pBuf = new BYTE[ nByte ];
	try
	{
		pFile.Read( pBuf, nByte );
	}
	catch ( CException* pException )
	{
		// File read error
		pFile.Abort();
		pException->Delete();
		delete [] pBuf;
		return strXML;
	}
	pFile.Close();

	BYTE* pByte = pBuf;
	if ( nByte >= 2 &&
		( ( pByte[0] == 0xFE && pByte[1] == 0xFF ) ||
		  ( pByte[0] == 0xFF && pByte[1] == 0xFE ) ) )
	{
		nByte = nByte / 2 - 1;
		if ( pByte[0] == 0xFE && pByte[1] == 0xFF )
		{
			pByte += 2;
			for ( DWORD nSwap = 0 ; nSwap < nByte ; nSwap ++ )
			{
				register CHAR nTemp = pByte[ ( nSwap << 1 ) + 0 ];
				pByte[ ( nSwap << 1 ) + 0 ] = pByte[ ( nSwap << 1 ) + 1 ];
				pByte[ ( nSwap << 1 ) + 1 ] = nTemp;
			}
		}
		else
		{
			pByte += 2; 
		}

		CopyMemory( strXML.GetBuffer( nByte ), pByte, nByte * sizeof( TCHAR ) );
		strXML.ReleaseBuffer( nByte );
	}
	else
	{
		if ( nByte >= 3 && pByte[0] == 0xEF && pByte[1] == 0xBB && pByte[2] == 0xBF )
		{
			pByte += 3;
			nByte -= 3;
		}

		strXML = UTF8Decode( (LPCSTR)pByte, nByte );
	}
	delete [] pBuf;

	return strXML;
}

BOOL ReplaceNoCase(CString& sInStr, LPCTSTR pszOldStr, LPCTSTR pszNewStr)
{
	BOOL bModified = FALSE;
	DWORD nInLength = sInStr.GetLength();
	LPCTSTR pszInStr = sInStr;

	CString result;
	result.Preallocate( nInLength );

	TCHAR nOldChar = pszOldStr[ 0 ];
	for ( DWORD nPos = 0; nPos < nInLength; )
	{
		TCHAR nChar = pszInStr[ nPos ];
		if ( ToLower( nChar ) == nOldChar )
		{
			DWORD nOffset = 0;
			while ( TCHAR nChar2 = pszOldStr[ ++nOffset ] )
			{
				if ( nChar2 != ToLower( pszInStr[ nPos + nOffset ] ) ) goto fail;
			}
			nPos += nOffset;
			result.Append( pszNewStr );
			bModified = TRUE;
		}
		else
		{
fail:
			result.AppendChar( nChar );
			++nPos;
		}
	}

	sInStr = result;

	return bModified;
}

CString HostToString(const SOCKADDR_IN* pHost)
{
	CString sHost;
	sHost.Format( _T("%s:%hu"), CString( inet_ntoa( pHost->sin_addr ) ), ntohs( pHost->sin_port ) );
	return sHost;
}