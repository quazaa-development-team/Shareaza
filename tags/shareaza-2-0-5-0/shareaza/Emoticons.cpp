//
// Emoticons.cpp
//
// Copyright (c) Shareaza Development Team, 2002-2004.
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
#include "Emoticons.h"
#include "ImageServices.h"
#include "ImageFile.h"
#include "XML.h"

#include "RichDocument.h"
#include "RichElement.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

CEmoticons Emoticons;


//////////////////////////////////////////////////////////////////////
// CEmoticons construction

CEmoticons::CEmoticons()
{
	m_pTokens = NULL;
}

CEmoticons::~CEmoticons()
{
	Clear();
}

//////////////////////////////////////////////////////////////////////
// CEmoticons find next token and index

LPCTSTR CEmoticons::FindNext(LPCTSTR pszText, int* pnIndex)
{
	LPCTSTR pszBest = NULL;
	int nIndex = 0, nBest;
	
	if ( m_pTokens == NULL ) return NULL;
	
	for ( LPCTSTR pszToken = m_pTokens ; *pszToken ; nIndex++ )
	{
		LPCTSTR pszFind = _tcsstr( pszText, pszToken );
		
		if ( pszFind != NULL && ( pszBest == NULL || pszFind < pszBest ) )
		{
			pszBest = pszFind;
			nBest = nIndex;
		}
		
		pszToken += _tcslen( pszToken ) + 1;
	}
	
	if ( pszBest && pnIndex ) *pnIndex = nBest;
	
	return pszBest;
}

//////////////////////////////////////////////////////////////////////
// CEmoticons lookup index from text

int CEmoticons::Lookup(LPCTSTR pszText, int nLen) const
{
	TCHAR cSave = 0;
	int nIndex = 0;
	
	if ( m_pTokens == NULL ) return -1;
	
	if ( nLen >= 0 )
	{
		cSave = pszText[ nLen ];
		((LPTSTR)pszText)[ nLen ] = 0;
	}
	
	for ( LPCTSTR pszToken = m_pTokens ; *pszToken ; nIndex++ )
	{
		if ( _tcscmp( pszToken, pszText ) == 0 )
		{
			break;
		}
		
		pszToken += _tcslen( pszToken ) + 1;
	}
	
	if ( nLen >= 0 ) ((LPTSTR)pszText)[ nLen ] = cSave;
	
	return ( *pszToken != 0 ) ? nIndex : -1;
}

//////////////////////////////////////////////////////////////////////
// CEmoticons get the text for an index

LPCTSTR	CEmoticons::GetText(int nIndex) const
{
	if ( m_pTokens == NULL ) return NULL;
	
	for ( LPCTSTR pszToken = m_pTokens ; *pszToken ; )
	{
		if ( nIndex-- <= 0 ) return pszToken;
		
		pszToken += _tcslen( pszToken ) + 1;
	}
	
	return NULL;
}

//////////////////////////////////////////////////////////////////////
// CEmoticons draw

void CEmoticons::Draw(CDC* pDC, int nIndex, int nX, int nY, COLORREF crBack)
{
	if ( m_pTokens == NULL ) return;
	ImageList_DrawEx( m_pImage.m_hImageList, nIndex, pDC->GetSafeHdc(),
		nX, nY, 16, 16, crBack, CLR_DEFAULT, ILD_NORMAL );
	// if ( crBack != CLR_NONE ) pDC->ExcludeClipRect( nX, nY, nX + 16, nY + 16 );
}

//////////////////////////////////////////////////////////////////////
// CEmoticons menu

CMenu* CEmoticons::CreateMenu()
{
	CMenu* pMenu = new CMenu();
	pMenu->CreatePopupMenu();
	
	int nCount = 0;
	
	for ( int nPos = 0 ; nPos < m_pButtons.GetSize() ; nPos++ )
	{
		int nIndex = m_pButtons.GetAt( nPos );
		
		if ( nCount > 0 && ( nCount % 12 ) == 0 )
		{
			pMenu->AppendMenu( MF_OWNERDRAW|MF_MENUBREAK, nIndex + 1, (LPCTSTR)NULL );
		}
		else
		{
			pMenu->AppendMenu( MF_OWNERDRAW, nIndex + 1, (LPCTSTR)NULL );
		}
		
		nCount++;
	}
	
	return pMenu;
}

//////////////////////////////////////////////////////////////////////
// CEmoticons load

BOOL CEmoticons::Load()
{
	Clear();
	m_pImage.Create( 16, 16, ILC_COLOR32|ILC_MASK, 1, 8 );
	
	CString strFile = Settings.General.Path + _T("\\Data\\Emoticons.xml");
	
	BOOL bSuccess = LoadTrillian( strFile );
	if ( ! bSuccess ) return FALSE;
	
	BuildTokens();
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CEmoticons clear

void CEmoticons::Clear()
{
	if ( m_pImage.m_hImageList != NULL ) m_pImage.DeleteImageList();
	
	if ( m_pTokens != NULL ) delete [] m_pTokens;
	m_pTokens = NULL;
	
	m_pIndex.RemoveAll();
	m_pButtons.RemoveAll();
}

//////////////////////////////////////////////////////////////////////
// CEmoticons add an emoticon

int CEmoticons::AddEmoticon(LPCTSTR pszText, CImageFile* pImage, CRect* pRect, COLORREF crBack, BOOL bButton)
{
	ASSERT( pImage->m_bLoaded && pImage->m_nComponents == 3 );
	
	if ( pRect->left < 0 || pRect->left + 16 > pImage->m_nWidth ) return -1;
	if ( pRect->top < 0 || pRect->top > pImage->m_nHeight + 16 ) return -1;
	if ( pRect->right != pRect->left + 16 ) return -1;
	if ( pRect->bottom != pRect->top + 16 ) return -1;
	
	DWORD nPitch = pImage->m_nWidth * pImage->m_nComponents;
	while ( nPitch & 3 ) nPitch++;
	
	BYTE* pSource = pImage->m_pImage;
	pSource += pRect->top * nPitch + pRect->left * pImage->m_nComponents;
	
	HDC hDC = GetDC( 0 );
	CBitmap bmImage;

	bmImage.CreateCompatibleBitmap( CDC::FromHandle( hDC ), 16, 16 );
	
	BITMAPINFOHEADER pInfo;
	pInfo.biSize		= sizeof(BITMAPINFOHEADER);
	pInfo.biWidth		= 16;
	pInfo.biHeight		= 16;
	pInfo.biPlanes		= 1;
	pInfo.biBitCount	= 24;
	pInfo.biCompression	= BI_RGB;
	pInfo.biSizeImage	= 16 * 16 * 3;
	
	for ( int nY = 15 ; nY >= 0 ; nY-- )
	{
		SetDIBits( hDC, bmImage, nY, 1, pSource, (BITMAPINFO*)&pInfo, DIB_RGB_COLORS );
		pSource += nPitch;
	}
	
	ReleaseDC( 0, hDC );
	int nIndex = m_pImage.Add( &bmImage, crBack );
	bmImage.DeleteObject();
	
	m_pIndex.Add( pszText );
	if ( bButton ) m_pButtons.Add( nIndex );
	
	return nIndex;
}

//////////////////////////////////////////////////////////////////////
// CEmoticons build tokens

void CEmoticons::BuildTokens()
{
	int nLength = 2;
	
	for ( int nIndex = 0 ; nIndex < m_pIndex.GetSize() ; nIndex++ )
	{
		nLength += m_pIndex.GetAt( nIndex ).GetLength() + 1;
	}
	
	ASSERT( m_pTokens == NULL );
	LPTSTR pszOut = m_pTokens = new TCHAR[ nLength ];
	
	for ( nIndex = 0 ; nIndex < m_pIndex.GetSize() ; nIndex++ )
	{
		_tcscpy( pszOut, m_pIndex.GetAt( nIndex ) );
		pszOut += m_pIndex.GetAt( nIndex ).GetLength() + 1;
	}
	
	*pszOut++ = 0;
}

//////////////////////////////////////////////////////////////////////
// CEmoticons load Trillian XML

BOOL CEmoticons::LoadTrillian(LPCTSTR pszFile)
{
	CString strPath, strValue;
	
	CXMLElement* pXML = CXMLElement::FromFile( pszFile, TRUE );
	if ( pXML == NULL ) return FALSE;
	
	strPath = pszFile;
	int nSlash = strPath.ReverseFind( '\\' );
	if ( nSlash >= 0 ) strPath = strPath.Left( nSlash + 1 );
	
	CXMLElement* pBitmap = pXML->GetElementByName( _T("bitmap") );
	
	if ( pBitmap == NULL )
	{
		delete pXML;
		return FALSE;
	}
	
	strValue = pBitmap->GetAttributeValue( _T("file") );
	
	nSlash = strValue.ReverseFind( '/' );
	if ( nSlash >= 0 ) strValue = strValue.Mid( nSlash + 1 );
	strValue = strPath + strValue;
	
	CImageServices pServices;
	CImageFile pImage( &pServices );
	
	if (	! pImage.LoadFromFile( strValue ) ||
			! pImage.EnsureRGB( GetSysColor( COLOR_WINDOW ) ) ||
			! pImage.SwapRGB() )
	{
		delete pXML;
		return FALSE;
	}
	
	COLORREF crBack = RGB( pImage.m_pImage[2], pImage.m_pImage[1], pImage.m_pImage[0] );
	
	for ( POSITION pos = pXML->GetElementIterator() ; pos ; )
	{
		CXMLElement* pEmoticon = pXML->GetNextElement( pos );
		if ( ! pEmoticon->IsNamed( _T("emoticon") ) ) continue;
		
		CXMLElement* pSource = pEmoticon->GetElementByName( _T("source") );
		CString strText = pEmoticon->GetAttributeValue( _T("text") );
		CRect rc( 0, 0, 0, 0 );
		
		strValue = pSource->GetAttributeValue( _T("left"), _T("0") );
		_stscanf( strValue, _T("%i"), &rc.left );
		strValue = pSource->GetAttributeValue( _T("top"), _T("0") );
		_stscanf( strValue, _T("%i"), &rc.top );
		strValue = pSource->GetAttributeValue( _T("right"), _T("0") );
		_stscanf( strValue, _T("%i"), &rc.right );
		strValue = pSource->GetAttributeValue( _T("bottom"), _T("0") );
		_stscanf( strValue, _T("%i"), &rc.bottom );
		
		BOOL bButton = pEmoticon->GetAttributeValue( _T("button") ).CompareNoCase( _T("yes") ) == 0;
		
		AddEmoticon( strText, &pImage, &rc, crBack, bButton );
	}
	
	delete pXML;
	
	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CEmoticons rich text formatting

void CEmoticons::FormatText(CRichDocument* pDocument, LPCTSTR pszBody, BOOL bNewlines)
{
	static LPCTSTR pszURLs[] = { _T("\r\n"), _T("http://"), _T("magnet:?"), _T("gnutella:"), _T("gnet:"), _T("ftp://"), _T("raza:"), _T("shareaza:"), _T("ed2k://"), _T("sig2dat:"), _T("www."), NULL };
	BOOL bBold = FALSE, bItalic = FALSE, bUnderline = FALSE;
	COLORREF cr = 0;
	CString str;
	
	while ( *pszBody )
	{
		LPCTSTR pszToken = _tcschr( pszBody, '[' );
		
		for ( int nURL = 0 ; pszURLs[ nURL ] != NULL ; nURL++ )
		{
			LPCTSTR pszFind = _tcsistr( pszBody, pszURLs[ nURL ] );
			if ( pszFind != NULL && ( pszToken == NULL || pszFind < pszToken ) ) pszToken = pszFind;
		}
		
		int nEmoticon = -1;
		LPCTSTR pszEmoticon = FindNext( pszBody, &nEmoticon );
		
		if ( pszEmoticon != NULL && ( pszToken == NULL || pszEmoticon < pszToken ) )
		{
			pszToken = pszEmoticon;
		}
		
		if ( pszToken != pszBody )
		{
			if ( pszToken != NULL )
			{
				TCHAR cSave = *pszToken;
				*(LPTSTR)pszToken = 0;
				str = pszBody;
				*(LPTSTR)pszToken = cSave;
			}
			else
			{
				str = pszBody;
			}
			
			pDocument->Add( retText, str, NULL,
				( bBold ? retfBold : 0 ) |
				( bItalic ? retfItalic : 0 ) |
				( bUnderline ? retfUnderline : 0 ) |
				( cr ? retfColour : 0 ) )->m_cColour = cr;
		}
		
		if ( pszToken == NULL ) break;
		
		pszBody = pszToken;
		if ( *pszBody == 0 ) break;
		
		if ( pszEmoticon == pszBody )
		{
			str.Format( _T("%lu"), nEmoticon );
			pDocument->Add( retEmoticon, str );
			pszBody += _tcslen( GetText( nEmoticon ) );
			continue;
		}
		else if ( pszBody[0] == '\r' && pszBody[1] == '\n' )
		{
			if ( bNewlines )
			{
				pDocument->Add( retNewline, _T("4") );
			}
			
			pszBody += 2;
			continue;
		}
		else if ( *pszBody != '[' )
		{
			for ( ; *pszToken ; pszToken++ )
			{
				if ( ! _istalnum( *pszToken ) &&
					_tcschr( _T(":@/?=&%._-+;~#"), *pszToken ) == NULL )
				{
					break;
				}
			}
			
			TCHAR cSave = *pszToken;
			*(LPTSTR)pszToken = 0;
			str = pszBody;
			*(LPTSTR)pszToken = cSave;
			
			if ( _tcsnicmp( str, _T("www."), 4 ) == 0 ) str = _T("http://") + str;
			
			pDocument->Add( retLink, str, str,
				( bBold ? retfBold : 0 ) |
				( bItalic ? retfItalic : 0 ) |
				( bUnderline ? retfUnderline : 0 ) );
			
			pszBody = pszToken;
		}
		else if ( _tcsnicmp( pszBody, _T("[b]"), 3 ) == 0 )
		{
			bBold = TRUE;
		}
		else if ( _tcsnicmp( pszBody, _T("[/b]"), 4 ) == 0 )
		{
			bBold = FALSE;
		}
		else if ( _tcsnicmp( pszBody, _T("[i]"), 3 ) == 0 )
		{
			bItalic = TRUE;
		}
		else if ( _tcsnicmp( pszBody, _T("[/i]"), 4 ) == 0 )
		{
			bItalic = FALSE;
		}
		else if ( _tcsnicmp( pszBody, _T("[u]"), 3 ) == 0 )
		{
			bUnderline = TRUE;
		}
		else if ( _tcsnicmp( pszBody, _T("[/u]"), 4 ) == 0 )
		{
			bUnderline = FALSE;
		}
		else if ( _tcsnicmp( pszBody, _T("[/c]"), 4 ) == 0 )
		{
			cr = 0;
		}
		else if ( _tcsnicmp( pszBody, _T("[c:#"), 4 ) == 0 && _tcslen( pszBody ) >= 4 + 6 + 1 )
		{
			_tcsncpy( str.GetBuffer( 6 ), pszBody + 4, 6 );
			str.ReleaseBuffer( 6 );
			int nRed, nGreen, nBlue;
			_stscanf( str.Mid( 0, 2 ), _T("%x"), &nRed );
			_stscanf( str.Mid( 2, 2 ), _T("%x"), &nGreen );
			_stscanf( str.Mid( 4, 2 ), _T("%x"), &nBlue );
			cr = RGB( nRed, nGreen, nBlue );
		}
		
		if ( *pszBody == '[' )
		{
			pszToken = _tcschr( pszBody, ']' );
			if ( pszToken != NULL ) pszBody = pszToken + 1;
			else pszBody ++;
		}
	}
}
