//
// Emoticons.h
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

#if !defined(AFX_EMOTICONS_H__0EE665E3_3AD7_4BFF_B2D8_000C806D9D08__INCLUDED_)
#define AFX_EMOTICONS_H__0EE665E3_3AD7_4BFF_B2D8_000C806D9D08__INCLUDED_

#pragma once

class CImageFile;
class CRichDocument;


class CEmoticons  
{
// Construction
public:
	CEmoticons();
	virtual ~CEmoticons();
	
// Attributes
public:
	CImageList		m_pImage;
	CStringArray	m_pIndex;
	LPTSTR			m_pTokens;
	CUIntArray		m_pButtons;
	
// Operations
public:
	LPCTSTR	FindNext(LPCTSTR pszText, int* pnIndex);
	int		Lookup(LPCTSTR pszText, int nLen = -1) const;
	LPCTSTR	GetText(int nIndex) const;
	void	Draw(CDC* pDC, int nIndex, int nX, int nY, COLORREF crBack = CLR_NONE);
	CMenu*	CreateMenu();
	void	FormatText(CRichDocument* pDocument, LPCTSTR pszBody, BOOL bNewlines = FALSE);
public:
	BOOL	Load();
	void	Clear();
protected:
	int		AddEmoticon(LPCTSTR pszText, CImageFile* pImage, CRect* pRect, COLORREF crBack, BOOL bButton);
	void	BuildTokens();
	BOOL	LoadTrillian(LPCTSTR pszFile);
	
	
};

extern CEmoticons Emoticons;

#endif // !defined(AFX_EMOTICONS_H__0EE665E3_3AD7_4BFF_B2D8_000C806D9D08__INCLUDED_)