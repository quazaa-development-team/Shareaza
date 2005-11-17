//
// FileExecutor.h
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

#if !defined(AFX_FILEEXECUTOR_H__FD5DD55D_4F14_48BB_B158_78680A23289F__INCLUDED_)
#define AFX_FILEEXECUTOR_H__FD5DD55D_4F14_48BB_B158_78680A23289F__INCLUDED_

#pragma once

class CMediaWnd;
class CLibraryWnd;


class CFileExecutor
{
// Operations
public:
	static BOOL		Execute(LPCTSTR pszFile, BOOL bForce = FALSE, BOOL bHasThumbnail = FALSE);
	static BOOL		Enqueue(LPCTSTR pszFiles, BOOL bForce = FALSE);
	static BOOL		ShowBitziTicket(DWORD nFile);
	static BOOL		DisplayURL(LPCTSTR pszURL);

// Implementation
protected:
	static void			GetFileComponents(LPCTSTR pszFile, CString& strPath, CString& strType);
	static CMediaWnd*	GetMediaWindow(BOOL bFocus);
	static CLibraryWnd*	GetLibraryWindow();
	static HDDEDATA CALLBACK DDECallback(UINT wType, UINT wFmt, HCONV hConv, HSZ hsz1, HSZ hsz2, HDDEDATA hData, DWORD dwData1, DWORD dwData2);

};

#endif // !defined(AFX_FILEEXECUTOR_H__FD5DD55D_4F14_48BB_B158_78680A23289F__INCLUDED_)
