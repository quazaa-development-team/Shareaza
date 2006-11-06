////////////////////////////////////////////////////////////////////////////////
//                                                                            //
// StdAfx.h                                                                   //
//                                                                            //
// Copyright (C) 2002-2005 Shareaza Development Team.                         //
// This file is part of SHAREAZA (www.shareaza.com).                          //
//                                                                            //
// Shareaza is free software; you can redistribute it                         //
// and/or modify it under the terms of the GNU General Public License         //
// as published by the Free Software Foundation; either version 2 of          //
// the License, or (at your option) any later version.                        //
//                                                                            //
// Shareaza is distributed in the hope that it will be useful,                //
// but WITHOUT ANY WARRANTY; without even the implied warranty of             //
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.                       //
// See the GNU General Public License for more details.                       //
//                                                                            //
// You should have received a copy of the GNU General Public License          //
// along with Shareaza; if not, write to the                                  //
// Free Software Foundation, Inc,                                             //
// 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA                    //
//                                                                            //
////////////////////////////////////////////////////////////////////////////////

//! \file       StdAfx.h
//! \brief      Standard header for prcompiled header feature.
//!
//! Includes MFC header files. Contains several global definitions.

#pragma once

//
// Configuration
//
#if 1
#if _MSC_VER > 1310
// 64bit related - need to be fixed
#pragma warning ( disable : 4302 4311 4312 )
// general - fix where feasable then move to useless
#pragma warning ( disable : 4061 4127 4191 4244 4263 4264 4265 4266 4296 4365 4555 4571 4640 4668 4686 4946 )
#pragma warning ( disable : 4548 )
// copy/asignment-related
#pragma warning ( disable : 4512 4625 4626 )
// behaviour change - check for regression
#pragma warning ( disable : 4347 4350 4351 )
// padding
#pragma warning ( disable : 4820 )
// useless
#pragma warning ( disable : 4514 4710 4711 )

#define _SCL_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE
#define _CRT_NON_CONFORMING_SWPRINTFS
#else
// 64bit related - need to be fixed
#pragma warning ( disable : 4302 4311 4312 )
// general - fix where feasable then move to useless
#pragma warning ( disable : 4061 4127 4191 4244 4263 4264 4265 4296 4529 4548 4555 4640 4668 4686 4946 )
// copy/asignment-related
#pragma warning ( disable : 4511 4512 4625 4626 )
// behaviour change - check for regression
#pragma warning ( disable : 4347 )
// padding
#pragma warning ( disable : 4820 )
// useless
#pragma warning ( disable : 4217 4514 4619 4702 4710 4711 )
#endif
#endif

const bool SHAREAZA_RESTRICT_WP64 = true;
// allow min to return the smaller type if called with unsigned arguments ?
const bool SHAREAZA_ADVANCED_MIN_TEMPLATE = true;

#define WINVER			0x0500		//!< Windows Version
#define _WIN32_WINDOWS	0x0500		//!< Windows Version
#define _WIN32_WINNT	0x0500		//!< NT Version
#define _WIN32_IE		0x0500		//!< IE Version
#define _WIN32_DCOM					//!< DCOM
#define _AFX_NO_RICHEDIT_SUPPORT	//!< No RichEdit

//
// MFC
//

#pragma warning( push, 0 )

#include <afxwin.h>         // MFC core and standard components
#include <afxext.h>         // MFC extensions
#include <afxcmn.h>			// MFC support for Windows Common Controls
#include <afxtempl.h>		// MFC templates
#include <afxmt.h>			// MFC threads
#include <afxole.h>			// MFC OLE
#include <afxocc.h>			// MDC OCC
#include <afxhtml.h>		// MFC HTML

//
// WIN32
//

#include <winsock2.h>		// Windows sockets V2
#include <objbase.h>		// OLE
#include <shlobj.h>			// Shell objects
#include <wininet.h>		// Internet
#include <ddeml.h>			// DDE
#include <math.h>			// Math

#undef IDC_HAND

#include <afxpriv.h>
#include <..\src\mfc\afximpl.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <exdispid.h>
#include <mmsystem.h>
#include <winioctl.h>
#include <zlib.h>
#include <atltime.h>

// If this header is not found, you'll need to install the Windows XP SP2 Platform SDK (or later)
// from http://www.microsoft.com/msdownload/platformsdk/sdkupdate/

#include <netfw.h>
#include <upnp.h>
#include <natupnp.h>
#include <iphlpapi.h>

#pragma warning( pop )

//
// Missing constants
//

#define BIF_NEWDIALOGSTYLE	0x0040
#define OFN_ENABLESIZING	0x00800000

// MFC changed resulttype of CWnd::OnNcHitTest method
#if _MSC_VER <= 1310
typedef UINT ONNCHITTESTRESULT;
// broken standard auto_ptr fix
#pragma warning ( disable : 4239 )
#else
typedef LRESULT ONNCHITTESTRESULT;
#endif

//
// Standard headers
//

#include "CommonInclude.hpp"

//
// 64-bit type
//

typedef unsigned __int64 QWORD;

//
// Tristate type
//

typedef int TRISTATE;

const TRISTATE TS_UNKNOWN = 0;
const TRISTATE TS_FALSE   = 1;
const TRISTATE TS_TRUE    = 2;

// CArchive operators to help replacing TRISTATE with safer and more convenient tribools
inline CArchive& operator<<(CArchive& ar, const boost::logic::tribool& rhs)
{
	TRISTATE value = rhs ? TS_TRUE : !rhs ? TS_FALSE : TS_UNKNOWN;
	return ar << value;
};
inline CArchive& operator>>(CArchive& ar, boost::logic::tribool& rhs)
{
	using boost::logic::tribool;
	TRISTATE value;
	ar >> value;
	rhs = value == TS_TRUE
		? tribool( true )
		: value == TS_FALSE
			? tribool( false )
			: boost::logic::indeterminate;
	return ar;
};

const uint64 SIZE_UNKNOWN = ~0ull;

//
// Protocol IDs
//

enum PROTOCOLID
{
	PROTOCOL_ANY  = -1,
	PROTOCOL_NULL = 0,
	PROTOCOL_G1   = 1,
	PROTOCOL_G2   = 2,
	PROTOCOL_ED2K = 3,
	PROTOCOL_HTTP = 4,
	PROTOCOL_FTP  = 5,
	PROTOCOL_BT   = 6
};
inline PROTOCOLID& operator++(PROTOCOLID& arg)
{
	ASSERT( arg < PROTOCOL_BT );
	arg = PROTOCOLID( arg + 1 );
	return arg;
}
inline PROTOCOLID& operator--(PROTOCOLID& arg)
{
	ASSERT( arg > PROTOCOL_ANY );
	arg = PROTOCOLID( arg - 1 );
	return arg;
}
inline CArchive& operator<<(CArchive& ar, const PROTOCOLID& rhs)
{
	int value = rhs;
	return ar << value;
};
inline CArchive& operator>>(CArchive& ar, PROTOCOLID& rhs)
{
	int value;
	ar >> value;
	if ( !( value >= PROTOCOL_ANY && value <= PROTOCOL_BT ) )
		AfxThrowUserException();
	rhs = value >= PROTOCOL_ANY && value <= PROTOCOL_BT
		? PROTOCOLID( value )
		: PROTOCOL_NULL;
	return ar;
};


class CQuickLock
{
public:
	explicit CQuickLock(CSyncObject& oMutex) : m_oMutex( oMutex ) { oMutex.Lock(); }
	~CQuickLock() { m_oMutex.Unlock(); }
private:
	CSyncObject& m_oMutex;
	CQuickLock(const CQuickLock&);
	CQuickLock& operator=(const CQuickLock&);
	static void* operator new(std::size_t);
	static void* operator new[](std::size_t);
	static void operator delete(void*);
	static void operator delete[](void*);
	CQuickLock* operator&() const;
};

template< class T >
class CGuarded
{
public:
	explicit CGuarded() : m_oSection(), m_oValue() { }
	explicit CGuarded(const CGuarded& other) : m_oSection(), m_oValue( other ) { }
	CGuarded(const T& oValue) : m_oSection(), m_oValue( oValue ) { }
	CGuarded& operator=(const T& oValue)
	{
		CQuickLock oLock( m_oSection );
		m_oValue = oValue;
		return *this;
	}
	operator T() const
	{
		CQuickLock oLock( m_oSection );
		return m_oValue;
	}
private:
	mutable CCriticalSection m_oSection;
	T m_oValue;
	CGuarded* operator&() const; // too unsafe
};

class CLowerCaseTable
{
public:
	explicit CLowerCaseTable()
	{
		for ( size_t i = 0; i < 65536; ++i ) cTable[ i ] = TCHAR( i );
		cTable[ 65536 ] = 0;
		CharLower( &cTable[ 1 ] );
		cTable[ 304 ] = 105; // turkish capital I with dot is converted to "i"
		// convert fullwidth latin characters to halfwidth
		for ( size_t i = 65281 ; i < 65313 ; ++i ) cTable[ i ] = TCHAR( i - 65248 );
		for ( size_t i = 65313 ; i < 65339 ; ++i ) cTable[ i ] = TCHAR( i - 65216 );
		for ( size_t i = 65339 ; i < 65375 ; ++i ) cTable[ i ] = TCHAR( i - 65248 );
		// convert circled katakana to ordinary katakana
		for ( size_t i = 13008 ; i < 13028 ; ++i ) cTable[ i ] = TCHAR( 2 * i - 13566 );
		for ( size_t i = 13028 ; i < 13033 ; ++i ) cTable[ i ] = TCHAR( i - 538 );
		for ( size_t i = 13033 ; i < 13038 ; ++i ) cTable[ i ] = TCHAR( 3 * i - 26604 );
		for ( size_t i = 13038 ; i < 13043 ; ++i ) cTable[ i ] = TCHAR( i - 528 );
		for ( size_t i = 13043 ; i < 13046 ; ++i ) cTable[ i ] = TCHAR( 2 * i - 13571 );
		for ( size_t i = 13046 ; i < 13051 ; ++i ) cTable[ i ] = TCHAR( i - 525 );
		cTable[ 13051 ] = TCHAR( 12527 );
		for ( size_t i = 13052 ; i < 13055 ; ++i ) cTable[ i ] = TCHAR( i - 524 );
		// map Katakana middle dot to space, since no API identifies it as a punctuation
		cTable[ 12539 ] = cTable[ 65381 ] = L' ';
		// map CJK Fullwidth space to halfwidth space
		cTable[ 12288 ] = L' ';
		// convert japanese halfwidth sound marks to fullwidth
		// all forms should be mapped; we need NFKD here
		cTable[ 65392 ] = TCHAR( 12540 );
		cTable[ 65438 ] = TCHAR( 12441 );
		cTable[ 65439 ] = TCHAR( 12442 );
	};
	const TCHAR& operator()(const TCHAR cLookup) const { return cTable[ cLookup ]; }
	CString& operator()(CString& strSource) const
	{
		const int nLength = strSource.GetLength();
		const LPTSTR str = strSource.GetBuffer() + nLength;
		for ( int i = -nLength; i; ++i ) str[ i ] = ( *this )( str[ i ] );
		if ( str[ -1 ] == 0x3c3 ) str[ -1 ] = 0x3c2; // last greek sigma fix
		strSource.ReleaseBuffer( nLength );
		return strSource;
	}
	const TCHAR& operator[](const TCHAR cLookup) const { return ( *this )( cLookup ); }
private:
	TCHAR cTable[ 65537 ];
};

extern const CLowerCaseTable ToLower;

inline void SetThreadName(DWORD dwThreadID, LPCSTR szThreadName)
{
#ifndef NDEBUG
	struct
	{
		DWORD dwType;		// must be 0x1000
		LPCSTR szName;		// pointer to name (in user addr space)
		DWORD dwThreadID;	// thread ID (-1=caller thread)
		DWORD dwFlags;		// reserved for future use, must be zero
	} info =
	{
		0x1000,
		szThreadName,
		dwThreadID,
		0
	};


	__try
	{
		RaiseException( 0x406D1388, 0, sizeof info / sizeof( DWORD ), (ULONG_PTR*)&info );
	}
	__except( EXCEPTION_CONTINUE_EXECUTION )
	{
	}
#endif
	UNUSED_ALWAYS(dwThreadID);
	UNUSED_ALWAYS(szThreadName);
}
