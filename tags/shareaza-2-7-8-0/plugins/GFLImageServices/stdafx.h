//
// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently,
// but are changed infrequently
//
// Copyright (c) Nikolay Raspopov, 2005-2014.
// This file is part of SHAREAZA (shareaza.sourceforge.net)
//
// GFL Library, GFL SDK and XnView
// Copyright (c) 1991-2004 Pierre-E Gougelet
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

#pragma once

#define STRICT
#define _WIN32_DCOM
#define _ATL_FREE_THREADED
#define _ATL_NO_AUTOMATIC_NAMESPACE
#define _ATL_CSTRING_EXPLICIT_CONSTRUCTORS
#define _ATL_CSTRING_NO_CRT
#define _ATL_ALL_WARNINGS

#define _WIN32_WINNT 0x0501
#include <SDKDDKVer.h>

#include "resource.h"

#include <atlbase.h>
#include <atlcom.h>
#include <atlstr.h>
#include <atlcoll.h>

#include "libgfl.h"

HRESULT SAFEgflLoadBitmap (LPCWSTR filename, GFL_BITMAP **bitmap, const GFL_LOAD_PARAMS *params, GFL_FILE_INFORMATION *info) throw ();
HRESULT SAFEgflLoadBitmapFromMemory (const GFL_UINT8 * data, GFL_UINT32 data_length, GFL_BITMAP **bitmap, const GFL_LOAD_PARAMS *params, GFL_FILE_INFORMATION *info) throw ();
HRESULT SAFEgflSaveBitmapIntoMemory (GFL_UINT8 ** data, GFL_UINT32 * data_length, const GFL_BITMAP *bitmap, const GFL_SAVE_PARAMS *params) throw ();
HRESULT SAFEgflSaveBitmap (LPCWSTR filename, const GFL_BITMAP *bitmap, const GFL_SAVE_PARAMS *params) throw ();
int GetFormatIndexByExt (LPCSTR ext);

using namespace ATL;
