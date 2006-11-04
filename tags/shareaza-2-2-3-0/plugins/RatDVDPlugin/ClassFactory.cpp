//
// ClassFactory.cpp
//
//	Date:			"$Date: $"
//	Revision:		"$Revision: 1.0 $"
//  Last change by:	"$Author: rolandas $"
//	Created by:		Rolandas Rudomanskis
//
// Copyright (c) Shareaza Development Team, 2002-2006.
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

#pragma once
#include "stdafx.h"
#include "Globals.h"
#include "RatDVDPlugin.h"
#include "shareaza_i.c"

////////////////////////////////////////////////////////////////////////
// CRatDVDClassFactory - IClassFactory Implementation
//
//  This is a fairly simple CF. We don't provide support for licensing
//  in this sample, nor aggregation. We just create and return a new 
//  CRatDVDPlugin object.
//

////////////////////////////////////////////////////////////////////////
// QueryInterface
//

STDMETHODIMP CRatDVDClassFactory::QueryInterface(REFIID riid, void** ppv)
{
	ODS("CRatDVDClassFactory::QueryInterface\n");
	CHECK_NULL_RETURN(ppv, E_POINTER);
	
	if ( CLSID_RatDVDReader == riid )
	{
		*ppv = this;
		this->AddRef();
		return S_OK;
	}
	*ppv = NULL;
	return E_NOINTERFACE;
}

////////////////////////////////////////////////////////////////////////
// AddRef
//
STDMETHODIMP_(ULONG) CRatDVDClassFactory::AddRef(void)
{
	TRACE1("CRatDVDClassFactory::AddRef - %d\n", m_cRef + 1);
    return ++m_cRef;
}

////////////////////////////////////////////////////////////////////////
// Release
//
STDMETHODIMP_(ULONG) CRatDVDClassFactory::Release(void)
{
	TRACE1("CRatDVDClassFactory::Release - %d\n", m_cRef - 1);
    if ( 0 != --m_cRef ) return m_cRef;

	ODS("CRatDVDClassFactory delete\n");
    LockServer(FALSE);
    return 0;
}

////////////////////////////////////////////////////////////////////////
// IClassFactory
//
////////////////////////////////////////////////////////////////////////
// CreateInstance
//
STDMETHODIMP CRatDVDClassFactory::CreateInstance(LPUNKNOWN punk, REFIID riid, void** ppv)
{
	HRESULT hr;

	ODS("CFileClassFactory::CreateInstance\n");
	CHECK_NULL_RETURN(ppv, E_POINTER);	*ppv = NULL;

 // This version does not support Aggregation...
	if (punk) return CLASS_E_NOAGGREGATION;

	if ( IID_ILibraryBuilderPlugin == riid || IID_IImageServicePlugin == riid )
	{
		CComObject<CRatDVDPlugin>*pRatDVDPlugin = new CComObject<CRatDVDPlugin>;

		CHECK_NULL_RETURN(pRatDVDPlugin, E_OUTOFMEMORY);
		hr = pRatDVDPlugin->QueryInterface( IID_IUnknown, ppv );
		if ( SUCCEEDED(hr) )
		{
			if ( IID_ILibraryBuilderPlugin == riid )
				*ppv = dynamic_cast<ILibraryBuilderPlugin*>(pRatDVDPlugin);
			else
				*ppv = dynamic_cast<IImageServicePlugin*>(pRatDVDPlugin);
		}
		else return hr;
	}
	else return E_NOINTERFACE;

	LockServer(TRUE); // on success, bump up the lock count

	return hr;
}

////////////////////////////////////////////////////////////////////////
// LockServer
//
STDMETHODIMP CRatDVDClassFactory::LockServer(BOOL fLock)
{
	TRACE1("CRatDVDClassFactory::LockServer - %d\n", fLock);
	if (fLock) DllAddRef();	else DllRelease();
	return S_OK;
}

