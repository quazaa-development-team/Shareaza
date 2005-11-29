//
// ImageServices.cpp
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
#include "Plugins.h"
#include "ImageServices.h"
#include "ImageFile.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

IMPLEMENT_DYNAMIC(CImageServices, CComObject)

LPCTSTR RT_JPEG = _T("JPEG");
LPCTSTR RT_PNG = _T("PNG");


/////////////////////////////////////////////////////////////////////////////
// CImageServices construction

CImageServices::CImageServices()
{
	m_bCOM = GetCurrentThreadId() == AfxGetApp()->m_nThreadID;
}

CImageServices::~CImageServices()
{
	Cleanup();
}

/////////////////////////////////////////////////////////////////////////////
// CImageServices load operations

BOOL CImageServices::LoadFromMemory(CImageFile* pFile, LPCTSTR pszType, LPCVOID pData, DWORD nLength, BOOL bScanOnly, BOOL bPartialOk)
{
	IImageServicePlugin* pService = GetService( pszType );
	if ( pService == NULL ) return FALSE;
	
	IMAGESERVICEDATA pParams = {};
	pParams.cbSize		= sizeof(pParams);
	if ( bScanOnly ) pParams.nFlags |= IMAGESERVICE_SCANONLY;
	if ( bPartialOk ) pParams.nFlags |= IMAGESERVICE_PARTIAL_IN;
	
	SAFEARRAY* pInput;
	LPBYTE pTarget;
	
	if ( FAILED( SafeArrayAllocDescriptor( 1, &pInput ) ) || pInput == NULL ) return FALSE;
	
	pInput->cbElements = 1;
	pInput->rgsabound[ 0 ].lLbound = 0;
	pInput->rgsabound[ 0 ].cElements = nLength;
	SafeArrayAllocData( pInput );
	
	if ( FAILED( SafeArrayAccessData( pInput, (void HUGEP* FAR*)&pTarget ) ) ) return FALSE;
	
	CopyMemory( pTarget, pData, nLength );
	SafeArrayUnaccessData( pInput );
	
	SAFEARRAY* pArray = NULL;
	HINSTANCE hRes = AfxGetResourceHandle();
	BSTR bstrType = SysAllocString ( CT2CW (pszType));
	BOOL bSuccess = SUCCEEDED( pService->LoadFromMemory( bstrType, pInput, &pParams, &pArray ) );
	SysFreeString (bstrType);
	AfxSetResourceHandle( hRes );
	
	SafeArrayDestroy( pInput );
	
	return PostLoad( pFile, &pParams, pArray, bSuccess );
}

BOOL CImageServices::LoadFromFile(CImageFile* pFile, LPCTSTR szFilename, BOOL bScanOnly, BOOL bPartialOk)
{
	CLSID* pCLSID = NULL;
	IImageServicePlugin* pService = GetService( szFilename, &pCLSID );
	if ( pService == NULL ) return FALSE;
	
	IMAGESERVICEDATA pParams = {};
	pParams.cbSize		= sizeof(pParams);
	if ( bScanOnly ) pParams.nFlags |= IMAGESERVICE_SCANONLY;
	if ( bPartialOk ) pParams.nFlags |= IMAGESERVICE_PARTIAL_IN;
	
	SAFEARRAY* pArray	= NULL;
	HINSTANCE hRes		= AfxGetResourceHandle();
	BSTR sFile			= SysAllocString (CT2CW (szFilename));
	HRESULT hr			= pService->LoadFromFile( sFile, &pParams, &pArray );
	SysFreeString (sFile);
	AfxSetResourceHandle( hRes );
	
	if ( hr != E_NOTIMPL ) return PostLoad( pFile, &pParams, pArray, SUCCEEDED( hr ) );
	
	// Second chance - load from memory
	pFile->Clear();
	if ( pArray != NULL ) SafeArrayDestroy( pArray );
	
	BOOL bMapped = FALSE;	
	HANDLE hFile = CreateFile( szFilename, GENERIC_READ, FILE_SHARE_READ,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
	if ( hFile != INVALID_HANDLE_VALUE ) {
	HANDLE hMap = CreateFileMapping( hFile, NULL, PAGE_READONLY, 0, 0, NULL );
		if ( hMap )
		{		
			LPCVOID pBuffer = MapViewOfFile( hMap, FILE_MAP_READ, 0, 0, 0 );
			if ( pBuffer )
			{
				bMapped = LoadFromMemory( pFile, szFilename, pBuffer,
					GetFileSize (hFile, NULL), bScanOnly, bPartialOk );
				UnmapViewOfFile( pBuffer );
			}
			CloseHandle( hMap );
		}
		CloseHandle( hFile );
	}
	return bMapped;
}

/////////////////////////////////////////////////////////////////////////////
// CImageServices post load

BOOL CImageServices::PostLoad(CImageFile* pFile, IMAGESERVICEDATA* pParams, SAFEARRAY* pArray, BOOL bSuccess)
{
	pFile->Clear();

	if ( ! bSuccess )
	{
		if ( pArray != NULL ) SafeArrayDestroy( pArray );
		return FALSE;
	}

	pFile->m_bScanned		= TRUE;
	pFile->m_nWidth			= pParams->nWidth;
	pFile->m_nHeight		= pParams->nHeight;
	pFile->m_nComponents	= pParams->nComponents;

	if ( pArray == NULL ) return TRUE;
	
	pFile->m_bLoaded = TRUE;
	
	LONG nArray = 0;
	SafeArrayGetUBound( pArray, 1, &nArray );
	nArray++;
	
	LONG nFullSize = pParams->nWidth * pParams->nComponents;
	while ( nFullSize & 3 ) nFullSize++;
	nFullSize *= pParams->nHeight;
	
	if ( nArray != nFullSize )
	{
		SafeArrayDestroy( pArray );
		return FALSE;
	}
	
	pFile->m_pImage = new BYTE[ nArray ];
	
	LPBYTE pData;
	SafeArrayAccessData( pArray, (VOID**)&pData );
	CopyMemory( pFile->m_pImage, pData, nArray );
	SafeArrayUnaccessData( pArray );
	SafeArrayDestroy( pArray );
	
	return TRUE;
}

/////////////////////////////////////////////////////////////////////////////
// CImageServices save operations

BOOL CImageServices::SaveToMemory(CImageFile* pFile, LPCTSTR pszType, int nQuality, LPBYTE* ppBuffer, DWORD* pnLength)
{
	*ppBuffer = NULL;
	*pnLength = 0;
	
	IImageServicePlugin* pService = GetService( pszType );
	if ( pService == NULL ) return FALSE;
	
	SAFEARRAY* pSource = ImageToArray( pFile );
	if ( pSource == NULL ) return FALSE;
	
	IMAGESERVICEDATA pParams = {};
	pParams.cbSize		= sizeof(pParams);
	pParams.nWidth		= pFile->m_nWidth;
	pParams.nHeight		= pFile->m_nHeight;
	pParams.nComponents	= pFile->m_nComponents;
	pParams.nQuality	= nQuality;
	
	SAFEARRAY* pOutput = NULL;
	HINSTANCE hRes = AfxGetResourceHandle();
	BSTR bstrType = SysAllocString ( CT2CW (pszType));
	/*BOOL bSuccess =*/ SUCCEEDED( pService->SaveToMemory( bstrType, &pOutput, &pParams, pSource ) );
	SysFreeString (bstrType);
	AfxSetResourceHandle( hRes );
	
	SafeArrayDestroy( pSource );
	
	if ( pOutput == NULL ) return FALSE;
	
	SafeArrayGetUBound( pOutput, 1, (PLONG)pnLength );
	(*pnLength)++;

	LPBYTE pEncoded;
	SafeArrayAccessData( pOutput, (VOID**)&pEncoded );
	
	*ppBuffer = new BYTE[ *pnLength ];
	CopyMemory( *ppBuffer, pEncoded, *pnLength );
	
	SafeArrayUnaccessData( pOutput );
	SafeArrayDestroy( pOutput );
	
	return TRUE;
}

/*BOOL CImageServices::SaveToFile(CImageFile* pFile, LPCTSTR pszType, int nQuality, HANDLE hFile, DWORD* pnLength)
{
	if ( pnLength ) *pnLength = 0;
	
	IImageServicePlugin* pService = GetService( pszType );
	if ( pService == NULL ) return FALSE;
	
	SAFEARRAY* pSource = ImageToArray( pFile );
	if ( pSource == NULL ) return FALSE;
	
	IMAGESERVICEDATA pParams = {};
	pParams.cbSize		= sizeof(pParams);
	pParams.nWidth		= pFile->m_nWidth;
	pParams.nHeight		= pFile->m_nHeight;
	pParams.nComponents	= pFile->m_nComponents;
	pParams.nQuality	= nQuality;
	
	DWORD nBefore = SetFilePointer( hFile, 0, NULL, FILE_CURRENT );
	
	HINSTANCE hRes = AfxGetResourceHandle();
	BOOL bSuccess = SUCCEEDED( pService->SaveToFile( hFile, &pParams, pSource ) );
	AfxSetResourceHandle( hRes );
	
	SafeArrayDestroy( pSource );
	
	if ( pnLength )
	{
		DWORD nAfter = SetFilePointer( hFile, 0, NULL, FILE_CURRENT );
		*pnLength = nAfter - nBefore;
	}
	
	return bSuccess;
}*/

/////////////////////////////////////////////////////////////////////////////
// CImageServices pre save utility

SAFEARRAY* CImageServices::ImageToArray(CImageFile* pFile)
{
	SAFEARRAY* pOutput;
	
	if ( FAILED( SafeArrayAllocDescriptor( 1, &pOutput ) ) || pOutput == NULL ) return NULL;
	
	DWORD nLength = pFile->m_nWidth * pFile->m_nComponents;
	while ( nLength & 3 ) nLength ++;
	nLength *= pFile->m_nHeight;
	
	pOutput->cbElements = 1;
	pOutput->rgsabound[ 0 ].lLbound = 0;
	pOutput->rgsabound[ 0 ].cElements = nLength;
	
	if ( FAILED( SafeArrayAllocData( pOutput ) ) ) return NULL;
	
	LPBYTE pTarget;
	if ( FAILED( SafeArrayAccessData( pOutput, (void HUGEP* FAR*)&pTarget ) ) ) return NULL;
	
	CopyMemory( pTarget, pFile->m_pImage, nLength );
	
	SafeArrayUnaccessData( pOutput );
	
	return pOutput;
}

/////////////////////////////////////////////////////////////////////////////
// CImageServices service discovery and control

IImageServicePlugin* CImageServices::GetService(LPCTSTR pszFile, CLSID** ppCLSID)
{
	LPCTSTR pszType = _tcsrchr( pszFile, '.' );
	if ( pszType == NULL ) return NULL;
	
	IImageServicePlugin* pService = NULL;
	CString strType( pszType );
	CharLower( strType.GetBuffer() );
	strType.ReleaseBuffer();
	
	if ( m_pService.Lookup( strType, pService ) )
	{
		if ( pService != NULL && ppCLSID != NULL )
		{
			m_pCLSID.Lookup( strType, *ppCLSID );
		}
		
		return pService;
	}
	else
	{
		CLSID pCLSID = { 0 };
		
		pService = LoadService( strType, &pCLSID );
		m_pService.SetAt( strType, pService );
		
		if ( pService != NULL )
		{
			CLSID* pCopy = new CLSID;
			if ( pCopy == NULL )
			{
				theApp.Message( MSG_ERROR, _T("Memory allocation error in CImageServices::GetService") );
				return NULL;				
			}
			*pCopy = pCLSID;
			delete m_pCLSID[ strType ];
			m_pCLSID[ strType ] = pCopy;
			if ( ppCLSID != NULL ) *ppCLSID = pCopy;
		}
		
		return pService;
	}
}

IImageServicePlugin* CImageServices::LoadService(LPCTSTR pszType, CLSID* ppCLSID)
{
	IImageServicePlugin* pService = NULL;
	
	DWORD dwContext = 0;
	// Add here all problematic extensions
	if ( _tcscmp( pszType, _T(".asf") ) == 0 )
	{
		dwContext = CLSCTX_NO_CUSTOM_MARSHAL;
	}
	
	CLSID pCLSID;
	
	if ( ! Plugins.LookupCLSID( _T("ImageService"), pszType, pCLSID ) ) return NULL;
	
	if ( ppCLSID != NULL ) *ppCLSID = pCLSID;
	
	if ( ! m_bCOM )
	{
		if ( FAILED( CoInitializeEx( NULL, COINIT_MULTITHREADED ) ) ) return NULL;
		m_bCOM = TRUE;
	}
	
	HINSTANCE hRes = AfxGetResourceHandle();
	HRESULT hResult = CoCreateInstance( pCLSID, NULL, CLSCTX_ALL|dwContext,
		IID_IImageServicePlugin, (void**)&pService );
	AfxSetResourceHandle( hRes );
	
	if ( FAILED( hResult ) )
	{
		//theApp.Message( MSG_DEBUG, _T("CImageServices::CoCreateInstance() -> %lu"), hResult );
		return NULL;
	}
	
	return pService;
}

/////////////////////////////////////////////////////////////////////////////
// CImageServices cleanup

void CImageServices::Cleanup()
{
	CString strType;
	POSITION pos;
	
	for ( pos = m_pService.GetStartPosition() ; pos ; )
	{
		IImageServicePlugin* pService = NULL;
		m_pService.GetNextAssoc( pos, strType, pService );
		if ( pService != NULL ) pService->Release();
	}
	
	m_pService.RemoveAll();
	
	for ( pos = m_pCLSID.GetStartPosition() ; pos ; )
	{
		CLSID* pCLSID = NULL;
		m_pCLSID.GetNextAssoc( pos, strType, pCLSID );
		if ( pCLSID != NULL ) delete pCLSID;
	}
	
	m_pCLSID.RemoveAll();
	
	if ( m_bCOM && ( GetCurrentThreadId() != AfxGetApp()->m_nThreadID ) )
	{
		m_bCOM = FALSE;
		CoUninitialize();
	}
}

/////////////////////////////////////////////////////////////////////////////
// CImageServices load bitmap

BOOL CImageServices::LoadBitmap(CBitmap* pBitmap, UINT nResourceID, LPCTSTR pszType)
{
	if ( pBitmap->m_hObject == NULL ) pBitmap->DeleteObject();

	CImageServices pService;
	CImageFile pFile( &pService );
	if ( ! pFile.LoadFromResource( AfxGetResourceHandle(), nResourceID, pszType ) ) return FALSE;
	if ( ! pFile.EnsureRGB() ) return FALSE;
	pBitmap->Attach( pFile.CreateBitmap() );

	return TRUE;
}
