//
// Application.cpp
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
#include "Application.h"
#include "CoolInterface.h"
#include "Library.h"
#include "Plugins.h"
#include "Skin.h"
#include "ComMenu.h"
#include "ComToolbar.h"
#include "WndMain.h"
#include "WndChild.h"
#include "WndPlugin.h"

#include "XML.h"
#include "XMLCOM.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

BEGIN_MESSAGE_MAP(CApplication, CComObject)
	//{{AFX_MSG_MAP(CApplication)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

BEGIN_INTERFACE_MAP(CApplication, CComObject)
	INTERFACE_PART(CApplication, IID_IApplication, Application)
	INTERFACE_PART(CApplication, IID_IUserInterface, UserInterface)
END_INTERFACE_MAP()

CApplication Application;


/////////////////////////////////////////////////////////////////////////////
// CApplication construction

CApplication::CApplication()
{
	EnableDispatch( IID_IApplication );
	EnableDispatch( IID_IUserInterface );
}

CApplication::~CApplication()
{
}

/////////////////////////////////////////////////////////////////////////////
// CApplication operations

IApplication* CApplication::GetApp()
{
	return (IApplication*)GetInterface( IID_IApplication, TRUE );
}

IUserInterface* CApplication::GetUI()
{
	return (IUserInterface*)GetInterface( IID_IUserInterface, TRUE );
}

/////////////////////////////////////////////////////////////////////////////
// CApplication IApplication

IMPLEMENT_DISPATCH(CApplication, Application)

STDMETHODIMP CApplication::XApplication::get_Application(IApplication FAR* FAR* ppApplication)
{
	METHOD_PROLOGUE( CApplication, Application )
	if ( ppApplication == NULL ) return E_INVALIDARG;
	*ppApplication = (IApplication*)pThis->GetInterface( IID_IApplication, TRUE );
	return S_OK;
}

STDMETHODIMP CApplication::XApplication::get_Version(BSTR FAR* psVersion)
{
	METHOD_PROLOGUE( CApplication, Application )
	if ( psVersion == NULL ) return E_INVALIDARG;
	theApp.m_sVersion.SetSysString( psVersion );
	return S_OK;
}

STDMETHODIMP CApplication::XApplication::CheckVersion(BSTR sVersion)
{
	METHOD_PROLOGUE( CApplication, Application )
	if ( sVersion == NULL ) return E_INVALIDARG;
	
	int nDesired[4];
	
	if ( swscanf( sVersion, L"%i.%i.%i.%i", &nDesired[3], &nDesired[2],
		&nDesired[1], &nDesired[0] ) != 4 ) return E_INVALIDARG;
	
	// NOTE: Assumes each version component is 8 bit
	BOOL bOk = ( theApp.m_nVersion[0] << 24 ) + ( theApp.m_nVersion[1] << 16 ) + ( theApp.m_nVersion[2] << 8 ) + theApp.m_nVersion[3]
			>= ( nDesired[3] << 24 ) + ( nDesired[2] << 16 ) + ( nDesired[1] << 8 ) + nDesired[0];
	
	return bOk ? S_OK : S_FALSE;
}

STDMETHODIMP CApplication::XApplication::CreateXML(ISXMLElement FAR* FAR* ppXML)
{
	METHOD_PROLOGUE( CApplication, Application )
	if ( ppXML == NULL ) return E_INVALIDARG;
	CXMLElement* pXML = new CXMLElement();
	*ppXML = (ISXMLElement*)CXMLCOM::Wrap( pXML, IID_ISXMLElement );
	return S_OK;
}

STDMETHODIMP CApplication::XApplication::get_UserInterface(IUserInterface FAR* FAR* ppUserInterface)
{
	METHOD_PROLOGUE( CApplication, Application )
	if ( ppUserInterface == NULL ) return E_INVALIDARG;
	*ppUserInterface = (IUserInterface*)pThis->GetInterface( IID_IUserInterface, TRUE );
	return S_OK;
}

STDMETHODIMP CApplication::XApplication::get_Library(ILibrary FAR* FAR* ppLibrary)
{
	METHOD_PROLOGUE( CApplication, Application )
	if ( ppLibrary == NULL ) return E_INVALIDARG;
	*ppLibrary = (ILibrary*)Library.GetInterface( IID_ILibrary, TRUE );
	return S_OK;
}

/////////////////////////////////////////////////////////////////////////////
// CApplication IUserInterface

IMPLEMENT_DISPATCH(CApplication, UserInterface)

STDMETHODIMP CApplication::XUserInterface::get_Application(IApplication FAR* FAR* ppApplication)
{
	METHOD_PROLOGUE( CApplication, UserInterface )
	if ( ppApplication == NULL ) return E_INVALIDARG;
	*ppApplication = (IApplication*)pThis->GetInterface( IID_IApplication, TRUE );
	return S_OK;
}

STDMETHODIMP CApplication::XUserInterface::get_UserInterface(IUserInterface FAR* FAR* ppUserInterface)
{
	METHOD_PROLOGUE( CApplication, UserInterface )
	if ( ppUserInterface == NULL ) return E_INVALIDARG;
	*ppUserInterface = (IUserInterface*)pThis->GetInterface( IID_IUserInterface, TRUE );
	return S_OK;
}

STDMETHODIMP CApplication::XUserInterface::NewWindow(BSTR bsName, IPluginWindowOwner FAR* pOwner, IPluginWindow FAR* FAR* ppWindow)
{
	METHOD_PROLOGUE( CApplication, UserInterface )
	
	if ( bsName == NULL || pOwner == NULL || ppWindow == NULL ) return E_INVALIDARG;
	if ( theApp.SafeMainWnd() == NULL ) return E_UNEXPECTED;
	
	IPluginWindowOwner* pOwner2;
	if ( FAILED( pOwner->QueryInterface( IID_IPluginWindowOwner, (void**)&pOwner2 ) ) ) return E_NOINTERFACE;
		
	CPluginWnd* pWnd = new CPluginWnd( CString( bsName ), pOwner2 );
	pOwner2->Release();
	
	*ppWindow = (IPluginWindow*)pWnd->GetInterface( &IID_IPluginWindow );
	
	return S_OK;
}

STDMETHODIMP CApplication::XUserInterface::get_MainWindowHwnd(HWND FAR* phWnd)
{
	METHOD_PROLOGUE( CApplication, UserInterface )
	if ( phWnd == NULL ) return E_INVALIDARG;
	if ( theApp.SafeMainWnd() == NULL ) return E_UNEXPECTED;
	*phWnd = theApp.SafeMainWnd()->GetSafeHwnd();
	return S_OK;
}

STDMETHODIMP CApplication::XUserInterface::get_ActiveView(IGenericView FAR* FAR* ppView)
{
	METHOD_PROLOGUE( CApplication, UserInterface )
	
	if ( ppView == NULL ) return E_INVALIDARG;
	*ppView = NULL;
	
	CMainWnd* pMainWnd = (CMainWnd*)theApp.SafeMainWnd();
	if ( pMainWnd == NULL ) return E_UNEXPECTED;
	CChildWnd* pChildWnd = pMainWnd->m_pWindows.GetActive();
	if ( pChildWnd == NULL ) return S_FALSE;
	
	return pChildWnd->GetGenericView( ppView );
}

STDMETHODIMP CApplication::XUserInterface::RegisterCommand(BSTR bsName, HICON hIcon, UINT* pnCommandID)
{
	METHOD_PROLOGUE( CApplication, UserInterface )
	if ( pnCommandID == NULL ) return E_INVALIDARG;
	*pnCommandID = Plugins.GetCommandID();
	if ( bsName != NULL ) CoolInterface.NameCommand( *pnCommandID, CString( bsName ) );
	if ( hIcon ) CoolInterface.AddIcon( *pnCommandID, hIcon );
	return S_OK;
}

STDMETHODIMP CApplication::XUserInterface::AddFromString(BSTR sXML)
{
	METHOD_PROLOGUE( CApplication, UserInterface )
	if ( sXML == NULL ) return E_INVALIDARG;
	return Skin.LoadFromString( CString( sXML ), Settings.General.Path + '\\' ) ? S_OK : E_FAIL;
}

STDMETHODIMP CApplication::XUserInterface::AddFromResource(HINSTANCE hInstance, UINT nID)
{
	METHOD_PROLOGUE( CApplication, UserInterface )
	if ( hInstance == NULL || nID == 0 ) return E_INVALIDARG;
	return Skin.LoadFromResource( hInstance, nID ) ? S_OK : E_FAIL;
}

STDMETHODIMP CApplication::XUserInterface::AddFromXML(ISXMLElement FAR* pXML)
{
	METHOD_PROLOGUE( CApplication, UserInterface )
	CXMLElement* pBase = CXMLCOM::Unwrap( pXML );
	if ( pBase == NULL ) return E_INVALIDARG;
	return Skin.LoadFromXML( pBase, Settings.General.Path + '\\' ) ? S_OK : E_FAIL;
}

STDMETHODIMP CApplication::XUserInterface::GetMenu(BSTR bsName, VARIANT_BOOL bCreate, ISMenu FAR* FAR* ppMenu)
{
	METHOD_PROLOGUE( CApplication, UserInterface )
	
	if ( bsName == NULL || ppMenu == NULL ) return E_INVALIDARG;
	*ppMenu = NULL;
	
	CMenu* pMenu = Skin.GetMenu( CString( bsName ) );

	if ( pMenu == NULL )
	{
		if ( bCreate == VARIANT_FALSE ) return E_FAIL;
		pMenu = new CMenu();
		pMenu->CreatePopupMenu();
		Skin.m_pMenus.SetAt( CString( bsName ), pMenu );
	}

	*ppMenu = CComMenu::Wrap( pMenu->GetSafeHmenu() );

	return S_OK;
}

STDMETHODIMP CApplication::XUserInterface::GetToolbar(BSTR bsName, VARIANT_BOOL bCreate, ISToolbar FAR* FAR* ppToolbar)
{
	METHOD_PROLOGUE( CApplication, UserInterface )
	
	if ( bsName == NULL || ppToolbar == NULL ) return E_INVALIDARG;
	*ppToolbar = NULL;
	
	CCoolBarCtrl* pBar = NULL;
	
	Skin.m_pToolbars.Lookup( CString( bsName ), (void*&)pBar );
	
	if ( pBar == NULL )
	{
		if ( bCreate == VARIANT_FALSE ) return E_FAIL;
		pBar = new CCoolBarCtrl();
		Skin.m_pToolbars.SetAt( CString( bsName ), pBar );
	}

	*ppToolbar = CComToolbar::Wrap( pBar );
	
	return S_OK;
}