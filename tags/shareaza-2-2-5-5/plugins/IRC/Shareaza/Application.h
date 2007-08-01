//
// Application.h
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

#if !defined(AFX_APPLICATION_H__CFDDF7CA_51F3_4E66_992D_3BF640D0A212__INCLUDED_)
#define AFX_APPLICATION_H__CFDDF7CA_51F3_4E66_992D_3BF640D0A212__INCLUDED_

#pragma once


class CApplication : public CComObject
{
// Construction
public:
	CApplication();
	virtual ~CApplication();

// Attributes
public:

// Operations
public:
	IApplication*		GetApp();
	IUserInterface*		GetUI();

// Overrides
public:
	//{{AFX_VIRTUAL(CApplication)
	//}}AFX_VIRTUAL

// Implementation
protected:
	//{{AFX_MSG(CApplication)
	//}}AFX_MSG

	DECLARE_MESSAGE_MAP()

// IApplication
protected:
	BEGIN_INTERFACE_PART(Application, IApplication)
		DECLARE_DISPATCH()
		STDMETHOD(get_Application)(IApplication FAR* FAR* ppApplication);
		STDMETHOD(get_Version)(BSTR FAR* psVersion);
		STDMETHOD(CheckVersion)(BSTR sVersion);
		STDMETHOD(CreateXML)(ISXMLElement FAR* FAR* ppXML);
		STDMETHOD(get_UserInterface)(IUserInterface FAR* FAR* ppUserInterface);
		STDMETHOD(get_Library)(ILibrary FAR* FAR* ppLibrary);
	END_INTERFACE_PART(Application)

	BEGIN_INTERFACE_PART(UserInterface, IUserInterface)
		DECLARE_DISPATCH()
		STDMETHOD(get_Application)(IApplication FAR* FAR* ppApplication);
		STDMETHOD(get_UserInterface)(IUserInterface FAR* FAR* ppUserInterface);
		STDMETHOD(NewWindow)(BSTR bsName, IPluginWindowOwner FAR* pOwner, IPluginWindow FAR* FAR* ppWindow);
		STDMETHOD(get_MainWindowHwnd)(HWND FAR* phWnd);
		STDMETHOD(get_ActiveView)(IGenericView FAR* FAR* ppView);
		STDMETHOD(RegisterCommand)(BSTR bsName, HICON hIcon, INT* pnCommandID);
		STDMETHOD(AddFromString)(BSTR sXML);
		STDMETHOD(AddFromResource)(HINSTANCE hInstance, INT nID);
		STDMETHOD(AddFromXML)(ISXMLElement FAR* pXML);
		STDMETHOD(GetMenu)(BSTR bsName, VARIANT_BOOL bCreate, ISMenu FAR* FAR* ppMenu);
		STDMETHOD(GetToolbar)(BSTR bsName, VARIANT_BOOL bCreate, ISToolbar FAR* FAR* ppToolbar);
		STDMETHOD(get_GUIMode)(SGUIMode FAR* pnMode);
		STDMETHOD(GetRichBox)(BSTR bsName, VARIANT_BOOL bCreate, ISRichBox FAR* FAR* ppRichBox);
	END_INTERFACE_PART(UserInterface)

	DECLARE_INTERFACE_MAP()

};

extern CApplication Application;

//{{AFX_INSERT_LOCATION}}

#endif // !defined(AFX_APPLICATION_H__CFDDF7CA_51F3_4E66_992D_3BF640D0A212__INCLUDED_)
