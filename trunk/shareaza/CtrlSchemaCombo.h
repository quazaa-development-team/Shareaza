//
// CtrlSchemaCombo.h
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

#pragma once

class CSchema;


class CSchemaCombo : public CComboBox
{
// Construction
public:
	CSchemaCombo();

// Attributes
public:
	CString		m_sNoSchemaText;
	int			m_nType;
	int			m_nAvailability;
protected:
	HWND		m_hListBox;
	WNDPROC		m_pWndProc;
	CString		m_sPreDrop;

// Operations
public:
	void		SetEmptyString(UINT nID);
	void		Load(LPCTSTR pszSelectURI = NULL, int nType = 0, int nAvailability = 0, BOOL bReset = TRUE);
	void		Select(LPCTSTR pszURI);
	void		Select(CSchema* pSchema);
	CSchema*	GetSelected() const;
	CString		GetSelectedURI() const;
protected:
	static LRESULT PASCAL ListWndProc(HWND hWnd, UINT nMsg, WPARAM wParam, LPARAM lParam);
	int			FindSchema(CSchema* pSchema);
	BOOL		OnClickItem(int nItem, BOOL bDown);

// Overrides
public:
	virtual BOOL Create(DWORD dwStyle, const RECT& rect, CWnd* pParentWnd, UINT nID);
	virtual void MeasureItem(LPMEASUREITEMSTRUCT lpMeasureItemStruct);
	virtual void DrawItem(LPDRAWITEMSTRUCT lpDrawItemStruct);

// Implementation
protected:
	DECLARE_MESSAGE_MAP()
	afx_msg LRESULT OnCtlColorListBox(WPARAM wParam, LPARAM lParam);
	afx_msg void OnDropDown();
};
