//
// DlgTorrentAdd.cpp
//
// Copyright (c) Shareaza Development Team, 2002-2009.
// This file is part of SHAREAZA (shareaza.sourceforge.net)
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
// DlgTorrentAdd.cpp : implementation file
//

#include "StdAfx.h"
#include "Shareaza.h"
#include "DlgTorrentAdd.h"
#include "LTHookTorrent.hpp"
#include "Skin.h"


// CTorrentAddDlg dialog

IMPLEMENT_DYNAMIC(CTorrentAddDlg, CDialog)

CTorrentAddDlg::CTorrentAddDlg(CWnd* pParent /*=NULL*/, wstring& sSaveFolder, wstring& sTempFolder, bool& bUseTemp, bool& bManagedTorrent, bool& bPausedTorrent, LTHook::bit::allocations& nAllocationType)
	: CDialog(CTorrentAddDlg::IDD, pParent)
{

}

CTorrentAddDlg::~CTorrentAddDlg()
{
}

void CTorrentAddDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CTorrentAddDialog)
	DDX_Control( pDX, IDC_SAVE_BROWSE, m_wndSavePath );
	DDX_Control( pDX, IDC_TEMP_BROWSE, m_wndTempPath );
	DDX_Control( pDX, IDC_EDIT_SAVE, m_sSavePath );
	DDX_Control( pDX, IDC_EDIT_TEMP, m_sTempPath );
	DDX_Control( pDX, IDC_CHECK_TEMP, m_bUseTemp );
	DDX_Control( pDX, IDC_CHECK_MANAGED, m_bManagedTorrent );
	DDX_Control( pDX, IDC_CHECK_PAUSED, m_bPauseTorrent );
	DDX_CONTROL( pDX, IDC_COMBO_ALLOCATION, m_wndAllocationMode );
}


BEGIN_MESSAGE_MAP(CTorrentAddDlg, CDialog)
	ON_BN_CLICKED(IDOK, &CTorrentAddDlg::OnOk)
	ON_BN_CLICKED(IDC_COMPLETE_BROWSE, &CTorrentAddDlg::OnCompleteBrowse)
	ON_CBN_SELCHANGE(IDC_COMBO_ALLOCATION, &CTorrentAddDlg::OnSelchangeComboAllocation)
	ON_BN_CLICKED(IDC_CHECK_TEMP, &CTorrentAddDlg::OnChangeCheckTemp)
	ON_BN_CLICKED(IDC_CHECK_MANAGED, &CTorrentAddDlg::OnChangeCheckManaged)
	ON_BN_CLICKED(IDC_CHECK_PAUSED, &CTorrentAddDlg::OnChangeCheckPaused)
	ON_EN_CHANGE(IDC_EDIT_SAVE, &CTorrentAddDlg::OnChangeEditSave)
	ON_EN_CHANGE(IDC_EDIT_TEMP, &CTorrentAddDlg::OnChangeEditTemp)
	ON_BN_CLICKED(IDC_TEMP_BROWSE, &CTorrentAddDlg::OnTempBrowse)
END_MESSAGE_MAP()


// CTorrentAddDialog message handlers

void CTorrentAddDlg::OnOk()
{
	// TODO: Add your control notification handler code here
	OnOK();
}

void CTorrentAddDlg::OnCompleteBrowse()
{
	// TODO: Add your control notification handler code here
}

void CTorrentAddDlg::OnTempBrowse()
{
	// TODO: Add your control notification handler code here
}

void CTorrentAddDlg::OnSelchangeComboAllocation()
{
	// TODO: Add your control notification handler code here
}

void CTorrentAddDlg::OnChangeCheckTemp()
{
	// TODO: Add your control notification handler code here
}

void CTorrentAddDlg::OnChangeCheckManaged()
{
	// TODO: Add your control notification handler code here
}

void CTorrentAddDlg::OnChangeCheckPaused()
{
	// TODO: Add your control notification handler code here
}

void CTorrentAddDlg::OnChangeEditSave()
{
	// TODO:  If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.

	// TODO:  Add your control notification handler code here
}

void CTorrentAddDlg::OnChangeEditTemp()
{
	// TODO:  If this is a RICHEDIT control, the control will not
	// send this notification unless you override the CDialog::OnInitDialog()
	// function and call CRichEditCtrl().SetEventMask()
	// with the ENM_CHANGE flag ORed into the mask.

	// TODO:  Add your control notification handler code here
}

// Special processing when the dialog box is initialized
BOOL CTorrentAddDlg::OnInitDialog()
{
	CSkinDialog::OnInitDialog();

	SkinMe( _T("CTorrentAddDlg") );

	m_wndSavePath.SetIcon( IDI_BROWSE );
	m_wndTempPath.SetIcon( IDI_BROWSE );
	return true;
}