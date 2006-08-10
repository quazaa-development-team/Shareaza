//
// PageSettingsConnection.cpp
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
#include "Settings.h"
#include "PageSettingsConnection.h"
#include "DlgHelp.h"
#include "UPnPFinder.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

IMPLEMENT_DYNCREATE(CConnectionSettingsPage, CSettingsPage)

BEGIN_MESSAGE_MAP(CConnectionSettingsPage, CSettingsPage)
	//{{AFX_MSG_MAP(CConnectionSettingsPage)
	ON_CBN_EDITCHANGE(IDC_INBOUND_HOST, OnEditChangeInboundHost)
	ON_CBN_CLOSEUP(IDC_INBOUND_HOST, OnCloseUpInboundHost)
	ON_EN_CHANGE(IDC_INBOUND_PORT, OnChangeInboundPort)
	ON_BN_CLICKED(IDC_INBOUND_RANDOM, OnInboundRandom)
	ON_WM_SHOWWINDOW()
	ON_BN_CLICKED(IDC_ENABLE_UPNP, OnClickedEnableUpnp)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()


/////////////////////////////////////////////////////////////////////////////
// CConnectionSettingsPage property page

CConnectionSettingsPage::CConnectionSettingsPage() : CSettingsPage(CConnectionSettingsPage::IDD)
{
	//{{AFX_DATA_INIT(CConnectionSettingsPage)
	m_bIgnoreLocalIP = FALSE;
	m_bInBind = FALSE;
	m_sInHost = _T("");
	m_nInPort = 0;
	m_sOutHost = _T("");
	m_nTimeoutConnection = 0;
	m_nTimeoutHandshake = 0;
	m_sOutSpeed = _T("");
	m_sInSpeed = _T("");
	m_bInRandom = FALSE;
	//}}AFX_DATA_INIT
}

CConnectionSettingsPage::~CConnectionSettingsPage()
{
}

void CConnectionSettingsPage::DoDataExchange(CDataExchange* pDX)
{
	CSettingsPage::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CConnectionSettingsPage)
	DDX_Control(pDX, IDC_INBOUND_PORT, m_wndInPort);
	DDX_Control(pDX, IDC_INBOUND_SPEED, m_wndInSpeed);
	DDX_Control(pDX, IDC_OUTBOUND_SPEED, m_wndOutSpeed);
	DDX_Control(pDX, IDC_INBOUND_HOST, m_wndInHost);
	DDX_Control(pDX, IDC_INBOUND_BIND, m_wndInBind);
	DDX_Control(pDX, IDC_TIMEOUT_HANDSHAKE_SPIN, m_wndTimeoutHandshake);
	DDX_Control(pDX, IDC_TIMEOUT_CONNECTION_SPIN, m_wndTimeoutConnection);
	DDX_Check(pDX, IDC_IGNORE_LOCAL, m_bIgnoreLocalIP);
	DDX_Check(pDX, IDC_INBOUND_BIND, m_bInBind);
	DDX_CBString(pDX, IDC_INBOUND_HOST, m_sInHost);
	DDX_Text(pDX, IDC_INBOUND_PORT, m_nInPort);
	DDX_CBString(pDX, IDC_OUTBOUND_HOST, m_sOutHost);
	DDX_Text(pDX, IDC_TIMEOUT_CONNECTION, m_nTimeoutConnection);
	DDX_Text(pDX, IDC_TIMEOUT_HANDSHAKE, m_nTimeoutHandshake);
	DDX_Control(pDX, IDC_CAN_ACCEPT, m_wndCanAccept);
	DDX_CBString(pDX, IDC_OUTBOUND_SPEED, m_sOutSpeed);
	DDX_CBString(pDX, IDC_INBOUND_SPEED, m_sInSpeed);
	DDX_Check(pDX, IDC_INBOUND_RANDOM, m_bInRandom);
	DDX_Check(pDX, IDC_ENABLE_UPNP, m_bEnableUPnP);
	//}}AFX_DATA_MAP
}

/////////////////////////////////////////////////////////////////////////////
// CConnectionSettingsPage message handlers

BOOL CConnectionSettingsPage::OnInitDialog()
{
	CSettingsPage::OnInitDialog();

	CString strAutomatic = GetInOutHostTranslation();
	CComboBox* pOutHost = (CComboBox*) GetDlgItem( IDC_OUTBOUND_HOST );

	// update all dropdowns
	m_wndInHost.DeleteString( 0 );
	m_wndInHost.AddString( strAutomatic );
	pOutHost->DeleteString( 0 );
	pOutHost->AddString( strAutomatic );

	// Firewall status
	CString str;
	LoadString( str, IDS_GENERAL_NO );
	m_wndCanAccept.AddString( str );
	LoadString( str, IDS_GENERAL_YES );
	m_wndCanAccept.AddString( str );
	LoadString( str, IDS_GENERAL_AUTO );
	m_wndCanAccept.AddString( str );

	m_wndCanAccept.SetCurSel( Settings.Connection.FirewallStatus );

	//m_bCanAccept			= Settings.Connection.FirewallStatus == CONNECTION_OPEN;
	m_sInHost				= Settings.Connection.InHost;
	m_bInRandom				= Settings.Connection.RandomPort;
	m_nInPort				= m_bInRandom ? 0 : Settings.Connection.InPort;
	m_bInBind				= Settings.Connection.InBind;
	m_sOutHost				= Settings.Connection.OutHost;
	m_bIgnoreLocalIP		= Settings.Connection.IgnoreLocalIP;
	m_bEnableUPnP			= Settings.Connection.EnableUPnP;
	m_nTimeoutConnection	= Settings.Connection.TimeoutConnect / 1000;
	m_nTimeoutHandshake		= Settings.Connection.TimeoutHandshake / 1000;

	if ( m_sInHost.IsEmpty() ) m_sInHost = strAutomatic;
	if ( m_sOutHost.IsEmpty() ) m_sOutHost = strAutomatic;

	m_wndTimeoutConnection.SetRange( 1, 480 );
	m_wndTimeoutHandshake.SetRange( 1, 480 );

	UpdateData( FALSE );

	m_wndInBind.EnableWindow( m_sInHost != strAutomatic);
	
	if ( theApp.m_bServer || theApp.m_dwWindowsVersion < 5 && !theApp.m_bWinME )
	{
		CButton* pWnd = (CButton*)GetDlgItem( IDC_ENABLE_UPNP );
		pWnd->EnableWindow( FALSE );
	}
	return TRUE;
}

CString CConnectionSettingsPage::FormatSpeed(DWORD nSpeed)
{
	return Settings.SmartVolume( nSpeed, TRUE, TRUE );
}

DWORD CConnectionSettingsPage::ParseSpeed(LPCTSTR psz)
{
	return (DWORD)Settings.ParseVolume( psz, TRUE ) / 1024;
}

void CConnectionSettingsPage::OnEditChangeInboundHost()
{
	CString strAutomatic = GetInOutHostTranslation();

	UpdateData();

	m_wndInBind.EnableWindow( m_sInHost != strAutomatic );
}

void CConnectionSettingsPage::OnCloseUpInboundHost()
{
	m_wndInBind.EnableWindow( m_wndInHost.GetCurSel() != 0 );
}

void CConnectionSettingsPage::OnChangeInboundPort()
{
	UpdateData();
	BOOL bRandom = m_nInPort == 0;

	if ( bRandom != m_bInRandom )
	{
		m_bInRandom = bRandom;
		UpdateData( FALSE );
	}
}

void CConnectionSettingsPage::OnInboundRandom()
{
	UpdateData();

	if ( m_bInRandom && m_nInPort != 0 )
	{
		m_nInPort = 0;
		UpdateData( FALSE );
	}
}

BOOL CConnectionSettingsPage::OnKillActive()
{
	UpdateData();

	if ( ParseSpeed( m_sInSpeed ) == 0 )
	{
		CString strMessage;
		LoadString( strMessage, IDS_SETTINGS_NEED_BANDWIDTH );
		AfxMessageBox( strMessage, MB_ICONEXCLAMATION );
		m_wndInSpeed.SetFocus();
		return FALSE;
	}

	if ( ParseSpeed( m_sOutSpeed ) == 0 )
	{
		CString strMessage;
		LoadString( strMessage, IDS_SETTINGS_NEED_BANDWIDTH );
		AfxMessageBox( strMessage, MB_ICONEXCLAMATION );
		m_wndOutSpeed.SetFocus();
		return FALSE;
	}

	return CSettingsPage::OnKillActive();
}

void CConnectionSettingsPage::OnOK()
{
	UpdateData();

	CString strAutomatic = GetInOutHostTranslation();

	if ( m_sInHost.CompareNoCase( strAutomatic ) == 0 )
		m_sInHost.Empty();
	if ( m_sOutHost.CompareNoCase( strAutomatic ) == 0 )
		m_sOutHost.Empty();

	Settings.Connection.FirewallStatus		= m_wndCanAccept.GetCurSel();
	Settings.Connection.InHost				= m_sInHost;

	bool bRandomForwarded = ( m_nInPort == 0 && 
		theApp.m_bUPnPPortsForwarded == TS_TRUE );

	if ( !bRandomForwarded || m_nInPort != 0 || !m_bInRandom )
	{
		if ( m_bEnableUPnP && ( (DWORD)m_nInPort != Settings.Connection.InPort ||
			!Settings.Connection.EnableUPnP ) )
		{
			Settings.Connection.InPort = m_nInPort;
			try
			{
				if ( !theApp.m_pUPnPFinder ) 
					theApp.m_pUPnPFinder.reset( new CUPnPFinder );
				if ( theApp.m_pUPnPFinder->AreServicesHealthy() )
					theApp.m_pUPnPFinder->StartDiscovery();
			}
			catch ( CUPnPFinder::UPnPError& ) {}
			catch ( CException* e ) { e->Delete(); }
		}
		else
			Settings.Connection.InPort = m_nInPort;
	}

	Settings.Connection.RandomPort			= ( m_bInRandom && m_nInPort == 0 );
	Settings.Connection.EnableUPnP			= m_bEnableUPnP;
	Settings.Connection.InBind				= m_bInBind;
	Settings.Connection.OutHost				= m_sOutHost;
	Settings.Connection.InSpeed				= ParseSpeed( m_sInSpeed );
	Settings.Connection.OutSpeed			= ParseSpeed( m_sOutSpeed );
	Settings.Connection.IgnoreLocalIP		= m_bIgnoreLocalIP;
	Settings.Connection.TimeoutConnect		= m_nTimeoutConnection * 1000;
	Settings.Connection.TimeoutHandshake	= m_nTimeoutHandshake  * 1000;

	/*
	// Correct the upload limit (if required)
	if ( Settings.Bandwidth.Uploads )
	{
		Settings.Bandwidth.Uploads = min ( Settings.Bandwidth.Uploads, ( ( Settings.Connection.OutSpeed / 8 ) * 1024 ) );
	}
	*/


	UpdateData();

	// Warn the user about upload limiting and ed2k/BT downloads
	if ( ( ! Settings.Live.UploadLimitWarning ) &&
		 ( Settings.eDonkey.EnableToday || Settings.eDonkey.EnableAlways || Settings.BitTorrent.AdvancedInterface || Settings.BitTorrent.AdvancedInterfaceSet ) ) 
	{
		DWORD nDownload = max ( Settings.Bandwidth.Downloads, ( ( Settings.Connection.InSpeed  / 8 ) * 1024 ) );
		DWORD nUpload = ( ( Settings.Connection.OutSpeed / 8 ) * 1024 );
		if ( Settings.Bandwidth.Uploads > 0 ) nUpload =  min( Settings.Bandwidth.Uploads, nUpload );
		
		if ( ( nUpload * 16 ) < ( nDownload ) )
		{
			CHelpDlg::Show( _T("GeneralHelp.UploadWarning") );
			Settings.Live.UploadLimitWarning = TRUE;
		}
	}
	CSettingsPage::OnOK();
}

CString CConnectionSettingsPage::GetInOutHostTranslation()
{
	CString strAutomatic, strInCombo, strOutCombo, strNew;

	LoadString( strAutomatic, IDS_SETTINGS_AUTOMATIC_IP );

	m_wndInHost.GetLBText( 0, strInCombo );
	CComboBox* pOutHost = (CComboBox*) GetDlgItem( IDC_OUTBOUND_HOST );
	pOutHost->GetLBText( 0, strOutCombo );

	// get non-english string if any
	strNew = strInCombo.CompareNoCase( _T("Automatic") ) == 0 ? strOutCombo : strInCombo;
	return strAutomatic.CompareNoCase( _T("Automatic") ) == 0 ? strNew : strAutomatic;
}

void CConnectionSettingsPage::OnShowWindow(BOOL bShow, UINT nStatus)
{
	CSettingsPage::OnShowWindow(bShow, nStatus);
	if ( bShow )
	{
		// Update speed units
		m_sOutSpeed	= FormatSpeed( Settings.Connection.OutSpeed );
		m_sInSpeed	= FormatSpeed( Settings.Connection.InSpeed );

		// Dropdown
		m_wndInSpeed.ResetContent();
		m_wndOutSpeed.ResetContent();
		const DWORD nSpeeds[] = { 28, 33, 56, 64, 128, 350, 576, 768, 1544, 3072, 45000, 100000, 155000, 0 };
		for ( int nSpeed = 0 ; nSpeeds[ nSpeed ] ; nSpeed++ )
		{
			CString str = FormatSpeed( nSpeeds[ nSpeed ] );
			m_wndInSpeed.AddString( str );
			m_wndOutSpeed.AddString( str );
		}

		UpdateData( FALSE );
	}
}

void CConnectionSettingsPage::OnClickedEnableUpnp()
{
	if ( !m_bEnableUPnP )
	{
		if ( !theApp.m_pUPnPFinder ) 
			theApp.m_pUPnPFinder.reset( new CUPnPFinder );

		// If the UPnP Device Host service is not running ask the user to start it.
		// It is not wise to have a delay up to 1 minute, especially that we would need
		// to wait until this and SSDP service are started. 
		// If the upnphost service can not be started Shareaza will lock up.
		if ( !theApp.m_pUPnPFinder->AreServicesHealthy() )
		{
			CString strMessage;
			LoadString( strMessage, IDS_UPNP_SERVICES_ERROR );
			MessageBox( strMessage, NULL, MB_OK | MB_ICONEXCLAMATION );
			UpdateData( FALSE );
		}
	}
}
