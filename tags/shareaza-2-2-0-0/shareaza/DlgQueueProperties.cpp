//
// DlgQueueProperties.cpp
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
#include "UploadQueue.h"
#include "UploadQueues.h"
#include "DlgQueueProperties.h"
#include "LiveList.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

BEGIN_MESSAGE_MAP(CQueuePropertiesDlg, CSkinDialog)
	//{{AFX_MSG_MAP(CQueuePropertiesDlg)
	ON_BN_CLICKED(IDC_MINIMUM_CHECK, OnMinimumCheck)
	ON_BN_CLICKED(IDC_MAXIMUM_CHECK, OnMaximumCheck)
	ON_BN_CLICKED(IDC_PROTOCOLS_CHECK, OnProtocolsCheck)
	ON_BN_CLICKED(IDC_MARKED_CHECK, OnMarkedCheck)
	ON_BN_CLICKED(IDC_ROTATE_ENABLE, OnRotateEnable)
	ON_WM_HSCROLL()
	ON_EN_CHANGE(IDC_TRANSFERS_MAX, OnChangeTransfersMax)
	ON_BN_CLICKED(IDC_MATCH_CHECK, OnMatchCheck)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()


/////////////////////////////////////////////////////////////////////////////
// CQueuePropertiesDlg dialog

CQueuePropertiesDlg::CQueuePropertiesDlg(CUploadQueue* pQueue, BOOL bEnable, CWnd* pParent) : CSkinDialog(CQueuePropertiesDlg::IDD, pParent)
{
	ASSERT( pQueue != NULL );
	m_pQueue = pQueue;
	m_bEnableOverride = bEnable;

	//{{AFX_DATA_INIT(CQueuePropertiesDlg)
	m_nCapacity = 0;
	m_bMaxSize = FALSE;
	m_sMaxSize = _T("");
	m_bMinSize = FALSE;
	m_sMinSize = _T("");
	m_bMarked = FALSE;
	m_sName = _T("");
	m_bPartial = FALSE;
	m_bProtocols = FALSE;
	m_bRotate = FALSE;
	m_bReward = FALSE;
	m_nRotateTime = 0;
	m_nTransfersMax = 0;
	m_nTransfersMin = 0;
	m_bMatch = FALSE;
	m_sMatch = _T("");
	m_bEnable = FALSE;
	m_sMarked = _T("");
	//}}AFX_DATA_INIT
}

void CQueuePropertiesDlg::DoDataExchange(CDataExchange* pDX)
{
	CSkinDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CQueuePropertiesDlg)
	DDX_Control(pDX, IDC_MATCH_TEXT, m_wndMatch);
	DDX_Control(pDX, IDC_BANDWIDTH_POINTS, m_wndBandwidthPoints);
	DDX_Control(pDX, IDC_BANDWIDTH_VALUE, m_wndBandwidthValue);
	DDX_Control(pDX, IDC_TRANSFERS_MIN_SPIN, m_wndTransfersMin);
	DDX_Control(pDX, IDC_TRANSFERS_MAX_SPIN, m_wndTransfersMax);
	DDX_Control(pDX, IDC_ROTATE_TIME_SPIN, m_wndRotateTimeSpin);
	DDX_Control(pDX, IDC_ROTATE_TIME, m_wndRotateTime);
	DDX_Control(pDX, IDC_PROTOCOLS_LIST, m_wndProtocols);
	DDX_Control(pDX, IDC_MINIMUM_VALUE, m_wndMinSize);
	DDX_Control(pDX, IDC_MAXIMUM_VALUE, m_wndMaxSize);
	DDX_Control(pDX, IDC_MARKED_LIST, m_wndMarked);
	DDX_Control(pDX, IDC_CAPACITY_SPIN, m_wndCapacity);
	DDX_Control(pDX, IDC_BANDWIDTH_SLIDER, m_wndBandwidthSlider);
	DDX_Text(pDX, IDC_CAPACITY, m_nCapacity);
	DDX_Check(pDX, IDC_MAXIMUM_CHECK, m_bMaxSize);
	DDX_Text(pDX, IDC_MAXIMUM_VALUE, m_sMaxSize);
	DDX_Check(pDX, IDC_MINIMUM_CHECK, m_bMinSize);
	DDX_Text(pDX, IDC_MINIMUM_VALUE, m_sMinSize);
	DDX_Check(pDX, IDC_MARKED_CHECK, m_bMarked);
	DDX_Text(pDX, IDC_NAME, m_sName);
	DDX_Check(pDX, IDC_PARTIAL_ENABLE, m_bPartial);
	DDX_Check(pDX, IDC_PROTOCOLS_CHECK, m_bProtocols);
	DDX_Check(pDX, IDC_ROTATE_ENABLE, m_bRotate);
	DDX_Text(pDX, IDC_ROTATE_TIME, m_nRotateTime);
	DDX_Text(pDX, IDC_TRANSFERS_MAX, m_nTransfersMax);
	DDX_Text(pDX, IDC_TRANSFERS_MIN, m_nTransfersMin);
	DDX_Check(pDX, IDC_REWARD_ENABLE, m_bReward);
	DDX_Check(pDX, IDC_MATCH_CHECK, m_bMatch);
	DDX_Text(pDX, IDC_MATCH_TEXT, m_sMatch);
	DDX_Check(pDX, IDC_ENABLE, m_bEnable);
	DDX_CBString(pDX, IDC_MARKED_LIST, m_sMarked);
	//}}AFX_DATA_MAP
}

/////////////////////////////////////////////////////////////////////////////
// CQueuePropertiesDlg message handlers

BOOL CQueuePropertiesDlg::OnInitDialog()
{
	CSkinDialog::OnInitDialog();

	SkinMe( _T("CQueuePropertiesDlg"), ID_VIEW_UPLOADS );

	m_wndTransfersMin.SetRange( 1, 128 );
	m_wndTransfersMax.SetRange( 1, 512 );
	m_wndRotateTimeSpin.SetRange( 30, 15 * 60 );

	CBitmap bmProtocols;
	bmProtocols.LoadBitmap( IDB_PROTOCOLS );
	if ( theApp.m_bRTL ) 
		bmProtocols.m_hObject = CreateMirroredBitmap( (HBITMAP)bmProtocols.m_hObject );

	m_gdiProtocols.Create( 16, 16, ILC_COLOR32|ILC_MASK, 7, 1 );
	m_gdiProtocols.Add( &bmProtocols, RGB( 0, 255, 0 ) );

	m_wndProtocols.SendMessage( LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_CHECKBOXES, LVS_EX_CHECKBOXES );
	m_wndProtocols.SetImageList( &m_gdiProtocols, LVSIL_SMALL );
	m_wndProtocols.InsertItem( LVIF_TEXT|LVIF_IMAGE|LVIF_PARAM, 0, _T("HTTP"), 0, 0, PROTOCOL_HTTP, PROTOCOL_HTTP );
	m_wndProtocols.InsertItem( LVIF_TEXT|LVIF_IMAGE|LVIF_PARAM, 1, _T("ED2K"), 0, 0, PROTOCOL_ED2K, PROTOCOL_ED2K );

	CSingleLock pLock( &UploadQueues.m_pSection, TRUE );

	if ( ! UploadQueues.Check( m_pQueue ) )
	{
		PostMessage( WM_CLOSE );
		return TRUE;
	}

	m_sName = m_pQueue->m_sName;

	m_bPartial = m_pQueue->m_bPartial;

	if ( m_bMinSize = ( m_pQueue->m_nMinSize > 0 ) )
	{
		m_sMinSize = Settings.SmartVolume( m_pQueue->m_nMinSize, FALSE );
	}
	else
	{
		m_sMinSize = Settings.SmartVolume( 0, FALSE );
	}

	if ( m_bMaxSize = ( m_pQueue->m_nMaxSize < SIZE_UNKNOWN ) )
	{
		m_sMaxSize = Settings.SmartVolume( m_pQueue->m_nMaxSize, FALSE );
	}
	else
	{
		m_sMaxSize = Settings.SmartVolume( 0, FALSE );
	}

	m_bMarked = ( m_pQueue->m_sShareTag.GetLength() > 0 );
	m_sMarked = m_pQueue->m_sShareTag;

	m_bMatch = ( m_pQueue->m_sNameMatch.GetLength() > 0 );
	m_sMatch = m_pQueue->m_sNameMatch;

	m_bProtocols = ( m_pQueue->m_nProtocols != 0 );

	if ( ! m_bProtocols || ( m_pQueue->m_nProtocols & (1<<PROTOCOL_HTTP) ) )
		m_wndProtocols.SetItemState( 0, INDEXTOSTATEIMAGEMASK(2), LVIS_STATEIMAGEMASK );
	if ( ! m_bProtocols || ( m_pQueue->m_nProtocols & (1<<PROTOCOL_ED2K) ) )
		m_wndProtocols.SetItemState( 1, INDEXTOSTATEIMAGEMASK(2), LVIS_STATEIMAGEMASK );

	m_bEnable		= m_pQueue->m_bEnable || m_bEnableOverride;

	m_nCapacity		= max( m_pQueue->m_nCapacity, m_pQueue->m_nMaxTransfers );
	m_nTransfersMin	= m_pQueue->m_nMinTransfers;
	m_nTransfersMax	= m_pQueue->m_nMaxTransfers;

	m_bRotate		= m_pQueue->m_bRotate;
	m_nRotateTime	= m_pQueue->m_nRotateTime;

	m_bReward		= m_pQueue->m_bRewardUploaders;

	DWORD nTotal = Settings.Connection.OutSpeed * 1024 / 8;
	DWORD nLimit = Settings.Bandwidth.Uploads;

	if ( nLimit == 0 || nLimit > nTotal ) nLimit = nTotal;
	int nOtherPoints = UploadQueues.GetTotalBandwidthPoints( !( m_pQueue->m_nProtocols & (1<<PROTOCOL_ED2K) ) ) - m_pQueue->m_nBandwidthPoints;

	if ( nOtherPoints < 0 ) nOtherPoints = 0;

	m_wndBandwidthSlider.SetRange( 1, max( 100, nOtherPoints * 3 ) );
	m_wndBandwidthSlider.SetPos( m_pQueue->m_nBandwidthPoints );

	UpdateData( FALSE );

	m_wndMinSize.EnableWindow( m_bMinSize );
	m_wndMaxSize.EnableWindow( m_bMaxSize );
	m_wndMarked.EnableWindow( m_bMarked );
	m_wndMatch.EnableWindow( m_bMatch );
	m_wndProtocols.EnableWindow( m_bProtocols );
	m_wndRotateTime.EnableWindow( m_bRotate );
	m_wndRotateTimeSpin.EnableWindow( m_bRotate );
	m_wndCapacity.SetRange32( m_nTransfersMax, 4096 );
	OnHScroll( 0, 0, NULL );


	if ( Settings.General.GUIMode == GUI_BASIC )
	{
		if ( !( Settings.eDonkey.EnableAlways | Settings.eDonkey.EnableToday ) )
		{
			m_bProtocols = FALSE;
			m_wndProtocols.EnableWindow( FALSE );
			m_wndProtocols.ShowWindow( FALSE );

			(GetProtocolCheckbox())->EnableWindow( FALSE );
			(GetProtocolCheckbox())->ShowWindow( FALSE );
		}
	}

	return TRUE;
}

void CQueuePropertiesDlg::OnMinimumCheck()
{
	UpdateData();
	m_wndMinSize.EnableWindow( m_bMinSize );
}

void CQueuePropertiesDlg::OnMaximumCheck()
{
	UpdateData();
	m_wndMaxSize.EnableWindow( m_bMaxSize );
}

void CQueuePropertiesDlg::OnMarkedCheck()
{
	UpdateData();
	m_wndMarked.EnableWindow( m_bMarked );
}

void CQueuePropertiesDlg::OnMatchCheck()
{
	UpdateData();
	m_wndMatch.EnableWindow( m_bMatch );
}

void CQueuePropertiesDlg::OnProtocolsCheck()
{
	if ( Settings.General.GUIMode == GUI_BASIC )
		if ( !( Settings.eDonkey.EnableAlways | Settings.eDonkey.EnableToday ) )
			return;

	UpdateData();
	m_wndProtocols.EnableWindow( m_bProtocols );
}

void CQueuePropertiesDlg::OnChangeTransfersMax()
{
	if ( m_wndBandwidthValue.m_hWnd != NULL )
	{
		UpdateData();
		m_nCapacity = max( m_nCapacity, m_nTransfersMax );
		m_wndCapacity.SetRange( m_nTransfersMax, 1024 );
		UpdateData( FALSE );
	}
}

void CQueuePropertiesDlg::OnRotateEnable()
{
	UpdateData();
	m_wndRotateTime.EnableWindow( m_bRotate );
	m_wndRotateTimeSpin.EnableWindow( m_bRotate );
}

void CQueuePropertiesDlg::OnHScroll(UINT nSBCode, UINT nPos, CScrollBar* pScrollBar)
{
	DWORD nTotal = Settings.Connection.OutSpeed * 1024 / 8;
	DWORD nLimit = Settings.Bandwidth.Uploads;

	if ( nLimit == 0 || nLimit > nTotal ) nLimit = nTotal;

	int nOtherPoints = UploadQueues.GetTotalBandwidthPoints( !( m_pQueue->m_nProtocols & (1<<PROTOCOL_ED2K) ) ) - m_pQueue->m_nBandwidthPoints;
	if ( nOtherPoints < 0 ) nOtherPoints = 0;

	int nLocalPoints = m_wndBandwidthSlider.GetPos();
	int nTotalPoints = nLocalPoints + nOtherPoints;

	DWORD nBandwidth = nLimit * nLocalPoints / max( 1, nTotalPoints );

	CString str;
	str.Format( _T("%.2f%% (%lu/%lu)"), 100.0 * nBandwidth / nLimit,
		nLocalPoints, nTotalPoints );

	m_wndBandwidthPoints.SetWindowText( str );
	m_wndBandwidthValue.SetWindowText( Settings.SmartVolume( nBandwidth * 8, FALSE, TRUE ) + '+' );
}

void CQueuePropertiesDlg::OnOK()
{
	UpdateData();

	CSingleLock pLock( &UploadQueues.m_pSection, TRUE );

	if ( ! UploadQueues.Check( m_pQueue ) )
	{
		CSkinDialog::OnCancel();
		return;
	}

	m_pQueue->m_sName = m_sName;

	m_pQueue->m_bPartial = m_bPartial;

	if ( m_bMinSize )
	{
		m_pQueue->m_nMinSize = Settings.ParseVolume( m_sMinSize, FALSE );
	}
	else
	{
		m_pQueue->m_nMinSize = 0;
	}

	if ( m_bMaxSize )
	{
		m_pQueue->m_nMaxSize = Settings.ParseVolume( m_sMaxSize, FALSE );
		if ( m_pQueue->m_nMaxSize == 0 ) m_pQueue->m_nMaxSize = SIZE_UNKNOWN;
	}
	else
	{
		m_pQueue->m_nMaxSize = SIZE_UNKNOWN;
	}

	if ( m_bMarked )
	{
		m_pQueue->m_sShareTag = m_sMarked;
	}
	else
	{
		m_pQueue->m_sShareTag.Empty();
	}

	if ( m_bMatch )
	{
		m_pQueue->m_sNameMatch = m_sMatch;
	}
	else
	{
		m_pQueue->m_sNameMatch.Empty();
	}

	m_pQueue->m_nProtocols = 0;

	if ( m_bProtocols )
	{
		if ( m_wndProtocols.GetItemState( 0, LVIS_STATEIMAGEMASK ) == INDEXTOSTATEIMAGEMASK(2) )
			m_pQueue->m_nProtocols |= (1<<PROTOCOL_HTTP);
		if ( m_wndProtocols.GetItemState( 1, LVIS_STATEIMAGEMASK ) == INDEXTOSTATEIMAGEMASK(2) )
			m_pQueue->m_nProtocols |= (1<<PROTOCOL_ED2K);

		if ( m_pQueue->m_nProtocols == ( (1<<PROTOCOL_HTTP)|(1<<PROTOCOL_ED2K) ) )
			m_pQueue->m_nProtocols = 0;
	}

	if ( ( m_pQueue->m_nProtocols & (1<<PROTOCOL_ED2K) ) )
		m_pQueue->m_nCapacity		= min( m_nCapacity, 4096 );
	else
		m_pQueue->m_nCapacity		= min( m_nCapacity, 64 );

	m_pQueue->m_bEnable			= m_bEnable;
	m_pQueue->m_nMinTransfers	= max( 1, m_nTransfersMin );
	m_pQueue->m_nMaxTransfers	= max( m_nTransfersMin, m_nTransfersMax );

	m_pQueue->m_bRotate			= m_bRotate;
	m_pQueue->m_nRotateTime		= max(30, m_nRotateTime );

	m_pQueue->m_nBandwidthPoints = m_wndBandwidthSlider.GetPos();

	m_pQueue->m_bRewardUploaders = m_bReward;

	CSkinDialog::OnOK();
}
