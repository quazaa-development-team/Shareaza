//
// Transfers.cpp
//
// Copyright (c) Shareaza Development Team, 2002-2007.
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
#include "Transfers.h"
#include "Transfer.h"
#include "TransferFile.h"
#include "Downloads.h"
#include "Uploads.h"
#include "EDClients.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

CTransfers Transfers;


//////////////////////////////////////////////////////////////////////
// CTransfers construction

CTransfers::CTransfers() : 	m_pMessageQueue()
{
	m_nBuffer		= 256*1024;
	m_pBuffer		= new BYTE[ m_nBuffer ];
	m_hThread		= NULL;
	m_bThread		= FALSE;
	m_nRunCookie	= 0;
}

CTransfers::~CTransfers()
{
	StopThread();
	delete [] m_pBuffer;
}

//////////////////////////////////////////////////////////////////////
// CTransfers list tests

INT_PTR CTransfers::GetActiveCount() const
{
	return Downloads.GetCount( TRUE ) + Uploads.GetTransferCount();
}

BOOL CTransfers::IsConnectedTo(IN_ADDR* pAddress)
{
	CSingleLock pLock( &m_pSection );
	if ( ! pLock.Lock( 100 ) ) return FALSE;

	const_TransferItem index  = begin();
	const_TransferItem indexEnd  = end();

	for (; index != indexEnd; index++ )
	{
		if ( (*index)->m_pHost.sin_addr.S_un.S_addr == pAddress->S_un.S_addr ) return TRUE;
	}

	return FALSE;
}

//////////////////////////////////////////////////////////////////////
// CTransfers thread start and stop

BOOL CTransfers::StartThread()
{
	if ( m_hThread != NULL && m_bThread ) return TRUE;
	if ( size() == 0 && Downloads.GetCount() == 0 ) return FALSE;

	m_hThread	= NULL;
	m_bThread	= TRUE;
	
	CITMQueue::EnableITM( &( m_pMessageQueue ) );
	CWinThread* pThread = AfxBeginThread( ThreadStart, this, THREAD_PRIORITY_NORMAL );
	SetThreadName( pThread->m_nThreadID, "Transfers" );
	m_hThread = pThread->m_hThread;

	return TRUE;
}

void CTransfers::StopThread()
{
	if ( m_hThread == NULL ) return;
	CITMQueue::DisableITM( &( m_pMessageQueue ) );

	m_bThread = FALSE;
	m_pWakeup.SetEvent();

	CloseThread( &m_hThread, _T("CTransfers") );

	Downloads.m_nTransfers	= 0;
	Downloads.m_nBandwidth	= 0;
	Uploads.m_nCount		= 0;
	Uploads.m_nBandwidth	= 0;
}

//////////////////////////////////////////////////////////////////////
// CTransfers registration

void CTransfers::Add(CTransfer* pTransfer)
{
	//ASSERT( pTransfer->m_hSocket != INVALID_SOCKET );
	WSAEventSelect( pTransfer->m_hSocket, m_pWakeup, FD_CONNECT|FD_READ|FD_WRITE|FD_CLOSE );

	CTransfers::Lock oLock;

//	ASSERT( pTransfer->m_pSelf == NULL );
//	if ( pTransfer->m_pSelf == NULL )
//	{
//		m_pList.push_front( pTransfer );
//		pTransfer->m_pSelf = m_pList.begin();
//	}
//	ASSERT( (*(pTransfer->m_pSelf)) == pTransfer );

	if ( !Check(pTransfer) ) m_pList.push_front( pTransfer );

	//if ( Settings.General.Debug && Settings.General.DebugLog ) 
	//	theApp.Message( MSG_DEBUG, _T("CTransfers::Add(): %x"), pTransfer );

	StartThread();
}

void CTransfers::Remove(CTransfer* pTransfer)
{
	//if ( Settings.General.Debug && Settings.General.DebugLog ) 
	//	theApp.Message( MSG_DEBUG, _T("CTransfers::Remove(): %x"), pTransfer );

	if ( pTransfer->m_hSocket != INVALID_SOCKET )
		WSAEventSelect( pTransfer->m_hSocket, m_pWakeup, 0 );


	CTransfers::Lock oLock;
	//ASSERT( (*(pTransfer->m_pSelf)) == pTransfer );
	//if ( pTransfer->m_pSelf != NULL )
	//{
	//	m_pList.erase(pTransfer->m_pSelf);
	//	pTransfer->m_pSelf = NULL;
	//}
	//ASSERT( pTransfer->m_pSelf == NULL );

	m_pList.remove(pTransfer);
}

//////////////////////////////////////////////////////////////////////
// CTransfers thread run

UINT CTransfers::ThreadStart(LPVOID pParam)
{
	CTransfers* pTransfers = (CTransfers*)pParam;
	pTransfers->OnRun();
	return 0;
}

void CTransfers::OnRun()
{
	while ( m_bThread )
	{
		Sleep( Settings.General.MinTransfersRest );
		WaitForSingleObject( m_pWakeup, 50 );

		CTransfers::Lock(), EDClients.OnRun();
		if ( ! m_bThread ) break;

		OnRunTransfers();
		if ( ! m_bThread ) break;
		Downloads.OnRun();
		if ( ! m_bThread ) break;

		CTransfers::Lock(), Uploads.OnRun(), OnCheckExit();

		TransferFiles.CommitDeferred();

		m_pMessageQueue.ProcessMessages();

	}

	Downloads.m_nTransfers = Downloads.m_nBandwidth = 0;
	Uploads.m_nCount = Uploads.m_nBandwidth = 0;
}

void CTransfers::OnRunTransfers()
{
	CTransfers::Lock oLock;

	++m_nRunCookie;

/*	TransferItem index = m_pList.begin();
	TransferItem indexEnd = m_pList.end();

	for (; index != indexEnd; )
	{
		TransferItem iTemp = index;
		ASSERT( iTemp == index );
		index++;
		//ASSERT( (*iTemp)->m_pSelf == iTemp );
		(*(iTemp))->DoRun();
		ASSERT( indexEnd == m_pList.end() );
		ASSERT( iTemp != m_pList.end() );
	}*/
	const_reverse_TransferItem temp;
	CTransfer * pTransfer;

	while( !m_pList.empty() )
	{
		temp = m_pList.rbegin();
		if ( (*(temp))->m_nRunCookie == m_nRunCookie ) break;
		(*(temp))->m_nRunCookie = m_nRunCookie;
		pTransfer = *temp;
		m_pList.pop_back();
		m_pList.push_front(pTransfer);
		pTransfer->DoRun();
	}
}

void CTransfers::OnCheckExit()
{
	if ( size() == 0 && Downloads.GetCount() == 0 ) m_bThread = FALSE;

	if ( Settings.Live.AutoClose && GetActiveCount() == 0 )
	{
		CSingleLock pLock( &theApp.m_pSection );

		if ( pLock.Lock( 250 ) )
		{
			if ( CWnd* pWnd = (CWnd*)theApp.SafeMainWnd() )
			{
				Settings.Live.AutoClose = FALSE;
				pWnd->PostMessage( WM_CLOSE );
			}
		}
	}
}
