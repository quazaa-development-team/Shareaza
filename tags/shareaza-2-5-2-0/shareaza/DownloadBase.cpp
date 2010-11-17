//
// DownloadBase.cpp
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

#include "StdAfx.h"
#include "Shareaza.h"
#include "Settings.h"
#include "Downloads.h"
#include "DownloadBase.h"
#include "DownloadTask.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

IMPLEMENT_DYNAMIC(CDownloadBase, CShareazaFile)

//////////////////////////////////////////////////////////////////////
// CDownloadBase construction

CDownloadBase::CDownloadBase() :
	m_bSHA1Trusted		( false )
,	m_bTigerTrusted		( false )
,	m_bED2KTrusted		( false )
,	m_bBTHTrusted		( false )
,	m_bMD5Trusted		( false )
,	m_nCookie			( 1 )
,	m_nSaveCookie		( 0 )
,	m_pTask				( NULL )
{
}

CDownloadBase::~CDownloadBase()
{
}

//////////////////////////////////////////////////////////////////////
// CDownloadBase check if a task is already running

bool CDownloadBase::IsTasking() const
{
	return ( m_pTask != NULL );
}

bool CDownloadBase::IsMoving() const
{
	return ( GetTaskType() == dtaskCopy );
}

//////////////////////////////////////////////////////////////////////
// CDownloadBase set a new running task

void CDownloadBase::SetTask(CDownloadTask* pTask)
{
	m_pTask = pTask;
}

//////////////////////////////////////////////////////////////////////
// CDownloadBase return currently running task

dtask CDownloadBase::GetTaskType() const
{
	return m_pTask ? m_pTask->GetTaskType() : dtaskNone;
}

//////////////////////////////////////////////////////////////////////
// CDownloadBase check if a task is the same as the currently running one

bool CDownloadBase::CheckTask(CDownloadTask* pTask) const
{
	return ( m_pTask == pTask );
}

//////////////////////////////////////////////////////////////////////
// CDownloadBase cancel currently running task

void CDownloadBase::AbortTask()
{
	if ( ! IsTasking() )
		return;

	m_pTask->Abort();

	m_pTask = NULL;
}

//////////////////////////////////////////////////////////////////////
// CDownloadBase modified

bool CDownloadBase::IsModified() const
{
	return ( m_nCookie != m_nSaveCookie );
}

void CDownloadBase::SetModified()
{
	++m_nCookie;
}

//////////////////////////////////////////////////////////////////////
// CDownload control : rename

bool CDownloadBase::Rename(const CString& strName)
{
	CString sNewName = SafeFilename( strName );

	// Don't bother if renaming to same name.
	if ( m_sName == sNewName )
		return false;

	// Set new name
	m_sName = sNewName;

	SetModified();

	return true;
}

//////////////////////////////////////////////////////////////////////
// CDownloadBase serialize

void CDownloadBase::Serialize(CArchive& ar, int nVersion)
{
	if ( ar.IsStoring() )
	{
		ar << m_sName;
		CString sSearchKeyword;
		ar << sSearchKeyword;
		ar << m_nSize;
		SerializeOut( ar, m_oSHA1 );
		ar << (uint32)m_bSHA1Trusted;
		SerializeOut( ar, m_oTiger );
		ar << (uint32)m_bTigerTrusted;
		SerializeOut( ar, m_oMD5 );
		ar << (uint32)m_bMD5Trusted;
		SerializeOut( ar, m_oED2K );
		ar << (uint32)m_bED2KTrusted;
		SerializeOut( ar, m_oBTH );
		ar << (uint32)m_bBTHTrusted;
	}
	else
	{
		ar >> m_sName;

		if ( nVersion >= 29 )
		{
			if ( nVersion >= 33 )
			{
				CString sSearchKeyword;
				ar >> sSearchKeyword;
			}
			ar >> m_nSize;
		}
		else
		{
			DWORD nSize;
			ar >> nSize;
			m_nSize = nSize;
		}
		uint32 b;
		SerializeIn( ar, m_oSHA1, nVersion );
		ar >> b;
		m_bSHA1Trusted = b != 0;
		SerializeIn( ar, m_oTiger, nVersion );
		ar >> b;
		m_bTigerTrusted = b != 0;
		if ( nVersion >= 22 )
		{
			SerializeIn( ar, m_oMD5, nVersion );
			ar >> b;
			m_bMD5Trusted = b != 0;
		}
		if ( nVersion >= 13 )
		{
			SerializeIn( ar, m_oED2K, nVersion );
			ar >> b;
			m_bED2KTrusted = b != 0;
		}
		if ( nVersion >= 37 )
		{
			SerializeIn( ar, m_oBTH, nVersion );
			ar >> b;
			m_bBTHTrusted = b != 0;
		}
	}
}