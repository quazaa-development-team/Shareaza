//
// SchemaCache.cpp
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
#include "SchemaCache.h"
#include "Schema.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

CSchemaCache SchemaCache;


//////////////////////////////////////////////////////////////////////
// CSchemaCache construction

CSchemaCache::CSchemaCache()
{
}

CSchemaCache::~CSchemaCache()
{
	Clear();
}

//////////////////////////////////////////////////////////////////////
// CSchemaCache load

int CSchemaCache::Load()
{
	WIN32_FIND_DATA pFind;
	CString strPath;
	HANDLE hSearch;
	int nCount;

	Clear();

	strPath.Format( _T("%s\\Schemas\\*.xsd"), (LPCTSTR)Settings.General.Path );
	hSearch = FindFirstFile( strPath, &pFind );
	if ( hSearch == INVALID_HANDLE_VALUE ) return 0;
	nCount = 0;

	do
	{
		strPath.Format( _T("%s\\Schemas\\%s"), (LPCTSTR)Settings.General.Path, pFind.cFileName );
		
		CSchema* pSchema = new CSchema();

		if ( pSchema->Load( strPath ) )
		{
			CString strURI( pSchema->m_sURI );
			ToLower( strURI );

			m_pURIs.SetAt( strURI, pSchema );
			
			CString strName( pSchema->m_sSingular );
			ToLower( strName );

			m_pNames.SetAt( strName, pSchema );
		}
		else
		{
			delete pSchema;
		}
	}
	while ( FindNextFile( hSearch, &pFind ) );

	FindClose( hSearch );

	return nCount;
}

//////////////////////////////////////////////////////////////////////
// CSchemaCache clear

void CSchemaCache::Clear()
{
	for ( POSITION pos = GetIterator() ; pos ; )
	{
		delete GetNext( pos );
	}
	
	m_pURIs.RemoveAll();
	m_pNames.RemoveAll();
}