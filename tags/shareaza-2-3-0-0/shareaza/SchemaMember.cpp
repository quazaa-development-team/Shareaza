//
// SchemaMember.cpp
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
#include "Schema.h"
#include "SchemaMember.h"
#include "XML.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif


//////////////////////////////////////////////////////////////////////
// CSchemaMember construction

CSchemaMember::CSchemaMember(CSchema* pSchema)
: m_pSchema(pSchema)
, m_bNumeric(FALSE)
, m_bYear(FALSE)
, m_bGUID(FALSE)
, m_bIndexed(FALSE)
, m_bSearched(FALSE)
, m_nMinOccurs(0)
, m_nMaxOccurs(0)
, m_nMaxLength(128)
, m_bPrompt(FALSE)
, m_nFormat(smfNone)
, m_nColumnWidth(60)
, m_nColumnAlign(LVCFMT_LEFT)
, m_bHidden(FALSE)
, m_bBoolean(FALSE)
{
}

CSchemaMember::~CSchemaMember()
{
}

//////////////////////////////////////////////////////////////////////
// CSchemaMember item access

POSITION CSchemaMember::GetItemIterator() const
{
	return m_pItems.GetHeadPosition();
}

CString CSchemaMember::GetNextItem(POSITION& pos) const
{
	return m_pItems.GetNext( pos );
}

//////////////////////////////////////////////////////////////////////
// CSchemaMember value lookup

CString CSchemaMember::GetValueFrom(CXMLElement* pBase, LPCTSTR pszDefault, BOOL bFormat) const
{
	// OPTIMIZE: This could all be done with LPCTSTR pointers instead of CString
	CString strValue;
	
	if ( pBase != NULL )
	{
		if ( CXMLElement* pElement = pBase->GetElementByName( m_sName ) )
		{
			strValue = pElement->GetValue();
		}
		else
		{
			strValue = pBase->GetAttributeValue( m_sName, pszDefault );
		}
	}
	else if ( pszDefault != NULL )
	{
		strValue = pszDefault;
	}
	
	// validate numeric value, empty if invalid
	if ( m_bNumeric )
	{
		float nNumber = 0.0;
		_stscanf( strValue, L"%f", &nNumber );
		if ( nNumber < (float)m_nMinOccurs || nNumber > (float)m_nMaxOccurs )
			strValue.Empty();
	}
	else if ( m_bYear )
	{
		int nYear = 0;
		if ( _stscanf( strValue, L"%i", &nYear ) != 1 || nYear < 1000 || nYear > 9999 ) 
			strValue.Empty();
	}
	else if ( m_bGUID && strValue.GetLength() )
	{
		Hashes::Guid tmp;
		if ( !( Hashes::fromGuid( strValue, &tmp[ 0 ] ) && tmp.validate() ) )
			strValue.Empty();
	}
	else if ( m_bBoolean )
	{
		if ( strValue == L"1" || strValue.CompareNoCase( L"true" ) == 0 )
			strValue = L"true";
		else if ( strValue == L"0" || strValue.CompareNoCase( L"false" ) == 0 )
			strValue = L"false";
		else
			strValue.Empty();
	}

	if ( strValue.IsEmpty() ) return strValue;
	
	if ( bFormat && m_bNumeric ) 
	{
		if ( m_nFormat == smfTimeMMSS )
		{
			DWORD nSeconds = 0;
			_stscanf( strValue, L"%lu", &nSeconds );
			strValue.Format( L"%.2u:%.2u", nSeconds / 60, nSeconds % 60 );
		}
		else if ( m_nFormat == smfTimeHHMMSSdec )
		{
			float nMinutes = 0;
			_stscanf( strValue, L"%f", &nMinutes );
			strValue.Format( L"%.2u:%.2u:%.2u", (int)nMinutes / 60,
				(int)nMinutes % 60, (int)( ( nMinutes - (int)nMinutes ) * 60 ) );
		}
		else if ( m_nFormat == smfFrequency )
		{
			DWORD nRate = 0;
			_stscanf( strValue, L"%lu", &nRate );
			strValue.Format( L"%.1f kHz", nRate / 1000.0 );
		}
		else if ( m_nFormat == smfBitrate )
		{
			BOOL bVariable = _tcschr( strValue, '~' ) != NULL;
			DWORD nBitrate = 0;
			_stscanf( strValue, L"%lu", &nBitrate );
			strValue.Format( bVariable ? L"%luk~" : L"%luk", nBitrate );
		}
	}
	
	return strValue;
}

//////////////////////////////////////////////////////////////////////
// CSchemaMember value set

void CSchemaMember::SetValueTo(CXMLElement* pBase, LPCTSTR pszValue)
{
	if ( CXMLElement* pElement = pBase->GetElementByName( m_sName ) )
	{
		if ( m_bElement && pszValue != NULL && _tcslen( pszValue ) > 0 )
			pElement->SetValue( pszValue );
		else
			pElement->Delete();
	}
	else if ( m_bElement && pszValue != NULL && _tcslen( pszValue ) > 0 )
	{
		CXMLElement* pElement = pBase->AddElement( m_sName );
		pElement->SetValue( pszValue );
	}
	
	if ( CXMLAttribute* pAttribute = pBase->GetAttribute( m_sName ) )
	{
		if ( ! m_bElement && pszValue != NULL && _tcslen( pszValue ) > 0 )
			pAttribute->SetValue( pszValue );
		else
			pAttribute->Delete();
	}
	else if ( ! m_bElement && pszValue != NULL && _tcslen( pszValue ) > 0 )
	{
		pBase->AddAttribute( m_sName, pszValue );
	}
}

//////////////////////////////////////////////////////////////////////
// CSchemaMember load schema

BOOL CSchemaMember::LoadSchema(CXMLElement* pRoot, CXMLElement* pElement)
{
	m_bElement = pElement->GetName().CompareNoCase( L"element" ) == 0;

	m_sName = pElement->GetAttributeValue( L"name", L"" );
	if ( m_sName.IsEmpty() ) return FALSE;

	m_sTitle = m_sName;
	m_sTitle.SetAt( 0, TCHAR( toupper( m_sTitle.GetAt( 0 ) ) ) );

	m_sType = pElement->GetAttributeValue( L"type", L"" );
	ToLower( m_sType );

	m_bNumeric = ( m_sType == L"short" || m_sType == L"int" || m_sType == L"decimal" );
	m_bBoolean = m_sType == L"boolean";
	m_bYear = m_sType == L"year";
	m_bGUID = m_sType == L"guidtype";

	CString strValue = pElement->GetAttributeValue( L"minOccurs", L"0" );
	_stscanf( strValue, L"%i", &m_nMinOccurs );
	strValue = pElement->GetAttributeValue( L"maxOccurs", L"65536" );
	_stscanf( strValue, L"%i", &m_nMaxOccurs );
	
	if ( pElement->GetElementCount() )
	{
		return LoadType( pElement->GetFirstElement() );
	}
	else if ( m_sType.GetLength() )
	{
		CXMLElement* pType = m_pSchema->GetType( pRoot, m_sType );
		return pType ? LoadType( pType ) : TRUE;
	}
	else
	{
		return FALSE;
	}
}

BOOL CSchemaMember::LoadType(CXMLElement* pType)
{
	CString strName = pType->GetName();

	if ( strName.CompareNoCase( L"simpleType" ) &&
		 strName.CompareNoCase( L"complexType" ) ) return FALSE;

	m_sType = pType->GetAttributeValue( L"base", L"" );
	ToLower( m_sType );

	m_bNumeric = ( m_sType == L"short" || m_sType == L"int" || m_sType == L"decimal" );
	m_bBoolean = m_sType == L"boolean";
	m_bYear = m_sType == L"year";
	m_bGUID = m_sType == L"guidtype";
	
	for ( POSITION pos = pType->GetElementIterator() ; pos ; )
	{
		CXMLElement* pElement	= pType->GetNextElement( pos );
		CString strElement		= pElement->GetName();

		if ( strElement.CompareNoCase( L"enumeration" ) == 0 )
		{
			CString strValue = pElement->GetAttributeValue( L"value", L"" );
			if ( strValue.GetLength() ) m_pItems.AddTail( strValue );
		}
		else if ( strElement.CompareNoCase( L"maxInclusive" ) == 0 )
		{
			CString strValue = pElement->GetAttributeValue( L"value", L"0" );
			_stscanf( strValue, L"%i", &m_nMaxLength );
		}
	}

	return TRUE;
}

//////////////////////////////////////////////////////////////////////
// CSchemaMember load descriptor

BOOL CSchemaMember::LoadDescriptor(CXMLElement* pXML)
{
	CString strSearch = pXML->GetAttributeValue( L"search" );
	
	if ( strSearch.CompareNoCase( L"generic" ) == 0 )
	{
		m_bIndexed	= TRUE;
		m_bSearched	= TRUE;
	}
	else if ( strSearch.CompareNoCase( L"indexed" ) == 0 )
	{
		m_bIndexed = TRUE;
	}
	
	CString strTitle = m_sTitle;
	m_sTitle.Empty();
	
	for ( POSITION pos = pXML->GetElementIterator() ; pos ; )
	{
		CXMLElement* pElement = pXML->GetNextElement( pos );
		
		if ( pElement->IsNamed( L"display" ) )
		{
			LoadDisplay( pElement );
		}
		else if ( pElement->IsNamed( L"title" ) )
		{
			if ( pElement->GetAttributeValue( L"language" ).
				 CompareNoCase( Settings.General.Language ) == 0 )
			{
				m_sTitle = pElement->GetValue();
			}
			else if ( m_sTitle.IsEmpty() )
			{
				m_sTitle = pElement->GetValue();
			}
		}
		else if ( pElement->IsNamed( L"link" ) )
		{
			m_sLinkURI	= pElement->GetAttributeValue( L"location" );
			m_sLinkName	= pElement->GetAttributeValue( L"remote" );
		}
	}
	
	if ( m_sTitle.IsEmpty() ) m_sTitle = strTitle;
	
	return TRUE;
}

BOOL CSchemaMember::LoadDisplay(CXMLElement* pDisplay)
{
	CString strFormat	= pDisplay->GetAttributeValue( L"format" );
	CString strWidth	= pDisplay->GetAttributeValue( L"columnWidth" );
	CString strAlign	= pDisplay->GetAttributeValue( L"columnAlign" );
	CString strColumn	= pDisplay->GetAttributeValue( L"defaultColumn" );
	CString strSearch	= pDisplay->GetAttributeValue( L"prompt" );
	CString strHidden	= pDisplay->GetAttributeValue( L"hidden" );	

	if ( strHidden.CompareNoCase( L"true" ) == 0 )
	{
		m_bHidden = TRUE;
		strSearch = strColumn = L"false";
	}

	if ( strFormat.CompareNoCase( L"timeMMSS" ) == 0 )
		m_nFormat = smfTimeMMSS;
	else if ( strFormat.CompareNoCase( L"timeHHMMSSdec" ) == 0 )
		m_nFormat = smfTimeHHMMSSdec;
	else if ( strFormat.CompareNoCase( L"bitrate" ) == 0 )
		m_nFormat = smfBitrate;
	else if ( strFormat.CompareNoCase( L"frequency" ) == 0 )
		m_nFormat = smfFrequency;
	
	_stscanf( strWidth, L"%lu", &m_nColumnWidth );
	
	if ( strAlign.CompareNoCase( L"left" ) == 0 )
		m_nColumnAlign = LVCFMT_LEFT;
	else if ( strAlign.CompareNoCase( L"center" ) == 0 )
		m_nColumnAlign = LVCFMT_CENTER;
	else if ( strAlign.CompareNoCase( L"right" ) == 0 )
		m_nColumnAlign = LVCFMT_RIGHT;
	
	if ( strColumn.CompareNoCase( L"true" ) == 0 )
	{
		m_pSchema->m_sDefaultColumns += '|';
		m_pSchema->m_sDefaultColumns += m_sName;
		m_pSchema->m_sDefaultColumns += '|';
	}
	
	if ( strSearch.CompareNoCase( _T("true") ) == 0 )
	{
		m_bPrompt = TRUE;
	}
	
	return TRUE;
}
