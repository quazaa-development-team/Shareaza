//
// CollectionFile.h
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

class CZIPFile;
class CXMLElement;
class CLibraryFile;


class CCollectionFile : public CComObject
{
// Construction
public:
	CCollectionFile();
	virtual ~CCollectionFile();
	DECLARE_DYNAMIC(CCollectionFile)

// Member File Class
public:
	class File
	{
	// Construction
	public:
		File(CCollectionFile* pParent);
		~File();

	// Attributes
	public:
		CCollectionFile*	m_pParent;
        Hashes::Sha1Hash    m_oSHA1;
        Hashes::Md5Hash     m_oMD5;
        Hashes::TigerHash   m_oTiger;
        Hashes::Ed2kHash    m_oED2K;
	public:
		CString				m_sName;
		QWORD				m_nSize;
		CXMLElement*		m_pMetadata;
		CString				m_sSource;

	// Operations
	public:
		BOOL	Parse(CXMLElement* pXML);
		BOOL	IsComplete() const;
		BOOL	IsDownloading() const;
		BOOL	Download();
		BOOL	ApplyMetadata(CLibraryFile* pShared);

	};

// Operations
public:
	BOOL		Open(LPCTSTR pszFile);
	BOOL		Attach(HANDLE hFile);
	void		Close();
public:
	File*		FindByURN(LPCTSTR pszURN);
	File*		FindFile(CLibraryFile* pShared, BOOL bApply = FALSE);
	int			GetMissingCount();
protected:
	BOOL		LoadManifest(CZIPFile& pZIP);
	static CXMLElement* CloneMetadata(CXMLElement* pMetadata);

// Attributes
protected:
	CList< File* >	m_pFiles;
	CString			m_sTitle;
	CString			m_sThisURI;
	CString			m_sParentURI;
	CXMLElement*	m_pMetadata;

// Inlines
public:
	inline BOOL IsOpen() const
	{
		return ( m_pFiles.GetCount() > 0 );
	}

	inline POSITION GetFileIterator() const
	{
		return m_pFiles.GetHeadPosition();
	}

	inline File* GetNextFile(POSITION& pos) const
	{
		return m_pFiles.GetNext( pos );
	}

	inline INT_PTR GetFileCount() const
	{
		return m_pFiles.GetCount();
	}

	inline CString GetTitle() const
	{
		return m_sTitle;
	}

	inline CString GetThisURI() const
	{
		return m_sThisURI;
	}

	inline CString GetParentURI() const
	{
		return m_sParentURI;
	}

	inline CXMLElement* GetMetadata() const
	{
		return m_pMetadata;
	}
};
