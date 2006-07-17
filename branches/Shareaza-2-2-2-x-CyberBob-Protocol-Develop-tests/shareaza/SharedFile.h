//
// SharedFile.h
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

#if !defined(AFX_SHAREDFILE_H__8FFCC311_D43C_445D_BAEB_575AE2AE8E99__INCLUDED_)
#define AFX_SHAREDFILE_H__8FFCC311_D43C_445D_BAEB_575AE2AE8E99__INCLUDED_

#pragma once

class CLibraryFolder;
class CSharedSource;
class CSchema;
class CXMLElement;
class CQuerySearch;
class CLibraryDownload;
class CTigerTree;
class CED2K;


class CLibraryFile : public CComObject
{
// Construction
public:
	CLibraryFile(CLibraryFolder* pFolder, LPCTSTR pszName = NULL);
	virtual ~CLibraryFile();
	
	DECLARE_DYNAMIC(CLibraryFile)
	
// Attributes
public:
	CLibraryFile*	m_pNextSHA1;
	CLibraryFile*	m_pNextTiger;
	CLibraryFile*	m_pNextED2K;
	CLibraryFile*	m_pNextMD5;
	DWORD			m_nScanCookie;
	DWORD			m_nUpdateCookie;
	DWORD			m_nSelectCookie;
	DWORD			m_nListCookie;
public:
	CLibraryFolder*	m_pFolder;
	CString			m_sName;
	DWORD			m_nIndex;
	QWORD			m_nSize;
	FILETIME		m_pTime;
	TRISTATE		m_bShared;
	QWORD			m_nVirtualBase;
	QWORD			m_nVirtualSize;
public:
    Hashes::Sha1Hash m_oSHA1;
    Hashes::TigerHash m_oTiger;
    Hashes::Md5Hash m_oMD5;
    Hashes::Ed2kHash m_oED2K;
	TRISTATE		m_bVerify;
public:
	CSchema*		m_pSchema;
	CXMLElement*	m_pMetadata;
	BOOL			m_bMetadataAuto;
	FILETIME		m_pMetadataTime;
	int				m_nRating;
	CString			m_sComments;
	CString			m_sShareTags;
public:
	DWORD			m_nHitsToday;
	DWORD			m_nHitsTotal;
	DWORD			m_nUploadsToday;
	DWORD			m_nUploadsTotal;
	BOOL			m_bCachedPreview;
	BOOL			m_bBogus;
	CList< CSharedSource* > m_pSources;
public:
	DWORD			m_nSearchCookie;
	DWORD			m_nSearchWords;
	CLibraryFile*	m_pNextHit;
	DWORD			m_nCollIndex;
	int				m_nIcon16;
	
// Operations
public:
	CString			GetPath() const;
	CString			GetSearchName() const;
	BOOL			IsShared() const;
	inline BOOL		IsGhost() const { return m_pFolder == NULL; }
	inline BOOL		IsAvailable() const { return m_pFolder != NULL; }
	BOOL			IsSchemaURI(LPCTSTR pszURI) const;
public:
	BOOL			Rebuild();
	BOOL			Rename(LPCTSTR pszName);
	BOOL			Delete(BOOL bDeleteGhost = FALSE);
	BOOL			SetMetadata(CXMLElement* pXML);
	CString			GetMetadataWords() const;
	BOOL			SaveMetadata();
	CTigerTree*		GetTigerTree();
	CED2K*			GetED2K();
public:
	CSharedSource*	AddAlternateSource(LPCTSTR pszURL, BOOL bForce = TRUE);
	CSharedSource*	AddAlternateSources(LPCTSTR pszURL);
	CString			GetAlternateSources(CList< CString >* pState, int nMaximum, PROTOCOLID nProtocol);
protected:
	void			Serialize(CArchive& ar, int nVersion);
	BOOL			ThreadScan(CSingleLock& pLock, DWORD nScanCookie, QWORD nSize, FILETIME* pTime, LPCTSTR pszMetaData);
	BOOL			LoadMetadata(HANDLE hFile);
	void			OnDelete(BOOL bDeleteGhost = FALSE);
	void			Ghost();
    BOOL			OnVerifyDownload(const Hashes::Sha1Hash& oSHA1, const Hashes::Ed2kHash& oED2K, LPCTSTR pszSources);
	
// Inlines
public:
	inline CString GetNameLC() const
	{
		CString str = m_sName;
		CharLower( str.GetBuffer() );
		str.ReleaseBuffer();
		return str;
	}
	
	inline QWORD GetSize() const
	{
		return ( m_nVirtualSize > 0 ) ? m_nVirtualSize : m_nSize;
	}
	
// Friends
public:
	friend class CLibrary;
	friend class CLibraryFolder;
	friend class CLibraryMaps;
	friend class CLibraryRecent;
	friend class CDeleteFileDlg;
	
// Automation
protected:
	BEGIN_INTERFACE_PART(LibraryFile, ILibraryFile)
		DECLARE_DISPATCH()
		STDMETHOD(get_Application)(IApplication FAR* FAR* ppApplication);
		STDMETHOD(get_Library)(ILibrary FAR* FAR* ppLibrary);
		STDMETHOD(get_Folder)(ILibraryFolder FAR* FAR* ppFolder);
		STDMETHOD(get_Path)(BSTR FAR* psPath);
		STDMETHOD(get_Name)(BSTR FAR* psPath);
		STDMETHOD(get_Shared)(STRISTATE FAR* pnValue);
		STDMETHOD(put_Shared)(STRISTATE nValue);
		STDMETHOD(get_EffectiveShared)(VARIANT_BOOL FAR* pbValue);
		STDMETHOD(get_Size)(LONG FAR* pnSize);
		STDMETHOD(get_Index)(LONG FAR* pnIndex);
		STDMETHOD(get_URN)(BSTR sURN, BSTR FAR* psURN);
		STDMETHOD(get_MetadataAuto)(VARIANT_BOOL FAR* pbValue);
		STDMETHOD(get_Metadata)(ISXMLElement FAR* FAR* ppXML);
		STDMETHOD(put_Metadata)(ISXMLElement FAR* pXML);
		STDMETHOD(Execute)();
		STDMETHOD(SmartExecute)();
		STDMETHOD(Delete)();
		STDMETHOD(Rename)(BSTR sNewName);
		STDMETHOD(Copy)(BSTR sNewPath);
		STDMETHOD(Move)(BSTR sNewPath);
	END_INTERFACE_PART(LibraryFile)
	
	DECLARE_INTERFACE_MAP()
	
};


class CSharedSource
{
// Construction
public:
	CSharedSource(LPCTSTR pszURL = NULL, FILETIME* pTime = NULL);

// Attributes
public:
	CString		m_sURL;									// The URL
	FILETIME	m_pTime;								// Time last seen

// Operations
public:
	void	Serialize(CArchive& ar, int nVersion);
	void	Freshen(FILETIME* pTime = NULL);
	BOOL	IsExpired(FILETIME& tNow);

};


// Still Under construction
class CSharedSourceAddr
{
public:
	// Node type
	enum NodeType
	{
	/*
		Bit
		5	4	3	2	1
		|	|	|	|	|
		|	|	|	|	-- Gnutella1 ( store only IP and PORT in format of "ip:port")
		|	|	|	------ Gnutella2 ( store only IP and PORT in format of "ip:port")
		|	|	---------- eDonkey2000 ( store only IP and PORT in format of "ip:port")
		|	-------------- Torrent ( store only IP and PORT in format of "ip:port")
		------------------ URL (This bit set means the String is URL, which can be HTTP/ed2kftp/ftp,
		                         the corresponding bit G1/2, ed2k can be set if the URL is for them, but
								 Strongly not recommended to do it.)
	*/


		PROTOCOL_NULL = 0,		// node is Unknown Type (Useless but needed for Constructor)
		PROTOCOL_G1 = 1,		// node is Gnutella1
		PROTOCOL_G2 = 2,		// node is Gnutella2
		PROTOCOL_GMIX = 3,		// node is Gnutella1/2 Mix (i.e. Shareaza, GnucDNA)
		PROTOCOL_ED2K = 4,		// node is eDonkey
		PROTOCOL_TORRENT = 8,	// node is Torrent (This is useless in Library for now, but might get supported in future.)
		PROTOCOL_ALL = 15,		// node is Mix of all above (i.e. Shareaza, possibly some others)
		PROTOCOL_URL = 16		// Address in m_pNode is URL (i.e. Web/FTP server)
	};
	

// Construction
public:
	CSharedSourceAddr( NodeType nType, CString pNode, FILETIME* pTime = NULL, FILETIME* pMinLastTime = NULL);

// Attributes
public:
	NodeType	m_nType;			// Node Type
	CString		m_pNode;			// SourceNode Address/URL
									// Reason to use String for node address is making compatible to URL and DDNS support.
	FILETIME	m_pTime;			// Time last seen
	FILETIME	m_pMinLastTime;		// Minimum time source should last (Override m_pTime, basically for Web Servers)

// Operations
public:
	void	Serialize(CArchive& ar, int nVersion);
	void	Freshen(FILETIME* pTime = NULL);
	BOOL	IsExpired(FILETIME& tNow);

};




#endif // !defined(AFX_SHAREDFILE_H__8FFCC311_D43C_445D_BAEB_575AE2AE8E99__INCLUDED_)
