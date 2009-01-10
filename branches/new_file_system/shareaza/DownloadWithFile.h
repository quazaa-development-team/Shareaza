//
// DownloadWithFile.h
//
// Copyright (c) Shareaza Development Team, 2002-2008.
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

#pragma once

#include "DownloadWithTransfers.h"
#include "FragmentedFile.h"

class CDownloadWithFile : public CDownloadWithTransfers
{
// Construction
protected:
	CDownloadWithFile();
	virtual ~CDownloadWithFile();

// Attributes
public:
	TRISTATE		m_bVerify;		// Verify status (TRI_TRUE - verified, TRI_FALSE - failed, TRI_UNKNOWN - not yet)
	DWORD			m_tReceived;
	BOOL			m_bMoving;		// Is complete file moving?

// Operations
public:
	QWORD			GetCompleted(QWORD nOffset, QWORD nLength) const;
	float			GetProgress() const;
	QWORD			GetVolumeComplete() const;
	QWORD			GetVolumeRemaining() const;
	DWORD			GetTimeRemaining() const;
	CString			GetDisplayName() const;
	BOOL			IsFileOpen() const;
	BOOL			IsComplete() const;
	BOOL			PrepareFile();
	BOOL			GetFragment(CDownloadTransfer* pTransfer);
	BOOL			IsPositionEmpty(QWORD nOffset);
	BOOL			AreRangesUseful(const Fragments::List& oAvailable);
	BOOL			IsRangeUseful(QWORD nOffset, QWORD nLength);
	BOOL			IsRangeUsefulEnough(CDownloadTransfer* pTransfer, QWORD nOffset, QWORD nLength);
	BOOL			ClipUploadRange(QWORD nOffset, QWORD& nLength) const;
	BOOL			GetRandomRange(QWORD& nOffset, QWORD& nLength) const;
	BOOL			SubmitData(QWORD nOffset, LPBYTE pData, QWORD nLength);
	QWORD			EraseRange(QWORD nOffset, QWORD nLength);
	BOOL			MakeComplete();
	QWORD			InvalidateFileRange(QWORD nOffset, QWORD nLength);

	inline Fragments::List GetEmptyFragmentList() const
	{
		return m_pFile ? m_pFile->GetEmptyFragmentList() : Fragments::List( 0 );
	}

	inline CFragmentedFile* GetFile()
	{
		if ( m_pFile )
			m_pFile->AddRef();
		return m_pFile;
	}

	inline BOOL FindByPath(const CString& sPath) const
	{
		return m_pFile && m_pFile->FindByPath( sPath );
	}

	// Get amount of subfiles
	inline DWORD GetFileCount() const
	{
		return m_pFile ? m_pFile->GetCount() : 0;
	}

	// Get path of subfile
	inline CString GetPath(DWORD nIndex) const
	{
		return m_pFile ? m_pFile->GetPath( nIndex ) : CString();
	}

	// Is file under move operation?
	inline BOOL IsMoving() const
	{
		return m_bMoving;
	}

	// Get last file/disk operation error
	inline DWORD GetFileError() const
	{
		return m_nFileError;
	}

	// Clear file/disk error status
	inline void ClearFileError()
	{
		m_nFileError = ERROR_SUCCESS;
	}

protected:
	virtual CString	GetAvailableRanges() const;
	BOOL			OpenFile();
	void			CloseFile();
	void			AttachFile(CFragmentedFile* pFile);
	// Delete file(s)
	void			DeleteFile();
	// Move file(s) to destination. Returns 0 on success or file error number.
	DWORD			MoveFile(LPCTSTR pszDestination, LPPROGRESS_ROUTINE lpProgressRoutine = NULL, LPVOID lpData = NULL);
	BOOL			FlushFile();
	BOOL			ReadFile(QWORD nOffset, LPVOID pData, QWORD nLength, QWORD* pnRead = NULL);
	BOOL			WriteFile(QWORD nOffset, LPCVOID pData, QWORD nLength, QWORD* pnWritten = NULL);
//	BOOL			AppendMetadata();
	virtual void	Serialize(CArchive& ar, int nVersion);
	void			SerializeFile(CArchive& ar, int nVersion);
	void			SetVerifyStatus(TRISTATE bVerify);
	BOOL			OnVerify(LPCTSTR pszPath, BOOL bVerified);

private:
	CFragmentedFile*	m_pFile;		// File(s)
	DWORD				m_nFileError;	// Last file/disk error

	Fragments::List	GetPossibleFragments(const Fragments::List& oAvailable, Fragments::Fragment& oLargest);
//	BOOL			AppendMetadataID3v1(HANDLE hFile, CXMLElement* pXML);
};
