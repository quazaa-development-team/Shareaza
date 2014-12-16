//
// DlgSplash.h
//
// Copyright (c) Shareaza Development Team, 2002-2010.
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


class CSplashDlg : public CDialog
{
	DECLARE_DYNAMIC(CSplashDlg)

public:
	CSplashDlg(int nMax, bool bClosing);
	virtual ~CSplashDlg();

	enum { IDD = IDD_SPLASH };

public:
	void	Step(LPCTSTR pszText);
	void	Topmost();
	void	Hide(BOOL bAbort = FALSE);

protected:
	int			m_nPos;
	int			m_nMax;
	bool		m_bClosing;
	CString		m_sState;
	CBitmap		m_bmSplash;
	CBitmap		m_bmBuffer;
	CDC			m_dcBuffer1;
	CDC			m_dcBuffer2;

	void		DoPaint(CDC* pDC);
	BOOL		(WINAPI *m_pfnAnimateWindow)(HWND, DWORD, DWORD);

	virtual BOOL OnInitDialog();
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	afx_msg void OnPaint();
	afx_msg LRESULT OnPrintClient(WPARAM wParam, LPARAM lParam);

	DECLARE_MESSAGE_MAP()
};
