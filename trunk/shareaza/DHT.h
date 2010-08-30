//
// DHT.h
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

class CBENode;


class CDHT
{
public:
	BOOL OnPacket(const SOCKADDR_IN* pHost, const CBENode* pRoot);

protected:
	CCriticalSection m_pSection;

	//BOOL Ping(const SOCKADDR_IN* pHost);
	BOOL Pong(const SOCKADDR_IN* pHost, LPCSTR szTransID, size_t nTransIDLength);
	//BOOL GetPeers(const SOCKADDR_IN* pHost, const Hashes::BtGuid& oNodeGUID, const Hashes::BtHash& oGUID);
};

extern CDHT DHT;
