//
// Buffer.cpp
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

// CBuffer holds some memory, and takes care of allocating and freeing it itself
// http://wiki.shareaza.com/static/Developers.Code.CBuffer

// Copy in the contents of these files here before compiling
#include "StdAfx.h"
#include "Shareaza.h"
#include "Settings.h"
#include "Buffer.h"
#include "Packet.h"
#include "ZLib.h"
#include "Statistics.h"

// If we are compiling in debug mode, replace the text "THIS_FILE" in the code with the name of this file
#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

// Define memory sizes to use in these methods
#define TEMP_BUFFER 4096       // Use a 4 KB buffer as a temporary store between a socket and the buffer object
#define BLOCK_SIZE  1024       // Change the allocated size of the buffer in 1 KB sized blocks
#define BLOCK_MASK  0xFFFFFC00 // Aids in rounding to the next biggest KB of size

///////////////////////////////////////////////////////////////////////////////
// CBuffer construction

// Takes access to a DWORD that is not used (do)
// Makes a new blank CBuffer object with no memory block allocated yet
CBuffer::CBuffer(DWORD* /*pLimit*/)
{
	// Null pointers and zero counts
	m_pNext   = NULL; // This object isn't in a list yet
	m_pBuffer = NULL; // No memory block has been allocated for this object yet
	m_nBuffer = 0;    // The size of the memory block is 0
	m_nLength = 0;    // No bytes have been written here yet
}

// Delete this CBuffer object
// Frees the memory taken up by the buffer
CBuffer::~CBuffer()
{
	// If the member variable points to some memory, free it
	if ( m_pBuffer ) free( m_pBuffer );
	m_pBuffer = NULL;
}

///////////////////////////////////////////////////////////////////////////////
// CBuffer add

// Takes a pointer to memory, and how many bytes are stored there
// Adds that memory to this buffer
void CBuffer::Add(const void * pData, size_t nLength_)
{
	// primitive overflow protection (relevant for 64bit)
	if ( nLength_ > std::numeric_limits< int >::max() - m_nBuffer ) return;
	DWORD nLength = static_cast< DWORD >( nLength_ );
	// If the buffer isn't big enough to hold the new memory
	if ( m_nLength + nLength > m_nBuffer )
	{
		// Set the buffer size to the size needed
		m_nBuffer = m_nLength + nLength;

		// Make the size larger to the nearest multiple of 1024 bytes, or 1 KB
		m_nBuffer = ( m_nBuffer + BLOCK_SIZE - 1 ) & BLOCK_MASK; // 1-1024 becomes 1024, 1025 becomes 2048

		// Allocate more space at the end of the memory block
		m_pBuffer = (BYTE*)realloc( m_pBuffer, m_nBuffer ); // This may move the block, returning a different pointer

	} // If the buffer is larger than 512 KB, but what it needs to hold is less than 256 KB
	else if ( m_nBuffer > 0x80000 && m_nLength + nLength < 0x40000 )
	{
		// Reallocate it to make it half as big
		m_nBuffer = 0x40000;
		m_pBuffer = (BYTE*)realloc( m_pBuffer, m_nBuffer ); // This may move the block, returning a different pointer
	}

	if ( m_pBuffer )
	{
		// Copy the given memory into the end of the memory block
		CopyMemory( m_pBuffer + m_nLength, pData, nLength );
		m_nLength += nLength; // Add the length of the new memory to the total length in the buffer
	}
	else
	{
		m_nLength = 0;
		m_nBuffer = 0;
		theApp.Message( MSG_ERROR, _T("Memory allocation error in CBuffer::Add()") );
	}
}

///////////////////////////////////////////////////////////////////////////////
// CBuffer insert

// Takes offset, a position in the memory block to insert some new memory at
// Inserts the memory there, shifting anything after it further to the right
void CBuffer::Insert(DWORD nOffset, const void * pData, size_t nLength_)
{
	// primitive overflow protection (relevant for 64bit)
	if ( nLength_ > std::numeric_limits< int >::max() - m_nBuffer ) return;
	DWORD nLength = static_cast< DWORD >( nLength_ );
	// If the buffer isn't big enough to hold the new memory
	if ( m_nLength + nLength > m_nBuffer )
	{
		// Set the buffer size to the size needed
		m_nBuffer = m_nLength + nLength;

		// Make the size larger to the nearest multiple of 1024 bytes, or 1 KB
		m_nBuffer = ( m_nBuffer + BLOCK_SIZE - 1 ) & BLOCK_MASK; // 1-1024 becomes 1024, 1025 becomes 2048

		// Allocate more space at the end of the memory block
		m_pBuffer = (BYTE*)realloc( m_pBuffer, m_nBuffer ); // This may move the block, returning a different pointer

	} // If the buffer is larger than 512 KB, but what it needs to hold is less than 256 KB
	else if ( m_nBuffer > 0x80000 && m_nLength + nLength < 0x40000 )
	{
		// Reallocate it to make it half as big
		m_nBuffer = 0x40000;
		m_pBuffer = (BYTE*)realloc( m_pBuffer, m_nBuffer ); // This may move the block, returning a different pointer
	}

	if ( m_pBuffer )
	{
		// Cut the memory block sitting in the buffer in two, slicing it at offset and shifting that part forward nLength
		MoveMemory(
			m_pBuffer + nOffset + nLength, // Destination is the offset plus the length of the memory block to insert
			m_pBuffer + nOffset,           // Source is at the offset
			m_nLength - nOffset );         // Length is the size of the memory block beyond the offset

		// Now that there is nLength of free space in the buffer at nOffset, copy the given memory to fill it
		CopyMemory(
			m_pBuffer + nOffset, // Destination is at the offset in the buffer
			pData,               // Source is the given pointer to the memory to insert
			nLength );           // Length is the length of that memory

		// Add the length of the new memory to the total length in the buffer
		m_nLength += nLength;
	}
	else
	{
		m_nLength = 0;
		m_nBuffer = 0;
		theApp.Message( MSG_ERROR, _T("Memory allocation error in CBuffer::Insert()") );
	}
}

///////////////////////////////////////////////////////////////////////////////
// CBuffer remove

// Takes a number of bytes
// Removes this number from the start of the buffer, shifting the memory after it to the start
void CBuffer::Remove(size_t nLength)
{
	// Check the given length
	if ( nLength > m_nLength // We're being asked to remove more bytes than are stores in the buffer
		|| nLength == 0 )    // We're being asked to remove nothing
		return;              // Leave now

	// Subtract the removed bytes from the count of how many are stored here
	m_nLength -= static_cast< DWORD >( nLength );

	// Shift the bytes at nLength in the buffer back up to the start of the buffer
	MoveMemory(
		m_pBuffer,           // Destination is the start of the buffer
		m_pBuffer + nLength, // Source is nLength into the buffer
		m_nLength );         // Length to copy is the new adjusted length
}

// Clears the memory from the buffer
void CBuffer::Clear()
{
	// Record that there are no bytes stored in the buffer
	m_nLength = 0; // Note that the buffer still has the same allocated size of m_nLength
}

///////////////////////////////////////////////////////////////////////////////
// CBuffer add utilities

// Takes ASCII text
// Prints it into the buffer, does not write a null terminator
void CBuffer::Print(LPCSTR pszText)
{
	// If the text is blank, don't do anything
	if ( pszText == NULL ) return;

	// Add the characters of the text to the buffer, each ASCII character takes up 1 byte
	Add( (void*)pszText, strlen( pszText ) ); // Length is 5 for "hello", this adds the characters without the null terminator
}

// Takes Unicode text, along with the code page it uses
// Converts it to ASCII and prints each ASCII character into the buffer, not printing a null terminator
void CBuffer::Print(LPCWSTR pszText, UINT nCodePage)
{
	// If the text is blank or no memory, don't do anything
	if ( pszText == NULL ) return;

	// Find the number of wide characters in the Unicode text
	size_t nLength = wcslen(pszText); // Length of "hello" is 5, does not include null terminator

	// Find out the required buffer size, in bytes, for the translated string
	int nBytes = WideCharToMultiByte( // Bytes required for "hello" is 5, does not include null terminator
		nCodePage, // Specify the code page used to perform the conversion
		0,         // No special flags to handle unmapped characters
		pszText,   // Wide character string to convert
		static_cast< int >( nLength ),   // The number of wide characters in that string
		NULL,      // No output buffer given, we just want to know how long it needs to be
		0,
		NULL,      // No replacement character given
		NULL );    // We don't want to know if a character didn't make it through the translation

	// Make sure the buffer is big enough for this, making it larger if necessary
	EnsureBuffer( (DWORD)nBytes );
	if ( m_nBuffer < (DWORD)nBytes ) return;

	// Convert the Unicode string into ASCII characters in the buffer
	WideCharToMultiByte( // Writes 5 bytes "hello", does not write a null terminator after that
		nCodePage, // Specify the code page used to perform the conversion
		0,         // No special flags to handle unmapped characters
		pszText,   // Wide character string to convert
		static_cast< int >( nLength ),   // The number of wide characters in that string
		(LPSTR)( m_pBuffer + m_nLength ), // Put the output ASCII characters at the end of the buffer
		nBytes,                           // There is at least this much space there
		NULL,      // No replacement character given
		NULL );    // We don't want to know if a character didn't make it through the translation

	// Add the newly written bytes to the buffer's record of how many bytes it is holding
	m_nLength += nBytes;
}

// Takes another CBuffer object, and a number of bytes there to copy, or the default -1 to copy the whole thing
// Moves the memory from pBuffer into this one
// Returns the number of bytes moved
DWORD CBuffer::AddBuffer(CBuffer* pBuffer, size_t nLength_)
{
	// primitive overflow protection (relevant for 64bit)
	if ( nLength_ > std::numeric_limits< int >::max() - m_nBuffer ) return 0;
	DWORD nLength = static_cast< DWORD >( nLength_ );
	// If the call specified a length, use it, otherwise use the length of pBuffer
	nLength = min( pBuffer->m_nLength, nLength );

	// Move nLength bytes from the start of pBuffer into this one
	Add( pBuffer->m_pBuffer, nLength ); // Copy the memory across
	pBuffer->Remove( nLength );         // Remove the memory from the source buffer

	// Report how many bytes we moved
	return nLength;
}

// Takes a pointer to some memory, and the number of bytes we can read there
// Adds them to this buffer, except in reverse order
void CBuffer::AddReversed(const void *pData, size_t nLength_)
{
	// primitive overflow protection (relevant for 64bit)
	if ( nLength_ > std::numeric_limits< int >::max() - m_nBuffer ) return;
	DWORD nLength = static_cast< DWORD >( nLength_ );
	// Make sure this buffer has enough memory allocated to hold another nLength bytes
	EnsureBuffer( nLength );

	// Copy nLength bytes from pData to the end of the buffer, except in reverse order
	ReverseBuffer( pData, m_pBuffer + m_nLength, nLength );

	// Record the new length
	m_nLength += nLength;
}

// Takes ASCII text
// Inserts it at the start of this buffer, shifting what is already here forward, does not write a null terminator
void CBuffer::Prefix(LPCSTR pszText)
{
	// If the text is blank, do nothing
	if ( NULL == pszText ) return;

	// Insert the bytes of the text at
	Insert(                  // Insert memory in the middle of the filled block of a buffer, splitting the block to the right
		0,                   // Insert the bytes at position 0, the start
		(void*)pszText,      // Insert the bytes of the ASCII text
		strlen( pszText ) ); // Insert each character byte, like 5 for "hello", does not insert a null terminator
}

// Takes a number of new bytes we're about to add to this buffer
// Makes sure the buffer will be big enough to hold them, allocating more memory if necessary
void CBuffer::EnsureBuffer(size_t nLength)
{
	// If the size of the buffer minus the size filled is bigger than or big enough for the given length, do nothing
	if ( m_nBuffer - m_nLength >= nLength ) return; // There is enough room to write nLength bytes without allocating anything

	if ( ULONG_MAX - m_nLength < nLength ) return;

	// Make m_nBuffer the size of what's written plus what's requested
	m_nBuffer = m_nLength + static_cast< DWORD >( nLength );

	// Round that up to the nearest multiple of 1024, or 1 KB
	m_nBuffer = ( m_nBuffer + BLOCK_SIZE - 1 ) & BLOCK_MASK;

	// Reallocate the memory block to this size
	m_pBuffer = (BYTE*)realloc( m_pBuffer, m_nBuffer ); // May return a different pointer
	
	if ( !m_pBuffer )
	{
		m_nLength = 0;
		m_nBuffer = 0;
		theApp.Message( MSG_ERROR, _T("Memory allocation error in CBuffer::EnsureBuffer()") );
	}
}

///////////////////////////////////////////////////////////////////////////////
// CBuffer read string helper

// Takes a maximum number of bytes to examine at the start of the buffer, and a code page which is ASCII by default
// Reads the given number of bytes as ASCII characters, copying them into a string
// Returns the text in a string, which will contain Unicode or ASCII characters depending on the compile
CString CBuffer::ReadString(size_t nBytes, UINT nCodePage)
{
	// Make a new blank string to hold the text we find
	CString str;

	// Set nSource to whichever is smaller, the number of bytes in the buffer, or the number we can look at there
	int nSource = (int)( nBytes < m_nLength ? nBytes : m_nLength );

	// Find out how many wide characters a buffer must be able to hold to convert this text to Unicode, null terminator not included
	int nLength = MultiByteToWideChar( // If the bytes "hello" are in the buffer, and nSource is 5, nLength will be 5 also
		nCodePage,                     // Code page to use, CP_ACP ANSI code page for ASCII text, the default
		0,                             // No special options about difficult to translate characters
		(LPCSTR)m_pBuffer,             // Use the start of this buffer as the source, where the ASCII text is
		nSource,                       // Convert this number of bytes there
		NULL,                          // No output buffer, we want to find out how long one must be
		0 );

	// Convert the ASCII characters at the start of this buffer to Unicode
	MultiByteToWideChar(          // Convert ASCII text to Unicode
		nCodePage,                // Code page to use, CP_ACP ANSI code page for ASCII text, the default
		0,                        // No special options about difficult to translate characters
		(LPCSTR)m_pBuffer,        // Use the start of this buffer as the source, where the ASCII text is
		nSource,                  // Convert this number of bytes there
		str.GetBuffer( nLength ), // Get direct access to the memory buffer for the CString object, telling it to be able to hold nLength characters
		nLength );                // Size of the buffer in wide characters

	// Release our direct manipulation of the CString's buffer
	str.ReleaseBuffer( nLength ); // Tell it how many wide characters we wrote there, null terminator not included

	// Return the string
	return str;
}

///////////////////////////////////////////////////////////////////////////////
// CBuffer read line helper

// Takes access to a string, default peek false to move a line from the buffer to the string, and default CP_ACP to read ASCII text
// Looks for bytes like "line\r\n" in the buffer, and moves them from the buffer to the string, throwing away the "\r\n" part
// Returns true if a line was found and moved from the buffer to the string, false if there isn't a '\n' in the buffer right now
BOOL CBuffer::ReadLine(CString& strLine, BOOL bPeek, UINT nCodePage)
{
	// Empty the string, making it blank
	strLine.Empty();

	// If this buffer is empty, tell the caller we didn't find a complete line
	if ( ! m_nLength ) return FALSE;

	// Scan down each byte in the buffer
	DWORD nLength = 0;
	for ( ; nLength < m_nLength ; nLength++ )
	{
		// If the byte at this length is the newline character '\n', exit the loop
		if ( m_pBuffer[ nLength ] == '\n' ) break;
	}

	// If the loop didn't find a '\n' and instead stopped because nLength grew to equal m_nLength
	if ( nLength >= m_nLength ) return FALSE; // There isn't an '\n' in the buffer, tell the caller we didn't find a complete line

	// Convert the nLength ASCII characters in the buffer into wide characters in strLine
	int nWide = MultiByteToWideChar( nCodePage, 0, (LPCSTR)m_pBuffer, nLength, NULL, 0 );
    MultiByteToWideChar( nCodePage, 0, (LPCSTR)m_pBuffer, nLength, strLine.GetBuffer( nWide ), nWide );
	strLine.ReleaseBuffer( nWide );

	// Find the last carriage return '\r' character in the string
	int nCR = strLine.ReverseFind( '\r' );   // Find the distance to the last \r, "hello\r" would be 5
	if ( nCR >= 0 ) strLine.Truncate( nCR ); // Cut the string to that length, like "hello"

	// Now that the line has been copied into the string, remove it and the '\n' from the buffer
	if ( ! bPeek )
	{
		Remove( 1 );
		Remove( nLength ); // Unless we're peeking, then leave it in the buffer
	}

	// Report that we found a line and moved it from the buffer to the string
	return TRUE;
}

///////////////////////////////////////////////////////////////////////////////
// CBuffer starts with helper

// Takes a pointer to ASCII text, and the option to remove these characters from the start of the buffer if they are found there
// Looks at the bytes at the start of the buffer, and determines if they are the same as the given ASCII text
// Returns true if the text matches, false if it doesn't
BOOL CBuffer::StartsWith(LPCSTR pszString, BOOL bRemove)
{
	// If the buffer isn't long enough to contain the given string, report the buffer doesn't start with it
	if ( m_nLength < (int)strlen( pszString ) ) return FALSE;

	// If the first characters in the buffer don't match those in the ASCII string, return false
	if ( strncmp(               // Returns 0 if all the characters are the same
		(LPCSTR)m_pBuffer,      // Look at the start of the buffer as ASCII text
		(LPCSTR)pszString,      // The given text
		strlen( pszString ) ) ) // Don't look too far into the buffer, we know it's long enough to hold the string
		return FALSE;           // If one string would sort above another, the result is positive or negative

	// If we got the option to remove the string if it matched, do it
	if ( bRemove ) Remove( strlen( pszString ) );

	// Report that the buffer does start with the given ASCII text
	return TRUE;
}

///////////////////////////////////////////////////////////////////////////////
// CBuffer socket receive

// Takes a handle to a socket
// Reads in data from the socket, moving it into the buffer
// Returns the number of bytes we got
DWORD CBuffer::Receive(SOCKET hSocket)
{
	// Make a local 4 KB buffer
	BYTE pData[TEMP_BUFFER];

	// Record how many bytes we get from the socket in this call to this method
	DWORD nTotal = 0;

	// Loop forever
	while ( TRUE )
	{
		// Move up to 4 KB of data from the socket to our pData buffer
		int nLength = recv( // Read data in from the socket, nLength is how many bytes we got
			hSocket,        // The socket that is connected to a remote computer
			(char *)pData,  // Put the data in our little local 4 KB buffer
			TEMP_BUFFER,    // Tell recv that it has 4 KB of space there
			0 );            // No advanced options

		// If we got 0 bytes, or SOCKET_ERROR -1, exit the loop
		if ( nLength <= 0 ) break;

		// Copy the data from the 4 KB buffer into this CBuffer object
		Add( pData, nLength );

		// Record this method has read nLength more bytes
		nTotal += nLength;
	}

	// Add the amount we read to the incoming bandwidth statistic, and return it
	Statistics.Current.Bandwidth.Incoming += nTotal;
	return nTotal;
}

///////////////////////////////////////////////////////////////////////////////
// CBuffer socket send

// Takes a handle to a socket
// Sends all the data in this buffer to the remote computer at the other end of it
// Returns how many bytes were sent
DWORD CBuffer::Send(SOCKET hSocket)
{
	// Record the total bytes we send in this call to this method
	DWORD nTotal = 0;

	// Loop until this buffer is empty
	while ( m_nLength )
	{
		// Copy the contents of this buffer into the socket
		int nLength = send(    // Send data out through the socket, nLength will be how much was sent
			hSocket,           // The socket that is connected to the remote computer
			(char *)m_pBuffer, // Send data from the start of this buffer
			static_cast< int >( m_nLength ),         // Try to send all the data in the buffer
			0 );               // No advanced options

		// If no data was sent, or send returned SOCKET_ERROR -1, exit the loop
		if ( nLength <= 0 ) break;

		// Remove the bytes that we copied into the socket from this buffer
		Remove( nLength );

		// Record that we sent these bytes
		nTotal += nLength;
	}

	// Add the amount we sent to the outgoing bandwidth statistic, and return it
	Statistics.Current.Bandwidth.Outgoing += nTotal;
	return nTotal;
}

//////////////////////////////////////////////////////////////////////
// CBuffer deflate and inflate compression

// Takes an option to avoid compressing a small buffer and to make sure compressing didn't actually make it bigger
// Compresses the data in this buffer in place
// Returns true if the data is compressed, false if there was an error
BOOL CBuffer::Deflate(BOOL bIfSmaller)
{
	// If the caller requested we check for small buffers, and this one contains less than 45 bytes, return false
	if ( bIfSmaller && m_nLength < 45 )
		return FALSE; // This buffer is too small for compression to work

	// Compress this buffer
	DWORD nCompress = 0; // Compress will write the size of the buffer it allocates and returns in this variable
	auto_array< BYTE > pCompress( CZLib::Compress( m_pBuffer, static_cast< DWORD >( m_nLength ), &nCompress ) );
			// Returns a buffer we must free
	if ( !pCompress.get() )
		return FALSE; // Compress had an error

	// If compressing the data actually made it bigger, and we were told to watch for this happening
	if ( bIfSmaller && nCompress >= m_nLength )
		return FALSE;

	// Move the compressed data from the buffer Compress returned to this one
	m_nLength = 0;                     // Record that there is no memory stored in this buffer
	Add( pCompress.get(), nCompress ); // Copy the compressed data into this buffer
	return TRUE;                       // Report success
}

// Takes the size we think the data will be when decompressed, or 0 if we don't know
// Decompresses the data in this buffer in place
// Returns true if the data is decompressed, false if there was an error
BOOL CBuffer::Inflate(DWORD nSuggest)
{
	// The bytes in this buffer are compressed, decompress them
	DWORD nCompress = 0; // Decompress will write the size of the buffer it allocates and returns in this variable
	auto_array< BYTE > pCompress( CZLib::Decompress( m_pBuffer, static_cast< DWORD >( m_nLength ), &nCompress, nSuggest ) );
	if ( !pCompress.get() )
		return FALSE; // Decompress had an error

	// Move the decompressed data from the buffer Decompress returned to this one
	m_nLength = 0;                     // Record that there is no memory stored in this buffer
	Add( pCompress.get(), nCompress ); // Copy the decompressed data into this buffer
	return TRUE;                       // Report success
}

// If the contents of this buffer are between headers and compressed with gzip, this method can remove all that
// Returns false on error
BOOL CBuffer::Ungzip()
{
	// Make sure there are at least 10 bytes in this buffer
	if ( m_nLength < 10 ) return FALSE;

	// Make sure the first 3 bytes are not 1f8b08
	if ( m_pBuffer[0] != 0x1F || m_pBuffer[1] != 0x8B || m_pBuffer[2] != 8 ) return FALSE;

	// At a distance of 3 bytes into the buffer, read the byte there and call it nFlags
	BYTE nFlags = m_pBuffer[3];

	// Remove the first 10 bytes of the buffer
	Remove( 10 );

	// If there is a 1 in position 0000 0100 in the flags byte
	if ( nFlags & 0x04 )
	{
		// Make sure the buffer has 2 or more bytes
		if ( m_nLength < 2 ) return FALSE;

		// Look at the first 2 bytes in the buffer as a word, this says how long the data it beyond it
		WORD nLen = *(WORD*)m_pBuffer;

		// If the buffer has less data than it should, return false
		if ( (int)m_nLength - 2 < (int)nLen ) return FALSE;

		// Remove the length word and the length it describes from the front of the buffer
		Remove( 2 );
		Remove( nLen );
	}

	// If there is a 1 in position 0000 1000 in the flags byte
	if ( nFlags & 0x08 )
	{
		// Loop until after we remove a 0 byte from the buffer
		for ( ;; )
		{
			// If the buffer is empty, return false
			if ( m_nLength == 0 ) return FALSE;

			// Move the first byte of the buffer into an int
			int nChar = m_pBuffer[0]; // Copy one byte from the start of the buffer into an int named nChar
			Remove( 1 );              // Remove that first byte from the buffer

			// If we just removed a 0 byte, exit the loop
			if ( nChar == 0 ) break;
		}
	}

	// If there is a 1 in position 0001 0000 in the flags byte
	if ( nFlags & 0x10 )
	{
		// Loop until after we remove a 0 byte from the buffer
		for ( ;; )
		{
			// If the buffer is empty, return false
			if ( m_nLength == 0 ) return FALSE;

			// Move the first byte of the buffer into an int
			int nChar = m_pBuffer[0]; // Copy one byte from the start of the buffer into an int named nChar
			Remove( 1 );              // Remove that first byte from the buffer

			// If we just removed a 0 byte, exit the loop
			if ( nChar == 0 ) break;
		}
	}

	// If there is a 1 in position 0000 0010 in the flags byte
	if ( nFlags & 0x02 )
	{
		// Make sure the buffer has at least 2 bytes, and then remove them
		if ( m_nLength < 2 ) return FALSE;
		Remove( 2 );
	}

	// After removing all that header information from the front, remove the last 8 bytes from the end
	if ( m_nLength <= 8 ) return FALSE; // Make sure the buffer has more than 8 bytes
	m_nLength -= 8;                     // Remove the last 8 bytes in the buffer

	// Setup a z_stream structure to perform a raw inflate
	z_stream pStream = {};
	if ( Z_OK != inflateInit2( // Initialize a stream inflation with more options than just inflateInit
		&pStream,              // Stream structure to initialize
		-MAX_WBITS ) ) {       // Window bits value of -15 to perform a raw inflate

		// The Zlib function inflateInit2 returned something other than Z_OK, report error
		return FALSE;
	}

	// Make a new buffer for the output.
	// Guess that inflating the data won't make it more than 6 times as big

	CBuffer pOutput;
	bool bValidSize = true;
	DWORD nLength = m_nLength;
	for ( short i = 0 ; i < 5 ; i++, nLength += m_nLength )
	{
		if ( UINT_MAX - nLength < m_nLength )
		{
			bValidSize = false;
			pOutput.EnsureBuffer( UINT_MAX );
			break;
		}
	}

	if ( bValidSize ) 
		pOutput.EnsureBuffer( m_nLength * 6 );

	// Tell the z_stream structure where to work
	pStream.next_in   = m_pBuffer;         // Decompress the memory here
	pStream.avail_in  = static_cast< uInt >( m_nLength );         // There is this much of it
	pStream.next_out  = pOutput.m_pBuffer; // Write decompressed data here
	pStream.avail_out = static_cast< uInt >( pOutput.m_nBuffer ); // Tell ZLib it has this much space, it make this smaller to show how much space is left

	// Call ZLib inflate to decompress all the data, and see if it returns Z_STREAM_END
	BOOL bSuccess = ( Z_STREAM_END == inflate( &pStream, Z_FINISH ) );

	// The inflate call returned Z_STREAM_END
	if ( bSuccess )
	{
		// Move the decompressed data from the output buffer into this one
		Clear();                   // Record there are no bytes stored here, doesn't change the allocated block size
		Add(pOutput.m_pBuffer,     // Add the memory at the start of the output buffer
			pOutput.m_nBuffer      // The amount of space the buffer had when we gave it to Zlib
			- pStream.avail_out ); // Minus the amount it said it left, this is the number of bytes it wrote

		// Close ZLib and report success
		inflateEnd( &pStream );
		return TRUE;

	} // The inflate call returned something else
	else
	{
		// Close ZLib and report error
		inflateEnd( &pStream );
		return FALSE;
	}
}

//////////////////////////////////////////////////////////////////////
// CBuffer reverse buffer

// This method is static, which means you can call it like CBuffer::ReverseBuffer() without having a CBuffer object at all
// Takes pointers to input memory and an output buffer, and a length, which is both the memory in input and the space in output
// Copies the bytes from input to output, but in reverse order
void CBuffer::ReverseBuffer(const void* pInput, void* pOutput, size_t nLength)
{
	// Point pInputWords at the end of the input memory block
	const DWORD* pInputWords = (const DWORD*)( (const BYTE*)pInput + nLength ); // This is a DWORD pointer, so it will move in steps of 4

	// Point pOutputWords at the start of the output buffer
	DWORD* pOutputWords      = (DWORD*)( pOutput );

	// Make a new local DWORD called nTemp, and request that Visual Studio place it in a machine register
	register DWORD nTemp; // The register keyword asks that nTemp be a machine register, making it really fast

	// Loop while nLength is bigger than 4, grabbing bytes 4 at a time and reversing them
	while ( nLength > 4 )
	{
		// Move pInputWords back 4 bytes, then copy the 4 bytes there into nTemp, the fast machine register DWORD
		nTemp = *--pInputWords;

		// Have SWAP_LONG reverse the order of the 4 bytes, copy them under pOutputWords, and then move that pointer 4 bytes forward
		*pOutputWords++ = SWAP_LONG( nTemp ); // If nTemp is "ABCD", SWAP_LONG( nTemp ) will be "DCBA", bit order is not changed

		// We've just reverse 4 bytes, subtract the length to reflect this
		nLength -= 4;
	}

	// If there are still some input bytes to add reversed
	if ( nLength )
	{
		// Point pInputBytes and pOutputBytes at the same places
		const BYTE* pInputBytes	= (const BYTE*)pInputWords; // This is a byte pointer, so it will move in steps of 1
		BYTE* pOutputBytes		= (BYTE*)pOutputWords;

		// Loop until there are no more bytes to copy over
		while ( nLength-- )
		{
			// Move pInputBytes back to grab a byte, copy it under pOutputBytes, then move pOutputBytes forward
			*pOutputBytes++ = *--pInputBytes;
		}
	}
}

//////////////////////////////////////////////////////////////////////
// CBuffer DIME handling

// DIME is a specification for sending and receiving SOAP messages along with additional attachments, like binary files or XML fragments
// Takes information to create a DIME message
// Composes the DIME message and writes it into this buffer
void CBuffer::WriteDIME(
	DWORD nFlags,   // 0, 1, or 2
	LPCSTR pszID,   // Blank, or a GUID in hexadecimal encoding
	LPCSTR pszType, // "text/xml" or a URI to an XML specification
	LPCVOID pBody,  // The XML fragment we're wrapping
	size_t nBody)    // How long it is
{
	// Format lengths into the bytes of the DIME header
	EnsureBuffer( 12 );                                               // Make sure this buffer has at least 12 bytes of space
	BYTE* pOut = m_pBuffer + m_nLength;                               // Point pOut at the end of the memory block in this buffer
	*pOut++ = 0x08 | ( nFlags & 1 ? 4 : 0 ) | ( nFlags & 2 ? 2 : 0 ); // *pOut++ = 0x08 sets the byte at pOut and then moves the pointer forward
	*pOut++ = strchr( pszType, ':' ) ? 0x20 : 0x10;
	*pOut++ = 0x00; *pOut++ = 0x00;
	*pOut++ = BYTE( ( strlen( pszID ) & 0xFF00 ) >> 8 );
	*pOut++ = BYTE( strlen( pszID ) & 0xFF );
	*pOut++ = BYTE( ( strlen( pszType ) & 0xFF00 ) >> 8 );
	*pOut++ = BYTE( strlen( pszType ) & 0xFF );
	*pOut++ = (BYTE)( ( nBody & 0xFF000000 ) >> 24 );
	*pOut++ = (BYTE)( ( nBody & 0x00FF0000 ) >> 16 );
	*pOut++ = (BYTE)( ( nBody & 0x0000FF00 ) >> 8 );
	*pOut++ = (BYTE)( nBody & 0x000000FF );
	m_nLength += 12;                                                  // Record that we wrote 12 bytes, but we really only wrote 11 (do)

	// Print pszID, which is blank or a GUID in hexadecimal encoding, and bytes of 0 until the total length we added is a multiple of 4
	Print( pszID );
	for ( size_t nPad = strlen( pszID ) ; nPad & 3 ; nPad++ ) Add( "", 1 ); // If we added "a", add "000" to get to the next group of 4

	// Print pszType, which is "text/xml" or a URI to an XML specification, and bytes of 0 until the total length we added is a multiple of 4
	Print( pszType );
	for ( size_t nPad = strlen( pszType ) ; nPad & 3 ; nPad++ ) Add( "", 1 ); // If we added "abcdef", add "00" to get to the next group of 4

	// If there is body text
	if ( pBody != NULL )
	{
		// Add it, followed by bytes of 0 until the total length we added is a multiple of 4
		Add( pBody, nBody );
		for ( size_t nPad = nBody ; nPad & 3 ; nPad++ ) Add( "", 1 );
	}
}

// DIME is a specification for sending and receiving SOAP messages along with additional attachments, like binary files or XML fragments
// If there is a DIME message sitting in this buffer, this method can read it
// Takes DWORD and CString pointers to fill with information from the DIME message
// Returns false if the DIME message wasn't formatted correctly
BOOL CBuffer::ReadDIME(
	DWORD* pnFlags,  // Writes the flags byte from the DIME message
	CString* psID,   // Writes a GUID in hexadecimal encoding from the DIME message
	CString* psType, // Writes "text/xml" or a URI to an XML specification
	DWORD* pnBody)   // Writes how long the body of the DIME message is
{
	// Make sure the buffer has at least 12 bytes
	if ( m_nLength < 12 ) return FALSE;

	// Point pIn at the start of this buffer
	BYTE* pIn = m_pBuffer;

	// The first 5 bits of the first byte, 00000---, must not be 00001---
	if ( ( *pIn & 0xF8 ) != 0x08 ) return FALSE;

	// If this method was passed a pnFlags DWORD
	if ( pnFlags != NULL )
	{
		// Write it for the caller
		*pnFlags = 0;                  // Start it out as 0
		if ( *pIn & 4 ) *pnFlags |= 1; // If the first byte in the buffer has a bit here -----1--, put one here -------1 in pnFlags
		if ( *pIn & 2 ) *pnFlags |= 2; // If the first byte in the buffer has a bit here ------1-, put one here ------1- in pnFlags
	}

	// Move the pIn pointer to the second byte in the buffer, and make sure it's not 00001010 or 00010100
	pIn++;
	if ( *pIn != 0x10 && *pIn != 0x20 ) return FALSE;

	// Make sure bytes 3 and 4 in the buffer aren't 0, and move pIn a distance of 4 bytes into the buffer, pointing at the 5th byte
	pIn++;
	if ( *pIn++ != 0x00 ) return FALSE;
	if ( *pIn++ != 0x00 ) return FALSE;

	// Read nID, nType, and pnBody from the buffer, and move the pointer forward 8 bytes
	ASSERT( pnBody != NULL ); // Make sure the caller gave us access to a DWORD to write the body length
	WORD nID   = ( pIn[0] << 8 ) + pIn[1]; pIn += 2;
	WORD nType = ( pIn[0] << 8 ) + pIn[1]; pIn += 2;
	*pnBody    = ( pIn[0] << 24 ) + ( pIn[1] << 16 ) + ( pIn[2] << 8 ) + pIn[3]; // Write the body length in the DWORD from the caller
	pIn += 4; // Move forward another 4 bytes to total 8 bytes for this section

	// Skip forward a distance determined by the lengths we just read
	DWORD nSkip = 12 + ( ( nID + 3 ) & ~3 ) + ( ( nType + 3 ) & ~3 );
	if ( m_nLength < nSkip + ( ( *pnBody + 3 ) & ~3 ) ) return FALSE; // Make sure the buffer is big enough to skip this far forward

	// Read psID, a GUID in hexadecimal encoding
	ASSERT( psID != NULL );            // Make sure the caller gave us access to a string to write the guid in hexadecimal encoding
	*psID = CString( reinterpret_cast< char* >( pIn ), nID );
	pIn += ( nID + 3 ) & ~3;           // Move pIn forward beyond the psID text and align at 4 bytes

	// Read psType, a GUID in hexadecimal encoding
	ASSERT( psType != NULL );			// Make sure the caller gave us access to a string to write the message body
	*psType = CString( reinterpret_cast< char* >( pIn ), nType );
	pIn += ( nType + 3 ) & ~3;           // Move pIn forward beyond the pszType text and align at 4 bytes

	// Remove the first part of the DIME message from the buffer, and report success
	Remove( nSkip );
	return TRUE;
}