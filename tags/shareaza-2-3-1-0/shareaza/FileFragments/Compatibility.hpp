//
// Fragments/Compatibility.hpp
//
// Copyright (c) Shareaza Development Team, 2002-2007.
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

#ifndef FRAGMENTS_COMPATIBILITY_HPP_INCLUDED
#define FRAGMENTS_COMPATIBILITY_HPP_INCLUDED

#pragma warning( push )
#pragma warning( disable : 4996 )

namespace Fragments
{

// move to a common (private) base/mixin for block transfer (BT/ED2K)
// selects an available block, either unaligned blocks or if none is available
// a random aligned block
template< class list_type, typename available_type >
typename list_type::range_type selectBlock(const list_type& src, 
	typename list_type::range_size_type block_size, const available_type* available)
{
	typedef typename list_type::range_type range_type;
	typedef typename list_type::range_size_type range_size_type;
	typedef typename list_type::const_iterator const_iterator;

	if ( src.empty() ) return range_type( 0, 0 );

	std::deque< range_size_type > blocks;

	for ( const_iterator select = src.begin(); select != src.end(); ++select )
	{
		range_size_type block_begin = select->begin() / block_size;
		if ( select->begin() % block_size )
		{
			// the start of a block is complete, but part is missing
			
			++block_begin;
			if ( !available || available[ block_begin ] )
			{
				return range_type( select->begin(),
					min( select->end(), block_size * block_begin ) );
			}
		}
		range_size_type block_end = ( select->end() - 1 ) / block_size + 1;
		if ( block_begin != block_end && select->end() % block_size )
		{
			// the end of a block is complete, but part is missing
			
			--block_end;
			if ( !available || available[ block_end ] )
			{
				return range_type( block_end * block_size, select->end() );
			}
		}
		// this fragment contains one or more aligned empty blocks
		for ( ; block_begin != block_end; ++block_begin )
		{
			if ( !available || available[ block_begin ] )
			{
				blocks.push_back( block_begin );
			}
		}
	}

	if ( blocks.empty() ) return range_type( 0, 0 );

	range_size_type block = blocks[ std::rand() % blocks.size() ] * block_size;

	return range_type( block, min( block + block_size, src.limit() ) );
}

inline void SerializeOut(CArchive& ar, const Ranges::Range< uint64 >& out)
{
	ar << out.begin() << out.size();
}

inline Ranges::Range< uint64 > SerializeIn(CArchive& ar, int version)
{
	try
	{
		if ( version >= 29 )
		{
			uint64 begin, length;
			ar >> begin >> length;
			if ( begin + length < begin ) AfxThrowArchiveException( CArchiveException::generic );
			return Ranges::Range< uint64 >( begin, begin + length );
		}
		else
		{
			uint32 begin, length;
			ar >> begin >> length;
			if ( begin + length < begin ) AfxThrowArchiveException( CArchiveException::generic );
			return Ranges::Range< uint64 >( begin, begin + length );
		}
	}
	catch ( Exception& )
	{
		AfxThrowArchiveException( CArchiveException::generic );
	}
}

// used in FragmentedFile.cpp
inline void SerializeOut1(CArchive& ar,
	const Ranges::List< Ranges::Range< uint64 >, ListTraits >& out)
{
	uint64 nTotal = out.limit();
	uint64 nRemaining = out.length_sum();
	uint32 nFragments = static_cast< uint32 >( out.size() );
	ar << nTotal << nRemaining << nFragments;

	for ( Ranges::List< Ranges::Range< uint64 >, ListTraits >::const_iterator i = out.begin();
		i != out.end(); ++i )
	{
		SerializeOut( ar, *i );
	}
}

inline void SerializeIn1(CArchive& ar,
	Ranges::List< Ranges::Range< uint64 >, ListTraits >& in, int version)
{
	if ( version >= 29 )
	{
		try
		{
			uint64 nTotal, nRemaining;
			uint32 nFragments;
			ar >> nTotal >> nRemaining >> nFragments;
			{
				Ranges::List< Ranges::Range< uint64 >, ListTraits > oNewRange( nTotal );
				in.swap( oNewRange );
			}
			for ( ; nFragments--; )
			{
				const Ranges::Range< uint64 >& fragment = SerializeIn( ar, version );
				if ( fragment.end() > nTotal ) AfxThrowArchiveException( CArchiveException::generic );
				in.insert( in.end(), fragment );
			}
			// Sanity check
			if ( in.length_sum() != nRemaining ) AfxThrowArchiveException( CArchiveException::generic );
		}
		catch ( Exception& )
		{
			AfxThrowArchiveException( CArchiveException::generic );
		}
	}
	else
	{
		try
		{
			uint32 nTotal, nRemaining;
			uint32 nFragments;
			ar >> nTotal >> nRemaining >> nFragments;
			{
				Ranges::List< Ranges::Range< uint64 >, ListTraits > oNewRange( nTotal );
				in.swap( oNewRange );
			}
			for ( ; nFragments--; )
			{
				const Ranges::Range< uint64 >& fragment = SerializeIn( ar, version );
				if ( fragment.end() > nTotal ) AfxThrowArchiveException( CArchiveException::generic );
				in.insert( in.end(), fragment );
			}
			// Sanity check
			if ( in.length_sum() != nRemaining ) AfxThrowArchiveException( CArchiveException::generic );
		}
		catch ( Exception& )
		{
			AfxThrowArchiveException( CArchiveException::generic );
		}
	}
}

// used in DownloadSource.cpp
inline void SerializeOut2(CArchive& ar,
	const Ranges::List< Ranges::Range< uint64 >, ListTraits >& out)
{
	ar.WriteCount( out.size() );

	for ( Ranges::List< Ranges::Range< uint64 >, ListTraits >::const_iterator i	= out.begin();
		i != out.end(); ++i )
	{
		SerializeOut( ar, *i );
	}
}

inline void SerializeIn2(CArchive& ar,
	Ranges::List< Ranges::Range< uint64 >, ListTraits >& in, int version)
{
	try
	{
		if ( version >= 20 )
		{
			for ( DWORD_PTR count = ar.ReadCount(); count--; )
			{
				const Ranges::Range< uint64 >& fragment = SerializeIn( ar, version );
				if ( fragment.end() > in.limit() ) AfxThrowArchiveException( CArchiveException::generic );
				in.insert( in.end(), fragment );
			}
		}
		else if ( version >= 5 )
		{
			while ( ar.ReadCount() )
			{
				const Ranges::Range< uint64 >& fragment = SerializeIn( ar, version );
				if ( fragment.end() > in.limit() ) AfxThrowArchiveException( CArchiveException::generic );
				in.insert( in.end(), fragment );
			}
		}
	}
	catch ( Exception& )
	{
		AfxThrowArchiveException( CArchiveException::generic );
	}
}

} // namespace Fragments

#pragma warning( pop )

#endif // #ifndef FRAGMENTS_COMPATIBILITY_HPP_INCLUDED