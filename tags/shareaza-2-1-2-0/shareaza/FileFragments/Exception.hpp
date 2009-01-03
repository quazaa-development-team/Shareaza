//
// FileFragments/Exception.hpp
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

#ifndef FILEFRAGMENTS_EXCEPTION_HPP_INCLUDED
#define FILEFRAGMENTS_EXCEPTION_HPP_INCLUDED

namespace detail
{

// @class exception
//       This is the general exception class used in this subsystem.
//       All exceptions generated by any facility of this subsystem
//       are guarantied to be derived from it, except for ::std::bad_alloc.
//       This allows exception handling on per subsystem base if desired.
class Exception : public ::std::exception
{
public:
    Exception(const char* message) throw() : msg_( message ) { }
    char const* what() const throw() { return msg_; }
    ~Exception() throw() { }
private:
    const char* msg_;
};

template< class FragmentT > class BadFragment : public Exception
{
public:
    typedef FragmentT FragmentType;
    typedef typename FragmentType::SizeType SizeType;
    typedef typename FragmentType::PayloadType PayloadType;
    BadFragment(SizeType begin, SizeType end, const PayloadType& payload) throw()
    : Exception( "Invalid fragment" ), 
      begin_( begin ),
      end_( end ),
      payload_( payload )
    { }
    ~BadFragment() throw() { }
    SizeType begin() const { return begin_; }
    SizeType end() const { return end_; }
private:
    SizeType begin_;
    SizeType end_;
    PayloadType payload_;
};

template< class FragmentT > class BadRange : public Exception
{
public:
    typedef FragmentT FragmentType;
    typedef typename FragmentType::SizeType FSizeType;
    BadRange(const FragmentType& invalidFragment, FSizeType limit) throw()
    : Exception( "fragment exceeds filesize" ),
        invalidFragment_( invalidFragment ), limit_( limit )
    { }
    ~BadRange() throw() { }
    FSizeType begin() const { return invalidFragment_.begin(); }
    FSizeType end() const { return invalidFragment_.end(); }
    FSizeType length() const
    {
        return invalidFragment_.end() - invalidFragment_.begin();
    }
    FSizeType limit() const { return limit_; }
    FragmentType& value() { return invalidFragment_; }
    const FragmentType& value() const { return invalidFragment_; }
private:
    FragmentType invalidFragment_;
    FSizeType limit_;
};

} // namespace detail

#endif // #ifndef FILEFRAGMENTS_EXCEPTION_HPP_INCLUDED