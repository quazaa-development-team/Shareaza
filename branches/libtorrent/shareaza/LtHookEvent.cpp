
//         Copyright E�in O'Callaghan 2006 - 2008.
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#define LTHOOK_EVENT_IMPL_UNIT

#include "stdAfx.hpp"

#include "LtHookEvent.hpp"
//TODO: Find code this is needed for and replace it with Shareaza Code
//#include "Halite.hpp"

#include <iostream>
#include <fstream>
#include <iterator>
#include <iomanip>
#include <map>
#include <algorithm>
#include <string>
#include <vector>

#pragma warning (push, 1)
#	include <libtorrent/file.hpp>
#	include <libtorrent/hasher.hpp>
#	include <libtorrent/entry.hpp>
#	include <libtorrent/bencode.hpp>
#	include <libtorrent/session.hpp>
#	include <libtorrent/ip_filter.hpp>
#	include <libtorrent/torrent_handle.hpp>
#	include <libtorrent/peer_connection.hpp>
#pragma warning (pop) 

namespace LtHook
{

struct event_impl
{
	mutable mutex_t mutex_;
	boost::signal<void (boost::shared_ptr<EventDetail>)> event_signal_;
};

event_logger::event_logger()
{
	init();
}

void event_logger::init()
{
	static boost::shared_ptr<event_impl> s_event_impl;

	if (!s_event_impl)
		s_event_impl.reset(new event_impl());

	pimpl_ = s_event_impl;
}

event_logger::~event_logger()
{}

boost::signals::connection event_logger::attach(boost::function<void (boost::shared_ptr<EventDetail>)> fn)
{
	if (pimpl_)
	{
		mutex_t::scoped_lock l(pimpl_->mutex_);
		return pimpl_->event_signal_.connect(fn);
	}
	else
		return boost::signals::connection();
}

void event_logger::dettach(const boost::signals::connection& c)
{
	if (pimpl_)
	{
		mutex_t::scoped_lock l(pimpl_->mutex_);
		pimpl_->event_signal_.disconnect(c);
	}
}

void event_logger::post(boost::shared_ptr<EventDetail> e)
{
	if (pimpl_)
	{//TODO: Replace commented out code with Shareaza equivalent
	mutex_t::scoped_lock l(pimpl_->mutex_);
	if (e->level() != LtHook::event_logger::debug || /*halite().logDebug()*/)
		pimpl_->event_signal_(e);
	}
}
	
std::wstring event_logger::eventLevelToStr(eventLevel event)
{
	switch (event)
	{
	case debug:
		return LtHook::app().res_wstr(LTHOOK_EVENTDEBUG);
	case info:
		return LtHook::app().res_wstr(LTHOOK_EVENTINFO);
	case warning:
		return LtHook::app().res_wstr(LTHOOK_EVENTWARNING);
	case critical:
		return LtHook::app().res_wstr(LTHOOK_EVENTCRITICAL);
	case fatal:
		return LtHook::app().res_wstr(LTHOOK_EVENTCRITICAL);
	case xml_dev:
		return L"XML Log";
	case torrent_dev:
		return L"Torrent Log";
	default:
		return LtHook::app().res_wstr(LTHOOK_EVENTNONE);
	}
}

} // namespace LtHook
