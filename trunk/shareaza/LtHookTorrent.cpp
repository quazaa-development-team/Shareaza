
//         Copyright E�in O'Callaghan 2006 - 2008.
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#include "stdAfx.hpp"

#include "global/wtl_app.hpp"
#include "global/string_conv.hpp"
#include "global/ini_adapter.hpp"

#include "LtHookTorrent.hpp"
#include "LtHookTypes.hpp"
#include "LtHookEvent.hpp"
#include "LtHookSignaler.hpp"

#include "LtHookTorrentInternal.hpp"
#include "LtHookSession.hpp"
//#include "LtHookSessionAlert.hpp"

namespace LtHook 
{
	libtorrent::session* torrent_internal::the_session_ = 0;
}

namespace LtHook 
{

bit& bittorrent()
{
	static bit t;
	return t;
}

const PeerDetails& torrent_details::peerDetails() const
{
	if (!peerDetailsFilled_)
	{
		bittorrent().get_all_peer_details(LtHook::to_utf8(name_), peerDetails_);
		peerDetailsFilled_ = true;
	}
	
	return peerDetails_;
}

const FileDetails& torrent_details::fileDetails() const
{
	if (!fileDetailsFilled_)
	{
		bittorrent().get_all_file_details(LtHook::to_utf8(name_), fileDetails_);
		fileDetailsFilled_ = true;
	}
	
	return fileDetails_;
}

bool nameLess(const torrent_details_ptr& left, const torrent_details_ptr& right)
{
	return left->state() < right->state();
}

void torrent_details_manager::sort(
	boost::function<bool (const torrent_details_ptr&, const torrent_details_ptr&)> fn) const
{
	std::stable_sort(torrents_.begin(), torrents_.end(), fn);
}

web_seed_or_dht_node_detail::web_seed_or_dht_node_detail() : 
	url(L""), 
	port(-1), 
	type(LtHook::app().res_wstr(LTHOOK_INT_NEWT_ADD_PEERS_WEB)) 
{}

web_seed_or_dht_node_detail::web_seed_or_dht_node_detail(std::wstring u) : 
	url(u), 
	port(-1), 
	type(LtHook::app().res_wstr(LTHOOK_INT_NEWT_ADD_PEERS_WEB)) 
{}

web_seed_or_dht_node_detail::web_seed_or_dht_node_detail(std::wstring u, int p) : 
	url(u), 
	port(p), 
	type(LtHook::app().res_wstr(LTHOOK_INT_NEWT_ADD_PEERS_DHT)) 
{}

bit::bit() :
	pimpl(new bit_impl())
{}

void bit::shutdown_session()
{
	LTHOOK_DEV_MSG(L"Commence shutdown_session()"); 

	pimpl.reset();

	LTHOOK_DEV_MSG(L"End shutdown_session()"); 
}

void bit::save_torrent_data()
{
	pimpl->save_torrent_data();
}

bool bit::create_torrent(const create_torrent_params& params, fs::wpath out_file, progress_callback fn)
{
	return pimpl->create_torrent(params, out_file, fn);
}

bit::torrent bit::get_wstr(const std::wstring& filename)
{
	return bit::torrent(pimpl->the_torrents_.get(filename));
}

bool bit::listen_on(std::pair<int, int> const& range)
{
	return pimpl->listen_on(range);
}

int bit::is_listening_on() 
{
	return pimpl->is_listening_on();
}

void bit::stop_listening()
{
	pimpl->stop_listening();
}

bool bit::ensure_dht_on(const LtHook::dht_settings& dht)
{
	return pimpl->ensure_dht_on(dht);
}

void bit::ensure_dht_off()
{
	pimpl->ensure_dht_off();
}

void bit::set_mapping(bool upnp, bool nat_pmp)
{
	pimpl->set_mapping(upnp, nat_pmp);
}

std::wstring bit::upnp_router_model()
{
	return pimpl->upnp_router_model();
}

queue_settings bit::get_queue_settings()
{
	return pimpl->get_queue_settings();
}

void bit::set_queue_settings(const queue_settings& s)
{
	pimpl->set_queue_settings(s);
}

timeouts bit::get_timeouts()
{
	return pimpl->get_timeouts();
}

void bit::set_timeouts(const timeouts& t)
{
	pimpl->set_timeouts(t);
}

void bit::set_session_limits(int maxConn, int maxUpload)
{		
	pimpl->set_session_limits(maxConn, maxUpload);
}

void bit::set_session_speed(float download, float upload)
{
	pimpl->set_session_speed(download, upload);
}

bool bit::ensure_ip_filter_on(progress_callback fn)
{
	return pimpl->ensure_ip_filter_on(fn);
}

void bit::ensure_ip_filter_off()
{
	pimpl->ensure_ip_filter_off();
}

void bit::set_resolve_countries(bool b)
{
	pimpl->set_resolve_countries(b);
}

void bit::start_smart_ban_plugin()
{
	pimpl->start_smart_ban_plugin();
}

void bit::start_ut_pex_plugin()
{
	pimpl->start_ut_pex_plugin();
}

void bit::start_ut_metadata_plugin()
{
	pimpl->start_ut_metadata_plugin();
}

void bit::start_metadata_plugin()
{
	pimpl->start_metadata_plugin();
}

#ifndef TORRENT_DISABLE_ENCRYPTION	

void bit::ensure_pe_on(const pe_settings& pe)
{
	pimpl->ensure_pe_on(pe);
}

void bit::ensure_pe_off()
{
	pimpl->ensure_pe_off();
}
#endif

void bit::ip_v4_filter_block(boost::asio::ip::address_v4 first, boost::asio::ip::address_v4 last)
{
	pimpl->ip_filter_.add_rule(first, last, libt::ip_filter::blocked);
	pimpl->ip_filter_count();
	pimpl->ip_filter_changed_ = true;
}

void bit::ip_v6_filter_block(boost::asio::ip::address_v6 first, boost::asio::ip::address_v6 last)
{
	pimpl->ip_v6_filter_block(first, last);
}

size_t bit::ip_filter_size()
{
	return pimpl->ip_filter_size();
}

void bit::clear_ip_filter()
{
	pimpl->clear_ip_filter();
}

bool bit::ip_filter_import_dat(boost::filesystem::path file, progress_callback fn, bool octalFix)
{
	return pimpl->ip_filter_import_dat(file, fn, octalFix);
}

const SessionDetail bit::get_session_details()
{
	SessionDetail details;
	
	details.port = pimpl->session_.is_listening() ? pimpl->session_.listen_port() : -1;
	
	libt::session_status status = pimpl->session_.status();
	
	details.speed = std::pair<double, double>(status.download_rate, status.upload_rate);
	
	details.dht_on = pimpl->dht_on_;
	details.dht_nodes = status.dht_nodes;
	details.dht_torrents = status.dht_torrents;
	
	details.ip_filter_on = pimpl->ip_filter_on_;
	details.ip_ranges_filtered = pimpl->ip_filter_count_;
	
	return details;
}

void bit::set_session_half_open_limit(int halfConn)
{
	pimpl->session_.set_max_half_open_connections(halfConn);

	event_log.post(shared_ptr<EventDetail>(new EventMsg(
		LtHook::wform(L"Set half-open connections limit to %1%.") % pimpl->session_.max_half_open_connections())));
}

void bit::set_torrent_defaults(const connections& defaults)
{
	pimpl->default_torrent_max_connections_ = defaults.total;
	pimpl->default_torrent_max_uploads_ = defaults.uploads;

	event_log.post(shared_ptr<EventDetail>(new EventMsg(
		LtHook::wform(L"Set torrent connections total %1% and uploads %2%.") 
			% defaults.total % defaults.uploads)));

	pimpl->default_torrent_download_ = defaults.download_rate;
	pimpl->default_torrent_upload_ = defaults.upload_rate;

	event_log.post(shared_ptr<EventDetail>(new EventMsg(
		LtHook::wform(L"Set torrent default rates at %1$.2fkb/s down and %2$.2fkb/s upload.") 
			% defaults.download_rate % defaults.upload_rate)));
}

void bit::add_torrent(wpath file, wpath saveDirectory, bool startStopped, bool managed, allocations alloc, 
		boost::filesystem::wpath moveToDirectory, bool useMoveTo) 
{
	pimpl->add_torrent(file, saveDirectory, startStopped, managed, alloc, moveToDirectory, useMoveTo);
}

const torrent_details_manager& bit::torrentDetails()
{
	return torrentDetails_;
}

const torrent_details_manager& bit::updatetorrent_details_manager(const wstring& focused, const std::set<wstring>& selected)
{
	try {
	
	mutex_t::scoped_lock l(torrentDetails_.mutex_);	
	
	torrentDetails_.clearAll(l);	
	torrentDetails_.torrents_.reserve(pimpl->the_torrents_.size());
	
	for (TorrentManager::torrentByName::iterator i=pimpl->the_torrents_.begin(), e=pimpl->the_torrents_.end(); i != e; ++i)
	{
		wstring utf8Name = (*i).torrent->name();
		torrent_details_ptr pT = (*i).torrent->get_torrent_details_ptr();
		
		if (selected.find(utf8Name) != selected.end())
		{
			torrentDetails_.selectedTorrents_.push_back(pT);
		}
		
		if (focused == utf8Name)
			torrentDetails_.selectedTorrent_ = pT;
		
		torrentDetails_.torrentMap_[(*i).torrent->name()] = pT;
		torrentDetails_.torrents_.push_back(pT);
	}
	
	} LTHOOK_GENERIC_TORRENT_EXCEPTION_CATCH("Torrent Unknown!", "updatetorrent_details_manager")
	
	return torrentDetails_;
}

void bit::resume_all()
{
	pimpl->resume_all();
}

void bit::close_all(boost::optional<report_num_active> fn)
{
	pimpl->close_all(fn);
}

PeerDetail::PeerDetail(libt::peer_info& peerInfo) :
	ipAddress(LtHook::from_utf8_safe(peerInfo.ip.address().to_string())),
	country(L""),
	speed(std::make_pair(peerInfo.payload_down_speed, peerInfo.payload_up_speed)),
	client(LtHook::from_utf8_safe(peerInfo.client))
{
	std::vector<wstring> status_vec;
	
#ifndef TORRENT_DISABLE_RESOLVE_COUNTRIES
	if (peerInfo.country[0] != 0 && peerInfo.country[1] != 0)
		country = (LtHook::wform(L"(%1%)") % LtHook::from_utf8_safe(string(peerInfo.country, 2))).str().c_str();
#endif	

	if (peerInfo.flags & libt::peer_info::handshake)
	{
		status_vec.push_back(app().res_wstr(LTHOOK_PEER_HANDSHAKE));
	}		
	else if (peerInfo.flags & libt::peer_info::connecting)
	{
		status_vec.push_back(app().res_wstr(LTHOOK_PEER_CONNECTING));
	}
	else
	{
	#ifndef TORRENT_DISABLE_ENCRYPTION		
		if (peerInfo.flags & libt::peer_info::rc4_encrypted)
			status_vec.push_back(app().res_wstr(LTHOOK_PEER_RC4_ENCRYPTED));		
		if (peerInfo.flags & libt::peer_info::plaintext_encrypted)
			status_vec.push_back(app().res_wstr(LTHOOK_PEER_PLAINTEXT_ENCRYPTED));
	#endif
		
		if (peerInfo.flags & libt::peer_info::interesting)
			status_vec.push_back(app().res_wstr(LTHOOK_PEER_INTERESTING));	
		if (peerInfo.flags & libt::peer_info::choked)
			status_vec.push_back(app().res_wstr(LTHOOK_PEER_CHOKED));	
		if (peerInfo.flags & libt::peer_info::remote_interested)
			status_vec.push_back(app().res_wstr(LTHOOK_PEER_REMOTE_INTERESTING));	
		if (peerInfo.flags & libt::peer_info::remote_choked)
			status_vec.push_back(app().res_wstr(LTHOOK_PEER_REMOTE_CHOKED));	
		if (peerInfo.flags & libt::peer_info::supports_extensions)
			status_vec.push_back(app().res_wstr(LTHOOK_PEER_SUPPORT_EXTENSIONS));	
	//	if (peerInfo.flags & libt::peer_info::local_connection)						// Not sure whats up here?
	//		status_vec.push_back(app().res_wstr(LTHOOK_PEER_LOCAL_CONNECTION));			
		if (peerInfo.flags & libt::peer_info::queued)
			status_vec.push_back(app().res_wstr(LTHOOK_PEER_QUEUED));
	}
	
	seed = (peerInfo.flags & libt::peer_info::seed) ? true : false;
	
	if (!status_vec.empty()) status = status_vec[0];
	
	if (status_vec.size() > 1)
	{
		for (size_t i=1; i<status_vec.size(); ++i)
		{
			status += L"; ";
			status += status_vec[i];
		}
	}	
}

const cache_details bit::get_cache_details() const
{
	return pimpl->get_cache_details();
}

void bit::get_all_peer_details(const std::string& filename, PeerDetails& peerContainer)
{
	get_all_peer_details(from_utf8_safe(filename), peerContainer);
}

void bit::get_all_peer_details(const std::wstring& filename, PeerDetails& peerContainer)
{
	try {
	
	pimpl->the_torrents_.get(filename)->get_peer_details(peerContainer);
	
	} LTHOOK_GENERIC_TORRENT_EXCEPTION_CATCH(filename, "getAllPeerDetails")
}

void bit::get_all_file_details(const std::string& filename, FileDetails& fileDetails)
{
	get_all_file_details(from_utf8_safe(filename), fileDetails);
}

void bit::get_all_file_details(const std::wstring& filename, FileDetails& fileDetails)
{
	try {
	
	pimpl->the_torrents_.get(filename)->get_file_details(fileDetails);
	
	} LTHOOK_GENERIC_TORRENT_EXCEPTION_CATCH(filename, "getAllFileDetails")
}

bool bit::is_torrent(const std::string& filename)
{	
	return is_torrent(LtHook::to_wstr_shim(filename));
}

bool bit::is_torrent(const std::wstring& filename)
{	
	try {
	
	return pimpl->the_torrents_.exists(filename);
	
	} LTHOOK_GENERIC_TORRENT_EXCEPTION_CATCH(filename, "isTorrent")
	
	return false;
}

void bit::pause_torrent(const std::string& filename)
{
	pause_torrent(LtHook::to_wstr_shim(filename));
}

void bit::pause_torrent(const std::wstring& filename)
{
	try {
	
	pimpl->the_torrents_.get(filename)->pause();
	
	} LTHOOK_GENERIC_TORRENT_EXCEPTION_CATCH(filename, "pauseTorrent")
}

void bit::resume_torrent(const std::string& filename)
{
	resume_torrent(LtHook::to_wstr_shim(filename));
}

void bit::resume_torrent(const std::wstring& filename)
{
	try {
	
	pimpl->the_torrents_.get(filename)->resume();
	
	} LTHOOK_GENERIC_TORRENT_EXCEPTION_CATCH(filename, "resumeTorrent")
}

void bit::stop_torrent(const std::string& filename)
{
	stop_torrent(LtHook::to_wstr_shim(filename));
}

void bit::stop_torrent(const std::wstring& filename)
{
	try {
	
	pimpl->the_torrents_.get(filename)->stop();
	
	} LTHOOK_GENERIC_TORRENT_EXCEPTION_CATCH(filename, "stopTorrent")
}

bool bit::is_torrent_active(const std::string& filename)
{
	return is_torrent_active(LtHook::to_wstr_shim(filename));
}

bool bit::is_torrent_active(const std::wstring& filename)
{
	try {
	
	return pimpl->the_torrents_.get(filename)->is_active();
	
	} LTHOOK_GENERIC_TORRENT_EXCEPTION_CATCH(filename, "isTorrentActive")
	
	return false; // ??? is this correct
}

void bit::reannounce_torrent(const std::string& filename)
{
	reannounce_torrent(LtHook::to_wstr_shim(filename));
}

void bit::reannounce_torrent(const std::wstring& filename)
{
	try {
	
	pimpl->the_torrents_.get(filename)->handle().force_reannounce();
	
	} LTHOOK_GENERIC_TORRENT_EXCEPTION_CATCH(filename, "reannounceTorrent")
}


void bit::recheck_torrent(const std::string& filename)
{
	recheck_torrent(LtHook::to_wstr_shim(filename));
}

void bit::recheck_torrent(const std::wstring& filename)
{
	try {
	
	pimpl->the_torrents_.get(filename)->force_recheck();
	
	} LTHOOK_GENERIC_TORRENT_EXCEPTION_CATCH(filename, "recheckTorrent")
}

void bit::remove_torrent_wstr(const std::wstring& filename)
{
	pimpl->remove_torrent(filename);
}

void bit::remove_torrent_wipe_files_wstr(const std::wstring& filename)
{
	pimpl->remove_torrent_wipe_files(LtHook::to_wstr_shim(filename));
}

void bit::pause_all_torrents()
{	
	try {
	
	for (TorrentManager::torrentByName::iterator i=pimpl->the_torrents_.begin(), e=pimpl->the_torrents_.end();
		i != e; ++i)
	{		
		if ((*i).torrent->in_session())
			(*i).torrent->pause();
	}
	
	} LTHOOK_GENERIC_TORRENT_EXCEPTION_CATCH("Torrent Unknown!", "pauseAllTorrents")
}

void bit::unpause_all_torrents()
{	
	try {
	
	for (TorrentManager::torrentByName::iterator i=pimpl->the_torrents_.begin(), e=pimpl->the_torrents_.end();
		i != e; ++i)
	{
		if ((*i).torrent->in_session() && (*i).torrent->get_state() == torrent_details::torrent_paused)
			(*i).torrent->resume();
	}
	
	} LTHOOK_GENERIC_TORRENT_EXCEPTION_CATCH("Torrent Unknown!", "unpauseAllTorrents")
}

bit::torrent::torrent()
{}

bit::torrent::torrent(boost::shared_ptr<torrent_internal> p) :
	ptr(p)
{}

bool bit::torrent::is_open() const
{
	return ptr;
}

bit::torrent::exec_around_ptr::proxy::proxy(torrent_internal* t) : 
	t_(t),
	l_(t->mutex_)
{
//	LTHOOK_DEV_MSG(L"Ctor proxy");
}

bit::torrent::exec_around_ptr::proxy::~proxy() 
{
//	LTHOOK_DEV_MSG(L"Dtor proxy");
}

const std::wstring bit::torrent::get_name() const
{
	try {
	
	return ptr->name();
	
	} LTHOOK_GENERIC_TORRENT_EXCEPTION_CATCH(L"Torrent Unknown", "torrent::get_name()")
	
	return 0;
}

float bit::torrent::get_ratio() const
{
	try {
	
	return ptr->get_ratio();
	
	} LTHOOK_GENERIC_TORRENT_PROP_EXCEPTION_CATCH("torrent::get_ratio")
	
	return 0;
}

void bit::torrent::set_ratio(float r)
{
	try {

	ptr->set_ratio(r);
	
	} LTHOOK_GENERIC_TORRENT_PROP_EXCEPTION_CATCH("torrent::set_ratio")
}

std::pair<int, int> bit::torrent::get_connection_limits() const
{
	try {
	
	return ptr->get_connection_limit();
	
	} LTHOOK_GENERIC_TORRENT_PROP_EXCEPTION_CATCH("torrent::get_connection_limits")
	
	return std::make_pair(-1, -1);
}

void bit::torrent::set_connection_limits(const std::pair<int, int>& l)
{
	try {
	
	ptr->set_connection_limit(l.first, l.second);
	
	} LTHOOK_GENERIC_TORRENT_PROP_EXCEPTION_CATCH("torrent::set_connection_limits")
}

std::pair<float, float> bit::torrent::get_rate_limits() const
{
	try {
	
	return ptr->get_transfer_speed();
	
	} LTHOOK_GENERIC_TORRENT_PROP_EXCEPTION_CATCH("torrent::get_rate_limits")
	
	return std::pair<float, float>(-1.0, -1.0);
}

void bit::torrent::set_rate_limits(const std::pair<float, float>& l)
{
	try {
	
	ptr->set_transfer_speed(l.first, l.second);
	
	} LTHOOK_GENERIC_TORRENT_PROP_EXCEPTION_CATCH("torrent::set_rate_limits")
}

wpath bit::torrent::get_save_directory() const
{
	try {
	
	return ptr->get_save_directory();
	
	} LTHOOK_GENERIC_TORRENT_PROP_EXCEPTION_CATCH("torrent::get_save_directory")
	
	return L"";
}

void bit::torrent::set_save_directory(const wpath& s)
{
	try {
	
	ptr->set_save_directory(s);
	
	} LTHOOK_GENERIC_TORRENT_PROP_EXCEPTION_CATCH("torrent::set_save_directory")
}

wpath bit::torrent::get_move_to_directory() const
{
	try {
	
	return ptr->get_move_to_directory();
	
	} LTHOOK_GENERIC_TORRENT_PROP_EXCEPTION_CATCH("torrent::get_save_directory")
	
	return L"";
}

void bit::torrent::set_move_to_directory(const wpath& m)
{
	try {
	
	ptr->set_move_to_directory(m);
	
	} LTHOOK_GENERIC_TORRENT_PROP_EXCEPTION_CATCH("torrent::set_move_to_directory")
}

std::pair<wstring, wstring> bit::torrent::get_tracker_login() const
{
	try {
	
	return ptr->get_tracker_login();
	
	} LTHOOK_GENERIC_TORRENT_PROP_EXCEPTION_CATCH("get_tracker_login")
	
	return std::make_pair(L"!!! exception thrown !!!", L"!!! exception thrown !!!");
}

void bit::torrent::set_tracker_login(const std::pair<wstring, wstring>& p)
{
	try {
	
	ptr->set_tracker_login(p.first, p.second);
	
	} LTHOOK_GENERIC_TORRENT_PROP_EXCEPTION_CATCH("torrent::set_tracker_login")
}

bool bit::torrent::get_is_active() const
{
	try {
	
	return ptr->is_active();
	
	} LTHOOK_GENERIC_TORRENT_PROP_EXCEPTION_CATCH("torrent::get_is_active")
	
	return L"";
}

bool bit::torrent::get_in_session() const
{
	try {
	
	return ptr->in_session();
	
	} LTHOOK_GENERIC_TORRENT_PROP_EXCEPTION_CATCH("torrent::get_in_session")
	
	return L"";
}

std::vector<tracker_detail> bit::torrent::get_trackers() const
{
	try {
	
	return ptr->get_trackers();
	
	} LTHOOK_GENERIC_TORRENT_PROP_EXCEPTION_CATCH("torrent::get_trackers")
	
	return std::vector<tracker_detail>();
}

void bit::torrent::set_trackers(const std::vector<tracker_detail>& trackers)
{
	try {
	
	ptr->set_trackers(trackers);
	
	} LTHOOK_GENERIC_TORRENT_PROP_EXCEPTION_CATCH("torrent::set_trackers")
}

void bit::torrent::reset_trackers()
{
	try {
	
	ptr->reset_trackers();
	
	} LTHOOK_GENERIC_TORRENT_PROP_EXCEPTION_CATCH("torrent::set_trackers")
}

void bit::torrent::set_file_priorities(const std::pair<std::vector<int>, int>& p)
{
	try { 

	ptr->set_file_priorities(p.first, p.second);
	
	} LTHOOK_GENERIC_TORRENT_PROP_EXCEPTION_CATCH("torrent::set_trackers")
}

void bit::torrent::adjust_queue_position(bit::queue_adjustments adjust)
{
	try { 

	ptr->adjust_queue_position(adjust);
	
	} LTHOOK_GENERIC_TORRENT_PROP_EXCEPTION_CATCH("torrent::adjust_queue_position")
}

bool bit::torrent::get_managed() const
{
	try {
	
	return ptr->is_managed();
	
	} LTHOOK_GENERIC_TORRENT_PROP_EXCEPTION_CATCH("torrent::get_managed")
	
	return false;
}

void bit::torrent::set_managed(bool m)
{
	try {
	
	ptr->set_managed(m);
	
	} LTHOOK_GENERIC_TORRENT_PROP_EXCEPTION_CATCH("torrent::set_managed")
}

void bit::start_event_receiver()
{
	event_log.post(shared_ptr<EventDetail>(new EventMsg(L"Starting event handler.")));

	pimpl->start_alert_handler();
}

void bit::stop_event_receiver()
{
	event_log.post(shared_ptr<EventDetail>(new EventMsg(L"Stopping event handler.")));

	pimpl->stop_alert_handler();
}

int bit::default_torrent_max_connections() { return pimpl->default_torrent_max_connections_; }
int bit::default_torrent_max_uploads() { return pimpl->default_torrent_max_uploads_; }
float bit::default_torrent_download() { return pimpl->default_torrent_download_; }
float bit::default_torrent_upload() { return pimpl->default_torrent_upload_; }
	
};
