
//         Copyright E�in O'Callaghan 2006 - 2008.
// Distributed under the Boost Software License, Version 1.0.
//    (See accompanying file LICENSE_1_0.txt or copy at
//          http://www.boost.org/LICENSE_1_0.txt)

#pragma once

//TODO: Convert to Shareaza identification and versioning or move all this to Shareaza defines.
#define LTHOOK_VERSION					0, 3, 1, 636
#define LTHOOK_VERSION_STRING			"v 0.3.1.6 dev 636"
#define	LTHOOK_FINGERPRINT				"HL", 0, 3, 1, 6

#ifndef LTHOOK_NA
#define LTHOOK_NA 40013
#endif

#define LTHOOK_TORRENT_EXT_BEGIN 				41000
#define LBT_EVENT_TORRENT_FINISHED			LTHOOK_TORRENT_EXT_BEGIN + 1
#define LTHOOK_PEER_BAN_ALERT					LTHOOK_TORRENT_EXT_BEGIN + 2
#define LTHOOK_HASH_FAIL_ALERT					LTHOOK_TORRENT_EXT_BEGIN + 3
#define LTHOOK_URL_SEED_ALERT					LTHOOK_TORRENT_EXT_BEGIN + 5
#define LTHOOK_TRACKER_WARNING_ALERT			LTHOOK_TORRENT_EXT_BEGIN + 4
#define LTHOOK_TRACKER_ANNOUNCE_ALERT			LTHOOK_TORRENT_EXT_BEGIN + 6
#define LTHOOK_TRACKER_ALERT					LTHOOK_TORRENT_EXT_BEGIN + 7
#define LTHOOK_TRACKER_REPLY_ALERT				LTHOOK_TORRENT_EXT_BEGIN + 8
#define LBT_EVENT_TORRENT_PAUSED			LTHOOK_TORRENT_EXT_BEGIN + 9
#define LTHOOK_FAST_RESUME_ALERT				LTHOOK_TORRENT_EXT_BEGIN + 10
#define LTHOOK_PIECE_FINISHED_ALERT			LTHOOK_TORRENT_EXT_BEGIN + 11
#define LTHOOK_BLOCK_FINISHED_ALERT			LTHOOK_TORRENT_EXT_BEGIN + 12
#define LTHOOK_BLOCK_DOWNLOADING_ALERT			LTHOOK_TORRENT_EXT_BEGIN + 13
#define LTHOOK_LISTEN_SUCCEEDED_ALERT			LTHOOK_TORRENT_EXT_BEGIN + 14
#define LTHOOK_LISTEN_FAILED_ALERT				LTHOOK_TORRENT_EXT_BEGIN + 15
#define LTHOOK_IPFILTER_ALERT					LTHOOK_TORRENT_EXT_BEGIN + 16
#define LTHOOK_INCORRECT_ENCODING_LEVEL		LTHOOK_TORRENT_EXT_BEGIN + 17
#define LTHOOK_INCORRECT_CONNECT_POLICY    	LTHOOK_TORRENT_EXT_BEGIN + 18
#define LTHOOK_PEER_ALERT						LTHOOK_TORRENT_EXT_BEGIN + 19
#define LTHOOK_LISTEN_V6_FAILED_ALERT			LTHOOK_TORRENT_EXT_BEGIN + 20
#define LTHOOK_TORRENT_LOAD_FILTERS			LTHOOK_TORRENT_EXT_BEGIN + 21
#define LTHOOK_EXTERNAL_IP_ALERT				LTHOOK_TORRENT_EXT_BEGIN + 22
#define LTHOOK_PORTMAP_ERROR_ALERT				LTHOOK_TORRENT_EXT_BEGIN + 23
#define LTHOOK_PORTMAP_ALERT					LTHOOK_TORRENT_EXT_BEGIN + 24
#define LTHOOK_PORTMAP_TYPE_PMP				LTHOOK_TORRENT_EXT_BEGIN + 25			
#define LTHOOK_PORTMAP_TYPE_UPNP				LTHOOK_TORRENT_EXT_BEGIN + 26
#define LTHOOK_FILE_ERROR_ALERT				LTHOOK_TORRENT_EXT_BEGIN + 27
#define LTHOOK_DHT_REPLY_ALERT					LTHOOK_TORRENT_EXT_BEGIN + 28
#define LTHOOK_WRITE_RESUME_ALERT				LTHOOK_TORRENT_EXT_BEGIN + 29

#define LTHOOK_TORRENT_INT_BEGIN 				42000
#define LTHOOK_PEER_INTERESTING            	LTHOOK_TORRENT_INT_BEGIN + 1
#define LTHOOK_PEER_CHOKED             		LTHOOK_TORRENT_INT_BEGIN + 2
#define LTHOOK_PEER_REMOTE_INTERESTING			LTHOOK_TORRENT_INT_BEGIN + 3
#define LTHOOK_PEER_REMOTE_CHOKED				LTHOOK_TORRENT_INT_BEGIN + 4
#define LTHOOK_PEER_SUPPORT_EXTENSIONS			LTHOOK_TORRENT_INT_BEGIN + 5
#define LTHOOK_PEER_LOCAL_CONNECTION			LTHOOK_TORRENT_INT_BEGIN + 6
#define LTHOOK_PEER_HANDSHAKE					LTHOOK_TORRENT_INT_BEGIN + 7
#define LTHOOK_PEER_CONNECTING					LTHOOK_TORRENT_INT_BEGIN + 8
#define LTHOOK_PEER_QUEUED						LTHOOK_TORRENT_INT_BEGIN + 9
#define LTHOOK_PEER_RC4_ENCRYPTED				LTHOOK_TORRENT_INT_BEGIN + 10
#define LTHOOK_PEER_PLAINTEXT_ENCRYPTED		LTHOOK_TORRENT_INT_BEGIN + 11
#define LTHOOK_TORRENT_QUEUED_CHECKING			LTHOOK_TORRENT_INT_BEGIN + 12
#define LTHOOK_TORRENT_CHECKING_FILES			LTHOOK_TORRENT_INT_BEGIN + 13
#define LTHOOK_TORRENT_CONNECTING				LTHOOK_TORRENT_INT_BEGIN + 14
#define LTHOOK_TORRENT_DOWNLOADING				LTHOOK_TORRENT_INT_BEGIN + 15
#define LTHOOK_TORRENT_FINISHED				LTHOOK_TORRENT_INT_BEGIN + 16
#define LTHOOK_TORRENT_SEEDING					LTHOOK_TORRENT_INT_BEGIN + 17
#define LTHOOK_TORRENT_ALLOCATING				LTHOOK_TORRENT_INT_BEGIN + 18
#define LTHOOK_TORRENT_QUEUED					LTHOOK_TORRENT_INT_BEGIN + 19
#define LTHOOK_TORRENT_STOPPED					LTHOOK_TORRENT_INT_BEGIN + 20
#define LTHOOK_TORRENT_PAUSED					LTHOOK_TORRENT_INT_BEGIN + 21
#define LTHOOK_TORRENT_STOPPING				LTHOOK_TORRENT_INT_BEGIN + 22
#define LTHOOK_TORRENT_PAUSING					LTHOOK_TORRENT_INT_BEGIN + 23
#define LTHOOK_TORRENT_METADATA            	LTHOOK_TORRENT_INT_BEGIN + 24
#define LTHOOK_NEWT_CREATING_TORRENT			LTHOOK_TORRENT_INT_BEGIN + 25
#define LTHOOK_NEWT_HASHING_PIECES            	LTHOOK_TORRENT_INT_BEGIN + 26
#define LTHOOK_TORRENT_IMPORT_FILTERS         	LTHOOK_TORRENT_INT_BEGIN + 27
#define LTHOOK_INT_NEWT_ADD_PEERS_WEB         	LTHOOK_TORRENT_INT_BEGIN + 28
#define LTHOOK_INT_NEWT_ADD_PEERS_DHT         	LTHOOK_TORRENT_INT_BEGIN + 29
#define LTHOOK_NEWT_CREATION_CANCELED         	LTHOOK_TORRENT_INT_BEGIN + 30
