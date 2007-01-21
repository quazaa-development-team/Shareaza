This branch is basically aimed to following:
1. Extend existing suppotred protocol on Shareaza
2. optimize network core

Currently Developping features.
- Better UDP firewall detection.
- Optimizations for a lot of parts.
- ASync Library/Download list lookup for search results (Using ITMQ)
- File Add/Delete message from Download/Library list to Search results (Using ITMQ)
- Optimized G2 LEAF/HUB node state switchig
- Implements some of GnucDNA only G2 packet (Need to contact GnucDNA developers to find meaning of their own packets)
- G2 Mode Change Notification packets (Need to contact GnucDNA developers to find meaning of their own packets for this)
- G1 PushProxy (TCP)
- Send out UHC/UKHL packets to the known node which are in HostCache
- Bi-directional Hit (maybe improper word)
- find and solve problem that search Gnutella2 protocol from Firewalled node is not working as good as what it should do.

Currently known Bugs/Problems
- Calculation for UDP firewall detection timeout is not good...
- ED2K Fast connect option is broken because of CNeighboursWithConnect optimization.
- AdvancedEdit implementation has to be fixed (Merge function and Hash change detection should be changed)
- Reading of G1 Metadata in QueryHit seems not reading in UTF8

Current Difference in between TRUNK and CB branch
- Added something similar to push-proxy for G2. (using X-G2NH tag on HTTP header)
- Search results checking all the known Hashes to look up Library/Download list.
- Upload checks all the known Hashes to lookup download/library list.
- Reading of ExtensionBlock/GGEP in QueryHitResultItem re-writen to make it work on all Localed OSes(previous implementation never worked at least on JAPANESE OS because of CP_ACP codepage problem)
- G1 UDP PushProxy support added.
- 64Bit offset support in ED2K FileTransfer(not tested at all)
- ASync impelmentation for certain process which requires to work on cross-thread (*1)
- lookup of QueryHashTable Bitmap for QueryRouting has been optimized(number of Hashing operations for strings has been reduced a lot)
- CNeighboursWithConnect has been optimized for counting neighbour connection. (reduced inclease/declease by make constructors of each network connections so no need to use LOOP operations a lot)(*2)
- HTTP transfer can use HEAD request and support ReconnectOnDrop for WebServers with "Connection: close"
- UHC/UKHL code has some security which basically accept only when request has been sent to the node.(accept all for non-blocked IP, some security Bypass has been added, because some UHC servers seems like "X-ray security"/"Shareaza Security" filter blocks some UHC server's IP range.) this added extra function which makes Failure detection such as Timeout on Service Query.


 
 (*1) list below has been re-implemented to use ITMQ in CB Branch to reduce Cross-Threading operation(reduce Locks) 
  - TRUNK version will make Transfer Thread Locking network thread to send PUSH packet.
  - TRUNK version's network thread locks Transfer thread to add sources from Hit packets.
  - TRUNK version's network thread locks GUI thread to put Hits to SearchResult/HitMonitor window.
  - TRUNK version's network thread locks GUI thread to print out QueryPackets to SearchMonitor window.
  - TRUNK version's network thread locks GUI thread to print out PacketDump window.

 (*2) little additional change.
  - Leaf mode change.
   * Max Hub connections has been changed to 2.
   * Max Ultrapeer connections has been changed to 5
  - Hub mode change
   * Current TRUNK code try to connect to 4Hubs if you have "Number of Peers" set ot 4. this has been changed.
     -  reuse "Max Hub connection" value as minimum peer connection.
     -  use Peer connection for Max Peer connection.
	 In this way, Hubs never try to fill all the slot, so if some one promoted to Hub, there should be some Hubs which can accept peer connections.

