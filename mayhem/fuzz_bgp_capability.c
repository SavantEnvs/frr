// libFuzzer harness for bgpd's Dynamic Capability message (BGP CAPABILITY, RFC 4724-style dynamic
// capabilities): the input is the message body, i.e. a series of <action, code, length, data...>
// entries, handed to bgp_capability_receive() for an Established peer that negotiated dynamic
// capabilities, exactly as bgp_process_packet() does for a received BGP_MSG_CAPABILITY.
//
// The packet buffer (peer->curr) is allocated to exactly the packet size: a handler that reads past
// the end of its capability data then reads past the end of the heap block.
#include <zebra.h>

#include "qobj.h"
#include "vty.h"
#include "stream.h"
#include "privs.h"
#include "memory.h"
#include "queue.h"
#include "filter.h"
#include "frr_pthread.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_io.h"
#include "bgpd/bgp_keepalives.h"

/* the symbols libbgp expects from the daemon's main() */
struct zebra_privs_t bgpd_privs = {};
struct event_loop *master = NULL;

static struct bgp *bgp;
static struct peer *peer;
static as_t asn = 100;

/* The peer fields a capability handler writes, as set up by peer_new(): restored after every input
 * so each input's result depends on that input only. */
static struct {
	uint64_t cap;
	uint32_t af_cap[AFI_MAX][SAFI_MAX];
	uint8_t afc_recv[AFI_MAX][SAFI_MAX];
	uint8_t afc_nego[AFI_MAX][SAFI_MAX];
	struct addpath_paths_limit addpath_paths_limit[AFI_MAX][SAFI_MAX];
	struct llgr_info llgr[AFI_MAX][SAFI_MAX];
	uint32_t v_gr_restart;
	uint8_t remote_role;
} initial;

#define DYN_CAPS (PEER_CAP_DYNAMIC_ADV | PEER_CAP_DYNAMIC_RCV)

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	int i, j;

	qobj_init();
	master = event_master_create(NULL);
	bgp_master_init(master, BGP_SOCKET_SNDBUF_SIZE, list_new());
	vrf_init(NULL, NULL, NULL, NULL);
	bgp_option_set(BGP_OPT_NO_LISTEN);

	frr_pthread_init();
	/* bgp_pthreads_init() is static in bgpd.c: the same two (never started) pthread objects. */
	struct frr_pthread_attr io = {
		.start = frr_pthread_attr_default.start,
		.stop = frr_pthread_attr_default.stop,
	};
	struct frr_pthread_attr ka = {
		.start = bgp_keepalives_start,
		.stop = bgp_keepalives_stop,
	};
	bgp_pth_io = frr_pthread_new(&io, "BGP I/O thread", "bgpd_io");
	bgp_pth_ka = frr_pthread_new(&ka, "BGP Keepalives thread", "bgpd_ka");
	bgp_pth_ka->running = true;

	if (bgp_get(&bgp, &asn, NULL, BGP_INSTANCE_TYPE_DEFAULT, NULL,
		    ASNOTATION_PLAIN) < 0)
		abort();

	peer = peer_create_accept(bgp);
	peer->host = (char *)"foo";
	peer->connection->status = Established;

	for (i = AFI_IP; i < AFI_MAX; i++)
		for (j = SAFI_UNICAST; j < SAFI_MAX; j++) {
			peer->afc[i][j] = 1;
			peer->afc_adv[i][j] = 1;
		}
	peer->cap |= DYN_CAPS;

	initial.cap = peer->cap;
	memcpy(initial.af_cap, peer->af_cap, sizeof(initial.af_cap));
	memcpy(initial.afc_recv, peer->afc_recv, sizeof(initial.afc_recv));
	memcpy(initial.afc_nego, peer->afc_nego, sizeof(initial.afc_nego));
	memcpy(initial.addpath_paths_limit, peer->addpath_paths_limit,
	       sizeof(initial.addpath_paths_limit));
	memcpy(initial.llgr, peer->llgr, sizeof(initial.llgr));
	initial.v_gr_restart = peer->v_gr_restart;
	initial.remote_role = peer->remote_role;
	return 0;
}

static void restore_peer(void)
{
	peer->cap = initial.cap;
	memcpy(peer->af_cap, initial.af_cap, sizeof(initial.af_cap));
	memcpy(peer->afc_recv, initial.afc_recv, sizeof(initial.afc_recv));
	memcpy(peer->afc_nego, initial.afc_nego, sizeof(initial.afc_nego));
	memcpy(peer->addpath_paths_limit, initial.addpath_paths_limit,
	       sizeof(initial.addpath_paths_limit));
	memcpy(peer->llgr, initial.llgr, sizeof(initial.llgr));
	peer->v_gr_restart = initial.v_gr_restart;
	peer->remote_role = initial.remote_role;
	XFREE(MTYPE_BGP_SOFT_VERSION, peer->soft_version);
	XFREE(MTYPE_BGP_PEER_HOST, peer->hostname);
	XFREE(MTYPE_BGP_PEER_HOST, peer->domainname);

	/* What bgp_notify_send() leaves behind for a malformed message: the reset cause and the notify
	 * record (each replaced on the next notify, but reset here so no input sees another's). */
	stream_free(peer->last_reset_cause);
	peer->last_reset_cause = NULL;
	XFREE(MTYPE_BGP_NOTIFICATION, peer->notify.data);
	memset(&peer->notify, 0, sizeof(peer->notify));
	peer->last_reset = 0;

	/* The notify's write() fails (the accepted peer has no fd), which queues a TCP_fatal_error event
	 * that nothing here runs: drop it, so neither the queue grows nor a later input runs the FSM. */
	event_cancel_event_ready(master, peer->connection);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	/* stream_new() asserts size > 0; a BGP message is at most 4096 bytes unless extended messages are
	 * negotiated, which this peer has not. */
	if (size == 0 || size > BGP_STANDARD_MESSAGE_MAX_PACKET_SIZE)
		return -1;

	peer->curr = stream_new(size);
	stream_write(peer->curr, data, size);

	bgp_capability_receive(peer->connection, peer, size);

	stream_free(peer->curr);
	peer->curr = NULL;
	restore_peer();
	return 0;
}
