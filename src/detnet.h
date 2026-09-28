/* SPDX-License-Identifier: GPL-2.0 */
/*
 * DetNet router: MPLS over UDP/IP data plane (RFC 9025 / RFC 8964) with the
 * service sub-layer functions PREOF (RFC 8655, RFC 9550):
 *
 *   encap    ingress PE: application IP traffic matched by a rule is given
 *            an S-label and a d-CW sequence number, and tunnelled in UDP/IP
 *   forward  relay: the outer Ethernet/IP/UDP header is rewritten, the
 *            S-label (optionally swapped) and the d-CW are kept
 *   decap    egress PE: the tunnel is removed, the inner IP packet leaves
 *            with a configured Ethernet header
 *
 *   replication (PRF)  several "output" lines on encap / forward
 *   elimination (PEF)  "eliminate = yes" on forward / decap
 *   ordering    (POF)  "order = yes" on forward / decap
 *
 * Wire format of a DetNet packet:
 *   Ethernet [802.1Q] | IPv4 | UDP | S-label (MPLS LSE, S=1) | d-CW | payload
 * with d-CW = 0000 + 28-bit sequence number.
 *
 * DetNet frames are handled before bridging; everything they emit goes
 * through the normal egress queues, so DetNet flows get TSN scheduling
 * (Qbv / ATS / strict priority) on the way out.
 */
#ifndef TSN_DETNET_H
#define TSN_DETNET_H

#include <pthread.h>
#include <stdint.h>
#include <stdatomic.h>
#include "classify.h"
#include "config.h"
#include "fdb.h"
#include "frame_pool.h"

#define DN_MAX_FLOWS   256
#define DN_MAX_OUT     8
#define DN_SEQ_MASK    0x0FFFFFFFu
#define DN_UDP_PORT    6635      /* MPLS-in-UDP, RFC 7510 */

enum dn_action { DN_ENCAP, DN_FORWARD, DN_DECAP };

struct dn_output {
	int port;                /* egress port, -1 = FDB lookup on dst_mac */
	int tc;                  /* resolved egress traffic class */
	int pcp;                 /* PCP of the outer tag, -1 = untagged */
	int swap_label;
	uint32_t label;          /* new S-label when swap_label */
	uint16_t l2_len;         /* 14 or 18 */
	uint16_t hdr_len;        /* template length: L2 (+ IPv4 + UDP unless decap) */
	uint8_t hdr[64];         /* header template */
	char text[200];
};

struct dn_held {                 /* frame waiting in the ordering buffer */
	uint64_t addr;
	uint32_t len;
	uint32_t seq;
	uint16_t keep_off;
	int16_t in_port;
	int64_t t;
};

struct dn_stats {
	_Atomic uint64_t rx, tx, dup, rogue, held, released_timeout, late, gaps, dropped;
};

struct dn_flow {
	char name[32];
	int action;
	uint32_t label;
	int udp_port;            /* forward/decap: -1 = any */
	int tc;                  /* -1 = from the output's PCP */
	int nout;
	struct dn_output out[DN_MAX_OUT];

	int eliminate;
	uint32_t hist_size;      /* power of two */
	int order;
	int64_t max_delay;
	uint32_t buf_size;
	int64_t reset_ns;
	int poll_port;           /* port thread that expires the ordering buffer */

	/* state, protected by lock (except seq_gen) */
	pthread_spinlock_t lock;
	_Atomic uint32_t seq_gen;
	int pef_synced;
	uint32_t pef_max;
	int64_t pef_last;
	uint64_t *hist;
	int pof_synced;
	uint32_t pof_last;
	int64_t pof_rx_last;
	uint32_t nheld;
	struct dn_held *held;

	struct dn_stats st;
};

/* Frames produced by the DetNet layer are handed to the switch through this. */
typedef void (*dn_emit_fn)(void *arg, int in_port, int out_port, int tc, uint64_t addr, uint32_t len);

struct dn_ctx {
	struct frame_pool *pool;
	struct frame_cache *cache;
	struct fdb *fdb;
	int64_t now;             /* switch clock, ns */
	uint32_t now_s;          /* FDB clock, s */
	dn_emit_fn emit;
	void *arg;
};

struct detnet {
	int n;
	struct dn_flow *flow;
	struct cls_table encap;      /* rule i -> flow encap_flow[i] */
	int encap_flow[DN_MAX_FLOWS];
	int nlabels;
	int label_tab[2048];         /* open addressing: flow index + 1 */
	int npof;
	int pof_flow[DN_MAX_FLOWS];
};

int  detnet_load(struct detnet *d, const char *path, const struct switch_cfg *c);
void detnet_free(struct detnet *d);
void detnet_dump(const struct detnet *d, const struct switch_cfg *c);
void detnet_print_stats(const struct detnet *d);

/*
 * Returns 0 if the frame is not DetNet (the caller keeps ownership and
 * bridges it) or 1 if the DetNet layer consumed it.
 */
int  detnet_rx(struct detnet *d, struct dn_ctx *x, int in_port, uint64_t addr, uint32_t len);

/* Releases frames that waited too long for reordering (port thread @port). */
void detnet_poll(struct detnet *d, struct dn_ctx *x, int port);

/* Returns every held frame to the pool (shutdown). */
void detnet_drain(struct detnet *d, struct frame_pool *pool, struct frame_cache *c);

#endif
