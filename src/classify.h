/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Programmable traffic classification.
 *
 * An ordered list of rules is matched against every received frame; the
 * first rule that matches decides the traffic class and/or forces the egress
 * port (e.g. VLAN-to-port mapping). Frames that match no rule fall back to
 * the PCP -> traffic class map and MAC learning.
 */
#ifndef TSN_CLASSIFY_H
#define TSN_CLASSIFY_H

#include <stdint.h>
#include <stdatomic.h>
#include "common.h"

#define CLS_MAX_RULES 256

enum {
	CLS_IN_PORT   = 1 << 0,
	CLS_VID       = 1 << 1,
	CLS_PCP       = 1 << 2,
	CLS_ETHERTYPE = 1 << 3,
	CLS_SMAC      = 1 << 4,
	CLS_DMAC      = 1 << 5,
	CLS_IP_PROTO  = 1 << 6,
	CLS_SIP       = 1 << 7,
	CLS_DIP       = 1 << 8,
	CLS_DSCP      = 1 << 9,
	CLS_SPORT     = 1 << 10,
	CLS_DPORT     = 1 << 11,
	CLS_UNTAGGED  = 1 << 12,
	CLS_L3        = CLS_IP_PROTO | CLS_SIP | CLS_DIP | CLS_DSCP | CLS_SPORT | CLS_DPORT,
};

struct cls_rule {
	uint32_t fields;           /* CLS_* bits that must match */
	int in_port;
	uint16_t vid;
	uint8_t pcp;
	uint16_t ethertype;        /* after the VLAN tag, if any */
	uint8_t smac[6], dmac[6];
	uint8_t ip_proto;
	uint32_t sip, sip_mask;    /* IPv4, host byte order */
	uint32_t dip, dip_mask;
	uint8_t dscp;
	uint16_t sport_lo, sport_hi;
	uint16_t dport_lo, dport_hi;

	int tc;                    /* action: traffic class, -1 = from PCP map */
	int out_port;              /* action: egress port, -1 = FDB lookup */
	char text[160];            /* original rule, for logs */
};

struct cls_table {
	int n;
	uint32_t fields;           /* union of all rules' fields */
	struct cls_rule rule[CLS_MAX_RULES];
	_Atomic uint64_t hits[CLS_MAX_RULES];
};

/* Returns the index of the first matching rule, or -1. */
int classify(struct cls_table *t, const uint8_t *pkt, uint32_t len, int in_port);

#endif
