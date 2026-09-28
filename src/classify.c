// SPDX-License-Identifier: GPL-2.0
#include <string.h>
#include "classify.h"

struct meta {
	int tagged;
	uint16_t vid;
	uint8_t pcp;
	uint16_t ethertype;
	int has_ip;
	uint8_t ip_proto;
	uint32_t sip, dip;
	uint8_t dscp;
	int has_ports;
	uint16_t sport, dport;
};

static inline uint16_t rd16(const uint8_t *p)
{
	return (uint16_t)(p[0] << 8 | p[1]);
}

static inline uint32_t rd32(const uint8_t *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static void parse(const uint8_t *pkt, uint32_t len, uint32_t need, struct meta *m)
{
	uint32_t off = 12;

	memset(m, 0, sizeof(*m));
	m->ethertype = rd16(pkt + off);
	off += 2;
	if ((m->ethertype == ETH_P_8021Q_ || m->ethertype == ETH_P_8021AD_) && len >= off + 4) {
		uint16_t tci = rd16(pkt + off);
		m->tagged = 1;
		m->pcp = tci >> 13;
		m->vid = tci & 0x0fff;
		m->ethertype = rd16(pkt + off + 2);
		off += 4;
		/* Q-in-Q: classify on the outer tag, skip the inner one. */
		if (m->ethertype == ETH_P_8021Q_ && len >= off + 4) {
			m->ethertype = rd16(pkt + off + 2);
			off += 4;
		}
	}
	if (!(need & CLS_L3))
		return;

	const uint8_t *l3 = pkt + off;
	uint32_t l4off;
	if (m->ethertype == 0x0800 && len >= off + 20 && (l3[0] >> 4) == 4) {
		uint32_t ihl = (l3[0] & 0x0f) * 4u;
		if (ihl < 20 || len < off + ihl)
			return;
		m->has_ip = 1;
		m->dscp = l3[1] >> 2;
		m->ip_proto = l3[9];
		m->sip = rd32(l3 + 12);
		m->dip = rd32(l3 + 16);
		/* Only the first fragment carries the L4 header. */
		if (rd16(l3 + 6) & 0x1fff)
			return;
		l4off = off + ihl;
	} else if (m->ethertype == 0x86DD && len >= off + 40 && (l3[0] >> 4) == 6) {
		m->has_ip = 1;
		m->dscp = (uint8_t)((rd16(l3) >> 6) & 0x3f);
		m->ip_proto = l3[6];   /* extension headers are not walked */
		l4off = off + 40;
	} else {
		return;
	}
	if ((m->ip_proto == 6 || m->ip_proto == 17 || m->ip_proto == 132) && len >= l4off + 4) {
		m->has_ports = 1;
		m->sport = rd16(pkt + l4off);
		m->dport = rd16(pkt + l4off + 2);
	}
}

static inline int match(const struct cls_rule *r, const struct meta *m,
			const uint8_t *pkt, int in_port)
{
	uint32_t f = r->fields;

	if ((f & CLS_IN_PORT) && r->in_port != in_port)
		return 0;
	if ((f & CLS_UNTAGGED) && m->tagged)
		return 0;
	if ((f & CLS_VID) && (!m->tagged || m->vid != r->vid))
		return 0;
	if ((f & CLS_PCP) && (!m->tagged || m->pcp != r->pcp))
		return 0;
	if ((f & CLS_ETHERTYPE) && m->ethertype != r->ethertype)
		return 0;
	if ((f & CLS_DMAC) && memcmp(pkt, r->dmac, 6))
		return 0;
	if ((f & CLS_SMAC) && memcmp(pkt + 6, r->smac, 6))
		return 0;
	if (!(f & CLS_L3))
		return 1;
	if (!m->has_ip)
		return 0;
	if ((f & CLS_IP_PROTO) && m->ip_proto != r->ip_proto)
		return 0;
	if ((f & CLS_DSCP) && m->dscp != r->dscp)
		return 0;
	/* Address rules are IPv4 only: an IPv6 frame never matches them. */
	if ((f & (CLS_SIP | CLS_DIP)) && m->ethertype != 0x0800)
		return 0;
	if ((f & CLS_SIP) && (m->sip & r->sip_mask) != r->sip)
		return 0;
	if ((f & CLS_DIP) && (m->dip & r->dip_mask) != r->dip)
		return 0;
	if (f & (CLS_SPORT | CLS_DPORT)) {
		if (!m->has_ports)
			return 0;
		if ((f & CLS_SPORT) && (m->sport < r->sport_lo || m->sport > r->sport_hi))
			return 0;
		if ((f & CLS_DPORT) && (m->dport < r->dport_lo || m->dport > r->dport_hi))
			return 0;
	}
	return 1;
}

int classify(struct cls_table *t, const uint8_t *pkt, uint32_t len, int in_port)
{
	struct meta m;

	parse(pkt, len, t->fields, &m);
	for (int i = 0; i < t->n; i++) {
		if (match(&t->rule[i], &m, pkt, in_port)) {
			atomic_fetch_add_explicit(&t->hits[i], 1, memory_order_relaxed);
			return i;
		}
	}
	return -1;
}
