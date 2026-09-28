// SPDX-License-Identifier: GPL-2.0
/*
 * DetNet MPLS-over-UDP/IP router with PREOF. See detnet.h for the model and
 * config/detnet-example.conf for the configuration format.
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>
#include "detnet.h"

#define SEQ_HALF      (1u << 27)
#define NEW_FRAME_OFF 256            /* where copies start inside a fresh frame */
#define LSE_TTL       255

static inline uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }
static inline uint32_t rd32(const uint8_t *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static inline void wr16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v; }
static inline void wr32(uint8_t *p, uint32_t v)
{
	p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v;
}

static uint16_t ip_csum(const uint8_t *h)
{
	uint32_t sum = 0;
	for (int i = 0; i < 20; i += 2)
		sum += rd16(h + i);
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)~sum;
}

#define STAT(f, name) atomic_fetch_add_explicit(&(f)->st.name, 1, memory_order_relaxed)

/* ------------------------------------------------------------ output -- */

/*
 * Build the packet for every output of @f and hand it to the switch.
 * The retained part of the incoming frame is [keep_off, len):
 *   encap   the inner IP packet          -> push L2+IPv4+UDP+S-label+d-CW
 *   forward S-label, d-CW and payload    -> push L2+IPv4+UDP
 *   decap   the inner IP packet          -> push L2
 * The last output reuses the received frame (in place when there is room in
 * front of the data), the others get copies: this is the replication.
 */
static void emit_outputs(struct dn_flow *f, struct dn_ctx *x, int in_port,
			 uint64_t addr, uint32_t len, uint32_t keep_off, uint32_t seq)
{
	struct frame_pool *fp = x->pool;
	const uint32_t fsize = 1u << fp->frame_shift;
	const uint32_t keep_len = len - keep_off;
	const uint32_t push = f->action == DN_ENCAP ? 8 : 0;

	for (int k = 0; k < f->nout; k++) {
		const struct dn_output *o = &f->out[k];
		const int last = k == f->nout - 1;
		uint32_t hlen = o->hdr_len + push;
		uint64_t start;

		if (last && addr + keep_off >= frame_base(fp, addr) + hlen) {
			start = addr + keep_off - hlen;
		} else {
			uint64_t nf;
			if (hlen + keep_len > fsize - NEW_FRAME_OFF ||
			    (nf = frame_alloc(fp, x->cache)) == FRAME_INVALID) {
				STAT(f, dropped);
				continue;
			}
			start = nf + NEW_FRAME_OFF;
			memcpy(frame_data(fp, start + hlen), frame_data(fp, addr + keep_off), keep_len);
		}

		uint8_t *p = frame_data(fp, start);
		memcpy(p, o->hdr, o->hdr_len);
		if (f->action == DN_DECAP) {
			uint8_t ver = p[hlen] >> 4;
			wr16(p + o->l2_len - 2, ver == 6 ? 0x86DD : 0x0800);
		} else {
			uint8_t *ip = p + o->l2_len, *udp = ip + 20, *lse = udp + 8;
			uint32_t l4 = 8 + push + keep_len;
			wr16(ip + 2, (uint16_t)(20 + l4));
			wr16(ip + 10, 0);
			wr16(ip + 10, ip_csum(ip));
			wr16(udp + 4, (uint16_t)l4);
			if (f->action == DN_ENCAP) {
				uint32_t label = o->swap_label ? o->label : f->label;
				wr32(lse, label << 12 | 1u << 8 | LSE_TTL);   /* TC 0, S=1 */
				wr32(lse + 4, seq & DN_SEQ_MASK);            /* d-CW */
			} else if (o->swap_label) {
				uint32_t lse_v = rd32(lse);
				wr32(lse, (o->label << 12) | (lse_v & 0xfff));
			}
		}

		int out = o->port;
		if (out < 0)
			out = fdb_lookup(x->fdb, p, x->now_s);
		STAT(f, tx);
		x->emit(x->arg, in_port, out, o->tc, start, hlen + keep_len);
	}
	/* Every output was a copy (or dropped): the received frame is done. */
	if (f->nout == 0 || addr + keep_off < frame_base(fp, addr) + f->out[f->nout - 1].hdr_len + push)
		frame_put(fp, x->cache, addr);
}

/* ------------------------------------------------------------ PEF ------ */

static inline int hist_test(const struct dn_flow *f, uint32_t seq)
{
	uint32_t i = seq & (f->hist_size - 1);
	return f->hist[i >> 6] >> (i & 63) & 1;
}

static inline void hist_set(struct dn_flow *f, uint32_t seq, int v)
{
	uint32_t i = seq & (f->hist_size - 1);
	if (v)
		f->hist[i >> 6] |= 1ull << (i & 63);
	else
		f->hist[i >> 6] &= ~(1ull << (i & 63));
}

/* Clear @n history bits starting at @seq, a word at a time where possible. */
static void hist_clear_range(struct dn_flow *f, uint32_t seq, uint32_t n)
{
	while (n) {
		uint32_t i = seq & (f->hist_size - 1);
		if (!(i & 63) && n >= 64) {
			f->hist[i >> 6] = 0;
			seq += 64;
			n -= 64;
		} else {
			hist_set(f, seq, 0);
			seq++;
			n--;
		}
	}
}

/*
 * Vector recovery (as in IEEE 802.1CB / RFC 9550): remember which of the
 * last hist_size sequence numbers were seen. Returns 1 to accept the packet.
 */
static int pef_accept(struct dn_flow *f, uint32_t seq, int64_t now)
{
	if (!f->pef_synced || now - f->pef_last > f->reset_ns) {
		memset(f->hist, 0, f->hist_size / 8);
		f->pef_max = seq;
		f->pef_synced = 1;
		f->pef_last = now;
		hist_set(f, seq, 1);
		return 1;
	}

	/*
	 * Only accepted packets restart the reset timer (as in 802.1CB), so a
	 * sender that restarts its numbering is picked up after reset_timeout
	 * even while its packets keep being rejected.
	 */
	uint32_t ahead = (seq - f->pef_max) & DN_SEQ_MASK;
	if (ahead == 0) {
		STAT(f, dup);
		return 0;
	}
	if (ahead < SEQ_HALF) {
		if (ahead >= f->hist_size)
			memset(f->hist, 0, f->hist_size / 8);
		else
			hist_clear_range(f, f->pef_max + 1, ahead - 1);
		f->pef_max = seq;
		f->pef_last = now;
		hist_set(f, seq, 1);
		return 1;
	}
	uint32_t behind = (f->pef_max - seq) & DN_SEQ_MASK;
	if (behind >= f->hist_size) {
		STAT(f, rogue);   /* older than the history window */
		return 0;
	}
	if (hist_test(f, seq)) {
		STAT(f, dup);
		return 0;
	}
	hist_set(f, seq, 1);
	f->pef_last = now;
	return 1;
}

/* ------------------------------------------------------------ POF ------ */

static void pof_deliver_run(struct dn_flow *f, struct dn_ctx *x)
{
	/* Send buffered packets that are now in sequence. */
	while (f->nheld && f->held[0].seq == ((f->pof_last + 1) & DN_SEQ_MASK)) {
		struct dn_held h = f->held[0];
		memmove(&f->held[0], &f->held[1], (f->nheld - 1) * sizeof(f->held[0]));
		f->nheld--;
		f->pof_last = h.seq;
		emit_outputs(f, x, h.in_port, h.addr, h.len, h.keep_off, h.seq);
	}
}

/* Give up waiting for the gap in front of the oldest held packet. */
static void pof_release_head(struct dn_flow *f, struct dn_ctx *x)
{
	struct dn_held h = f->held[0];

	memmove(&f->held[0], &f->held[1], (f->nheld - 1) * sizeof(f->held[0]));
	f->nheld--;
	atomic_fetch_add_explicit(&f->st.gaps, ((h.seq - f->pof_last) & DN_SEQ_MASK) - 1,
				  memory_order_relaxed);
	f->pof_last = h.seq;
	emit_outputs(f, x, h.in_port, h.addr, h.len, h.keep_off, h.seq);
	pof_deliver_run(f, x);
}

/*
 * Basic POF (RFC 9550): deliver in sequence; a packet ahead of the next
 * expected number waits until the gap is filled, at most max_delay (or until
 * the buffer is full). Packets older than the last delivered are dropped.
 */
static void pof_input(struct dn_flow *f, struct dn_ctx *x, int in_port, uint64_t addr,
		      uint32_t len, uint32_t keep_off, uint32_t seq)
{
	if (!f->pof_synced || (f->nheld == 0 && x->now - f->pof_rx_last > f->reset_ns)) {
		f->pof_last = (seq - 1) & DN_SEQ_MASK;
		f->pof_synced = 1;
	}

	uint32_t d = (seq - f->pof_last) & DN_SEQ_MASK;
	if (d == 0 || d >= SEQ_HALF) {
		STAT(f, late);
		frame_put(x->pool, x->cache, addr);
		return;
	}
	f->pof_rx_last = x->now;   /* only packets that are delivered or held */
	if (d == 1) {
		f->pof_last = seq;
		emit_outputs(f, x, in_port, addr, len, keep_off, seq);
		pof_deliver_run(f, x);
		return;
	}

	uint32_t pos = 0;
	while (pos < f->nheld && ((f->held[pos].seq - f->pof_last) & DN_SEQ_MASK) < d)
		pos++;
	if (pos < f->nheld && f->held[pos].seq == seq) {
		STAT(f, dup);
		frame_put(x->pool, x->cache, addr);
		return;
	}
	if (f->nheld == f->buf_size) {
		if (pos == 0) {
			/* Buffer full and this is the next packet we have: send it now. */
			atomic_fetch_add_explicit(&f->st.gaps, d - 1, memory_order_relaxed);
			f->pof_last = seq;
			emit_outputs(f, x, in_port, addr, len, keep_off, seq);
			pof_deliver_run(f, x);
			return;
		}
		pof_release_head(f, x);
		/* The release may have caught up with this packet. */
		pof_input(f, x, in_port, addr, len, keep_off, seq);
		return;
	}
	memmove(&f->held[pos + 1], &f->held[pos], (f->nheld - pos) * sizeof(f->held[0]));
	f->held[pos] = (struct dn_held){ addr, len, seq, (uint16_t)keep_off, (int16_t)in_port, x->now };
	f->nheld++;
	STAT(f, held);
}

void detnet_poll(struct detnet *d, struct dn_ctx *x, int port)
{
	for (int i = 0; i < d->npof; i++) {
		struct dn_flow *f = &d->flow[d->pof_flow[i]];
		if (f->poll_port != port || !__atomic_load_n(&f->nheld, __ATOMIC_RELAXED))
			continue;
		pthread_spin_lock(&f->lock);
		/*
		 * Any held packet that has waited max_delay forces the release of
		 * everything in front of it (the held list is sorted by sequence).
		 */
		for (;;) {
			int64_t oldest = INT64_MAX;
			for (uint32_t k = 0; k < f->nheld; k++)
				if (f->held[k].t < oldest)
					oldest = f->held[k].t;
			if (!f->nheld || x->now - oldest < f->max_delay)
				break;
			STAT(f, released_timeout);
			pof_release_head(f, x);
		}
		pthread_spin_unlock(&f->lock);
	}
}

void detnet_drain(struct detnet *d, struct frame_pool *pool, struct frame_cache *c)
{
	for (int i = 0; i < d->n; i++) {
		struct dn_flow *f = &d->flow[i];
		for (uint32_t k = 0; k < f->nheld; k++)
			frame_put(pool, c, f->held[k].addr);
		f->nheld = 0;
	}
}

/* ------------------------------------------------------------ RX ------- */

/*
 * If an IPv4/IPv6 packet starts at @off, returns where it ends (trimming
 * Ethernet padding), otherwise 0.
 */
static uint32_t ip_extent(const uint8_t *pkt, uint32_t off, uint32_t len)
{
	if (len < off + 20)
		return 0;
	uint8_t ver = pkt[off] >> 4;
	uint32_t tot;
	if (ver == 4)
		tot = rd16(pkt + off + 2);
	else if (ver == 6 && len >= off + 40)
		tot = 40u + rd16(pkt + off + 4);
	else
		return 0;
	if (tot < 20 || off + tot > len)
		return 0;
	return off + tot;
}

static inline int label_slot(uint32_t label)
{
	return (int)((label * 2654435761u) >> 21) & 2047;
}

static struct dn_flow *label_lookup(struct detnet *d, uint32_t label)
{
	for (int i = label_slot(label), n = 0; n < 2048; i = (i + 1) & 2047, n++) {
		int v = d->label_tab[i];
		if (!v)
			return NULL;
		if (d->flow[v - 1].label == label)
			return &d->flow[v - 1];
	}
	return NULL;
}

int detnet_rx(struct detnet *d, struct dn_ctx *x, int in_port, uint64_t addr, uint32_t len)
{
	const uint8_t *pkt = frame_data(x->pool, addr);
	uint32_t off = 12;
	uint16_t et = rd16(pkt + off);

	for (int tags = 0; tags < 2 && (et == ETH_P_8021Q_ || et == ETH_P_8021AD_) && len >= off + 6; tags++) {
		off += 4;
		et = rd16(pkt + off);
	}
	off += 2;   /* start of L3 */

	/* Relay / egress: an S-label we serve inside UDP. */
	if (d->nlabels && et == 0x0800 && len >= off + 20 + 8 + 8) {
		const uint8_t *ip = pkt + off;
		uint32_t ihl = (ip[0] & 0x0f) * 4u;
		if ((ip[0] >> 4) == 4 && ip[9] == 17 && ihl >= 20 && !(rd16(ip + 6) & 0x3fff) &&
		    len >= off + ihl + 8 + 8) {
			const uint8_t *udp = ip + ihl, *lse = udp + 8;
			struct dn_flow *f = label_lookup(d, rd32(lse) >> 12);
			if (f && (f->udp_port < 0 || f->udp_port == rd16(udp + 2)) &&
			    (lse[2] & 1) && (lse[4] >> 4) == 0) {   /* S-label is bottom of stack, d-CW */
				uint32_t seq = rd32(lse + 4) & DN_SEQ_MASK;
				uint32_t keep = off + ihl + 8 + (f->action == DN_DECAP ? 8 : 0);
				uint32_t tot = rd16(ip + 2);

				STAT(f, rx);
				/* Drop Ethernet padding: the outer IP length is authoritative. */
				if (tot >= ihl + 16 && off + tot <= len)
					len = off + tot;
				if (f->action == DN_DECAP && !(len = ip_extent(pkt, keep, len))) {
					STAT(f, dropped);   /* the tunnel does not carry an IP packet */
					frame_put(x->pool, x->cache, addr);
					return 1;
				}
				if (!f->eliminate && !f->order) {
					emit_outputs(f, x, in_port, addr, len, keep, seq);
					return 1;
				}
				pthread_spin_lock(&f->lock);
				if (f->eliminate && !pef_accept(f, seq, x->now))
					frame_put(x->pool, x->cache, addr);
				else if (f->order)
					pof_input(f, x, in_port, addr, len, keep, seq);
				else
					emit_outputs(f, x, in_port, addr, len, keep, seq);
				pthread_spin_unlock(&f->lock);
				return 1;
			}
		}
	}

	/* Ingress: application traffic that starts a DetNet flow. */
	if (d->encap.n) {
		int r = classify(&d->encap, pkt, len, in_port);
		if (r >= 0) {
			struct dn_flow *f = &d->flow[d->encap_flow[r]];
			/*
			 * DetNet carries IP only. Anything else that matches the rule
			 * (ARP of the application host, for instance) is bridged as usual.
			 */
			uint32_t end = (et == 0x0800 || et == 0x86DD) ? ip_extent(pkt, off, len) : 0;
			if (!end)
				return 0;
			len = end;
			STAT(f, rx);
			uint32_t seq = (atomic_fetch_add_explicit(&f->seq_gen, 1, memory_order_relaxed) + 1)
				       & DN_SEQ_MASK;
			emit_outputs(f, x, in_port, addr, len, off, seq);
			return 1;
		}
	}
	return 0;
}

/* ------------------------------------------------------------ config --- */

#define ERR(...) do { if (lineno) fprintf(stderr, "%s:%d: ", path, lineno); \
		      else fprintf(stderr, "%s: ", path); \
		      fprintf(stderr, __VA_ARGS__); fputc('\n', stderr); goto fail; } while (0)

static int parse_output(const struct switch_cfg *c, struct dn_flow *f, const char *text,
			struct dn_output *o, char *err, size_t errlen)
{
	char buf[512], *save, *tok;
	uint8_t dmac[6], smac[6];
	uint32_t sip = 0, dip = 0, mask;
	uint64_t u;
	int have = 0, vid = -1, pcp = 0, pcp_set = 0, dscp = 0, ttl = 64, sport = 49152, dport = DN_UDP_PORT;
	enum { H_DMAC = 1, H_SMAC = 2, H_SIP = 4, H_DIP = 8, H_IP = 16 };

	memset(o, 0, sizeof(*o));
	if (strlen(text) >= sizeof(buf)) {
		snprintf(err, errlen, "output line too long");
		return -1;
	}
	o->port = -1;
	o->tc = -1;
	snprintf(o->text, sizeof(o->text), "%s", text);
	snprintf(buf, sizeof(buf), "%s", text);

	for (tok = strtok_r(buf, " \t", &save); tok; tok = strtok_r(NULL, " \t", &save)) {
		char *eq = strchr(tok, '=');
		if (!eq) {
			snprintf(err, errlen, "expected field=value, got '%s'", tok);
			return -1;
		}
		*eq = 0;
		const char *k = tok, *v = eq + 1;
		int bad = 0;

		if (!strcmp(k, "port")) {
			bad = (o->port = cfg_port_by_name(c, v)) < 0;
		} else if (!strcmp(k, "dst_mac")) {
			bad = cfg_parse_mac(v, dmac);
			have |= H_DMAC;
		} else if (!strcmp(k, "src_mac")) {
			bad = cfg_parse_mac(v, smac);
			have |= H_SMAC;
		} else if (!strcmp(k, "vid")) {
			bad = cfg_parse_u64(v, &u) || u > 4095;
			vid = u;
		} else if (!strcmp(k, "pcp")) {
			bad = cfg_parse_u64(v, &u) || u > 7;
			pcp = u;
			pcp_set = 1;
		} else if (!strcmp(k, "tc")) {
			bad = cfg_parse_u64(v, &u) || u >= TSN_NUM_TC;
			o->tc = u;
		} else if (!strcmp(k, "src_ip")) {
			bad = cfg_parse_prefix(v, &sip, &mask) || mask != ~0u;
			have |= H_SIP;
		} else if (!strcmp(k, "dst_ip")) {
			bad = cfg_parse_prefix(v, &dip, &mask) || mask != ~0u;
			have |= H_DIP;
		} else if (!strcmp(k, "src_port")) {
			bad = cfg_parse_u64(v, &u) || u > 65535;
			sport = u;
			have |= H_IP;
		} else if (!strcmp(k, "dst_port")) {
			bad = cfg_parse_u64(v, &u) || u > 65535;
			dport = u;
			have |= H_IP;
		} else if (!strcmp(k, "dscp")) {
			bad = cfg_parse_u64(v, &u) || u > 63;
			dscp = u;
			have |= H_IP;
		} else if (!strcmp(k, "ttl")) {
			bad = cfg_parse_u64(v, &u) || u < 1 || u > 255;
			ttl = u;
			have |= H_IP;
		} else if (!strcmp(k, "label")) {
			bad = cfg_parse_u64(v, &u) || u < 16 || u > 0xFFFFF;
			o->swap_label = 1;
			o->label = u;
		} else {
			snprintf(err, errlen, "unknown output field '%s'", k);
			return -1;
		}
		if (bad) {
			snprintf(err, errlen, "bad value for '%s': '%s'", k, v);
			return -1;
		}
	}

	if ((have & (H_DMAC | H_SMAC)) != (H_DMAC | H_SMAC)) {
		snprintf(err, errlen, "output needs dst_mac and src_mac");
		return -1;
	}
	if (f->action == DN_DECAP) {
		if (have & (H_SIP | H_DIP | H_IP) || o->swap_label) {
			snprintf(err, errlen, "a decap output only takes port, MACs, vid, pcp and tc");
			return -1;
		}
	} else if ((have & (H_SIP | H_DIP)) != (H_SIP | H_DIP)) {
		snprintf(err, errlen, "output needs src_ip and dst_ip");
		return -1;
	}

	uint8_t *h = o->hdr;
	memcpy(h, dmac, 6);
	memcpy(h + 6, smac, 6);
	o->l2_len = 14;
	if (vid >= 0) {
		wr16(h + 12, ETH_P_8021Q_);
		wr16(h + 14, (uint16_t)(pcp << 13 | vid));
		o->l2_len = 18;
	}
	wr16(h + o->l2_len - 2, 0x0800);
	o->hdr_len = o->l2_len;
	if (f->action != DN_DECAP) {
		uint8_t *ip = h + o->l2_len, *udp = ip + 20;
		ip[0] = 0x45;
		ip[1] = dscp << 2;
		wr16(ip + 6, 0x4000);   /* DF */
		ip[8] = ttl;
		ip[9] = 17;
		wr32(ip + 12, sip);
		wr32(ip + 16, dip);
		wr16(udp, sport);
		wr16(udp + 2, dport);   /* UDP checksum 0 is allowed over IPv4 (RFC 7510) */
		o->hdr_len += 28;
	}

	if (pcp_set && vid < 0) {
		snprintf(err, errlen, "pcp= needs vid= (an untagged frame has no PCP)");
		return -1;
	}
	o->pcp = vid >= 0 ? pcp : -1;
	return 0;
}

static int alloc_state(struct dn_flow *f)
{
	pthread_spin_init(&f->lock, PTHREAD_PROCESS_PRIVATE);
	if (f->eliminate && !(f->hist = calloc(f->hist_size / 64 + 1, sizeof(uint64_t))))
		return -1;
	if (f->order && !(f->held = calloc(f->buf_size, sizeof(*f->held))))
		return -1;
	return 0;
}

int detnet_load(struct detnet *d, const char *path, const struct switch_cfg *c)
{
	static char match_text[DN_MAX_FLOWS][256];
	struct dn_flow *f = NULL;
	char line[512];
	int lineno = 0;
	FILE *fh;

	memset(d, 0, sizeof(*d));
	d->flow = calloc(DN_MAX_FLOWS, sizeof(*d->flow));
	if (!d->flow)
		return -1;
	fh = fopen(path, "r");
	if (!fh) {
		fprintf(stderr, "cannot open DetNet config %s: %s\n", path, strerror(errno));
		detnet_free(d);
		return -1;
	}

	while (fgets(line, sizeof(line), fh)) {
		lineno++;
		if (!strchr(line, '\n') && !feof(fh))
			ERR("line too long (max %zu characters)", sizeof(line) - 2);
		char *hash = strchr(line, '#');
		if (hash)
			*hash = 0;
		char *s = cfg_trim(line);
		if (!*s)
			continue;

		if (*s == '[') {
			char *end = strchr(s, ']');
			if (!end)
				ERR("unterminated section header");
			*end = 0;
			char *name = cfg_trim(s + 1);
			if (strncasecmp(name, "flow", 4) || !name[4] || (name[4] != ' ' && name[4] != '\t'))
				ERR("only [flow <name>] sections are allowed");
			name = cfg_trim(name + 4);
			if (d->n == DN_MAX_FLOWS)
				ERR("too many flows (max %d)", DN_MAX_FLOWS);
			f = &d->flow[d->n];
			match_text[d->n][0] = 0;
			d->n++;
			snprintf(f->name, sizeof(f->name), "%s", name);
			f->action = -1;
			f->udp_port = DN_UDP_PORT;
			f->tc = -1;
			f->hist_size = 1024;
			f->max_delay = 5000000;
			f->buf_size = 256;
			f->reset_ns = 1000000000;
			for (int i = 0; i < d->n - 1; i++)
				if (!strcmp(d->flow[i].name, name))
					ERR("duplicate flow '%s'", name);
			continue;
		}
		if (!f)
			ERR("key outside of a [flow] section");

		char *eq = strchr(s, '=');
		if (!eq)
			ERR("expected key = value");
		*eq = 0;
		char *k = cfg_trim(s), *v = cfg_trim(eq + 1);
		uint64_t u;
		char err[160];

		if (!strcmp(k, "action")) {
			if (!strcasecmp(v, "encap")) f->action = DN_ENCAP;
			else if (!strcasecmp(v, "forward")) f->action = DN_FORWARD;
			else if (!strcasecmp(v, "decap")) f->action = DN_DECAP;
			else ERR("action must be encap, forward or decap");
		} else if (!strcmp(k, "label")) {
			if (cfg_parse_u64(v, &u) || u < 16 || u > 0xFFFFF)
				ERR("label must be 16..1048575 (0-15 are reserved MPLS labels)");
			f->label = u;
		} else if (!strcmp(k, "match")) {
			if (strlen(v) >= sizeof(match_text[0]))
				ERR("match too long");
			snprintf(match_text[d->n - 1], sizeof(match_text[0]), "%s", v);
		} else if (!strcmp(k, "udp_port")) {
			if (!strcasecmp(v, "any")) f->udp_port = -1;
			else if (cfg_parse_u64(v, &u) || u > 65535) ERR("udp_port must be a port or 'any'");
			else f->udp_port = u;
		} else if (!strcmp(k, "tc")) {
			if (cfg_parse_u64(v, &u) || u >= TSN_NUM_TC) ERR("tc must be 0..7");
			f->tc = u;
		} else if (!strcmp(k, "eliminate")) {
			if (cfg_parse_bool(v, &f->eliminate)) ERR("bad boolean");
		} else if (!strcmp(k, "history")) {
			if (cfg_parse_u64(v, &u) || u < 64 || u > 65536 || (u & (u - 1)))
				ERR("history must be a power of two in [64, 65536]");
			f->hist_size = u;
		} else if (!strcmp(k, "order")) {
			if (cfg_parse_bool(v, &f->order)) ERR("bad boolean");
		} else if (!strcmp(k, "order_max_delay")) {
			if (cfg_parse_duration(v, &u) || !u) ERR("bad duration");
			f->max_delay = u;
		} else if (!strcmp(k, "order_buffer")) {
			if (cfg_parse_u64(v, &u) || u < 1 || u > 4096) ERR("order_buffer must be 1..4096");
			f->buf_size = u;
		} else if (!strcmp(k, "reset_timeout")) {
			if (cfg_parse_duration(v, &u) || !u) ERR("bad duration");
			f->reset_ns = u;
		} else if (!strcmp(k, "output")) {
			if (f->action < 0)
				ERR("set 'action' before the outputs");
			if (f->nout == DN_MAX_OUT)
				ERR("too many outputs (max %d)", DN_MAX_OUT);
			if (parse_output(c, f, v, &f->out[f->nout], err, sizeof(err)))
				ERR("%s", err);
			f->nout++;
		} else {
			ERR("unknown flow key '%s'", k);
		}
	}
	fclose(fh);
	fh = NULL;

	for (int i = 0; i < d->n; i++) {
		f = &d->flow[i];
		char err[160];
		lineno = 0;
		if (f->action < 0)
			ERR("flow '%s' has no action", f->name);
		if (!f->label)
			ERR("flow '%s' has no label", f->name);
		if (!f->nout)
			ERR("flow '%s' has no output", f->name);
		if (f->action == DN_DECAP && f->nout > 1)
			ERR("flow '%s': a decap flow has exactly one output", f->name);
		if (f->action == DN_ENCAP) {
			if (!match_text[i][0])
				ERR("encap flow '%s' needs 'match = ...'", f->name);
			if (f->eliminate || f->order)
				ERR("flow '%s': elimination/ordering apply to forward and decap flows", f->name);
			struct cls_rule *r = &d->encap.rule[d->encap.n];
			if (cfg_parse_match(c, match_text[i], r, err, sizeof(err)))
				ERR("flow '%s' match: %s", f->name, err);
			d->encap.fields |= r->fields;
			d->encap_flow[d->encap.n++] = i;
		} else {
			if (match_text[i][0])
				ERR("flow '%s': 'match' is only for encap flows (others match the label)", f->name);
			if (label_lookup(d, f->label))
				ERR("label %u is used by two forward/decap flows", f->label);
			int slot = label_slot(f->label);
			while (d->label_tab[slot])
				slot = (slot + 1) & 2047;
			d->label_tab[slot] = i + 1;
			d->nlabels++;
		}
		for (int k = 0; k < f->nout; k++) {
			struct dn_output *o = &f->out[k];
			if (o->tc < 0)   /* output tc=, else flow tc, else the outer PCP */
				o->tc = f->tc >= 0 ? f->tc : o->pcp >= 0 ? c->pcp_to_tc[o->pcp] : 0;
		}
		if (f->order) {
			f->poll_port = f->out[0].port >= 0 ? f->out[0].port : 0;
			d->pof_flow[d->npof++] = i;
		}
		if (alloc_state(f))
			ERR("out of memory");
	}
	return 0;

fail:
	if (fh)
		fclose(fh);
	detnet_free(d);
	return -1;
}

void detnet_free(struct detnet *d)
{
	if (d->flow) {
		for (int i = 0; i < d->n; i++) {
			free(d->flow[i].hist);
			free(d->flow[i].held);
		}
		free(d->flow);
	}
	memset(d, 0, sizeof(*d));
}

static const char *action_name(int a)
{
	return a == DN_ENCAP ? "encap" : a == DN_FORWARD ? "forward" : "decap";
}

void detnet_dump(const struct detnet *d, const struct switch_cfg *c)
{
	for (int i = 0; i < d->n; i++) {
		const struct dn_flow *f = &d->flow[i];
		printf("detnet flow '%s': %s label %u", f->name, action_name(f->action), f->label);
		if (f->action != DN_ENCAP)
			f->udp_port < 0 ? printf(" udp any") : printf(" udp %d", f->udp_port);
		if (f->eliminate)
			printf(" | eliminate (history %u)", f->hist_size);
		if (f->order)
			printf(" | order (max delay %lld ns, buffer %u)", (long long)f->max_delay, f->buf_size);
		printf("\n");
		for (int r = 0; r < d->encap.n; r++)
			if (d->encap_flow[r] == i)
				printf("    match: %s\n", d->encap.rule[r].text);
		for (int k = 0; k < f->nout; k++)
			printf("    output%s -> %s tc%d: %s\n", f->nout > 1 ? " (replica)" : "",
			       f->out[k].port >= 0 ? c->port[f->out[k].port].name : "fdb",
			       f->out[k].tc, f->out[k].text);
	}
}

void detnet_print_stats(const struct detnet *d)
{
	for (int i = 0; i < d->n; i++) {
		const struct dn_flow *f = &d->flow[i];
#define G(x) (unsigned long long)atomic_load(&f->st.x)
		printf("detnet %-10s %-7s rx=%llu tx=%llu", f->name, action_name(f->action), G(rx), G(tx));
		if (f->eliminate)
			printf(" eliminated=%llu out_of_window=%llu", G(dup), G(rogue));
		if (f->order)
			printf(" reordered=%llu timeouts=%llu late=%llu lost=%llu", G(held),
			       G(released_timeout), G(late), G(gaps));
		if (G(dropped))
			printf(" dropped=%llu", G(dropped));
		printf("\n");
#undef G
	}
}
