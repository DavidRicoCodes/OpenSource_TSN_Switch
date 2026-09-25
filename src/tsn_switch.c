// SPDX-License-Identifier: GPL-2.0
/*
 * tsn-switch: an IEEE 802.1Q bridge with an 802.1Qbv time-aware shaper,
 * built on AF_XDP.
 *
 * Data path (one busy-polling thread per port):
 *
 *   NIC -> XDP (redirect) -> AF_XDP RX ring
 *       -> classify (PCP -> traffic class) -> learn / look up MAC
 *       -> enqueue descriptor on the egress port's per-class queue
 *   egress thread:
 *       gate control list -> strict priority among open gates
 *       -> link-rate model + guard band -> AF_XDP TX ring -> NIC
 *
 * All ports share one UMEM, so frames are never copied in user space.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/resource.h>
#include <bpf/bpf.h>

#include "common.h"
#include "config.h"
#include "fdb.h"
#include "frame_pool.h"
#include "gcl.h"
#include "mpsc.h"
#include "netdev.h"
#include "xsk.h"

#define RX_BATCH   64
#define FILL_BATCH 64
#define WIRE_OVERHEAD 24 /* preamble+SFD (8) + FCS (4) + inter-frame gap (12) */

struct tc_stats {
	stat_t tx;
	stat_t tx_bytes;
	_Atomic uint64_t drop;  /* written by producers on other ports */
};

struct port {
	int idx;
	const struct port_cfg *cfg;
	int ifindex;
	int xsk_key;
	int xdp_mode;           /* mode actually attached, -1 if not attached */
	int promisc_set;        /* we turned promiscuous mode on */
	struct xsk xsk;

	struct gcl gcl;         /* private copy: gcl_eval() updates the hint */
	uint64_t ps_per_byte;   /* 0 = link rate unknown, no pacing */
	int64_t wire_free_at;

	struct frame_cache cache;
	pthread_t thread;

	_Alignas(CACHELINE) struct mpsc_queue txq[TSN_NUM_TC];

	_Alignas(CACHELINE) stat_t rx, rx_bytes, rx_filtered, rx_runt, flooded;
	stat_t tx, completed, pool_empty; /* pool_empty: refills that found no frame */
	struct tc_stats tc[TSN_NUM_TC];
};

static struct switch_cfg cfg;
static struct frame_pool pool;
static struct fdb fdb;
static struct port ports[TSN_MAX_PORTS];
static int nports;
static struct xdp_prog xprog;
static volatile sig_atomic_t stop;

static void on_signal(int sig)
{
	(void)sig;
	stop = 1;
}

static inline int64_t now_ns(void)
{
	struct timespec ts;
	clock_gettime(cfg.clock_id, &ts);
	return (int64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

static inline uint32_t now_sec_coarse(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
	return (uint32_t)ts.tv_sec;
}

/* ------------------------------------------------------------------ RX -- */

static inline void enqueue(struct port *in, struct port *out, int tc, uint64_t addr, uint32_t len)
{
	if (likely(mpsc_enqueue(&out->txq[tc], addr, len)))
		return;
	atomic_fetch_add_explicit(&out->tc[tc].drop, 1, memory_order_relaxed);
	frame_put(&pool, &in->cache, addr);
}

static inline void rx_frame(struct port *in, uint64_t addr, uint32_t len, uint32_t now_s)
{
	const uint8_t *pkt = frame_data(&pool, addr);
	uint8_t pcp = in->cfg->default_pcp;

	if (unlikely(len < ETH_HLEN_)) {
		STAT_INC(in->rx_runt);
		frame_put(&pool, &in->cache, addr);
		return;
	}

	uint16_t proto = (uint16_t)(pkt[12] << 8 | pkt[13]);
	if ((proto == ETH_P_8021Q_ || proto == ETH_P_8021AD_) && len >= ETH_HLEN_ + 4)
		pcp = pkt[14] >> 5;
	int tc = cfg.pcp_to_tc[pcp];

	const uint8_t *dst = pkt, *src = pkt + 6;
	if (likely(!mac_is_multicast(src)))
		fdb_learn(&fdb, src, in->idx, now_s);

	int out = mac_is_multicast(dst) ? -1 : fdb_lookup(&fdb, dst, now_s);
	if (out == in->idx) {
		/* Destination lives on the ingress segment: filter. */
		STAT_INC(in->rx_filtered);
		frame_put(&pool, &in->cache, addr);
		return;
	}
	if (out >= 0) {
		enqueue(in, &ports[out], tc, addr, len);
		return;
	}

	/* Broadcast, multicast or unknown unicast: flood to every other port. */
	STAT_INC(in->flooded);
	if (nports > 2)
		frame_get(&pool, addr, nports - 2);
	for (int i = 0; i < nports; i++)
		if (i != in->idx)
			enqueue(in, &ports[i], tc, addr, len);
}

static void rx_poll(struct port *p)
{
	uint32_t idx, n = xring_cons_peek(&p->xsk.rx, RX_BATCH, &idx);

	if (!n)
		return;

	uint32_t now_s = now_sec_coarse();
	uint64_t bytes = 0;
	for (uint32_t i = 0; i < n; i++) {
		const struct xdp_desc *d = xring_rx_desc(&p->xsk.rx, idx + i);
		if (i + 1 < n)
			__builtin_prefetch(frame_data(&pool, xring_rx_desc(&p->xsk.rx, idx + i + 1)->addr));
		bytes += d->len;
		rx_frame(p, d->addr, d->len, now_s);
	}
	xring_cons_release(&p->xsk.rx);
	STAT_ADD(p->rx, n);
	STAT_ADD(p->rx_bytes, bytes);
}

static void fill_refill(struct port *p)
{
	struct xring *fq = &p->xsk.fill;
	uint32_t free = xring_prod_free(fq);
	uint32_t done = 0;

	if (free < FILL_BATCH)
		return;
	while (done < free) {
		uint64_t addr = frame_alloc(&pool, &p->cache);
		if (addr == FRAME_INVALID) {
			STAT_INC(p->pool_empty);
			break;
		}
		*xring_fill_addr(fq, fq->cached_prod++) = addr;
		done++;
	}
	if (done)
		xring_prod_commit(fq);
}

static void comp_reap(struct port *p)
{
	uint32_t idx, n;

	while ((n = xring_cons_peek(&p->xsk.comp, 256, &idx))) {
		for (uint32_t i = 0; i < n; i++)
			frame_put(&pool, &p->cache, xring_comp_addr(&p->xsk.comp, idx + i));
		xring_cons_release(&p->xsk.comp);
		STAT_ADD(p->completed, n);
	}
}

/* ------------------------------------------------------- 802.1Qbv TX -- */

static inline int64_t wire_ns(const struct port *p, uint32_t len)
{
	return (int64_t)(((uint64_t)len + WIRE_OVERHEAD) * p->ps_per_byte / 1000);
}

/*
 * Transmission selection: among the traffic classes whose gate is open, the
 * highest class goes first (strict priority). With a known link rate the
 * port keeps a model of when the wire becomes idle, so that
 *   - no more than tx_lookahead of traffic is queued ahead in the NIC, and
 *   - a frame is only started if it will finish before its gate closes
 *     (guard band), otherwise it waits for the next window.
 */
static void tx_schedule(struct port *p, int64_t now)
{
	struct xring *tx = &p->xsk.tx;
	struct gate_state gs;
	uint32_t free, sent = 0;

	gcl_eval(&p->gcl, now, &gs);
	if (!gs.gates)
		return;
	free = xring_prod_free(tx);
	if (!free)
		return;

	const int paced = p->ps_per_byte != 0;
	const int64_t horizon = now + (int64_t)p->cfg->lookahead_ns;
	if (p->wire_free_at < now)
		p->wire_free_at = now;

	for (int tc = TSN_NUM_TC - 1; tc >= 0 && free; tc--) {
		struct mpsc_queue *q = &p->txq[tc];
		uint64_t addr, bytes = 0;
		uint32_t len, n = 0;

		if (!(gs.gates & (1u << tc)))
			continue;
		while (free && mpsc_peek(q, &addr, &len)) {
			if (paced) {
				if (p->wire_free_at > horizon)
					break;
				int64_t finish = p->wire_free_at + wire_ns(p, len);
				if (p->cfg->guard_band && finish > gs.close_at[tc])
					break; /* would overrun the window: hold */
				p->wire_free_at = finish;
			}
			mpsc_pop(q);
			struct xdp_desc *d = xring_tx_desc(tx, tx->cached_prod++);
			d->addr = addr;
			d->len = len;
			d->options = 0;
			free--;
			n++;
			bytes += len;
		}
		if (n) {
			STAT_ADD(p->tc[tc].tx, n);
			STAT_ADD(p->tc[tc].tx_bytes, bytes);
			sent += n;
		}
		if (paced && p->wire_free_at > horizon)
			break;
	}
	if (sent) {
		xring_prod_commit(tx);
		STAT_ADD(p->tx, sent);
	}
}

static void *port_thread(void *arg)
{
	struct port *p = arg;
	struct xring *tx = &p->xsk.tx;

	if (p->cfg->cpu >= 0) {
		cpu_set_t set;
		CPU_ZERO(&set);
		CPU_SET(p->cfg->cpu, &set);
		if (pthread_setaffinity_np(pthread_self(), sizeof(set), &set))
			fprintf(stderr, "warning: cannot pin port %s to CPU %d\n", p->cfg->name, p->cfg->cpu);
	}
	char name[16];
	snprintf(name, sizeof(name), "tsn-%.11s", p->cfg->name);
	pthread_setname_np(pthread_self(), name);

	while (!stop) {
		comp_reap(p);
		rx_poll(p);
		fill_refill(p);
		xsk_kick_rx(&p->xsk);
		tx_schedule(p, now_ns());
		/* Copy mode sends at most a few dozen frames per syscall: keep kicking. */
		if (tx->cached_prod != __atomic_load_n(tx->consumer, __ATOMIC_ACQUIRE))
			xsk_kick_tx(&p->xsk);
	}
	return NULL;
}

/* ---------------------------------------------------------------- setup -- */

static int open_sockets(int zerocopy)
{
	struct xsk_opts o = {
		.rx_size = cfg.ring_size, .tx_size = cfg.ring_size,
		.fill_size = cfg.ring_size * 2, .comp_size = cfg.ring_size * 2,
		.zerocopy = zerocopy, .need_wakeup = cfg.need_wakeup,
	};
	uint64_t umem_len = (uint64_t)cfg.frames * cfg.frame_size;

	for (int i = 0; i < nports; i++) {
		struct port *p = &ports[i];
		int err = xsk_open(&p->xsk, p->cfg->ifname, p->ifindex, p->cfg->queue,
				   pool.area, umem_len, cfg.frame_size,
				   i ? &ports[0].xsk : NULL, &o);
		if (err) {
			fprintf(stderr, "%s: AF_XDP socket on %s queue %u (%s): %s\n",
				zerocopy ? "zero-copy" : "copy", p->cfg->ifname, p->cfg->queue,
				i ? "shared UMEM" : "UMEM owner", strerror(-err));
			for (int j = i - 1; j >= 0; j--)
				xsk_close(&ports[j].xsk);
			return err;
		}
	}
	return 0;
}

static const char *default_bpf_path(char *buf, size_t len)
{
	char exe[PATH_MAX];
	ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);

	if (n > 0) {
		exe[n] = 0;
		char *slash = strrchr(exe, '/');
		if (slash) {
			*slash = 0;
			snprintf(buf, len, "%.4000s/tsn_xdp.bpf.o", exe);
			if (!access(buf, R_OK))
				return buf;
		}
	}
	snprintf(buf, len, "tsn_xdp.bpf.o");
	return buf;
}

static int setup(void)
{
	char bpf_path[PATH_MAX];
	int err;

	struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
	setrlimit(RLIMIT_MEMLOCK, &rl);

	/* Make every port safe for teardown() before anything can fail. */
	nports = cfg.nports;
	for (int i = 0; i < nports; i++) {
		ports[i].idx = i;
		ports[i].cfg = &cfg.port[i];
		ports[i].xdp_mode = -1;
		ports[i].xsk.fd = -1;
	}

	for (int i = 0; i < nports; i++) {
		struct port *p = &ports[i];
		p->gcl = p->cfg->gcl;
		p->ifindex = if_nametoindex(p->cfg->ifname);
		if (!p->ifindex) {
			fprintf(stderr, "port %s: interface %s not found\n", p->cfg->name, p->cfg->ifname);
			return -1;
		}

		int64_t mbps = p->cfg->link_mbps < 0 ? netdev_speed_mbps(p->cfg->ifname) : p->cfg->link_mbps;
		p->ps_per_byte = mbps > 0 ? (uint64_t)(8000000 / mbps) : 0;
		if (!p->ps_per_byte && p->gcl.n && p->cfg->guard_band)
			fprintf(stderr, "warning: port %s: link speed unknown, guard band disabled "
				"(set link_speed)\n", p->cfg->name);

		int nq = netdev_rx_queues(p->cfg->ifname);
		if (nq > 1)
			fprintf(stderr, "warning: %s has %d RX queues but the switch only serves queue %u; "
				"run 'ethtool -L %s combined 1' or steer traffic to that queue\n",
				p->cfg->ifname, nq, p->cfg->queue, p->cfg->ifname);

		int was_promisc = 1;
		if ((err = netdev_set_promisc(p->cfg->ifname, 1, &was_promisc)))
			fprintf(stderr, "warning: %s: cannot enable promiscuous mode (%s)\n",
				p->cfg->ifname, strerror(-err));
		p->promisc_set = !err && !was_promisc;

		if (cfg.disable_vlan_offload && (err = netdev_disable_vlan_offload(p->cfg->ifname)))
			fprintf(stderr, "warning: %s: cannot disable VLAN offload (%s); tagged frames may "
				"lose their PCP\n", p->cfg->ifname, strerror(-err));

		/* Ports on the same netdev (different queues) share one XSKMAP block. */
		int base = i;
		for (int j = 0; j < i; j++)
			if (ports[j].ifindex == p->ifindex) {
				base = j;
				break;
			}
		p->xsk_key = base * TSN_MAX_QUEUES + p->cfg->queue;

		for (int tc = 0; tc < TSN_NUM_TC; tc++)
			if (mpsc_init(&p->txq[tc], cfg.queue_depth))
				return -1;
	}

	if (frame_pool_init(&pool, cfg.frames, cfg.frame_size, cfg.hugepages)) {
		fprintf(stderr, "cannot allocate UMEM (%u x %u bytes)\n", cfg.frames, cfg.frame_size);
		return -1;
	}

	fdb_init(&fdb, cfg.fdb_aging);
	for (int i = 0; i < cfg.nstatic; i++)
		if (fdb_add_static(&fdb, cfg.fdb_static[i].mac, cfg.fdb_static[i].port))
			fprintf(stderr, "warning: static FDB bucket full, entry %d ignored\n", i);

	if (xdp_prog_load(&xprog, cfg.bpf_obj[0] ? cfg.bpf_obj : default_bpf_path(bpf_path, sizeof(bpf_path)),
			  cfg.pass_ctrl ? TSN_BPF_F_PASS_CTRL : 0))
		return -1;

	for (int i = 0; i < nports; i++) {
		struct port *p = &ports[i];
		uint32_t key = p->ifindex, val = (uint32_t)(p->xsk_key / TSN_MAX_QUEUES);
		int shared = 0;

		for (int j = 0; j < i; j++)
			shared |= ports[j].ifindex == p->ifindex;
		if (shared)
			continue;
		if (bpf_map_update_elem(xprog.port_map_fd, &key, &val, 0)) {
			fprintf(stderr, "cannot update port_map: %s\n", strerror(errno));
			return -1;
		}
		int mode = xdp_attach(p->ifindex, xprog.prog_fd, cfg.xdp_mode);
		if (mode < 0) {
			fprintf(stderr, "cannot attach XDP to %s: %s\n", p->cfg->ifname, strerror(-mode));
			return -1;
		}
		p->xdp_mode = mode;
	}

	/* Zero-copy needs every port to support it because the UMEM is shared. */
	err = -1;
	if (cfg.zerocopy != TRI_OFF) {
		err = open_sockets(1);
		if (err && cfg.zerocopy == TRI_ON)
			return -1;
		if (err)
			fprintf(stderr, "zero-copy not available on all ports, falling back to copy mode\n");
	}
	if (err && open_sockets(0))
		return -1;

	for (int i = 0; i < nports; i++) {
		uint32_t key = ports[i].xsk_key;
		if (bpf_map_update_elem(xprog.xsks_fd, &key, &ports[i].xsk.fd, 0)) {
			fprintf(stderr, "cannot insert socket in xsks_map: %s\n", strerror(errno));
			return -1;
		}
	}
	return 0;
}

static void teardown(void)
{
	for (int i = 0; i < nports; i++) {
		struct port *p = &ports[i];
		if (p->xdp_mode >= 0)
			xdp_detach(p->ifindex, p->xdp_mode);
		if (p->promisc_set)
			netdev_set_promisc(p->cfg->ifname, 0, NULL);
	}
	for (int i = nports - 1; i >= 0; i--)
		if (ports[i].xsk.fd >= 0)
			xsk_close(&ports[i].xsk);
	xdp_prog_close(&xprog);
	for (int i = 0; i < nports; i++)
		for (int tc = 0; tc < TSN_NUM_TC; tc++)
			mpsc_free(&ports[i].txq[tc]);
	frame_pool_destroy(&pool);
}

/* ---------------------------------------------------------------- stats -- */

struct snap {
	uint64_t rx, rx_bytes, tx, tx_bytes, drops, tc_tx[TSN_NUM_TC];
};

static void take_snap(struct port *p, struct snap *s)
{
	s->rx = STAT_GET(p->rx);
	s->rx_bytes = STAT_GET(p->rx_bytes);
	s->tx = STAT_GET(p->tx);
	s->drops = 0;
	s->tx_bytes = 0;
	for (int tc = 0; tc < TSN_NUM_TC; tc++) {
		s->tc_tx[tc] = STAT_GET(p->tc[tc].tx);
		s->tx_bytes += STAT_GET(p->tc[tc].tx_bytes);
		s->drops += atomic_load_explicit(&p->tc[tc].drop, memory_order_relaxed);
	}
}

static void print_stats(struct snap *prev, double dt)
{
	printf("\n%-8s %-12s %10s %10s %9s %9s %9s %9s  queue depth per TC (7..0)\n",
	       "port", "ifname", "rx pps", "tx pps", "rx Mb/s", "tx Mb/s", "drops", "flooded");
	for (int i = 0; i < nports; i++) {
		struct port *p = &ports[i];
		struct snap s;
		take_snap(p, &s);
		printf("%-8s %-12s %10.0f %10.0f %9.1f %9.1f %9llu %9llu ",
		       p->cfg->name, p->cfg->ifname,
		       (s.rx - prev[i].rx) / dt, (s.tx - prev[i].tx) / dt,
		       (s.rx_bytes - prev[i].rx_bytes) * 8 / dt / 1e6,
		       (s.tx_bytes - prev[i].tx_bytes) * 8 / dt / 1e6,
		       (unsigned long long)s.drops, (unsigned long long)STAT_GET(p->flooded));
		for (int tc = TSN_NUM_TC - 1; tc >= 0; tc--)
			printf(" %u", mpsc_count(&p->txq[tc]));
		printf("\n");
		prev[i] = s;
	}
	printf("fdb entries: %d, free frames: %llu\n", fdb_count(&fdb, now_sec_coarse()),
	       (unsigned long long)frame_pool_free_count(&pool));
	fflush(stdout);
}

/*
 * After the port threads have stopped, every frame must be in exactly one
 * place: the free pool, a thread cache, a fill ring, a TX ring/completion
 * ring or a traffic class queue. Anything else is a leak.
 */
static void account_frames(void)
{
	uint64_t n;

	/* Return queued and completed frames to the pool first. */
	for (int i = 0; i < nports; i++) {
		struct port *p = &ports[i];
		uint64_t addr;
		uint32_t len;

		if (p->xsk.fd < 0)
			continue;
		comp_reap(p);
		for (int tc = 0; tc < TSN_NUM_TC; tc++)
			while (mpsc_peek(&p->txq[tc], &addr, &len)) {
				mpsc_pop(&p->txq[tc]);
				frame_put(&pool, &p->cache, addr);
			}
	}

	n = frame_pool_free_count(&pool);
	for (int i = 0; i < nports; i++) {
		struct port *p = &ports[i];
		if (p->xsk.fd < 0)
			continue;
		n += p->cache.n;
		n += p->xsk.fill.cached_prod - __atomic_load_n(p->xsk.fill.consumer, __ATOMIC_ACQUIRE);
		n += p->xsk.tx.cached_prod - __atomic_load_n(p->xsk.tx.consumer, __ATOMIC_ACQUIRE);
		n += __atomic_load_n(p->xsk.rx.producer, __ATOMIC_ACQUIRE) - p->xsk.rx.cached_cons;
	}
	printf("frames accounted: %llu/%u%s\n", (unsigned long long)n, cfg.frames,
	       n == cfg.frames ? " (no leaks)" : "  <-- in flight in the kernel or leaked");
}

static void print_final(void)
{
	printf("\nfinal counters:\n");
	for (int i = 0; i < nports; i++) {
		struct port *p = &ports[i];
		printf("%-8s rx=%llu tx=%llu completed=%llu filtered=%llu runt=%llu flooded=%llu "
		       "pool_empty=%llu\n", p->cfg->name,
		       (unsigned long long)STAT_GET(p->rx), (unsigned long long)STAT_GET(p->tx),
		       (unsigned long long)STAT_GET(p->completed), (unsigned long long)STAT_GET(p->rx_filtered),
		       (unsigned long long)STAT_GET(p->rx_runt), (unsigned long long)STAT_GET(p->flooded),
		       (unsigned long long)STAT_GET(p->pool_empty));
		printf("         tx per TC:");
		for (int tc = 0; tc < TSN_NUM_TC; tc++)
			printf(" %d:%llu", tc, (unsigned long long)STAT_GET(p->tc[tc].tx));
		printf("\n         drops per TC:");
		for (int tc = 0; tc < TSN_NUM_TC; tc++)
			printf(" %d:%llu", tc, (unsigned long long)atomic_load(&p->tc[tc].drop));
		printf("\n");
	}
}

/* ----------------------------------------------------------------- main -- */

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s -c <config> [options]\n"
		"  -c, --config FILE   switch configuration (see config/)\n"
		"  -b, --bpf FILE      XDP object (default: tsn_xdp.bpf.o next to the binary)\n"
		"  -n, --check         parse the configuration, print it and exit\n"
		"  -q, --quiet         do not print periodic statistics\n"
		"  -h, --help          this help\n", prog);
}

int main(int argc, char **argv)
{
	static const struct option opts[] = {
		{ "config", required_argument, NULL, 'c' },
		{ "bpf", required_argument, NULL, 'b' },
		{ "check", no_argument, NULL, 'n' },
		{ "quiet", no_argument, NULL, 'q' },
		{ "help", no_argument, NULL, 'h' },
		{ 0 }
	};
	const char *cfg_path = NULL, *bpf_path = NULL;
	int check = 0, quiet = 0, c, rc = 0;

	while ((c = getopt_long(argc, argv, "c:b:nqh", opts, NULL)) != -1) {
		switch (c) {
		case 'c': cfg_path = optarg; break;
		case 'b': bpf_path = optarg; break;
		case 'n': check = 1; break;
		case 'q': quiet = 1; break;
		default: usage(argv[0]); return c == 'h' ? 0 : 1;
		}
	}
	if (!cfg_path) {
		usage(argv[0]);
		return 1;
	}
	if (config_load(&cfg, cfg_path))
		return 1;
	if (bpf_path)
		snprintf(cfg.bpf_obj, sizeof(cfg.bpf_obj), "%s", bpf_path);
	if (quiet)
		cfg.stats_interval = 0;

	config_dump(&cfg);
	if (check)
		return 0;

	struct sigaction sa = { .sa_handler = on_signal };
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	if (setup()) {
		teardown();
		return 1;
	}

	printf("\nUMEM: %u frames x %u B, %s mode\n", cfg.frames, cfg.frame_size,
	       ports[0].xsk.zerocopy ? "zero-copy" : "copy");
	for (int i = 0; i < nports; i++)
		printf("port %-8s %-12s XDP %-6s link %s\n", ports[i].cfg->name, ports[i].cfg->ifname,
		       ports[i].xdp_mode == XDP_MODE_SKB ? "skb" : "native",
		       ports[i].ps_per_byte ? "paced" : "unpaced");

	for (int i = 0; i < nports; i++) {
		if ((errno = pthread_create(&ports[i].thread, NULL, port_thread, &ports[i]))) {
			perror("pthread_create");
			stop = 1;
			for (int j = 0; j < i; j++)
				pthread_join(ports[j].thread, NULL);
			teardown();
			return 1;
		}
	}
	printf("tsn-switch running, Ctrl-C to stop\n");
	fflush(stdout);

	struct snap prev[TSN_MAX_PORTS];
	for (int i = 0; i < nports; i++)
		take_snap(&ports[i], &prev[i]);
	struct timespec last;
	clock_gettime(CLOCK_MONOTONIC, &last);

	while (!stop) {
		if (!cfg.stats_interval) {
			pause();
			continue;
		}
		sleep(cfg.stats_interval);
		struct timespec t;
		clock_gettime(CLOCK_MONOTONIC, &t);
		double dt = (t.tv_sec - last.tv_sec) + (t.tv_nsec - last.tv_nsec) / 1e9;
		last = t;
		if (!stop && dt > 0)
			print_stats(prev, dt);
	}

	for (int i = 0; i < nports; i++)
		pthread_join(ports[i].thread, NULL);
	print_final();
	account_frames();
	teardown();
	return rc;
}
