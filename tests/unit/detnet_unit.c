// SPDX-License-Identifier: GPL-2.0
/*
 * Deterministic tests of the DetNet elimination (PEF) and ordering (POF)
 * functions: crafted DetNet packets go through detnet_rx()/detnet_poll()
 * with a simulated clock, and the order of the decapsulated packets is
 * checked. No network or root needed: make unit
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "config.h"
#include "detnet.h"

#define NFRAMES 4096

static struct frame_pool pool;
static struct frame_cache cache;
static struct fdb fdb;
static uint32_t out[200000];
static int nout;
static int failures;

/* Decap output: the sequence number was stored in the inner IPv4 source. */
static void emit(void *arg, int in_port, int out_port, int tc, uint64_t addr, uint32_t len)
{
	const uint8_t *p = frame_data(&pool, addr);
	out[nout++] = (uint32_t)p[26] << 24 | p[27] << 16 | p[28] << 8 | p[29];
	frame_put(&pool, &cache, addr);
}

static void put16(uint8_t *p, uint16_t v) { p[0] = v >> 8; p[1] = v; }
static void put32(uint8_t *p, uint32_t v) { p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v; }

/* Ethernet | IPv4 | UDP 6635 | S-label | d-CW | inner IPv4 (src = seq) */
static void feed(struct detnet *d, struct dn_ctx *x, uint32_t label, uint32_t seq)
{
	uint64_t addr = frame_alloc(&pool, &cache) + 256;
	uint8_t *p = frame_data(&pool, addr);

	memset(p, 0, 90);
	put16(p + 12, 0x0800);
	uint8_t *ip = p + 14, *udp = ip + 20, *lse = udp + 8, *in = lse + 8;
	ip[0] = 0x45;
	put16(ip + 2, 20 + 8 + 8 + 20);
	ip[8] = 64;
	ip[9] = 17;
	put16(udp + 2, 6635);
	put16(udp + 4, 8 + 8 + 20);
	put32(lse, label << 12 | 1 << 8 | 255);
	put32(lse + 4, seq & DN_SEQ_MASK);
	in[0] = 0x45;
	put16(in + 2, 20);
	in[9] = 17;
	put32(in + 12, seq & DN_SEQ_MASK);
	if (!detnet_rx(d, x, 0, addr, 14 + 20 + 8 + 8 + 20)) {
		printf("  packet seq %u not taken by the DetNet layer\n", seq);
		failures++;
		frame_put(&pool, &cache, addr);
	}
}

static void expect(const char *name, const uint32_t *want, int n)
{
	int ok = nout == n && !memcmp(out, want, n * sizeof(*want));
	printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
	if (!ok) {
		printf("  got %d:", nout);
		for (int i = 0; i < nout && i < 20; i++)
			printf(" %x", out[i]);
		printf("\n  want %d:", n);
		for (int i = 0; i < n && i < 20; i++)
			printf(" %x", want[i]);
		printf("\n");
		failures++;
	}
	nout = 0;
}

static const char *flows =
	"[flow full-buffer]\n"
	"action = decap\nlabel = 100\norder = yes\norder_buffer = 1\norder_max_delay = 1s\n"
	"output = port=p0 dst_mac=02:00:00:00:00:01 src_mac=02:00:00:00:00:02\n"
	"[flow restart]\n"
	"action = decap\nlabel = 101\neliminate = yes\nreset_timeout = 10ms\n"
	"output = port=p0 dst_mac=02:00:00:00:00:01 src_mac=02:00:00:00:00:02\n"
	"[flow wrap]\n"
	"action = decap\nlabel = 102\neliminate = yes\norder = yes\norder_max_delay = 1ms\n"
	"output = port=p0 dst_mac=02:00:00:00:00:01 src_mac=02:00:00:00:00:02\n"
	"[flow timeout]\n"
	"action = decap\nlabel = 103\norder = yes\norder_max_delay = 1ms\n"
	"output = port=p0 dst_mac=02:00:00:00:00:01 src_mac=02:00:00:00:00:02\n";

int main(void)
{
	char path[] = "/tmp/detnet_unit_XXXXXX";
	struct switch_cfg *cfg = calloc(1, sizeof(*cfg));
	struct detnet d;
	int fd = mkstemp(path);

	if (fd < 0 || write(fd, flows, strlen(flows)) != (ssize_t)strlen(flows))
		return 1;
	close(fd);
	cfg->nports = 1;
	snprintf(cfg->port[0].name, sizeof(cfg->port[0].name), "p0");
	for (int i = 0; i < 8; i++)
		cfg->pcp_to_tc[i] = i;
	if (frame_pool_init(&pool, NFRAMES, 2048, 0) || detnet_load(&d, path, cfg))
		return 1;
	unlink(path);
	fdb_init(&fdb, 300);

	struct dn_ctx x = { .pool = &pool, .cache = &cache, .fdb = &fdb, .emit = emit, .now = 1000000000 };

	/* 1. Full ordering buffer: the next packet in sequence must go out, not be dropped. */
	feed(&d, &x, 100, 5);
	feed(&d, &x, 100, 10);   /* held, buffer (1 slot) now full */
	feed(&d, &x, 100, 7);    /* closer than the held one: deliver it */
	feed(&d, &x, 100, 8);
	feed(&d, &x, 100, 9);    /* ...and 10 follows from the buffer */
	expect("POF full buffer delivers the next packet", (uint32_t[]){ 5, 7, 8, 9, 10 }, 5);

	/* 2. Sequence restart while traffic keeps flowing (1 us per packet). */
	for (uint32_t s = 1; s <= 100000; s++, x.now += 1000)
		feed(&d, &x, 101, s);
	nout = 0;
	for (uint32_t s = 1; s <= 20000; s++, x.now += 1000)
		feed(&d, &x, 101, s);
	/* Rejected for reset_timeout (10 ms = 10000 packets), then accepted again. */
	int ok = nout > 9000 && nout < 11000 && out[nout - 1] == 20000;
	printf("[%s] PEF recovers from a sequence restart (%d of 20000 accepted after the reset)\n",
	       ok ? "PASS" : "FAIL", nout);
	failures += !ok;
	nout = 0;

	/* 3. Elimination + ordering across the 2^28 wrap. */
	const uint32_t M = DN_SEQ_MASK;
	uint32_t in3[] = { M - 2, M, M - 1, M, 1, 0, M - 1, 2, 1 };
	for (unsigned i = 0; i < sizeof(in3) / sizeof(in3[0]); i++)
		feed(&d, &x, 102, in3[i]);
	expect("PEF+POF across the sequence wrap", (uint32_t[]){ M - 2, M - 1, M, 0, 1, 2 }, 6);

	/* 4. Timeout: a gap that never fills is skipped after order_max_delay. */
	feed(&d, &x, 103, 50);
	feed(&d, &x, 103, 53);   /* 51, 52 lost */
	x.now += 500000;
	feed(&d, &x, 103, 55);   /* 54 lost too, held later than 53 */
	detnet_poll(&d, &x, 0);  /* 0.5 ms: nothing is due yet */
	int early = nout;
	x.now += 600000;         /* 53 waited 1.1 ms, 55 only 0.6 ms */
	detnet_poll(&d, &x, 0);
	int mid = nout;
	x.now += 500000;
	detnet_poll(&d, &x, 0);
	ok = early == 1 && mid == 2 && nout == 3 && out[1] == 53 && out[2] == 55;
	printf("[%s] POF releases each held packet after order_max_delay\n", ok ? "PASS" : "FAIL");
	failures += !ok;
	nout = 0;

	detnet_print_stats(&d);
	detnet_drain(&d, &pool, &cache);
	uint64_t free_frames = frame_pool_free_count(&pool) + cache.n;
	ok = free_frames == NFRAMES;
	printf("[%s] no frame leaked (%llu/%d)\n", ok ? "PASS" : "FAIL",
	       (unsigned long long)free_frames, NFRAMES);
	failures += !ok;

	detnet_free(&d);
	printf("%s\n", failures ? "FAIL" : "all unit tests passed");
	return failures ? 1 : 0;
}
