/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Minimal AF_XDP socket layer built directly on the kernel UAPI.
 *
 * It replaces the xsk.h helpers that moved from libbpf to libxdp, so the
 * switch builds against any libbpf (0.x or 1.x) without extra dependencies.
 * Ring semantics match libbpf's xsk_ring_prod / xsk_ring_cons.
 */
#ifndef TSN_XSK_H
#define TSN_XSK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <linux/if_xdp.h>

struct xring {
	uint32_t cached_prod;
	uint32_t cached_cons;
	uint32_t mask;
	uint32_t size;
	uint32_t *producer;
	uint32_t *consumer;
	uint32_t *flags;
	void *ring;
	void *map;
	size_t map_len;
};

struct xsk {
	int fd;
	int zerocopy;
	int need_wakeup;
	struct xring rx, tx, fill, comp;
};

struct xsk_opts {
	uint32_t rx_size, tx_size, fill_size, comp_size; /* powers of two */
	int zerocopy;      /* 1: force XDP_ZEROCOPY, 0: force XDP_COPY */
	int need_wakeup;
};

/*
 * Create the socket that registers the UMEM (primary) or a socket that shares
 * the UMEM of @primary (possibly on another netdev). Returns 0 or -errno.
 */
int  xsk_open(struct xsk *x, const char *ifname, int ifindex, uint32_t queue,
	      void *umem_area, uint64_t umem_len, uint32_t frame_size,
	      const struct xsk *primary, const struct xsk_opts *o);
void xsk_close(struct xsk *x);

/* ---- producer rings (fill, tx) ---- */

static inline uint32_t xring_prod_free(struct xring *r)
{
	uint32_t free = r->size - (r->cached_prod - r->cached_cons);

	if (free == 0 || free < r->size / 4) {
		r->cached_cons = __atomic_load_n(r->consumer, __ATOMIC_ACQUIRE);
		free = r->size - (r->cached_prod - r->cached_cons);
	}
	return free;
}

static inline struct xdp_desc *xring_tx_desc(struct xring *r, uint32_t idx)
{
	return &((struct xdp_desc *)r->ring)[idx & r->mask];
}

static inline uint64_t *xring_fill_addr(struct xring *r, uint32_t idx)
{
	return &((uint64_t *)r->ring)[idx & r->mask];
}

/* Publish every slot written since the last commit (cached_prod advanced). */
static inline void xring_prod_commit(struct xring *r)
{
	__atomic_store_n(r->producer, r->cached_prod, __ATOMIC_RELEASE);
}

static inline bool xring_needs_wakeup(const struct xring *r)
{
	return *(volatile uint32_t *)r->flags & XDP_RING_NEED_WAKEUP;
}

/* ---- consumer rings (rx, comp) ---- */

static inline uint32_t xring_cons_peek(struct xring *r, uint32_t max, uint32_t *idx)
{
	uint32_t avail = r->cached_prod - r->cached_cons;

	if (avail == 0) {
		r->cached_prod = __atomic_load_n(r->producer, __ATOMIC_ACQUIRE);
		avail = r->cached_prod - r->cached_cons;
	}
	if (avail > max)
		avail = max;
	*idx = r->cached_cons;
	r->cached_cons += avail;
	return avail;
}

static inline const struct xdp_desc *xring_rx_desc(struct xring *r, uint32_t idx)
{
	return &((const struct xdp_desc *)r->ring)[idx & r->mask];
}

static inline uint64_t xring_comp_addr(struct xring *r, uint32_t idx)
{
	return ((const uint64_t *)r->ring)[idx & r->mask];
}

static inline void xring_cons_release(struct xring *r)
{
	__atomic_store_n(r->consumer, r->cached_cons, __ATOMIC_RELEASE);
}

void xsk_kick_tx(struct xsk *x);
void xsk_kick_rx(struct xsk *x);

#endif
