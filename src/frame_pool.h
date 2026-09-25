/* SPDX-License-Identifier: GPL-2.0 */
/*
 * UMEM frame allocator shared by all ports.
 *
 * All sockets share one UMEM, so a frame received on port A is transmitted on
 * port B without copying. Frames live in a global free stack protected by a
 * spinlock; every port thread keeps a private cache so the lock is only taken
 * in bulk. A per-frame reference count lets one received frame be flooded to
 * several egress ports at once.
 */
#ifndef TSN_FRAME_POOL_H
#define TSN_FRAME_POOL_H

#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <stdatomic.h>
#include "common.h"

#define FRAME_INVALID   UINT64_MAX
#define POOL_CACHE_SIZE 1024
#define POOL_BULK       256

struct frame_pool {
	uint8_t *area;
	uint64_t nframes;
	uint32_t frame_shift; /* log2(frame_size) */

	pthread_spinlock_t lock;
	uint64_t *stack;
	uint64_t top;

	_Atomic uint16_t *ref;
};

struct frame_cache {
	uint64_t n;
	uint64_t addr[POOL_CACHE_SIZE];
};

int  frame_pool_init(struct frame_pool *fp, uint64_t nframes, uint32_t frame_size, int hugepages);
void frame_pool_destroy(struct frame_pool *fp);
uint64_t frame_pool_free_count(struct frame_pool *fp);

static inline uint64_t frame_base(const struct frame_pool *fp, uint64_t addr)
{
	return (addr >> fp->frame_shift) << fp->frame_shift;
}

static inline void *frame_data(const struct frame_pool *fp, uint64_t addr)
{
	return fp->area + addr;
}

static inline uint64_t frame_alloc(struct frame_pool *fp, struct frame_cache *c)
{
	if (unlikely(c->n == 0)) {
		pthread_spin_lock(&fp->lock);
		uint64_t take = fp->top < POOL_BULK ? fp->top : POOL_BULK;
		fp->top -= take;
		memcpy(c->addr, &fp->stack[fp->top], take * sizeof(uint64_t));
		pthread_spin_unlock(&fp->lock);
		c->n = take;
		if (take == 0)
			return FRAME_INVALID;
	}
	uint64_t addr = c->addr[--c->n];

	atomic_store_explicit(&fp->ref[addr >> fp->frame_shift], 1, memory_order_relaxed);
	return addr;
}

/* Add @n extra owners to a frame (used when flooding). */
static inline void frame_get(struct frame_pool *fp, uint64_t addr, uint16_t n)
{
	atomic_fetch_add_explicit(&fp->ref[addr >> fp->frame_shift], n, memory_order_relaxed);
}

/* Drop one owner; the last owner returns the frame to the pool. */
static inline void frame_put(struct frame_pool *fp, struct frame_cache *c, uint64_t addr)
{
	uint64_t idx = addr >> fp->frame_shift;

	if (atomic_fetch_sub_explicit(&fp->ref[idx], 1, memory_order_acq_rel) != 1)
		return;

	if (unlikely(c->n == POOL_CACHE_SIZE)) {
		pthread_spin_lock(&fp->lock);
		c->n -= POOL_BULK;
		memcpy(&fp->stack[fp->top], &c->addr[c->n], POOL_BULK * sizeof(uint64_t));
		fp->top += POOL_BULK;
		pthread_spin_unlock(&fp->lock);
	}
	c->addr[c->n++] = idx << fp->frame_shift;
}

#endif
