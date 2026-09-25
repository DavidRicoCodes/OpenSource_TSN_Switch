/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Bounded lock-free multi-producer / single-consumer queue of frame
 * descriptors (D. Vyukov's bounded MPMC algorithm, consumer side simplified).
 *
 * Producers are the RX paths of every port thread; the consumer is the TX
 * scheduler of the egress port that owns the queue. Enqueue never blocks: a
 * full queue is reported to the caller, which tail-drops the frame.
 */
#ifndef TSN_MPSC_H
#define TSN_MPSC_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdatomic.h>
#include "common.h"

struct mpsc_cell {
	_Atomic uint32_t seq;
	uint32_t len;
	uint64_t addr;
};

struct mpsc_queue {
	struct mpsc_cell *cells;
	uint32_t mask;
	_Alignas(CACHELINE) _Atomic uint32_t enq_pos;
	_Alignas(CACHELINE) uint32_t deq_pos;
};

static inline int mpsc_init(struct mpsc_queue *q, uint32_t size_pow2)
{
	q->cells = aligned_alloc(CACHELINE, sizeof(*q->cells) * size_pow2);
	if (!q->cells)
		return -1;
	for (uint32_t i = 0; i < size_pow2; i++)
		atomic_init(&q->cells[i].seq, i);
	q->mask = size_pow2 - 1;
	atomic_init(&q->enq_pos, 0);
	q->deq_pos = 0;
	return 0;
}

static inline void mpsc_free(struct mpsc_queue *q)
{
	free(q->cells);
	q->cells = NULL;
}

static inline bool mpsc_enqueue(struct mpsc_queue *q, uint64_t addr, uint32_t len)
{
	struct mpsc_cell *c;
	uint32_t pos = atomic_load_explicit(&q->enq_pos, memory_order_relaxed);

	for (;;) {
		c = &q->cells[pos & q->mask];
		uint32_t seq = atomic_load_explicit(&c->seq, memory_order_acquire);
		int32_t diff = (int32_t)(seq - pos);

		if (diff == 0) {
			if (atomic_compare_exchange_weak_explicit(&q->enq_pos, &pos, pos + 1,
								  memory_order_relaxed,
								  memory_order_relaxed))
				break;
		} else if (diff < 0) {
			return false; /* full */
		} else {
			pos = atomic_load_explicit(&q->enq_pos, memory_order_relaxed);
		}
	}
	c->addr = addr;
	c->len = len;
	atomic_store_explicit(&c->seq, pos + 1, memory_order_release);
	return true;
}

/* Consumer only: look at the head element without removing it. */
static inline bool mpsc_peek(struct mpsc_queue *q, uint64_t *addr, uint32_t *len)
{
	struct mpsc_cell *c = &q->cells[q->deq_pos & q->mask];
	uint32_t seq = atomic_load_explicit(&c->seq, memory_order_acquire);

	if ((int32_t)(seq - (q->deq_pos + 1)) < 0)
		return false;
	*addr = c->addr;
	*len = c->len;
	return true;
}

/* Consumer only: drop the head element previously returned by mpsc_peek(). */
static inline void mpsc_pop(struct mpsc_queue *q)
{
	struct mpsc_cell *c = &q->cells[q->deq_pos & q->mask];

	atomic_store_explicit(&c->seq, q->deq_pos + q->mask + 1, memory_order_release);
	q->deq_pos++;
}

/* Approximate occupancy, for statistics only. */
static inline uint32_t mpsc_count(struct mpsc_queue *q)
{
	uint32_t e = atomic_load_explicit(&q->enq_pos, memory_order_relaxed);
	uint32_t d = *(volatile uint32_t *)&q->deq_pos;

	return e - d;
}

#endif
