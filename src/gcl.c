// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include "gcl.h"

int gcl_finalize(struct gcl *g, char *err, size_t errlen)
{
	uint64_t sum = 0;

	if (g->n == 0)
		return 0;

	for (int i = 0; i < g->n; i++) {
		if (g->e[i].interval == 0) {
			snprintf(err, errlen, "sched-entry %d has a zero interval", i);
			return -1;
		}
		sum += g->e[i].interval;
	}
	if (g->cycle_time == 0)
		g->cycle_time = sum;

	/*
	 * Same rules as 802.1Qbv / taprio: a list longer than the cycle is
	 * truncated, a shorter one keeps the last gate state until cycle end.
	 */
	uint64_t t = 0;
	int n = 0;
	for (; n < g->n && t < g->cycle_time; n++) {
		g->e[n].start = t;
		if (t + g->e[n].interval > g->cycle_time)
			g->e[n].interval = g->cycle_time - t;
		t += g->e[n].interval;
	}
	g->n = n;
	if (t < g->cycle_time)
		g->e[n - 1].interval += g->cycle_time - t;

	for (int i = 0; i < g->n; i++) {
		for (int tc = 0; tc < TSN_NUM_TC; tc++) {
			uint8_t bit = 1u << tc;
			uint64_t acc = 0;
			int k;

			if (!(g->e[i].gates & bit)) {
				g->e[i].open_for[tc] = 0;
				continue;
			}
			for (k = 0; k < g->n; k++) {
				const struct gcl_entry *x = &g->e[(i + k) % g->n];
				if (!(x->gates & bit))
					break;
				acc += x->interval;
			}
			g->e[i].open_for[tc] = (k == g->n) ? (uint64_t)GCL_NEVER : acc;
		}
	}
	g->hint = 0;
	return 0;
}

void gcl_eval(struct gcl *g, int64_t now, struct gate_state *st)
{
	if (g->n == 0) {
		st->gates = 0xff;
		for (int tc = 0; tc < TSN_NUM_TC; tc++)
			st->close_at[tc] = GCL_NEVER;
		st->next_change = GCL_NEVER;
		return;
	}

	int64_t cycle = (int64_t)g->cycle_time;
	int64_t off = (now - g->base_time) % cycle;
	if (off < 0)
		off += cycle;

	/* Entries are visited in order, so the hint almost always hits. */
	int i = g->hint;
	for (int tries = 0; tries <= g->n; tries++) {
		const struct gcl_entry *x = &g->e[i];
		if ((uint64_t)off >= x->start && (uint64_t)off < x->start + x->interval)
			break;
		i = (i + 1) % g->n;
	}
	g->hint = i;

	const struct gcl_entry *x = &g->e[i];
	int64_t entry_start = now - (off - (int64_t)x->start);

	st->gates = x->gates;
	st->next_change = entry_start + (int64_t)x->interval;
	for (int tc = 0; tc < TSN_NUM_TC; tc++) {
		uint64_t of = x->open_for[tc];
		st->close_at[tc] = of == (uint64_t)GCL_NEVER ? GCL_NEVER : entry_start + (int64_t)of;
	}
}
