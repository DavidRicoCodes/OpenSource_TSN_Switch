/* SPDX-License-Identifier: GPL-2.0 */
/*
 * IEEE 802.1Qbv gate control list (time-aware shaper schedule).
 *
 * The schedule repeats every cycle_time ns starting at base_time. Each entry
 * holds a gate-state bitmask (bit N = traffic class N may transmit) for a
 * given interval, exactly like "sched-entry S <mask> <interval>" in tc-taprio.
 */
#ifndef TSN_GCL_H
#define TSN_GCL_H

#include <stdint.h>
#include "common.h"

#define GCL_NEVER INT64_MAX

struct gcl_entry {
	uint8_t gates;
	uint64_t interval;
	uint64_t start;                 /* offset inside the cycle */
	uint64_t open_for[TSN_NUM_TC];  /* time from entry start until gate closes */
};

struct gcl {
	int n;                          /* 0 = no schedule: all gates always open */
	int64_t base_time;
	uint64_t cycle_time;
	struct gcl_entry e[TSN_MAX_GCL];
	int hint;                       /* last entry found (owner thread only) */
};

struct gate_state {
	uint8_t gates;
	int64_t close_at[TSN_NUM_TC];   /* absolute time each open gate closes */
	int64_t next_change;            /* absolute time of the next entry */
};

/* Validates and precomputes the schedule. Returns 0 or -1 with a message. */
int  gcl_finalize(struct gcl *g, char *err, size_t errlen);
void gcl_eval(struct gcl *g, int64_t now, struct gate_state *st);

#endif
