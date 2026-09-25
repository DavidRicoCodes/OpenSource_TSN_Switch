/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Learning MAC forwarding database shared by all port threads.
 *
 * Set-associative hash table of 64-bit words (MAC << 16 | flags | port) so
 * lookups and updates are single atomic loads/stores with no locking. Two RX
 * threads learning into the same bucket at the same time may overwrite each
 * other; the loser simply re-learns on its next frame, which is the normal
 * behaviour of a learning bridge.
 */
#ifndef TSN_FDB_H
#define TSN_FDB_H

#include <stdint.h>
#include <stdatomic.h>
#include "common.h"

#define FDB_BUCKETS 4096
#define FDB_WAYS    4

struct fdb_slot {
	_Atomic uint64_t key;   /* mac:48 | static:8 | port+1:8, 0 = empty */
	_Atomic uint32_t seen;  /* seconds, CLOCK_MONOTONIC_COARSE */
	uint32_t pad;
};

struct fdb {
	uint32_t aging;         /* seconds, 0 = never age out */
	_Alignas(CACHELINE) struct fdb_slot slot[FDB_BUCKETS][FDB_WAYS];
};

void fdb_init(struct fdb *f, uint32_t aging);
int  fdb_add_static(struct fdb *f, const uint8_t *mac, int port);
int  fdb_lookup(struct fdb *f, const uint8_t *mac, uint32_t now);
void fdb_learn(struct fdb *f, const uint8_t *mac, int port, uint32_t now);
int  fdb_count(struct fdb *f, uint32_t now);

static inline int mac_is_multicast(const uint8_t *mac)
{
	return mac[0] & 1;
}

#endif
