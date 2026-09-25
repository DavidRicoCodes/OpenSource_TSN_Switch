// SPDX-License-Identifier: GPL-2.0
#include <string.h>
#include "fdb.h"

#define KEY_STATIC 0x100

static inline uint64_t mac48(const uint8_t *m)
{
	return ((uint64_t)m[0] << 40) | ((uint64_t)m[1] << 32) | ((uint64_t)m[2] << 24) |
	       ((uint64_t)m[3] << 16) | ((uint64_t)m[4] << 8) | m[5];
}

static inline uint32_t bucket_of(uint64_t mac)
{
	uint64_t h = mac * 0x9E3779B97F4A7C15ull;
	return (uint32_t)(h >> 52) & (FDB_BUCKETS - 1);
}

static inline int slot_live(const struct fdb *f, uint64_t key, uint32_t seen, uint32_t now)
{
	if (!key)
		return 0;
	if ((key & KEY_STATIC) || f->aging == 0)
		return 1;
	return now - seen <= f->aging;
}

void fdb_init(struct fdb *f, uint32_t aging)
{
	memset(f, 0, sizeof(*f));
	f->aging = aging;
}

int fdb_add_static(struct fdb *f, const uint8_t *mac, int port)
{
	uint64_t m = mac48(mac);
	struct fdb_slot *b = f->slot[bucket_of(m)];

	for (int w = 0; w < FDB_WAYS; w++) {
		uint64_t k = atomic_load(&b[w].key);
		if (!k || (k >> 16) == m) {
			atomic_store(&b[w].key, (m << 16) | KEY_STATIC | (uint64_t)(port + 1));
			return 0;
		}
	}
	return -1;
}

int fdb_lookup(struct fdb *f, const uint8_t *mac, uint32_t now)
{
	uint64_t m = mac48(mac);
	struct fdb_slot *b = f->slot[bucket_of(m)];

	for (int w = 0; w < FDB_WAYS; w++) {
		uint64_t k = atomic_load_explicit(&b[w].key, memory_order_relaxed);
		if ((k >> 16) != m || !k)
			continue;
		uint32_t seen = atomic_load_explicit(&b[w].seen, memory_order_relaxed);
		if (!slot_live(f, k, seen, now))
			return -1;
		return (int)(k & 0xff) - 1;
	}
	return -1;
}

void fdb_learn(struct fdb *f, const uint8_t *mac, int port, uint32_t now)
{
	uint64_t m = mac48(mac);
	uint64_t want = (m << 16) | (uint64_t)(port + 1);
	struct fdb_slot *b = f->slot[bucket_of(m)];
	int victim = -1;
	uint32_t oldest = UINT32_MAX;

	for (int w = 0; w < FDB_WAYS; w++) {
		uint64_t k = atomic_load_explicit(&b[w].key, memory_order_relaxed);
		uint32_t seen = atomic_load_explicit(&b[w].seen, memory_order_relaxed);

		if (k && (k >> 16) == m) {
			if (k & KEY_STATIC)
				return;
			if (k != want)          /* station moved */
				atomic_store_explicit(&b[w].key, want, memory_order_relaxed);
			if (seen != now)        /* avoid dirtying the line on every frame */
				atomic_store_explicit(&b[w].seen, now, memory_order_relaxed);
			return;
		}
		if (k & KEY_STATIC)
			continue;
		if (!slot_live(f, k, seen, now)) {
			victim = w;
			oldest = 0;
		} else if (victim < 0 || (oldest && seen < oldest)) {
			victim = w;
			oldest = seen;
		}
	}
	if (victim < 0)
		return; /* bucket full of static entries */
	atomic_store_explicit(&b[victim].seen, now, memory_order_relaxed);
	atomic_store_explicit(&b[victim].key, want, memory_order_relaxed);
}

int fdb_count(struct fdb *f, uint32_t now)
{
	int n = 0;

	for (int i = 0; i < FDB_BUCKETS; i++)
		for (int w = 0; w < FDB_WAYS; w++)
			n += slot_live(f, atomic_load(&f->slot[i][w].key),
				       atomic_load(&f->slot[i][w].seen), now);
	return n;
}
