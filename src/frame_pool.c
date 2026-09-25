// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include "frame_pool.h"

int frame_pool_init(struct frame_pool *fp, uint64_t nframes, uint32_t frame_size, int hugepages)
{
	size_t len = nframes * frame_size;
	int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE;

	memset(fp, 0, sizeof(*fp));
	fp->frame_shift = __builtin_ctz(frame_size);
	fp->nframes = nframes;

	if (hugepages) {
		fp->area = mmap(NULL, len, PROT_READ | PROT_WRITE, flags | MAP_HUGETLB, -1, 0);
		if (fp->area == MAP_FAILED)
			fprintf(stderr, "warning: hugepage UMEM allocation failed (%s), using 4K pages\n",
				strerror(errno));
	}
	if (!hugepages || fp->area == MAP_FAILED)
		fp->area = mmap(NULL, len, PROT_READ | PROT_WRITE, flags, -1, 0);
	if (fp->area == MAP_FAILED) {
		fp->area = NULL;
		return -errno;
	}

	fp->stack = calloc(nframes, sizeof(uint64_t));
	fp->ref = calloc(nframes, sizeof(*fp->ref));
	if (!fp->stack || !fp->ref)
		return -ENOMEM;

	/* Push in reverse so the first allocations get the lowest addresses. */
	for (uint64_t i = 0; i < nframes; i++)
		fp->stack[i] = (nframes - 1 - i) << fp->frame_shift;
	fp->top = nframes;

	pthread_spin_init(&fp->lock, PTHREAD_PROCESS_PRIVATE);
	return 0;
}

void frame_pool_destroy(struct frame_pool *fp)
{
	if (fp->area)
		munmap(fp->area, fp->nframes << fp->frame_shift);
	free(fp->stack);
	free((void *)fp->ref);
	pthread_spin_destroy(&fp->lock);
	memset(fp, 0, sizeof(*fp));
}

uint64_t frame_pool_free_count(struct frame_pool *fp)
{
	pthread_spin_lock(&fp->lock);
	uint64_t n = fp->top;
	pthread_spin_unlock(&fp->lock);
	return n;
}
