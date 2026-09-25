// SPDX-License-Identifier: GPL-2.0
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include "xsk.h"

#ifndef SOL_XDP
#define SOL_XDP 283
#endif
#ifndef AF_XDP
#define AF_XDP 44
#endif

static int ring_mmap(struct xring *r, int fd, uint32_t size, const struct xdp_ring_offset *off,
		     size_t desc_size, off_t pgoff)
{
	r->map_len = off->desc + (size_t)size * desc_size;
	r->map = mmap(NULL, r->map_len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, pgoff);
	if (r->map == MAP_FAILED) {
		r->map = NULL;
		return -errno;
	}
	r->producer = (uint32_t *)((uint8_t *)r->map + off->producer);
	r->consumer = (uint32_t *)((uint8_t *)r->map + off->consumer);
	r->flags = (uint32_t *)((uint8_t *)r->map + off->flags);
	r->ring = (uint8_t *)r->map + off->desc;
	r->size = size;
	r->mask = size - 1;
	r->cached_prod = __atomic_load_n(r->producer, __ATOMIC_ACQUIRE);
	r->cached_cons = __atomic_load_n(r->consumer, __ATOMIC_ACQUIRE);
	return 0;
}

static void ring_unmap(struct xring *r)
{
	if (r->map)
		munmap(r->map, r->map_len);
	memset(r, 0, sizeof(*r));
}

int xsk_open(struct xsk *x, const char *ifname, int ifindex, uint32_t queue,
	     void *umem_area, uint64_t umem_len, uint32_t frame_size,
	     const struct xsk *primary, const struct xsk_opts *o)
{
	struct xdp_mmap_offsets off;
	socklen_t optlen = sizeof(off);
	struct sockaddr_xdp sxdp = {0};
	int err;

	(void)ifname;
	memset(x, 0, sizeof(*x));
	x->fd = socket(AF_XDP, SOCK_RAW | SOCK_CLOEXEC, 0);
	if (x->fd < 0)
		return -errno;

	if (!primary) {
		struct xdp_umem_reg reg = {
			.addr = (uint64_t)(uintptr_t)umem_area,
			.len = umem_len,
			.chunk_size = frame_size,
			.headroom = 0,
		};
		if (setsockopt(x->fd, SOL_XDP, XDP_UMEM_REG, &reg, sizeof(reg)))
			goto fail;
	}

	/*
	 * Every socket gets its own fill/completion ring: they belong to the
	 * (netdev, queue) the socket binds to, even when the UMEM is shared.
	 */
	if (setsockopt(x->fd, SOL_XDP, XDP_UMEM_FILL_RING, &o->fill_size, sizeof(o->fill_size)) ||
	    setsockopt(x->fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &o->comp_size, sizeof(o->comp_size)) ||
	    setsockopt(x->fd, SOL_XDP, XDP_RX_RING, &o->rx_size, sizeof(o->rx_size)) ||
	    setsockopt(x->fd, SOL_XDP, XDP_TX_RING, &o->tx_size, sizeof(o->tx_size)))
		goto fail;

	if (getsockopt(x->fd, SOL_XDP, XDP_MMAP_OFFSETS, &off, &optlen))
		goto fail;

	if ((err = ring_mmap(&x->fill, x->fd, o->fill_size, &off.fr, sizeof(uint64_t), XDP_UMEM_PGOFF_FILL_RING)) ||
	    (err = ring_mmap(&x->comp, x->fd, o->comp_size, &off.cr, sizeof(uint64_t), XDP_UMEM_PGOFF_COMPLETION_RING)) ||
	    (err = ring_mmap(&x->rx, x->fd, o->rx_size, &off.rx, sizeof(struct xdp_desc), XDP_PGOFF_RX_RING)) ||
	    (err = ring_mmap(&x->tx, x->fd, o->tx_size, &off.tx, sizeof(struct xdp_desc), XDP_PGOFF_TX_RING))) {
		errno = -err;
		goto fail;
	}

	sxdp.sxdp_family = AF_XDP;
	sxdp.sxdp_ifindex = ifindex;
	sxdp.sxdp_queue_id = queue;
	if (primary) {
		/* Copy/zero-copy and wakeup mode are inherited from the primary. */
		sxdp.sxdp_flags = XDP_SHARED_UMEM;
		sxdp.sxdp_shared_umem_fd = primary->fd;
		x->zerocopy = primary->zerocopy;
		x->need_wakeup = primary->need_wakeup;
	} else {
		sxdp.sxdp_flags = o->zerocopy ? XDP_ZEROCOPY : XDP_COPY;
		if (o->need_wakeup)
			sxdp.sxdp_flags |= XDP_USE_NEED_WAKEUP;
		x->zerocopy = o->zerocopy;
		x->need_wakeup = o->need_wakeup;
	}
	if (bind(x->fd, (struct sockaddr *)&sxdp, sizeof(sxdp)))
		goto fail;

	return 0;

fail:
	err = -errno;
	xsk_close(x);
	return err;
}

void xsk_close(struct xsk *x)
{
	ring_unmap(&x->rx);
	ring_unmap(&x->tx);
	ring_unmap(&x->fill);
	ring_unmap(&x->comp);
	if (x->fd >= 0)
		close(x->fd);
	x->fd = -1;
}

void xsk_kick_tx(struct xsk *x)
{
	/* Copy mode transmits only from sendto(); zero-copy only when asked to. */
	if (x->zerocopy && x->need_wakeup && !xring_needs_wakeup(&x->tx))
		return;
	int ret = sendto(x->fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
	(void)ret; /* EAGAIN/EBUSY/ENOBUFS just mean "try again later" */
}

void xsk_kick_rx(struct xsk *x)
{
	if (x->need_wakeup && xring_needs_wakeup(&x->fill)) {
		int ret = recvfrom(x->fd, NULL, 0, MSG_DONTWAIT, NULL, NULL);
		(void)ret;
	}
}
