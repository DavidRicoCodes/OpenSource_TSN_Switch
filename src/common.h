/* SPDX-License-Identifier: GPL-2.0 */
#ifndef TSN_COMMON_H
#define TSN_COMMON_H

#include <linux/types.h>

/* Shared between user space and the XDP program. */
#define TSN_MAX_PORTS      16
#define TSN_MAX_QUEUES     16  /* HW RX queues per port addressable by the XSKMAP */
#define TSN_NUM_TC         8   /* 802.1Q traffic classes */
#define TSN_MAX_GCL        256 /* max gate control list entries per port */

#define TSN_BPF_F_PASS_CTRL (1u << 0) /* hand link-local / PTP frames to the kernel */

struct tsn_bpf_cfg {
	__u32 flags;
};

#ifndef __bpf__
#include <stdint.h>
#include <stdatomic.h>

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define CACHELINE   64

/* Statistics are written by exactly one thread and read by the stats thread. */
typedef _Atomic uint64_t stat_t;
#define STAT_ADD(s, v) atomic_store_explicit(&(s), atomic_load_explicit(&(s), memory_order_relaxed) + (v), memory_order_relaxed)
#define STAT_INC(s)    STAT_ADD(s, 1)
#define STAT_GET(s)    atomic_load_explicit(&(s), memory_order_relaxed)

#define ETH_HLEN_      14
#define ETH_P_8021Q_   0x8100
#define ETH_P_8021AD_  0x88A8

#endif /* __bpf__ */
#endif
