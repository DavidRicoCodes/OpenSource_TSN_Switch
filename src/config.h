/* SPDX-License-Identifier: GPL-2.0 */
#ifndef TSN_CONFIG_H
#define TSN_CONFIG_H

#include <stdint.h>
#include <net/if.h>
#include "common.h"
#include "gcl.h"

enum xdp_mode_cfg { XDP_MODE_AUTO, XDP_MODE_NATIVE, XDP_MODE_SKB };
enum tri_cfg { TRI_AUTO = -1, TRI_OFF = 0, TRI_ON = 1 };

struct port_cfg {
	char name[32];
	char ifname[IF_NAMESIZE];
	uint32_t queue;
	int cpu;                  /* -1 = no pinning */
	uint8_t default_pcp;      /* priority of untagged frames */
	int64_t link_mbps;        /* -1 = read from sysfs, 0 = unknown/unlimited */
	int guard_band;
	uint64_t lookahead_ns;
	struct gcl gcl;
};

struct static_fdb {
	uint8_t mac[6];
	int port;
};

struct switch_cfg {
	/* [global] */
	int clock_id;
	uint32_t frame_size;
	uint32_t frames;
	uint32_t queue_depth;     /* per traffic class and egress port */
	uint32_t ring_size;
	int zerocopy;             /* enum tri_cfg */
	int xdp_mode;             /* enum xdp_mode_cfg */
	int need_wakeup;
	int hugepages;
	int pass_ctrl;            /* PTP / link-local frames go to the kernel */
	int disable_vlan_offload;
	uint32_t fdb_aging;
	uint32_t stats_interval;  /* seconds, 0 = off */
	char bpf_obj[256];

	/* [pcp-map] */
	uint8_t pcp_to_tc[8];

	int nports;
	struct port_cfg port[TSN_MAX_PORTS];

	int nstatic;
	struct static_fdb fdb_static[256];
};

int config_load(struct switch_cfg *c, const char *path);
void config_dump(const struct switch_cfg *c);
const char *clock_name(int clock_id);

#endif
