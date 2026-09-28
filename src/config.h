/* SPDX-License-Identifier: GPL-2.0 */
#ifndef TSN_CONFIG_H
#define TSN_CONFIG_H

#include <stdint.h>
#include <net/if.h>
#include "common.h"
#include "classify.h"
#include "gcl.h"

enum xdp_mode_cfg { XDP_MODE_AUTO, XDP_MODE_NATIVE, XDP_MODE_SKB };
enum tri_cfg { TRI_AUTO = -1, TRI_OFF = 0, TRI_ON = 1 };

/* Token bucket of one traffic class (asynchronous traffic shaping). */
struct ats_cfg {
	int enabled;
	uint64_t rate_bps;        /* committed rate, bits per second */
	uint64_t burst_bytes;     /* bucket size */
};

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
	struct ats_cfg ats[TSN_NUM_TC];
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
	char detnet_path[512];    /* DetNet flow table, "" = no DetNet */
	int bridging;             /* 0: only DetNet flows and port= rules are forwarded */

	/* [pcp-map] */
	uint8_t pcp_to_tc[8];

	int nports;
	struct port_cfg port[TSN_MAX_PORTS];

	int nstatic;
	struct static_fdb fdb_static[256];

	/* [classify] */
	struct cls_table cls;
};

int config_load(struct switch_cfg *c, const char *path);
void config_dump(const struct switch_cfg *c);
const char *clock_name(int clock_id);

char *cfg_trim(char *s);
int cfg_parse_bool(const char *v, int *out);
int cfg_parse_u64(const char *v, uint64_t *out);
int cfg_parse_duration(const char *v, uint64_t *out);
int cfg_parse_mac(const char *v, uint8_t *mac);
int cfg_parse_prefix(const char *v, uint32_t *addr, uint32_t *mask);
int cfg_port_by_name(const struct switch_cfg *c, const char *name);
int cfg_parse_match(const struct switch_cfg *c, const char *text, struct cls_rule *r,
		    char *err, size_t errlen);

#endif
