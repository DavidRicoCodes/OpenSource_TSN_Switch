// SPDX-License-Identifier: GPL-2.0
/*
 * XDP front-end of the TSN switch.
 *
 * One program is attached to every switch port. It steers each frame to the
 * AF_XDP socket of its ingress port; all switching and 802.1Qbv scheduling
 * happens in user space. Frames that belong to the local control plane
 * (IEEE 802.1 link-local addresses such as gPTP, LLDP, STP, and PTP over
 * Ethernet) are passed to the kernel so ptp4l / lldpd keep working on the
 * switch ports.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../src/common.h"

#ifndef ETH_P_1588
#define ETH_P_1588 0x88F7
#endif
#ifndef ETH_P_LLDP
#define ETH_P_LLDP 0x88CC
#endif

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, TSN_MAX_PORTS * TSN_MAX_QUEUES);
	__uint(key_size, sizeof(__u32));   /* XSKMAP does not accept BTF types */
	__uint(value_size, sizeof(__u32));
} xsks_map SEC(".maps");

/* ifindex -> switch port number */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, TSN_MAX_PORTS);
	__type(key, __u32);
	__type(value, __u32);
} port_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct tsn_bpf_cfg);
} cfg_map SEC(".maps");

struct vlan_hdr_ {
	__be16 tci;
	__be16 proto;
};

static __always_inline int is_ctrl_frame(void *data, void *data_end)
{
	struct ethhdr *eth = data;
	__u16 proto;

	if ((void *)(eth + 1) > data_end)
		return 0;

	/* 01:80:C2:00:00:0X must never be forwarded by an 802.1Q bridge. */
	if (eth->h_dest[0] == 0x01 && eth->h_dest[1] == 0x80 && eth->h_dest[2] == 0xC2 &&
	    eth->h_dest[3] == 0x00 && eth->h_dest[4] == 0x00 && (eth->h_dest[5] & 0xF0) == 0)
		return 1;

	proto = eth->h_proto;
	if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {
		struct vlan_hdr_ *vh = (void *)(eth + 1);
		if ((void *)(vh + 1) > data_end)
			return 0;
		proto = vh->proto;
	}
	return proto == bpf_htons(ETH_P_1588) || proto == bpf_htons(ETH_P_LLDP);
}

SEC("xdp")
int tsn_xdp(struct xdp_md *ctx)
{
	__u32 ifindex = ctx->ingress_ifindex;
	__u32 qid = ctx->rx_queue_index;
	__u32 zero = 0;
	__u32 *port;
	struct tsn_bpf_cfg *cfg;

	port = bpf_map_lookup_elem(&port_map, &ifindex);
	if (!port || qid >= TSN_MAX_QUEUES)
		return XDP_PASS;

	cfg = bpf_map_lookup_elem(&cfg_map, &zero);
	if (cfg && (cfg->flags & TSN_BPF_F_PASS_CTRL) &&
	    is_ctrl_frame((void *)(long)ctx->data, (void *)(long)ctx->data_end))
		return XDP_PASS;

	/* Falls back to XDP_PASS if no socket is bound to this queue. */
	return bpf_redirect_map(&xsks_map, *port * TSN_MAX_QUEUES + qid, XDP_PASS);
}

char _license[] SEC("license") = "GPL";
