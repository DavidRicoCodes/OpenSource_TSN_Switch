/* SPDX-License-Identifier: GPL-2.0 */
#ifndef TSN_NETDEV_H
#define TSN_NETDEV_H

#include <stdint.h>

struct bpf_object;

struct xdp_prog {
	struct bpf_object *obj;
	int prog_fd;
	int xsks_fd;
	int port_map_fd;
	int cfg_fd;
};

int  xdp_prog_load(struct xdp_prog *xp, const char *path, uint32_t flags);
void xdp_prog_close(struct xdp_prog *xp);

/* mode: XDP_MODE_* from config.h. Returns the mode used or -errno. */
int  xdp_attach(int ifindex, int prog_fd, int mode);
void xdp_detach(int ifindex, int mode);

/* Link speed in Mbit/s from sysfs, 0 if unknown. */
int64_t netdev_speed_mbps(const char *ifname);

/*
 * Turn off 802.1Q tag stripping/insertion offloads so the VLAN tag (and so
 * the PCP) stays in the frame that XDP sees. Returns 0 if the tag is in-band.
 */
int  netdev_disable_vlan_offload(const char *ifname);
int  netdev_rx_queues(const char *ifname);

/* A switch port must accept frames for every MAC address. */
int  netdev_set_promisc(const char *ifname, int on, int *was_on);

#endif
