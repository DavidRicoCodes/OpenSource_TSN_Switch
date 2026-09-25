// SPDX-License-Identifier: GPL-2.0
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/ethtool.h>
#include <linux/if_link.h>
#include <linux/sockios.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "config.h"
#include "netdev.h"

/* bpf_xdp_attach() appeared in libbpf 0.8, bpf_set_link_xdp_fd() left in 1.0. */
#if defined(LIBBPF_MAJOR_VERSION) && (LIBBPF_MAJOR_VERSION > 0 || LIBBPF_MINOR_VERSION >= 8)
#define HAVE_BPF_XDP_ATTACH 1
#endif

int xdp_prog_load(struct xdp_prog *xp, const char *path, uint32_t flags)
{
	struct bpf_program *prog;
	struct tsn_bpf_cfg cfg = { .flags = flags };
	uint32_t zero = 0;
	int err;

	memset(xp, 0, sizeof(*xp));
	xp->obj = bpf_object__open_file(path, NULL);
	err = libbpf_get_error(xp->obj);
	if (err || !xp->obj) {
		xp->obj = NULL;
		fprintf(stderr, "cannot open BPF object %s: %s\n", path, strerror(err ? -err : errno));
		return -1;
	}
	if ((err = bpf_object__load(xp->obj))) {
		fprintf(stderr, "cannot load BPF object %s: %s\n", path, strerror(-err));
		return -1;
	}
	prog = bpf_object__find_program_by_name(xp->obj, "tsn_xdp");
	if (!prog) {
		fprintf(stderr, "program tsn_xdp not found in %s\n", path);
		return -1;
	}
	xp->prog_fd = bpf_program__fd(prog);
	xp->xsks_fd = bpf_object__find_map_fd_by_name(xp->obj, "xsks_map");
	xp->port_map_fd = bpf_object__find_map_fd_by_name(xp->obj, "port_map");
	xp->cfg_fd = bpf_object__find_map_fd_by_name(xp->obj, "cfg_map");
	if (xp->prog_fd < 0 || xp->xsks_fd < 0 || xp->port_map_fd < 0 || xp->cfg_fd < 0) {
		fprintf(stderr, "BPF object %s is missing maps\n", path);
		return -1;
	}
	if (bpf_map_update_elem(xp->cfg_fd, &zero, &cfg, 0)) {
		fprintf(stderr, "cannot configure XDP program: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

void xdp_prog_close(struct xdp_prog *xp)
{
	if (xp->obj)
		bpf_object__close(xp->obj);
	memset(xp, 0, sizeof(*xp));
}

static int set_xdp_fd(int ifindex, int fd, uint32_t flags)
{
#ifdef HAVE_BPF_XDP_ATTACH
	if (fd < 0)
		return bpf_xdp_detach(ifindex, flags, NULL);
	return bpf_xdp_attach(ifindex, fd, flags, NULL);
#else
	return bpf_set_link_xdp_fd(ifindex, fd, flags);
#endif
}

int xdp_attach(int ifindex, int prog_fd, int mode)
{
	int err;

	/* Clear leftovers of a previous run in either mode. */
	set_xdp_fd(ifindex, -1, XDP_FLAGS_DRV_MODE);
	set_xdp_fd(ifindex, -1, XDP_FLAGS_SKB_MODE);

	if (mode != XDP_MODE_SKB) {
		err = set_xdp_fd(ifindex, prog_fd, XDP_FLAGS_DRV_MODE);
		if (!err)
			return XDP_MODE_NATIVE;
		if (mode == XDP_MODE_NATIVE)
			return err < 0 ? err : -EINVAL;
	}
	err = set_xdp_fd(ifindex, prog_fd, XDP_FLAGS_SKB_MODE);
	if (!err)
		return XDP_MODE_SKB;
	return err < 0 ? err : -EINVAL;
}

void xdp_detach(int ifindex, int mode)
{
	set_xdp_fd(ifindex, -1, mode == XDP_MODE_SKB ? XDP_FLAGS_SKB_MODE : XDP_FLAGS_DRV_MODE);
}

int64_t netdev_speed_mbps(const char *ifname)
{
	char path[128];
	long long v = 0;
	FILE *f;

	snprintf(path, sizeof(path), "/sys/class/net/%s/speed", ifname);
	f = fopen(path, "r");
	if (!f)
		return 0;
	if (fscanf(f, "%lld", &v) != 1 || v <= 0)
		v = 0;
	fclose(f);
	return v;
}

int netdev_rx_queues(const char *ifname)
{
	char path[128];
	struct dirent *d;
	int n = 0;
	DIR *dir;

	snprintf(path, sizeof(path), "/sys/class/net/%s/queues", ifname);
	dir = opendir(path);
	if (!dir)
		return -1;
	while ((d = readdir(dir)))
		n += !strncmp(d->d_name, "rx-", 3);
	closedir(dir);
	return n;
}

static int ethtool_flags(int fd, const char *ifname, uint32_t cmd, uint32_t *data)
{
	struct ethtool_value ev = { .cmd = cmd, .data = *data };
	struct ifreq ifr = {0};

	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
	ifr.ifr_data = (void *)&ev;
	if (ioctl(fd, SIOCETHTOOL, &ifr))
		return -errno;
	*data = ev.data;
	return 0;
}

int netdev_disable_vlan_offload(const char *ifname)
{
	const uint32_t vlan = ETH_FLAG_RXVLAN | ETH_FLAG_TXVLAN;
	uint32_t flags = 0;
	int fd, err;

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;
	err = ethtool_flags(fd, ifname, ETHTOOL_GFLAGS, &flags);
	if (!err && (flags & vlan)) {
		flags &= ~vlan;
		err = ethtool_flags(fd, ifname, ETHTOOL_SFLAGS, &flags);
		if (!err) {
			flags = 0;
			err = ethtool_flags(fd, ifname, ETHTOOL_GFLAGS, &flags);
			if (!err && (flags & ETH_FLAG_RXVLAN))
				err = -EOPNOTSUPP;
		}
	}
	close(fd);
	return err;
}

int netdev_set_promisc(const char *ifname, int on, int *was_on)
{
	struct ifreq ifr = {0};
	int fd, err = 0;

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
	if (ioctl(fd, SIOCGIFFLAGS, &ifr)) {
		err = -errno;
		goto out;
	}
	if (was_on)
		*was_on = !!(ifr.ifr_flags & IFF_PROMISC);
	if (!!(ifr.ifr_flags & IFF_PROMISC) != !!on) {
		ifr.ifr_flags = on ? ifr.ifr_flags | IFF_PROMISC : ifr.ifr_flags & ~IFF_PROMISC;
		if (ioctl(fd, SIOCSIFFLAGS, &ifr))
			err = -errno;
	}
out:
	close(fd);
	return err;
}
