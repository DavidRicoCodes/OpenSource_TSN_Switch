// SPDX-License-Identifier: GPL-2.0
/*
 * INI-style configuration:
 *
 *   [global]        key = value
 *   [pcp-map]       <pcp> = <tc>
 *   [port <name>]   key = value, sched-entry = S <hex-gates> <interval>
 *   [fdb]           static = <mac> <port-name>
 *
 * Durations accept ns (default), us, ms and s suffixes. '#' and ';' start
 * comments. See the config/ directory for complete examples.
 */
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include "config.h"

#define ERR(...) do { fprintf(stderr, "%s:%d: ", path, lineno); fprintf(stderr, __VA_ARGS__); \
		      fputc('\n', stderr); return -1; } while (0)

static char *trim(char *s)
{
	while (isspace((unsigned char)*s))
		s++;
	char *e = s + strlen(s);
	while (e > s && isspace((unsigned char)e[-1]))
		*--e = 0;
	return s;
}

static int parse_bool(const char *v, int *out)
{
	if (!strcasecmp(v, "yes") || !strcasecmp(v, "on") || !strcasecmp(v, "true") || !strcmp(v, "1"))
		*out = 1;
	else if (!strcasecmp(v, "no") || !strcasecmp(v, "off") || !strcasecmp(v, "false") || !strcmp(v, "0"))
		*out = 0;
	else
		return -1;
	return 0;
}

static int parse_u64(const char *v, uint64_t *out)
{
	char *end;
	errno = 0;
	unsigned long long x = strtoull(v, &end, 0);
	if (errno || end == v || *trim(end))
		return -1;
	*out = x;
	return 0;
}

static int parse_i64(const char *v, int64_t *out)
{
	char *end;
	errno = 0;
	long long x = strtoll(v, &end, 0);
	if (errno || end == v || *trim(end))
		return -1;
	*out = x;
	return 0;
}

/* "250us", "1ms", "1000000" (ns) ... */
static int parse_duration(const char *v, uint64_t *out)
{
	char *end;
	errno = 0;
	double x = strtod(v, &end);
	if (errno || end == v || x < 0)
		return -1;
	end = trim(end);
	double mul = 1;
	if (!*end || !strcmp(end, "ns"))
		mul = 1;
	else if (!strcmp(end, "us"))
		mul = 1e3;
	else if (!strcmp(end, "ms"))
		mul = 1e6;
	else if (!strcmp(end, "s"))
		mul = 1e9;
	else
		return -1;
	*out = (uint64_t)(x * mul + 0.5);
	return 0;
}

static int parse_mac(const char *s, uint8_t *mac)
{
	unsigned int b[6];
	char tail;
	if (sscanf(s, "%x:%x:%x:%x:%x:%x%c", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5], &tail) != 6)
		return -1;
	for (int i = 0; i < 6; i++) {
		if (b[i] > 0xff)
			return -1;
		mac[i] = b[i];
	}
	return 0;
}

const char *clock_name(int clock_id)
{
	switch (clock_id) {
	case CLOCK_TAI: return "tai";
	case CLOCK_REALTIME: return "realtime";
	case CLOCK_MONOTONIC: return "monotonic";
	}
	return "?";
}

static void set_defaults(struct switch_cfg *c)
{
	memset(c, 0, sizeof(*c));
	c->clock_id = CLOCK_TAI;
	c->frame_size = 2048;
	c->frames = 32768;
	c->queue_depth = 512;
	c->ring_size = 2048;
	c->zerocopy = TRI_AUTO;
	c->xdp_mode = XDP_MODE_AUTO;
	c->need_wakeup = 1;
	c->pass_ctrl = 1;
	c->disable_vlan_offload = 1;
	c->fdb_aging = 300;
	c->stats_interval = 1;
	for (int i = 0; i < 8; i++)
		c->pcp_to_tc[i] = i;
}

static void port_defaults(struct port_cfg *p, const char *name)
{
	memset(p, 0, sizeof(*p));
	snprintf(p->name, sizeof(p->name), "%s", name);
	p->cpu = -1;
	p->link_mbps = -1;
	p->guard_band = 1;
	p->lookahead_ns = 20000;
}

static int is_pow2(uint64_t x)
{
	return x && !(x & (x - 1));
}

int config_load(struct switch_cfg *c, const char *path)
{
	enum { S_NONE, S_GLOBAL, S_PCP, S_PORT, S_FDB } sec = S_NONE;
	char static_port[256][32];
	struct port_cfg *p = NULL;
	char line[512];
	int lineno = 0;
	FILE *f;

	set_defaults(c);
	f = fopen(path, "r");
	if (!f) {
		fprintf(stderr, "cannot open %s: %s\n", path, strerror(errno));
		return -1;
	}

	while (fgets(line, sizeof(line), f)) {
		lineno++;
		char *s = line;
		char *hash = strpbrk(s, "#;");
		if (hash)
			*hash = 0;
		s = trim(s);
		if (!*s)
			continue;

		if (*s == '[') {
			char *end = strchr(s, ']');
			if (!end)
				ERR("unterminated section header");
			*end = 0;
			char *name = trim(s + 1);
			if (!strcasecmp(name, "global")) {
				sec = S_GLOBAL;
			} else if (!strcasecmp(name, "pcp-map")) {
				sec = S_PCP;
			} else if (!strcasecmp(name, "fdb")) {
				sec = S_FDB;
			} else if (!strncasecmp(name, "port", 4) && isspace((unsigned char)name[4])) {
				char *pname = trim(name + 4);
				if (c->nports == TSN_MAX_PORTS)
					ERR("too many ports (max %d)", TSN_MAX_PORTS);
				for (int i = 0; i < c->nports; i++)
					if (!strcmp(c->port[i].name, pname))
						ERR("duplicate port '%s'", pname);
				p = &c->port[c->nports++];
				port_defaults(p, pname);
				sec = S_PORT;
			} else {
				ERR("unknown section [%s]", name);
			}
			continue;
		}

		char *eq = strchr(s, '=');
		if (!eq)
			ERR("expected key = value");
		*eq = 0;
		char *k = trim(s), *v = trim(eq + 1);
		uint64_t u;
		int64_t i64;

		switch (sec) {
		case S_NONE:
			ERR("key outside of a section");

		case S_GLOBAL:
			if (!strcmp(k, "clock")) {
				if (!strcasecmp(v, "tai")) c->clock_id = CLOCK_TAI;
				else if (!strcasecmp(v, "realtime")) c->clock_id = CLOCK_REALTIME;
				else if (!strcasecmp(v, "monotonic")) c->clock_id = CLOCK_MONOTONIC;
				else ERR("clock must be tai, realtime or monotonic");
			} else if (!strcmp(k, "frame_size")) {
				if (parse_u64(v, &u) || !is_pow2(u) || u < 2048 || u > 4096)
					ERR("frame_size must be 2048 or 4096");
				c->frame_size = u;
			} else if (!strcmp(k, "frames")) {
				if (parse_u64(v, &u) || u < 1024 || u > (1u << 22))
					ERR("frames must be between 1024 and 4194304");
				c->frames = u;
			} else if (!strcmp(k, "queue_depth")) {
				if (parse_u64(v, &u) || !is_pow2(u) || u > 65536)
					ERR("queue_depth must be a power of two <= 65536");
				c->queue_depth = u;
			} else if (!strcmp(k, "ring_size")) {
				if (parse_u64(v, &u) || !is_pow2(u) || u < 64 || u > 32768)
					ERR("ring_size must be a power of two in [64, 32768]");
				c->ring_size = u;
			} else if (!strcmp(k, "zerocopy")) {
				int b;
				if (!strcasecmp(v, "auto")) c->zerocopy = TRI_AUTO;
				else if (!parse_bool(v, &b)) c->zerocopy = b;
				else ERR("zerocopy must be auto, yes or no");
			} else if (!strcmp(k, "xdp_mode")) {
				if (!strcasecmp(v, "auto")) c->xdp_mode = XDP_MODE_AUTO;
				else if (!strcasecmp(v, "native") || !strcasecmp(v, "drv")) c->xdp_mode = XDP_MODE_NATIVE;
				else if (!strcasecmp(v, "skb") || !strcasecmp(v, "generic")) c->xdp_mode = XDP_MODE_SKB;
				else ERR("xdp_mode must be auto, native or skb");
			} else if (!strcmp(k, "need_wakeup")) {
				if (parse_bool(v, &c->need_wakeup)) ERR("bad boolean");
			} else if (!strcmp(k, "hugepages")) {
				if (parse_bool(v, &c->hugepages)) ERR("bad boolean");
			} else if (!strcmp(k, "pass_ctrl_to_kernel")) {
				if (parse_bool(v, &c->pass_ctrl)) ERR("bad boolean");
			} else if (!strcmp(k, "disable_vlan_offload")) {
				if (parse_bool(v, &c->disable_vlan_offload)) ERR("bad boolean");
			} else if (!strcmp(k, "fdb_aging")) {
				if (parse_u64(v, &u) || u > 1000000) ERR("bad fdb_aging");
				c->fdb_aging = u;
			} else if (!strcmp(k, "stats_interval")) {
				if (parse_u64(v, &u) || u > 3600) ERR("bad stats_interval");
				c->stats_interval = u;
			} else if (!strcmp(k, "bpf_object")) {
				snprintf(c->bpf_obj, sizeof(c->bpf_obj), "%s", v);
			} else {
				ERR("unknown global key '%s'", k);
			}
			break;

		case S_PCP:
			if (parse_u64(k, &u) || u > 7)
				ERR("pcp must be 0..7");
			{
				uint64_t tc;
				if (parse_u64(v, &tc) || tc >= TSN_NUM_TC)
					ERR("traffic class must be 0..%d", TSN_NUM_TC - 1);
				c->pcp_to_tc[u] = tc;
			}
			break;

		case S_PORT:
			if (!strcmp(k, "ifname")) {
				if (strlen(v) >= IF_NAMESIZE) ERR("interface name too long");
				snprintf(p->ifname, sizeof(p->ifname), "%s", v);
			} else if (!strcmp(k, "queue")) {
				if (parse_u64(v, &u) || u >= TSN_MAX_QUEUES)
					ERR("queue must be < %d", TSN_MAX_QUEUES);
				p->queue = u;
			} else if (!strcmp(k, "cpu")) {
				if (parse_i64(v, &i64) || i64 < -1 || i64 > 4095) ERR("bad cpu");
				p->cpu = i64;
			} else if (!strcmp(k, "default_pcp")) {
				if (parse_u64(v, &u) || u > 7) ERR("default_pcp must be 0..7");
				p->default_pcp = u;
			} else if (!strcmp(k, "link_speed")) {
				if (!strcasecmp(v, "auto")) p->link_mbps = -1;
				else if (parse_i64(v, &i64) || i64 < 0) ERR("link_speed must be auto or Mbit/s");
				else p->link_mbps = i64;
			} else if (!strcmp(k, "guard_band")) {
				if (parse_bool(v, &p->guard_band)) ERR("bad boolean");
			} else if (!strcmp(k, "tx_lookahead")) {
				if (parse_duration(v, &p->lookahead_ns)) ERR("bad duration");
			} else if (!strcmp(k, "base_time")) {
				if (parse_i64(v, &i64)) ERR("base_time must be an integer (ns)");
				p->gcl.base_time = i64;
			} else if (!strcmp(k, "cycle_time")) {
				if (parse_duration(v, &u) || u == 0) ERR("bad cycle_time");
				p->gcl.cycle_time = u;
			} else if (!strcmp(k, "sched-entry")) {
				char cmd[8], gates[16], interval[32], extra;
				if (sscanf(v, "%7s %15s %31s %c", cmd, gates, interval, &extra) != 3)
					ERR("sched-entry = S <gate-mask-hex> <interval>");
				if (strcmp(cmd, "S") && strcmp(cmd, "s"))
					ERR("only 'S' (set gates) entries are supported");
				char *end;
				unsigned long m = strtoul(gates, &end, 16);
				if (*end || m > 0xff)
					ERR("gate mask must be hex 00..ff");
				if (p->gcl.n == TSN_MAX_GCL)
					ERR("too many sched-entry lines (max %d)", TSN_MAX_GCL);
				struct gcl_entry *e = &p->gcl.e[p->gcl.n++];
				e->gates = m;
				if (parse_duration(interval, &e->interval) || !e->interval)
					ERR("bad interval '%s'", interval);
			} else {
				ERR("unknown port key '%s'", k);
			}
			break;

		case S_FDB:
			if (strcmp(k, "static"))
				ERR("only 'static = <mac> <port>' is allowed in [fdb]");
			{
				char mac[32], pname[32];
				if (c->nstatic == 256)
					ERR("too many static entries");
				if (sscanf(v, "%31s %31s", mac, pname) != 2 ||
				    parse_mac(mac, c->fdb_static[c->nstatic].mac))
					ERR("static = aa:bb:cc:dd:ee:ff <port-name>");
				snprintf(static_port[c->nstatic], sizeof(static_port[0]), "%s", pname);
				c->nstatic++;
			}
			break;
		}
	}
	fclose(f);

	lineno = 0;
	if (c->nports < 2)
		ERR("at least two [port] sections are required");
	for (int i = 0; i < c->nports; i++) {
		struct port_cfg *pp = &c->port[i];
		char err[128];
		if (!pp->ifname[0])
			ERR("port '%s' has no ifname", pp->name);
		for (int j = 0; j < i; j++)
			if (!strcmp(c->port[j].ifname, pp->ifname) && c->port[j].queue == pp->queue)
				ERR("ports '%s' and '%s' use the same interface/queue", c->port[j].name, pp->name);
		if (gcl_finalize(&pp->gcl, err, sizeof(err)))
			ERR("port '%s': %s", pp->name, err);
	}
	for (int i = 0; i < c->nstatic; i++) {
		c->fdb_static[i].port = -1;
		for (int j = 0; j < c->nports; j++)
			if (!strcmp(c->port[j].name, static_port[i]))
				c->fdb_static[i].port = j;
		if (c->fdb_static[i].port < 0)
			ERR("static FDB entry references unknown port '%s'", static_port[i]);
	}
	/* Worst case: every fill and TX ring full and every egress queue full. */
	uint64_t need = (uint64_t)c->nports * (c->ring_size * 3 + TSN_NUM_TC * c->queue_depth);
	if (need > c->frames)
		fprintf(stderr, "warning: frames = %u, but rings and queues can hold %llu; under "
			"congestion the pool can run dry and ports will drop on receive\n",
			c->frames, (unsigned long long)need);
	return 0;
}

void config_dump(const struct switch_cfg *c)
{
	printf("clock=%s frames=%u frame_size=%u queue_depth=%u ring=%u\n",
	       clock_name(c->clock_id), c->frames, c->frame_size, c->queue_depth, c->ring_size);
	printf("pcp->tc:");
	for (int i = 0; i < 8; i++)
		printf(" %d->%d", i, c->pcp_to_tc[i]);
	printf("\n");
	for (int i = 0; i < c->nports; i++) {
		const struct port_cfg *p = &c->port[i];
		printf("port %d '%s' if=%s q=%u cpu=%d default_pcp=%u link=%lld Mb/s guard_band=%s\n",
		       i, p->name, p->ifname, p->queue, p->cpu, p->default_pcp,
		       (long long)p->link_mbps, p->guard_band ? "on" : "off");
		if (!p->gcl.n) {
			printf("    gates: always open (strict priority only)\n");
			continue;
		}
		printf("    base_time=%lld cycle_time=%llu ns\n",
		       (long long)p->gcl.base_time, (unsigned long long)p->gcl.cycle_time);
		for (int j = 0; j < p->gcl.n; j++)
			printf("    [%2d] +%10llu  gates=%02x  for %llu ns\n", j,
			       (unsigned long long)p->gcl.e[j].start, p->gcl.e[j].gates,
			       (unsigned long long)p->gcl.e[j].interval);
	}
}
