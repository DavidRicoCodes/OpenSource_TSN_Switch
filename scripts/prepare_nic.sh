#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Prepare physical NICs to be switch ports:
#   - a single combined queue, so every frame reaches the AF_XDP socket on queue 0
#   - VLAN offloads off, so the 802.1Q tag (PCP) stays in the frame
#   (tsn-switch itself enables promiscuous mode while it runs)
#
#   sudo scripts/prepare_nic.sh enp1s0f0 enp1s0f1 [...]
set -e
[ $# -gt 0 ] || { echo "usage: $0 <ifname>..."; exit 1; }

for ifc in "$@"; do
	echo "== $ifc"
	ethtool -L "$ifc" combined 1 2>/dev/null || ethtool -L "$ifc" rx 1 tx 1 2>/dev/null ||
		echo "   could not set 1 queue (check 'ethtool -l $ifc')"
	ethtool -K "$ifc" rxvlan off txvlan off 2>/dev/null || echo "   could not disable VLAN offload"
	ethtool -K "$ifc" rx-vlan-filter off 2>/dev/null || true
	ip link set "$ifc" up
	ethtool -l "$ifc" 2>/dev/null | awk '/Current/{c=1} c&&/Combined/{print "   queues: " $2; exit}'
done
