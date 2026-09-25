#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Test topology: N hosts, each in its own network namespace, attached to the
# switch through a veth pair.
#
#     [ns tsn-h0] eth0 <--veth--> tsn-sw0 --+
#     [ns tsn-h1] eth0 <--veth--> tsn-sw1 --+-- tsn-switch (root namespace)
#     [ns tsn-h2] eth0 <--veth--> tsn-sw2 --+
#
# Host i: MAC 02:00:00:00:00:0i, IP 10.10.0.(i+1)/24
#
#   veth_topology.sh up [N]     (default N=3)
#   veth_topology.sh down [N]
set -e

ACTION=${1:-up}
N=${2:-3}

up() {
	for i in $(seq 0 $((N - 1))); do
		ns=tsn-h$i
		ip netns add $ns
		ip link add tsn-sw$i type veth peer name eth0 netns $ns
		ip -n $ns link set eth0 address 02:00:00:00:00:0$i
		ip -n $ns addr add 10.10.0.$((i + 1))/24 dev eth0
		ip -n $ns link set lo up
		ip -n $ns link set eth0 up
		ip link set tsn-sw$i up
		# AF_XDP never computes checksums: make the hosts' stacks do it.
		# Keep 802.1Q tags in-band so the switch can read the PCP.
		ip netns exec $ns ethtool -K eth0 tx off txvlan off rxvlan off >/dev/null
		ethtool -K tsn-sw$i txvlan off rxvlan off >/dev/null
		# No IPv6 autoconf chatter during the measurements.
		ip netns exec $ns sysctl -qw net.ipv6.conf.all.disable_ipv6=1
		sysctl -qw net.ipv6.conf.tsn-sw$i.disable_ipv6=1
	done
}

down() {
	for i in $(seq 0 $((N - 1))); do
		ip link del tsn-sw$i 2>/dev/null || true
		ip netns del tsn-h$i 2>/dev/null || true
	done
}

case $ACTION in
up) down; up ;;
down) down ;;
*) echo "usage: $0 up|down [N]"; exit 1 ;;
esac
