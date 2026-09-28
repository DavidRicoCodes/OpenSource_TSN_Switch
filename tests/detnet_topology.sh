#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Links between the three DetNet routers of tests/conf/detnet (on top of the
# host veths created by veth_topology.sh):
#   dn-r1b <-> dn-r2a   (path A, R1 -> R2)
#   dn-r2b <-> dn-r3a   (path A, R2 -> R3)
#   dn-r1c <-> dn-r3b   (path B, R1 -> R3)
#
#   detnet_topology.sh up|down
set -e
PAIRS="dn-r1b:dn-r2a dn-r2b:dn-r3a dn-r1c:dn-r3b"

down() {
	for p in $PAIRS; do ip link del ${p%%:*} 2>/dev/null || true; done
}

up() {
	for p in $PAIRS; do
		a=${p%%:*} b=${p##*:}
		ip link add $a type veth peer name $b
		for i in $a $b; do
			sysctl -qw net.ipv6.conf.$i.disable_ipv6=1
			ethtool -K $i txvlan off rxvlan off >/dev/null
			ip link set $i up
		done
	done
}

case ${1:-up} in
up) down; up ;;
down) down ;;
*) echo "usage: $0 up|down"; exit 1 ;;
esac
