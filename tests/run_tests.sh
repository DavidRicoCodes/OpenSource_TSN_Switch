#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# End-to-end tests of tsn-switch on a veth topology (see veth_topology.sh).
# Needs root. Usage: sudo tests/run_tests.sh [test-name...]
#
# Timing checks use kernel RX timestamps on the receiving host, so they
# measure the switch's egress schedule plus the (small) veth latency.
set -u
cd "$(dirname "$0")/.."

SW=build/tsn-switch
TT="python3 tests/tsn_traffic.py"
WORK=$(mktemp -d /tmp/tsn-test.XXXXXX)
MAC0=02:00:00:00:00:00
MAC1=02:00:00:00:00:01
MAC2=02:00:00:00:00:02
SW_PID=
PASSED=0
FAILED=0
FAILED_NAMES=()

[ "$(id -u)" = 0 ] || { echo "run as root"; exit 1; }
[ -x $SW ] || { echo "build first (make)"; exit 1; }

cleanup() {
	[ -n "$SW_PID" ] && kill -INT $SW_PID 2>/dev/null && wait $SW_PID 2>/dev/null
	tests/veth_topology.sh down 3
	rm -rf "$WORK"
}
trap cleanup EXIT

h() { local n=$1; shift; ip netns exec tsn-h$n "$@"; }

start_switch() {
	$SW -c "$1" >"$WORK/switch.log" 2>&1 &
	SW_PID=$!
	for _ in $(seq 50); do
		grep -q "running" "$WORK/switch.log" && return 0
		kill -0 $SW_PID 2>/dev/null || break
		sleep 0.1
	done
	echo "switch failed to start:"; cat "$WORK/switch.log"
	return 1
}

# Stops the switch and checks it exits cleanly without leaking UMEM frames.
stop_switch() {
	kill -INT $SW_PID
	wait $SW_PID
	local rc=$?
	SW_PID=
	if [ $rc != 0 ] || ! grep -q "no leaks" "$WORK/switch.log"; then
		echo "  switch exit code $rc"; tail -20 "$WORK/switch.log"
		return 1
	fi
}

# Resolve ARP and let the switch learn every host.
learn_all() {
	h 0 ping -c 1 -W 1 10.10.0.2 >/dev/null
	h 0 ping -c 1 -W 1 10.10.0.3 >/dev/null
	h 1 ping -c 1 -W 1 10.10.0.3 >/dev/null
}

# Background capture on host $1 for $2 seconds into $3; wait_captures joins them.
CAPS=()
capture() { h $1 $TT recv --iface eth0 --duration $2 --out "$3" >/dev/null & CAPS+=($!); }
wait_captures() { wait "${CAPS[@]}"; CAPS=(); }

result() {
	if [ "$2" = 0 ]; then
		echo "[PASS] $1"; PASSED=$((PASSED + 1))
	else
		echo "[FAIL] $1"; FAILED=$((FAILED + 1)); FAILED_NAMES+=("$1")
	fi
}

# ---------------------------------------------------------------- tests --

t_connectivity() {
	start_switch tests/conf/basic.conf || return 1
	local rc=0
	for pair in "0 10.10.0.2" "0 10.10.0.3" "1 10.10.0.3" "2 10.10.0.1"; do
		set -- $pair
		h $1 ping -c 5 -i 0.05 -W 1 $2 >"$WORK/ping" || { echo "  ping h$1 -> $2 failed"; rc=1; }
	done
	stop_switch || rc=1
	return $rc
}

t_learning() {
	start_switch tests/conf/basic.conf || return 1
	learn_all
	capture 1 3 "$WORK/h1.json"
	capture 2 3 "$WORK/h2.json"
	sleep 0.5
	h 0 $TT send --iface eth0 --src $MAC0 --dst $MAC1 --pcp 0 --rate 2000 --duration 1 >/dev/null
	wait_captures
	local rc=0
	$TT analyze "$WORK/h1.json" --count 0:2000:2000 >/dev/null || { echo "  h1 did not get all frames"; rc=1; }
	$TT analyze "$WORK/h2.json" --never 0 >/dev/null || { echo "  learned unicast leaked to h2"; rc=1; }
	stop_switch || rc=1
	return $rc
}

t_link_local() {
	# 01:80:C2:00:00:0E is the gPTP / LLDP address: must go to the local stack.
	start_switch tests/conf/basic.conf || return 1
	capture 1 2 "$WORK/h1.json"
	sleep 0.5
	h 0 $TT send --iface eth0 --src $MAC0 --dst 01:80:c2:00:00:0e --pcp 0 --rate 500 --duration 0.5 >/dev/null
	wait_captures
	local rc=0
	$TT analyze "$WORK/h1.json" --never 0 >/dev/null || { echo "  link-local frame was forwarded"; rc=1; }
	stop_switch || rc=1
	return $rc
}

t_tcp() {
	start_switch tests/conf/basic.conf || return 1
	h 1 python3 tests/tcp_check.py server 5001 >"$WORK/srv" &
	local srv=$!
	sleep 0.5
	h 0 python3 tests/tcp_check.py client 10.10.0.2 5001 200 >"$WORK/cli"
	wait $srv
	local rc=0
	read -r nb_s sha_s <"$WORK/srv"
	read -r nb_c sha_c mbps <"$WORK/cli"
	echo "  200 MiB TCP h0 -> h1: ${mbps} Mbit/s"
	[ "$sha_s" = "$sha_c" ] && [ "$nb_s" = "$nb_c" ] || { echo "  data mismatch"; rc=1; }
	stop_switch || rc=1
	return $rc
}

t_qbv_windows() {
	start_switch tests/conf/qbv.conf || return 1
	learn_all
	capture 1 5 "$WORK/h1.json"
	sleep 0.5
	h 0 $TT send --iface eth0 --src $MAC0 --dst $MAC1 --pcp 7,0,3 --rate 6000 --duration 3 >/dev/null
	wait_captures
	local rc=0
	$TT analyze "$WORK/h1.json" --cycle 10ms --tolerance 50us \
		--window 7:0-3ms --window 0:3ms-10ms --never 3 --count 7:6000:6000 --count 0:6000:6000 \
		>"$WORK/report" || { cat "$WORK/report"; rc=1; }
	grep -E '"phase_(min|max)_us"' "$WORK/report" | paste - - | sed 's/^/  /'
	stop_switch || rc=1
	return $rc
}

t_guard_band() {
	start_switch tests/conf/guard_band.conf || return 1
	learn_all
	capture 1 4 "$WORK/h1.json"
	sleep 0.5
	h 0 $TT send --iface eth0 --src $MAC0 --dst $MAC1 --pcp 0 --size 1400 --rate 3000 --duration 2 >/dev/null
	wait_captures
	local rc=0
	$TT analyze "$WORK/h1.json" --cycle 1ms --tolerance 30us --window 0:0-150us \
		--max-per-cycle 0:1 --expect 0 >"$WORK/report" || { cat "$WORK/report"; rc=1; }
	stop_switch || rc=1
	return $rc
}

t_strict_priority() {
	start_switch tests/conf/priority.conf || return 1
	learn_all
	capture 1 5 "$WORK/h1.json"
	sleep 0.5
	# 1200 frames/s of 1400 B = 13.7 Mbit/s offered to a 10 Mbit/s port.
	h 0 $TT send --iface eth0 --src $MAC0 --dst $MAC1 --pcp 7,0 --size 1400 --rate 1200 --duration 3 >/dev/null
	wait_captures
	local rc=0
	$TT analyze "$WORK/h1.json" --count 7:1800:1800 --count 0:1:1500 >"$WORK/report" || { cat "$WORK/report"; rc=1; }
	echo "  delivered: $(python3 -c "import json,collections;print(dict(collections.Counter(r[0] for r in json.load(open('$WORK/h1.json')))))") (pcp: frames, 1800 sent each)"
	stop_switch || rc=1
	return $rc
}

t_classify_l3() {
	# Untagged UDP/IP traffic: rules put port 5000 and DSCP EF into TC7.
	start_switch tests/conf/classify.conf || return 1
	learn_all
	capture 1 5 "$WORK/h1.json"
	sleep 0.5
	h 0 $TT send --iface eth0 --src $MAC0 --dst $MAC1 --untagged \
		--udp 5000,6000,6001 --dscp 0,0,46 --label 7,0,6 --rate 3000 --duration 3 >/dev/null
	wait_captures
	local rc=0
	$TT analyze "$WORK/h1.json" --cycle 10ms --tolerance 50us \
		--window 7:0-3ms --window 6:0-3ms --window 0:3ms-10ms \
		--count 7:3000:3000 --count 6:3000:3000 --count 0:3000:3000 \
		>"$WORK/report" || { cat "$WORK/report"; rc=1; }
	stop_switch || rc=1
	grep -q "hits=3000: ip_proto=udp dst_port=5000" "$WORK/switch.log" &&
		grep -q "hits=3000: in_port=p0 src_ip" "$WORK/switch.log" ||
		{ echo "  unexpected rule hit counters:"; grep "^rule" "$WORK/switch.log"; rc=1; }
	return $rc
}

t_vlan_port_map() {
	# VID 200 is mapped to p2 by a rule, even though the MAC belongs to h1.
	start_switch tests/conf/classify.conf || return 1
	learn_all
	capture 1 3 "$WORK/h1.json"
	capture 2 3 "$WORK/h2.json"
	sleep 0.5
	h 0 $TT send --iface eth0 --src $MAC0 --dst $MAC1 --pcp 0,0 --vid 100,200 --label 1,2 \
		--rate 2000 --duration 1 >/dev/null
	wait_captures
	local rc=0
	$TT analyze "$WORK/h1.json" --count 1:1000:1000 --never 2 >/dev/null ||
		{ echo "  h1 must get only VID 100"; rc=1; }
	$TT analyze "$WORK/h2.json" --count 2:1000:1000 --never 1 >/dev/null ||
		{ echo "  h2 must get only VID 200"; rc=1; }
	stop_switch || rc=1
	return $rc
}

t_ats() {
	start_switch tests/conf/ats.conf || return 1
	learn_all
	capture 1 5 "$WORK/h1.json"
	sleep 0.5
	# 8 Mbit/s offered per class; TC7 is shaped to 2 Mbit/s, TC0 is not shaped.
	h 0 $TT send --iface eth0 --src $MAC0 --dst $MAC1 --pcp 7,0 --size 1000 --rate 2000 --duration 3 >/dev/null
	wait_captures
	local rc=0
	$TT analyze "$WORK/h1.json" --rate 7:1.9:2.1 --count 0:3000:3000 >"$WORK/report" ||
		{ cat "$WORK/report"; rc=1; }
	echo "  TC7 shaped rate: $(python3 -c "import json;print(json.load(open('/dev/stdin'))['7']['rate_mbps'])" < <(head -n -1 "$WORK/report")) Mbit/s (bucket 2 Mbit/s)"
	stop_switch || rc=1
	return $rc
}

t_reload() {
	# Swap the two windows of the schedule with SIGHUP while traffic runs.
	cp tests/conf/qbv.conf "$WORK/reload.conf"
	start_switch "$WORK/reload.conf" || return 1
	learn_all
	local rc=0
	capture 1 3 "$WORK/before.json"
	sleep 0.3
	h 0 $TT send --iface eth0 --src $MAC0 --dst $MAC1 --pcp 7,0 --rate 4000 --duration 2 >/dev/null
	wait_captures
	sed -i 's/^sched-entry = S 80 3ms/sched-entry = S 01 3ms/; t; s/^sched-entry = S 01 7ms/sched-entry = S 80 7ms/' \
		"$WORK/reload.conf"
	kill -HUP $SW_PID
	sleep 1.5
	grep -q "new schedules" "$WORK/switch.log" || { echo "  no reload message"; rc=1; }
	capture 1 3 "$WORK/after.json"
	sleep 0.3
	h 0 $TT send --iface eth0 --src $MAC0 --dst $MAC1 --pcp 7,0 --rate 4000 --duration 2 >/dev/null
	wait_captures
	$TT analyze "$WORK/before.json" --cycle 10ms --tolerance 50us --window 7:0-3ms --window 0:3ms-10ms \
		--expect 7 --expect 0 >"$WORK/report" || { echo "  before reload:"; cat "$WORK/report"; rc=1; }
	$TT analyze "$WORK/after.json" --cycle 10ms --tolerance 50us --window 0:0-3ms --window 7:3ms-10ms \
		--expect 7 --expect 0 >"$WORK/report" || { echo "  after reload:"; cat "$WORK/report"; rc=1; }
	stop_switch || rc=1
	return $rc
}

ALL="connectivity learning link_local tcp qbv_windows guard_band strict_priority classify_l3 vlan_port_map ats reload"
TESTS=${*:-$ALL}

for t in $TESTS; do
	tests/veth_topology.sh up 3
	t_$t
	result "$t" $?
done

echo
echo "$PASSED passed, $FAILED failed ${FAILED_NAMES[*]:-}"
[ $FAILED = 0 ]
