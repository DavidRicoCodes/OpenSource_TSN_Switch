# tsn-switch — an open source 802.1Qbv TSN switch on AF_XDP

`tsn-switch` turns a Linux box with several NICs into an Ethernet switch
that implements the IEEE 802.1Qbv **time-aware shaper** (TAS). Frames are
steered from the NIC into user space by a small XDP program and switched by
busy-polling threads over **AF_XDP** sockets that share one UMEM. That means
no kernel bridge, no qdisc and no packet copies in user space.

It is a C rewrite of the Go prototype (`asavie/xdp`) from the original
OpenSource_TSN_Switch work. It keeps the same idea (XDP + eBPF front end, user
space Qbv scheduler) and fixes the problems of the prototype:

| Go prototype | tsn-switch |
|---|---|
| queued slices pointed into UMEM frames that were recycled to the NIC, so frames could be overwritten | refcounted UMEM frames, zero-copy hand-off between ports |
| queues drained only when a new frame arrived | independent per-port scheduler, evaluated continuously |
| priority = `VLAN ID - 9`, gates rotated by a 10 s ticker | 802.1Q PCP → traffic class map, GCL with ns intervals, aligned to `base_time` |
| 2 ports, data races between goroutines | up to 16 ports, lock-free queues, one thread per port |

## Features

- **IEEE 802.1Q bridging**: MAC learning with aging, static entries,
  flooding of broadcast/multicast/unknown unicast, filtering of frames whose
  destination is on the ingress port.
- **8 traffic classes per egress port**, selected from the 802.1Q PCP
  (configurable PCP → TC map, per-port priority for untagged frames).
- **802.1Qbv gate control list per egress port**, the same model as
  `tc-taprio`: `base_time`, `cycle_time`, `sched-entry S <gates> <interval>`.
- **Strict priority** transmission selection among the open gates.
- **Guard band / link-rate model**: a frame is only started if it finishes
  on the wire before its gate closes, and only `tx_lookahead` of traffic is
  queued ahead of the wire, so a gate closing really stops the class.
- **PTP friendly**: gPTP / LLDP / STP (01:80:C2:00:00:0X) and EtherType
  0x88F7 frames go to the kernel, so `ptp4l` can run on the switch ports and
  CLOCK_TAI can be disciplined with `phc2sys`.
- Zero-copy AF_XDP when every port supports it (ixgbe, i40e, ice, igc, mlx5…),
  with automatic fallback to copy mode (veth, virtio, anything with XDP).
- Builds against libbpf 0.x or 1.x. The AF_XDP layer is self-contained, so no
  libxdp is needed.

## Architecture

```
 ingress port p0                                         egress port p1
 ───────────────                                         ──────────────
 NIC ─▶ XDP ─▶ AF_XDP RX ─▶ PCP → TC ─▶ FDB lookup ─┬─▶ [TC7 queue] ─┐
                                                    ├─▶ [ ...     ] ─┼─▶ GCL gates ─▶ strict priority ─▶ AF_XDP TX ─▶ NIC
                                                    └─▶ [TC0 queue] ─┘   (802.1Qbv)   + guard band

 all ports share one UMEM: only descriptors move between threads, frames are never copied
```

Every port thread busy-polls its own AF_XDP socket and does, in a loop:

1. reap TX completions (return frames to the pool),
2. receive, classify, learn, and enqueue each frame descriptor on the egress
   port's traffic-class queue (for a flood, on several queues with a refcount),
3. refill the fill ring,
4. evaluate its gate control list at "now" and transmit from the open classes,
   highest class first, subject to the link-rate model and the guard band.

Sources:

| file | purpose |
|---|---|
| `bpf/tsn_xdp.bpf.c` | XDP program: control frames to the kernel, everything else to the port's AF_XDP socket |
| `src/tsn_switch.c` | port threads, forwarding, Qbv transmission selection, setup, stats |
| `src/gcl.c` | gate control list evaluation (when does each gate close?) |
| `src/fdb.c` | lock-free learning MAC table |
| `src/mpsc.h` | bounded lock-free MPSC queue (one per egress port and TC) |
| `src/frame_pool.[ch]` | shared UMEM frame allocator with per-thread caches and refcounts |
| `src/xsk.[ch]` | minimal AF_XDP socket / ring implementation on the kernel UAPI |
| `src/config.c` | configuration parser |

## Requirements

- Linux ≥ 5.10 (AF_XDP UMEM shared across netdevs). Tested on 6.8.
- clang/llvm (BPF target), gcc, libbpf-dev, libelf-dev, zlib.
  On Ubuntu/Debian:

  ```sh
  sudo apt install clang llvm libbpf-dev libelf-dev zlib1g-dev pkg-config
  ```
- Root privileges (or CAP_NET_ADMIN + CAP_BPF + CAP_IPC_LOCK).

## Build

```sh
make            # -> build/tsn-switch, build/tsn_xdp.bpf.o
```

## Quick start on veth (no hardware needed)

```sh
sudo tests/veth_topology.sh up 3          # 3 hosts in namespaces tsn-h0..2
sudo build/tsn-switch -c tests/conf/qbv.conf
# in another terminal
sudo ip netns exec tsn-h0 ping 10.10.0.2
sudo tests/veth_topology.sh down 3
```

## Running on real NICs

```sh
sudo scripts/prepare_nic.sh enp1s0f0 enp1s0f1   # 1 queue, VLAN offload off
cp config/example.conf my.conf                  # set ifname, cpu, schedule
sudo build/tsn-switch -c my.conf
```

- Each port serves one RX queue. Run `ethtool -L <if> combined 1` (the
  script does it), or steer the traffic to the configured `queue`.
- Pin every port thread to its own isolated core (`cpu = N`, plus
  `isolcpus=` / `nohz_full=` on the kernel command line for the best
  jitter). Threads busy-poll, so each port uses 100% of one core.
- For a network-wide schedule, synchronize the NIC clocks with gPTP and
  CLOCK_TAI with the PHC, and keep `clock = tai`:

  ```sh
  sudo ptp4l -i enp1s0f0 -f /usr/share/doc/linuxptp/configs/gPTP.cfg &
  sudo phc2sys -s enp1s0f0 -c CLOCK_REALTIME --step_threshold=1 -w &   # also sets the TAI offset
  ```

  With `pass_ctrl_to_kernel = yes` (default) ptp4l keeps receiving its
  frames while the switch is running.

The whole configuration format is documented in
[`config/example.conf`](config/example.conf). A gate control list looks like
this:

```ini
[port p1]
ifname = enp1s0f1
link_speed = 1000        ; Mbit/s, "auto" reads it from sysfs
guard_band = yes
base_time = 0            ; ns in the configured clock
cycle_time = 1ms
sched-entry = S 80 200us ; TC7 only (scheduled traffic)
sched-entry = S 7f 800us ; TC0..6 (best effort)
```

`tsn-switch -n -c my.conf` parses the file, prints the normalized schedule
and exits.

## Tests

`make test` (or `sudo tests/run_tests.sh [name...]`) builds a 3-host veth
topology and runs:

| test | checks |
|---|---|
| `connectivity` | ping between every pair of hosts (ARP flooding + learning) |
| `learning` | learned unicast goes only to its port; no leak to the third host |
| `link_local` | 01:80:C2:00:00:0E (gPTP/LLDP) is never forwarded |
| `tcp` | 200 MiB TCP transfer, SHA-256 verified end to end |
| `qbv_windows` | 10 ms cycle: PCP 7 arrives only in [0, 3) ms, PCP 0 only in [3, 10) ms, PCP 3 (gate never open) never |
| `guard_band` | 100 Mbit/s port, 150 µs TC0 window, 1400 B frames: at most 1 frame per cycle, all inside the window |
| `strict_priority` | a 10 Mbit/s port oversubscribed by PCP 7 + PCP 0: all PCP 7 frames delivered, PCP 0 gets the rest |

Every test also checks that the switch exits cleanly with all UMEM frames
accounted for. The timing tests use kernel RX timestamps on the receiving
host. On veth the measured arrival phases stay within a few µs of the
configured windows. `tests/tsn_traffic.py` (send / recv / analyze) can be
used on its own for measurements on real hardware.

Sample output of the Qbv test (phase = arrival time inside the 10 ms cycle):

```
PCP 0: 6000 frames, phase 3000.6 .. 9823.1 us  (window 3 .. 10 ms)
PCP 7: 6000 frames, phase    0.6 .. 2656.3 us  (window 0 .. 3 ms)
PCP 3: 0 frames                                 (gate never open)
```

## Limitations

- The shaper runs in software. Gate edges are respected to within the
  polling loop and NIC queueing (µs scale with pinned, isolated cores and
  zero-copy), not the ns precision of a hardware TAS. With `link_speed = 0`
  (unknown rate) there is no pacing, so frames already handed to the NIC may
  still leave after their gate closed.
- Not implemented: frame preemption (802.1Qbu/802.3br), per-stream
  filtering and policing (802.1Qci), credit-based shaper (802.1Qav), FRER
  (802.1CB), VLAN membership / tag rewriting, and runtime schedule updates
  (restart to change the GCL).
- One RX queue per port.

## License

GPL-2.0, see [LICENSE](LICENSE).
