#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""
Traffic generator / sink for testing the TSN switch (no dependencies).

  send     emit test streams round robin (802.1Q-tagged or untagged,
           raw EtherType 0x88B5 or IPv4/UDP)
  recv     capture test frames with kernel RX timestamps into a JSON file
  analyze  check captured arrival times / counts / rates

Every stream has a label (default: its PCP) carried in the payload together
with a sequence number: ... "TSNT" [label:u8] [seq:u32] [padding]. The
analyzer options that take a PCP refer to this label.
"""
import argparse
import json
import socket
import struct
import sys
import time
from collections import Counter, defaultdict

ETH_P_ALL = 0x0003
ETH_P_TEST = 0x88B5
MAGIC = b"TSNT"
SO_TIMESTAMPNS = 35
SCM_TIMESTAMPNS = SO_TIMESTAMPNS


def mac_bytes(s):
    return bytes(int(x, 16) for x in s.split(":"))


def parse_duration(s):
    s = s.strip()
    for suffix, mul in (("ns", 1), ("us", 1e3), ("ms", 1e6), ("s", 1e9)):
        if s.endswith(suffix):
            return int(float(s[: -len(suffix)]) * mul)
    return int(s)


def ip_checksum(hdr):
    total = sum(struct.unpack("!%dH" % (len(hdr) // 2), hdr))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def build_frame(a, dst, src, pcp, vid, label, dport, dscp):
    """Returns (frame, offset of the sequence number)."""
    eth = dst + src
    if not a.untagged:
        eth += struct.pack("!HH", 0x8100, (pcp << 13) | (vid & 0xFFF))
    body = MAGIC + struct.pack("!BI", label, 0)
    if dport is None:
        frame = eth + struct.pack("!H", ETH_P_TEST) + body
        seq_off = len(eth) + 2 + 5
    else:
        pad = max(0, a.size - (len(eth) + 2 + 20 + 8 + len(body)))
        payload = body + bytes(pad)
        udp = struct.pack("!HHHH", a.sport, dport, 8 + len(payload), 0)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, dscp << 2, 20 + len(udp) + len(payload), 0, 0,
                         64, 17, 0, socket.inet_aton(a.sip), socket.inet_aton(a.dip))
        ip = ip[:10] + struct.pack("!H", ip_checksum(ip)) + ip[12:]
        frame = eth + struct.pack("!H", 0x0800) + ip + udp + payload
        seq_off = len(eth) + 2 + 20 + 8 + 5
    if len(frame) < a.size:
        frame += bytes(a.size - len(frame))
    return frame, seq_off


def ints(v):
    return [int(x) for x in v.split(",")] if v else None


def cmd_send(a):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((a.iface, 0))
    dst, src = mac_bytes(a.dst), mac_bytes(a.src)
    lists = {"pcp": ints(a.pcp), "vid": ints(a.vid), "label": ints(a.label),
             "udp": ints(a.udp), "dscp": ints(a.dscp)}
    n = max(len(v) for v in lists.values() if v)
    pick = lambda name, k, dflt: lists[name][k % len(lists[name])] if lists[name] else dflt
    streams = []
    for k in range(n):
        pcp = pick("pcp", k, 0)
        f, off = build_frame(a, dst, src, pcp, pick("vid", k, 100), pick("label", k, pcp),
                             pick("udp", k, None), pick("dscp", k, 0))
        streams.append((pick("label", k, pcp), bytearray(f), off))
    seq = [0] * n
    interval = 1e9 / a.rate
    t_end = time.monotonic_ns() + int(a.duration * 1e9)
    nxt = time.monotonic_ns()
    sent = 0
    i = 0
    while True:
        now = time.monotonic_ns()
        if now >= t_end:
            break
        if now < nxt:
            continue
        k = i % n
        _, f, off = streams[k]
        struct.pack_into("!I", f, off, seq[k])
        try:
            s.send(f)
            seq[k] += 1
            sent += 1
        except BlockingIOError:
            pass
        i += 1
        nxt += interval
    per = Counter()
    for (label, _, _), c in zip(streams, seq):
        per[str(label)] += c
    print(json.dumps({"sent": sent, "per_label": dict(per)}))


def find_payload(data):
    """Offset of the TSNT magic in a test frame, or None."""
    off = 12
    et = struct.unpack_from("!H", data, off)[0]
    if et in (0x8100, 0x88A8):
        off += 4
        et = struct.unpack_from("!H", data, off)[0]
    off += 2
    if et == 0x0800 and len(data) >= off + 28 and data[off + 9] == 17:
        udp = off + (data[off] & 0x0F) * 4
        off = udp + 8
        # DetNet MPLS-in-UDP: skip S-label + d-CW and look inside the tunnel.
        if struct.unpack_from("!H", data, udp + 2)[0] == 6635 and len(data) >= off + 36:
            off += 8
            if data[off] >> 4 == 4 and data[off + 9] == 17:
                off += (data[off] & 0x0F) * 4 + 8
    elif et != ETH_P_TEST:
        return None
    return off if data[off: off + 4] == MAGIC else None


def cmd_recv(a):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((a.iface, 0))
    s.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 24)
    s.settimeout(0.2)
    out = []
    t_end = time.monotonic() + a.duration
    while time.monotonic() < t_end:
        try:
            data, anc, _flags, addr = s.recvmsg(4096, socket.CMSG_SPACE(16))
        except socket.timeout:
            continue
        if addr[2] == socket.PACKET_OUTGOING or len(data) < 18:
            continue
        off = find_payload(data)
        if off is None:
            continue
        label, seq = struct.unpack_from("!BI", data, off + 4)
        pcp_tag = data[14] >> 5 if struct.unpack_from("!H", data, 12)[0] in (0x8100, 0x88A8) else None
        ts = None
        for lvl, typ, val in anc:
            if lvl == socket.SOL_SOCKET and typ == SCM_TIMESTAMPNS:
                sec, nsec = struct.unpack("qq", val[:16])
                ts = sec * 1_000_000_000 + nsec
        out.append([label, seq, ts, len(data), pcp_tag])
    with open(a.out, "w") as f:
        json.dump(out, f)
    print(json.dumps({"received": len(out), "per_label": dict(Counter(str(r[0]) for r in out))}))


def cmd_analyze(a):
    """
    --window PCP:START-END (offsets inside the cycle, may repeat) defines when
    each PCP is allowed to arrive. Frames outside [START-tol, END+tol] fail.
    --max-per-cycle checks how many frames of a PCP fit in one cycle.
    --never PCP asserts that a PCP never arrived.
    """
    with open(a.file) as f:
        rows = json.load(f)
    cycle = parse_duration(a.cycle) if a.cycle else 1
    base = parse_duration(a.base)
    tol = parse_duration(a.tolerance)
    windows = defaultdict(list)
    for w in a.window or []:
        pcp, span = w.split(":")
        st, en = span.split("-")
        windows[int(pcp)].append((parse_duration(st), parse_duration(en)))

    ok = True
    report = {}
    by_pcp = defaultdict(list)
    for pcp, seq, ts, ln, tag in rows:
        by_pcp[pcp].append((seq, ts))

    for pcp, items in sorted(by_pcp.items()):
        phases = [((ts - base) % cycle) for _, ts in items]
        r = {"frames": len(items)}
        seqs = [s for s, _ in items]
        r["reordered"] = sum(1 for x, y in zip(seqs, seqs[1:]) if y < x)
        r["duplicates"] = len(seqs) - len(set(seqs))
        if a.no_dups and r["duplicates"]:
            ok = False
        if pcp in windows:
            bad = 0
            worst = 0
            for ph in phases:
                inside = False
                dist = cycle
                for st, en in windows[pcp]:
                    if st - tol <= ph < en + tol:
                        inside = True
                        break
                    # distance outside of the window, wrapping around the cycle
                    d = min((st - ph) % cycle, (ph - en) % cycle)
                    dist = min(dist, d)
                if not inside:
                    bad += 1
                    worst = max(worst, dist)
            r["outside_window"] = bad
            r["worst_violation_ns"] = worst
            r["phase_min_us"] = round(min(phases) / 1e3, 1) if phases else None
            r["phase_max_us"] = round(max(phases) / 1e3, 1) if phases else None
            if bad:
                ok = False
        if r["reordered"] and not a.allow_reorder:
            ok = False
        report[str(pcp)] = r

    for spec in a.max_per_cycle or []:
        pcp, mx = (int(x) for x in spec.split(":"))
        cnt = Counter((ts - base) // cycle for _, ts in by_pcp.get(pcp, []))
        worst = max(cnt.values()) if cnt else 0
        report.setdefault(str(pcp), {})["max_per_cycle"] = worst
        if worst > mx:
            ok = False

    for pcp in a.never or []:
        n = len(by_pcp.get(pcp, []))
        report.setdefault(str(pcp), {})["frames"] = n
        if n:
            ok = False

    for pcp in a.expect or []:
        if not by_pcp.get(pcp):
            report.setdefault(str(pcp), {})["frames"] = 0
            ok = False

    for spec in a.rate or []:
        pcp, lo, hi = spec.split(":")
        items = sorted((ts, ln) for (p, _, ts, ln, _) in rows if p == int(pcp))
        mbps = 0.0
        if len(items) > 1:
            mbps = sum(ln for _, ln in items[1:]) * 8 / (items[-1][0] - items[0][0]) * 1e3
        report.setdefault(pcp, {})["rate_mbps"] = round(mbps, 3)
        if not float(lo) <= mbps <= float(hi):
            ok = False

    for spec in a.count or []:
        pcp, lo, hi = (int(x) for x in spec.split(":"))
        n = len(by_pcp.get(pcp, []))
        report.setdefault(str(pcp), {})["expected_count"] = [lo, hi]
        if not lo <= n <= hi:
            ok = False

    print(json.dumps(report, indent=1))
    print("PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("send")
    p.add_argument("--iface", required=True)
    p.add_argument("--dst", required=True)
    p.add_argument("--src", required=True)
    p.add_argument("--pcp", default="0", help="comma separated list; one stream per entry, round robin")
    p.add_argument("--vid", default="100", help="VLAN ID per stream (list, cycled)")
    p.add_argument("--label", help="payload label per stream (default: its PCP)")
    p.add_argument("--untagged", action="store_true", help="no 802.1Q tag")
    p.add_argument("--udp", help="send IPv4/UDP to these destination ports (one per stream)")
    p.add_argument("--dscp", help="IPv4 DSCP per stream")
    p.add_argument("--sip", default="10.10.0.1")
    p.add_argument("--dip", default="10.10.0.2")
    p.add_argument("--sport", type=int, default=4000)
    p.add_argument("--size", type=int, default=128)
    p.add_argument("--rate", type=float, default=1000, help="frames per second (total)")
    p.add_argument("--duration", type=float, default=2)

    p = sub.add_parser("recv")
    p.add_argument("--iface", required=True)
    p.add_argument("--duration", type=float, default=3)
    p.add_argument("--out", required=True)

    p = sub.add_parser("analyze")
    p.add_argument("file")
    p.add_argument("--cycle")
    p.add_argument("--base", default="0")
    p.add_argument("--tolerance", default="100us")
    p.add_argument("--window", action="append")
    p.add_argument("--max-per-cycle", action="append")
    p.add_argument("--never", type=int, action="append")
    p.add_argument("--expect", type=int, action="append")
    p.add_argument("--count", action="append", help="PCP:MIN:MAX frames")
    p.add_argument("--no-dups", action="store_true", help="fail on repeated sequence numbers")
    p.add_argument("--allow-reorder", action="store_true", help="do not fail on out-of-order arrivals")
    p.add_argument("--rate", action="append", help="PCP:MIN:MAX Mbit/s (frame bytes, first to last)")

    a = ap.parse_args()
    {"send": cmd_send, "recv": cmd_recv, "analyze": cmd_analyze}[a.cmd](a)


if __name__ == "__main__":
    main()
