#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""
Traffic generator / sink for testing the TSN switch (no dependencies).

  send     emit 802.1Q-tagged test frames with the given PCPs, round robin
  recv     capture test frames with kernel RX timestamps into a JSON file
  analyze  check captured arrival times against a gate schedule

Test frame: [dst][src][0x8100][PCP|VID][0x88B5]["TSNT"][pcp:u8][seq:u32][pad]
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


def build_frame(dst, src, pcp, vid, seq, size):
    tci = (pcp << 13) | (vid & 0xFFF)
    hdr = dst + src + struct.pack("!HHH", 0x8100, tci, ETH_P_TEST)
    body = MAGIC + struct.pack("!BI", pcp, seq)
    frame = hdr + body
    if len(frame) < size:
        frame += bytes(size - len(frame))
    return frame


def cmd_send(a):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    s.bind((a.iface, 0))
    dst, src = mac_bytes(a.dst), mac_bytes(a.src)
    pcps = [int(x) for x in a.pcp.split(",")]
    frames = [build_frame(dst, src, p, a.vid, 0, a.size) for p in pcps]
    seq = [0] * len(pcps)
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
        k = i % len(pcps)
        f = bytearray(frames[k])
        struct.pack_into("!I", f, 23, seq[k])
        try:
            s.send(f)
            seq[k] += 1
            sent += 1
        except BlockingIOError:
            pass
        i += 1
        nxt += interval
    print(json.dumps({"sent": sent, "per_pcp": dict(zip(map(str, pcps), seq))}))


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
        if addr[2] == socket.PACKET_OUTGOING:
            continue
        off = 12
        et = struct.unpack_from("!H", data, off)[0]
        pcp_tag = None
        if et in (0x8100, 0x88A8):
            pcp_tag = data[14] >> 5
            off = 16
            et = struct.unpack_from("!H", data, off)[0]
        if et != ETH_P_TEST or data[off + 2: off + 6] != MAGIC:
            continue
        pcp, seq = struct.unpack_from("!BI", data, off + 6)
        ts = None
        for lvl, typ, val in anc:
            if lvl == socket.SOL_SOCKET and typ == SCM_TIMESTAMPNS:
                sec, nsec = struct.unpack("qq", val[:16])
                ts = sec * 1_000_000_000 + nsec
        out.append([pcp, seq, ts, len(data), pcp_tag])
    with open(a.out, "w") as f:
        json.dump(out, f)
    print(json.dumps({"received": len(out), "per_pcp": dict(Counter(str(r[0]) for r in out))}))


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
        if r["reordered"]:
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
    p.add_argument("--pcp", default="0", help="comma separated list, sent round robin")
    p.add_argument("--vid", type=int, default=100)
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

    a = ap.parse_args()
    {"send": cmd_send, "recv": cmd_recv, "analyze": cmd_analyze}[a.cmd](a)


if __name__ == "__main__":
    main()
