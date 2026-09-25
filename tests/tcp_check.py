#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Bulk TCP transfer through the switch; the receiver verifies a SHA-256.

  tcp_check.py server PORT            prints "<bytes> <sha256>" when done
  tcp_check.py client HOST PORT MB    prints "<bytes> <sha256> <Mbit/s>"
"""
import hashlib
import random
import socket
import sys
import time


def server(port):
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("0.0.0.0", port))
    ls.listen(1)
    ls.settimeout(30)
    c, _ = ls.accept()
    h = hashlib.sha256()
    n = 0
    while True:
        b = c.recv(1 << 16)
        if not b:
            break
        h.update(b)
        n += len(b)
    print(n, h.hexdigest(), flush=True)


def client(host, port, mb):
    rnd = random.Random(1234)
    chunk = bytes(rnd.getrandbits(8) for _ in range(1 << 16))
    h = hashlib.sha256()
    s = socket.create_connection((host, port), timeout=30)
    t0 = time.monotonic()
    total = mb << 20
    sent = 0
    while sent < total:
        b = chunk[: min(len(chunk), total - sent)]
        s.sendall(b)
        h.update(b)
        sent += len(b)
    s.shutdown(socket.SHUT_WR)
    s.recv(1)
    dt = time.monotonic() - t0
    print(sent, h.hexdigest(), round(sent * 8 / dt / 1e6, 1), flush=True)


if __name__ == "__main__":
    if sys.argv[1] == "server":
        server(int(sys.argv[2]))
    else:
        client(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))
