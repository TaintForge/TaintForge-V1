#!/usr/bin/env python3
"""Replay the isolated Kestrel LF-only header boundary differential on loopback."""

from __future__ import annotations

import socket


HOST = "127.0.0.1"
PORT = 5001


def request(payload: bytes) -> bytes:
    with socket.create_connection((HOST, PORT), timeout=2) as sock:
        sock.settimeout(2)
        sock.sendall(payload)
        response = sock.recv(4096)
    return response.split(b"\r\n", 1)[0]


def make_payload(padding: int) -> bytes:
    return (
        b"GET / HTTP/1.1\n"
        b"Host: x\n"
        b"X:"
        + (b"a" * padding)
        + b"\nt:\n\n"
    )


def main() -> int:
    baseline = request(b"GET / HTTP/1.1\nHost: x\nt:\n\n")
    before = request(make_payload(4067))
    crossing_lf = request(make_payload(4068))
    crossing_colon_lf = request(make_payload(4069))
    after = request(make_payload(4070))

    results = {
        "baseline": baseline,
        "before-boundary": before,
        "lf-crosses-boundary": crossing_lf,
        "colon-lf-cross-boundary": crossing_colon_lf,
        "after-boundary": after,
    }
    for name, status in results.items():
        print(f"{name}: {status.decode('ascii', errors='replace')}")

    expected_ok = b"HTTP/1.1 200 OK"
    expected_bad = b"HTTP/1.1 400 Bad Request"
    reproduced = (
        baseline == expected_ok
        and before == expected_ok
        and crossing_lf == expected_bad
        and crossing_colon_lf == expected_bad
        and after == expected_ok
    )
    print("PASS" if reproduced else "FAIL")
    return 0 if reproduced else 1


if __name__ == "__main__":
    raise SystemExit(main())
