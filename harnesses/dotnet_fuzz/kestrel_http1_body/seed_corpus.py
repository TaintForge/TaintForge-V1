#!/usr/bin/env python3
from pathlib import Path
import sys


SEEDS = {
    "content-length": (
        b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\ntest"
    ),
    "content-length-pipeline": (
        b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\ntest"
        b"GET /next HTTP/1.1\r\nHost: localhost\r\n\r\n"
    ),
    "duplicate-content-length": (
        b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n"
        b"Content-Length: 4\r\n\r\ntest"
    ),
    "conflicting-content-length": (
        b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n"
        b"Content-Length: 5\r\n\r\ntestx"
    ),
    "chunked": (
        b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"4\r\ntest\r\n0\r\n\r\n"
    ),
    "chunked-extension-trailer": (
        b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n"
        b"Trailer: X-End\r\n\r\n4;foo=bar\r\ntest\r\n0\r\nX-End: yes\r\n\r\n"
    ),
    "chunked-pipeline": (
        b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"1\r\nx\r\n0\r\n\r\nGET /next HTTP/1.1\r\nHost: localhost\r\n\r\n"
    ),
    "content-length-and-chunked": (
        b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n"
        b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
    ),
    "transfer-coding-chain": (
        b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: gzip, chunked\r\n\r\n"
        b"0\r\n\r\n"
    ),
    "malformed-chunk-suffix": (
        b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"1\r\nx\n0\r\n\r\n"
    ),
    "oversized-chunk-prefix": (
        b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n"
        b"80000000\r\n"
    ),
    "expect-continue": (
        b"POST / HTTP/1.1\r\nHost: localhost\r\nExpect: 100-continue\r\n"
        b"Content-Length: 4\r\n\r\ntest"
    ),
}


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} OUTPUT_DIR", file=sys.stderr)
        return 2

    output = Path(sys.argv[1])
    output.mkdir(parents=True, exist_ok=True)
    for name, payload in SEEDS.items():
        (output / name).write_bytes(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
