#!/usr/bin/env python3
from pathlib import Path
import sys


SEEDS = {
    "basic-get": b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
    # Cover every fast-path method recognized by HttpUtilities.GetKnownMethod.  The
    # long-running AFL queue reached GET/POST/OPTIONS/CONNECT but had not synthesized
    # any of these five methods or the custom-method fallback.
    "method-put": b"PUT /resource HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
    "method-delete": b"DELETE /resource HTTP/1.1\r\nHost: localhost\r\n\r\n",
    "method-head": b"HEAD /resource HTTP/1.1\r\nHost: localhost\r\n\r\n",
    "method-trace": b"TRACE /resource HTTP/1.1\r\nHost: localhost\r\n\r\n",
    "method-patch": b"PATCH /resource HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
    "method-custom": b"PROPFIND /resource HTTP/1.1\r\nHost: localhost\r\n\r\n",
    "query-percent": b"GET /a%2fb?q=x%20y HTTP/1.1\r\nHost: localhost\r\nX-A: b\r\n\r\n",
    "absolute-form": b"GET http://localhost/a?b=c HTTP/1.1\r\nHost: localhost\r\n\r\n",
    "asterisk": b"OPTIONS * HTTP/1.1\r\nHost: localhost\r\n\r\n",
    "connect": b"CONNECT localhost:443 HTTP/1.1\r\nHost: localhost:443\r\n\r\n",
    "unknown-version": b"GET / HTTP/2.0\r\nHost: localhost\r\n\r\n",
    "tls-on-http": b"\x16\x03\x01\x00\x00\n",
    "nul-request-line": b"GET /\x00",
    "lf-only": b"GET / HTTP/1.1\nHost: localhost\nX-Test: value\n\n",
    "whitespace": b"GET  /space  HTTP/1.1\r\nHost:\tlocalhost\t\r\nX-Empty:\r\n\r\n",
    # ParseMultiSpanHeader switches from stackalloc to ArrayPool above 256 bytes.
    "large-header": b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Large: " + (b"A" * 300) + b"\r\n\r\n",
    "content-length": b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\ntest",
    "chunked": b"POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    "invalid-cr": b"GET / HTTP/1.1\r\nHost: localhost\rX: y\r\n\r\n",
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
