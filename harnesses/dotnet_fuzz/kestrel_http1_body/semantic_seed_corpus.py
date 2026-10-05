#!/usr/bin/env python3
from pathlib import Path
import sys


BODY_LENGTHS = (
    0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256,
    511, 512, 1023, 1024, 2047, 2048, 2049, 4095, 4096, 4097, 8191, 8192,
    8193, 16383, 16384, 16385,
)


def decision(
    framing: int,
    *,
    chunk: int = 0,
    pipeline: int = 0,
    length: int = 4,
    chunks: int = 2,
    extra: int = 0,
    method: int = 0,
    path: int = 0,
    app: int = 0,
    body: bytes = b"semantic-body-seed",
) -> bytes:
    try:
        length_selector = BODY_LENGTHS.index(length)
    except ValueError as error:
        raise ValueError(f"unsupported semantic body length: {length}") from error

    return bytes(
        (framing, chunk, pipeline, length_selector, chunks, extra, method, path, app)
    ) + body


SEEDS = {
    "cl-exact": decision(0),
    "cl-repeated-same": decision(1),
    "cl-repeated-conflict": decision(2),
    "cl-list-same": decision(3),
    "cl-list-conflict": decision(4),
    "te-chunked": decision(5),
    "te-repeated-final-chunked": decision(6),
    "te-chain-final-chunked": decision(7),
    "te-chain-final-gzip": decision(8),
    "cl-and-te": decision(9),
    "te-duplicate-chunked": decision(10),
    "cl-short": decision(11, pipeline=1),
    "cl-long": decision(12, pipeline=1),
    "te-identity": decision(13),
    "unframed-body": decision(14, pipeline=1),
    "cl-zero-with-body": decision(15, pipeline=1),
    "chunk-extension": decision(5, chunk=1, extra=4),
    "chunk-malformed-extension": decision(5, chunk=2, extra=4),
    "chunk-invalid-size": decision(5, chunk=3),
    "chunk-overflow-size": decision(5, chunk=4),
    "chunk-size-off-by-one": decision(5, chunk=5),
    "chunk-lf-data-terminator": decision(5, chunk=6),
    "chunk-missing-data-terminator": decision(5, chunk=7),
    "chunk-lf-final-terminator": decision(5, chunk=8),
    "chunk-missing-final-terminator": decision(5, chunk=9),
    "chunk-trailers": decision(5, chunk=10, extra=4),
    "chunk-malformed-trailers": decision(5, chunk=11, extra=4),
    "pipeline-get": decision(0, pipeline=1),
    "pipeline-post": decision(0, pipeline=2),
    "pipeline-options": decision(5, pipeline=3),
    "pipeline-partial": decision(5, pipeline=4),
    "pipeline-absolute": decision(5, pipeline=5),
    "expect-continue": decision(0, extra=1),
    "duplicate-host": decision(0, extra=2),
    "conflicting-host": decision(0, extra=3),
    "connection-keepalive": decision(5, extra=5),
    "te-trailers": decision(5, chunk=10, extra=6),
    "padded-header": decision(5, extra=7),
    "method-connect": decision(0, method=5),
    "method-custom": decision(5, method=7, path=5),
    "app-no-read-cl": decision(0, pipeline=1, app=1),
    "app-no-read-chunked": decision(5, chunk=10, pipeline=1, extra=4, app=1),
    "app-stream-one-cl": decision(0, pipeline=1, app=2),
    "app-stream-one-chunked": decision(5, pipeline=1, app=2),
    "app-pipe-one-examine-cl": decision(0, pipeline=1, app=3),
    "app-pipe-one-examine-chunked": decision(5, pipeline=1, app=3),
    "app-pipe-examine-cl": decision(0, pipeline=1, app=4),
    "app-pipe-examine-chunked": decision(5, pipeline=1, app=4),
}

# The socket transport asks for 2 KiB minimum allocations and the source-built pinned pool uses
# 4 KiB blocks. Seed exact/adjacent sizes for both content-length and chunked paths so AFL starts
# beyond the old 64-byte ceiling instead of having to discover every selector independently.
for boundary_length in (
    2047, 2048, 2049,
    4095, 4096, 4097,
    8191, 8192, 8193,
    16383, 16384, 16385,
):
    SEEDS[f"cl-boundary-{boundary_length}"] = decision(
        0,
        pipeline=1,
        length=boundary_length,
    )
    SEEDS[f"chunk-boundary-{boundary_length}"] = decision(
        5,
        chunk=0,
        pipeline=1,
        length=boundary_length,
        chunks=4,
    )
    SEEDS[f"cl-auto-drain-boundary-{boundary_length}"] = decision(
        0,
        pipeline=1,
        length=boundary_length,
        app=1,
    )
    SEEDS[f"chunk-partial-drain-boundary-{boundary_length}"] = decision(
        5,
        chunk=0,
        pipeline=1,
        length=boundary_length,
        chunks=4,
        app=3,
    )


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
