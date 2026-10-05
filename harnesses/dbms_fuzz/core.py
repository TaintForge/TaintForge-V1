#!/usr/bin/env python3
"""Shared local-only primitives for DBMS wire and SQL fuzzing."""

from __future__ import annotations

import base64
import glob
import hashlib
import ipaddress
import json
import random
import re
import socket
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable


CRASH_RE = re.compile(
    r"addresssanitizer|undefinedbehaviorsanitizer|memorysanitizer|heap-buffer-overflow|"
    r"stack-buffer-overflow|use-after-free|double[- ]free|runtime error:|"
    r"segmentation fault|sigsegv|sigabrt|core dumped|terminated by signal|assertion .* failed",
    re.IGNORECASE,
)


@dataclass
class WireCase:
    engine: str
    name: str
    chunks: list[bytes]
    receive_first: bool = False
    half_close: bool = False
    receive_after: list[int] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def payload(self) -> bytes:
        return b"".join(self.chunks)

    def serializable(self) -> dict[str, Any]:
        value = asdict(self)
        value["chunks_b64"] = [base64.b64encode(chunk).decode("ascii") for chunk in self.chunks]
        del value["chunks"]
        return value

    @classmethod
    def from_serializable(cls, value: dict[str, Any]) -> "WireCase":
        return cls(
            engine=str(value["engine"]),
            name=str(value["name"]),
            chunks=[base64.b64decode(item) for item in value["chunks_b64"]],
            receive_first=bool(value.get("receive_first", False)),
            receive_after=[int(item) for item in value.get("receive_after", [])],
            half_close=bool(value.get("half_close", False)),
            metadata=dict(value.get("metadata", {})),
        )


def assert_loopback(host: str) -> None:
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, None)}
    except socket.gaierror as exc:
        raise SystemExit(f"cannot resolve target {host!r}: {exc}") from exc
    if not addresses or any(not ipaddress.ip_address(addr).is_loopback for addr in addresses):
        raise SystemExit(f"refusing non-loopback target {host!r}: {sorted(addresses)}")


def recv_available(sock: socket.socket, limit: int = 1_048_576) -> bytes:
    output = bytearray()
    while len(output) < limit:
        try:
            chunk = sock.recv(min(65536, limit - len(output)))
        except (TimeoutError, socket.timeout, ConnectionResetError):
            break
        if not chunk:
            break
        output.extend(chunk)
    return bytes(output)


def deterministic_bytes(rng: random.Random, size: int) -> bytes:
    return bytes(rng.randrange(256) for _ in range(size))


def fragment(data: bytes, rng: random.Random, max_chunks: int = 12) -> list[bytes]:
    if len(data) < 2 or rng.random() < 0.55:
        return [data]
    points = sorted(
        set(rng.randrange(1, len(data)) for _ in range(rng.randint(1, min(max_chunks, len(data) - 1))))
    )
    chunks: list[bytes] = []
    start = 0
    for point in points:
        chunks.append(data[start:point])
        start = point
    chunks.append(data[start:])
    return [chunk for chunk in chunks if chunk]


def mutate_bytes(data: bytes, rng: random.Random, max_input: int) -> bytes:
    value = bytearray(data)
    boundaries = (0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 127, 128, 255, 256, 65535, 0x7FFFFFFF)
    operations = ("flip", "insert", "delete", "repeat", "u16", "u24", "u32", "truncate")
    for _ in range(rng.randint(1, 8)):
        op = rng.choice(operations)
        if op == "flip" and value:
            pos = rng.randrange(len(value))
            value[pos] ^= 1 << rng.randrange(8)
        elif op == "insert":
            pos = rng.randrange(len(value) + 1)
            value[pos:pos] = deterministic_bytes(rng, rng.randint(1, min(64, max_input)))
        elif op == "delete" and value:
            pos = rng.randrange(len(value))
            del value[pos : pos + rng.randint(1, min(64, len(value) - pos))]
        elif op == "repeat" and value:
            pos = rng.randrange(len(value))
            frag = value[pos : pos + rng.randint(1, min(32, len(value) - pos))]
            value[pos:pos] = frag * rng.randint(1, 8)
        elif op in {"u16", "u24", "u32"}:
            width = {"u16": 2, "u24": 3, "u32": 4}[op]
            if len(value) >= width:
                pos = rng.randrange(len(value) - width + 1)
                integer = rng.choice(boundaries)
                value[pos : pos + width] = int(integer & ((1 << (8 * width)) - 1)).to_bytes(width, "big")
        elif op == "truncate" and value:
            del value[rng.randrange(len(value) + 1) :]
        if len(value) > max_input:
            del value[max_input:]
    return bytes(value)


def sha256_short(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()[:16]


class DockerMonitor:
    def __init__(self, container: str | None):
        self.container = container

    def snapshot(self) -> dict[str, Any]:
        if not self.container:
            return {}
        proc = subprocess.run(
            ["docker", "inspect", self.container], capture_output=True, text=True, check=False
        )
        if proc.returncode != 0:
            return {"inspect_error": proc.stderr.strip()[-2000:]}
        try:
            item = json.loads(proc.stdout)[0]
        except (json.JSONDecodeError, IndexError, TypeError):
            return {"inspect_error": proc.stdout.strip()[-2000:]}
        state = item.get("State", {})
        return {
            "id": item.get("Id", "")[:16],
            "running": state.get("Running"),
            "pid": state.get("Pid"),
            "exit_code": state.get("ExitCode"),
            "started_at": state.get("StartedAt"),
            "finished_at": state.get("FinishedAt"),
            "restart_count": item.get("RestartCount", 0),
        }

    def logs_since(self, epoch: float) -> str:
        if not self.container:
            return ""
        proc = subprocess.run(
            ["docker", "logs", "--since", str(max(0, int(epoch) - 1)), self.container],
            capture_output=True,
            text=True,
            check=False,
        )
        return (proc.stdout + proc.stderr)[-100_000:]


class FileLogMonitor:
    """Read sanitizer/runtime logs without confusing client crashes for server faults."""

    def __init__(self, pattern: str | None):
        self.pattern = pattern

    def snapshot(self) -> dict[str, Any]:
        if not self.pattern:
            return {}
        files = []
        for name in sorted(glob.glob(self.pattern)):
            try:
                stat = Path(name).stat()
            except OSError:
                continue
            files.append({"path": name, "size": stat.st_size, "mtime_ns": stat.st_mtime_ns})
        return {"files": files}

    def logs_since(self, epoch: float) -> str:
        if not self.pattern:
            return ""
        chunks: list[str] = []
        for name in sorted(glob.glob(self.pattern)):
            path = Path(name)
            try:
                if path.stat().st_mtime < epoch - 1:
                    continue
                chunks.append(f"===== {path} =====\n{path.read_text(encoding='utf-8', errors='replace')}")
            except OSError:
                continue
        return "\n".join(chunks)[-200_000:]


def state_changed(before: dict[str, Any], after: dict[str, Any]) -> bool:
    if not before or not after:
        return False
    keys = ("running", "pid", "started_at", "restart_count")
    return any(before.get(key) != after.get(key) for key in keys)


def save_case(root: Path, case: WireCase, result: dict[str, Any], response: bytes) -> Path:
    path = root / case.engine / f"{case.name}-{sha256_short(case.payload)}"
    path.mkdir(parents=True, exist_ok=True)
    (path / "case.json").write_text(json.dumps(case.serializable(), indent=2, sort_keys=True) + "\n")
    (path / "input.bin").write_bytes(case.payload)
    (path / "response.bin").write_bytes(response)
    (path / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return path


def write_jsonl(path: Path, values: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        for value in values:
            handle.write(json.dumps(value, sort_keys=True) + "\n")


def run_wire_case(
    host: str,
    port: int,
    timeout: float,
    case: WireCase,
    receive_limit: int = 1_048_576,
) -> tuple[bytes, str | None, float]:
    started = time.monotonic()
    response = bytearray()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if case.receive_first:
                response.extend(recv_available(sock, receive_limit))
            for index, chunk in enumerate(case.chunks):
                if chunk:
                    sock.sendall(chunk)
                requested = case.receive_after[index] if index < len(case.receive_after) else 0
                while requested > 0 and len(response) < receive_limit:
                    reply = sock.recv(min(requested, receive_limit - len(response)))
                    if not reply:
                        break
                    response.extend(reply)
                    requested -= len(reply)
                if len(case.chunks) > 1:
                    time.sleep(0.001)
            if case.half_close:
                sock.shutdown(socket.SHUT_WR)
            response.extend(recv_available(sock, max(0, receive_limit - len(response))))
        return bytes(response), None, time.monotonic() - started
    except OSError as exc:
        return bytes(response), f"{type(exc).__name__}: {exc}", time.monotonic() - started
