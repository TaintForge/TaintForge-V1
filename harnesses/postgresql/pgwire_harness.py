#!/usr/bin/env python3
"""Loopback-only PostgreSQL pre-auth wire-protocol regression/fuzz harness."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import random
import socket
import struct
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


SSL_REQUEST = 80877103
GSSENC_REQUEST = 80877104
CANCEL_REQUEST = 80877102


@dataclass
class Case:
    name: str
    chunks: list[bytes]
    shutdown_write: bool = False


def i32(value: int) -> bytes:
    return struct.pack("!I", value & 0xFFFFFFFF)


def startup(params: list[tuple[str, str]], protocol: int = 196608) -> bytes:
    body = i32(protocol)
    for key, value in params:
        body += key.encode() + b"\0" + value.encode() + b"\0"
    body += b"\0"
    return i32(len(body) + 4) + body


def request(code: int) -> bytes:
    return i32(8) + i32(code)


def corpus(user: str) -> list[Case]:
    normal = startup([("user", user), ("database", "postgres"), ("application_name", "tf-preauth")])
    duplicate = startup([("user", user), ("user", "postgres"), ("database", "postgres")])
    odd = startup([("user", user), ("database", "postgres"), ("x" * 127, "y" * 4096)])
    cancel = i32(16) + i32(CANCEL_REQUEST) + i32(0x41414141) + i32(0x42424242)
    return [
        Case("startup-baseline", [normal]),
        Case("startup-bytewise", [normal[i : i + 1] for i in range(len(normal))]),
        Case("startup-duplicate-keys", [duplicate]),
        Case("startup-long-unknown-param", [odd]),
        Case("ssl-only", [request(SSL_REQUEST)]),
        Case("ssl-then-startup", [request(SSL_REQUEST), normal]),
        Case("gssenc-only", [request(GSSENC_REQUEST)]),
        Case("cancel-random-key", [cancel], True),
        Case("length-zero", [i32(0)], True),
        Case("length-one", [i32(1)], True),
        Case("length-three", [i32(3)], True),
        Case("length-header-only", [i32(0x7FFFFFFF)], True),
        Case("startup-no-terminator", [normal[:-1]], True),
        Case("startup-trailing-data", [normal + b"TRAILING"], True),
        Case("protocol-major-overflow", [i32(8) + i32(0x7FFFFFFF)], True),
    ]


def mutate(seed: bytes, rng: random.Random) -> bytes:
    data = bytearray(seed)
    for _ in range(rng.randint(1, 6)):
        op = rng.choice(("flip", "insert", "delete", "length", "repeat"))
        if op == "flip" and data:
            at = rng.randrange(len(data))
            data[at] ^= 1 << rng.randrange(8)
        elif op == "insert":
            at = rng.randrange(len(data) + 1)
            data[at:at] = os.urandom(rng.randint(1, 32))
        elif op == "delete" and data:
            at = rng.randrange(len(data))
            del data[at : at + rng.randint(1, min(32, len(data) - at))]
        elif op == "length" and len(data) >= 4:
            data[:4] = i32(rng.choice((0, 1, 3, 4, 7, 8, len(data), len(data) + 1, 0x7FFFFFFF)))
        elif op == "repeat" and data:
            at = rng.randrange(len(data))
            frag = data[at : at + rng.randint(1, min(16, len(data) - at))]
            data[at:at] = frag * rng.randint(1, 4)
    return bytes(data[:1_048_576])


def assert_loopback(host: str) -> None:
    addresses = {item[4][0] for item in socket.getaddrinfo(host, None)}
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


def backend_events(data: bytes) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    pos = 0
    if data[:1] in (b"N", b"S"):
        events.append({"type": "negotiation", "value": data[:1].decode("ascii")})
        pos = 1
    while pos + 5 <= len(data):
        tag = data[pos : pos + 1]
        length = struct.unpack("!I", data[pos + 1 : pos + 5])[0]
        if length < 4 or pos + 1 + length > len(data):
            break
        payload = data[pos + 5 : pos + 1 + length]
        event: dict[str, object] = {"type": tag.decode("ascii", "replace"), "length": length}
        if tag == b"R" and len(payload) >= 4:
            event["auth_code"] = struct.unpack("!I", payload[:4])[0]
        events.append(event)
        pos += 1 + length
    return events


def docker_snapshot(container: str | None) -> dict[str, object]:
    if not container:
        return {}
    inspect = subprocess.run(
        ["docker", "inspect", container, "--format", "{{json .State}}"],
        text=True,
        capture_output=True,
        check=False,
    )
    state: dict[str, object] = {}
    if inspect.returncode == 0:
        try:
            state = json.loads(inspect.stdout)
        except json.JSONDecodeError:
            state = {"raw": inspect.stdout.strip()}
    logs = subprocess.run(
        ["docker", "logs", "--since", "2s", container],
        text=True,
        capture_output=True,
        check=False,
    )
    return {"state": state, "logs": (logs.stdout + logs.stderr)[-20000:]}


def run_case(host: str, port: int, timeout: float, case: Case) -> tuple[bytes, str | None]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            for chunk in case.chunks:
                sock.sendall(chunk)
                if len(case.chunks) > 1:
                    time.sleep(0.002)
            if case.shutdown_write:
                sock.shutdown(socket.SHUT_WR)
            return recv_available(sock), None
    except OSError as exc:
        return b"", f"{type(exc).__name__}: {exc}"


def save_artifact(root: Path, case: Case, response: bytes, record: dict[str, object]) -> Path:
    payload = b"".join(case.chunks)
    digest = hashlib.sha256(payload).hexdigest()[:16]
    case_dir = root / f"{case.name}-{digest}"
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "input.bin").write_bytes(payload)
    (case_dir / "response.bin").write_bytes(response)
    (case_dir / "result.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    return case_dir


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=55432)
    parser.add_argument("--timeout", type=float, default=0.75)
    parser.add_argument("--iterations", type=int, default=0, help="deterministic mutated cases")
    parser.add_argument("--seed", type=int, default=0x5A4443)
    parser.add_argument("--container", default="zerodaycloud-postgresql")
    parser.add_argument("--artifacts", type=Path, default=Path("workspace/harness-artifacts/postgresql"))
    args = parser.parse_args()
    assert_loopback(args.host)

    user = f"tf_preauth_{args.seed:x}"
    cases = corpus(user)
    rng = random.Random(args.seed)
    seeds = [b"".join(case.chunks) for case in cases]
    for index in range(args.iterations):
        cases.append(Case(f"mut-{index:06d}", [mutate(rng.choice(seeds), rng)], True))

    baseline = docker_snapshot(args.container)
    suspicious = 0
    for index, case in enumerate(cases, 1):
        response, error = run_case(args.host, args.port, args.timeout, case)
        events = backend_events(response)
        auth_bypass = any(
            event.get("type") == "Z" or (event.get("type") == "R" and event.get("auth_code") == 0)
            for event in events
        )
        after = docker_snapshot(args.container)
        logs = str(after.get("logs", ""))
        crash = any(
            needle in logs.lower()
            for needle in ("segmentation fault", "terminated by signal", "terminated abnormally", "core dumped")
        )
        record = {
            "case": case.name,
            "index": index,
            "input_len": sum(map(len, case.chunks)),
            "response_len": len(response),
            "response_sha256": hashlib.sha256(response).hexdigest(),
            "events": events,
            "error": error,
            "auth_bypass_signal": auth_bypass,
            "crash_signal": crash,
            "container_before": baseline.get("state", {}),
            "container_after": after.get("state", {}),
            "container_logs": logs if crash else "",
        }
        mark = "SUSPICIOUS" if auth_bypass or crash else "ok"
        print(f"[{index:04d}/{len(cases):04d}] {mark:10s} {case.name} in={record['input_len']} out={len(response)} error={error or '-'}")
        if auth_bypass or crash:
            suspicious += 1
            path = save_artifact(args.artifacts, case, response, record)
            print(f"  artifact: {path}")
        baseline = after

    print(json.dumps({"cases": len(cases), "suspicious": suspicious, "artifacts": str(args.artifacts)}))
    return 2 if suspicious else 0


if __name__ == "__main__":
    raise SystemExit(main())
