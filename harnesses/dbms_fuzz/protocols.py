#!/usr/bin/env python3
"""Protocol-aware seed corpora and mutations for local DBMS daemons."""

from __future__ import annotations

import random
import struct
from typing import Protocol

from core import WireCase, fragment, mutate_bytes


class Adapter(Protocol):
    name: str
    default_port: int

    def seeds(self) -> list[WireCase]: ...

    def mutate(self, seed: WireCase, rng: random.Random, max_input: int, index: int) -> WireCase: ...

    def response_class(self, data: bytes, error: str | None) -> str: ...

    def suspicious_response(self, case: WireCase, data: bytes) -> list[str]: ...


def be32(value: int) -> bytes:
    return struct.pack("!I", value & 0xFFFFFFFF)


class PostgreSQLAdapter:
    name = "postgresql"
    default_port = 5432
    SSL_REQUEST = 80877103
    GSSENC_REQUEST = 80877104
    CANCEL_REQUEST = 80877102

    @staticmethod
    def startup(params: list[tuple[str, str]], protocol: int = 196608) -> bytes:
        body = be32(protocol)
        for key, value in params:
            body += key.encode("utf-8") + b"\0" + value.encode("utf-8") + b"\0"
        body += b"\0"
        return be32(len(body) + 4) + body

    @staticmethod
    def typed(tag: bytes, payload: bytes, declared: int | None = None) -> bytes:
        length = len(payload) + 4 if declared is None else declared
        return tag[:1] + be32(length) + payload

    @classmethod
    def sasl_initial(cls, nonce: bytes = b"tfnonce0123456789") -> bytes:
        first = b"n,,n=,r=" + nonce
        payload = b"SCRAM-SHA-256\0" + be32(len(first)) + first
        return cls.typed(b"p", payload)

    @classmethod
    def sasl_final_invalid(cls, nonce: bytes = b"tfnonce0123456789") -> bytes:
        return cls.typed(b"p", b"c=biws,r=" + nonce + b"server,p=AAAA")

    @staticmethod
    def frames(data: bytes) -> tuple[bytes, list[tuple[bytes, bytes]]] | None:
        if len(data) < 8:
            return None
        startup_length = int.from_bytes(data[:4], "big")
        if startup_length < 8 or startup_length > len(data):
            return None
        startup = data[:startup_length]
        frames: list[tuple[bytes, bytes]] = []
        pos = startup_length
        while pos + 5 <= len(data):
            tag = data[pos : pos + 1]
            length = int.from_bytes(data[pos + 1 : pos + 5], "big")
            end = pos + 1 + length
            if length < 4 or end > len(data):
                return None
            frames.append((tag, data[pos + 5 : end]))
            pos = end
        return (startup, frames) if pos == len(data) else None

    @staticmethod
    def negotiation_prefix_end(data: bytes) -> int:
        pos = 0
        while data[pos : pos + 1] in (b"N", b"S", b"G"):
            if pos + 5 <= len(data):
                frame_length = int.from_bytes(data[pos + 1 : pos + 5], "big")
                if 4 <= frame_length <= len(data) - pos - 1:
                    break
            pos += 1
        return pos

    def seeds(self) -> list[WireCase]:
        normal = self.startup(
            [("user", "tf_fuzz_missing"), ("database", "postgres"), ("application_name", "tf-db-fuzz")]
        )
        duplicate = self.startup(
            [("user", "tf_fuzz_missing"), ("user", "postgres"), ("database", "postgres")]
        )
        sasl_startup = self.startup(
            [("user", "demo"), ("database", "postgres"), ("application_name", "tf-preauth")]
        )
        sasl_initial = self.sasl_initial()
        sasl_final = self.sasl_final_invalid()
        cancel = be32(16) + be32(self.CANCEL_REQUEST) + be32(0x41414141) + be32(0x42424242)
        ssl_request = be32(8) + be32(self.SSL_REQUEST)
        gssenc_request = be32(8) + be32(self.GSSENC_REQUEST)
        return [
            WireCase(self.name, "startup", [normal]),
            WireCase(self.name, "startup-bytewise", [normal[i : i + 1] for i in range(len(normal))]),
            WireCase(self.name, "startup-duplicate", [duplicate]),
            WireCase(self.name, "startup-sasl-initial", [sasl_startup, sasl_initial], half_close=True),
            WireCase(self.name, "startup-sasl-invalid-final", [sasl_startup, sasl_initial, sasl_final]),
            WireCase(self.name, "startup-sasl-empty", [sasl_startup, self.typed(b"p", b"")], half_close=True),
            WireCase(self.name, "startup-protocol-v2", [self.startup([("user", "demo")], 131072)]),
            WireCase(self.name, "ssl", [ssl_request]),
            WireCase(self.name, "ssl-truncated-tls", [ssl_request, b"\x16\x03\x03\x00\x05\x01\x00"], half_close=True),
            WireCase(self.name, "gssenc", [gssenc_request]),
            WireCase(self.name, "ssl-repeat", [ssl_request, ssl_request], receive_after=[1, 0]),
            WireCase(self.name, "gssenc-repeat", [gssenc_request, gssenc_request], receive_after=[1, 0]),
            WireCase(
                self.name,
                "ssl-gssenc-startup",
                [ssl_request, gssenc_request, normal],
                receive_after=[1, 1, 0],
            ),
            WireCase(
                self.name,
                "gssenc-ssl-startup",
                [gssenc_request, ssl_request, normal],
                receive_after=[1, 1, 0],
            ),
            WireCase(self.name, "cancel", [cancel], half_close=True),
            WireCase(self.name, "declared-zero", [be32(0)], half_close=True),
            WireCase(self.name, "declared-max", [be32(0x7FFFFFFF)], half_close=True),
            WireCase(self.name, "startup-truncated", [normal[:-1]], half_close=True),
        ]

    def mutate(self, seed: WireCase, rng: random.Random, max_input: int, index: int) -> WireCase:
        if seed.receive_after:
            chunks = list(seed.chunks)
            candidates = [
                chunk_index
                for chunk_index, requested in enumerate(seed.receive_after)
                if requested == 0 and chunk_index < len(chunks)
            ] or list(range(len(chunks)))
            chunk_index = rng.choice(candidates)
            other_bytes = sum(len(chunk) for item, chunk in enumerate(chunks) if item != chunk_index)
            budget = max(1, max_input - other_bytes)
            data = mutate_bytes(chunks[chunk_index], rng, budget)
            if len(data) >= 4 and rng.random() < 0.3:
                declared = rng.choice((0, 1, 3, 4, 7, 8, len(data), len(data) + 1, 0x7FFFFFFF))
                data = be32(declared) + data[4:]
            chunks[chunk_index] = data
            return WireCase(
                self.name,
                f"mut-{index:08d}",
                chunks,
                receive_after=list(seed.receive_after),
                half_close=rng.random() < 0.35,
                metadata={"parent": seed.name},
            )

        original = seed.payload
        parsed = self.frames(original)
        if parsed is not None and rng.random() < 0.7:
            startup, frames = parsed
            if frames and rng.random() < 0.7:
                frame_index = rng.randrange(len(frames))
                tag, payload = frames[frame_index]
                frames[frame_index] = (tag, mutate_bytes(payload, rng, min(max_input, 65536)))
            else:
                startup = mutate_bytes(startup, rng, min(max_input, 65536))
                if len(startup) >= 4:
                    startup = be32(len(startup)) + startup[4:]
            data = startup + b"".join(self.typed(tag, payload) for tag, payload in frames)
        else:
            data = mutate_bytes(original, rng, max_input)
        if len(data) >= 4 and rng.random() < 0.3:
            declared = rng.choice((0, 1, 3, 4, 7, 8, len(data), len(data) + 1, 0x7FFFFFFF))
            data = be32(declared) + data[4:]
        return WireCase(
            self.name,
            f"mut-{index:08d}",
            fragment(data, rng),
            half_close=rng.random() < 0.35,
            metadata={"parent": seed.name},
        )

    def response_class(self, data: bytes, error: str | None) -> str:
        if error:
            return f"transport:{error.split(':', 1)[0]}"
        negotiation: list[str] = []
        pos = self.negotiation_prefix_end(data)
        for item in data[:pos]:
            negotiation.append(bytes([item]).decode("ascii"))
        states: list[str] = []
        while pos + 5 <= len(data) and len(states) < 8:
            tag = data[pos : pos + 1]
            length = int.from_bytes(data[pos + 1 : pos + 5], "big")
            if length < 4 or pos + 1 + length > len(data):
                states.append("malformed")
                break
            payload = data[pos + 5 : pos + 1 + length]
            if tag == b"R" and len(payload) >= 4:
                states.append(f"R{int.from_bytes(payload[:4], 'big')}")
            else:
                states.append(tag.decode("latin1"))
            pos += 1 + length
        messages = "messages:" + ("-".join(states) if states else (data[pos : pos + 1].hex() if data[pos:] else "eof"))
        if negotiation:
            prefix = "negotiation:" + "-".join(negotiation)
            return prefix if pos == len(data) and not states else f"{prefix}|{messages}"
        return messages

    def suspicious_response(self, case: WireCase, data: bytes) -> list[str]:
        reasons: list[str] = []
        pos = self.negotiation_prefix_end(data)
        while pos + 5 <= len(data):
            tag = data[pos : pos + 1]
            length = int.from_bytes(data[pos + 1 : pos + 5], "big")
            if length < 4 or pos + 1 + length > len(data):
                break
            payload = data[pos + 5 : pos + 1 + length]
            if tag == b"R" and len(payload) >= 4 and int.from_bytes(payload[:4], "big") == 0:
                reasons.append("AuthenticationOk without a valid proof")
            if tag == b"Z":
                reasons.append("ReadyForQuery before successful authentication")
            pos += 1 + length
        return reasons


class MySQLAdapter:
    name = "mysql"
    default_port = 3306
    CLIENT_LONG_PASSWORD = 1
    CLIENT_CONNECT_WITH_DB = 1 << 3
    CLIENT_PROTOCOL_41 = 1 << 9
    CLIENT_SSL = 1 << 11
    CLIENT_SECURE_CONNECTION = 1 << 15
    CLIENT_PLUGIN_AUTH = 1 << 19
    CLIENT_CONNECT_ATTRS = 1 << 20
    CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 1 << 21

    def __init__(self, name: str = "mysql"):
        self.name = name

    @staticmethod
    def packet(payload: bytes, sequence: int = 1, declared: int | None = None) -> bytes:
        length = len(payload) if declared is None else declared
        return int(length & 0xFFFFFF).to_bytes(3, "little") + bytes([sequence & 0xFF]) + payload

    def handshake_response(self, capabilities: int, auth: bytes = b"invalid", attrs: bytes = b"") -> bytes:
        fixed = struct.pack("<IIB23s", capabilities, 16 * 1024 * 1024, 45, b"\0" * 23)
        payload = fixed + b"tf_fuzz_missing\0"
        if capabilities & self.CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA:
            payload += bytes([len(auth)]) + auth
        elif capabilities & self.CLIENT_SECURE_CONNECTION:
            payload += bytes([len(auth) & 0xFF]) + auth
        else:
            payload += auth + b"\0"
        if capabilities & self.CLIENT_CONNECT_WITH_DB:
            payload += b"test\0"
        if capabilities & self.CLIENT_PLUGIN_AUTH:
            payload += b"caching_sha2_password\0"
        if capabilities & self.CLIENT_CONNECT_ATTRS:
            payload += bytes([len(attrs)]) + attrs
        return self.packet(payload)

    def seeds(self) -> list[WireCase]:
        base = (
            self.CLIENT_LONG_PASSWORD
            | self.CLIENT_PROTOCOL_41
            | self.CLIENT_SECURE_CONNECTION
            | self.CLIENT_PLUGIN_AUTH
        )
        attr = base | self.CLIENT_CONNECT_ATTRS
        ssl = self.CLIENT_PROTOCOL_41 | self.CLIENT_SSL | self.CLIENT_SECURE_CONNECTION
        ssl_prefix = struct.pack("<IIB23s", ssl, 16 * 1024 * 1024, 45, b"\0" * 23)
        return [
            WireCase(self.name, "handshake-invalid-auth", [self.handshake_response(base)], receive_first=True),
            WireCase(
                self.name,
                "handshake-attrs",
                [self.handshake_response(attr, attrs=b"\x03_os\x05linux")],
                receive_first=True,
            ),
            WireCase(self.name, "ssl-request", [self.packet(ssl_prefix)], receive_first=True, half_close=True),
            WireCase(self.name, "zero-packet", [b"\0\0\0\x01"], receive_first=True, half_close=True),
            WireCase(
                self.name,
                "max-declared",
                [self.packet(b"A", declared=0xFFFFFF)],
                receive_first=True,
                half_close=True,
            ),
        ]

    def mutate(self, seed: WireCase, rng: random.Random, max_input: int, index: int) -> WireCase:
        data = mutate_bytes(seed.payload, rng, max_input)
        if len(data) >= 4 and rng.random() < 0.55:
            declared = rng.choice((0, 1, 3, 4, len(data) - 4, max(0, len(data) - 3), 0xFFFFFE, 0xFFFFFF))
            data = int(declared & 0xFFFFFF).to_bytes(3, "little") + bytes([rng.randrange(256)]) + data[4:]
        return WireCase(
            self.name,
            f"mut-{index:08d}",
            fragment(data, rng),
            receive_first=True,
            half_close=rng.random() < 0.4,
            metadata={"parent": seed.name},
        )

    def response_class(self, data: bytes, error: str | None) -> str:
        if error:
            return f"transport:{error.split(':', 1)[0]}"
        # The first packet is a randomized greeting. Classify the final packet marker instead.
        pos = 0
        markers: list[int] = []
        while pos + 4 <= len(data):
            length = int.from_bytes(data[pos : pos + 3], "little")
            end = pos + 4 + length
            if end > len(data):
                break
            if length:
                markers.append(data[pos + 4])
            pos = end
        return "mysql:" + ("-".join(f"{item:02x}" for item in markers[-2:]) or "eof")

    def suspicious_response(self, case: WireCase, data: bytes) -> list[str]:
        pos = 0
        markers: list[int] = []
        while pos + 4 <= len(data):
            length = int.from_bytes(data[pos : pos + 3], "little")
            end = pos + 4 + length
            if end > len(data):
                break
            if length:
                markers.append(data[pos + 4])
            pos = end
        if len(markers) >= 2 and markers[-1] == 0x00:
            return ["OK packet after invalid or malformed authentication response"]
        return []


class RedisAdapter:
    name = "redis"
    default_port = 6379

    @staticmethod
    def resp(*parts: bytes) -> bytes:
        return b"*" + str(len(parts)).encode() + b"\r\n" + b"".join(
            b"$" + str(len(part)).encode() + b"\r\n" + part + b"\r\n" for part in parts
        )

    def seeds(self) -> list[WireCase]:
        return [
            WireCase(self.name, "ping", [self.resp(b"PING")]),
            WireCase(self.name, "auth-invalid", [self.resp(b"AUTH", b"invalid")]),
            WireCase(self.name, "hello-auth-invalid", [self.resp(b"HELLO", b"3", b"AUTH", b"default", b"invalid")]),
            WireCase(self.name, "inline", [b"PING\r\n"]),
            WireCase(self.name, "negative-array", [b"*-2\r\n"]),
            WireCase(self.name, "bulk-short", [b"*1\r\n$8\r\nPING\r\n"], half_close=True),
            WireCase(self.name, "bulk-overflow", [b"*1\r\n$9223372036854775807\r\n"], half_close=True),
            WireCase(self.name, "pipeline", [self.resp(b"AUTH", b"invalid") + self.resp(b"PING")]),
        ]

    def mutate(self, seed: WireCase, rng: random.Random, max_input: int, index: int) -> WireCase:
        data = mutate_bytes(seed.payload, rng, max_input)
        if rng.random() < 0.35:
            token = str(rng.choice((-2, -1, 0, 1, 2, 127, 128, 65535, 2147483647, 9223372036854775807))).encode()
            data = data.replace(b"1", token, 1)
        return WireCase(
            self.name,
            f"mut-{index:08d}",
            fragment(data, rng),
            half_close=rng.random() < 0.3,
            metadata={"parent": seed.name},
        )

    def response_class(self, data: bytes, error: str | None) -> str:
        if error:
            return f"transport:{error.split(':', 1)[0]}"
        first = data[:1]
        if first in (b"+", b"-", b":", b"$", b"*", b"_", b"%", b"~", b">"):
            line = data.split(b"\r\n", 1)[0][:120]
            return f"resp:{first.decode('latin1')}:{line[1:].decode('utf-8', 'replace')}"
        return f"resp:raw:{first.hex() if first else 'eof'}"

    def suspicious_response(self, case: WireCase, data: bytes) -> list[str]:
        payload_upper = case.payload.upper()
        if b"AUTH" in payload_upper and data.startswith(b"+OK"):
            return ["AUTH accepted despite generated invalid credentials"]
        return []


class OracleAdapter:
    name = "oracle"
    default_port = 1521

    @staticmethod
    def packet(packet_type: int, payload: bytes, declared: int | None = None) -> bytes:
        length = len(payload) + 8 if declared is None else declared
        return struct.pack("!HHBBH", length & 0xFFFF, 0, packet_type & 0xFF, 0, 0) + payload

    def connect_packet(self, descriptor: bytes) -> bytes:
        # TNS CONNECT fixed data followed by the connect descriptor. Values are intentionally
        # conservative and unauthenticated; malformed variants come from the mutator.
        fixed = struct.pack(
            "!HHHHHHHHHHIHHI",
            0x013A,
            0x012C,
            0,
            0x0800,
            0x7FFF,
            0,
            1,
            len(descriptor),
            58,
            0,
            0x00000001,
            0,
            0,
            0,
        )
        fixed += b"\0" * max(0, 50 - len(fixed))
        return self.packet(1, fixed + descriptor)

    def seeds(self) -> list[WireCase]:
        descriptor = b"(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=127.0.0.1)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=FREEPDB1)))"
        connect = self.connect_packet(descriptor)
        return [
            WireCase(self.name, "connect", [connect]),
            WireCase(self.name, "connect-bytewise", [connect[i : i + 1] for i in range(len(connect))]),
            WireCase(self.name, "connect-truncated", [connect[:-1]], half_close=True),
            WireCase(self.name, "data-empty", [self.packet(6, b"")], half_close=True),
            WireCase(self.name, "declared-zero", [self.packet(1, b"", declared=0)], half_close=True),
            WireCase(self.name, "declared-max", [self.packet(1, b"A", declared=0xFFFF)], half_close=True),
        ]

    def mutate(self, seed: WireCase, rng: random.Random, max_input: int, index: int) -> WireCase:
        data = mutate_bytes(seed.payload, rng, max_input)
        if len(data) >= 2 and rng.random() < 0.5:
            declared = rng.choice((0, 1, 7, 8, len(data), len(data) + 1, 0x7FFF, 0xFFFF))
            data = int(declared & 0xFFFF).to_bytes(2, "big") + data[2:]
        return WireCase(
            self.name,
            f"mut-{index:08d}",
            fragment(data, rng),
            half_close=rng.random() < 0.4,
            metadata={"parent": seed.name},
        )

    def response_class(self, data: bytes, error: str | None) -> str:
        if error:
            return f"transport:{error.split(':', 1)[0]}"
        if len(data) >= 6:
            return f"tns:type-{data[4]:02x}:len-{int.from_bytes(data[:2], 'big')}"
        return f"tns:short-{len(data)}"

    def suspicious_response(self, case: WireCase, data: bytes) -> list[str]:
        return []


def get_adapter(engine: str) -> Adapter:
    normalized = engine.lower()
    if normalized in {"postgres", "postgresql", "pgsql"}:
        return PostgreSQLAdapter()
    if normalized == "mysql":
        return MySQLAdapter("mysql")
    if normalized in {"mariadb", "maria"}:
        return MySQLAdapter("mariadb")
    if normalized == "redis":
        return RedisAdapter()
    if normalized in {"oracle", "oracledb"}:
        return OracleAdapter()
    raise ValueError(f"unsupported engine: {engine}")
