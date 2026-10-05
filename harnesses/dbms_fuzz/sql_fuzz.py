#!/usr/bin/env python3
"""Low-privilege, structure-aware SQL execution fuzzing for local database targets."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import re
import socket
import struct
import tempfile
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from core import CRASH_RE, DockerMonitor, FileLogMonitor, assert_loopback, mutate_bytes, state_changed


@dataclass(frozen=True)
class SQLCase:
    name: str
    statements: tuple[str, ...]


@dataclass(frozen=True)
class PostgreSQLBinaryCase:
    name: str
    type_name: str
    type_oid: int
    payload: bytes
    parent: str | None = None


@dataclass(frozen=True)
class PostgreSQLPortalResult:
    status_name: str
    sqlstate: str
    error: str
    rows: int
    message_types: str


@dataclass(frozen=True)
class PostgreSQLFunctionResult:
    status_name: str
    sqlstate: str
    error: str
    result_len: int
    message_types: str


BOUNDARY_INTS = (-2147483648, -1, 0, 1, 2, 31, 32, 63, 64, 127, 128, 255, 256, 32767, 65535, 2147483647)
TEXT_ATOMS = ("", "a", "A", "0", "\\", "'", '"', "[]", "{}", "()", "é", "한", "\u0000")
REGEX_ATOMS = (".", ".*", "(a+)+$", "[[:alpha:]]", "(?:a|aa)*", "^$", "[")
FORMAT_ATOMS = ("YYYY-MM-DD", "TZ", "TZH:TZM", "FM999999999", "YYYY" * 64)

BINARY_BOUNDARIES: dict[int, tuple[int, ...]] = {
    1: (0, 1, 2, 0x7F, 0x80, 0xFF),
    2: (0, 1, 2, 0x7FFF, 0x8000, 0xFFFE, 0xFFFF),
    4: (0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF),
    8: (0, 1, 2, 0x7FFFFFFFFFFFFFFF, 0x8000000000000000, 0xFFFFFFFFFFFFFFFF),
}

# numeric_recv() represents each wire digit in base 10000.  Generic uint16
# boundaries mostly fail its digit-range check, so keep high-value arithmetic
# boundaries inside the receiver's valid domain for the semantic lane.
NUMERIC_DIGIT_BOUNDARIES = (0, 1, 2, 9, 10, 99, 100, 999, 1000, 9998, 9999)

# timetz_recv() parses a signed int64 microsecond-of-day followed by a signed
# int32 displacement and validates the two fields against independent limits.
# Keep wire-encoded values immediately around both limits so structure-aware
# mutations reach those checks without first corrupting the 12-byte frame.
POSTGRESQL_TIMETZ_BOUNDARIES: dict[int, tuple[int, ...]] = {
    8: (
        0,
        1,
        86_400_000_000 - 1,
        86_400_000_000,
        86_400_000_000 + 1,
        0x7FFFFFFFFFFFFFFF,
        0x8000000000000000,
        0xFFFFFFFFFFFFFFFF,
    ),
    4: tuple(
        value & 0xFFFFFFFF
        for value in (-57_601, -57_600, -57_599, -1, 0, 1, 57_599, 57_600, 57_601)
    ),
}

# Novel error signatures are useful boundary feedback, but uniformly feeding
# them back as mutation parents eventually makes almost every child fail in
# outer framing or receiver validation.  Keep a quarter of parent selections
# on that full feedback corpus while favoring inputs that completed Bind/COPY.
# Select the receiver type before the accepted input: bytea accepts arbitrary
# payloads and would otherwise crowd out structured receivers such as arrays,
# records, ranges, and text-search types.
POSTGRESQL_ACCEPTED_PARENT_RATIO = 0.75
POSTGRESQL_ACCEPTED_CORPUS_FORMAT = "taintforge-postgresql-accepted-corpus"
POSTGRESQL_ACCEPTED_CORPUS_VERSION = 1
POSTGRESQL_ACCEPTED_CORPUS_FILE = "postgresql-accepted-corpus-v1.jsonl"
POSTGRESQL_PREPARED_STATEMENT = b"tf_binary_receiver"
POSTGRESQL_PORTAL_STATEMENT = b"tf_binary_receiver_portal_stmt"
POSTGRESQL_PORTAL_NAME = b"tf_binary_receiver_portal"
POSTGRESQL_PORTAL_RESPONSE_LIMIT = 8 * 1024 * 1024
POSTGRESQL_FUNCTION_RESPONSE_LIMIT = 8 * 1024 * 1024


# Exact PostgreSQL 18 binary-send encodings for representative built-in values.
# Keeping the outer Bind frame valid lets mutations reach type receive functions
# instead of dying in generic frontend framing first.
POSTGRESQL_BINARY_SEED_HEX: tuple[tuple[str, int, str], ...] = (
    ("bool", 16, "00"),
    ("bytea", 17, "00ff7f80"),
    ("int8", 20, "8000000000000000"),
    ("int2", 21, "8000"),
    (
        "int2vector",
        22,
        "0000000100000000000000150000000500000000"
        "000000020001000000020002000000020003000000028000000000027fff",
    ),
    ("int4", 23, "80000000"),
    ("text", 25, "61cc88"),
    (
        "oidvector",
        30,
        "00000001000000000000001a0000000400000000"
        "00000004000000100000000400000011000000040000001700000004ffffffff",
    ),
    # record_send() for the PostgreSQL 18.6 pg_type row describing bool.
    # OID 71 is the fixed pg_type composite row type, so this reaches
    # record_recv() and its nested per-column binary receive dispatch.
    (
        "pg-type-record",
        71,
        "000000200000001a00000004000000100000001300000004626f6f6c"
        "0000001a000000040000000b0000001a000000040000000a00000015"
        "00000002000100000010000000010100000012000000016200000012"
        "00000001420000001000000001010000001000000001010000001200"
        "0000012c0000001a0000000400000000000000180000000400000000"
        "0000001a00000004000000000000001a00000004000003e800000018"
        "00000004000004da0000001800000004000004db0000001800000004"
        "00000984000000180000000400000985000000180000000400000000"
        "00000018000000040000000000000018000000040000000000000012"
        "00000001630000001200000001700000001000000001000000001a00"
        "000004000000000000001700000004ffffffff000000170000000400"
        "0000000000001a0000000400000000000000c2ffffffff00000019ff"
        "ffffff0000040affffffff",
    ),
    ("point", 600, "bff80000000000004002000000000000"),
    (
        "path",
        602,
        "00000000033ff000000000000040000000000000004008000000000000"
        "401000000000000040140000000000004018000000000000",
    ),
    (
        "polygon",
        604,
        "00000004000000000000000000000000000000003ff0000000000000"
        "00000000000000003ff00000000000003ff00000000000000000000000000000"
        "3ff0000000000000",
    ),
    # Unlike inet_recv(), cidr_recv() validates that all host bits beyond the
    # mask are clear.  Keep a valid /24 parent so mutations reach that branch.
    ("cidr", 650, "02180104c0000200"),
    ("float8", 701, "7ff8000000000000"),
    # macaddr8_recv() has a distinct six-byte EUI-48 path that inserts FF:FE;
    # macaddr8_send() would canonicalize this to eight bytes, so preserve the
    # shorter receive-only representation explicitly.
    ("macaddr8", 774, "001122334455"),
    ("inet", 869, "02180004c0000201"),
    # json_send() uses the validated JSON text itself as the binary payload.
    # Keep nested strings and decimals available to the semantic mutation lane
    # so json_recv() reaches the lexer/parser instead of UTF-8 rejection.
    (
        "json",
        114,
        "7b2261223a5b312c322c335d2c2273223a22616c706861222c"
        "226e6573746564223a7b226e223a39397d7d",
    ),
    (
        "int4-array",
        1007,
        "0000000100000000000000170000000300000001"
        "00000004800000000000000400000000000000047fffffff",
    ),
    # A two-dimensional text array with a negative lower bound, one NULL,
    # and a multibyte UTF-8 element.  Unlike int4[], this reaches array_recv's
    # null bitmap, varlena sizing/alignment, and nested text_recv paths.
    (
        "text-array",
        1009,
        "00000002000000010000001900000002ffffffff0000000200000001"
        "00000005616c706861ffffffff00000003ed959c000000056f6d656761",
    ),
    ("date", 1082, "00000000"),
    ("timestamp", 1114, "0000000000000000"),
    ("timestamptz", 1184, "0000000000000000"),
    ("interval", 1186, "0000000292556ab00000000200000001"),
    # 04:05:06.789012+05:30.  The second field is PostgreSQL's signed
    # seconds-west-of-UTC displacement, here -19,800.
    ("timetz", 1266, "000000036c97ca94ffffb2a8"),
    ("bit", 1560, "00000008aa"),
    # Nine bits require two data bytes and exercise varbit_recv()'s distinct
    # count-driven allocation/copy path plus its partial-byte padding.
    ("varbit", 1562, "00000009aa80"),
    ("numeric", 1700, "0002000000000004000108fc"),
    ("uuid", 2950, "00000000000000000000000000000001"),
    ("tsvector", 3614, "00000003616c706861000001000162657461000001000267616d6d610000010003"),
    ("tsquery", 3615, "000000040202020101000064656c746100010000616c70686100"),
    ("jsonb", 3802, "017b2261223a205b312c20322c20335d7d"),
    ("int4range", 3904, "020000000480000000000000047fffffff"),
    ("jsonpath", 4072, "01242e2261225b2a5d3f2840203e3d203229"),
    (
        "int4multirange",
        4451,
        "00000002000000110200000004000000010000000400000003"
        "000000110200000004000000050000000400000008",
    ),
    (
        "pg_snapshot",
        5038,
        "00000002000000000000000a0000000000000014"
        "000000000000000c000000000000000f",
    ),
)


def postgresql_binary_seeds() -> tuple[PostgreSQLBinaryCase, ...]:
    return tuple(
        PostgreSQLBinaryCase(f"{type_name}-valid", type_name, type_oid, bytes.fromhex(payload_hex))
        for type_name, type_oid, payload_hex in POSTGRESQL_BINARY_SEED_HEX
    )


def _postgresql_binary_function_oids(
    connection: Any,
    cases: list[PostgreSQLBinaryCase],
) -> dict[int, int]:
    """Find executable one-argument send functions with an exact input type."""
    type_oids = sorted({case.type_oid for case in cases})
    if not type_oids:
        return {}
    rows = connection.execute(
        """
        SELECT t.oid::int, t.typsend::oid::int
          FROM pg_catalog.pg_type AS t
          JOIN pg_catalog.pg_proc AS p ON p.oid = t.typsend
         WHERE t.oid = ANY(%s)
           AND p.pronargs = 1
           AND p.proargtypes[0] = t.oid
           AND has_function_privilege(p.oid, 'EXECUTE')
        """,
        (type_oids,),
    ).fetchall()
    return {int(type_oid): int(function_oid) for type_oid, function_oid in rows}


def _length_prefixed_offsets(payload: bytes, start: int, limit: int = 128) -> list[tuple[int, int]]:
    """Locate int32 length fields in a valid-ish PostgreSQL binary sequence."""
    offsets: list[tuple[int, int]] = []
    cursor = start
    while cursor + 4 <= len(payload) and len(offsets) < limit:
        offsets.append((cursor, 4))
        length = int.from_bytes(payload[cursor : cursor + 4], "big", signed=True)
        cursor += 4
        if length == -1:
            continue
        if length < 0 or cursor + length > len(payload):
            break
        cursor += length
    return offsets


def _length_prefixed_values(
    payload: bytes,
    start: int,
    limit: int = 128,
    end: int | None = None,
) -> list[tuple[int, int]]:
    """Locate value spans while retaining their surrounding length fields."""
    offsets: list[tuple[int, int]] = []
    cursor = start
    boundary = len(payload) if end is None else min(end, len(payload))
    while cursor + 4 <= boundary and len(offsets) < limit:
        length = int.from_bytes(payload[cursor : cursor + 4], "big", signed=True)
        cursor += 4
        if length == -1:
            continue
        if length < 0 or cursor + length > boundary:
            break
        if length:
            offsets.append((cursor, length))
        cursor += length
    return offsets


def _textual_value_offsets(payload: bytes, start: int) -> list[tuple[int, int]]:
    """Locate safe same-width string and decimal spans in a text payload."""
    offsets: list[tuple[int, int]] = []
    cursor = start
    string_start: int | None = None
    in_string = False

    while cursor < len(payload):
        byte = payload[cursor]
        if in_string:
            if byte == ord("\\"):
                if string_start is not None:
                    offsets.append((string_start, cursor - string_start))
                    string_start = None
                if cursor + 1 >= len(payload):
                    return []
                if payload[cursor + 1] == ord("u"):
                    if cursor + 5 >= len(payload):
                        return []
                    cursor += 6
                else:
                    cursor += 2
                continue
            if byte == ord('"'):
                if string_start is not None:
                    offsets.append((string_start, cursor - string_start))
                    string_start = None
                in_string = False
            elif 0x20 <= byte < 0x7F:
                if string_start is None:
                    string_start = cursor
            else:
                if string_start is not None:
                    offsets.append((string_start, cursor - string_start))
                    string_start = None
            cursor += 1
            continue

        if byte == ord('"'):
            in_string = True
            cursor += 1
            continue
        if ord("0") <= byte <= ord("9"):
            number_start = cursor
            while cursor < len(payload) and ord("0") <= payload[cursor] <= ord("9"):
                cursor += 1
            offsets.append((number_start, cursor - number_start))
            continue
        cursor += 1

    if in_string:
        return []
    return offsets


def _postgresql_binary_semantic_offsets(case: PostgreSQLBinaryCase) -> list[tuple[int, int]]:
    """Return nested values that can change without corrupting receiver framing."""
    payload = case.payload
    name = case.type_name
    offsets: list[tuple[int, int]] = []

    if name in {"int2vector", "oidvector", "int4-array", "text-array"} and len(payload) >= 12:
        ndim = int.from_bytes(payload[:4], "big", signed=True)
        values_start = 12 + max(0, ndim) * 8
        if 0 <= ndim <= 6 and values_start <= len(payload):
            offsets.extend(_length_prefixed_values(payload, values_start))
    elif name == "pg-type-record" and len(payload) >= 4:
        field_count = int.from_bytes(payload[:4], "big", signed=True)
        cursor = 4
        if 0 <= field_count <= 128:
            for _ in range(field_count):
                if cursor + 8 > len(payload):
                    break
                length = int.from_bytes(payload[cursor + 4 : cursor + 8], "big", signed=True)
                cursor += 8
                if length == -1:
                    continue
                if length < 0 or cursor + length > len(payload):
                    break
                if length:
                    offsets.append((cursor, length))
                cursor += length
    elif name == "path" and len(payload) >= 5:
        point_count = int.from_bytes(payload[1:5], "big", signed=True)
        if 0 <= point_count <= 128 and 5 + point_count * 16 <= len(payload):
            offsets.extend((offset, 8) for offset in range(5, 5 + point_count * 16, 8))
    elif name == "polygon" and len(payload) >= 4:
        point_count = int.from_bytes(payload[:4], "big", signed=True)
        if 0 <= point_count <= 128 and 4 + point_count * 16 <= len(payload):
            offsets.extend((offset, 8) for offset in range(4, 4 + point_count * 16, 8))
    elif name == "int4range" and payload:
        offsets.extend(_length_prefixed_values(payload, 1, limit=2))
    elif name == "int4multirange" and len(payload) >= 4:
        range_count = int.from_bytes(payload[:4], "big", signed=True)
        cursor = 4
        if 0 <= range_count <= 128:
            for _ in range(range_count):
                if cursor + 4 > len(payload):
                    break
                range_length = int.from_bytes(payload[cursor : cursor + 4], "big", signed=True)
                cursor += 4
                range_end = cursor + range_length
                if range_length < 1 or range_end > len(payload):
                    break
                offsets.extend(_length_prefixed_values(payload, cursor + 1, limit=2, end=range_end))
                cursor = range_end
    elif name == "pg_snapshot" and len(payload) >= 20:
        xip_count = int.from_bytes(payload[:4], "big", signed=True)
        value_count = 2 + max(0, xip_count)
        if 0 <= xip_count <= 128 and 4 + value_count * 8 <= len(payload):
            offsets.extend((offset, 8) for offset in range(4, 4 + value_count * 8, 8))
    elif name == "timetz" and len(payload) == 12:
        offsets.extend(((0, 8), (8, 4)))
    elif name == "varbit" and len(payload) >= 4:
        bit_length = int.from_bytes(payload[:4], "big", signed=True)
        expected_length = 4 + (bit_length + 7) // 8 if bit_length >= 0 else -1
        if len(payload) == expected_length and len(payload) > 4:
            offsets.append((4, len(payload) - 4))
    elif name == "numeric" and len(payload) >= 8:
        # numeric_recv() consumes four uint16/int16 header fields followed by
        # exactly ndigits base-10000 uint16 values.  Validate the complete
        # payload before exposing only digit words to semantic mutation.
        digit_count = int.from_bytes(payload[:2], "big")
        sign = int.from_bytes(payload[4:6], "big")
        dscale = int.from_bytes(payload[6:8], "big")
        valid_signs = {0x0000, 0x4000, 0xC000, 0xD000, 0xF000}
        expected_length = 8 + digit_count * 2
        if (
            digit_count <= 4096
            and len(payload) == expected_length
            and sign in valid_signs
            and dscale <= 0x3FFF
        ):
            digit_offsets = range(8, expected_length, 2)
            if all(
                int.from_bytes(payload[offset : offset + 2], "big") < 10000
                for offset in digit_offsets
            ):
                offsets.extend((offset, 2) for offset in digit_offsets)
    elif name == "tsvector" and len(payload) >= 4:
        # tsvectorrecv() consumes a count followed by NUL-terminated lexemes,
        # uint16 position counts, and uint16 positions.  Mutate lexeme bytes
        # without disturbing delimiters or position framing so inputs reach
        # the allocation, sort, and position-processing paths.
        entry_count = int.from_bytes(payload[:4], "big", signed=True)
        cursor = 4
        if not 0 <= entry_count <= 4096:
            return []
        for _ in range(entry_count):
            terminator = payload.find(b"\0", cursor)
            if terminator <= cursor or terminator + 3 > len(payload):
                return []
            offsets.append((cursor, terminator - cursor))
            position_count = int.from_bytes(
                payload[terminator + 1 : terminator + 3], "big"
            )
            cursor = terminator + 3 + position_count * 2
            if cursor > len(payload):
                return []
        if cursor != len(payload):
            return []
    elif name == "tsquery" and len(payload) >= 4:
        # tsqueryrecv() consumes prefix-notation items.  Keep the item types,
        # operators, arity, and NUL framing intact while changing operand text
        # (and phrase distance when present).
        item_count = int.from_bytes(payload[:4], "big")
        cursor = 4
        if item_count > 4096:
            return []
        for _ in range(item_count):
            if cursor >= len(payload):
                return []
            item_type = payload[cursor]
            cursor += 1
            if item_type == 1:  # QI_VAL: weight, prefix, C string
                if cursor + 2 > len(payload):
                    return []
                cursor += 2
                terminator = payload.find(b"\0", cursor)
                if terminator < cursor:
                    return []
                if terminator > cursor:
                    offsets.append((cursor, terminator - cursor))
                cursor = terminator + 1
            elif item_type == 2:  # QI_OPR
                if cursor >= len(payload):
                    return []
                operator = payload[cursor]
                cursor += 1
                if operator not in (1, 2, 3, 4):
                    return []
                if operator == 4:  # OP_PHRASE carries a uint16 distance
                    if cursor + 2 > len(payload):
                        return []
                    offsets.append((cursor, 2))
                    cursor += 2
            else:
                return []
        if cursor != len(payload):
            return []
    elif name == "json":
        try:
            json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            return []
        offsets.extend(_textual_value_offsets(payload, 0))
    elif name == "jsonb" and len(payload) > 1 and payload[0] == 1:
        try:
            json.loads(payload[1:].decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            return []
        offsets.extend(_textual_value_offsets(payload, 1))
    elif name == "jsonpath" and len(payload) > 1 and payload[0] == 1:
        try:
            text = payload[1:].decode("utf-8")
        except UnicodeDecodeError:
            return []
        if not text or "\0" in text:
            return []
        offsets.extend(_textual_value_offsets(payload, 1))

    return [(offset, width) for offset, width in offsets if width > 0 and offset + width <= len(payload)]


def _mutate_postgresql_binary_values(
    payload: bytes,
    offsets: list[tuple[int, int]],
    rng: random.Random,
    boundaries_by_width: dict[int, tuple[int, ...]] | None = None,
) -> bytes:
    """Mutate one to three nested values without changing their encoded widths."""
    value = bytearray(payload)
    mutation_count = rng.randint(1, min(3, len(offsets)))
    for offset, width in rng.sample(offsets, mutation_count):
        current = bytes(value[offset : offset + width])
        if width == 1 and current[0] in (0, 1):
            replacement = bytes([current[0] ^ 1])
        elif current and all(ord("0") <= item <= ord("9") for item in current):
            position = rng.randrange(width)
            replacement_value = bytearray(current)
            choices = tuple(
                item for item in b"0123456789" if item != replacement_value[position]
            )
            replacement_value[position] = rng.choice(choices)
            replacement = bytes(replacement_value)
        elif current and all(0x20 <= item < 0x7F for item in current):
            position = rng.randrange(width)
            replacement_value = bytearray(current)
            choices = tuple(item for item in b"A0z_-" if item != replacement_value[position])
            replacement_value[position] = rng.choice(choices)
            replacement = bytes(replacement_value)
        elif width in BINARY_BOUNDARIES:
            numeric = int.from_bytes(current, "big")
            boundaries = (
                boundaries_by_width.get(width, BINARY_BOUNDARIES[width])
                if boundaries_by_width is not None
                else BINARY_BOUNDARIES[width]
            )
            choices = tuple(item for item in boundaries if item != numeric)
            replacement = rng.choice(choices).to_bytes(width, "big")
        else:
            position = rng.randrange(width)
            replacement_value = bytearray(current)
            replacement_value[position] ^= 1 << rng.randrange(8)
            replacement = bytes(replacement_value)
        value[offset : offset + width] = replacement
    return bytes(value)


def _postgresql_binary_scalar_offsets(case: PostgreSQLBinaryCase) -> list[tuple[int, int]]:
    """Return receiver-specific count, length, tag and scalar field offsets."""
    payload = case.payload
    name = case.type_name
    offsets: list[tuple[int, int]] = []

    if name in {"int2vector", "oidvector", "int4-array", "text-array"}:
        # ndim, flags, element OID, each dimension/lower-bound pair, followed
        # by length-prefixed values.  Derive the value offset so multidimensional
        # arrays do not mistake dimension metadata for element framing.
        offsets.extend((offset, 4) for offset in (0, 4, 8))
        if len(payload) >= 12:
            ndim = int.from_bytes(payload[:4], "big", signed=True)
            values_start = 12 + max(0, ndim) * 8
            if 0 <= ndim <= 6 and values_start <= len(payload):
                offsets.extend((offset, 4) for offset in range(12, values_start, 4))
                offsets.extend(_length_prefixed_offsets(payload, values_start))
    elif name == "pg-type-record":
        offsets.append((0, 4))  # field count
        cursor = 4
        while cursor + 8 <= len(payload) and len(offsets) < 256:
            offsets.extend(((cursor, 4), (cursor + 4, 4)))  # type OID, value length
            length = int.from_bytes(payload[cursor + 4 : cursor + 8], "big", signed=True)
            cursor += 8
            if length == -1:
                continue
            if length < 0 or cursor + length > len(payload):
                break
            cursor += length
    elif name == "path":
        offsets.extend(((0, 1), (1, 4)))  # closed flag, point count
    elif name == "polygon":
        offsets.append((0, 4))  # point count
    elif name == "int4multirange":
        offsets.append((0, 4))  # range count
        offsets.extend(_length_prefixed_offsets(payload, 4))
    elif name == "pg_snapshot":
        offsets.append((0, 4))  # xip count
        offsets.extend((offset, 8) for offset in range(4, len(payload) - 7, 8))
    elif name == "int4range":
        offsets.append((0, 1))  # range flags
        offsets.extend(_length_prefixed_offsets(payload, 1, limit=2))
    elif name == "numeric":
        offsets.extend((offset, 2) for offset in range(0, min(len(payload), 8), 2))
    elif name in {"bit", "varbit", "tsvector", "tsquery"}:
        offsets.append((0, 4))
    elif name in {"jsonb", "jsonpath"}:
        offsets.append((0, 1))  # wire-format version
    elif name in {"inet", "cidr"}:
        offsets.extend((offset, 1) for offset in range(min(len(payload), 4)))
    elif name == "macaddr8":
        offsets.extend((offset, 1) for offset in range(len(payload)))
    elif name in {"bool"}:
        offsets.append((0, 1))
    elif name in {"int2"}:
        offsets.append((0, 2))
    elif name in {"int4", "date"}:
        offsets.append((0, 4))
    elif name in {"int8", "float8", "timestamp", "timestamptz"}:
        offsets.append((0, 8))
    elif name == "interval":
        offsets.extend(((0, 8), (8, 4), (12, 4)))
    elif name == "timetz":
        offsets.extend(((0, 8), (8, 4)))

    return [(offset, width) for offset, width in offsets if offset + width <= len(payload)]


def mutate_postgresql_binary(
    seed: PostgreSQLBinaryCase,
    rng: random.Random,
    max_input: int,
    index: int,
) -> PostgreSQLBinaryCase:
    if max_input < 1:
        raise ValueError("max_input must be positive")
    original = seed.payload
    bounded = original[:max_input]
    offsets = [
        (offset, width)
        for offset, width in _postgresql_binary_scalar_offsets(seed)
        if offset + width <= len(bounded)
    ]
    semantic_offsets = [
        (offset, width)
        for offset, width in _postgresql_binary_semantic_offsets(seed)
        if offset + width <= len(bounded)
    ]

    # Preserve nested framing often enough to reach per-value receive calls,
    # while retaining dedicated count/length and generic corruption lanes.
    mode = rng.random()
    if semantic_offsets and mode < 0.60:
        if seed.type_name == "numeric":
            semantic_boundaries = {2: NUMERIC_DIGIT_BOUNDARIES}
        elif seed.type_name == "timetz":
            semantic_boundaries = POSTGRESQL_TIMETZ_BOUNDARIES
        else:
            semantic_boundaries = None
        payload = _mutate_postgresql_binary_values(
            bounded, semantic_offsets, rng, semantic_boundaries
        )
    elif offsets and mode < (0.85 if semantic_offsets else 0.75):
        value = bytearray(bounded)
        mutation_count = rng.randint(1, min(3, len(offsets)))
        for offset, width in rng.sample(offsets, mutation_count):
            current = int.from_bytes(value[offset : offset + width], "big")
            choices = tuple(item for item in BINARY_BOUNDARIES[width] if item != current)
            boundary = rng.choice(choices)
            value[offset : offset + width] = boundary.to_bytes(width, "big")
        payload = bytes(value)
    else:
        payload = bounded
        for _ in range(8):
            payload = mutate_bytes(bounded, rng, max_input)
            if payload != bounded and len(payload) <= max_input:
                break

    if payload == original:
        if len(bounded) < max_input:
            payload = bounded + b"\0"
        elif bounded:
            payload = bytes([bounded[0] ^ 1]) + bounded[1:]
        else:
            payload = b"\0"
    return PostgreSQLBinaryCase(
        f"{seed.type_name}-mut-{index:08d}",
        seed.type_name,
        seed.type_oid,
        payload,
        parent=seed.name,
    )


def execute_postgresql_binary(pgconn: Any, case: PostgreSQLBinaryCase) -> Any:
    from psycopg import pq

    return pgconn.exec_params(
        b"SELECT $1",
        [case.payload],
        [case.type_oid],
        [pq.Format.BINARY],
        pq.Format.TEXT,
    )


def execute_postgresql_binary_mixed(pgconn: Any, case: PostgreSQLBinaryCase) -> Any:
    """Exercise per-parameter Bind formats before the target receiver."""
    from psycopg import pq

    return pgconn.exec_params(
        b"SELECT $1, $2",
        [b"1", case.payload],
        [23, case.type_oid],
        [pq.Format.TEXT, pq.Format.BINARY],
        pq.Format.TEXT,
    )


def execute_postgresql_binary_prepared(pgconn: Any, case: PostgreSQLBinaryCase) -> Any:
    """Exercise named prepared-statement lookup and successful plan reuse."""
    from psycopg import pq

    prepared = pgconn.prepare(
        POSTGRESQL_PREPARED_STATEMENT,
        b"SELECT $1",
        [case.type_oid],
    )
    if pq.ExecStatus(prepared.status) != pq.ExecStatus.COMMAND_OK:
        return prepared

    result = pgconn.exec_prepared(
        POSTGRESQL_PREPARED_STATEMENT,
        [case.payload],
        [pq.Format.BINARY],
        pq.Format.TEXT,
    )
    if pq.ExecStatus(result.status) != pq.ExecStatus.TUPLES_OK:
        return result

    return pgconn.exec_prepared(
        POSTGRESQL_PREPARED_STATEMENT,
        [case.payload],
        [pq.Format.BINARY],
        pq.Format.TEXT,
    )


def _postgresql_protocol_message(kind: bytes, payload: bytes = b"") -> bytes:
    if len(kind) != 1:
        raise ValueError("PostgreSQL protocol message type must be one byte")
    return kind + struct.pack("!I", len(payload) + 4) + payload


def postgresql_binary_portal_transcript(case: PostgreSQLBinaryCase) -> bytes:
    """Build a named-portal transcript with repeated partial Execute calls."""
    statement = POSTGRESQL_PORTAL_STATEMENT
    portal = POSTGRESQL_PORTAL_NAME
    query = b"SELECT $1 FROM pg_catalog.generate_series(1, 3)"
    parse = (
        statement
        + b"\0"
        + query
        + b"\0"
        + struct.pack("!H", 1)
        + struct.pack("!I", case.type_oid)
    )
    bind = (
        portal
        + b"\0"
        + statement
        + b"\0"
        + struct.pack("!Hh", 1, 1)  # one binary parameter format
        + struct.pack("!H", 1)
        + struct.pack("!I", len(case.payload))
        + case.payload
        + struct.pack("!Hh", 1, 0)  # one text result format
    )
    execute_one = portal + b"\0" + struct.pack("!I", 1)
    execute_all = portal + b"\0" + struct.pack("!I", 0)
    describe_statement = b"S" + statement + b"\0"
    describe_portal = b"P" + portal + b"\0"
    close_statement = b"S" + statement + b"\0"
    close_portal = b"P" + portal + b"\0"
    return b"".join(
        (
            _postgresql_protocol_message(b"P", parse),
            _postgresql_protocol_message(b"D", describe_statement),
            _postgresql_protocol_message(b"B", bind),
            _postgresql_protocol_message(b"D", describe_portal),
            _postgresql_protocol_message(b"E", execute_one),
            _postgresql_protocol_message(b"D", describe_portal),
            _postgresql_protocol_message(b"E", execute_one),
            _postgresql_protocol_message(b"E", execute_all),
            _postgresql_protocol_message(b"C", close_portal),
            _postgresql_protocol_message(b"C", close_statement),
            _postgresql_protocol_message(b"S"),
        )
    )


def _postgresql_error_fields(payload: bytes) -> dict[bytes, bytes]:
    fields: dict[bytes, bytes] = {}
    cursor = 0
    while cursor < len(payload):
        field_type = payload[cursor : cursor + 1]
        cursor += 1
        if field_type == b"\0":
            break
        terminator = payload.find(b"\0", cursor)
        if terminator < 0:
            break
        fields[field_type] = payload[cursor:terminator]
        cursor = terminator + 1
    return fields


def _read_postgresql_portal_result(raw_socket: socket.socket) -> PostgreSQLPortalResult:
    buffered = bytearray()
    message_types: list[str] = []
    rows = 0
    command_complete = False
    saw_error = False
    sqlstate = ""
    error = ""

    while True:
        while len(buffered) < 5:
            chunk = raw_socket.recv(65536)
            if not chunk:
                raise ConnectionError("PostgreSQL portal transcript ended before ReadyForQuery")
            buffered.extend(chunk)

        kind = bytes(buffered[:1])
        length = struct.unpack("!I", buffered[1:5])[0]
        if length < 4 or length > POSTGRESQL_PORTAL_RESPONSE_LIMIT:
            raise ValueError(f"invalid PostgreSQL response length: {length}")
        frame_size = 1 + length
        while len(buffered) < frame_size:
            chunk = raw_socket.recv(65536)
            if not chunk:
                raise ConnectionError("truncated PostgreSQL portal response")
            buffered.extend(chunk)

        payload = bytes(buffered[5:frame_size])
        del buffered[:frame_size]
        message_types.append(kind.decode("ascii", "replace"))
        if len(message_types) > 256:
            raise ValueError("too many PostgreSQL portal response messages")
        if kind == b"D":
            rows += 1
        elif kind == b"C":
            command_complete = True
        elif kind == b"E":
            saw_error = True
            fields = _postgresql_error_fields(payload)
            sqlstate = fields.get(b"C", b"").decode("ascii", "replace")
            error = fields.get(b"M", b"").decode("utf-8", "replace")[-2000:]
        elif kind == b"Z":
            break

    if saw_error:
        status_name = "FATAL_ERROR"
    elif command_complete:
        status_name = "TUPLES_OK"
    else:
        raise RuntimeError("PostgreSQL portal transcript completed without a result")
    return PostgreSQLPortalResult(
        status_name=status_name,
        sqlstate=sqlstate,
        error=error,
        rows=rows,
        message_types="".join(message_types),
    )


def execute_postgresql_binary_portal(
    pgconn: Any,
    case: PostgreSQLBinaryCase,
    timeout_ms: int,
) -> PostgreSQLPortalResult:
    """Reach named portal, suspend/resume, Describe, and Close protocol paths."""
    if pgconn.ssl_in_use:
        raise RuntimeError("named-portal transport requires a non-TLS local listener")
    socket_fd = int(pgconn.socket)
    if socket_fd < 0:
        raise RuntimeError("PostgreSQL connection has no active socket")

    raw_socket = socket.socket(fileno=os.dup(socket_fd))
    raw_socket.settimeout(max(1.0, timeout_ms / 1000.0 + 1.0))
    try:
        raw_socket.sendall(postgresql_binary_portal_transcript(case))
        return _read_postgresql_portal_result(raw_socket)
    finally:
        raw_socket.close()


def postgresql_binary_function_transcript(
    case: PostgreSQLBinaryCase,
    function_oid: int,
) -> bytes:
    """Build one protocol-v3 FunctionCall using a binary argument/result."""
    if not 0 < function_oid <= 0xFFFFFFFF:
        raise ValueError(f"invalid PostgreSQL function OID: {function_oid}")
    if len(case.payload) > 0x7FFFFFFF:
        raise ValueError("PostgreSQL function argument is too large")
    body = b"".join(
        (
            struct.pack("!I", function_oid),
            struct.pack("!Hh", 1, 1),  # one binary argument format
            struct.pack("!H", 1),
            struct.pack("!i", len(case.payload)),
            case.payload,
            struct.pack("!h", 1),  # binary function result
        )
    )
    return _postgresql_protocol_message(b"F", body)


def _read_postgresql_function_result(
    raw_socket: socket.socket,
) -> PostgreSQLFunctionResult:
    buffered = bytearray()
    message_types: list[str] = []
    saw_result = False
    result_len = -1
    saw_error = False
    sqlstate = ""
    error = ""

    while True:
        while len(buffered) < 5:
            chunk = raw_socket.recv(65536)
            if not chunk:
                raise ConnectionError("PostgreSQL FunctionCall ended before ReadyForQuery")
            buffered.extend(chunk)

        kind = bytes(buffered[:1])
        length = struct.unpack("!I", buffered[1:5])[0]
        if length < 4 or length > POSTGRESQL_FUNCTION_RESPONSE_LIMIT:
            raise ValueError(f"invalid PostgreSQL response length: {length}")
        frame_size = 1 + length
        while len(buffered) < frame_size:
            chunk = raw_socket.recv(65536)
            if not chunk:
                raise ConnectionError("truncated PostgreSQL FunctionCall response")
            buffered.extend(chunk)

        payload = bytes(buffered[5:frame_size])
        del buffered[:frame_size]
        message_types.append(kind.decode("ascii", "replace"))
        if len(message_types) > 32:
            raise ValueError("too many PostgreSQL FunctionCall response messages")
        if kind == b"V":
            if len(payload) < 4:
                raise ValueError("truncated PostgreSQL FunctionCall result")
            result_len = struct.unpack("!i", payload[:4])[0]
            expected = 4 if result_len == -1 else 4 + result_len
            if result_len < -1 or len(payload) != expected:
                raise ValueError("invalid PostgreSQL FunctionCall result length")
            saw_result = True
        elif kind == b"E":
            saw_error = True
            fields = _postgresql_error_fields(payload)
            sqlstate = fields.get(b"C", b"").decode("ascii", "replace")
            error = fields.get(b"M", b"").decode("utf-8", "replace")[-2000:]
        elif kind == b"Z":
            break

    if saw_error:
        status_name = "FATAL_ERROR"
    elif saw_result:
        status_name = "FUNCTION_OK"
    else:
        raise RuntimeError("PostgreSQL FunctionCall completed without a result")
    return PostgreSQLFunctionResult(
        status_name=status_name,
        sqlstate=sqlstate,
        error=error,
        result_len=result_len,
        message_types="".join(message_types),
    )


def execute_postgresql_binary_function(
    pgconn: Any,
    case: PostgreSQLBinaryCase,
    function_oid: int,
    timeout_ms: int,
) -> PostgreSQLFunctionResult:
    """Reach the legacy FunctionCall parser and the case's binary receiver."""
    if pgconn.ssl_in_use:
        raise RuntimeError("FunctionCall transport requires a non-TLS local listener")
    socket_fd = int(pgconn.socket)
    if socket_fd < 0:
        raise RuntimeError("PostgreSQL connection has no active socket")

    raw_socket = socket.socket(fileno=os.dup(socket_fd))
    raw_socket.settimeout(max(1.0, timeout_ms / 1000.0 + 1.0))
    try:
        raw_socket.sendall(postgresql_binary_function_transcript(case, function_oid))
        return _read_postgresql_function_result(raw_socket)
    finally:
        raw_socket.close()


def postgresql_binary_copy_stream(case: PostgreSQLBinaryCase) -> bytes:
    """Wrap one binary value in a valid one-column PostgreSQL COPY stream."""
    return b"".join(
        (
            b"PGCOPY\n\xff\r\n\x00",
            struct.pack("!ii", 0, 0),  # flags and header-extension length
            struct.pack("!h", 1),
            struct.pack("!i", len(case.payload)),
            case.payload,
            struct.pack("!h", -1),
        )
    )


def _postgresql_binary_sql_type(case: PostgreSQLBinaryCase) -> str:
    """Return a trusted catalog type name for a built-in binary seed."""
    array_types = {
        "int4-array": "pg_catalog.int4[]",
        "text-array": "pg_catalog.text[]",
    }
    if case.type_name in array_types:
        return array_types[case.type_name]
    if case.type_name == "pg-type-record":
        return "pg_catalog.pg_type"
    if not re.fullmatch(r"[a-z][a-z0-9_]*", case.type_name):
        raise ValueError(f"unsupported PostgreSQL binary type: {case.type_name!r}")
    return f"pg_catalog.{case.type_name}"


def execute_postgresql_binary_copy(connection: Any, case: PostgreSQLBinaryCase) -> int:
    """Send one receiver payload through PostgreSQL's binary COPY FROM parser."""
    sql_type = _postgresql_binary_sql_type(case)
    connection.execute(f"CREATE TEMP TABLE tf_binary_copy (value {sql_type})")
    with connection.cursor().copy(
        "COPY pg_temp.tf_binary_copy (value) FROM STDIN (FORMAT BINARY)"
    ) as writer:
        writer.write(postgresql_binary_copy_stream(case))
    return 1


def _postgresql_binary_transport(
    index: int,
    seed_count: int,
    function_seed_count: int,
) -> str:
    """Cover each transport with valid seeds, then split mutation traffic."""
    if index < seed_count:
        return "binary-bind"
    if index < seed_count * 2:
        return "binary-copy"
    if index < seed_count * 3:
        return "binary-bind-mixed"
    if index < seed_count * 4:
        return "binary-bind-prepared"
    if index < seed_count * 5:
        return "binary-bind-portal"
    function_start = seed_count * 5
    if index < function_start + function_seed_count:
        return "binary-function-call"
    mutation_slot = (index - function_start - function_seed_count) % 6
    if mutation_slot == 0:
        return "binary-copy"
    if mutation_slot == 1:
        return "binary-bind-mixed"
    if mutation_slot == 2:
        return "binary-bind-prepared"
    if mutation_slot == 3:
        return "binary-bind-portal"
    if mutation_slot == 4:
        return "binary-function-call"
    return "binary-bind"


def _postgresql_binary_type_indices(
    corpus: list[PostgreSQLBinaryCase],
) -> dict[str, list[int]]:
    """Index a binary corpus by receiver type without copying its payloads."""
    result: dict[str, list[int]] = {}
    for index, case in enumerate(corpus):
        result.setdefault(case.type_name, []).append(index)
    return result


def _choose_postgresql_binary_parent(
    accepted_corpus: list[PostgreSQLBinaryCase],
    accepted_type_indices: dict[str, list[int]],
    feedback_corpus: list[PostgreSQLBinaryCase],
    rng: random.Random,
    allowed_type_names: frozenset[str] | None = None,
) -> PostgreSQLBinaryCase:
    """Retain deep receiver execution without letting easy types monopolize it."""
    eligible_feedback = (
        feedback_corpus
        if allowed_type_names is None
        else [case for case in feedback_corpus if case.type_name in allowed_type_names]
    )
    if not eligible_feedback:
        raise ValueError("PostgreSQL binary feedback corpus must not be empty")
    eligible_types = tuple(
        type_name
        for type_name in accepted_type_indices
        if allowed_type_names is None or type_name in allowed_type_names
    )
    if eligible_types and rng.random() < POSTGRESQL_ACCEPTED_PARENT_RATIO:
        type_name = rng.choice(eligible_types)
        return accepted_corpus[rng.choice(accepted_type_indices[type_name])]
    return rng.choice(eligible_feedback)


def _postgresql_binary_digest(case: PostgreSQLBinaryCase) -> bytes:
    return hashlib.sha256(
        case.type_oid.to_bytes(4, "big") + case.payload
    ).digest()


def _postgresql_binary_accepted_type_capacities(
    base_seeds: list[PostgreSQLBinaryCase],
    max_corpus: int,
) -> dict[str, int]:
    """Divide non-seed accepted slots evenly across canonical receiver types."""
    type_names = tuple(dict.fromkeys(case.type_name for case in base_seeds))
    if not type_names:
        return {}
    available = max(0, max_corpus - len(base_seeds))
    per_type, remainder = divmod(available, len(type_names))
    return {
        type_name: per_type + (index < remainder)
        for index, type_name in enumerate(type_names)
    }


def _load_postgresql_binary_accepted_corpus(
    path: Path,
    base_seeds: list[PostgreSQLBinaryCase],
    max_input: int,
    max_corpus: int,
) -> list[PostgreSQLBinaryCase]:
    """Load only bounded, canonical-type cases from a prior binary batch."""
    available = max(0, max_corpus - len(base_seeds))
    if available == 0 or not path.is_file():
        return []

    expected_oids = {case.type_name: case.type_oid for case in base_seeds}
    type_capacities = _postgresql_binary_accepted_type_capacities(
        base_seeds, max_corpus
    )
    loaded_per_type = {type_name: 0 for type_name in expected_oids}
    seen = {_postgresql_binary_digest(case) for case in base_seeds}
    loaded: list[PostgreSQLBinaryCase] = []
    try:
        with path.open(encoding="utf-8") as handle:
            header = json.loads(handle.readline())
            if not isinstance(header, dict) or header.get("format") != POSTGRESQL_ACCEPTED_CORPUS_FORMAT:
                return []
            if header.get("version") != POSTGRESQL_ACCEPTED_CORPUS_VERSION:
                return []
            for line in handle:
                if len(loaded) >= available:
                    break
                # Base64 expands by 4/3. Reject oversized records before
                # decoding so damaged state cannot inflate campaign memory.
                if len(line) > ((max_input + 2) // 3) * 4 + 1024:
                    continue
                try:
                    item = json.loads(line)
                    type_name = item["type_name"]
                    type_oid = item["type_oid"]
                    payload = base64.b64decode(item["payload_b64"], validate=True)
                except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                    continue
                if not isinstance(type_name, str) or not isinstance(type_oid, int):
                    continue
                if expected_oids.get(type_name) != type_oid or len(payload) > max_input:
                    continue
                if loaded_per_type[type_name] >= type_capacities[type_name]:
                    continue
                digest = hashlib.sha256(type_oid.to_bytes(4, "big") + payload).digest()
                if digest in seen:
                    continue
                seen.add(digest)
                loaded_per_type[type_name] += 1
                loaded.append(
                    PostgreSQLBinaryCase(
                        f"{type_name}-persisted-{digest.hex()[:16]}",
                        type_name,
                        type_oid,
                        payload,
                        parent="accepted-checkpoint",
                    )
                )
    except (OSError, UnicodeError, json.JSONDecodeError):
        return []
    return loaded


def _save_postgresql_binary_accepted_corpus(
    path: Path,
    accepted_corpus: list[PostgreSQLBinaryCase],
    protected_count: int,
    max_corpus: int,
) -> None:
    """Atomically checkpoint non-seed accepted inputs without connection data."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            handle.write(
                json.dumps(
                    {
                        "format": POSTGRESQL_ACCEPTED_CORPUS_FORMAT,
                        "version": POSTGRESQL_ACCEPTED_CORPUS_VERSION,
                    },
                    sort_keys=True,
                )
                + "\n"
            )
            for case in accepted_corpus[protected_count:max_corpus]:
                handle.write(
                    json.dumps(
                        {
                            "payload_b64": base64.b64encode(case.payload).decode("ascii"),
                            "type_name": case.type_name,
                            "type_oid": case.type_oid,
                        },
                        sort_keys=True,
                    )
                    + "\n"
                )
        temporary_path.replace(path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _remember_postgresql_binary_accepted_case(
    accepted_corpus: list[PostgreSQLBinaryCase],
    accepted_hashes: set[bytes],
    accepted_type_indices: dict[str, list[int]],
    case: PostgreSQLBinaryCase,
    max_corpus: int,
    protected_count: int,
    rng: random.Random,
) -> str | None:
    """Rotate accepted descendants within an equal per-type slot budget."""
    digest = _postgresql_binary_digest(case)
    if digest in accepted_hashes or max_corpus <= protected_count:
        return None

    capacities = _postgresql_binary_accepted_type_capacities(
        accepted_corpus[:protected_count], max_corpus
    )
    type_indices = accepted_type_indices.get(case.type_name)
    capacity = capacities.get(case.type_name, 0)
    if type_indices is None or capacity == 0:
        return None
    mutable_indices = [index for index in type_indices if index >= protected_count]

    if len(mutable_indices) < capacity and len(accepted_corpus) < max_corpus:
        accepted_corpus.append(case)
        accepted_hashes.add(digest)
        type_indices.append(len(accepted_corpus) - 1)
        return "added"

    if not mutable_indices:
        return None
    replace_at = rng.choice(mutable_indices)
    accepted_hashes.remove(_postgresql_binary_digest(accepted_corpus[replace_at]))
    accepted_corpus[replace_at] = case
    accepted_hashes.add(digest)
    return "replaced"


def templates(engine: str) -> list[SQLCase]:
    if engine == "postgresql":
        return [
            SQLCase("to-char", ("SELECT to_char(current_timestamp, {{FMT}})",)),
            SQLCase("regexp-split", ("SELECT regexp_split_to_array({{TEXT}}, {{REGEX}})",)),
            SQLCase("regexp-replace", ("SELECT regexp_replace({{TEXT}}, {{REGEX}}, {{TEXT}})",)),
            SQLCase("tsvector", ("SELECT to_tsvector('simple', {{TEXT}})::text",)),
            SQLCase("tsquery", ("SELECT plainto_tsquery('simple', {{TEXT}})::text",)),
            SQLCase("substring", ("SELECT substring({{TEXT}} FROM {{POS}} FOR {{LEN}})",)),
            SQLCase("array-update", (
                "CREATE TEMP TABLE tf_fuzz_array(v int[]) ON COMMIT DROP",
                "INSERT INTO tf_fuzz_array VALUES (ARRAY[1,2,3])",
                "UPDATE tf_fuzz_array SET v[{{POS}}] = {{INT}} RETURNING v",
            )),
            SQLCase("prepared-cast", (
                "PREPARE tf_fuzz_q(text) AS SELECT $1::text",
                "EXECUTE tf_fuzz_q({{TEXT}})",
                "DEALLOCATE tf_fuzz_q",
            )),
        ]
    if engine in {"mysql", "mariadb"}:
        values = [
            SQLCase("regexp-replace", ("SELECT REGEXP_REPLACE({{TEXT}}, {{REGEX}}, {{TEXT}})",)),
            SQLCase("json-extract", ("SELECT JSON_EXTRACT({{JSON}}, {{PATH}})",)),
            SQLCase("charset-convert", ("SELECT CONVERT({{TEXT}} USING utf8mb4)",)),
            SQLCase("substring", ("SELECT SUBSTRING({{TEXT}}, {{POS}}, {{LEN}})",)),
            SQLCase("prepared-cast", ("SELECT CAST({{TEXT}} AS CHAR)",)),
        ]
        if engine == "mariadb":
            values.append(SQLCase("json-valid", ("SELECT JSON_VALID({{JSON}})",)))
        return values
    if engine == "oracle":
        return [
            SQLCase("to-char", ("SELECT TO_CHAR(SYSTIMESTAMP, {{FMT}}) FROM dual",)),
            SQLCase("regexp-replace", ("SELECT REGEXP_REPLACE({{TEXT}}, {{REGEX}}, {{TEXT}}) FROM dual",)),
            SQLCase("json", ("SELECT JSON_QUERY({{JSON}}, {{PATH}}) FROM dual",)),
            SQLCase("substring", ("SELECT SUBSTR({{TEXT}}, {{POS}}, {{LEN}}) FROM dual",)),
            SQLCase("charset", ("SELECT CONVERT({{TEXT}}, 'AL32UTF8') FROM dual",)),
        ]
    raise ValueError(f"SQL mode is not available for {engine}")


def sql_string(value: str) -> str:
    if "\x00" in value:
        value = value.replace("\x00", "")
    return "'" + value.replace("'", "''") + "'"


def generated_text(rng: random.Random, max_literal: int) -> str:
    atom = rng.choice(TEXT_ATOMS)
    target = rng.choice((0, 1, 2, 7, 8, 31, 32, 127, 128, 255, 256, 1024, max_literal))
    if not atom:
        return ""
    return (atom * ((target + len(atom) - 1) // len(atom)))[:target]


def instantiate(case: SQLCase, rng: random.Random, max_literal: int, index: int) -> SQLCase:
    text = generated_text(rng, max_literal)
    regex = rng.choice(REGEX_ATOMS)
    fmt = rng.choice(FORMAT_ATOMS)
    if rng.random() < 0.25:
        fmt = (fmt * rng.randint(2, max(2, min(256, max_literal // max(1, len(fmt))))))[:max_literal]
    integer = rng.choice(BOUNDARY_INTS)
    replacements = {
        "{{TEXT}}": sql_string(text),
        "{{REGEX}}": sql_string(regex),
        "{{FMT}}": sql_string(fmt),
        "{{POS}}": str(rng.choice(BOUNDARY_INTS)),
        "{{LEN}}": str(rng.choice(BOUNDARY_INTS)),
        "{{INT}}": str(integer),
        "{{JSON}}": sql_string(rng.choice(("null", "[]", "{}", '["a"]', '{"a":1}', "[" * 8 + "]" * 8))),
        "{{PATH}}": sql_string(rng.choice(("$", "$.a", "$[*]", "$..a", "$[0]"))),
    }
    statements = []
    for statement in case.statements:
        for marker, value in replacements.items():
            statement = statement.replace(marker, value)
        statements.append(statement)
    return SQLCase(f"{case.name}-{index:08d}", tuple(statements))


def dsn_host(dsn: str, engine: str) -> str:
    if "://" in dsn:
        parsed = urllib.parse.urlparse(dsn)
        return parsed.hostname or "127.0.0.1"
    match = re.search(r"(?:^|\s)host=([^\s]+)", dsn)
    if match:
        return match.group(1)
    if engine == "oracle" and "@" in dsn:
        connect = dsn.rsplit("@", 1)[1]
        return connect.split(":", 1)[0].lstrip("/") or "127.0.0.1"
    return "127.0.0.1"


def load_dsn(path: Path) -> str:
    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        raise SystemExit(f"DSN file must be mode 0600 or stricter: {path} has {oct(mode)}")
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise SystemExit(f"empty DSN file: {path}")
    return value


def connector(engine: str, dsn: str) -> Callable[[], Any]:
    if engine == "postgresql":
        import psycopg

        return lambda: psycopg.connect(dsn, autocommit=False)
    if engine in {"mysql", "mariadb"}:
        import pymysql

        parsed = urllib.parse.urlparse(dsn)
        if parsed.scheme not in {"mysql", "mariadb"}:
            raise SystemExit("MySQL/MariaDB DSN must be mysql:// or mariadb://")
        kwargs = {
            "host": parsed.hostname or "127.0.0.1",
            "port": parsed.port or 3306,
            "user": urllib.parse.unquote(parsed.username or ""),
            "password": urllib.parse.unquote(parsed.password or ""),
            "database": parsed.path.lstrip("/") or None,
            "autocommit": False,
            "connect_timeout": 3,
            "read_timeout": 3,
            "write_timeout": 3,
        }
        return lambda: pymysql.connect(**kwargs)
    if engine == "oracle":
        try:
            import oracledb
        except ImportError as exc:
            raise SystemExit("Oracle SQL mode requires python-oracledb") from exc
        parsed = urllib.parse.urlparse(dsn)
        if parsed.scheme not in {"oracle", "oracledb"}:
            raise SystemExit("Oracle DSN must be oracle://user:pass@host:port/service")
        connect_dsn = f"{parsed.hostname or '127.0.0.1'}:{parsed.port or 1521}/{parsed.path.lstrip('/')}"
        return lambda: oracledb.connect(
            user=urllib.parse.unquote(parsed.username or ""),
            password=urllib.parse.unquote(parsed.password or ""),
            dsn=connect_dsn,
        )
    raise ValueError(engine)


def error_signature(exc: BaseException) -> str:
    sqlstate = getattr(exc, "sqlstate", None)
    if sqlstate:
        return f"sqlstate:{sqlstate}"
    args = getattr(exc, "args", ())
    if args and isinstance(args[0], int):
        return f"dbcode:{args[0]}"
    return f"exception:{type(exc).__name__}"


def save_sql_case(root: Path, engine: str, case: SQLCase, result: dict[str, Any]) -> Path:
    digest = hashlib.sha256("\n".join(case.statements).encode()).hexdigest()[:16]
    path = root / engine / f"{case.name}-{digest}"
    path.mkdir(parents=True, exist_ok=True)
    (path / "case.sql").write_text(";\n".join(case.statements) + ";\n", encoding="utf-8")
    (path / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return path


def redact_dsn_error(value: str, dsn: str) -> str:
    redacted = value.replace(dsn, "<redacted-dsn>")
    if "://" in dsn:
        parsed = urllib.parse.urlparse(dsn)
        for secret in (parsed.password, urllib.parse.unquote(parsed.password or "")):
            if secret:
                redacted = redacted.replace(secret, "<redacted>")
    return re.sub(r"(?i)(password\s*=\s*)\S+", r"\1<redacted>", redacted)


def save_postgresql_binary_case(
    root: Path,
    case: PostgreSQLBinaryCase,
    result: dict[str, Any],
) -> Path:
    digest = hashlib.sha256(case.type_oid.to_bytes(4, "big") + case.payload).hexdigest()[:16]
    path = root / "postgresql" / f"{case.name}-{digest}"
    path.mkdir(parents=True, exist_ok=True)
    serialized = {
        "engine": "postgresql",
        "name": case.name,
        "parent": case.parent,
        "query": (
            "COPY pg_temp.tf_binary_copy (value) FROM STDIN (FORMAT BINARY)"
            if result.get("transport") == "binary-copy"
            else (
                "protocol FunctionCall"
                if result.get("transport") == "binary-function-call"
                else (
                    "SELECT $1, $2"
                    if result.get("transport") == "binary-bind-mixed"
                    else "SELECT $1"
                )
            )
        ),
        "type_name": case.type_name,
        "type_oid": case.type_oid,
        "parameter_format": "binary",
        "transport": result.get("transport", "binary-bind"),
        "function_oid": result.get("function_oid"),
        "payload_b64": base64.b64encode(case.payload).decode("ascii"),
    }
    (path / "case.json").write_text(json.dumps(serialized, indent=2, sort_keys=True) + "\n")
    (path / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return path


def _postgresql_binary_response_signature(
    transport: str,
    type_name: str,
    status_name: str,
    sqlstate: str,
    error_shape: str,
    protocol_messages: str,
) -> str:
    """Normalize the protocol/type outcome used for state feedback and retention."""
    shape_digest = hashlib.sha256(
        error_shape.encode("utf-8", "replace")
    ).hexdigest()[:12]
    return (
        f"{transport}:{type_name}:{status_name}:{sqlstate or '-'}:"
        f"{shape_digest}:{protocol_messages or '-'}"
    )


def _load_postgresql_binary_artifact_signatures(root: Path) -> set[str]:
    """Load one replay-state signature per persisted binary artifact outcome.

    Older artifacts predate the explicit ``signature`` field, so reconstruct it
    from their normalized result fields.  Malformed or incomplete artifacts are
    retained on disk but cannot suppress a future complete replay case.
    """
    signatures: set[str] = set()
    if not root.is_dir():
        return signatures

    for result_path in root.glob("*/result.json"):
        try:
            result = json.loads(result_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if not isinstance(result, dict):
            continue

        explicit = result.get("signature")
        if isinstance(explicit, str) and explicit:
            signatures.add(explicit)
            continue

        required = ("transport", "type_name", "status", "error_shape")
        if any(not isinstance(result.get(key), str) for key in required):
            continue
        sqlstate = result.get("sqlstate", "")
        protocol_messages = result.get("protocol_messages", "")
        if not isinstance(sqlstate, str) or not isinstance(protocol_messages, str):
            continue
        signatures.add(
            _postgresql_binary_response_signature(
                result["transport"],
                result["type_name"],
                result["status"],
                sqlstate,
                result["error_shape"],
                protocol_messages,
            )
        )
    return signatures


def run_sql_campaign(
    engine: str,
    dsn_file: Path,
    iterations: int,
    seed: int,
    max_literal: int,
    timeout_ms: int,
    container: str | None,
    artifacts: Path,
    sanitizer_log_glob: str | None = None,
) -> int:
    dsn = load_dsn(dsn_file)
    assert_loopback(dsn_host(dsn, engine))
    connect = connector(engine, dsn)
    rng = random.Random(seed)
    seeds = templates(engine)
    monitor = DockerMonitor(container)
    sanitizer_monitor = FileLogMonitor(sanitizer_log_glob)
    seen: set[str] = set()
    suspicious = 0

    for index in range(iterations):
        case = instantiate(rng.choice(seeds), rng, max_literal, index)
        before = monitor.snapshot()
        log_epoch = time.time()
        started = time.monotonic()
        signature = "ok"
        error_text = ""
        rows = 0
        connection = None
        try:
            connection = connect()
            cursor = connection.cursor()
            if engine == "postgresql":
                cursor.execute(f"SET LOCAL statement_timeout = {int(timeout_ms)}")
            for statement in case.statements:
                cursor.execute(statement)
                if getattr(cursor, "description", None):
                    fetched = cursor.fetchmany(4)
                    rows += len(fetched)
            connection.rollback()
        except Exception as exc:  # DB drivers expose engine errors through diverse classes.
            signature = error_signature(exc)
            error_text = str(exc)[-4000:]
            if connection is not None:
                try:
                    connection.rollback()
                except Exception:
                    pass
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass

        elapsed = time.monotonic() - started
        after = monitor.snapshot()
        logs = "\n".join(
            part
            for part in (monitor.logs_since(log_epoch), sanitizer_monitor.logs_since(log_epoch))
            if part
        )
        crash = bool(CRASH_RE.search(logs)) or state_changed(before, after)
        novel = signature not in seen
        seen.add(signature)
        result = {
            "engine": engine,
            "case": case.name,
            "signature": signature,
            "error": error_text,
            "rows_sampled": rows,
            "elapsed_seconds": round(elapsed, 6),
            "novel_state": novel,
            "crash_signal": crash,
            "container_before": before,
            "container_after": after,
            "container_logs": logs if crash else "",
        }
        mark = "SUSPICIOUS" if crash else ("novel" if novel else "ok")
        print(f"[{index + 1:06d}/{iterations:06d}] {mark:10s} {case.name} {signature} {elapsed:.3f}s")
        if crash or novel:
            path = save_sql_case(artifacts, engine, case, result)
            if crash:
                suspicious += 1
                print(f"  artifact: {path}")

    print(json.dumps({"engine": engine, "cases": iterations, "states": len(seen), "suspicious": suspicious}))
    return 2 if suspicious else 0


def run_postgresql_binary_campaign(
    dsn_file: Path,
    iterations: int,
    seed: int,
    max_input: int,
    timeout_ms: int,
    container: str | None,
    artifacts: Path,
    sanitizer_log_glob: str | None = None,
    max_corpus: int = 4096,
) -> int:
    if iterations < 0:
        raise SystemExit("iterations must not be negative")
    if max_input < 1:
        raise SystemExit("max input must be positive")
    if timeout_ms < 1:
        raise SystemExit("timeout must be positive")

    import psycopg
    from psycopg import pq

    dsn = load_dsn(dsn_file)
    assert_loopback(dsn_host(dsn, "postgresql"))
    rng = random.Random(seed)
    accepted_rng = random.Random(seed ^ 0x4143434550544544)
    base_seeds = list(postgresql_binary_seeds())
    with psycopg.connect(dsn, autocommit=True, connect_timeout=3) as metadata_connection:
        function_oids = _postgresql_binary_function_oids(metadata_connection, base_seeds)
    function_seeds = [case for case in base_seeds if case.type_oid in function_oids]
    function_type_names = frozenset(case.type_name for case in function_seeds)
    if not function_seeds:
        raise SystemExit("no executable exact-type PostgreSQL send functions found")
    corpus = list(base_seeds)
    corpus_hashes = {_postgresql_binary_digest(case) for case in corpus}
    accepted_checkpoint = artifacts / POSTGRESQL_ACCEPTED_CORPUS_FILE
    loaded_accepted = _load_postgresql_binary_accepted_corpus(
        accepted_checkpoint, base_seeds, max_input, max_corpus
    )
    accepted_corpus = [*base_seeds, *loaded_accepted]
    accepted_hashes = {
        _postgresql_binary_digest(case) for case in accepted_corpus
    }
    accepted_type_indices = _postgresql_binary_type_indices(accepted_corpus)
    accepted_updates = {"added": 0, "replaced": 0}
    monitor = DockerMonitor(container)
    sanitizer_monitor = FileLogMonitor(sanitizer_log_glob)
    seen: set[str] = set()
    persisted_signatures = _load_postgresql_binary_artifact_signatures(
        artifacts / "postgresql"
    )
    persisted_signatures_loaded = len(persisted_signatures)
    suspicious = 0
    seed_count = len(base_seeds)
    function_seed_count = len(function_seeds)
    function_start = seed_count * 5
    mutation_start = function_start + function_seed_count
    cases_total = mutation_start + iterations
    transport_counts = {
        "binary-bind": 0,
        "binary-copy": 0,
        "binary-bind-mixed": 0,
        "binary-bind-prepared": 0,
        "binary-bind-portal": 0,
        "binary-function-call": 0,
    }

    for index in range(cases_total):
        transport = _postgresql_binary_transport(index, seed_count, function_seed_count)
        if index < seed_count:
            case = base_seeds[index]
        elif index < seed_count * 2:
            seed_case = base_seeds[index - seed_count]
            case = PostgreSQLBinaryCase(
                f"{seed_case.type_name}-copy-valid",
                seed_case.type_name,
                seed_case.type_oid,
                seed_case.payload,
                parent=seed_case.name,
            )
        elif index < seed_count * 3:
            seed_case = base_seeds[index - seed_count * 2]
            case = PostgreSQLBinaryCase(
                f"{seed_case.type_name}-mixed-valid",
                seed_case.type_name,
                seed_case.type_oid,
                seed_case.payload,
                parent=seed_case.name,
            )
        elif index < seed_count * 4:
            seed_case = base_seeds[index - seed_count * 3]
            case = PostgreSQLBinaryCase(
                f"{seed_case.type_name}-prepared-valid",
                seed_case.type_name,
                seed_case.type_oid,
                seed_case.payload,
                parent=seed_case.name,
            )
        elif index < seed_count * 5:
            seed_case = base_seeds[index - seed_count * 4]
            case = PostgreSQLBinaryCase(
                f"{seed_case.type_name}-portal-valid",
                seed_case.type_name,
                seed_case.type_oid,
                seed_case.payload,
                parent=seed_case.name,
            )
        elif index < mutation_start:
            seed_case = function_seeds[index - function_start]
            case = PostgreSQLBinaryCase(
                f"{seed_case.type_name}-function-valid",
                seed_case.type_name,
                seed_case.type_oid,
                seed_case.payload,
                parent=seed_case.name,
            )
        else:
            parent = _choose_postgresql_binary_parent(
                accepted_corpus,
                accepted_type_indices,
                corpus,
                rng,
                function_type_names if transport == "binary-function-call" else None,
            )
            case = mutate_postgresql_binary(
                parent, rng, max_input, index - mutation_start
            )
        transport_counts[transport] += 1

        before = monitor.snapshot()
        log_epoch = time.time()
        started = time.monotonic()
        status_name = "CLIENT_EXCEPTION"
        sqlstate = ""
        error_text = ""
        rows = 0
        protocol_messages = ""
        function_oid = None
        connection = None
        try:
            connection = psycopg.connect(dsn, autocommit=True, connect_timeout=3)
            connection.execute(f"SET statement_timeout = {int(timeout_ms)}")
            if transport == "binary-copy":
                rows = execute_postgresql_binary_copy(connection, case)
                status_name = "COMMAND_OK"
            else:
                if transport == "binary-bind-portal":
                    portal_result = execute_postgresql_binary_portal(
                        connection.pgconn, case, timeout_ms
                    )
                    status_name = portal_result.status_name
                    sqlstate = portal_result.sqlstate
                    error_text = portal_result.error
                    rows = portal_result.rows
                    protocol_messages = portal_result.message_types
                    result = None
                elif transport == "binary-function-call":
                    function_oid = function_oids[case.type_oid]
                    function_result = execute_postgresql_binary_function(
                        connection.pgconn, case, function_oid, timeout_ms
                    )
                    status_name = function_result.status_name
                    sqlstate = function_result.sqlstate
                    error_text = function_result.error
                    rows = int(function_result.result_len >= 0)
                    protocol_messages = function_result.message_types
                    result = None
                elif transport == "binary-bind-prepared":
                    result = execute_postgresql_binary_prepared(connection.pgconn, case)
                elif transport == "binary-bind-mixed":
                    result = execute_postgresql_binary_mixed(connection.pgconn, case)
                else:
                    result = execute_postgresql_binary(connection.pgconn, case)
                if result is not None:
                    status_name = pq.ExecStatus(result.status).name
                    sqlstate_value = result.error_field(pq.DiagnosticField.SQLSTATE)
                    sqlstate = (sqlstate_value or b"").decode("ascii", "replace")
                    message = result.error_field(pq.DiagnosticField.MESSAGE_PRIMARY)
                    error_text = (message or b"").decode("utf-8", "replace")[-2000:]
                    rows = int(result.ntuples)
        except Exception as exc:
            exception_sqlstate = getattr(exc, "sqlstate", None)
            if exception_sqlstate:
                status_name = "FATAL_ERROR"
                sqlstate = str(exception_sqlstate)
            else:
                exception_signature = error_signature(exc)
                if exception_signature.startswith("sqlstate:"):
                    sqlstate = exception_signature.split(":", 1)[1]
            error_text = redact_dsn_error(str(exc)[-4000:], dsn)
        finally:
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass

        elapsed = time.monotonic() - started
        after = monitor.snapshot()
        logs = "\n".join(
            part
            for part in (monitor.logs_since(log_epoch), sanitizer_monitor.logs_since(log_epoch))
            if part
        )
        crash = bool(CRASH_RE.search(logs)) or state_changed(before, after)
        error_shape = re.sub(r"0x[0-9a-f]+|\d+", "#", error_text.lower())
        error_shape = re.sub(r"'[^']*'|\"[^\"]*\"", "<value>", error_shape)
        error_shape = re.sub(r"\s+", " ", error_shape).strip()[:240]
        signature = _postgresql_binary_response_signature(
            transport,
            case.type_name,
            status_name,
            sqlstate,
            error_shape,
            protocol_messages,
        )
        novel = signature not in seen
        novel_persisted_state = signature not in persisted_signatures
        seen.add(signature)
        digest = _postgresql_binary_digest(case)
        if status_name in {"TUPLES_OK", "COMMAND_OK", "FUNCTION_OK"}:
            update = _remember_postgresql_binary_accepted_case(
                accepted_corpus,
                accepted_hashes,
                accepted_type_indices,
                case,
                max_corpus,
                seed_count,
                accepted_rng,
            )
            if update is not None:
                accepted_updates[update] += 1
        if novel and digest not in corpus_hashes and len(corpus) < max_corpus:
            corpus.append(case)
            corpus_hashes.add(digest)

        result_data = {
            "engine": "postgresql",
            "case": case.name,
            "type_name": case.type_name,
            "type_oid": case.type_oid,
            "input_len": len(case.payload),
            "parameter_format": "binary",
            "transport": transport,
            "function_oid": function_oid,
            "authentication": "low-privilege",
            "status": status_name,
            "sqlstate": sqlstate,
            "error": error_text,
            "error_shape": error_shape,
            "signature": signature,
            "rows_sampled": rows,
            "protocol_messages": protocol_messages,
            "elapsed_seconds": round(elapsed, 6),
            "novel_state": novel,
            "novel_persisted_state": novel_persisted_state,
            "crash_signal": crash,
            "container_before": before,
            "container_after": after,
            "container_logs": logs if crash else "",
        }
        mark = "SUSPICIOUS" if crash else ("novel" if novel else "ok")
        print(
            f"[{index + 1:06d}/{cases_total:06d}] {mark:10s} {case.name} "
            f"transport={transport} bytes={len(case.payload)} "
            f"{status_name}:{sqlstate or '-'}",
            flush=True,
        )
        # Preserve every crash input.  For ordinary states, retain one exact
        # replay case across batch rollovers; accepted inputs and in-batch
        # mutation feedback are maintained independently above.
        if crash or (novel and novel_persisted_state):
            saved = save_postgresql_binary_case(artifacts, case, result_data)
            persisted_signatures.add(signature)
            if crash:
                suspicious += 1
                print(f"  artifact: {saved}", flush=True)

    checkpoint_saved = True
    try:
        _save_postgresql_binary_accepted_corpus(
            accepted_checkpoint, accepted_corpus, seed_count, max_corpus
        )
    except OSError as exc:
        checkpoint_saved = False
        print(f"warning: accepted-corpus checkpoint failed: {exc}", flush=True)

    print(
        json.dumps(
            {
                "engine": "postgresql",
                "lane": "binary-bind",
                "cases": cases_total,
                "states": len(seen),
                "corpus": len(corpus),
                "accepted_corpus": len(accepted_corpus),
                "accepted_corpus_loaded": len(loaded_accepted),
                "accepted_corpus_updates": accepted_updates,
                "accepted_corpus_checkpoint_saved": checkpoint_saved,
                "artifact_signatures_loaded": persisted_signatures_loaded,
                "artifact_signatures_total": len(persisted_signatures),
                "accepted_corpus_type_counts": {
                    type_name: len(indices)
                    for type_name, indices in accepted_type_indices.items()
                },
                "transports": transport_counts,
                "suspicious": suspicious,
            },
            sort_keys=True,
        )
    )
    return 2 if suspicious else 0
