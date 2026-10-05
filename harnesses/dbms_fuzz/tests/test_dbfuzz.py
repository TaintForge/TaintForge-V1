#!/usr/bin/env python3
from __future__ import annotations

import base64
import json
import random
import socket
import struct
import sys
import tempfile
import time
import unittest
from collections import Counter
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch


HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))

from core import FileLogMonitor, WireCase, assert_loopback, mutate_bytes, run_wire_case, save_case
from dbfuzz import _load_wire_feedback, doctor
from protocols import MySQLAdapter, OracleAdapter, PostgreSQLAdapter, RedisAdapter, get_adapter
from postgresql_sql import (
    mutation_resource_safe,
    standalone_safe,
    split_sql,
    strip_psql_lines,
    unwrap_transaction,
    usable_statement,
    wrap_transaction,
)
import postgresql_structured_mutator as pg_mutator
from sql_fuzz import (
    _choose_postgresql_binary_parent,
    _load_postgresql_binary_artifact_signatures,
    _load_postgresql_binary_accepted_corpus,
    _postgresql_binary_digest,
    _postgresql_binary_function_oids,
    _postgresql_binary_response_signature,
    _postgresql_binary_scalar_offsets,
    _postgresql_binary_semantic_offsets,
    _postgresql_binary_sql_type,
    _postgresql_binary_transport,
    _postgresql_binary_type_indices,
    _remember_postgresql_binary_accepted_case,
    _save_postgresql_binary_accepted_corpus,
    execute_postgresql_binary,
    execute_postgresql_binary_copy,
    execute_postgresql_binary_function,
    execute_postgresql_binary_mixed,
    execute_postgresql_binary_portal,
    execute_postgresql_binary_prepared,
    instantiate,
    mutate_postgresql_binary,
    postgresql_binary_copy_stream,
    postgresql_binary_function_transcript,
    postgresql_binary_portal_transcript,
    postgresql_binary_seeds,
    save_postgresql_binary_case,
    templates,
)


class DBFuzzTests(unittest.TestCase):
    def test_loopback_guard(self) -> None:
        assert_loopback("127.0.0.1")
        with self.assertRaises(SystemExit):
            assert_loopback("192.0.2.10")

    def test_case_round_trip(self) -> None:
        case = WireCase(
            "redis",
            "x",
            [b"a", b"b"],
            receive_after=[1, 0],
            half_close=True,
            metadata={"x": 1},
        )
        rebuilt = WireCase.from_serializable(json.loads(json.dumps(case.serializable())))
        self.assertEqual(rebuilt.payload, b"ab")
        self.assertEqual(rebuilt.receive_after, [1, 0])
        self.assertTrue(rebuilt.half_close)

    def test_adapters_have_bounded_mutations(self) -> None:
        rng = random.Random(7)
        for adapter in (PostgreSQLAdapter(), MySQLAdapter(), MySQLAdapter("mariadb"), RedisAdapter(), OracleAdapter()):
            seeds = adapter.seeds()
            self.assertTrue(seeds)
            case = adapter.mutate(seeds[0], rng, 4096, 1)
            self.assertLessEqual(len(case.payload), 4096)
            self.assertEqual(get_adapter(adapter.name).name, adapter.name)

    def test_postgresql_sasl_seed_preserves_message_frames(self) -> None:
        adapter = PostgreSQLAdapter()
        seed = next(case for case in adapter.seeds() if case.name == "startup-sasl-invalid-final")
        parsed = adapter.frames(seed.payload)
        self.assertIsNotNone(parsed)
        assert parsed is not None
        self.assertEqual([tag for tag, _ in parsed[1]], [b"p", b"p"])

    def test_postgresql_negotiation_regressions_wait_for_server_bytes(self) -> None:
        adapter = PostgreSQLAdapter()
        seeds = {case.name: case for case in adapter.seeds()}
        self.assertEqual(seeds["ssl-repeat"].receive_after, [1, 0])
        self.assertEqual(seeds["gssenc-repeat"].receive_after, [1, 0])
        self.assertEqual(seeds["ssl-gssenc-startup"].receive_after, [1, 1, 0])
        self.assertEqual(seeds["gssenc-ssl-startup"].receive_after, [1, 1, 0])
        auth_sasl = b"R" + (8).to_bytes(4, "big") + (10).to_bytes(4, "big")
        self.assertEqual(
            adapter.response_class(b"NN" + auth_sasl, None),
            "negotiation:N-N|messages:R10",
        )
        notice = b"N" + (5).to_bytes(4, "big") + b"x"
        self.assertEqual(adapter.response_class(notice, None), "messages:N")
        auth_ok = b"R" + (8).to_bytes(4, "big") + (0).to_bytes(4, "big")
        self.assertIn(
            "AuthenticationOk without a valid proof",
            adapter.suspicious_response(seeds["ssl-gssenc-startup"], b"NN" + auth_ok),
        )
        mutated = adapter.mutate(seeds["ssl-gssenc-startup"], random.Random(7), 4096, 1)
        self.assertEqual(mutated.receive_after, [1, 1, 0])
        self.assertEqual(mutated.chunks[:2], seeds["ssl-gssenc-startup"].chunks[:2])
        self.assertLessEqual(len(mutated.payload), 4096)

    def test_wire_runner_receives_between_transcript_chunks(self) -> None:
        events: list[tuple[str, object]] = []

        class FakeSocket:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return None

            def settimeout(self, timeout: float) -> None:
                events.append(("timeout", timeout))

            def sendall(self, value: bytes) -> None:
                events.append(("send", value))

            def recv(self, size: int) -> bytes:
                events.append(("recv", size))
                return b"N" if sum(event[0] == "recv" for event in events) == 1 else b""

            def shutdown(self, _how: int) -> None:
                events.append(("shutdown", None))

        case = WireCase("postgresql", "sync", [b"first", b"second"], receive_after=[1, 0])
        with patch("core.socket.create_connection", return_value=FakeSocket()):
            response, error, _elapsed = run_wire_case("127.0.0.1", 55434, 0.5, case)
        self.assertIsNone(error)
        self.assertEqual(response, b"N")
        self.assertLess(events.index(("recv", 1)), events.index(("send", b"second")))

    def test_wire_feedback_is_bounded_per_persisted_response_class(self) -> None:
        adapter = PostgreSQLAdapter()
        signatures = ("messages:E", "messages:R10", "transport:OSError")
        with tempfile.TemporaryDirectory() as directory:
            artifacts = Path(directory)
            for state_index, signature in enumerate(signatures):
                for case_index in range(5):
                    case = WireCase(
                        "postgresql",
                        f"feedback-{state_index}-{case_index}",
                        [f"feedback-{state_index}-{case_index}".encode()],
                        metadata={"expected_state": signature},
                    )
                    save_case(
                        artifacts,
                        case,
                        {"response_class": signature},
                        b"",
                    )

            with patch("dbfuzz.WIRE_FEEDBACK_CASES_PER_STATE", 2):
                corpus, seen = _load_wire_feedback(
                    artifacts, adapter, adapter.seeds(), 4096
                )

        feedback = corpus[len(adapter.seeds()) :]
        self.assertEqual(seen, set(signatures))
        self.assertEqual(len(feedback), 6)
        self.assertEqual(
            Counter(case.metadata["expected_state"] for case in feedback),
            Counter({signature: 2 for signature in signatures}),
        )

    def test_generic_mutator_is_deterministic(self) -> None:
        self.assertEqual(
            mutate_bytes(b"abcdef", random.Random(1), 512),
            mutate_bytes(b"abcdef", random.Random(1), 512),
        )

    def test_sql_templates_fully_instantiate(self) -> None:
        for engine in ("postgresql", "mysql", "mariadb", "oracle"):
            case = instantiate(templates(engine)[0], random.Random(3), 1024, 1)
            self.assertNotIn("{{", " ".join(case.statements))

    def test_postgresql_binary_seeds_cover_complex_receivers(self) -> None:
        seeds = postgresql_binary_seeds()
        names = {case.type_name for case in seeds}
        self.assertTrue(
            {"int4-array", "numeric", "json", "jsonb", "jsonpath", "int4range", "tsvector", "tsquery"}
            <= names
        )
        self.assertEqual(len({case.type_oid for case in seeds}), len(seeds))
        self.assertTrue(all(case.payload for case in seeds))

    def test_postgresql_binary_seeds_cover_count_driven_receivers(self) -> None:
        seeds = {case.type_name: case for case in postgresql_binary_seeds()}
        expected_oids = {
            "int2vector": 22,
            "oidvector": 30,
            "path": 602,
            "polygon": 604,
            "int4multirange": 4451,
            "pg_snapshot": 5038,
        }
        self.assertEqual(
            {name: seeds[name].type_oid for name in expected_oids},
            expected_oids,
        )

        self.assertEqual(int.from_bytes(seeds["int2vector"].payload[:4], "big"), 1)
        self.assertEqual(int.from_bytes(seeds["oidvector"].payload[:4], "big"), 1)
        self.assertEqual(int.from_bytes(seeds["path"].payload[1:5], "big"), 3)
        self.assertEqual(int.from_bytes(seeds["polygon"].payload[:4], "big"), 4)
        self.assertEqual(int.from_bytes(seeds["int4multirange"].payload[:4], "big"), 2)
        self.assertEqual(int.from_bytes(seeds["pg_snapshot"].payload[:4], "big"), 2)

    def test_postgresql_binary_seeds_cover_network_receiver_branches(self) -> None:
        seeds = {case.type_name: case for case in postgresql_binary_seeds()}

        self.assertEqual(seeds["cidr"].type_oid, 650)
        self.assertEqual(seeds["cidr"].payload, bytes.fromhex("02180104c0000200"))
        self.assertEqual(
            _postgresql_binary_scalar_offsets(seeds["cidr"]),
            [(0, 1), (1, 1), (2, 1), (3, 1)],
        )

        self.assertEqual(seeds["macaddr8"].type_oid, 774)
        self.assertEqual(seeds["macaddr8"].payload, bytes.fromhex("001122334455"))
        self.assertEqual(len(seeds["macaddr8"].payload), 6)
        self.assertEqual(
            _postgresql_binary_scalar_offsets(seeds["macaddr8"]),
            [(offset, 1) for offset in range(6)],
        )

        for name in ("cidr", "macaddr8"):
            mutated = mutate_postgresql_binary(
                seeds[name], random.Random(1), 65_536, 1
            )
            self.assertEqual(len(mutated.payload), len(seeds[name].payload), name)
            self.assertNotEqual(mutated.payload, seeds[name].payload, name)

    def test_postgresql_binary_seed_covers_timetz_receiver_boundaries(self) -> None:
        seed = {case.type_name: case for case in postgresql_binary_seeds()}["timetz"]

        self.assertEqual(seed.type_oid, 1266)
        self.assertEqual(len(seed.payload), 12)
        self.assertEqual(struct.unpack("!qi", seed.payload), (14_706_789_012, -19_800))
        self.assertEqual(_postgresql_binary_semantic_offsets(seed), [(0, 8), (8, 4)])
        self.assertEqual(_postgresql_binary_scalar_offsets(seed), [(0, 8), (8, 4)])

        mutated = mutate_postgresql_binary(seed, random.Random(1), 65_536, 1)
        time_value, zone = struct.unpack("!qi", mutated.payload)
        self.assertEqual(len(mutated.payload), len(seed.payload))
        self.assertNotEqual(mutated.payload, seed.payload)
        self.assertIn(
            time_value,
            {
                14_706_789_012,
                -9_223_372_036_854_775_808,
                -1,
                0,
                1,
                86_399_999_999,
                86_400_000_000,
                86_400_000_001,
                9_223_372_036_854_775_807,
            },
        )
        self.assertIn(
            zone,
            {-57_601, -57_600, -57_599, -19_800, -1, 0, 1, 57_599, 57_600, 57_601},
        )

    def test_postgresql_binary_seed_covers_varbit_length_and_padding(self) -> None:
        seed = {case.type_name: case for case in postgresql_binary_seeds()}["varbit"]

        self.assertEqual(seed.type_oid, 1562)
        self.assertEqual(int.from_bytes(seed.payload[:4], "big", signed=True), 9)
        self.assertEqual(seed.payload[4:], bytes.fromhex("aa80"))
        self.assertEqual(_postgresql_binary_semantic_offsets(seed), [(4, 2)])
        self.assertEqual(_postgresql_binary_scalar_offsets(seed), [(0, 4)])

        mutated = mutate_postgresql_binary(seed, random.Random(1), 65_536, 1)
        self.assertEqual(mutated.payload[:4], seed.payload[:4])
        self.assertEqual(len(mutated.payload), len(seed.payload))
        self.assertNotEqual(mutated.payload, seed.payload)

    def test_postgresql_binary_seed_covers_composite_record_receiver(self) -> None:
        seed = {case.type_name: case for case in postgresql_binary_seeds()}["pg-type-record"]
        self.assertEqual(seed.type_oid, 71)
        self.assertEqual(len(seed.payload), 347)
        self.assertEqual(int.from_bytes(seed.payload[:4], "big"), 32)
        self.assertEqual(int.from_bytes(seed.payload[4:8], "big"), 26)
        self.assertEqual(int.from_bytes(seed.payload[8:12], "big", signed=True), 4)
        self.assertEqual(int.from_bytes(seed.payload[12:16], "big"), 16)

    def test_postgresql_binary_seed_covers_multidimensional_nullable_text_array(self) -> None:
        seed = {case.type_name: case for case in postgresql_binary_seeds()}["text-array"]

        self.assertEqual(seed.type_oid, 1009)
        self.assertEqual(len(seed.payload), 57)
        self.assertEqual(
            struct.unpack("!iii", seed.payload[:12]),
            (2, 1, 25),
        )
        self.assertEqual(
            struct.unpack("!iiii", seed.payload[12:28]),
            (2, -1, 2, 1),
        )
        self.assertEqual(
            _postgresql_binary_semantic_offsets(seed),
            [(32, 5), (45, 3), (52, 5)],
        )
        self.assertEqual(
            _postgresql_binary_scalar_offsets(seed),
            [
                (0, 4),
                (4, 4),
                (8, 4),
                (12, 4),
                (16, 4),
                (20, 4),
                (24, 4),
                (28, 4),
                (37, 4),
                (41, 4),
                (48, 4),
            ],
        )
        self.assertEqual(_postgresql_binary_sql_type(seed), "pg_catalog.text[]")

        mutated = mutate_postgresql_binary(seed, random.Random(1), 65_536, 1)
        self.assertEqual(mutated.payload[:28], seed.payload[:28])
        self.assertEqual(mutated.payload[37:45], seed.payload[37:45])
        self.assertEqual(len(mutated.payload), len(seed.payload))
        self.assertNotEqual(mutated.payload, seed.payload)

    def test_postgresql_binary_mutation_is_changed_bounded_and_deterministic(self) -> None:
        for seed in postgresql_binary_seeds():
            first = mutate_postgresql_binary(seed, random.Random(7), 64, 1)
            second = mutate_postgresql_binary(seed, random.Random(7), 64, 1)
            self.assertEqual(first, second)
            self.assertNotEqual(first.payload, seed.payload)
            self.assertLessEqual(len(first.payload), 64)
            self.assertEqual(first.type_oid, seed.type_oid)
            self.assertEqual(first.parent, seed.name)

    def test_postgresql_binary_mutation_targets_internal_counts_and_lengths(self) -> None:
        seeds = {case.type_name: case for case in postgresql_binary_seeds()}
        for name in ("int4-array", "path", "polygon", "int4multirange", "pg_snapshot", "pg-type-record"):
            seed = seeds[name]
            mutated = mutate_postgresql_binary(seed, random.Random(1), 65_536, 1)
            self.assertEqual(len(mutated.payload), len(seed.payload), name)
            self.assertNotEqual(mutated.payload, seed.payload, name)

    def test_postgresql_binary_semantic_mutation_preserves_nested_framing(self) -> None:
        seeds = {case.type_name: case for case in postgresql_binary_seeds()}
        names = (
            "int2vector",
            "oidvector",
            "int4-array",
            "text-array",
            "pg-type-record",
            "path",
            "polygon",
            "int4range",
            "int4multirange",
            "pg_snapshot",
            "numeric",
            "tsvector",
            "tsquery",
            "json",
            "jsonb",
            "jsonpath",
        )
        for name in names:
            seed = seeds[name]
            spans = _postgresql_binary_semantic_offsets(seed)
            self.assertTrue(spans, name)
            mutable = {
                index
                for offset, width in spans
                for index in range(offset, offset + width)
            }
            mutated = mutate_postgresql_binary(seed, random.Random(1), 65_536, 1)
            changed = {
                index
                for index, (before, after) in enumerate(zip(seed.payload, mutated.payload))
                if before != after
            }
            self.assertTrue(changed, name)
            self.assertLessEqual(changed, mutable, name)
            self.assertEqual(len(mutated.payload), len(seed.payload), name)

    def test_postgresql_numeric_semantic_mutation_preserves_wire_domain(self) -> None:
        seed = {
            case.type_name: case for case in postgresql_binary_seeds()
        }["numeric"]
        mutated = mutate_postgresql_binary(seed, random.Random(1), 65_536, 1)

        self.assertEqual(mutated.payload[:8], seed.payload[:8])
        self.assertEqual(len(mutated.payload), len(seed.payload))
        digit_count = int.from_bytes(mutated.payload[:2], "big")
        digits = [
            int.from_bytes(mutated.payload[offset : offset + 2], "big")
            for offset in range(8, len(mutated.payload), 2)
        ]
        self.assertEqual(len(digits), digit_count)
        self.assertTrue(all(0 <= digit < 10_000 for digit in digits))
        self.assertNotEqual(mutated.payload, seed.payload)

    def test_postgresql_binary_text_semantic_mutation_preserves_grammar(self) -> None:
        seeds = {case.type_name: case for case in postgresql_binary_seeds()}
        for name in ("json", "jsonb", "jsonpath"):
            seed = seeds[name]
            mutated = mutate_postgresql_binary(seed, random.Random(1), 65_536, 1)
            if name != "json":
                self.assertEqual(mutated.payload[0], 1, name)
            self.assertEqual(len(mutated.payload), len(seed.payload), name)
            self.assertNotEqual(mutated.payload, seed.payload, name)
        self.assertEqual(seeds["json"].type_oid, 114)
        json.loads(
            mutate_postgresql_binary(
                seeds["json"], random.Random(1), 65_536, 1
            ).payload
        )
        json.loads(
            mutate_postgresql_binary(
                seeds["jsonb"], random.Random(1), 65_536, 1
            ).payload[1:]
        )

    def test_postgresql_json_binary_receiver_regression(self) -> None:
        seed = {
            case.type_name: case for case in postgresql_binary_seeds()
        }["json"]
        spans = _postgresql_binary_semantic_offsets(seed)
        mutated = mutate_postgresql_binary(seed, random.Random(1), 65_536, 1)

        self.assertEqual(seed.type_oid, 114)
        self.assertEqual(json.loads(seed.payload)["nested"]["n"], 99)
        self.assertTrue(spans)
        self.assertEqual(len(mutated.payload), len(seed.payload))
        self.assertIsInstance(json.loads(mutated.payload), dict)
        self.assertNotEqual(mutated.payload, seed.payload)

    def test_postgresql_binary_execution_uses_binary_bind_format(self) -> None:
        calls: list[tuple[object, ...]] = []
        marker = object()

        class FakePGConn:
            def exec_params(self, *args):
                calls.append(args)
                return marker

        case = postgresql_binary_seeds()[0]
        self.assertIs(execute_postgresql_binary(FakePGConn(), case), marker)
        command, values, types, formats, result_format = calls[0]
        self.assertEqual(command, b"SELECT $1")
        self.assertEqual(values, [case.payload])
        self.assertEqual(types, [case.type_oid])
        self.assertEqual([int(value) for value in formats], [1])
        self.assertEqual(int(result_format), 0)

    def test_postgresql_binary_mixed_execution_uses_per_parameter_formats(self) -> None:
        calls: list[tuple[object, ...]] = []
        marker = object()

        class FakePGConn:
            def exec_params(self, *args):
                calls.append(args)
                return marker

        case = postgresql_binary_seeds()[0]
        self.assertIs(execute_postgresql_binary_mixed(FakePGConn(), case), marker)
        command, values, types, formats, result_format = calls[0]
        self.assertEqual(command, b"SELECT $1, $2")
        self.assertEqual(values, [b"1", case.payload])
        self.assertEqual(types, [23, case.type_oid])
        self.assertEqual([int(value) for value in formats], [0, 1])
        self.assertEqual(int(result_format), 0)

    def test_postgresql_binary_prepared_execution_reuses_named_statement(self) -> None:
        from psycopg import pq

        calls: list[tuple[str, tuple[object, ...]]] = []

        class FakeResult:
            def __init__(self, status):
                self.status = status

        first = FakeResult(pq.ExecStatus.TUPLES_OK)
        second = FakeResult(pq.ExecStatus.TUPLES_OK)

        class FakePGConn:
            def prepare(self, *args):
                calls.append(("prepare", args))
                return FakeResult(pq.ExecStatus.COMMAND_OK)

            def exec_prepared(self, *args):
                calls.append(("execute", args))
                return first if len(calls) == 2 else second

        case = postgresql_binary_seeds()[0]
        self.assertIs(execute_postgresql_binary_prepared(FakePGConn(), case), second)
        self.assertEqual([kind for kind, _args in calls], ["prepare", "execute", "execute"])
        statement_name, command, types = calls[0][1]
        self.assertEqual(statement_name, b"tf_binary_receiver")
        self.assertEqual(command, b"SELECT $1")
        self.assertEqual(types, [case.type_oid])
        for _kind, args in calls[1:]:
            name, values, formats, result_format = args
            self.assertEqual(name, statement_name)
            self.assertEqual(values, [case.payload])
            self.assertEqual([int(value) for value in formats], [1])
            self.assertEqual(int(result_format), 0)

    def test_postgresql_binary_portal_transport_suspends_and_closes(self) -> None:
        case = {case.type_name: case for case in postgresql_binary_seeds()}["int4"]
        transcript = postgresql_binary_portal_transcript(case)
        frames: list[tuple[bytes, bytes]] = []
        cursor = 0
        while cursor < len(transcript):
            length = struct.unpack("!I", transcript[cursor + 1 : cursor + 5])[0]
            frames.append(
                (
                    transcript[cursor : cursor + 1],
                    transcript[cursor + 5 : cursor + 1 + length],
                )
            )
            cursor += 1 + length

        self.assertEqual(b"".join(kind for kind, _body in frames), b"PDBDEDEECCS")
        execute_rows = [
            struct.unpack("!I", body[-4:])[0]
            for kind, body in frames
            if kind == b"E"
        ]
        self.assertEqual(execute_rows, [1, 1, 0])
        self.assertIn(case.payload, next(body for kind, body in frames if kind == b"B"))

        def response(kind: bytes, payload: bytes = b"") -> bytes:
            return kind + struct.pack("!I", len(payload) + 4) + payload

        client, server = socket.socketpair()
        try:
            server.sendall(
                b"".join(
                    response(bytes((kind,)), b"I" if kind == ord("Z") else b"")
                    for kind in b"1tT2TDsTDsDC33Z"
                )
            )

            class FakePGConn:
                ssl_in_use = False
                socket = client.fileno()

            result = execute_postgresql_binary_portal(FakePGConn(), case, 1500)
            server.settimeout(1.0)
            received = bytearray()
            while len(received) < len(transcript):
                received.extend(server.recv(len(transcript) - len(received)))

            self.assertEqual(bytes(received), transcript)
            self.assertEqual(result.status_name, "TUPLES_OK")
            self.assertEqual(result.rows, 3)
            self.assertEqual(result.message_types, "1tT2TDsTDsDC33Z")
        finally:
            client.close()
            server.close()

    def test_postgresql_binary_function_transport_frames_and_reads_result(self) -> None:
        case = {case.type_name: case for case in postgresql_binary_seeds()}["int4"]
        function_oid = 2407
        transcript = postgresql_binary_function_transcript(case, function_oid)
        self.assertEqual(transcript[:1], b"F")
        self.assertEqual(struct.unpack("!I", transcript[1:5])[0], len(transcript) - 1)
        body = transcript[5:]
        self.assertEqual(struct.unpack("!I", body[:4])[0], function_oid)
        self.assertEqual(struct.unpack("!HhH", body[4:10]), (1, 1, 1))
        self.assertEqual(struct.unpack("!i", body[10:14])[0], len(case.payload))
        self.assertEqual(body[14 : 14 + len(case.payload)], case.payload)
        self.assertEqual(struct.unpack("!h", body[-2:])[0], 1)

        def response(kind: bytes, payload: bytes = b"") -> bytes:
            return kind + struct.pack("!I", len(payload) + 4) + payload

        client, server = socket.socketpair()
        try:
            server.sendall(
                response(b"V", struct.pack("!i", len(case.payload)) + case.payload)
                + response(b"Z", b"I")
            )

            class FakePGConn:
                ssl_in_use = False
                socket = client.fileno()

            result = execute_postgresql_binary_function(
                FakePGConn(), case, function_oid, 1500
            )
            server.settimeout(1.0)
            received = bytearray()
            while len(received) < len(transcript):
                received.extend(server.recv(len(transcript) - len(received)))

            self.assertEqual(bytes(received), transcript)
            self.assertEqual(result.status_name, "FUNCTION_OK")
            self.assertEqual(result.result_len, len(case.payload))
            self.assertEqual(result.message_types, "VZ")
        finally:
            client.close()
            server.close()

    def test_postgresql_binary_function_oids_require_exact_argument_types(self) -> None:
        class FakeResult:
            def fetchall(self):
                return [(23, 2407), (25, 2415)]

        class FakeConnection:
            def execute(self, query, params):
                self.query = query
                self.params = params
                return FakeResult()

        connection = FakeConnection()
        cases = list(postgresql_binary_seeds())
        self.assertEqual(
            _postgresql_binary_function_oids(connection, cases),
            {23: 2407, 25: 2415},
        )
        self.assertIn("p.proargtypes[0] = t.oid", connection.query)
        self.assertEqual(set(connection.params[0]), {case.type_oid for case in cases})

    def test_postgresql_binary_copy_transport_preserves_framing(self) -> None:
        case = postgresql_binary_seeds()[0]
        stream = postgresql_binary_copy_stream(case)
        self.assertEqual(stream[:11], b"PGCOPY\n\xff\r\n\x00")
        self.assertEqual(struct.unpack("!ii", stream[11:19]), (0, 0))
        self.assertEqual(struct.unpack("!h", stream[19:21]), (1,))
        self.assertEqual(struct.unpack("!i", stream[21:25]), (len(case.payload),))
        self.assertEqual(stream[25 : 25 + len(case.payload)], case.payload)
        self.assertEqual(struct.unpack("!h", stream[-2:]), (-1,))

        writes: list[bytes] = []
        statements: list[str] = []

        class FakeCopy:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def write(self, value: bytes) -> None:
                writes.append(value)

        class FakeCursor:
            def copy(self, statement: str):
                statements.append(statement)
                return FakeCopy()

        class FakeConnection:
            def execute(self, statement: str) -> None:
                statements.append(statement)

            def cursor(self):
                return FakeCursor()

        self.assertEqual(execute_postgresql_binary_copy(FakeConnection(), case), 1)
        self.assertEqual(writes, [stream])
        self.assertIn("pg_catalog.bool", statements[0])
        self.assertIn("FORMAT BINARY", statements[1])

        seed_count = len(postgresql_binary_seeds())
        function_seed_count = 26
        self.assertEqual(
            _postgresql_binary_transport(0, seed_count, function_seed_count),
            "binary-bind",
        )
        self.assertEqual(
            _postgresql_binary_transport(seed_count, seed_count, function_seed_count),
            "binary-copy",
        )
        self.assertEqual(
            _postgresql_binary_transport(seed_count * 2, seed_count, function_seed_count),
            "binary-bind-mixed",
        )
        self.assertEqual(
            _postgresql_binary_transport(seed_count * 3, seed_count, function_seed_count),
            "binary-bind-prepared",
        )
        self.assertEqual(
            _postgresql_binary_transport(seed_count * 4, seed_count, function_seed_count),
            "binary-bind-portal",
        )
        self.assertEqual(
            _postgresql_binary_transport(seed_count * 5, seed_count, function_seed_count),
            "binary-function-call",
        )
        mutation_start = seed_count * 5 + function_seed_count
        self.assertEqual(
            [
                _postgresql_binary_transport(i, seed_count, function_seed_count)
                for i in range(mutation_start, mutation_start + 12)
            ],
            [
                "binary-copy",
                "binary-bind-mixed",
                "binary-bind-prepared",
                "binary-bind-portal",
                "binary-function-call",
                "binary-bind",
                "binary-copy",
                "binary-bind-mixed",
                "binary-bind-prepared",
                "binary-bind-portal",
                "binary-function-call",
                "binary-bind",
            ],
        )

    def test_postgresql_binary_parent_selection_preserves_deep_inputs(self) -> None:
        seeds = list(postgresql_binary_seeds())
        accepted = [
            seeds[0],
            *(
                type(seeds[1])(
                    f"bytea-accepted-{index}",
                    seeds[1].type_name,
                    seeds[1].type_oid,
                    index.to_bytes(2, "big"),
                    parent=seeds[1].name,
                )
                for index in range(1, 201)
            ),
        ]
        accepted_type_indices = _postgresql_binary_type_indices(accepted)
        with patch("sql_fuzz.POSTGRESQL_ACCEPTED_PARENT_RATIO", 1.0):
            selected = [
                _choose_postgresql_binary_parent(
                    accepted, accepted_type_indices, accepted, random.Random(index)
                )
                for index in range(2000)
            ]

        # Select receiver types uniformly even when an always-accepting type
        # occupies nearly the entire retained corpus.
        bool_count = sum(case.type_name == "bool" for case in selected)
        self.assertGreater(bool_count, 900)
        self.assertLess(bool_count, 1100)

        malformed = [
            type(seeds[0])(
                f"malformed-{index}",
                seeds[0].type_name,
                seeds[0].type_oid,
                bytes([index + 1]),
                parent=seeds[0].name,
            )
            for index in range(8)
        ]
        with patch("sql_fuzz.POSTGRESQL_ACCEPTED_PARENT_RATIO", 0.0):
            selected = [
                _choose_postgresql_binary_parent(
                    accepted,
                    accepted_type_indices,
                    malformed,
                    random.Random(index),
                )
                for index in range(100)
            ]
        self.assertTrue(all(case in malformed for case in selected))

        with self.assertRaises(ValueError):
            _choose_postgresql_binary_parent([], {}, [], random.Random(1))

    def test_postgresql_binary_accepted_corpus_persists_and_rotates_safely(self) -> None:
        seeds = list(postgresql_binary_seeds())
        first = type(seeds[0])(
            "bool-accepted", "bool", seeds[0].type_oid, b"\x01", seeds[0].name
        )
        second = type(seeds[1])(
            "bytea-accepted-a", "bytea", seeds[1].type_oid, b"accepted-a", seeds[1].name
        )
        third = type(seeds[1])(
            "bytea-accepted-b", "bytea", seeds[1].type_oid, b"accepted-b", second.name
        )
        limit = len(seeds) + 2

        accepted = [*seeds, first, second]
        accepted_hashes = {_postgresql_binary_digest(case) for case in accepted}
        accepted_type_indices = _postgresql_binary_type_indices(accepted)
        update = _remember_postgresql_binary_accepted_case(
            accepted,
            accepted_hashes,
            accepted_type_indices,
            third,
            limit,
            len(seeds),
            random.Random(7),
        )
        self.assertEqual(update, "replaced")
        self.assertEqual(accepted[: len(seeds)], seeds)
        self.assertEqual(len(accepted), limit)
        self.assertIn(_postgresql_binary_digest(third), accepted_hashes)
        self.assertEqual(
            accepted_hashes,
            {_postgresql_binary_digest(case) for case in accepted},
        )

        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory) / "accepted.jsonl"
            _save_postgresql_binary_accepted_corpus(
                checkpoint, accepted, len(seeds), limit
            )
            lines = checkpoint.read_text(encoding="utf-8").splitlines()
            oversized = base64.b64encode(b"x" * 65).decode("ascii")
            skewed_bytea = [
                json.dumps(
                    {
                        "type_name": "bytea",
                        "type_oid": seeds[1].type_oid,
                        "payload_b64": base64.b64encode(
                            f"skew-{index}".encode()
                        ).decode("ascii"),
                    }
                )
                for index in range(20)
            ]
            checkpoint.write_text(
                "\n".join(
                    (
                        lines[0],
                        '{"type_name":"bool","type_oid":999,"payload_b64":"AA=="}',
                        '{"type_name":"bool","type_oid":16,"payload_b64":"***"}',
                        json.dumps(
                            {
                                "type_name": "bool",
                                "type_oid": 16,
                                "payload_b64": oversized,
                            }
                        ),
                        lines[1],
                        lines[1],
                        *lines[2:],
                        *skewed_bytea,
                    )
                )
                + "\n",
                encoding="utf-8",
            )
            loaded = _load_postgresql_binary_accepted_corpus(
                checkpoint, seeds, 64, limit
            )

        self.assertEqual(
            {_postgresql_binary_digest(case) for case in loaded},
            {_postgresql_binary_digest(case) for case in accepted[len(seeds) :]},
        )
        self.assertEqual(
            {type_name: sum(case.type_name == type_name for case in loaded)
             for type_name in ("bool", "bytea")},
            {"bool": 1, "bytea": 1},
        )
        self.assertTrue(all(case.parent == "accepted-checkpoint" for case in loaded))

    def test_postgresql_binary_artifacts_deduplicate_response_states(self) -> None:
        seed = list(postgresql_binary_seeds())[0]
        second = type(seed)(
            "bool-second", seed.type_name, seed.type_oid, b"\x01", seed.name
        )
        result = {
            "transport": "binary-bind",
            "type_name": "bool",
            "status": "TUPLES_OK",
            "sqlstate": "",
            "error_shape": "",
            "protocol_messages": "",
        }
        signature = _postgresql_binary_response_signature(
            "binary-bind", "bool", "TUPLES_OK", "", "", ""
        )

        with tempfile.TemporaryDirectory() as directory:
            artifacts = Path(directory)
            save_postgresql_binary_case(
                artifacts, seed, {**result, "signature": signature}
            )
            # Legacy artifacts have no explicit signature and must collapse
            # onto the same state rather than forcing one save per batch.
            save_postgresql_binary_case(artifacts, second, result)
            malformed = artifacts / "postgresql" / "malformed"
            malformed.mkdir()
            (malformed / "result.json").write_text("{", encoding="utf-8")

            loaded = _load_postgresql_binary_artifact_signatures(
                artifacts / "postgresql"
            )

        self.assertEqual(loaded, {signature})
        self.assertNotEqual(
            signature,
            _postgresql_binary_response_signature(
                "binary-bind-portal", "bool", "TUPLES_OK", "", "", "1tT2Z"
            ),
        )

    def test_postgresql_splitter_preserves_dollar_bodies(self) -> None:
        sql = "SELECT ';'; DO $$ BEGIN PERFORM ';'; END $$; SELECT 2;"
        self.assertEqual(len(split_sql(sql)), 3)

    def test_postgresql_psql_filter_removes_copy_payload(self) -> None:
        sql = "\\set x 1\nCOPY t FROM STDIN;\n1\t2\n\\.\nSELECT 1;\n"
        filtered = strip_psql_lines(sql)
        self.assertNotIn("1\t2", filtered)
        self.assertEqual(len(split_sql(filtered)), 2)

    def test_postgresql_transaction_round_trip(self) -> None:
        payload = wrap_transaction(["SELECT 1", "SELECT 'x;y'"])
        self.assertEqual(unwrap_transaction(payload), ["SELECT 1", "SELECT 'x;y'"])

    def test_postgresql_single_user_lanes_enable_multiline_input(self) -> None:
        # Without -j, postgres --single treats every newline as a command
        # delimiter and rejects continuation lines in upstream regression SQL.
        for script_name in (
            "postgresql-afl-campaign.sh",
            "postgresql-afl-target.sh",
            "postgresql-afl-triage.sh",
        ):
            script = (HERE / script_name).read_text(encoding="utf-8")
            self.assertIn("--single -j ", script, script_name)

    def test_postgresql_copy_uses_dedicated_lane(self) -> None:
        self.assertFalse(usable_statement("COPY t TO STDOUT"))
        self.assertTrue(usable_statement("SELECT 1"))

    def test_postgresql_transaction_control_with_comment_is_rejected(self) -> None:
        self.assertFalse(usable_statement("-- transaction\nCOMMIT WORK"))
        self.assertFalse(usable_statement("/* x */ PREPARE TRANSACTION 'x'"))
        self.assertTrue(usable_statement("CREATE PROCEDURE p() AS $$ BEGIN NULL; END $$ LANGUAGE plpgsql"))

    def test_postgresql_control_functions_are_not_seeded(self) -> None:
        self.assertFalse(usable_statement("SELECT pg_terminate_backend(pg_backend_pid())"))

    def test_postgresql_timeout_guards_cannot_be_overridden(self) -> None:
        unsafe = (
            "RESET statement_timeout",
            "-- regression setup\nSET LOCAL lock_timeout = 0",
            'SET SESSION "statement_timeout" = 0',
            'RESET "lock_timeout"',
            "RESET ALL",
            "SELECT set_config('statement_timeout', '0', false)",
        )
        for statement in unsafe:
            self.assertFalse(usable_statement(statement))

        payload = wrap_transaction([*unsafe, "SELECT 1"])
        self.assertEqual(unwrap_transaction(payload), ["SELECT 1"])
        self.assertTrue(usable_statement("SELECT current_setting('statement_timeout')"))

        # Existing minimized corpora can predate this filter.  Verify that the
        # custom mutator repairs such a seed before executing its mutation.
        legacy = (
            b"BEGIN;\n"
            b"SET LOCAL statement_timeout = '750ms';\n"
            b"SET LOCAL lock_timeout = '100ms';\n"
            b"RESET statement_timeout;\n"
            b"SELECT * FROM generate_series(1, 2147483647);\n"
            b"ROLLBACK;\n"
        )
        pg_mutator.init(20260927)
        mutated = pg_mutator.fuzz(legacy, b"", 4096)
        self.assertNotIn(b"RESET statement_timeout", mutated)

    def test_postgresql_mutator_filters_delay_functions(self) -> None:
        delayed = (
            "SELECT pg_sleep(0.1)",
            "SELECT pg_catalog.pg_sleep_for(interval '100 milliseconds')",
            "SELECT pg_sleep_until(clock_timestamp() + interval '1 hour')",
        )
        quoted_or_commented = (
            "SELECT 'pg_sleep(3600)'",
            "SELECT 1 -- pg_sleep(3600)",
        )
        self.assertTrue(
            all(not mutation_resource_safe(statement) for statement in delayed)
        )
        self.assertTrue(
            all(mutation_resource_safe(statement) for statement in quoted_or_commented)
        )

        repaired = pg_mutator._bounded([*delayed, "SELECT date '2000-01-01'"], 4096)
        self.assertEqual(unwrap_transaction(repaired), ["SELECT date '2000-01-01'"])

    def test_postgresql_mutator_filters_static_resource_amplifiers(self) -> None:
        explosive = (
            "SELECT to_tsvector('simple', repeat(repeat('A', 4096), 65535))",
            "SELECT to_timestamp('Fri 1-Jan-0', repeat(repeat('A', 4096), 4096))",
            "SELECT array_fill(NULL::text, ARRAY[256,65535])",
            "SELECT array_fill('juhu'::text, ARRAY[32767,256])",
            "SELECT array_fill(7, ARRAY[65535,255], ARRAY[2,2])",
            "SELECT array_fill(repeat('A', 4096)::text, ARRAY[65535,3])",
        )
        safe_boundaries = (
            "SELECT repeat('A', 4096)",
            "SELECT array_fill(7, ARRAY[256,256])",
            "SELECT array_fill(repeat('A', 16)::text, ARRAY[256,256])",
            "SELECT 2147483647",
            "SELECT 'repeat(''A'', 2147483647)'",
            "SELECT 'array_fill(7, ARRAY[65535,255])'",
            "SELECT 1 -- repeat('A', 2147483647)",
        )
        self.assertTrue(all(not mutation_resource_safe(statement) for statement in explosive))
        self.assertTrue(all(mutation_resource_safe(statement) for statement in safe_boundaries))

        repaired = pg_mutator._bounded([*explosive, "SELECT 1"], 4096)
        self.assertEqual(unwrap_transaction(repaired), ["SELECT 1"])

    def test_postgresql_mutator_filters_static_generate_series_amplifiers(self) -> None:
        explosive = (
            "SELECT * FROM generate_series(-5, 32767)",
            "SELECT * FROM generate_series(-5, 2147483647)",
            "SELECT * FROM generate_series(2147483647, -2147483648, -1)",
            "SELECT * FROM generate_series(1, 256) a, generate_series(1, 256) b",
            "SELECT * FROM generate_series(10, 1) z, generate_series(1, 2147483647) g",
        )
        safe_boundaries = (
            "SELECT * FROM generate_series(1, 4096)",
            "SELECT * FROM generate_series(4096, 1, -1)",
            "SELECT * FROM generate_series(10, 1)",
            "SELECT * FROM generate_series(1, 10, 0)",
            "SELECT 'generate_series(1, 2147483647)'",
            "SELECT 1 -- generate_series(1, 2147483647)",
        )

        self.assertTrue(all(not mutation_resource_safe(statement) for statement in explosive))
        self.assertTrue(all(mutation_resource_safe(statement) for statement in safe_boundaries))

        repaired = pg_mutator._bounded([*explosive, "SELECT 1"], 4096)
        self.assertEqual(unwrap_transaction(repaired), ["SELECT 1"])

    def test_postgresql_temp_relations_become_rollback_scoped_regular_relations(self) -> None:
        self.assertEqual(
            standalone_safe("CREATE TEMP TABLE t(a int) ON COMMIT DROP"),
            "CREATE TABLE t(a int)",
        )

    def test_postgresql_custom_mutator_preserves_wrapper(self) -> None:
        pg_mutator.init(7)
        payload = pg_mutator.fuzz(wrap_transaction(["SELECT 1"]), b"", 4096)
        # AFL++ 4.09c's Python bridge misreads a bytes return as bytearray;
        # keeping this type assertion prevents a fuzzer-process segfault.
        self.assertIsInstance(payload, bytearray)
        self.assertIsInstance(pg_mutator.describe(64), bytes)
        text = payload.decode()
        self.assertTrue(text.startswith("BEGIN;"))
        self.assertTrue(text.endswith("ROLLBACK;\n"))
        self.assertLessEqual(len(payload), 4096)

    def test_postgresql_custom_mutator_caps_afl_stage_budget(self) -> None:
        seed = wrap_transaction(["SELECT 1"])
        self.assertEqual(pg_mutator.fuzz_count(seed), 256)

    def test_postgresql_custom_mutator_does_not_return_unchanged_input(self) -> None:
        pg_mutator.init(20260927)
        seeds = (
            wrap_transaction(["SELECT 1"]),
            wrap_transaction(["SELECT 'text'"]),
            wrap_transaction(["CREATE TABLE t(a int)", "INSERT INTO t VALUES (1)"]),
        )
        for seed in seeds:
            for _ in range(128):
                self.assertNotEqual(bytes(pg_mutator.fuzz(seed, b"", 4096)), seed)

    def test_doctor_checks_only_selected_engine(self) -> None:
        fake_manifest = {
            "targets": {
                "postgresql": {"host": "127.0.0.1", "port": 55432},
                "redis": {"host": "127.0.0.1", "port": 56379},
            }
        }
        output = StringIO()
        with (
            patch("dbfuzz.manifest", return_value=fake_manifest),
            patch("dbfuzz.socket.create_connection") as connect,
            redirect_stdout(output),
        ):
            self.assertEqual(doctor(["postgresql"]), 0)
        connect.assert_called_once_with(("127.0.0.1", 55432), timeout=0.25)
        self.assertEqual(set(json.loads(output.getvalue())["targets"]), {"postgresql"})

    def test_file_log_monitor_reads_only_recent_server_logs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old = root / "asan.old"
            new = root / "asan.new"
            old.write_text("AddressSanitizer: old\n", encoding="utf-8")
            epoch = time.time()
            old.touch()
            old_time = epoch - 10
            old.chmod(0o600)
            import os

            os.utime(old, (old_time, old_time))
            new.write_text("AddressSanitizer: new\n", encoding="utf-8")
            monitor = FileLogMonitor(str(root / "asan.*"))
            logs = monitor.logs_since(epoch)
            self.assertIn("AddressSanitizer: new", logs)
            self.assertNotIn("AddressSanitizer: old", logs)


if __name__ == "__main__":
    unittest.main()
