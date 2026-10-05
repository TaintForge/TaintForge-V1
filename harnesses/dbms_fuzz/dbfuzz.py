#!/usr/bin/env python3
"""Local-only structured fuzz runner for Redis, MySQL, MariaDB, PostgreSQL, and Oracle."""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import shutil
import socket
import sys
import time
from pathlib import Path
from typing import Any

from core import (
    CRASH_RE,
    DockerMonitor,
    FileLogMonitor,
    WireCase,
    assert_loopback,
    run_wire_case,
    save_case,
    sha256_short,
    state_changed,
)
from protocols import get_adapter
from sql_fuzz import run_postgresql_binary_campaign, run_sql_campaign


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_ARTIFACTS = ROOT / "workspace" / "db-fuzz"
MANIFEST = Path(__file__).with_name("targets.json")
WIRE_FEEDBACK_CASES_PER_STATE = 32


def manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def doctor(engines: list[str] | None = None) -> int:
    config = manifest()
    selected = set(engines or config["targets"])
    tools = [
        "docker",
        "clang",
        "clang++",
        "gcc",
        "g++",
        "afl-fuzz",
        "afl-clang-lto",
        "gdb",
        "psql",
        "mysql",
        "redis-cli",
    ]
    result = {
        "tools": {tool: shutil.which(tool) for tool in tools},
        "python": {},
        "targets": {},
    }
    for module in ("psycopg", "pymysql", "oracledb"):
        try:
            __import__(module)
            result["python"][module] = True
        except ImportError:
            result["python"][module] = False
    for engine, item in config["targets"].items():
        if engine not in selected:
            continue
        source = ROOT / item["source"] if item.get("source") else None
        host = item.get("host", "127.0.0.1")
        port = int(item["port"])
        reachable = False
        try:
            assert_loopback(host)
            with socket.create_connection((host, port), timeout=0.25):
                reachable = True
        except (OSError, SystemExit):
            pass
        result["targets"][engine] = {
            "source": str(source) if source else None,
            "source_present": bool(source and source.is_dir()),
            "endpoint": f"{host}:{port}",
            "reachable": reachable,
            "container": item.get("container"),
            "instrumentation": item.get("instrumentation"),
        }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def target_defaults(engine: str) -> dict:
    values = manifest()["targets"]
    normalized = "postgresql" if engine in {"postgres", "pgsql"} else engine
    if normalized not in values:
        raise SystemExit(f"no target manifest entry for {engine}")
    return values[normalized]


def _load_wire_feedback(
    artifacts: Path,
    adapter: Any,
    base_seeds: list[WireCase],
    max_corpus: int,
) -> tuple[list[WireCase], set[str]]:
    """Load a bounded, response-class-stratified wire feedback corpus.

    Wire batches run in fresh processes, while their artifacts persist.  If
    every prior input is loaded, repeated instances of a small number of
    externally visible states eventually fill the corpus and crowd out rarer
    protocol states.  Keep recent representatives per response class and
    carry the complete set of observed classes across batch boundaries.
    """
    corpus = list(base_seeds)
    corpus_hashes = {sha256_short(case.payload) for case in corpus}
    seen: set[str] = set()
    persisted = artifacts / adapter.name
    if not persisted.is_dir():
        return corpus, seen

    records: list[tuple[int, str, str, WireCase]] = []
    for result_path in persisted.glob("*/result.json"):
        case_path = result_path.with_name("case.json")
        try:
            result = json.loads(result_path.read_text(encoding="utf-8"))
            signature = result["response_class"]
            candidate = WireCase.from_serializable(
                json.loads(case_path.read_text(encoding="utf-8"))
            )
            modified = result_path.stat().st_mtime_ns
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            continue
        if not isinstance(signature, str) or not signature:
            continue
        if candidate.engine != adapter.name:
            continue
        seen.add(signature)
        records.append((modified, str(result_path), signature, candidate))

    selected_per_state: dict[str, int] = {}
    for _modified, _path, signature, candidate in sorted(records, reverse=True):
        if len(corpus) >= max_corpus:
            break
        if selected_per_state.get(signature, 0) >= WIRE_FEEDBACK_CASES_PER_STATE:
            continue
        digest = sha256_short(candidate.payload)
        if digest in corpus_hashes:
            continue
        corpus.append(candidate)
        corpus_hashes.add(digest)
        selected_per_state[signature] = selected_per_state.get(signature, 0) + 1

    return corpus, seen


def run_wire(args: argparse.Namespace) -> int:
    adapter = get_adapter(args.engine)
    defaults = target_defaults(adapter.name)
    host = args.host or defaults.get("host", "127.0.0.1")
    port = args.port or int(defaults.get("port", adapter.default_port))
    container = args.container if args.container is not None else defaults.get("container")
    assert_loopback(host)

    rng = random.Random(args.seed)
    base_seeds = adapter.seeds()
    artifacts = Path(args.artifacts)
    corpus, seen = _load_wire_feedback(
        artifacts, adapter, base_seeds, args.max_corpus
    )
    corpus_hashes = {sha256_short(case.payload) for case in corpus}
    persisted_states = len(seen)
    persisted_feedback_cases = len(corpus) - len(base_seeds)
    cases_total = len(base_seeds) + args.iterations

    monitor = DockerMonitor(container)
    sanitizer_monitor = FileLogMonitor(args.sanitizer_log_glob)
    suspicious = 0
    for index in range(cases_total):
        if index < len(base_seeds):
            case = base_seeds[index]
        else:
            case = adapter.mutate(rng.choice(corpus), rng, args.max_input, index - len(base_seeds))
        before = monitor.snapshot()
        log_epoch = time.time()
        response, error, elapsed = run_wire_case(host, port, args.timeout, case, args.receive_limit)
        after = monitor.snapshot()
        logs = "\n".join(
            part
            for part in (monitor.logs_since(log_epoch), sanitizer_monitor.logs_since(log_epoch))
            if part
        )
        signature = adapter.response_class(response, error)
        response_alerts = adapter.suspicious_response(case, response)
        crash = bool(CRASH_RE.search(logs)) or state_changed(before, after)
        novel = signature not in seen
        seen.add(signature)
        digest = sha256_short(case.payload)
        if novel and digest not in corpus_hashes and len(corpus) < args.max_corpus:
            corpus.append(case)
            corpus_hashes.add(digest)
        result = {
            "engine": adapter.name,
            "case": case.name,
            "input_len": len(case.payload),
            "response_len": len(response),
            "response_class": signature,
            "error": error,
            "elapsed_seconds": round(elapsed, 6),
            "novel_state": novel,
            "response_alerts": response_alerts,
            "crash_signal": crash,
            "container_before": before,
            "container_after": after,
            "container_logs": logs if crash else "",
        }
        suspicious_case = crash or bool(response_alerts)
        mark = "SUSPICIOUS" if suspicious_case else ("novel" if novel else "ok")
        print(
            f"[{index + 1:06d}/{cases_total:06d}] {mark:10s} {case.name} "
            f"in={len(case.payload)} out={len(response)} {signature}"
        , flush=True)
        if suspicious_case or novel:
            path = save_case(artifacts, case, result, response)
            if suspicious_case:
                suspicious += 1
                print(f"  artifact: {path}")

    print(
        json.dumps(
            {
                "engine": adapter.name,
                "cases": cases_total,
                "states": len(seen),
                "new_states": len(seen) - persisted_states,
                "corpus": len(corpus),
                "persisted_feedback_cases": persisted_feedback_cases,
                "suspicious": suspicious,
            }
        )
    )
    return 2 if suspicious else 0


def replay(args: argparse.Namespace) -> int:
    value = json.loads(Path(args.case).read_text(encoding="utf-8"))
    case = WireCase.from_serializable(value)
    defaults = target_defaults(case.engine)
    host = args.host or defaults.get("host", "127.0.0.1")
    port = args.port or int(defaults["port"])
    assert_loopback(host)
    response, error, elapsed = run_wire_case(host, port, args.timeout, case)
    adapter = get_adapter(case.engine)
    print(
        json.dumps(
            {
                "case": case.name,
                "response_len": len(response),
                "response_class": adapter.response_class(response, error),
                "error": error,
                "elapsed_seconds": round(elapsed, 6),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 1 if error else 0


def minimize(args: argparse.Namespace) -> int:
    case_path = Path(args.case)
    case = WireCase.from_serializable(json.loads(case_path.read_text(encoding="utf-8")))
    defaults = target_defaults(case.engine)
    host = args.host or defaults.get("host", "127.0.0.1")
    port = args.port or int(defaults["port"])
    container = args.container if args.container is not None else defaults.get("container")
    assert_loopback(host)
    adapter = get_adapter(case.engine)
    monitor = DockerMonitor(container)

    prior_result = case_path.with_name("result.json")
    saved = json.loads(prior_result.read_text(encoding="utf-8")) if prior_result.is_file() else {}
    expected_signature = args.signature or saved.get("response_class")
    expect_security_signal = bool(saved.get("crash_signal") or saved.get("response_alerts"))
    if not expected_signature and not expect_security_signal:
        raise SystemExit("minimize requires --signature or a sibling result.json")

    attempts = 0

    def preserves(data: bytes) -> bool:
        nonlocal attempts
        attempts += 1
        trial = WireCase(
            case.engine,
            f"{case.name}-min",
            [data],
            receive_first=case.receive_first,
            half_close=case.half_close,
            metadata={**case.metadata, "minimized_from": case.name},
        )
        before = monitor.snapshot()
        log_epoch = time.time()
        response, error, _ = run_wire_case(host, port, args.timeout, trial)
        after = monitor.snapshot()
        logs = monitor.logs_since(log_epoch)
        crash = bool(CRASH_RE.search(logs)) or state_changed(before, after)
        alerts = adapter.suspicious_response(trial, response)
        if expect_security_signal:
            return crash or bool(alerts)
        return adapter.response_class(response, error) == expected_signature

    data = case.payload
    if not preserves(data):
        raise SystemExit("original case no longer preserves the requested signal")
    granularity = 2
    while len(data) >= 2 and attempts < args.max_attempts:
        width = math.ceil(len(data) / granularity)
        reduced = False
        for start in range(0, len(data), width):
            candidate = data[:start] + data[start + width :]
            if not candidate or attempts >= args.max_attempts:
                continue
            if preserves(candidate):
                data = candidate
                granularity = max(2, granularity - 1)
                reduced = True
                print(f"reduced to {len(data)} bytes after {attempts} attempts", flush=True)
                break
        if not reduced:
            if granularity >= len(data):
                break
            granularity = min(len(data), granularity * 2)

    minimized = WireCase(
        case.engine,
        f"{case.name}-minimized",
        [data],
        receive_first=case.receive_first,
        half_close=case.half_close,
        metadata={**case.metadata, "minimized_from": case.name, "attempts": attempts},
    )
    output = args.output or case_path.with_name("minimized-case.json")
    Path(output).write_text(json.dumps(minimized.serializable(), indent=2, sort_keys=True) + "\n")
    print(json.dumps({"input_bytes": len(case.payload), "output_bytes": len(data), "attempts": attempts, "output": str(output)}))
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    doctor_parser = sub.add_parser(
        "doctor", help="show tools, drivers, source trees, and local service reachability"
    )
    doctor_parser.add_argument(
        "--engine",
        action="append",
        choices=("redis", "mysql", "mariadb", "postgresql", "oracle"),
        help="limit endpoint checks to this engine (repeatable)",
    )

    wire = sub.add_parser("wire", help="run structured pre-auth protocol fuzzing")
    wire.add_argument("--engine", required=True, choices=("redis", "mysql", "mariadb", "postgresql", "oracle"))
    wire.add_argument("--host")
    wire.add_argument("--port", type=int)
    wire.add_argument("--container")
    wire.add_argument(
        "--sanitizer-log-glob",
        help="server-side ASan/UBSan log glob; never point this at client logs",
    )
    wire.add_argument("--iterations", type=int, default=0)
    wire.add_argument("--seed", type=lambda value: int(value, 0), default=0x5441494E54)
    wire.add_argument("--timeout", type=float, default=0.75)
    wire.add_argument("--max-input", type=int, default=1_048_576)
    wire.add_argument("--max-corpus", type=int, default=4096)
    wire.add_argument("--receive-limit", type=int, default=1_048_576)
    wire.add_argument("--artifacts", default=str(DEFAULT_ARTIFACTS / "wire"))

    sql = sub.add_parser("sql", help="run low-privilege SQL executor fuzzing")
    sql.add_argument("--engine", required=True, choices=("mysql", "mariadb", "postgresql", "oracle"))
    sql.add_argument("--dsn-file", type=Path, default=None)
    sql.add_argument("--container")
    sql.add_argument(
        "--sanitizer-log-glob",
        help="server-side ASan/UBSan log glob; never point this at client logs",
    )
    sql.add_argument("--iterations", type=int, default=100)
    sql.add_argument("--seed", type=lambda value: int(value, 0), default=0x53454C454354)
    sql.add_argument("--max-literal", type=int, default=65_536)
    sql.add_argument("--timeout-ms", type=int, default=1500)
    sql.add_argument("--artifacts", type=Path, default=DEFAULT_ARTIFACTS / "sql")

    binary = sub.add_parser(
        "postgresql-binary",
        help="fuzz authenticated PostgreSQL extended-query binary Bind parameters",
    )
    binary.add_argument("--dsn-file", type=Path, default=None)
    binary.add_argument("--container")
    binary.add_argument(
        "--sanitizer-log-glob",
        help="server-side ASan/UBSan log glob; never point this at client logs",
    )
    binary.add_argument("--iterations", type=int, default=100)
    binary.add_argument("--seed", type=lambda value: int(value, 0), default=0x42494E44)
    binary.add_argument("--max-input", type=int, default=65_536)
    binary.add_argument("--max-corpus", type=int, default=4096)
    binary.add_argument("--timeout-ms", type=int, default=1500)
    binary.add_argument(
        "--artifacts", type=Path, default=DEFAULT_ARTIFACTS / "postgresql-binary"
    )

    replay_parser = sub.add_parser("replay", help="replay one saved wire case")
    replay_parser.add_argument("--case", required=True, type=Path)
    replay_parser.add_argument("--host")
    replay_parser.add_argument("--port", type=int)
    replay_parser.add_argument("--timeout", type=float, default=1.0)

    minimize_parser = sub.add_parser("minimize", help="delta-minimize a saved wire case")
    minimize_parser.add_argument("--case", required=True, type=Path)
    minimize_parser.add_argument("--signature")
    minimize_parser.add_argument("--host")
    minimize_parser.add_argument("--port", type=int)
    minimize_parser.add_argument("--container")
    minimize_parser.add_argument("--timeout", type=float, default=0.75)
    minimize_parser.add_argument("--max-attempts", type=int, default=500)
    minimize_parser.add_argument("--output", type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.command == "doctor":
        return doctor(args.engine)
    if args.command == "wire":
        return run_wire(args)
    if args.command == "replay":
        return replay(args)
    if args.command == "minimize":
        return minimize(args)
    if args.command == "sql":
        defaults = target_defaults(args.engine)
        dsn_file = args.dsn_file or (Path(os.environ["DBFUZZ_DSN_FILE"]) if "DBFUZZ_DSN_FILE" in os.environ else None)
        if dsn_file is None:
            raise SystemExit("SQL mode requires --dsn-file or DBFUZZ_DSN_FILE")
        container = args.container if args.container is not None else defaults.get("container")
        return run_sql_campaign(
            args.engine,
            dsn_file,
            args.iterations,
            args.seed,
            args.max_literal,
            args.timeout_ms,
            container,
            args.artifacts,
            args.sanitizer_log_glob,
        )
    if args.command == "postgresql-binary":
        defaults = target_defaults("postgresql")
        dsn_file = args.dsn_file or (
            Path(os.environ["DBFUZZ_DSN_FILE"])
            if "DBFUZZ_DSN_FILE" in os.environ
            else None
        )
        if dsn_file is None:
            raise SystemExit("PostgreSQL binary mode requires --dsn-file or DBFUZZ_DSN_FILE")
        container = args.container if args.container is not None else defaults.get("container")
        return run_postgresql_binary_campaign(
            dsn_file,
            args.iterations,
            args.seed,
            args.max_input,
            args.timeout_ms,
            container,
            args.artifacts,
            args.sanitizer_log_glob,
            args.max_corpus,
        )
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
