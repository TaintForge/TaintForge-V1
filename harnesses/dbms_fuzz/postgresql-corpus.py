#!/usr/bin/env python3
"""Build a rollback-safe PostgreSQL AFL corpus from upstream test SQL."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path

import psycopg

from postgresql_sql import (
    mutation_resource_safe,
    split_sql,
    standalone_safe,
    strip_psql_lines,
    unwrap_transaction,
    usable_statement,
    wrap_transaction,
)


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SOURCE = ROOT / ".labs/db-fuzz/source/postgresql-zdc-2026-postgresql-18.6-afl"
DEFAULT_DSN = ROOT / ".labs/db-fuzz/runtime/postgresql-asan/demo.dsn"
DEFAULT_OUTPUT = ROOT / "workspace/db-fuzz/postgresql-afl/corpus-v2"
BLOCK_RE = re.compile(r"(?:setup|teardown|step\s+\w+)\s*\{([\s\S]*?)\}", re.IGNORECASE)


HANDWRITTEN: dict[str, tuple[str, ...]] = {
    "array-slice": ("SELECT (ARRAY[1,2,3,2147483647])[-2:8]",),
    "jsonpath": ("SELECT jsonb_path_query_array('{\"a\":[1,2,3]}'::jsonb, '$.a[*] ? (@ >= 2)')",),
    "regexp": ("SELECT regexp_replace(repeat('ab', 256), '(a+)+b', E'\\\\1', 'g')",),
    "numeric": ("SELECT ('1e1000'::numeric * '-0.00000000000000000001'::numeric) / 3",),
    "textsearch": ("SELECT to_tsvector('simple', repeat('alpha beta gamma ', 32)) @@ to_tsquery('simple', 'alpha & !delta')",),
    "range": ("SELECT int8multirange(int8range(-9223372036854775807, 0, '[)'), int8range(0, 9223372036854775807, '[)'))",),
    "state-array": (
        "CREATE TEMP TABLE tf_array(v int[]) ON COMMIT DROP",
        "INSERT INTO tf_array VALUES (ARRAY[1,2,3])",
        "UPDATE tf_array SET v[2] = 2147483647 RETURNING v",
    ),
    "state-index": (
        "CREATE TEMP TABLE tf_idx(a bigint, b text) ON COMMIT DROP",
        "INSERT INTO tf_idx SELECT g, repeat(chr(97 + (g % 26)::int), 8) FROM generate_series(1,32) g",
        "CREATE INDEX ON tf_idx ((lower(b))) INCLUDE (a)",
        "ANALYZE tf_idx",
        "SELECT a, b FROM tf_idx WHERE lower(b) LIKE 'a%' ORDER BY a DESC LIMIT 8",
    ),
    "state-window": (
        "CREATE TEMP TABLE tf_win(a int, b numeric) ON COMMIT DROP",
        "INSERT INTO tf_win SELECT g, g::numeric / 3 FROM generate_series(-16,16) g",
        "SELECT a, sum(b) OVER (ORDER BY a ROWS BETWEEN 3 PRECEDING AND 2 FOLLOWING) FROM tf_win",
    ),
}


def load_dsn(path: Path) -> str:
    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        raise SystemExit(f"DSN file must be mode 0600 or stricter: {path}")
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise SystemExit(f"empty DSN file: {path}")
    return value


def source_files(source: Path) -> list[Path]:
    values = list((source / "src/test/regress/sql").glob("*.sql"))
    values.extend(source.glob("contrib/*/sql/*.sql"))
    values.extend((source / "src/test/isolation/specs").glob("*.spec"))
    return sorted(path for path in values if path.is_file())


def statements_from(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix == ".spec":
        text = "\n".join(BLOCK_RE.findall(text))
    text = strip_psql_lines(text)
    return [
        statement
        for statement in split_sql(text)
        if usable_statement(statement) and mutation_resource_safe(statement)
    ]


class CorpusWriter:
    def __init__(self, root: Path, max_seed_bytes: int, timeout_ms: int):
        self.root = root
        self.max_seed_bytes = max_seed_bytes
        self.timeout_ms = timeout_ms
        self.hashes: set[str] = set()
        self.counts = {"fast": 0, "stateful": 0}
        for lane in self.counts:
            lane_root = root / lane
            lane_root.mkdir(parents=True, exist_ok=True)
            for stale in lane_root.glob("*.sql"):
                stale.unlink()
        manifest = root / "manifest.json"
        if manifest.is_file():
            manifest.unlink()

    def add(self, lane: str, label: str, statements: list[str] | tuple[str, ...]) -> bool:
        payload = wrap_transaction((standalone_safe(item) for item in statements), self.timeout_ms)
        if len(payload) > self.max_seed_bytes:
            return False
        digest = hashlib.sha256(payload).hexdigest()
        if digest in self.hashes:
            return False
        self.hashes.add(digest)
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", label).strip("-")[:72] or "seed"
        path = self.root / lane / f"{self.counts[lane]:05d}-{safe}-{digest[:12]}.sql"
        path.write_bytes(payload)
        self.counts[lane] += 1
        return True


def reconnect(dsn: str) -> psycopg.Connection:
    # Regression tests contain DEALLOCATE ALL. Disable psycopg's implicit
    # prepared-statement cache so target SQL cannot invalidate driver state.
    connection = psycopg.connect(dsn, autocommit=False, prepare_threshold=None)
    connection.execute("SET statement_timeout = '500ms'")
    connection.execute("SET lock_timeout = '100ms'")
    connection.rollback()
    return connection


def validate_file(
    connection: psycopg.Connection,
    path: Path,
    statements: list[str],
    writer: CorpusWriter,
) -> tuple[int, int]:
    valid: list[str] = []
    accepted = 0
    rejected = 0
    milestones = {1, 2, 4, 8, 16, 32, 64}
    connection.execute("BEGIN")
    connection.execute("SET LOCAL statement_timeout = '500ms'")
    connection.execute("SET LOCAL lock_timeout = '100ms'")
    for index, statement in enumerate(statements):
        connection.execute("SAVEPOINT tf_seed")
        try:
            connection.execute(statement)
        except Exception:
            rejected += 1
            connection.execute("ROLLBACK TO SAVEPOINT tf_seed")
            connection.execute("RELEASE SAVEPOINT tf_seed")
            continue
        connection.execute("RELEASE SAVEPOINT tf_seed")
        valid.append(statement)
        accepted += 1
        label = f"{path.stem}-{index}"
        writer.add("fast", label, [statement])
        if len(valid) in milestones:
            writer.add("stateful", f"{path.stem}-prefix-{len(valid)}", valid)
    if valid:
        writer.add("stateful", f"{path.stem}-sequence", valid)
    connection.rollback()
    return accepted, rejected


def validate_fast_corpus(dsn: str, writer: CorpusWriter) -> tuple[int, int]:
    """Keep only seeds that execute from the clean default schema by themselves."""
    kept = 0
    removed = 0
    connection = reconnect(dsn)
    files = sorted((writer.root / "fast").glob("*.sql"))
    for index, path in enumerate(files, 1):
        statements = unwrap_transaction(path.read_bytes())
        try:
            connection.execute("BEGIN")
            connection.execute("SET LOCAL statement_timeout = '500ms'")
            connection.execute("SET LOCAL lock_timeout = '100ms'")
            for statement in statements:
                connection.execute(statement)
        except Exception:
            removed += 1
            path.unlink()
            try:
                connection.rollback()
            except Exception:
                try:
                    connection.close()
                except Exception:
                    pass
                connection = reconnect(dsn)
        else:
            kept += 1
            connection.rollback()
        if index % 1000 == 0:
            print(f"fast-validation={index}/{len(files)} kept={kept} removed={removed}", flush=True)
    connection.close()
    writer.counts["fast"] = kept
    return kept, removed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--dsn-file", type=Path, default=DEFAULT_DSN)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--max-seed-bytes", type=int, default=65536)
    parser.add_argument("--timeout-ms", type=int, default=750)
    parser.add_argument("--limit-files", type=int)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    source = args.source.resolve()
    if not source.is_dir() or not (source / "src/backend/parser/gram.y").is_file():
        raise SystemExit(f"not a PostgreSQL source tree: {source}")
    files = source_files(source)
    if args.limit_files is not None:
        files = files[: max(0, args.limit_files)]
    writer = CorpusWriter(args.output, args.max_seed_bytes, args.timeout_ms)
    for label, statements in HANDWRITTEN.items():
        writer.add("fast" if len(statements) == 1 else "stateful", label, statements)

    dsn = load_dsn(args.dsn_file)
    connection = reconnect(dsn)
    accepted = 0
    rejected = 0
    processed = 0
    for path in files:
        statements = statements_from(path)
        if not statements:
            continue
        try:
            good, bad = validate_file(connection, path, statements, writer)
        except (psycopg.OperationalError, psycopg.InterfaceError) as exc:
            try:
                connection.close()
            except Exception:
                pass
            connection = reconnect(dsn)
            print(
                f"skipped-disconnected path={path.relative_to(source)} "
                f"error={type(exc).__name__}",
                flush=True,
            )
            good, bad = 0, len(statements)
        accepted += good
        rejected += bad
        processed += 1
        if processed % 25 == 0:
            print(f"processed={processed}/{len(files)} accepted={accepted} rejected={rejected}", flush=True)
    connection.close()
    fast_kept, fast_removed = validate_fast_corpus(dsn, writer)

    manifest = {
        "source": str(source),
        "source_files": len(files),
        "processed_files": processed,
        "accepted_statements": accepted,
        "rejected_statements": rejected,
        "fast_candidates_removed": fast_removed,
        "corpus": writer.counts,
        "max_seed_bytes": args.max_seed_bytes,
        "timeout_ms": args.timeout_ms,
    }
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps(manifest, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
