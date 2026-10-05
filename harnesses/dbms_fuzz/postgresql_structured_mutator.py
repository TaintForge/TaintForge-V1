"""AFL++ Python mutator that preserves PostgreSQL statement structure."""

from __future__ import annotations

import random
import re

from postgresql_sql import (
    mutation_resource_safe,
    standalone_safe,
    unwrap_transaction,
    usable_statement,
    wrap_transaction,
)


_rng = random.Random(0)
BOUNDARIES = (
    "-9223372036854775808",
    "-2147483648",
    "-1",
    "0",
    "1",
    "2",
    "31",
    "32",
    "63",
    "64",
    "127",
    "128",
    "255",
    "256",
    "32767",
    "65535",
    "2147483647",
    "9223372036854775807",
)
ATOMS = (
    "''",
    "'a'",
    "E'\\\\x00'",
    "repeat('A', 4096)",
    "decode('00ff7f80', 'hex')",
    "ARRAY[]::int[]",
    "ARRAY[-2147483648,0,2147483647]",
    "'{}'::jsonb",
    "'[]'::jsonb",
    "'NaN'::numeric",
    "'Infinity'::float8",
)
SELF_CONTAINED = (
    "SELECT regexp_replace(repeat('ab', 512), '(a+)+b', E'\\\\1', 'g')",
    "SELECT jsonb_path_query_array('{\"a\":[1,2,3]}'::jsonb, '$.a[*] ? (@ >= 2)')",
    "SELECT (ARRAY[-2147483648,0,2147483647])[0:2147483647]",
    "SELECT width_bucket('NaN'::numeric, ARRAY[-1::numeric,0,1])",
    "SELECT to_tsvector('simple', repeat('a b c ', 128)) @@ to_tsquery('simple', 'a & !z')",
    "SELECT normalize(U&'a\\0308', NFC), unicode_assigned(U&'a\\0308')",
    "SELECT int8multirange(int8range(-9223372036854775807, 0, '[)'), int8range(0, 9223372036854775807, '[)'))",
)
MUTATION_ATTEMPTS = 8
# PostgreSQL's residual coverage variability can make most structured outputs
# look novel.  Without an explicit count, AFL++ doubles the custom stage after
# each find up to 12,800 executions per queue entry, starving corpus breadth.
# Keep the normal HAVOC_CYCLES-sized budget and disable that feedback loop.
FUZZ_COUNT = 256
NUMBER_RE = re.compile(r"(?<![A-Za-z_$])[-+]?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?")
STRING_RE = re.compile(r"(?:E|U&)?'(?:''|[^'])*'", re.IGNORECASE)
IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z_0-9$]*\b")
KEYWORDS = {
    "select", "from", "where", "create", "temp", "temporary", "table", "insert", "into",
    "values", "update", "set", "delete", "returning", "as", "and", "or", "not", "null",
    "true", "false", "join", "on", "group", "by", "order", "limit", "offset", "with",
    "index", "analyze", "explain", "using", "case", "when", "then", "else", "end",
}


def init(seed: int) -> None:
    global _rng
    _rng = random.Random(seed)


def fuzz_count(buf: bytes) -> int:
    return FUZZ_COUNT


def splice_optout() -> None:
    return None


def _replace_match(text: str, pattern: re.Pattern[str], replacement: str) -> str:
    matches = list(pattern.finditer(text))
    if not matches:
        return text
    match = _rng.choice(matches)
    return text[: match.start()] + replacement + text[match.end() :]


def _mutate_statement(statement: str) -> str:
    operation = _rng.choice(("number", "number", "string", "identifier", "predicate", "cast"))
    if operation == "number":
        return _replace_match(statement, NUMBER_RE, _rng.choice(BOUNDARIES))
    if operation == "string":
        return _replace_match(statement, STRING_RE, _rng.choice(ATOMS))
    if operation == "identifier":
        identifiers = [item for item in IDENT_RE.findall(statement) if item.lower() not in KEYWORDS]
        if len(identifiers) >= 2:
            source = _rng.choice(identifiers)
            target = _rng.choice(identifiers)
            return re.sub(rf"\b{re.escape(source)}\b", target, statement, count=1)
        return statement
    if operation == "predicate" and statement.lstrip().upper().startswith("SELECT"):
        return f"SELECT * FROM ({statement}) AS tf_sub WHERE ({_rng.choice(BOUNDARIES)}) IS NOT NULL"
    if operation == "cast":
        return f"SELECT ({_rng.choice(ATOMS)})::{_rng.choice(('text', 'bytea', 'numeric', 'jsonb', 'int8[]'))}"
    return statement


def _bounded(statements: list[str], max_size: int) -> bytearray:
    statements = [
        standalone_safe(item)
        for item in statements
        if usable_statement(item) and mutation_resource_safe(item)
    ] or [_rng.choice(SELF_CONTAINED)]
    while statements:
        payload = wrap_transaction(statements)
        if len(payload) <= max_size:
            return bytearray(payload)
        if len(statements) == 1:
            shortened = statements[0].encode("utf-8", "replace")[: max(32, max_size // 2)]
            statements[0] = shortened.decode("utf-8", "ignore")
        else:
            del statements[_rng.randrange(len(statements))]
    return bytearray(wrap_transaction(["SELECT 1"]))


def _fuzz_once(statements: list[str], donor: list[str], max_size: int) -> bytearray:
    statements = list(statements)
    for _ in range(_rng.randint(1, 4)):
        operation = _rng.choice(("mutate", "mutate", "insert", "duplicate", "splice", "delete", "swap"))
        if operation == "mutate":
            index = _rng.randrange(len(statements))
            statements[index] = _mutate_statement(statements[index])
        elif operation == "insert":
            statements.insert(_rng.randrange(len(statements) + 1), _rng.choice(SELF_CONTAINED))
        elif operation == "duplicate" and statements:
            index = _rng.randrange(len(statements))
            statements.insert(index, statements[index])
        elif operation == "splice" and donor:
            statements.insert(_rng.randrange(len(statements) + 1), _rng.choice(donor))
        elif operation == "delete" and len(statements) > 1:
            del statements[_rng.randrange(len(statements))]
        elif operation == "swap" and len(statements) > 1:
            left, right = _rng.sample(range(len(statements)), 2)
            statements[left], statements[right] = statements[right], statements[left]
    return _bounded(statements, max_size)


def fuzz(buf: bytes, add_buf: bytes, max_size: int) -> bytearray:
    original = bytes(buf)
    statements = unwrap_transaction(original)
    donor = unwrap_transaction(bytes(add_buf)) if add_buf else []
    if not statements:
        statements = ["SELECT 1"]

    # AFL_CUSTOM_MUTATOR_ONLY disables every built-in mutation stage.  Do not
    # spend an execution on a no-op when an inapplicable delete/swap/splice or
    # token replacement happens to leave the structured payload unchanged.
    for _ in range(MUTATION_ATTEMPTS):
        candidate = _fuzz_once(statements, donor, max_size)
        if bytes(candidate) != original:
            return candidate

    # Keep the fallback structured and executable.  Under the campaign's
    # normal max_size this also guarantees a changed payload after the bounded
    # retries without falling back to blind byte mutation.
    for statement in SELF_CONTAINED:
        candidate = _bounded([*statements, statement], max_size)
        if bytes(candidate) != original:
            return candidate
    return _bounded(["SELECT 0"], max_size)


def init_trim(buf: bytes) -> int:
    return 0


def trim() -> bytes:
    return b""


def post_trim(success: bool) -> int:
    return 0


def describe(max_description_length: int) -> bytes:
    # AFL++ 4.09c's Python bridge calls PyBytes_AsString() directly.  A Python
    # str leaves a pending TypeError and a NULL stage description, which makes
    # this AFL release crash in its testcase-name memcpy path.
    return b"postgresql-structured-sql"[:max_description_length]


def deinit() -> None:
    # AFL++ 4.09c probes this nominally optional hook during initialization
    # and can leave a Python exception pending when it is absent.
    return None
