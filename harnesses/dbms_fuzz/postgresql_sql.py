#!/usr/bin/env python3
"""Small PostgreSQL-aware SQL helpers shared by corpus and AFL mutator code."""

from __future__ import annotations

import re
from collections.abc import Iterable


TRANSACTION_CONTROL_RE = re.compile(
    r"^\s*(?:ABORT|BEGIN|START\s+TRANSACTION|COMMIT(?:\s+PREPARED)?|END|"
    r"ROLLBACK(?:\s+PREPARED)?|SAVEPOINT|RELEASE|PREPARE\s+TRANSACTION|SET\s+TRANSACTION)\b",
    re.IGNORECASE,
)
PSQL_VARIABLE_RE = re.compile(r"(?<!:):(?:'[^']+'|\"[^\"]+\")")
COPY_STDIN_RE = re.compile(r"\bCOPY\b[\s\S]*?\bFROM\s+STDIN\b", re.IGNORECASE)
COPY_RE = re.compile(r"^\s*COPY\b", re.IGNORECASE)
CONTROL_FUNCTION_RE = re.compile(
    r"\bpg_(?:terminate_backend|cancel_backend|reload_conf|rotate_logfile|promote)\s*\(",
    re.IGNORECASE,
)
TIMEOUT_CONTROL_RE = re.compile(
    r'^\s*(?:SET(?:\s+(?:SESSION|LOCAL))?\s+"?(?:statement_timeout|lock_timeout)\b"?|'
    r'RESET\s+(?:"?(?:statement_timeout|lock_timeout)\b"?|ALL\b))',
    re.IGNORECASE,
)
TIMEOUT_SET_CONFIG_RE = re.compile(
    r"\bset_config\s*\([^)]*\b(?:statement_timeout|lock_timeout)\b",
    re.IGNORECASE,
)
STATIC_REPEAT_RE = re.compile(
    r"\brepeat\s*\(\s*(?:E|U&)?'(?P<value>(?:''|[^'])*)'\s*,\s*"
    r"(?P<count>[+-]?\d+)\s*\)",
    re.IGNORECASE,
)
STATIC_NESTED_REPEAT_RE = re.compile(
    r"\brepeat\s*\(\s*repeat\s*\(\s*(?:E|U&)?'(?P<value>(?:''|[^'])*)'\s*,\s*"
    r"(?P<inner>[+-]?\d+)\s*\)\s*,\s*(?P<outer>[+-]?\d+)\s*\)",
    re.IGNORECASE,
)
STATIC_ARRAY_FILL_RE = re.compile(
    r"\barray_fill\s*\(\s*[^,;]+,\s*(?:ARRAY\s*)?\["
    r"(?P<dims>\s*[+-]?\d+(?:\s*,\s*[+-]?\d+)*\s*)\]",
    re.IGNORECASE,
)
STATIC_ARRAY_FILL_REPEAT_RE = re.compile(
    r"\barray_fill\s*\(\s*repeat\s*\(\s*(?:E|U&)?'"
    r"(?P<value>(?:''|[^'])*)'\s*,\s*(?P<count>[+-]?\d+)\s*\)"
    r"(?:\s*::\s*(?:text|varchar|bpchar))?\s*,\s*(?:ARRAY\s*)?\["
    r"(?P<dims>\s*[+-]?\d+(?:\s*,\s*[+-]?\d+)*\s*)\]",
    re.IGNORECASE,
)
STATIC_DELAY_FUNCTION_RE = re.compile(
    r"\bpg_sleep(?:_for|_until)?\s*\(",
    re.IGNORECASE,
)
STATIC_INTEGER_SERIES_RE = re.compile(
    r"\bgenerate_series\s*\(\s*(?P<start>[+-]?\d+)\s*,\s*"
    r"(?P<stop>[+-]?\d+)\s*(?:,\s*(?P<step>[+-]?\d+)\s*)?\)",
    re.IGNORECASE,
)
MAX_MUTATED_REPEAT_BYTES = 1 << 20
MAX_MUTATED_ARRAY_ITEMS = 1 << 18
MAX_MUTATED_ARRAY_BYTES = 1 << 24
MAX_MUTATED_SERIES_ROWS = 1 << 12
TEMP_CREATE_RE = re.compile(
    r"\bCREATE\s+(?:(?:GLOBAL|LOCAL)\s+)?TEMP(?:ORARY)?\s+"
    r"(?=(?:TABLE|VIEW|SEQUENCE)\b)",
    re.IGNORECASE,
)
ON_COMMIT_RE = re.compile(
    r"\s+ON\s+COMMIT\s+(?:DROP|DELETE\s+ROWS|PRESERVE\s+ROWS)\b",
    re.IGNORECASE,
)


def code_prefix(statement: str) -> str:
    """Return a statement with leading whitespace/comments removed for classification."""
    value = statement
    while True:
        value = value.lstrip()
        if value.startswith("--"):
            newline = value.find("\n")
            value = "" if newline < 0 else value[newline + 1 :]
            continue
        if value.startswith("/*"):
            end = value.find("*/", 2)
            value = "" if end < 0 else value[end + 2 :]
            continue
        return value


def strip_psql_lines(text: str) -> str:
    """Remove psql meta commands and inline COPY data while preserving SQL lines."""
    output: list[str] = []
    pending = ""
    copy_data = False
    for line in text.splitlines(keepends=True):
        stripped = line.lstrip()
        if copy_data:
            if stripped.rstrip("\r\n") == r"\.":
                copy_data = False
            continue
        if stripped.startswith("\\"):
            continue
        output.append(line)
        pending = (pending + line)[-16384:]
        if ";" in line:
            if COPY_STDIN_RE.search(pending):
                copy_data = True
            pending = pending.rsplit(";", 1)[-1]
    return "".join(output)


def split_sql(text: str) -> list[str]:
    """Split PostgreSQL statements without breaking quotes, comments, or dollar bodies."""
    statements: list[str] = []
    start = 0
    index = 0
    single = False
    double = False
    line_comment = False
    block_depth = 0
    dollar_tag: str | None = None
    length = len(text)

    while index < length:
        char = text[index]
        nxt = text[index + 1] if index + 1 < length else ""

        if line_comment:
            if char == "\n":
                line_comment = False
            index += 1
            continue
        if block_depth:
            if char == "/" and nxt == "*":
                block_depth += 1
                index += 2
            elif char == "*" and nxt == "/":
                block_depth -= 1
                index += 2
            else:
                index += 1
            continue
        if dollar_tag is not None:
            if text.startswith(dollar_tag, index):
                index += len(dollar_tag)
                dollar_tag = None
            else:
                index += 1
            continue
        if single:
            if char == "'" and nxt == "'":
                index += 2
            elif char == "'":
                single = False
                index += 1
            else:
                index += 1
            continue
        if double:
            if char == '"' and nxt == '"':
                index += 2
            elif char == '"':
                double = False
                index += 1
            else:
                index += 1
            continue

        if char == "-" and nxt == "-":
            line_comment = True
            index += 2
        elif char == "/" and nxt == "*":
            block_depth = 1
            index += 2
        elif char == "'":
            single = True
            index += 1
        elif char == '"':
            double = True
            index += 1
        elif char == "$":
            match = re.match(r"\$[A-Za-z_][A-Za-z_0-9]*\$|\$\$", text[index:])
            if match:
                dollar_tag = match.group(0)
                index += len(dollar_tag)
            else:
                index += 1
        elif char == ";":
            statement = text[start:index].strip()
            if statement:
                statements.append(statement)
            start = index + 1
            index += 1
        else:
            index += 1

    tail = text[start:].strip()
    if tail:
        statements.append(tail)
    return statements


def usable_statement(statement: str, max_bytes: int = 65536) -> bool:
    encoded = statement.encode("utf-8", "replace")
    if not statement.strip() or len(encoded) > max_bytes:
        return False
    code = code_prefix(statement)
    if not code or TRANSACTION_CONTROL_RE.match(code):
        return False
    if PSQL_VARIABLE_RE.search(statement):
        return False
    if COPY_STDIN_RE.search(statement):
        return False
    # psycopg exposes COPY through a streaming API. Keep COPY seeds in the
    # dedicated protocol lane instead of misclassifying them in SQL execute().
    if COPY_RE.match(code):
        return False
    if CONTROL_FUNCTION_RE.search(code):
        return False
    # Keep the per-testcase resource guards authoritative.  Upstream
    # regression SQL can contain RESET statement_timeout, and retaining it
    # lets a structured mutation turn a bounded generate_series()/repeat()
    # case into an AFL process timeout instead of a backend statement timeout.
    if TIMEOUT_CONTROL_RE.match(code) or TIMEOUT_SET_CONFIG_RE.search(code):
        return False
    return True


def _sql_code_mask(value: str) -> list[bool]:
    """Mark characters outside SQL strings, quoted identifiers, and comments."""
    mask = [False] * len(value)
    index = 0
    line_comment = False
    block_depth = 0
    single = False
    double = False
    dollar_tag: str | None = None
    while index < len(value):
        char = value[index]
        nxt = value[index + 1] if index + 1 < len(value) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
            index += 1
        elif block_depth:
            if char == "/" and nxt == "*":
                block_depth += 1
                index += 2
            elif char == "*" and nxt == "/":
                block_depth -= 1
                index += 2
            else:
                index += 1
        elif dollar_tag is not None:
            if value.startswith(dollar_tag, index):
                index += len(dollar_tag)
                dollar_tag = None
            else:
                index += 1
        elif single:
            if char == "'" and nxt == "'":
                index += 2
            elif char == "'":
                single = False
                index += 1
            else:
                index += 1
        elif double:
            if char == '"' and nxt == '"':
                index += 2
            elif char == '"':
                double = False
                index += 1
            else:
                index += 1
        elif char == "-" and nxt == "-":
            line_comment = True
            index += 2
        elif char == "/" and nxt == "*":
            block_depth = 1
            index += 2
        elif char == "'":
            single = True
            index += 1
        elif char == '"':
            double = True
            index += 1
        elif char == "$":
            match = re.match(r"\$[A-Za-z_][A-Za-z_0-9]*\$|\$\$", value[index:])
            if match:
                dollar_tag = match.group(0)
                index += len(dollar_tag)
            else:
                mask[index] = True
                index += 1
        else:
            mask[index] = True
            index += 1
    return mask


def mutation_resource_safe(statement: str) -> bool:
    """Reject only statically provable mutation-time resource amplifiers.

    Large integer boundaries remain available everywhere else.  This guard is
    intentionally limited to explicit delay functions, literal generate_series()
    cardinality, literal repeat() expansion, and literal array_fill() dimensions
    observed to consume AFL's outer timeout before useful coverage can be collected.
    """
    code_mask = _sql_code_mask(statement)
    for match in STATIC_DELAY_FUNCTION_RE.finditer(statement):
        if code_mask[match.start()]:
            return False

    series_rows = 1
    for match in STATIC_INTEGER_SERIES_RE.finditer(statement):
        if not code_mask[match.start()]:
            continue
        start = int(match.group("start"))
        stop = int(match.group("stop"))
        step_text = match.group("step")
        step = int(step_text) if step_text is not None else 1
        if step == 0 or (step > 0 and start > stop) or (step < 0 and start < stop):
            rows = 0
        elif step > 0:
            rows = (stop - start) // step + 1
        else:
            rows = (start - stop) // -step + 1
        if rows > MAX_MUTATED_SERIES_ROWS:
            return False
        if rows:
            series_rows *= rows
            if series_rows > MAX_MUTATED_SERIES_ROWS:
                return False

    for match in STATIC_NESTED_REPEAT_RE.finditer(statement):
        if not code_mask[match.start()]:
            continue
        inner = max(0, int(match.group("inner")))
        outer = max(0, int(match.group("outer")))
        literal_bytes = len(match.group("value").replace("''", "'").encode("utf-8"))
        if literal_bytes * inner * outer > MAX_MUTATED_REPEAT_BYTES:
            return False

    for match in STATIC_REPEAT_RE.finditer(statement):
        if not code_mask[match.start()]:
            continue
        count = max(0, int(match.group("count")))
        literal_bytes = len(match.group("value").replace("''", "'").encode("utf-8"))
        if literal_bytes * count > MAX_MUTATED_REPEAT_BYTES:
            return False

    for match in STATIC_ARRAY_FILL_REPEAT_RE.finditer(statement):
        if not code_mask[match.start()]:
            continue
        dimensions = [int(value.strip()) for value in match.group("dims").split(",")]
        if any(value < 0 for value in dimensions):
            continue
        items = 1
        for value in dimensions:
            items *= value
        repeat_count = max(0, int(match.group("count")))
        literal_bytes = len(match.group("value").replace("''", "'").encode("utf-8"))
        if literal_bytes * repeat_count * items > MAX_MUTATED_ARRAY_BYTES:
            return False

    for match in STATIC_ARRAY_FILL_RE.finditer(statement):
        if not code_mask[match.start()]:
            continue
        dimensions = [int(value.strip()) for value in match.group("dims").split(",")]
        if any(value < 0 for value in dimensions):
            continue
        items = 1
        for value in dimensions:
            items *= value
        if items > MAX_MUTATED_ARRAY_ITEMS:
            return False

    return True


def wrap_transaction(statements: Iterable[str], timeout_ms: int = 750) -> bytes:
    body = [
        statement.strip().rstrip(";")
        for statement in statements
        if statement.strip() and usable_statement(statement)
    ]
    sql = [
        "BEGIN",
        f"SET LOCAL statement_timeout = '{max(1, int(timeout_ms))}ms'",
        "SET LOCAL lock_timeout = '100ms'",
        *body,
        "ROLLBACK",
    ]
    return (";\n".join(sql) + ";\n").encode("utf-8", "replace")


def standalone_safe(statement: str) -> str:
    """Avoid standalone-backend-only temp-relation pgstat assertions.

    The whole testcase is rolled back, so regular relations retain equivalent
    testcase lifetime without entering PostgreSQL's unsupported single-user
    temp-buffer statistics path.
    """
    value = TEMP_CREATE_RE.sub("CREATE ", statement)
    return ON_COMMIT_RE.sub("", value)


def unwrap_transaction(data: bytes) -> list[str]:
    text = data.decode("utf-8", "replace")
    statements = split_sql(text)
    body: list[str] = []
    for statement in statements:
        upper = statement.strip().upper()
        if upper in {"BEGIN", "COMMIT", "END", "ROLLBACK"}:
            continue
        if upper.startswith("SET LOCAL STATEMENT_TIMEOUT") or upper.startswith("SET LOCAL LOCK_TIMEOUT"):
            continue
        if usable_statement(statement):
            body.append(statement.strip())
    return body
