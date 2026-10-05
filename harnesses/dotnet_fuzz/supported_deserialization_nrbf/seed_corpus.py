#!/usr/bin/env python3
"""Extract the exact netcoreapp20 NRBF compatibility corpus from the 10.0.12 tests."""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path
import re
import sys


CONTROL_SHA256 = "462a66402329d788484a300f4c6a9cb05edc8f0cc905e28427a26190497881b1"
MAXIMUM_INPUT_LENGTH = 1024 * 1024
SEED_PATTERN = re.compile(
    r'new\("([A-Za-z0-9+/=]+)",\s*TargetFrameworkMoniker\.netcoreapp20\)'
)


def write_exact(path: Path, content: bytes) -> None:
    if path.exists():
        if path.read_bytes() != content:
            raise RuntimeError(f"refusing to replace non-matching generated state: {path}")
        return
    path.write_bytes(content)


def main() -> int:
    if len(sys.argv) != 4:
        print(f"usage: {sys.argv[0]} BinaryFormatterTestData.cs CORPUS_DIR CONTROL_FILE", file=sys.stderr)
        return 2

    source_path = Path(sys.argv[1])
    corpus_path = Path(sys.argv[2])
    control_path = Path(sys.argv[3])
    corpus_path.mkdir(parents=True, exist_ok=True)
    control_path.parent.mkdir(parents=True, exist_ok=True)

    source = source_path.read_text(encoding="utf-8")
    unique: dict[str, tuple[int, bytes]] = {}
    for source_index, match in enumerate(SEED_PATTERN.finditer(source), start=1):
        payload = base64.b64decode(match.group(1), validate=True)
        if not payload or len(payload) > MAXIMUM_INPUT_LENGTH:
            continue
        digest = hashlib.sha256(payload).hexdigest()
        unique.setdefault(digest, (source_index, payload))

    control: bytes | None = None
    manifest_rows = ["source_index\tsha256\tlength\tfile"]
    for digest, (source_index, payload) in sorted(unique.items(), key=lambda item: item[1][0]):
        filename = f"seed-{source_index:04d}-{digest[:16]}.nrbf"
        write_exact(corpus_path / filename, payload)
        manifest_rows.append(f"{source_index}\t{digest}\t{len(payload)}\t{filename}")
        if digest == CONTROL_SHA256:
            control = payload

    if control is None:
        raise RuntimeError(f"clean Int32 control {CONTROL_SHA256} was not present in {source_path}")
    write_exact(control_path, control)

    manifest = ("\n".join(manifest_rows) + "\n").encode()
    write_exact(corpus_path.parent / "manifest.tsv", manifest)
    print(f"official_unique_seeds={len(unique)}")
    print(f"clean_control_sha256={CONTROL_SHA256} length={len(control)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
