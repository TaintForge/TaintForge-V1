#!/usr/bin/env python3
"""Small event queue for the PostgreSQL AFL triage agents."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / "workspace" / "db-fuzz" / "postgresql-afl"
TRIAGE = STATE / "triage"
FINDINGS = ROOT / "workspace" / "findings"
MARKERS = STATE / "agents" / "markers"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def summary(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value
    return values


def pending_c() -> list[Path]:
    pending: list[Path] = []
    for item in sorted(TRIAGE.glob("*/summary.txt")):
        artifact = item.parent
        if summary(item).get("classification") not in {"sanitizer", "abnormal"}:
            continue
        if not (artifact / "agent-review.json").is_file():
            pending.append(artifact)
    return pending


def finding_rows() -> list[tuple[Path, dict]]:
    rows: list[tuple[Path, dict]] = []
    for path in sorted(FINDINGS.glob("*.json")):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(value, dict):
            rows.append((path, value))
    return rows


def marker(role: str, path: Path) -> Path:
    return MARKERS / role / f"{path.stem}-{digest(path)}.done"


def pending_e() -> list[Path]:
    return [
        path
        for path, value in finding_rows()
        if value.get("status") == "needs_reanalysis" and not marker("E", path).is_file()
    ]


def pending_d() -> list[Path]:
    return [
        path
        for path, value in finding_rows()
        if value.get("status") in {"reproduced", "confirmed"}
        and not marker("D", path).is_file()
    ]


def next_item(role: str) -> Path | None:
    items = {"C": pending_c, "E": pending_e, "D": pending_d}[role]()
    return items[0] if items else None


def mark(role: str, path: Path) -> None:
    target = marker(role, path.resolve())
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(f"path={path.resolve()}\n", encoding="utf-8")


def status() -> dict[str, int]:
    return {
        "triage_artifacts": len(list(TRIAGE.glob("*/summary.txt"))),
        "pending_triage": len(pending_c()),
        "pending_reanalysis": len(pending_e()),
        "pending_exploitation": len(pending_d()),
        "findings": len(finding_rows()),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    next_parser = subparsers.add_parser("next")
    next_parser.add_argument("role", choices=("C", "E", "D"))
    mark_parser = subparsers.add_parser("mark")
    mark_parser.add_argument("role", choices=("E", "D"))
    mark_parser.add_argument("path", type=Path)
    subparsers.add_parser("status")
    args = parser.parse_args()

    if args.command == "next":
        item = next_item(args.role)
        if item is not None:
            print(item.resolve())
        return 0
    if args.command == "mark":
        mark(args.role, args.path)
        return 0
    print(json.dumps(status(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
