#!/usr/bin/env python3
"""Correlate an independent engine's output onto candidate findings (step 2a).

Reads a CodeQL SARIF or OpenGrep/Semgrep JSON result file, indexes every location the
engine flagged, and bumps any `candidate` finding whose SINK the engine independently
flagged to `status: cross_validated`, appending a `cross-validation` history entry.

Agreement rule: same file, and the engine hit lands within --window lines of the
finding's sink line. Findings the engine did not flag are left untouched - the engine
is a second opinion, never a veto (reproduction is the real evidence).

Usage: correlate.py <engine_output> --engine <codeql|opengrep|semgrep> --root <target_dir>
                    [--findings DIR] [--window N] [--dry-run]
"""
import argparse
import datetime
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
WRITER = os.path.join(HERE, "..", "..", "_shared", "write_finding.py")


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _norm(path, root):
    """Normalize an engine path to a repo-relative path for comparison."""
    if not path:
        return ""
    path = str(path)
    for prefix in ("file://", "file:"):
        if path.startswith(prefix):
            path = path[len(prefix):]
    path = os.path.normpath(path)
    if os.path.isabs(path):
        try:
            cwd_rel = os.path.relpath(path, os.getcwd())
            if not cwd_rel.startswith(".."):
                path = cwd_rel
        except ValueError:
            pass
    return path.lstrip("./")


def load_hits(out_file, root):
    """Return {normalized_path: [(line, rule_id)]} from SARIF or semgrep JSON."""
    with open(out_file, "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    hits = {}

    def add(path, line, rule):
        path = _norm(path, root)
        if not path:
            return
        hits.setdefault(path, []).append((int(line or 0), rule or "?"))

    if "runs" in data:  # SARIF (CodeQL)
        for run in data.get("runs") or []:
            for res in run.get("results") or []:
                rule = res.get("ruleId") or "?"
                for loc in res.get("locations") or []:
                    phys = (loc.get("physicalLocation") or {})
                    uri = (phys.get("artifactLocation") or {}).get("uri")
                    line = (phys.get("region") or {}).get("startLine")
                    add(uri, line, rule)
    else:  # semgrep / opengrep JSON
        for res in data.get("results") or []:
            add(res.get("path"), (res.get("start") or {}).get("line"), res.get("check_id"))
    return hits


def engine_agrees(hits, sink_file, sink_line, window):
    """Did the engine flag the same file within `window` lines of the sink?"""
    sink_file = _norm(sink_file, None)
    if not sink_file:
        return None
    cands = hits.get(sink_file)
    if cands is None:
        # tolerate differing path roots: match on the longest common suffix
        for path, entries in hits.items():
            if path.endswith(sink_file) or sink_file.endswith(path):
                cands = entries
                break
    if not cands:
        return None
    best = None
    for line, rule in cands:
        dist = abs(line - int(sink_line or 0))
        if dist <= window and (best is None or dist < best[0]):
            best = (dist, line, rule)
    return best


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("output", help="engine output file (SARIF or semgrep JSON)")
    ap.add_argument("--engine", required=True)
    ap.add_argument("--root", default="")
    ap.add_argument("--findings", default="workspace/findings")
    ap.add_argument("--window", type=int, default=5)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if not os.path.isfile(args.output):
        print(f"[correlate] no engine output at {args.output}")
        return 0
    try:
        hits = load_hits(args.output, args.root)
    except Exception as exc:  # noqa: BLE001 - never break the pipeline on bad output
        print(f"[correlate] could not parse {args.output}: {exc}")
        return 0
    total = sum(len(v) for v in hits.values())
    print(f"[correlate] {args.engine}: {total} hits across {len(hits)} files")

    if not os.path.isdir(args.findings):
        print("[correlate] no findings directory yet - nothing to correlate")
        return 0

    bumped = skipped = 0
    for name in sorted(os.listdir(args.findings)):
        if not name.endswith(".json"):
            continue
        path = os.path.join(args.findings, name)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                finding = json.load(fh)
        except Exception:
            continue
        if finding.get("status") != "candidate":
            continue
        sink = finding.get("sink") or {}
        match = engine_agrees(hits, sink.get("file"), sink.get("line"), args.window)
        if not match:
            skipped += 1
            continue
        dist, line, rule = match
        finding["status"] = "cross_validated"
        finding["updated_at"] = _now()
        finding.setdefault("history", []).append({
            "stage": "cross-validation",
            "action": (
                f"{args.engine} independently flagged {sink.get('file')}:{line} "
                f"({rule}), {dist} line(s) from the reported sink -> cross_validated"
            ),
            "ts": _now(),
        })
        print(f"[correlate] {finding.get('id', name)} -> cross_validated ({rule} @ {line})")
        bumped += 1
        if args.dry_run:
            continue
        proc = subprocess.run(
            [sys.executable, WRITER, "--update", finding.get("id") or name[:-5]],
            input=json.dumps(finding), text=True, capture_output=True,
        )
        if proc.returncode != 0:
            print(f"[correlate] writer rejected {finding.get('id')}: "
                  f"{(proc.stderr or proc.stdout).strip()[:300]}")

    print(f"[correlate] bumped {bumped}; left {skipped} candidate(s) unmatched "
          f"(engine silence is not a veto)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
