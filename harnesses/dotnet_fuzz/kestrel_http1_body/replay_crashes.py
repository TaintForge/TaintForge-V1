#!/usr/bin/env python3
"""Classify every artifact AFL saved for the Kestrel HTTP/1 semantic body lane.

AFL writes an input to ``crashes/`` as soon as the fuzz child reports a fault. For this lane
the fault is reported by SharpFuzz's out-of-process fork server, which relays the child's raw
wait status, so a saved artifact is a *lead*: it says "the child died here", not "this input
violates a framing invariant". The two artifacts the v5 lane has saved so far both replay PASS
on the stock build with identical contiguous and segmented responses, which means they cannot
support a finding on their own and must not consume triage time downstream.

This script replays each artifact against the stock build several times and classifies it:

  reproduced      at least one replay failed or raised the oracle - a real lead to dig into
  flaky           replays disagree with each other - the artifact is load/state dependent
  not_reproduced  every replay produced the identical complete response - oracle noise

Artifacts are only ever read. AFL queues, corpora and every afl* directory are left untouched.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
LAB = ROOT / ".labs/dotnet/source/aspnetcore-10.0.12"
DOTNET = LAB / ".dotnet/dotnet"
HARNESS_NAME = "KestrelHttp1BodyFuzz.dll"

NORMALIZED_RE = re.compile(r"normalized_sha256=([0-9A-F]+)")
ARTIFACT_RE = re.compile(r"^id:\d+")


def state_dir(generation: str) -> Path:
    if generation == "v1":
        return ROOT / "workspace/dotnet-bounty/kestrel-http1-body-semantic"
    return ROOT / f"workspace/dotnet-bounty/kestrel-http1-body-semantic-{generation}"


def find_artifacts(state: Path, generation: str) -> list[tuple[str, Path]]:
    """Every saved crash/hang under every worker, including AFL's rotated backups."""
    found: list[tuple[str, Path]] = []
    for output in sorted(state.glob(f"afl-body-semantic-{generation}")):
        for worker in sorted(p for p in output.iterdir() if p.is_dir()):
            for bucket in sorted(worker.iterdir()):
                if not bucket.is_dir():
                    continue
                name = bucket.name
                if name.startswith("crashes"):
                    kind = "crash"
                elif name.startswith("hangs"):
                    kind = "hang"
                else:
                    continue
                for artifact in sorted(bucket.iterdir()):
                    if artifact.is_file() and ARTIFACT_RE.match(artifact.name):
                        found.append((kind, artifact))
    return found


def replay(publish: Path, artifact: Path, repeats: int, timeout: int) -> list[dict]:
    harness = publish / HARNESS_NAME
    runs: list[dict] = []
    env = {
        "DOTNET_ROOT": str(DOTNET.parent),
        "DOTNET_ROLL_FORWARD": "Major",
        "DOTNET_HOSTBUILDER__RELOADCONFIGONCHANGE": "false",
        "PATH": "/usr/bin:/bin",
        "HOME": str(ROOT / "workspace/dotnet-bounty/dotnet-cli-home"),
    }
    for _ in range(repeats):
        try:
            done = subprocess.run(
                [str(DOTNET), str(harness), "--replay-semantic", str(artifact)],
                capture_output=True, text=True, timeout=timeout, env=env, cwd=str(ROOT),
            )
            stdout, stderr, code = done.stdout, done.stderr, done.returncode
        except subprocess.TimeoutExpired:
            runs.append({"exit_code": None, "passed": False, "normalized_sha256": None,
                         "detail": f"replay exceeded {timeout}s"})
            continue
        match = NORMALIZED_RE.search(stdout)
        runs.append({
            "exit_code": code,
            "passed": code == 0 and stdout.startswith("PASS"),
            "normalized_sha256": match.group(1) if match else None,
            "detail": (stderr.strip().splitlines() or [""])[0][:400],
        })
    return runs


def classify(runs: list[dict]) -> str:
    if not runs:
        return "error"
    if any(not r["passed"] for r in runs):
        # A replay that failed or raised the oracle is a genuine lead worth digging into.
        return "reproduced" if all(not r["passed"] for r in runs) else "flaky"
    responses = {r["normalized_sha256"] for r in runs}
    return "not_reproduced" if len(responses) == 1 else "flaky"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--generation", default="v5", help="semantic lane generation (default: v5)")
    parser.add_argument("--repeats", type=int, default=5, help="replays per artifact (default: 5)")
    parser.add_argument("--timeout", type=int, default=180, help="seconds per replay (default: 180)")
    parser.add_argument("--publish", type=Path, default=None,
                        help="stock build to replay against (default: the generation's publish)")
    args = parser.parse_args()

    state = state_dir(args.generation)
    if not state.is_dir():
        print(f"no such lane state: {state}", file=sys.stderr)
        return 3
    publish = args.publish or (state / "publish")
    if not (publish / HARNESS_NAME).is_file():
        print(f"no harness build at {publish}", file=sys.stderr)
        return 3
    if not DOTNET.is_file():
        print(f"missing bootstrapped .NET: {DOTNET}", file=sys.stderr)
        return 3

    artifacts = find_artifacts(state, args.generation)
    results = []
    for kind, artifact in artifacts:
        data = artifact.read_bytes()
        runs = replay(publish, artifact, args.repeats, args.timeout)
        verdict = classify(runs)
        results.append({
            "kind": kind,
            "path": str(artifact.relative_to(ROOT)),
            "signal": (re.search(r"sig:(\d+)", artifact.name) or [None, None])[1],
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest().upper(),
            "verdict": verdict,
            "repeats": len(runs),
            "distinct_responses": sorted({r["normalized_sha256"] for r in runs if r["normalized_sha256"]}),
            "runs": runs,
        })
        print(f"{verdict:<15} {kind:<5} sig:{results[-1]['signal']} {artifact.name}")

    report = {
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "generation": args.generation,
        "publish": str(publish.relative_to(ROOT)),
        "repeats": args.repeats,
        "artifact_count": len(results),
        "verdict_counts": {v: sum(1 for r in results if r["verdict"] == v)
                           for v in ("reproduced", "flaky", "not_reproduced", "error")},
        "artifacts": results,
    }
    out = state / "crash-triage.json"
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"\nartifacts={len(results)} {report['verdict_counts']}")
    print(f"report={out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
