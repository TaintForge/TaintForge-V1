#!/usr/bin/env bash
# OPTIONAL Track A hint generator. Codex is the main finder; this just points it at
# suspicious spots. Never fatal - if it crashes or finds nothing, Codex still works
# from the code. OpenGrep preferred (Semgrep OSS core segfaults on big repos).
# Output: workspace/hints/track-a-semgrep.{md,json}  (LEADS, not findings)
#
# Usage: run_semgrep.sh <target_dir>
set -uo pipefail
TARGET="${1:?usage: run_semgrep.sh <target_dir>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
RULES="$HERE/../rules"
RAW="workspace/hints/_raw.json"
mkdir -p workspace/hints
PY="python3"; [ -x .venv/bin/python ] && PY=.venv/bin/python

# pick engine: opengrep (stable) > semgrep
if command -v opengrep >/dev/null 2>&1; then BIN=opengrep; SUB="scan"; OUT=(--output "$RAW");
elif command -v semgrep >/dev/null 2>&1; then BIN=semgrep; SUB=""; OUT=(-o "$RAW");
else echo "[hints] no opengrep/semgrep - skipping leads, Codex finds from code"; exit 0; fi

CFG=(); for y in "$RULES"/*.yaml; do [ -e "$y" ] && CFG+=(--config "$y"); done
[ -d "$RULES/vendor" ] && CFG+=(--config "$RULES/vendor")

# validated crash-avoidance options (big repos / 3rd-party code segfault the core)
echo "[hints] $BIN scanning $TARGET (optional, crash-safe)..."
$BIN $SUB "${CFG[@]}" --json "${OUT[@]}" \
  --jobs 1 --max-target-bytes 500000 --timeout 20 --timeout-threshold 3 \
  --exclude 'vendor/' --exclude 'concrete/vendor/' --exclude 'node_modules/' \
  --exclude '*.min.js' --exclude 'tests/' --exclude 'spec/' \
  "$TARGET" 2>/dev/null || echo "[hints] engine errored - continuing (Codex works without leads)"

"$PY" "$HERE/semgrep_to_hints.py" "$RAW" --root "$TARGET" --out workspace/hints || true