#!/usr/bin/env bash
# Build the Code Model's structural layer (ast+regex extractor; no required deps).
# Usage: build_code_model.sh <target_dir> [out_path]
set -euo pipefail
TARGET="${1:?usage: build_code_model.sh <target_dir> [out]}"
OUT="${2:-workspace/CODE_MODEL.json}"
HERE="$(cd "$(dirname "$0")" && pwd)"
# Prefer an interpreter that can actually load a tree-sitter backend; the regex fallback
# loses a lot of fidelity on large TypeScript/Rust trees. TF_PY overrides the search.
pick_py() {
  local c
  for c in "${TF_PY:-}" ".venv/bin/python" "python3"; do
    [ -n "$c" ] || continue
    command -v "$c" >/dev/null 2>&1 || [ -x "$c" ] || continue
    # Import alone is not enough: some cores import fine but expose a different
    # Node/Tree API or reject bytes, and ts_extract then silently falls back to
    # regex. Probe the real extraction path instead.
    if "$c" - "$HERE" >/dev/null 2>&1 <<'PROBE'
import sys
sys.path.insert(0, sys.argv[1])
import ts_extract as t
r = t.extract("a.ts", "typescript", "class C { m() { g(); } }", "m",
              lambda *a, **k: {}, lambda *a, **k: None, set())
sys.exit(0 if r and r[0] and r[1] else 1)
PROBE
    then
      echo "$c"; return
    fi
  done
  for c in "${TF_PY:-}" ".venv/bin/python" "python3"; do
    [ -n "$c" ] || continue
    if command -v "$c" >/dev/null 2>&1 || [ -x "$c" ]; then echo "$c"; return; fi
  done
  echo python3
}
PY="$(pick_py)"
echo "[info] interpreter: $PY"
"$PY" "$HERE/build_code_model.py" "$TARGET" -o "$OUT"