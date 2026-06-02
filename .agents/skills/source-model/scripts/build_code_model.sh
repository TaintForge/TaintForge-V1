#!/usr/bin/env bash
# Build the Code Model's structural layer.
# Prefers a project venv at .venv (deterministic). tree-sitter is OPTIONAL:
# if it's missing or can't load a grammar (e.g. offline in Codex Cloud), the
# extractor degrades to regex and still produces a valid CODE_MODEL.json
# (you just lose the precise call graph).
#
# Usage: build_code_model.sh <target_dir> [out_path]
set -euo pipefail
TARGET="${1:?usage: build_code_model.sh <target_dir> [out]}"
OUT="${2:-workspace/CODE_MODEL.json}"
HERE="$(cd "$(dirname "$0")" && pwd)"

# pick interpreter: project .venv if present, else python3
if [ -x ".venv/bin/python" ]; then
  PY=".venv/bin/python"
else
  PY="python3"
  echo "[info] no .venv found; using system python3 (see setup note in SKILL.md)"
fi

# best-effort deps (non-fatal): tree-sitter for call graph, jsonschema for validation
"$PY" -c "import tree_sitter_language_pack" 2>/dev/null \
  || "$PY" -m pip install -q -r "$HERE/requirements.txt" 2>/dev/null \
  || echo "[warn] tree-sitter not installed -> regex fallback (no call graph)"

"$PY" "$HERE/build_code_model.py" "$TARGET" -o "$OUT"