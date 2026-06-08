#!/usr/bin/env bash
# Build the Code Model's structural layer (ast+regex extractor; no required deps).
# Usage: build_code_model.sh <target_dir> [out_path]
set -euo pipefail
TARGET="${1:?usage: build_code_model.sh <target_dir> [out]}"
OUT="${2:-workspace/CODE_MODEL.json}"
HERE="$(cd "$(dirname "$0")" && pwd)"
if [ -x ".venv/bin/python" ]; then PY=".venv/bin/python"; else PY="python3"; echo "[info] no .venv; using system python3"; fi
"$PY" "$HERE/build_code_model.py" "$TARGET" -o "$OUT"