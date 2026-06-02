#!/usr/bin/env bash
# 2a cross-validation: always CodeQL (deepest interprocedural/cross-file taint),
# then correlate hits onto candidate findings (-> cross_validated).
# Fallback to OpenGrep/Semgrep only if CodeQL is unavailable or fails, so the
# pipeline never silently skips cross-validation.
#
# LICENSE NOTE: CodeQL is free only for OSI open-source / research. Using it on
# private/commercial code requires GitHub Advanced Security. You chose CodeQL-always
# - make sure your targets are licensed for it.
#
# Usage: cross_validate.sh <target_dir> [language]
#   env: ENGINE=opengrep  (escape hatch to force OpenGrep instead)
set -uo pipefail
TARGET="${1:?usage: cross_validate.sh <target_dir> [language]}"
LANG_="${2:-${LANG_GUESS:-}}"
HERE="$(cd "$(dirname "$0")" && pwd)"
RULES="$HERE/../../vuln-track-a/rules"
ENGINE="${ENGINE:-codeql}"            # default: always CodeQL

# infer language from CODE_MODEL if not given
if [ -z "$LANG_" ] && [ -f workspace/CODE_MODEL.json ]; then
  LANG_="$(python3 -c "import json;print((json.load(open('workspace/CODE_MODEL.json'))['target'].get('languages') or ['javascript'])[0])" 2>/dev/null || echo javascript)"
fi
LANG_="${LANG_:-javascript}"

OUT=""; ENGINE_TAG=""
if [ "$ENGINE" = "codeql" ]; then
  if ! command -v codeql >/dev/null 2>&1; then
    echo "[cross-val] codeql not found -> falling back to OpenGrep"; ENGINE=opengrep
  else
    OUT="workspace/_codeql.sarif"; rm -rf workspace/_cqldb
    echo "[cross-val] CodeQL DB ($LANG_)..."
    if codeql database create workspace/_cqldb --language="$LANG_" --source-root="$TARGET" --overwrite \
       && codeql database analyze workspace/_cqldb --format=sarifv2.1.0 -o "$OUT" \
            "codeql/${LANG_}-queries:codeql-suites/${LANG_}-security-extended.qls"; then
      ENGINE_TAG=codeql
    else
      echo "[cross-val] codeql failed -> falling back to OpenGrep"; ENGINE=opengrep; OUT=""
    fi
  fi
fi

if [ "$ENGINE" = "opengrep" ]; then
  BIN="$(command -v opengrep || command -v semgrep || true)"
  [ -z "$BIN" ] && { echo "[cross-val] no codeql/opengrep/semgrep available - skipping (rely on reproduction)"; exit 0; }
  OUT="workspace/_xval.json"
  CFG=(); for y in "$RULES"/*.yaml; do [ -e "$y" ] && CFG+=(--config "$y"); done
  [ -d "$RULES/vendor" ] && CFG+=(--config "$RULES/vendor")
  echo "[cross-val] $(basename "$BIN") deep pass..."
  "$BIN" "${CFG[@]}" --json -o "$OUT" "$TARGET" 2>/dev/null || true
  ENGINE_TAG="$([ "$(basename "$BIN")" = semgrep ] && echo semgrep || echo opengrep)"
fi

[ -n "$OUT" ] && [ -f "$OUT" ] && \
  python3 "$HERE/correlate.py" "$OUT" --engine "$ENGINE_TAG" --root "$TARGET" || \
  echo "[cross-val] no engine output to correlate"