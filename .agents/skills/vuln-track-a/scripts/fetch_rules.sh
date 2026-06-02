#!/usr/bin/env bash
# One-time: vendor the Semgrep community ruleset into rules/vendor/ so the WHOLE
# injection/web family is covered OFFLINE (works in Codex Cloud with no internet
# at scan time). Re-run to update. ~hundreds of curated rules per language.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DEST="$HERE/../rules/vendor"
TMP="$(mktemp -d)"
echo "[fetch] cloning semgrep/semgrep-rules (shallow)..."
git clone --depth 1 -q https://github.com/semgrep/semgrep-rules "$TMP/semgrep-rules"
rm -rf "$DEST"; mkdir -p "$DEST"
# keep only security rule dirs across languages (skip tests/docs/generic noise)
for d in "$TMP"/semgrep-rules/*/; do
  lang="$(basename "$d")"
  if [ -d "$d/security" ] || ls "$d"/*/security >/dev/null 2>&1; then
    mkdir -p "$DEST/$lang"
    cp -r "$d"/* "$DEST/$lang/" 2>/dev/null || true
    # drop test fixtures to cut load time
    find "$DEST/$lang" -name '*.test.yaml' -delete 2>/dev/null || true
  fi
done
rm -rf "$TMP"
echo "[fetch] vendored to $DEST ($(find "$DEST" -name '*.yaml' | wc -l) rule files)"