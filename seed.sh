#!/usr/bin/env bash
# Seed a target: whole-repo structural index + per-module full models + coverage + hypotheses.
#
#   ./seed.sh targets/<app> [modules-file]
#
# Why the per-module models exist: build_code_model.sh degrades to a graph-only extract above
# ~4000 analyzable files, and a graph-only model has no dataflow, no sink set and no proof
# ledger - which is most of what A and B actually query. So each security-relevant area of a
# large target gets its own full model under workspace/cm/<name>.json, and the roles query
# those with `callgraph.py --model` / `proof_ledger.py --ledger`.
#
# The modules file is one `name:path` per line, path relative to the target root; `#` comments
# and blank lines are ignored. A module whose path is absent from this version is skipped, so
# one file keeps working across releases. With no modules file, only the whole-repo index,
# coverage tree and hypotheses are built - fine for a small target.
#
# See campaigns/README.md for how a campaign pins its target, modules and role context.
set -Eeuo pipefail
cd "$(dirname "$0")"

TARGET="${1:-}"
MODULES_FILE="${2:-}"
JOBS="${TF_SEED_JOBS:-6}"

[ -n "$TARGET" ] || { echo "usage: ./seed.sh targets/<app> [modules-file]" >&2; exit 2; }
[ -d "$TARGET" ] || { echo "no such target: $TARGET" >&2; exit 2; }
[ -z "$MODULES_FILE" ] || [ -f "$MODULES_FILE" ] || {
  echo "no such modules file: $MODULES_FILE" >&2; exit 2; }

S=.agents/skills
mkdir -p workspace/cm

echo "== whole-repo structural index =="
"$S/source-model/scripts/build_code_model.sh" "$TARGET"

if [ -n "$MODULES_FILE" ]; then
  echo "== per-module full models (dataflow + sinks + proof ledger), $JOBS at a time =="
  running=0
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%%#*}"; line="$(echo "$line" | xargs || true)"
    [ -n "$line" ] || continue
    name="${line%%:*}"; dir="${line#*:}"
    if [ "$name" = "$dir" ]; then echo "SKIP $line (not name:path)"; continue; fi
    if [ ! -d "$TARGET/$dir" ]; then echo "SKIP $name ($dir not in this version)"; continue; fi
    (
      if python3 "$S/source-model/scripts/build_code_model.py" "$TARGET/$dir" \
           -o "workspace/cm/$name.json" >"workspace/cm/$name.buildlog" 2>&1; then
        echo "OK   $name"
      else
        echo "FAIL $name (see workspace/cm/$name.buildlog)"
      fi
    ) &
    running=$((running + 1))
    if [ "$running" -ge "$JOBS" ]; then wait; running=0; fi
  done < "$MODULES_FILE"
  wait
fi

echo "== coverage tree + hypotheses =="
python3 "$S/source-model/scripts/coverage.py" --init "$TARGET"
python3 "$S/hypothesize/scripts/gen_hypotheses.py" --target "$TARGET"
echo "== seed complete for $TARGET =="
