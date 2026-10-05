#!/usr/bin/env bash
# Repeated low-privilege PostgreSQL binary Bind batches against the ASan daemon.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STATE="$ROOT/workspace/db-fuzz/postgresql-afl/binary-bind"
STOP="$STATE/_stop"
ARTIFACTS="$STATE/artifacts"
DSN="$ROOT/.labs/db-fuzz/runtime/postgresql-asan/demo.dsn"
LOG_GLOB="$ROOT/.labs/db-fuzz/runtime/postgresql-asan/sanitizer.*"
# Keep the in-memory state/corpus feedback alive long enough to compound
# mutations instead of resetting it every few minutes.
BATCH="${DBFUZZ_BINARY_BATCH:-50000}"

run_campaign() {
  [ -s "$DSN" ] || { echo "missing PostgreSQL diagnostic DSN file: $DSN" >&2; exit 3; }
  mkdir -p "$STATE" "$ARTIFACTS"
  find "$STOP" -delete 2>/dev/null || true
  trap 'exit 0' INT TERM
  while [ ! -e "$STOP" ]; do
    seed="$(date +%s%N)"
    set +e
    DBFUZZ_DSN_FILE="$DSN" \
      python3 "$ROOT/harnesses/dbms_fuzz/dbfuzz.py" postgresql-binary \
      --container '' --sanitizer-log-glob "$LOG_GLOB" \
      --iterations "$BATCH" --seed "$seed" --timeout-ms 1500 \
      --artifacts "$ARTIFACTS"
    rc=$?
    set -e
    printf '[%s] batch_exit=%s seed=%s\n' "$(date -Is)" "$rc" "$seed"
    [ "$rc" -ne 2 ] || sleep 2
  done
}

status_campaign() {
  printf 'binary_cases='
  if [ -d "$ARTIFACTS/postgresql" ]; then
    find "$ARTIFACTS/postgresql" -type f -name result.json | wc -l
  else
    echo 0
  fi
  printf 'binary_suspicious='
  if [ -d "$ARTIFACTS/postgresql" ]; then
    { rg -l '"crash_signal": true' "$ARTIFACTS/postgresql" -g result.json 2>/dev/null || true; } | wc -l
  else
    echo 0
  fi
}

case "${1:-status}" in
  run) run_campaign ;;
  stop) mkdir -p "$STATE"; : > "$STOP" ;;
  status) status_campaign ;;
  *) echo "usage: $0 run|stop|status" >&2; exit 2 ;;
esac
