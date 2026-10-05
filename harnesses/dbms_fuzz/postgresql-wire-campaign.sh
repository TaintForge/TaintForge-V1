#!/usr/bin/env bash
# Repeated bounded pre-auth batches against the loopback ASan PostgreSQL daemon.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STATE="$ROOT/workspace/db-fuzz/postgresql-afl/wire"
STOP="$STATE/_stop"
ARTIFACTS="$STATE/artifacts"
LOG_GLOB="$ROOT/.labs/db-fuzz/runtime/postgresql-asan/sanitizer.*"
BATCH="${DBFUZZ_WIRE_BATCH:-5000}"

run_campaign() {
  mkdir -p "$STATE" "$ARTIFACTS"
  find "$STOP" -delete 2>/dev/null || true
  trap 'exit 0' INT TERM
  while [ ! -e "$STOP" ]; do
    seed="$(date +%s%N)"
    set +e
    python3 "$ROOT/harnesses/dbms_fuzz/dbfuzz.py" wire \
      --engine postgresql --host 127.0.0.1 --port 55434 --container '' \
      --sanitizer-log-glob "$LOG_GLOB" --iterations "$BATCH" \
      --seed "$seed" --timeout 0.5 --artifacts "$ARTIFACTS"
    rc=$?
    set -e
    printf '[%s] batch_exit=%s seed=%s\n' "$(date -Is)" "$rc" "$seed"
    [ "$rc" -ne 2 ] || sleep 2
  done
}

status_campaign() {
  printf 'wire_cases='
  if [ -d "$ARTIFACTS/postgresql" ]; then
    find "$ARTIFACTS/postgresql" -type f -name result.json | wc -l
  else
    echo 0
  fi
  printf 'wire_suspicious='
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
