#!/usr/bin/env bash
# Replay AFL crash and hang artifacts under the ASan+UBSan PostgreSQL build.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STATE="$ROOT/workspace/db-fuzz/postgresql-afl"
OUTS=(
  "$STATE/output"
  "$STATE/output-v2-fast"
  "$STATE/output-v2-stateful"
  "$STATE/output-v3-stable-fast"
  "$STATE/output-v3-stable-stateful"
)
TEMPLATE="$STATE/template-data"
TRIAGE="$STATE/triage"
ASAN_POSTGRES="$ROOT/.labs/db-fuzz/install/postgresql-asan/usr/local/pgsql/bin/postgres"
STDOUT_LIMIT="${DBFUZZ_TRIAGE_STDOUT_LIMIT:-1048576}"

init_triage() {
  [ -x "$ASAN_POSTGRES" ] || { echo "missing ASan postgres: $ASAN_POSTGRES" >&2; exit 3; }
  [ -s "$TEMPLATE/PG_VERSION" ] || { echo "missing replay template: $TEMPLATE" >&2; exit 3; }
  case "$STDOUT_LIMIT" in
    ''|*[!0-9]*) echo "invalid DBFUZZ_TRIAGE_STDOUT_LIMIT: $STDOUT_LIMIT" >&2; exit 3 ;;
  esac
  [ "$STDOUT_LIMIT" -gt 0 ] || {
    echo "DBFUZZ_TRIAGE_STDOUT_LIMIT must be positive" >&2
    exit 3
  }
  mkdir -p "$TRIAGE"
}

# Keep reading after the retained prefix is full.  Stopping the reader would
# send SIGPIPE to postgres and turn large valid query output into a harness-
# induced process termination, obscuring the sanitizer/timeout result.
capture_bounded_stdout() {
  local output="$1" head_status=0 drain_status=0
  head -c "$STDOUT_LIMIT" > "$output" || head_status=$?
  cat >/dev/null || drain_status=$?
  [ "$head_status" -eq 0 ] && [ "$drain_status" -eq 0 ]
}

replay_one() {
  local crash="$1"
  local digest result replay_data exit_code capture_exit classification read_only jit parallel artifact_kind
  local stdout_bytes stdout_capped
  local -a replay_status
  digest="$(sha256sum "$crash" | cut -d' ' -f1)"
  result="$TRIAGE/$digest"
  [ ! -s "$result/summary.txt" ] || return 0
  case "$crash" in
    */hangs/*) artifact_kind=hang ;;
    *) artifact_kind=crash ;;
  esac

  mkdir -p "$result"
  cp "$crash" "$result/input.sql"
  replay_data="$(mktemp -d "$STATE/replay-data.XXXXXX")"
  cp -a --reflink=auto "$TEMPLATE/." "$replay_data/"

  read_only=on
  jit=off
  parallel=0
  case "$crash" in
    "$STATE"/output-v2-stateful/*|"$STATE"/output-v3-stable-stateful/*)
      read_only=off
      case "$crash" in
        */state-jit-par/*) jit=on; parallel=4 ;;
      esac
      ;;
  esac

  set +e
  ASAN_OPTIONS="abort_on_error=1:disable_coredump=0:detect_leaks=0:log_path=$result/asan" \
  UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1:log_path=$result/ubsan" \
    timeout 15s "$ASAN_POSTGRES" --single -j -D "$replay_data" -F \
      -c exit_on_error=on \
      -c default_transaction_read_only="$read_only" \
      -c jit="$jit" \
      -c max_parallel_workers="$parallel" \
      postgres < "$result/input.sql" 2> "$result/stderr.txt" |
    capture_bounded_stdout "$result/stdout.txt"
  replay_status=("${PIPESTATUS[@]}")
  exit_code="${replay_status[0]:-125}"
  capture_exit="${replay_status[1]:-125}"
  set -e

  stdout_bytes="$(stat -c %s "$result/stdout.txt" 2>/dev/null || echo 0)"
  stdout_capped=false
  if [ "$stdout_bytes" -ge "$STDOUT_LIMIT" ]; then
    stdout_capped=true
  fi

  if [ "$capture_exit" -ne 0 ]; then
    classification=harness-output-error
  elif find "$result" -maxdepth 1 -type f \( -name 'asan.*' -o -name 'ubsan.*' \) -print -quit | grep -q .; then
    classification=sanitizer
  elif rg -qi 'assertion.*failed|TRAP:|PANIC:|Segmentation fault|Aborted' "$result/stderr.txt"; then
    classification=abnormal
  elif [ "$exit_code" -eq 124 ]; then
    classification=timeout
  else
    classification=not-reproduced
  fi

  printf 'source=%s\nsha256=%s\nartifact_kind=%s\nexit_code=%s\ncapture_exit=%s\nstdout_bytes=%s\nstdout_limit=%s\nstdout_capped=%s\nclassification=%s\n' \
    "$crash" "$digest" "$artifact_kind" "$exit_code" "$capture_exit" \
    "$stdout_bytes" "$STDOUT_LIMIT" "$stdout_capped" "$classification" > "$result/summary.txt"

  case "$replay_data" in
    "$STATE"/replay-data.*) rm -rf -- "$replay_data" ;;
    *) echo "refusing to remove unexpected replay path: $replay_data" >&2; exit 4 ;;
  esac
  printf '%s %s\n' "$classification" "$digest"
}

scan_once() {
  for output in "${OUTS[@]}"; do
    while IFS= read -r -d '' crash; do
      replay_one "$crash"
    done < <(
      find "$output" -type f \
        \( -path '*/crashes/id:*' -o -path '*/hangs/id:*' \) -print0 2>/dev/null
    )
  done
}

main() {
  init_triage
  if [ "${1:-run}" = once ]; then
    scan_once
    return 0
  fi

  echo "watching AFL crashes and hangs for ASan+UBSan replay: ${OUTS[*]}"
  while :; do
    scan_once
    sleep 5
  done
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi
