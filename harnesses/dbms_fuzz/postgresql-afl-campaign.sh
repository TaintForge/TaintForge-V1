#!/usr/bin/env bash
# Four-worker PostgreSQL AFL++ campaign: fast SQL plus stateful executor lanes.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SELF="$ROOT/harnesses/dbms_fuzz/postgresql-afl-campaign.sh"
STATE="$ROOT/workspace/db-fuzz/postgresql-afl"
CORPUS_BUILT="$STATE/corpus-v2"
CORPUS_MIN="$STATE/corpus-v2-min-next"
DICT="$ROOT/harnesses/dbms_fuzz/corpus/postgresql-sql.dict"
TEMPLATE="$STATE/template-data"
WORKER_ROOT="$STATE/workers-v3-stable"
OUT_FAST="$STATE/output-v3-stable-fast"
OUT_STATE="$STATE/output-v3-stable-stateful"
POSTGRES="$ROOT/.labs/db-fuzz/install/postgresql-afl-stable/usr/local/pgsql/bin/postgres"
INITDB="$ROOT/.labs/db-fuzz/install/postgresql-asan/usr/local/pgsql/bin/initdb"
SHARE_SOURCE="$ROOT/.labs/db-fuzz/install/postgresql-asan/usr/local/pgsql/share"
TRIAGE="$ROOT/harnesses/dbms_fuzz/postgresql-afl-triage.sh"
WIRE="$ROOT/harnesses/dbms_fuzz/postgresql-wire-campaign.sh"
BINARY="$ROOT/harnesses/dbms_fuzz/postgresql-binary-campaign.sh"
SESSION="${DBFUZZ_AFL_SESSION:-taintforge-pg-afl}"

corpus_root() {
  if [ -s "$CORPUS_MIN/READY" ] && [ -n "$(find "$CORPUS_MIN/fast" -type f -name '*.sql' -print -quit 2>/dev/null)" ]; then
    printf '%s\n' "$CORPUS_MIN"
  else
    printf '%s\n' "$CORPUS_BUILT"
  fi
}

init_campaign() {
  command -v afl-fuzz >/dev/null
  command -v afl-whatsup >/dev/null
  [ -x "$POSTGRES" ] || { echo "missing instrumented postgres: $POSTGRES" >&2; exit 3; }
  [ -x "$INITDB" ] || { echo "missing initdb: $INITDB" >&2; exit 3; }
  [ -d "$SHARE_SOURCE/timezone" ] || { echo "missing PostgreSQL share tree: $SHARE_SOURCE" >&2; exit 3; }
  [ -s "$CORPUS_BUILT/manifest.json" ] || python3 "$ROOT/harnesses/dbms_fuzz/postgresql-corpus.py"
  mkdir -p "$STATE" "$WORKER_ROOT" "$OUT_FAST" "$OUT_STATE"
  if [ ! -s "$TEMPLATE/PG_VERSION" ]; then
    ASAN_OPTIONS=detect_leaks=0 "$INITDB" -D "$TEMPLATE" -U afl_admin \
      --auth-local=trust --auth-host=reject --no-instructions
  fi
  for index in 0 1 2 3; do
    worker_data="$WORKER_ROOT/worker-$index"
    if [ ! -s "$worker_data/PG_VERSION" ]; then
      cp -a --reflink=auto "$TEMPLATE" "$worker_data"
    fi
  done
}

worker_command() {
  local index="$1" lane="$2" out="$3" role="$4" mode="$5" read_only="$6" jit="$7" parallel="$8"
  local corpus input worker_data
  corpus="$(corpus_root)/$lane"
  input="$corpus"
  worker_data="$WORKER_ROOT/worker-$index"
  [ ! -d "$out/$role/queue" ] || input="-"
  printf '%q ' env \
    PYTHONPATH="$ROOT/harnesses/dbms_fuzz" \
    AFL_PYTHON_MODULE=postgresql_structured_mutator \
    AFL_CUSTOM_MUTATOR_ONLY=1 \
    AFL_DISABLE_TRIM=1 \
    AFL_MAP_SIZE=262144 \
    AFL_SKIP_CPUFREQ=1 \
    AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
    afl-fuzz -i "$input" -o "$out" "$mode" "$role" \
    -p explore -x "$DICT" -t 2000 -m none -- \
    "$POSTGRES" --single -j -D "$worker_data" -F \
    -c exit_on_error=on \
    -c default_transaction_read_only="$read_only" \
    -c jit="$jit" \
    -c max_parallel_workers="$parallel" \
    postgres
}

new_worker_window() {
  local name="$1" title="$2" command="$3" pane
  pane="$(tmux new-window -d -t "$SESSION:" -n "$name" -c "$ROOT" -P -F '#{pane_id}' "$command")"
  tmux set-window-option -t "$SESSION:$name" remain-on-exit on
  tmux select-pane -t "$pane" -T "$title"
}

start_campaign() {
  if tmux has-session -t "$SESSION" 2>/dev/null; then
    echo "already running: tmux attach -t $SESSION"
    return
  fi
  init_campaign
  for index in 0 1 2 3; do
    find "$WORKER_ROOT/worker-$index" -maxdepth 1 -type f -name postmaster.pid -delete
  done

  local command pane
  command="$(worker_command 0 fast "$OUT_FAST" fast-main -M on off 0)"
  pane="$(tmux new-session -d -s "$SESSION" -n fast-main -x 240 -y 60 -c "$ROOT" \
    -P -F '#{pane_id}' "$command")"
  tmux set-window-option -t "$SESSION:fast-main" remain-on-exit on
  tmux select-pane -t "$pane" -T "AFL FAST main / structured SQL"

  command="$(worker_command 1 fast "$OUT_FAST" fast-secondary -S on off 0)"
  new_worker_window fast-s1 "AFL FAST secondary / structured SQL" "$command"

  command="$(worker_command 2 stateful "$OUT_STATE" state-main -M off off 0)"
  new_worker_window state-main "AFL STATE main / rollback executor" "$command"

  command="$(worker_command 3 stateful "$OUT_STATE" state-jit-par -S off on 4)"
  new_worker_window state-jit "AFL STATE JIT+parallel / rollback executor" "$command"

  command="$(printf '%q' "$WIRE") run"
  new_worker_window preauth "PREAUTH wire / startup SSL GSS SASL" "$command"

  command="$(printf '%q' "$BINARY") run"
  new_worker_window binary "AUTH binary Bind / type receive functions" "$command"

  command="$(printf '%q' "$TRIAGE")"
  new_worker_window triage "ASan+UBSan crash replay" "$command"

  command="watch -n 2 $(printf '%q' "$SELF") status-brief"
  new_worker_window dashboard "PostgreSQL multi-lane status" "$command"

  tmux set -t "$SESSION" mouse on
  tmux select-window -t "$SESSION:dashboard"
  echo "started 4 AFL workers + preauth wire + binary Bind + sanitizer replay"
  echo "attach: tmux attach -t $SESSION"
}

# Sandboxed role sessions can share the tmux socket and output tree while
# living in a different PID namespace from afl-fuzz.  Treat recent
# fuzzer_stats updates as the liveness source instead of pgrep/afl-whatsup.
brief_one() {
  local label="$1" out="$2" now max_age
  local -a stats
  printf '%s ' "$label"
  stats=("$out"/*/fuzzer_stats)
  if [ ! -f "${stats[0]}" ]; then
    echo 'not-started'
    return
  fi
  now="${DBFUZZ_STATUS_NOW:-$(date +%s)}"
  max_age="${DBFUZZ_AFL_HEARTBEAT_SECONDS:-120}"
  awk -F: -v now="$now" -v max_age="$max_age" '
    FNR == 1 { workers++ }
    {
      key = $1
      value = $2
      gsub(/[[:space:]]/, "", key)
      gsub(/^[[:space:]]+|[[:space:]%]+$/, "", value)
    }
    key == "last_update" && value ~ /^[0-9]+$/ {
      if (value <= now && now - value <= max_age)
        fresh++
    }
    key == "execs_done" { execs += value }
    key == "execs_ps_last_min" { speed += value }
    key == "pending_total" { pending += value }
    key == "bitmap_cvg" && value + 0 > coverage { coverage = value + 0 }
    key == "stability" {
      if (!saw_stability || value + 0 < min_stability)
        min_stability = value + 0
      if (!saw_stability || value + 0 > max_stability)
        max_stability = value + 0
      saw_stability = 1
    }
    key == "saved_crashes" { crashes += value }
    key == "saved_hangs" { hangs += value }
    END {
      printf "workers=%d fresh=%d execs=%.0f speed=%.2f/sec pending=%.0f " \
             "coverage=%.2f%% stability=%.2f-%.2f%% crashes=%.0f hangs=%.0f\n", \
             workers, fresh, execs, speed, pending, coverage, \
             min_stability, max_stability, crashes, hangs
    }
  ' "${stats[@]}"
}

count_fresh_workers() {
  local now max_age output stats_file updated count=0
  now="${DBFUZZ_STATUS_NOW:-$(date +%s)}"
  max_age="${DBFUZZ_AFL_HEARTBEAT_SECONDS:-120}"
  case "$now:$max_age" in
    *[!0-9:]*) echo "invalid AFL heartbeat status interval" >&2; return 2 ;;
  esac
  for output in "$@"; do
    for stats_file in "$output"/*/fuzzer_stats; do
      [ -f "$stats_file" ] || continue
      updated="$(awk -F: '
        {
          key = $1
          gsub(/[[:space:]]/, "", key)
        }
        key == "last_update" {
          value = $2
          gsub(/[[:space:]]/, "", value)
          print value
          exit
        }
      ' "$stats_file")"
      if [[ "$updated" =~ ^[0-9]+$ ]] &&
         (( updated <= now && now - updated <= max_age )); then
        count=$((count + 1))
      fi
    done
  done
  printf '%s\n' "$count"
}

status_brief() {
  local root
  root="$(corpus_root)"
  printf 'session=%s corpus=%s fast_seeds=' "$SESSION" "${root#$ROOT/}"
  find "$root/fast" -type f -name '*.sql' 2>/dev/null | wc -l
  printf 'stateful_seeds='; find "$root/stateful" -type f -name '*.sql' 2>/dev/null | wc -l
  printf 'afl_workers='; count_fresh_workers "$OUT_FAST" "$OUT_STATE"
  brief_one fast "$OUT_FAST"
  brief_one stateful "$OUT_STATE"
  "$WIRE" status
  "$BINARY" status
}

main() {
  case "${1:-status}" in
    init) init_campaign ;;
    start) start_campaign ;;
    stop)
      tmux kill-session -t "$SESSION" 2>/dev/null || true
      echo "stopped $SESSION"
      ;;
    status|status-brief) status_brief ;;
    attach) exec tmux attach -t "$SESSION" ;;
    *) echo "usage: $0 init|start|stop|status|attach" >&2; exit 2 ;;
  esac
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi
