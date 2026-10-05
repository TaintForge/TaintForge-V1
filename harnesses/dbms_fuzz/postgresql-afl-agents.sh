#!/usr/bin/env bash
# Event-driven C/E/D agents plus adaptive PostgreSQL fuzzing producer F.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SELF="$ROOT/harnesses/dbms_fuzz/postgresql-afl-agents.sh"
QUEUE="$ROOT/harnesses/dbms_fuzz/postgresql-afl-agent-queue.py"
STATE="$ROOT/workspace/db-fuzz/postgresql-afl/agents"
STOP="$STATE/_stop"
PIDS="$STATE/_pids"
SESSION="${DBFUZZ_AGENT_SESSION:-taintforge-pg-agents}"
LOG_C="$STATE/C-triage.log"
LOG_E="$STATE/E-reanalysis.log"
LOG_D="$STATE/D-exploit.log"
LOG_F="$STATE/F-adapt.log"
LOG_RUNNER="$STATE/runtime.log"
ADAPT_INTERVAL="${DBFUZZ_ADAPT_INTERVAL:-1800}"

timestamp() {
  date '+%Y-%m-%dT%H:%M:%S%z'
}

prompt_c() {
  local artifact="$1"
  cat <<EOF
You are C, the event-driven PostgreSQL AFL crash triage agent in an authorized local campaign.
Do not delegate. Read $ROOT/AGENTS.md, then read the dbms-fuzzing and convergence skills fully.

Analyze only this sanitizer replay artifact: $artifact
Its AFL input, summary, stdout/stderr, and sanitizer logs are inside that directory. The
read-only PostgreSQL 18.6 source is $ROOT/targets/zdc-2026-postgresql-18.6. Authorized endpoints
are only 127.0.0.1:55432, :55433, and :55434. Never print credentials; read an existing mode-0600
DSN file if low-privilege replay is needed.

Minimize while preserving the same crash signature, obtain a source-level root cause, replay on
the ASan build, and then test the exact stock target. Explicitly determine whether the input is
pre-auth, low-privilege SQL, or only standalone-superuser reachable. A standalone-backend assert
is not automatically a remotely reachable vulnerability. Create or update a track-A finding only
through .agents/skills/_shared/write_finding.py and only after the dbms-fuzzing promotion threshold.

At the end, write $artifact/agent-review.json with JSON fields: status, classification,
root_cause, asan_reproduced, stock_reproduced, auth_level, finding_id, and notes. Use status
promoted, rejected, or needs_reanalysis. Keep evidence exact and bounds honest.
EOF
}

prompt_e() {
  local finding="$1"
  cat <<EOF
You are E, the PostgreSQL AFL needs_reanalysis agent in an authorized local campaign. Do not
delegate. Read $ROOT/AGENTS.md, then read the dbms-fuzzing and convergence skills fully.

Reanalyze only this finding: $finding
Read its exact failed premise and associated artifacts under
$ROOT/workspace/db-fuzz/postgresql-afl. Determine whether the missing condition is reachability,
authentication level, reproducibility, sanitizer evidence, or stock-build behavior. Use only
127.0.0.1:55432, :55433, and :55434. Never print credentials. Update findings only through
.agents/skills/_shared/write_finding.py. Return it for retriage only with genuinely new evidence;
otherwise mark it false_positive with the precise reason.
EOF
}

prompt_d() {
  local finding="$1"
  cat <<EOF
You are D, the PostgreSQL memory-corruption exploitation agent in an authorized local campaign.
Do not delegate. Read $ROOT/AGENTS.md, then read the convergence and dbms-fuzzing skills fully.

Work only on this reproduced or confirmed finding: $finding
Verify the exact primitive before attempting escalation. Determine controllable bytes, size,
offset, lifetime, allocator assumptions, authentication level, and mitigations. Target only the
local authorized PostgreSQL endpoints 127.0.0.1:55432, :55433, and :55434. Seek demonstrable RCE,
but never overstate an assert, DoS, or standalone-only condition. Update the exploit object only
through .agents/skills/_shared/write_finding.py and store any exploit artifact under the finding's
report directory.
EOF
}

prompt_f() {
  cat <<EOF
You are F, the adaptive PostgreSQL memory-corruption fuzzing producer in an authorized local
campaign. Do not delegate. Read $ROOT/AGENTS.md and the dbms-fuzzing skill completely.

Inspect the live campaign through $ROOT/harnesses/dbms_fuzz/postgresql-afl-campaign.sh status,
AFL fuzzer_stats/queues, wire artifacts, sanitizer replay output, and the read-only PostgreSQL
18.6 source at $ROOT/targets/zdc-2026-postgresql-18.6. Authorized endpoints are only loopback
127.0.0.1 ports 55432, 55433, and 55434. Never print credentials or modify targets/.

Look for concrete stagnation causes: invalid-seed rate, unstable coverage, untouched parser/type/
executor/protocol states, low mutation acceptance, repeated harness-only assertions, timeouts, or
worker failure. If evidence supports it, make at most one focused self-repair or corpus/mutator/
harness improvement under harnesses/dbms_fuzz, add a regression test, and verify it without
resetting queues or stopping a healthy campaign. Generated state belongs under workspace/db-fuzz.
If no change is justified, record the measured reason and leave code unchanged. A crash is only a
lead until sanitizer reproduction, stock replay, reachability, and authentication level are known.
EOF
}

run_model() {
  local role="$1"
  local prompt="$2"
  case "$role" in
    C|E)
      codex exec --sandbox workspace-write \
        --config sandbox_workspace_write.network_access=true \
        --config web_search=live \
        --model gpt-6-sol --config model_reasoning_effort=xhigh "$prompt"
      ;;
    D|F)
      codex exec --sandbox workspace-write \
        --config sandbox_workspace_write.network_access=true \
        --model gpt-daybreak-blue-latest --config model_reasoning_effort=max "$prompt"
      ;;
  esac
}

supervise_adaptation() {
  local child="" prompt
  trap '[ -z "$child" ] || kill "$child" 2>/dev/null || true; exit 0' INT TERM
  while [ ! -e "$STOP" ]; do
    prompt="$(prompt_f)"
    printf '[%s] role F starting adaptive campaign review\n' "$(timestamp)" >> "$LOG_F"
    run_model F "$prompt" >> "$LOG_F" 2>&1 &
    child=$!
    if wait "$child"; then
      printf '[%s] role F adaptive review complete\n' "$(timestamp)" >> "$LOG_F"
    else
      printf '[%s] role F adaptive review failed; next interval will retry\n' "$(timestamp)" >> "$LOG_F"
    fi
    child=""
    local slept=0
    while [ "$slept" -lt "$ADAPT_INTERVAL" ] && [ ! -e "$STOP" ]; do
      sleep 5
      slept=$((slept + 5))
    done
  done
}

supervise() {
  local role="$1"
  local logfile="$2"
  local item prompt idle=0 child=""
  trap '[ -z "$child" ] || kill "$child" 2>/dev/null || true; exit 0' INT TERM
  while [ ! -e "$STOP" ]; do
    item="$(python3 "$QUEUE" next "$role")"
    if [ -z "$item" ]; then
      if [ "$idle" = "0" ]; then
        printf '[%s] role %s idle: waiting for eligible AFL evidence\n' "$(timestamp)" "$role" >> "$logfile"
        idle=1
      fi
      sleep 5
      continue
    fi
    idle=0
    printf '[%s] role %s consuming %s\n' "$(timestamp)" "$role" "$item" >> "$logfile"
    case "$role" in
      C) prompt="$(prompt_c "$item")" ;;
      E) prompt="$(prompt_e "$item")" ;;
      D) prompt="$(prompt_d "$item")" ;;
    esac
    run_model "$role" "$prompt" >> "$logfile" 2>&1 &
    child=$!
    if wait "$child"; then
      if [ "$role" = "C" ]; then
        if [ ! -s "$item/agent-review.json" ]; then
          printf '[%s] role C returned without agent-review.json; retrying later\n' "$(timestamp)" >> "$logfile"
          sleep 30
        fi
      else
        python3 "$QUEUE" mark "$role" "$item"
      fi
    else
      printf '[%s] role %s failed; retrying later\n' "$(timestamp)" "$role" >> "$logfile"
      sleep 30
    fi
    child=""
  done
}

run_supervisors() {
  mkdir -p "$STATE" "$ROOT/workspace/findings"
  printf '[%s] focused PostgreSQL AFL agent runner started\n' "$(timestamp)" >> "$LOG_RUNNER"
  supervise C "$LOG_C" & local c_pid=$!
  supervise E "$LOG_E" & local e_pid=$!
  supervise D "$LOG_D" & local d_pid=$!
  supervise_adaptation & local f_pid=$!
  printf '%s %s %s %s\n' "$c_pid" "$e_pid" "$d_pid" "$f_pid" > "$PIDS"
  trap 'kill "$c_pid" "$e_pid" "$d_pid" "$f_pid" 2>/dev/null || true; wait 2>/dev/null || true; exit 0' INT TERM
  wait
}

status_brief() {
  printf 'session=%s\n' "$SESSION"
  python3 "$QUEUE" status
  printf 'afl_workers='; { ps -C afl-fuzz -o pid= 2>/dev/null || true; } | wc -l
  printf 'triage_agent='; pgrep -f 'gpt-6-sol.*event-driven PostgreSQL AFL crash triage' >/dev/null && echo active || echo idle
  printf 'reanalysis_agent='; pgrep -f 'gpt-6-sol.*PostgreSQL AFL needs_reanalysis' >/dev/null && echo active || echo idle
  printf 'exploit_agent='; pgrep -f 'gpt-daybreak-blue-latest.*PostgreSQL memory-corruption exploitation' >/dev/null && echo active || echo idle
  printf 'adaptive_fuzzer='; pgrep -f 'gpt-daybreak-blue-latest.*adaptive PostgreSQL memory-corruption fuzzing' >/dev/null && echo active || echo idle
}

start_session() {
  if tmux has-session -t "$SESSION" 2>/dev/null; then
    echo "already running: tmux attach -t $SESSION"
    return
  fi
  mkdir -p "$STATE" "$ROOT/workspace/findings"
  rm -f "$STOP" "$PIDS"
  : >> "$LOG_C"
  : >> "$LOG_E"
  : >> "$LOG_D"
  : >> "$LOG_F"
  : >> "$LOG_RUNNER"

  local command pane
  command="$(printf '%q' "$SELF") run"
  pane="$(tmux new-session -d -s "$SESSION" -n runtime -x 180 -y 50 -c "$ROOT" \
    -P -F '#{pane_id}' "$command")"
  tmux select-pane -t "$pane" -T "event supervisors"

  command="tail -n 100 -F $(printf '%q' "$LOG_C")"
  pane="$(tmux new-window -d -t "$SESSION:" -n triage-c -c "$ROOT" -P -F '#{pane_id}' "$command")"
  tmux select-pane -t "$pane" -T "C TRIAGE / GPT-6 Sol xhigh"

  command="tail -n 100 -F $(printf '%q' "$LOG_E")"
  pane="$(tmux new-window -d -t "$SESSION:" -n reanalysis-e -c "$ROOT" -P -F '#{pane_id}' "$command")"
  tmux select-pane -t "$pane" -T "E REANALYSIS / GPT-6 Sol xhigh"

  command="tail -n 100 -F $(printf '%q' "$LOG_D")"
  pane="$(tmux new-window -d -t "$SESSION:" -n exploit-d -c "$ROOT" -P -F '#{pane_id}' "$command")"
  tmux select-pane -t "$pane" -T "D EXPLOIT / Daybreak Blue max"

  command="tail -n 100 -F $(printf '%q' "$LOG_F")"
  pane="$(tmux new-window -d -t "$SESSION:" -n adapt-f -c "$ROOT" -P -F '#{pane_id}' "$command")"
  tmux select-pane -t "$pane" -T "F ADAPT / Daybreak Blue max"

  command="watch -n 2 $(printf '%q' "$SELF") status-brief"
  pane="$(tmux new-window -d -t "$SESSION:" -n dashboard -c "$ROOT" -P -F '#{pane_id}' "$command")"
  tmux select-pane -t "$pane" -T "AFL agent queue"
  tmux set -t "$SESSION" mouse on
  tmux select-window -t "$SESSION:dashboard"
  echo "started: tmux attach -t $SESSION"
  echo "switch windows with Ctrl-b n / Ctrl-b p"
}

stop_session() {
  mkdir -p "$STATE"
  : > "$STOP"
  if [ -s "$PIDS" ]; then
    while read -r pid; do
      [[ "$pid" =~ ^[0-9]+$ ]] && kill "$pid" 2>/dev/null || true
    done < <(tr ' ' '\n' < "$PIDS")
  fi
  tmux kill-session -t "$SESSION" 2>/dev/null || true
  echo "stopped $SESSION"
}

case "${1:-status}" in
  start) start_session ;;
  stop) stop_session ;;
  status|status-brief) status_brief ;;
  attach) exec tmux attach -t "$SESSION" ;;
  run) run_supervisors ;;
  *) echo "usage: $0 start|stop|status|attach" >&2; exit 2 ;;
esac
