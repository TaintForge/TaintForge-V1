#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SELF="$ROOT/harnesses/dotnet_fuzz/kestrel_http1/campaign.sh"
PROJECT="$ROOT/harnesses/dotnet_fuzz/kestrel_http1/KestrelHttp1Fuzz.csproj"
SEEDER="$ROOT/harnesses/dotnet_fuzz/kestrel_http1/seed_corpus.py"
DICT="$ROOT/harnesses/dotnet_fuzz/kestrel_http1/http.dict"
ASPNET_LAB="$ROOT/.labs/dotnet/source/aspnetcore-10.0.12"
DOTNET="$ASPNET_LAB/.dotnet/dotnet"
TOOL_DIR="$ROOT/.tools/dotnet/sharpfuzz"
SHARPFUZZ="$TOOL_DIR/sharpfuzz"
STATE="$ROOT/workspace/dotnet-bounty/kestrel-http1"
PUBLISH="$STATE/publish"
CORPUS="$STATE/corpus"
OUTPUT="$STATE/afl-diff-v2"
SESSION="${TF_DOTNET_FUZZ_SESSION:-taintforge-dotnet-fuzz}"
TARGET_DLL="$PUBLISH/Microsoft.AspNetCore.Server.Kestrel.Core.dll"
HARNESS_DLL="$PUBLISH/KestrelHttp1Fuzz.dll"
SOURCE_KESTREL_DLL="$ASPNET_LAB/artifacts/bin/Microsoft.AspNetCore.Server.Kestrel.Core/Debug/net10.0/Microsoft.AspNetCore.Server.Kestrel.Core.dll"

export DOTNET_ROOT="$(dirname "$DOTNET")"
export DOTNET_ROLL_FORWARD=Major

prepare() {
  [ -x "$DOTNET" ] || { echo "missing bootstrapped .NET: $DOTNET" >&2; exit 3; }
  [ -f "$SOURCE_KESTREL_DLL" ] || {
    echo "Kestrel Debug build is missing; build the lab copy first" >&2
    exit 3
  }

  mkdir -p "$TOOL_DIR" "$STATE" "$CORPUS"
  if [ ! -x "$SHARPFUZZ" ]; then
    "$DOTNET" tool install SharpFuzz.CommandLine --tool-path "$TOOL_DIR" --version 2.2.0
  fi

  "$DOTNET" publish "$PROJECT" -c Release -o "$PUBLISH"
  # Publish is incremental and can otherwise leave the previously instrumented assembly in
  # place. Always restore a clean source-built target before applying SharpFuzz.
  install -m 0644 "$SOURCE_KESTREL_DLL" "$TARGET_DLL"
  "$SHARPFUZZ" "$TARGET_DLL"
  python3 "$SEEDER" "$CORPUS"
  echo "prepared=$PUBLISH"
  echo "corpus=$CORPUS"
}

run_worker() {
  local role="$1"
  local name="$2"
  local input="$CORPUS"
  [ ! -d "$OUTPUT/$name" ] || input="-"
  export AFL_SKIP_BIN_CHECK=1
  export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
  export TF_KESTREL_STRICT_CRLF=1
  if [ "$role" = main ]; then
    exec afl-fuzz -i "$input" -o "$OUTPUT" -M "$name" -p explore \
      -x "$DICT" -t 10000 -m none -- "$DOTNET" "$HARNESS_DLL"
  else
    exec afl-fuzz -i "$input" -o "$OUTPUT" -S "$name" -p fast \
      -x "$DICT" -t 10000 -m none -- "$DOTNET" "$HARNESS_DLL"
  fi
}

start() {
  prepare
  tmux has-session -t "$SESSION" 2>/dev/null && {
    echo "already running: tmux attach -t $SESSION"
    return 0
  }

  local main_pane secondary_pane structured_pane status_pane
  printf -v main_cmd '%q run-worker main parser-main' "$SELF"
  main_pane="$(tmux new-session -d -s "$SESSION" -n fuzz -x 240 -y 60 -c "$ROOT" -P -F '#{pane_id}' "$main_cmd")"
  printf -v secondary_cmd '%q run-worker secondary parser-secondary' "$SELF"
  secondary_pane="$(tmux split-window -h -t "$main_pane" -c "$ROOT" -P -F '#{pane_id}' "$secondary_cmd")"
  # Keep a distinct synchronized worker for source-derived semantic seeds.  Its AFL
  # directory is append-only like the original pair, and on first launch it imports
  # the corpus paths that a resumed (-i -) worker cannot discover.
  printf -v structured_cmd '%q run-worker secondary parser-structured' "$SELF"
  structured_pane="$(tmux split-window -v -t "$main_pane" -c "$ROOT" -P -F '#{pane_id}' "$structured_cmd")"
  printf -v status_cmd 'watch -n 2 %q status' "$SELF"
  status_pane="$(tmux split-window -v -t "$secondary_pane" -c "$ROOT" -P -F '#{pane_id}' "$status_cmd")"
  tmux select-layout -t "$SESSION:fuzz" tiled
  tmux select-pane -t "$main_pane" -T "Kestrel HTTP/1 AFL main"
  tmux select-pane -t "$secondary_pane" -T "Kestrel HTTP/1 AFL secondary"
  tmux select-pane -t "$structured_pane" -T "Kestrel HTTP/1 AFL structured"
  tmux select-pane -t "$status_pane" -T "Kestrel fuzz status"
  tmux set -t "$SESSION" mouse on
  echo "started: tmux attach -t $SESSION"
}

status() {
  printf 'session=%s\n' "$SESSION"
  if tmux has-session -t "$SESSION" 2>/dev/null; then
    tmux list-panes -t "$SESSION:fuzz" -F '#{pane_title} dead=#{pane_dead} pid=#{pane_pid}'
  else
    echo 'tmux=stopped'
  fi
  if [ -d "$OUTPUT" ]; then
    for stats in "$OUTPUT"/*/fuzzer_stats; do
      [ -f "$stats" ] || continue
      worker="$(basename "$(dirname "$stats")")"
      printf '%s ' "$worker"
      awk -F ': +' '/^(execs_done|execs_per_sec|corpus_count|saved_crashes|saved_hangs|last_find)/ {printf "%s=%s ", $1, $2} END {print ""}' "$stats"
    done
  fi
}

stop() {
  tmux kill-session -t "$SESSION" 2>/dev/null || true
  echo "stopped $SESSION; corpus and findings preserved under $STATE"
}

case "${1:-status}" in
  prepare) prepare ;;
  start) start ;;
  run-worker) run_worker "${2:?role}" "${3:?name}" ;;
  status) status ;;
  attach) exec tmux attach -t "$SESSION" ;;
  stop) stop ;;
  *) echo "usage: $0 prepare|start|status|attach|stop" >&2; exit 2 ;;
esac
