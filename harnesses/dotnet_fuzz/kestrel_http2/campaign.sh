#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SELF="$ROOT/harnesses/dotnet_fuzz/kestrel_http2/campaign.sh"
PROJECT="$ROOT/harnesses/dotnet_fuzz/kestrel_http2/KestrelHttp2Fuzz.csproj"
SEEDER="$ROOT/harnesses/dotnet_fuzz/kestrel_http2/seed_corpus.py"
DICT="$ROOT/harnesses/dotnet_fuzz/kestrel_http2/http2.dict"
ASPNET_LAB="$ROOT/.labs/dotnet/source/aspnetcore-10.0.12"
DOTNET="$ASPNET_LAB/.dotnet/dotnet"
TOOL_DIR="$ROOT/.tools/dotnet/sharpfuzz"
SHARPFUZZ="$TOOL_DIR/sharpfuzz"
GENERATION="${TF_DOTNET_HTTP2_GENERATION:-v1}"
STATE="$ROOT/workspace/dotnet-bounty/kestrel-http2-structured"
CLEAN_PUBLISH="$STATE/publish-clean-$GENERATION"
AFL_PUBLISH="$STATE/publish-afl-$GENERATION"
CORPUS="$STATE/corpus-$GENERATION"
OUTPUT="$STATE/afl-structured-$GENERATION"
SESSION="${TF_DOTNET_HTTP2_FUZZ_SESSION:-taintforge-dotnet-kestrel-http2-$GENERATION}"
STOP_FLAG="$ROOT/workspace/dotnet-bounty/agents/_stop"
SOURCE_KESTREL_DLL="$ASPNET_LAB/artifacts/bin/Microsoft.AspNetCore.Server.Kestrel.Core/Release/net10.0/Microsoft.AspNetCore.Server.Kestrel.Core.dll"
CLEAN_KESTREL_DLL="$CLEAN_PUBLISH/Microsoft.AspNetCore.Server.Kestrel.Core.dll"
CLEAN_HARNESS_DLL="$CLEAN_PUBLISH/KestrelHttp2Fuzz.dll"
AFL_HARNESS_DLL="$AFL_PUBLISH/KestrelHttp2Fuzz.dll"

export DOTNET_ROOT="$(dirname "$DOTNET")"
export DOTNET_ROLL_FORWARD=Major
export DOTNET_HOSTBUILDER__RELOADCONFIGONCHANGE=false
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_CLI_HOME="$ROOT/workspace/dotnet-bounty/dotnet-cli-home"
export NUGET_HTTP_CACHE_PATH="$ROOT/workspace/dotnet-bounty/nuget/http"

check_generation() {
  case "$GENERATION" in
    v1) ;;
    *) echo "unsupported HTTP/2 lane generation: $GENERATION" >&2; exit 2 ;;
  esac
}

prepare() {
  check_generation
  [ -x "$DOTNET" ] || { echo "missing bootstrapped .NET: $DOTNET" >&2; exit 3; }
  [ -f "$SOURCE_KESTREL_DLL" ] || {
    echo "Kestrel Release build is missing; build the lab copy first" >&2
    exit 3
  }

  mkdir -p "$TOOL_DIR" "$STATE" "$CORPUS" "$CLEAN_PUBLISH" "$AFL_PUBLISH" \
    "$DOTNET_CLI_HOME" "$NUGET_HTTP_CACHE_PATH"
  if [ ! -x "$SHARPFUZZ" ]; then
    "$DOTNET" tool install SharpFuzz.CommandLine --tool-path "$TOOL_DIR" --version 2.2.0
  fi

  "$DOTNET" publish "$PROJECT" -c Release -o "$CLEAN_PUBLISH" --nologo
  # Publishing can be incremental. Restore the exact uninstrumented source-built Kestrel and
  # keep a separate clean replay tree before instrumenting only the synchronous classifier.
  install -m 0644 "$SOURCE_KESTREL_DLL" "$CLEAN_KESTREL_DLL"
  cp -a "$CLEAN_PUBLISH/." "$AFL_PUBLISH/"
  "$SHARPFUZZ" "$AFL_HARNESS_DLL" KestrelHttp2Fuzz.Http2OutcomeCoverage
  python3 "$SEEDER" "$CORPUS"

  echo "generation=$GENERATION"
  echo "clean_publish=$CLEAN_PUBLISH"
  echo "afl_publish=$AFL_PUBLISH"
  echo "corpus=$CORPUS"
  sha256sum "$SOURCE_KESTREL_DLL" "$CLEAN_KESTREL_DLL" \
    "$AFL_PUBLISH/Microsoft.AspNetCore.Server.Kestrel.Core.dll"
}

replay_seeds() {
  [ -f "$CLEAN_HARNESS_DLL" ] || prepare
  local seed
  local count=0
  for seed in "$CORPUS"/*; do
    [ -f "$seed" ] || continue
    timeout 15s "$DOTNET" "$CLEAN_HARNESS_DLL" --replay "$seed"
    count=$((count + 1))
  done
  echo "clean_seed_replays=$count"
}

replay_input() {
  local input="${1:?input path}"
  local repetitions="${2:-1}"
  [ -f "$CLEAN_HARNESS_DLL" ] || prepare
  local run
  for ((run = 1; run <= repetitions; run++)); do
    echo "replay=$run/$repetitions input=$input"
    timeout 15s "$DOTNET" "$CLEAN_HARNESS_DLL" --replay "$input"
  done
}

run_worker() {
  local name="$1"
  local input="$CORPUS"
  [ ! -d "$OUTPUT/$name" ] || input="-"
  export AFL_SKIP_BIN_CHECK=1
  export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
  export AFL_NO_UI=1
  exec afl-fuzz -i "$input" -o "$OUTPUT" -M "$name" -p explore \
    -x "$DICT" -t 15000 -m none -- "$DOTNET" "$AFL_HARNESS_DLL"
}

start() {
  [ ! -e "$STOP_FLAG" ] || { echo "role stop flag exists: $STOP_FLAG" >&2; exit 4; }
  if tmux has-session -t "$SESSION" 2>/dev/null; then
    echo "already running: tmux attach -t $SESSION"
    return 0
  fi

  prepare
  replay_seeds

  local fuzz_pane status_pane
  printf -v fuzz_cmd '%q run-worker http2-main' "$SELF"
  fuzz_pane="$(tmux new-session -d -s "$SESSION" -n fuzz -x 220 -y 55 -c "$ROOT" -P -F '#{pane_id}' "$fuzz_cmd")"
  printf -v status_cmd 'watch -n 2 %q status' "$SELF"
  status_pane="$(tmux split-window -h -t "$fuzz_pane" -c "$ROOT" -P -F '#{pane_id}' "$status_cmd")"
  tmux select-layout -t "$SESSION:fuzz" even-horizontal
  tmux select-pane -t "$fuzz_pane" -T "Kestrel HTTP/2 structured AFL"
  tmux select-pane -t "$status_pane" -T "Kestrel HTTP/2 fuzz status"
  tmux set -t "$SESSION" mouse on
  echo "started: tmux attach -t $SESSION"
}

status() {
  printf 'generation=%s session=%s\n' "$GENERATION" "$SESSION"
  if tmux has-session -t "$SESSION" 2>/dev/null; then
    tmux list-panes -t "$SESSION:fuzz" -F '#{pane_title} dead=#{pane_dead} pid=#{pane_pid}'
  else
    echo 'tmux=stopped'
  fi

  if [ -d "$OUTPUT" ]; then
    local stats worker
    for stats in "$OUTPUT"/*/fuzzer_stats; do
      [ -f "$stats" ] || continue
      worker="$(basename "$(dirname "$stats")")"
      printf '%s ' "$worker"
      awk -F ': +' '/^(run_time|execs_done|execs_per_sec|corpus_count|corpus_found|stability|saved_crashes|saved_hangs|last_find)/ {printf "%s=%s ", $1, $2} END {print ""}' "$stats"
    done
  fi
}

stop() {
  tmux kill-session -t "$SESSION" 2>/dev/null || true
  echo "stopped $SESSION; all corpus and afl directories remain under $STATE"
}

case "${1:-status}" in
  prepare) prepare ;;
  replay-seeds) replay_seeds ;;
  replay) replay_input "${2:?input path}" "${3:-1}" ;;
  start) start ;;
  run-worker) run_worker "${2:?worker name}" ;;
  status) status ;;
  attach) exec tmux attach -t "$SESSION" ;;
  stop) stop ;;
  *) echo "usage: $0 prepare|replay-seeds|replay INPUT [COUNT]|start|status|attach|stop" >&2; exit 2 ;;
esac
