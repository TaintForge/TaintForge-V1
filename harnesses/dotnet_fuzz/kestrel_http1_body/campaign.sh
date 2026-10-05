#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SELF="$ROOT/harnesses/dotnet_fuzz/kestrel_http1_body/campaign.sh"
PROJECT="$ROOT/harnesses/dotnet_fuzz/kestrel_http1_body/KestrelHttp1BodyFuzz.csproj"
SEEDER="$ROOT/harnesses/dotnet_fuzz/kestrel_http1_body/seed_corpus.py"
DICT="$ROOT/harnesses/dotnet_fuzz/kestrel_http1_body/http-body.dict"
ASPNET_LAB="$ROOT/.labs/dotnet/source/aspnetcore-10.0.12"
DOTNET="$ASPNET_LAB/.dotnet/dotnet"
TOOL_DIR="$ROOT/.tools/dotnet/sharpfuzz"
SHARPFUZZ="$TOOL_DIR/sharpfuzz"
STATE="$ROOT/workspace/dotnet-bounty/kestrel-http1-body"
PUBLISH="$STATE/publish"
CORPUS="$STATE/corpus"
OUTPUT="$STATE/afl-body-v2"
SESSION="${TF_DOTNET_BODY_FUZZ_SESSION:-taintforge-dotnet-kestrel-body}"
TARGET_DLL="$PUBLISH/Microsoft.AspNetCore.Server.Kestrel.Core.dll"
HARNESS_DLL="$PUBLISH/KestrelHttp1BodyFuzz.dll"
SOURCE_HARNESS_DLL="$ROOT/harnesses/dotnet_fuzz/kestrel_http1_body/bin/Release/net10.0/KestrelHttp1BodyFuzz.dll"
SOURCE_KESTREL_DLL="$ASPNET_LAB/artifacts/bin/Microsoft.AspNetCore.Server.Kestrel.Core/Debug/net10.0/Microsoft.AspNetCore.Server.Kestrel.Core.dll"
SOURCE_APP_DIR="$ASPNET_LAB/artifacts/bin/PlaintextApp/Debug/net10.0"

export DOTNET_ROOT="$(dirname "$DOTNET")"
export DOTNET_ROLL_FORWARD=Major

prepare() {
  [ -x "$DOTNET" ] || { echo "missing bootstrapped .NET: $DOTNET" >&2; exit 3; }
  [ -f "$SOURCE_KESTREL_DLL" ] || {
    echo "Kestrel Debug build is missing; build the lab copy first" >&2
    exit 3
  }
  [ -f "$SOURCE_APP_DIR/Microsoft.AspNetCore.Hosting.dll" ] || {
    echo "PlaintextApp dependency closure is missing; build the lab copy first" >&2
    exit 3
  }

  mkdir -p "$TOOL_DIR" "$STATE" "$CORPUS"
  if [ ! -x "$SHARPFUZZ" ]; then
    "$DOTNET" tool install SharpFuzz.CommandLine --tool-path "$TOOL_DIR" --version 2.2.0
  fi

  "$DOTNET" publish "$PROJECT" -c Release -o "$PUBLISH"
  # The bootstrapped SDK's shared ASP.NET runtime can lag the checked-out patch. Stage the
  # complete source-built PlaintextApp dependency closure so Kestrel Core and its DI/hosting
  # collaborators are all from the authorized 10.0.12 lab build.
  install -m 0644 "$SOURCE_APP_DIR"/*.dll "$PUBLISH/"
  install -m 0644 "$SOURCE_KESTREL_DLL" "$TARGET_DLL"
  # Kestrel runs request processing on worker threads. Instrumenting those product types made
  # AFL maps timing-dependent and turned response-oracle noise into non-stock signal families.
  # Restore both assemblies on every prepare, leave Kestrel pristine, and instrument only the
  # synchronous post-exchange classifier that exposes protocol outcomes to AFL.
  install -m 0644 "$SOURCE_HARNESS_DLL" "$HARNESS_DLL"
  "$SHARPFUZZ" "$HARNESS_DLL" KestrelHttp1BodyFuzz.OutcomeCoverage
  python3 "$SEEDER" "$CORPUS"
  echo "prepared=$PUBLISH"
  echo "corpus=$CORPUS"
}

run_worker() {
  local name="$1"
  local input="$CORPUS"
  [ ! -d "$OUTPUT/$name" ] || input="-"
  export AFL_SKIP_BIN_CHECK=1
  export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
  export DOTNET_HOSTBUILDER__RELOADCONFIGONCHANGE=false
  exec afl-fuzz -i "$input" -o "$OUTPUT" -M "$name" -p explore \
    -x "$DICT" -t 5000 -m none -- "$DOTNET" "$HARNESS_DLL"
}

start() {
  if tmux has-session -t "$SESSION" 2>/dev/null; then
    echo "already running: tmux attach -t $SESSION"
    return 0
  fi

  prepare

  local fuzz_pane status_pane
  printf -v fuzz_cmd '%q run-worker body-main' "$SELF"
  fuzz_pane="$(tmux new-session -d -s "$SESSION" -n fuzz -x 220 -y 55 -c "$ROOT" -P -F '#{pane_id}' "$fuzz_cmd")"
  printf -v status_cmd 'watch -n 2 %q status' "$SELF"
  status_pane="$(tmux split-window -h -t "$fuzz_pane" -c "$ROOT" -P -F '#{pane_id}' "$status_cmd")"
  tmux select-layout -t "$SESSION:fuzz" even-horizontal
  tmux select-pane -t "$fuzz_pane" -T "Kestrel HTTP/1 body AFL"
  tmux select-pane -t "$status_pane" -T "Kestrel body fuzz status"
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
  run-worker) run_worker "${2:?worker name}" ;;
  status) status ;;
  attach) exec tmux attach -t "$SESSION" ;;
  stop) stop ;;
  *) echo "usage: $0 prepare|start|status|attach|stop" >&2; exit 2 ;;
esac
