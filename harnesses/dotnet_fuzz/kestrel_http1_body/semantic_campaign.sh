#!/usr/bin/env bash
set -Eeuo pipefail

TF_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
TF_SELF="$TF_ROOT/harnesses/dotnet_fuzz/kestrel_http1_body/semantic_campaign.sh"
TF_PROJECT="$TF_ROOT/harnesses/dotnet_fuzz/kestrel_http1_body/KestrelHttp1BodyFuzz.csproj"
TF_SEEDER="$TF_ROOT/harnesses/dotnet_fuzz/kestrel_http1_body/semantic_seed_corpus.py"
TF_DICT="$TF_ROOT/harnesses/dotnet_fuzz/kestrel_http1_body/http-body.dict"
TF_ASPNET_LAB="$TF_ROOT/.labs/dotnet/source/aspnetcore-10.0.12"
TF_DOTNET="$TF_ASPNET_LAB/.dotnet/dotnet"
TF_TOOL_DIR="$TF_ROOT/.tools/dotnet/sharpfuzz"
TF_SHARPFUZZ="$TF_TOOL_DIR/sharpfuzz"
TF_GENERATION="${TF_DOTNET_SEMANTIC_GENERATION:-v1}"
case "$TF_GENERATION" in
  ''|*[!A-Za-z0-9._-]*)
    echo "invalid semantic campaign generation: $TF_GENERATION" >&2
    exit 2
    ;;
esac
if [ "$TF_GENERATION" = v1 ]; then
  TF_STATE="$TF_ROOT/workspace/dotnet-bounty/kestrel-http1-body-semantic"
  TF_DEFAULT_SESSION="taintforge-dotnet-kestrel-semantic"
else
  TF_STATE="$TF_ROOT/workspace/dotnet-bounty/kestrel-http1-body-semantic-$TF_GENERATION"
  TF_DEFAULT_SESSION="taintforge-dotnet-kestrel-semantic-$TF_GENERATION"
fi
TF_PUBLISH="$TF_STATE/publish"
TF_CORPUS="$TF_STATE/corpus"
TF_OUTPUT="$TF_STATE/afl-body-semantic-$TF_GENERATION"
TF_SESSION="${TF_DOTNET_SEMANTIC_FUZZ_SESSION:-$TF_DEFAULT_SESSION}"
TF_TARGET_DLL="$TF_PUBLISH/Microsoft.AspNetCore.Server.Kestrel.Core.dll"
TF_HARNESS_DLL="$TF_PUBLISH/KestrelHttp1BodyFuzz.dll"
TF_SOURCE_HARNESS_DLL="$TF_ROOT/harnesses/dotnet_fuzz/kestrel_http1_body/bin/Release/net10.0/KestrelHttp1BodyFuzz.dll"
TF_SOURCE_KESTREL_DLL="$TF_ASPNET_LAB/artifacts/bin/Microsoft.AspNetCore.Server.Kestrel.Core/Debug/net10.0/Microsoft.AspNetCore.Server.Kestrel.Core.dll"
TF_SOURCE_APP_DIR="$TF_ASPNET_LAB/artifacts/bin/PlaintextApp/Debug/net10.0"

export DOTNET_ROOT="$(dirname "$TF_DOTNET")"
export DOTNET_ROLL_FORWARD=Major

prepare() {
  [ -x "$TF_DOTNET" ] || { echo "missing bootstrapped .NET: $TF_DOTNET" >&2; exit 3; }
  [ -f "$TF_SOURCE_KESTREL_DLL" ] || {
    echo "Kestrel Debug build is missing; build the lab copy first" >&2
    exit 3
  }
  [ -f "$TF_SOURCE_APP_DIR/Microsoft.AspNetCore.Hosting.dll" ] || {
    echo "PlaintextApp dependency closure is missing; build the lab copy first" >&2
    exit 3
  }

  mkdir -p "$TF_TOOL_DIR" "$TF_STATE" "$TF_CORPUS"
  if [ ! -x "$TF_SHARPFUZZ" ]; then
    "$TF_DOTNET" tool install SharpFuzz.CommandLine --tool-path "$TF_TOOL_DIR" --version 2.2.0
  fi

  "$TF_DOTNET" publish "$TF_PROJECT" -c Release -o "$TF_PUBLISH"
  install -m 0644 "$TF_SOURCE_APP_DIR"/*.dll "$TF_PUBLISH/"
  install -m 0644 "$TF_SOURCE_KESTREL_DLL" "$TF_TARGET_DLL"
  # Keep asynchronously executed Kestrel code stock. AFL feedback comes from the stable,
  # synchronous response/cross-request classifier after both exchanges have completed.
  install -m 0644 "$TF_SOURCE_HARNESS_DLL" "$TF_HARNESS_DLL"
  "$TF_SHARPFUZZ" "$TF_HARNESS_DLL" KestrelHttp1BodyFuzz.OutcomeCoverage
  python3 "$TF_SEEDER" "$TF_CORPUS"
  echo "prepared=$TF_PUBLISH"
  echo "corpus=$TF_CORPUS"
}

run_worker() {
  local tf_name="$1"
  local tf_input="$TF_CORPUS"
  [ ! -d "$TF_OUTPUT/$tf_name" ] || tf_input="-"
  export AFL_SKIP_BIN_CHECK=1
  export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
  export TF_KESTREL_HTTP1_SEMANTIC_REPAIR=1
  export DOTNET_HOSTBUILDER__RELOADCONFIGONCHANGE=false
  exec afl-fuzz -i "$tf_input" -o "$TF_OUTPUT" -M "$tf_name" -p explore \
    -x "$TF_DICT" -t 5000 -m none -- "$TF_DOTNET" "$TF_HARNESS_DLL"
}

start() {
  if tmux has-session -t "$TF_SESSION" 2>/dev/null; then
    echo "already running: tmux attach -t $TF_SESSION"
    return 0
  fi

  prepare

  local tf_fuzz_pane tf_status_pane tf_fuzz_cmd tf_status_cmd
  printf -v tf_fuzz_cmd 'TF_DOTNET_SEMANTIC_GENERATION=%q %q run-worker semantic-main' \
    "$TF_GENERATION" "$TF_SELF"
  tf_fuzz_pane="$(tmux new-session -d -s "$TF_SESSION" -n fuzz -x 220 -y 55 -c "$TF_ROOT" -P -F '#{pane_id}' "$tf_fuzz_cmd")"
  printf -v tf_status_cmd 'watch -n 2 env TF_DOTNET_SEMANTIC_GENERATION=%q %q status' \
    "$TF_GENERATION" "$TF_SELF"
  tf_status_pane="$(tmux split-window -h -t "$tf_fuzz_pane" -c "$TF_ROOT" -P -F '#{pane_id}' "$tf_status_cmd")"
  tmux select-layout -t "$TF_SESSION:fuzz" even-horizontal
  tmux select-pane -t "$tf_fuzz_pane" -T "Kestrel HTTP/1 semantic AFL"
  tmux select-pane -t "$tf_status_pane" -T "Kestrel semantic fuzz status"
  tmux set -t "$TF_SESSION" mouse on
  echo "started: tmux attach -t $TF_SESSION"
}

status() {
  printf 'session=%s\n' "$TF_SESSION"
  if tmux has-session -t "$TF_SESSION" 2>/dev/null; then
    tmux list-panes -t "$TF_SESSION:fuzz" -F '#{pane_title} dead=#{pane_dead} pid=#{pane_pid}'
  else
    echo 'tmux=stopped'
  fi

  if [ -d "$TF_OUTPUT" ]; then
    for tf_stats in "$TF_OUTPUT"/*/fuzzer_stats; do
      [ -f "$tf_stats" ] || continue
      tf_worker="$(basename "$(dirname "$tf_stats")")"
      printf '%s ' "$tf_worker"
      awk -F ': +' '/^(execs_done|execs_per_sec|corpus_count|saved_crashes|saved_hangs|last_find|stability|bitmap_cvg)/ {printf "%s=%s ", $1, $2} END {print ""}' "$tf_stats"
    done
  fi
}

stop() {
  tmux kill-session -t "$TF_SESSION" 2>/dev/null || true
  echo "stopped $TF_SESSION; corpus and findings preserved under $TF_STATE"
}

case "${1:-status}" in
  prepare) prepare ;;
  start) start ;;
  run-worker) run_worker "${2:?worker name}" ;;
  status) status ;;
  attach) exec tmux attach -t "$TF_SESSION" ;;
  stop) stop ;;
  *) echo "usage: $0 prepare|start|status|attach|stop" >&2; exit 2 ;;
esac
