#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SELF="$ROOT/harnesses/dotnet_fuzz/supported_deserialization_nrbf/campaign.sh"
SEEDER="$ROOT/harnesses/dotnet_fuzz/supported_deserialization_nrbf/seed_corpus.py"
DICT="$ROOT/harnesses/dotnet_fuzz/supported_deserialization_nrbf/nrbf.dict"
PROJECT="$ROOT/.labs/dotnet/source/resource-binary-materializer-fuzz/ResourceBinaryMaterializerFuzz.csproj"
RUNTIME_LAB="$ROOT/.labs/dotnet/source/runtime-10.0.12"
DOTNET="$RUNTIME_LAB/.dotnet/dotnet"
SOURCE_NRBF_DLL="$RUNTIME_LAB/artifacts/bin/System.Formats.Nrbf/Release/net10.0/System.Formats.Nrbf.dll"
SOURCE_RESOURCES_DLL="$RUNTIME_LAB/artifacts/bin/System.Resources.Extensions/Release/net10.0/System.Resources.Extensions.dll"
SOURCE_DATA="$ROOT/targets/dotnet-runtime-10.0.12/src/libraries/System.Resources.Extensions/tests/BinaryFormatTests/Legacy/BinaryFormatterTestData.cs"
KNOWN_DECIMAL="$ROOT/.labs/dotnet/source/nrbf-shared-dependency-callback/stock-decimal.nrbf"
TOOL_DIR="$ROOT/.tools/dotnet/sharpfuzz"
SHARPFUZZ="$TOOL_DIR/sharpfuzz"
GENERATION="${TF_DOTNET_DESER_GENERATION:-v2}"
STATE="$ROOT/workspace/dotnet-bounty/supported-deserialization-nrbf"
CLEAN_PUBLISH="$STATE/publish-clean-$GENERATION"
AFL_PUBLISH="$STATE/publish-afl-$GENERATION"
CORPUS="$STATE/corpus-$GENERATION"
CONTROL="$STATE/controls-$GENERATION/int32-clean.nrbf"
OUTPUT="$STATE/afl-$GENERATION"
SANDBOXES="$STATE/sandboxes-$GENERATION"
TRACES="$STATE/traces-$GENERATION"
CLEAN_HARNESS_DLL="$CLEAN_PUBLISH/ResourceBinaryMaterializerFuzz.dll"
AFL_HARNESS_DLL="$AFL_PUBLISH/ResourceBinaryMaterializerFuzz.dll"
SESSION="${TF_DOTNET_DESER_FUZZ_SESSION:-taintforge-dotnet-supported-deser-$GENERATION}"
STOP_FLAG="$ROOT/workspace/dotnet-bounty/agents/_stop"

export DOTNET_ROOT="$(dirname "$DOTNET")"
export DOTNET_ROLL_FORWARD=Major
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_CLI_HOME="$ROOT/workspace/dotnet-bounty/dotnet-cli-home"
export NUGET_HTTP_CACHE_PATH="$ROOT/workspace/dotnet-bounty/nuget/http"

check_generation() {
  case "$GENERATION" in
    v1|v2) ;;
    *) echo "unsupported supported-deserialization lane generation: $GENERATION" >&2; exit 2 ;;
  esac
}

require_inputs() {
  [ -x "$DOTNET" ] || { echo "missing bootstrapped .NET: $DOTNET" >&2; exit 3; }
  [ -f "$SOURCE_NRBF_DLL" ] || { echo "missing source-built System.Formats.Nrbf: $SOURCE_NRBF_DLL" >&2; exit 3; }
  [ -f "$SOURCE_RESOURCES_DLL" ] || { echo "missing source-built System.Resources.Extensions: $SOURCE_RESOURCES_DLL" >&2; exit 3; }
  [ -f "$SOURCE_DATA" ] || { echo "missing official NRBF test data: $SOURCE_DATA" >&2; exit 3; }
  command -v unshare >/dev/null || { echo "unshare is required to deny non-loopback traffic" >&2; exit 3; }
}

prepare() {
  check_generation
  require_inputs
  mkdir -p "$TOOL_DIR" "$STATE" "$CORPUS" "$CLEAN_PUBLISH" "$AFL_PUBLISH" \
    "$SANDBOXES" "$TRACES" "$DOTNET_CLI_HOME" "$NUGET_HTTP_CACHE_PATH"
  if [ ! -x "$SHARPFUZZ" ]; then
    "$DOTNET" tool install SharpFuzz.CommandLine --tool-path "$TOOL_DIR" --version 2.2.0
  fi

  "$DOTNET" publish "$PROJECT" -c Release -o "$CLEAN_PUBLISH" --nologo
  install -m 0644 "$SOURCE_NRBF_DLL" "$CLEAN_PUBLISH/System.Formats.Nrbf.dll"
  install -m 0644 "$SOURCE_RESOURCES_DLL" "$CLEAN_PUBLISH/System.Resources.Extensions.dll"

  # Keep a pristine exact-build replay tree. Restore the AFL tree from it before each
  # instrumentation pass; no queue directory is removed or reused across generations.
  cp -a "$CLEAN_PUBLISH/." "$AFL_PUBLISH/"
  "$SHARPFUZZ" "$AFL_PUBLISH/System.Formats.Nrbf.dll"
  if [ "$GENERATION" = "v1" ]; then
    # Preserved negative control: materializer callback and lazy assembly-load paths make
    # whole-assembly coverage nondeterministic. v2 leaves this stock and uses it as an oracle.
    "$SHARPFUZZ" "$AFL_PUBLISH/System.Resources.Extensions.dll"
  fi
  python3 "$SEEDER" "$SOURCE_DATA" "$CORPUS" "$CONTROL"

  echo "generation=$GENERATION"
  echo "clean_publish=$CLEAN_PUBLISH"
  echo "afl_publish=$AFL_PUBLISH"
  echo "corpus=$CORPUS"
  sha256sum "$SOURCE_NRBF_DLL" "$CLEAN_PUBLISH/System.Formats.Nrbf.dll" \
    "$SOURCE_RESOURCES_DLL" "$CLEAN_PUBLISH/System.Resources.Extensions.dll" "$CONTROL"
}

run_isolated() {
  unshare --user --map-root-user --net -- "$@"
}

replay_control() {
  local repetitions="${1:-3}"
  [ -f "$CLEAN_HARNESS_DLL" ] || prepare
  mkdir -p "$SANDBOXES/control"
  local run
  for ((run = 1; run <= repetitions; run++)); do
    echo "clean_control_replay=$run/$repetitions"
    TF_DESER_SANDBOX_ROOT="$SANDBOXES/control" \
      timeout 20s unshare --user --map-root-user --net -- \
      "$DOTNET" "$CLEAN_HARNESS_DLL" replay-probe "$CONTROL" "$CONTROL"
  done
}

replay_input() {
  local input
  input="$(realpath "${1:?input path}")"
  local repetitions="${2:-1}"
  [ -f "$CLEAN_HARNESS_DLL" ] || prepare
  mkdir -p "$SANDBOXES/replay"
  local run
  for ((run = 1; run <= repetitions; run++)); do
    echo "stock_replay=$run/$repetitions input=$input"
    TF_DESER_SANDBOX_ROOT="$SANDBOXES/replay" \
      timeout 20s unshare --user --map-root-user --net -- \
      "$DOTNET" "$CLEAN_HARNESS_DLL" replay-probe "$input" "$CONTROL"
  done
}

replay_seeds() {
  [ -f "$CLEAN_HARNESS_DLL" ] || prepare
  local seed count=0
  for seed in "$CORPUS"/*.nrbf; do
    [ -f "$seed" ] || continue
    if ! replay_input "$seed" 1 >/dev/null; then
      echo "clean_seed_replay_failed=$seed" >&2
      return 6
    fi
    count=$((count + 1))
    if ((count % 50 == 0)); then
      echo "clean_seed_replays=$count"
    fi
  done
  echo "clean_seed_replays=$count"
}

replay_known_regression() {
  [ -f "$CLEAN_HARNESS_DLL" ] || prepare
  echo "known_regression=$KNOWN_DECIMAL"
  set +e
  replay_input "$KNOWN_DECIMAL" 1
  local status=$?
  set -e
  echo "known_regression_exit=$status"
  if [ "$status" -eq 0 ]; then
    echo "known invalid-Decimal regression unexpectedly completed cleanly" >&2
    return 5
  fi
  replay_control 2
}

trace_input() {
  local input
  input="$(realpath "${1:?input path}")"
  [ -f "$CLEAN_HARNESS_DLL" ] || prepare
  command -v strace >/dev/null || { echo "strace is required for side-effect tracing" >&2; exit 3; }
  local stem trace_dir
  stem="$(sha256sum "$input" | awk '{print substr($1, 1, 16)}')-$(date -u +%Y%m%dT%H%M%SZ)"
  trace_dir="$TRACES/$stem"
  mkdir -p "$trace_dir" "$SANDBOXES/trace"
  set +e
  TF_DESER_SANDBOX_ROOT="$SANDBOXES/trace" TF_DESER_TRACE_MARKERS=1 \
    timeout 30s unshare --user --map-root-user --net -- \
    strace -ff -qq -s 256 -e trace=%file,%network,%process,write -o "$trace_dir/trace" \
    "$DOTNET" "$CLEAN_HARNESS_DLL" replay-probe "$input" "$CONTROL" \
    >"$trace_dir/stdout.txt" 2>"$trace_dir/stderr.txt"
  local status=$?
  set -e
  echo "trace_exit=$status trace_dir=$trace_dir"
  grep -H "TF_DESER_CANDIDATE_" "$trace_dir"/trace* "$trace_dir/stderr.txt" || true
  local marker_trace
  marker_trace="$(grep -l 'TF_DESER_CANDIDATE_BEGIN' "$trace_dir"/trace* | head -n 1 || true)"
  if [ -n "$marker_trace" ]; then
    awk '/TF_DESER_CANDIDATE_BEGIN/{inside=1; next} /TF_DESER_CANDIDATE_END/{inside=0} inside' \
      "$marker_trace" >"$trace_dir/candidate-syscalls.txt"
    grep -E \
      '^(execve|execveat|fork|vfork|clone|clone3|socket|socketpair|connect|bind|listen|accept|accept4|sendto|recvfrom|sendmsg|recvmsg|creat|unlink|unlinkat|rename|renameat|renameat2|mkdir|mkdirat|rmdir|link|linkat|symlink|symlinkat|truncate|ftruncate|mount)\(|^open(at)?\(.*O_(WRONLY|RDWR|CREAT|TRUNC|APPEND)' \
      "$trace_dir/candidate-syscalls.txt" >"$trace_dir/candidate-side-effect-syscalls.txt" || true
    echo "candidate_side_effect_syscalls=$(wc -l <"$trace_dir/candidate-side-effect-syscalls.txt")"
  else
    echo "candidate trace has no completed begin marker; inspect all trace shards" >&2
  fi
  return "$status"
}

run_worker() {
  local name="$1"
  local input="$CORPUS"
  [ ! -d "$OUTPUT/$name" ] || input="-"
  mkdir -p "$SANDBOXES/$name"
  export TF_DESER_SANDBOX_ROOT="$SANDBOXES/$name"
  export AFL_SKIP_BIN_CHECK=1
  export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
  export AFL_NO_UI=1
  exec afl-fuzz -i "$input" -o "$OUTPUT" -M "$name" -p explore \
    -x "$DICT" -t 10000 -m none -- \
    unshare --user --map-root-user --net -- "$DOTNET" "$AFL_HARNESS_DLL" afl "$CONTROL"
}

start() {
  [ ! -e "$STOP_FLAG" ] || { echo "role stop flag exists: $STOP_FLAG" >&2; exit 4; }
  if tmux has-session -t "$SESSION" 2>/dev/null; then
    if tmux list-panes -t "$SESSION" -F '#{pane_title}' | grep -Fxq 'Supported NRBF compatibility AFL'; then
      echo "already running: tmux attach -t $SESSION"
      return 0
    fi
    echo "removing stale status-only tmux session; all AFL state remains under $OUTPUT"
    tmux kill-session -t "$SESSION"
  fi

  prepare
  replay_control 3
  replay_seeds

  local fuzz_pane status_pane
  printf -v fuzz_cmd '%q run-worker deser-main' "$SELF"
  fuzz_pane="$(tmux new-session -d -s "$SESSION" -n fuzz -x 220 -y 55 -c "$ROOT" -P -F '#{pane_id}' "$fuzz_cmd")"
  printf -v status_cmd 'watch -n 2 %q status' "$SELF"
  status_pane="$(tmux split-window -h -t "$fuzz_pane" -c "$ROOT" -P -F '#{pane_id}' "$status_cmd")"
  tmux select-layout -t "$SESSION:fuzz" even-horizontal
  tmux select-pane -t "$fuzz_pane" -T "Supported NRBF compatibility AFL"
  tmux select-pane -t "$status_pane" -T "Supported deserialization status"
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
      awk -F ': +' '/^(run_time|execs_done|execs_per_sec|corpus_count|corpus_found|stability|saved_crashes|saved_hangs|last_find|last_crash)/ {printf "%s=%s ", $1, $2} END {print ""}' "$stats"
    done
  fi
}

stop() {
  tmux kill-session -t "$SESSION" 2>/dev/null || true
  echo "stopped $SESSION; corpus, traces, sandboxes, and every afl generation remain under $STATE"
}

case "${1:-status}" in
  prepare) prepare ;;
  replay-control) replay_control "${2:-3}" ;;
  replay-seeds) replay_seeds ;;
  replay) replay_input "${2:?input path}" "${3:-1}" ;;
  replay-known-regression) replay_known_regression ;;
  trace) trace_input "${2:?input path}" ;;
  start) start ;;
  run-worker) run_worker "${2:?worker name}" ;;
  status) status ;;
  attach) exec tmux attach -t "$SESSION" ;;
  stop) stop ;;
  *)
    echo "usage: $0 prepare|replay-control [COUNT]|replay-seeds|replay INPUT [COUNT]|replay-known-regression|trace INPUT|start|status|attach|stop" >&2
    exit 2
    ;;
esac
