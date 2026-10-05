#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
MINER="$ROOT/harnesses/dotnet_fuzz/patch_variants/miner.py"
STATE="$ROOT/workspace/dotnet-bounty/patch-variants"
STOP="$STATE/_stop"
SESSION="${TF_DOTNET_PATCH_SESSION:-taintforge-dotnet-patch-variants}"

cd "$ROOT"

run_loop() {
  mkdir -p "$STATE"
  rm -f "$STOP"
  while [ ! -e "$STOP" ]; do
    python3 "$MINER" refresh >> "$STATE/refresh.log" 2>&1 || true
    for _ in $(seq 1 2160); do
      [ -e "$STOP" ] && break
      sleep 10
    done
  done
}

start() {
  if tmux has-session -t "$SESSION" 2>/dev/null; then
    echo "already running: tmux attach -t $SESSION"
    return
  fi
  mkdir -p "$STATE"
  rm -f "$STOP"
  tmux new-session -d -s "$SESSION" -n patch-variants -x 220 -y 60 -c "$ROOT" \
    "$(printf '%q' "$0") run-loop"
  tmux split-window -h -t "$SESSION:patch-variants" -c "$ROOT" \
    "watch -n 10 python3 $(printf '%q' "$MINER") status"
  tmux select-layout -t "$SESSION:patch-variants" even-horizontal
  tmux select-pane -t "$SESSION:patch-variants.0" -T "OFFICIAL ADVISORY + PATCH REFRESH"
  tmux select-pane -t "$SESSION:patch-variants.1" -T "VARIANT QUEUE"
  tmux set -t "$SESSION" mouse on
  echo "started: tmux attach -t $SESSION"
}

case "${1:-status}" in
  start) start ;;
  stop) mkdir -p "$STATE"; : > "$STOP"; tmux kill-session -t "$SESSION" 2>/dev/null || true ;;
  run-loop) run_loop ;;
  refresh) exec python3 "$MINER" refresh "${@:2}" ;;
  status) exec python3 "$MINER" status ;;
  claim|complete|show) exec python3 "$MINER" "$@" ;;
  attach) exec tmux attach -t "$SESSION" ;;
  *) echo "usage: $0 start|stop|refresh|status|claim|complete|show|attach" >&2; exit 2 ;;
esac
