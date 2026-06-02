#!/usr/bin/env bash
# TaintForge launcher with a live tmux dashboard.
# Seeds the model, spawns the 3 Codex sessions (via audit.sh SPAWN_ONLY), then opens a
# 4-pane tmux view:  A inject | B logic  /  C converge | live dashboard.
#
# Usage:
#   ./start.sh targets/<app>
#   ./start.sh -u http://localhost:8080 targets/<app>
#   ./start.sh -u http://host --accounts creds.json targets/<app>
# Detach from tmux with Ctrl-b then d (sessions keep running). Re-attach: tmux attach -t taintforge
# Stop everything:  kill $(cat workspace/_pids); tmux kill-session -t taintforge
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SESS="taintforge"
S=".agents/skills"

command -v tmux >/dev/null 2>&1 || { echo "tmux not installed - falling back to plain run"; exec "$HERE/audit.sh" "$@"; }

# spawn sessions + seed (audit.sh does the work, returns immediately)
SPAWN_ONLY=1 "$HERE/audit.sh" "$@" || { echo "spawn failed"; exit 1; }

# (re)build the tmux window
tmux kill-session -t "$SESS" 2>/dev/null
DASH="python3 $S/convergence/scripts/dashboard.py"
A="tail -n +1 -f workspace/_log_A.txt"
B="tail -n +1 -f workspace/_log_B.txt"
C="tail -n +1 -f workspace/_log_C.txt"

tmux new-session  -d -s "$SESS" -n forge "$A"        # pane 0 (A)
tmux split-window -h -t "$SESS:forge" "$B"           # pane 1 (B), right
tmux split-window -v -t "$SESS:forge.0" "$C"         # pane 2 (C), bottom-left
tmux split-window -v -t "$SESS:forge.1" "$DASH"      # pane 3 (dashboard), bottom-right
tmux select-layout -t "$SESS:forge" tiled

# pretty pane titles + borders
tmux set -t "$SESS" pane-border-status top
tmux set -t "$SESS" pane-border-format " #[bold]#{?pane_active,#[fg=cyan],#[fg=white]}#{pane_title} "
tmux select-pane -t "$SESS:forge.0" -T "🅐 INJECT / data-flow"
tmux select-pane -t "$SESS:forge.1" -T "🅑 LOGIC / access-control"
tmux select-pane -t "$SESS:forge.2" -T "🅒 CONVERGE / reproduce"
tmux select-pane -t "$SESS:forge.3" -T "📊 DASHBOARD"
tmux set -t "$SESS" mouse on

echo "tmux session '$SESS' ready. Attaching... (Ctrl-b d to detach; sessions keep running)"
sleep 1
tmux attach -t "$SESS"