#!/usr/bin/env bash
# TaintForge launcher with a live tmux dashboard.
# Seeds the model, spawns the 3 Codex sessions (audit.sh SPAWN_ONLY), then opens a tmux
# 2x2 view whose pane labels MATCH their contents (panes are captured by id, not by index,
# so the tiled layout can't scramble the labels):
#     🅐 INJECT (A)   |   🅑 LOGIC (B)
#     🅒 CONVERGE (C) |   📊 DASHBOARD
#
# Usage:  ./start.sh [-u URL] [--accounts FILE] targets/<app>
# Detach: Ctrl-b then d (sessions keep running).  Re-attach: tmux attach -t taintforge
# Stop:   touch workspace/_stop; kill $(cat workspace/_pids); pkill -f 'codex exec'; tmux kill-session -t taintforge
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SESS="taintforge"
S=".agents/skills"

command -v tmux >/dev/null 2>&1 || { echo "tmux not installed - plain run"; exec "$HERE/audit.sh" "$@"; }

mkdir -p workspace
# spawn sessions + seed (returns immediately; fds detached so background supervisors
# can't hold this shell open)
SPAWN_ONLY=1 "$HERE/audit.sh" "$@" </dev/null >workspace/_spawn.log 2>&1 || { echo "spawn failed - see workspace/_spawn.log"; exit 1; }

tmux kill-session -t "$SESS" 2>/dev/null

DASH="python3 $S/convergence/scripts/dashboard.py"
TA="tail -n +1 -f workspace/_log_A.txt"
TB="tail -n +1 -f workspace/_log_B.txt"
TC="tail -n +1 -f workspace/_log_C.txt"

# Build a reliable 2x2. Create the detached session BIG (-x/-y) so later splits never hit
# tmux's minimum-pane-size limit (that was dropping the 4th/C pane on an 80x24 default).
P_A=$(tmux new-session -d -s "$SESS" -n forge -x 250 -y 60 -P -F '#{pane_id}' "$TA")
P_B=$(tmux split-window -h -t "$P_A" -P -F '#{pane_id}' "$TB")    # top row:    A | B
P_C=$(tmux split-window -v -t "$P_A" -P -F '#{pane_id}' "$TC")    # bottom-left:  C
P_D=$(tmux split-window -v -t "$P_B" -P -F '#{pane_id}' "$DASH")  # bottom-right: DASHBOARD
tmux select-layout -t "$SESS:forge" tiled

# pane border titles, bound to the captured ids (won't scramble)
tmux set  -t "$SESS" pane-border-status top
tmux set  -t "$SESS" pane-border-format " #[bold]#{?pane_active,#[fg=colour44],#[fg=colour245]}#{pane_title} "
tmux select-pane -t "$P_A" -T "🅐 INJECT / data-flow (A)"
tmux select-pane -t "$P_B" -T "🅑 LOGIC / access-control (B)"
tmux select-pane -t "$P_C" -T "🅒 CONVERGE / reproduce (C)"
tmux select-pane -t "$P_D" -T "📊 DASHBOARD"
tmux set  -t "$SESS" mouse on
tmux select-pane -t "$P_C"   # focus the convergence pane

echo "tmux '$SESS' ready (labels bound to panes by id). Attaching... Ctrl-b d to detach."
sleep 1
exec tmux attach -t "$SESS"