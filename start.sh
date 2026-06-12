#!/usr/bin/env bash
# TaintForge launcher with a live tmux dashboard.
# Seeds the model, spawns the Codex sessions (audit.sh SPAWN_ONLY), then opens a tmux view
# whose pane labels MATCH their contents (panes captured by id, not index, so the tiled
# layout can't scramble labels).
#   Panes:
#     🅐 INJECT (A)  | 🅑 LOGIC (B)
#     🅒 CONVERGE(C) | 🅓 EXPLOIT (D)
#     📊 DASHBOARD
#
# Usage:  ./start.sh [-u URL] [--accounts FILE] targets/<app>
#   ./start.sh -u http://127.0.0.1:31655 targets/gitlab
# Detach: Ctrl-b then d.  Re-attach: tmux attach -t taintforge
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
# logs: whitebox A/B; C/D shared.
mklog(){ echo "tail -n +1 -F workspace/_log_$1.txt"; }

# Create the detached session BIG (-x/-y) so later splits never hit tmux's minimum-pane-size
# limit (that was dropping panes on an 80x24 default).
P_A=$(tmux new-session -d -s "$SESS" -n forge -x 250 -y 60 -P -F '#{pane_id}' "$(mklog A)")
P_B=$(tmux split-window -h -t "$P_A" -P -F '#{pane_id}' "$(mklog B)")
P_C=$(tmux split-window -v -t "$P_A" -P -F '#{pane_id}' "$(mklog C)")
P_D=$(tmux split-window -v -t "$P_B" -P -F '#{pane_id}' "$(mklog D)")
P_DASH=$(tmux split-window -v -t "$P_C" -P -F '#{pane_id}' "$DASH")
tmux select-layout -t "$SESS:forge" tiled
tmux set -t "$SESS" pane-border-status top
tmux set -t "$SESS" pane-border-format " #[bold]#{?pane_active,#[fg=colour44],#[fg=colour245]}#{pane_title} "
tmux select-pane -t "$P_A" -T "🅐 INJECT / data-flow (A)"
tmux select-pane -t "$P_B" -T "🅑 LOGIC / access-control (B)"
tmux select-pane -t "$P_C" -T "🅒 CONVERGE / reproduce (C)"
tmux select-pane -t "$P_D" -T "🅓 EXPLOIT / weaponize (D)"
tmux select-pane -t "$P_DASH" -T "📊 DASHBOARD"
FOCUS="$P_C"
tmux set -t "$SESS" mouse on
tmux select-pane -t "$FOCUS"

echo "tmux '$SESS' ready (labels bound to panes by id). Attaching... Ctrl-b d to detach."
sleep 1
exec tmux attach -t "$SESS"