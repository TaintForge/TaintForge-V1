#!/usr/bin/env bash
# TaintForge launcher with a live tmux dashboard.
#
# audit.sh starts one supervised root Codex session. That root owns the A/B/C/D custom
# subagents defined in .codex/agents/*.toml. tmux shows the combined orchestration stream
# beside the queue/report dashboard.
#
# Usage:  ./start.sh [-u URL] [--accounts FILE] targets/<app>
# Detach: Ctrl-b then d. Re-attach: tmux attach -t taintforge
# Stop:   touch workspace/_stop; kill $(cat workspace/_pids); tmux kill-session -t taintforge
set -Eeuo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SESS="taintforge"
S=".agents/skills"
cd "$HERE"

command -v tmux >/dev/null 2>&1 || {
  echo "tmux not installed - plain run"
  exec "$HERE/audit.sh" "$@"
}

mkdir -p workspace
SPAWN_ONLY=1 "$HERE/audit.sh" "$@" </dev/null >workspace/_spawn.log 2>&1 || {
  echo "spawn failed - see workspace/_spawn.log"
  exit 1
}
[ -s workspace/_pids ] || {
  echo "spawn failed - workspace/_pids was not created; see workspace/_spawn.log"
  exit 1
}

tmux kill-session -t "$SESS" 2>/dev/null || true

ORCHESTRATOR_LOG="tail -n +1 -F workspace/_log_orchestrator.txt"
DASHBOARD="python3 $S/convergence/scripts/dashboard.py"

P_ORCH="$(tmux new-session -d -s "$SESS" -n forge -x 220 -y 55 -P -F '#{pane_id}' "$ORCHESTRATOR_LOG")"
P_DASH="$(tmux split-window -h -t "$P_ORCH" -P -F '#{pane_id}' "$DASHBOARD")"
tmux select-layout -t "$SESS:forge" even-horizontal

tmux set -t "$SESS" default-terminal "tmux-256color"
tmux set -t "$SESS" status on
tmux set -t "$SESS" status-position bottom
tmux set -t "$SESS" status-interval 2
tmux set -t "$SESS" status-justify centre
tmux set -t "$SESS" status-style "bg=colour232,fg=colour245"
tmux set -t "$SESS" status-left-length 64
tmux set -t "$SESS" status-right-length 96
tmux set -t "$SESS" status-left "#[bg=colour44,fg=black,bold]  TaintForge  #[bg=colour232,fg=colour44]▌ #[fg=colour247]#{session_name} "
tmux set -t "$SESS" status-right "#[fg=colour241]findings #[fg=colour44,bold]#(find workspace/findings -maxdepth 1 -name '*.json' 2>/dev/null | wc -l | tr -d ' ') #[fg=colour238]│ #[fg=colour245]%Y-%m-%d #[fg=colour44,bold]%H:%M "
tmux set -t "$SESS" pane-border-status top
tmux set -t "$SESS" pane-border-format "#{?pane_active,#[bg=colour44,fg=black,bold],#[bg=colour235,fg=colour245]}  #{pane_title}  #[default]"
tmux set -t "$SESS" pane-border-style "bg=black,fg=colour235"
tmux set -t "$SESS" pane-active-border-style "bg=black,fg=colour44"
tmux set -t "$SESS" mouse on
tmux setw -t "$SESS:forge" remain-on-exit on

tmux select-pane -t "$P_ORCH" -T "ORCHESTRATOR  A/B/C/D subagents"
tmux select-pane -t "$P_DASH" -T "DASHBOARD"
tmux select-pane -t "$P_ORCH"

PANES="$(tmux list-panes -t "$SESS:forge" -F '#{pane_id}' | wc -l | tr -d ' ')"
[ "$PANES" = "2" ] || {
  echo "tmux setup failed - expected 2 panes, got $PANES" >&2
  exit 1
}

echo "tmux '$SESS' ready. Attaching... Ctrl-b d to detach."
sleep 1
exec tmux attach -t "$SESS"
