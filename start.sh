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
set -Eeuo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SESS="taintforge"
S=".agents/skills"

command -v tmux >/dev/null 2>&1 || { echo "tmux not installed - plain run"; exec "$HERE/audit.sh" "$@"; }

mkdir -p workspace
# spawn sessions + seed (returns immediately; fds detached so background supervisors
# can't hold this shell open)
SPAWN_ONLY=1 "$HERE/audit.sh" "$@" </dev/null >workspace/_spawn.log 2>&1 || { echo "spawn failed - see workspace/_spawn.log"; exit 1; }
[ -s workspace/_pids ] || { echo "spawn failed - workspace/_pids was not created; see workspace/_spawn.log"; exit 1; }

tmux kill-session -t "$SESS" 2>/dev/null || true

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
tmux set -t "$SESS" window-status-separator ""
tmux set -t "$SESS" window-status-style "bg=colour232,fg=colour241"
tmux set -t "$SESS" window-status-format "#[bg=colour232,fg=colour241]  #I:#W  "
tmux set -t "$SESS" window-status-current-format "#[bg=colour236,fg=colour44,bold]  #I:#W  "
tmux set -t "$SESS" message-style "bg=colour236,fg=colour255"
tmux set -t "$SESS" message-command-style "bg=colour236,fg=colour255"
tmux set -t "$SESS" mode-style "bg=colour44,fg=black,bold"
tmux set -t "$SESS" clock-mode-colour colour44
tmux set -t "$SESS" display-panes-active-colour colour44
tmux set -t "$SESS" display-panes-colour colour238
tmux set -t "$SESS" pane-border-style "bg=black,fg=colour235"
tmux set -t "$SESS" pane-active-border-style "bg=black,fg=colour44"
tmux set -t "$SESS" pane-border-lines single
tmux set -t "$SESS" pane-border-status top
tmux setw -t "$SESS:forge" remain-on-exit on
tmux setw -t "$SESS:forge" window-style "bg=black,fg=colour250"
tmux setw -t "$SESS:forge" window-active-style "bg=black,fg=colour252"
tmux set -t "$SESS" pane-border-format "#{?pane_active,#[bg=colour44,fg=black,bold],#[bg=colour235,fg=colour245]}  #{pane_title}  #[default]"
tmux select-pane -t "$P_A" -T "A  INJECT / data-flow"
tmux select-pane -t "$P_B" -T "B  LOGIC / access-control"
tmux select-pane -t "$P_C" -T "C  CONVERGE / reproduce"
tmux select-pane -t "$P_D" -T "D  EXPLOIT / weaponize"
tmux select-pane -t "$P_DASH" -T "DASHBOARD"
FOCUS="$P_C"
tmux set -t "$SESS" mouse on
tmux select-pane -t "$FOCUS"

PANES=$(tmux list-panes -t "$SESS:forge" -F '#{pane_id}' | wc -l | tr -d ' ')
[ "$PANES" = "5" ] || {
  echo "tmux setup failed - expected 5 panes, got $PANES" >&2
  tmux list-panes -t "$SESS:forge" -F '#{pane_index} #{pane_id} #{pane_title} #{pane_current_command}' >&2 || true
  exit 1
}

echo "tmux '$SESS' ready (labels bound to panes by id). Attaching... Ctrl-b d to detach."
sleep 1
exec tmux attach -t "$SESS"
