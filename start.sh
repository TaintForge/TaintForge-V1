#!/usr/bin/env bash
# TaintForge launcher with a live tmux dashboard.
#
# audit.sh starts A/B/C/D/E and optionally DBMS fuzzer F. tmux gives every role its own pane.
#
# Usage:  ./start.sh [-u URL] [--accounts FILE] targets/<app>
# Detach: Ctrl-b then d. Re-attach: tmux attach -t taintforge
# Stop:   touch workspace/_stop; kill $(cat workspace/_pids); tmux kill-session -t taintforge
set -Eeuo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SESS="${TAINTFORGE_SESSION:-taintforge}"
S=".agents/skills"
cd "$HERE"

command -v tmux >/dev/null 2>&1 || {
  echo "tmux not installed - plain run"
  exec "$HERE/audit.sh" "$@"
}

mkdir -p workspace
if tmux has-session -t "$SESS" 2>/dev/null; then
  touch workspace/_stop
  if [ -s workspace/_pids ]; then
    while read -r pid; do
      [[ "$pid" =~ ^[0-9]+$ ]] && kill "$pid" 2>/dev/null || true
    done < <(tr ' ' '\n' < workspace/_pids)
  fi
  tmux kill-session -t "$SESS" 2>/dev/null || true
fi
rm -f workspace/_stop workspace/_pids

# A long-lived tmux server keeps the environment from the first client that
# created it. Pass campaign-scoped values explicitly so two concurrent target
# sessions cannot inherit each other's URL context, model overrides, or canary.
RUNNER_ENV=()
for name in MAX_HOURS SPAWN_ONLY TF_REUSE_SEED TF_MAX_REANALYSIS \
  TF_BACKEND TF_MODEL \
  TF_DBMS_FUZZ TF_DBMS_ENGINES DBFUZZ_DSN_FILE \
  SSRF_HOST SSRF_PORT CANARY_HOST CANARY_PORT TAINTFORGE_EXTRA_CONTEXT \
  CODEX_CMD CODEX_CMD_A CODEX_CMD_B CODEX_CMD_C CODEX_CMD_D CODEX_CMD_E CODEX_CMD_F; do
  if [[ -v "$name" ]]; then
    RUNNER_ENV+=("$name=${!name}")
  fi
done
printf -v RUNNER_CMD '%q ' env "${RUNNER_ENV[@]}" "$HERE/audit.sh" "$@"
P_RUNNER="$(tmux new-session -d -s "$SESS" -n runtime -x 250 -y 60 -c "$HERE" -P -F '#{pane_id}' "$RUNNER_CMD")"

mklog() { printf 'tail -n +1 -F workspace/_log_%s.txt' "$1"; }
DASHBOARD="python3 $S/convergence/scripts/dashboard.py"

P_A="$(tmux new-window -d -t "$SESS:" -n forge -c "$HERE" -P -F '#{pane_id}' "$(mklog A)")"
P_B="$(tmux split-window -h -t "$P_A" -P -F '#{pane_id}' "$(mklog B)")"
P_C="$(tmux split-window -v -t "$P_A" -P -F '#{pane_id}' "$(mklog C)")"
P_D="$(tmux split-window -v -t "$P_B" -P -F '#{pane_id}' "$(mklog D)")"
P_E="$(tmux split-window -v -t "$P_C" -P -F '#{pane_id}' "$(mklog E)")"
P_DASH="$(tmux split-window -v -t "$P_D" -P -F '#{pane_id}' "$DASHBOARD")"
P_F=""
if [ "${TF_DBMS_FUZZ:-0}" = "1" ]; then
  P_F="$(tmux split-window -v -t "$P_E" -P -F '#{pane_id}' "$(mklog F)")"
fi
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
tmux set -t "$SESS" pane-border-status top
tmux set -t "$SESS" pane-border-format "#{?pane_active,#[bg=colour44,fg=black,bold],#[bg=colour235,fg=colour245]}  #{pane_title}  #[default]"
tmux set -t "$SESS" pane-border-style "bg=black,fg=colour235"
tmux set -t "$SESS" pane-active-border-style "bg=black,fg=colour44"
tmux set -t "$SESS" mouse on
tmux setw -t "$SESS:runtime" remain-on-exit on
tmux setw -t "$SESS:forge" remain-on-exit on

tmux select-pane -t "$P_RUNNER" -T "RUNTIME / supervisors"
tmux select-pane -t "$P_A" -T "A  INJECT / data-flow"
tmux select-pane -t "$P_B" -T "B  AUTH / logic"
tmux select-pane -t "$P_C" -T "C  TRIAGE / GPT-6 Sol xhigh"
tmux select-pane -t "$P_D" -T "D  EXPLOIT / Daybreak Blue max"
tmux select-pane -t "$P_E" -T "E  REANALYSIS / GPT-6 Sol xhigh"
[ -z "$P_F" ] || tmux select-pane -t "$P_F" -T "F  DBMS FUZZ / Daybreak Blue max"
tmux select-pane -t "$P_DASH" -T "DASHBOARD"
tmux select-window -t "$SESS:forge"
tmux select-pane -t "$P_C"

PANES="$(tmux list-panes -t "$SESS:forge" -F '#{pane_id}' | wc -l | tr -d ' ')"
EXPECTED_PANES=6
[ -z "$P_F" ] || EXPECTED_PANES=7
[ "$PANES" = "$EXPECTED_PANES" ] || {
  echo "tmux setup failed - expected $EXPECTED_PANES panes, got $PANES" >&2
  exit 1
}

for _ in $(seq 1 30); do
  [ -s workspace/_pids ] && break
  sleep 1
done
[ -s workspace/_pids ] || {
  echo "audit runner failed to create workspace/_pids; inspect tmux '$SESS:runtime'" >&2
  exit 1
}

echo "tmux '$SESS' ready with A/B/C/D/E${P_F:+/F} + dashboard."
if [ "${TAINTFORGE_NO_ATTACH:-0}" = "1" ]; then
  exit 0
fi
echo "Attaching... Ctrl-b d to detach."
sleep 1
exec tmux attach -t "$SESS"
