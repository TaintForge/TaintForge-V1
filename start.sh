#!/usr/bin/env bash
# TaintForge launcher with a live tmux dashboard.
#
# audit.sh starts A/B/C/D/E. tmux gives every role its own pane.
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
  SSRF_HOST SSRF_PORT CANARY_HOST CANARY_PORT TAINTFORGE_EXTRA_CONTEXT \
  TAINTFORGE_DYNAMIC_CONTEXT TF_PY \
  CODEX_CMD CODEX_CMD_A CODEX_CMD_B CODEX_CMD_C CODEX_CMD_D CODEX_CMD_E; do
  if [[ -v "$name" ]]; then
    RUNNER_ENV+=("$name=${!name}")
  fi
done
# tmux hands the pane command to the user's default-shell, which is not necessarily
# bash. Multi-line role context values do not survive that round trip as one quoted
# argv, so write a tiny launcher script instead and run that.
RUNNER_SH="workspace/_runner.sh"
{
  echo '#!/usr/bin/env bash'
  echo 'set -Eeuo pipefail'
  printf 'cd %q\n' "$HERE"
  for kv in "${RUNNER_ENV[@]}"; do
    printf 'export %s=%q\n' "${kv%%=*}" "${kv#*=}"
  done
  printf 'exec %q' "$HERE/audit.sh"
  for a in "$@"; do printf ' %q' "$a"; done
  printf '\n'
} > "$RUNNER_SH"
chmod +x "$RUNNER_SH"
printf -v RUNNER_CMD '%q %q' bash "$HERE/$RUNNER_SH"
P_RUNNER="$(tmux new-session -d -s "$SESS" -n runtime -x 250 -y 60 -c "$HERE" -P -F '#{pane_id}' "$RUNNER_CMD")"

# The claude backend writes stream-json JSONL; render it human-readable in the pane.
if [ "${TF_BACKEND:-codex}" = "claude" ]; then
  mklog() { printf 'tail -n +1 -F workspace/_log_%s.txt | python3 -u .agents/stream_fmt.py' "$1"; }
else
  mklog() { printf 'tail -n +1 -F workspace/_log_%s.txt' "$1"; }
fi
DASHBOARD="python3 $S/convergence/scripts/dashboard.py"

P_A="$(tmux new-window -d -t "$SESS:" -n forge -c "$HERE" -P -F '#{pane_id}' "$(mklog A)")"
P_B="$(tmux split-window -h -t "$P_A" -P -F '#{pane_id}' "$(mklog B)")"
P_C="$(tmux split-window -v -t "$P_A" -P -F '#{pane_id}' "$(mklog C)")"
P_D="$(tmux split-window -v -t "$P_B" -P -F '#{pane_id}' "$(mklog D)")"
P_E="$(tmux split-window -v -t "$P_C" -P -F '#{pane_id}' "$(mklog E)")"
P_DASH="$(tmux split-window -v -t "$P_D" -P -F '#{pane_id}' "$DASHBOARD")"
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

# Pane titles name the model each role actually runs on, so a mixed-model
# campaign (e.g. a stronger model on D only) is visible at a glance.
rolemodel() {
  local tag="$1" cmd
  eval "cmd=\${CODEX_CMD_${tag}:-\${CODEX_CMD:-}}"
  if [ -z "$cmd" ]; then
    if [ "${TF_BACKEND:-codex}" = "claude" ]; then cmd="${TF_MODEL:-claude-opus-5}"; else cmd="gpt-6-sol xhigh"; fi
  fi
  sed -n 's/.*--model[ =]\([^ ]*\).*/\1/p' <<<"$cmd" | head -1 | grep . || echo "$cmd"
}
tmux select-pane -t "$P_RUNNER" -T "RUNTIME / supervisors"
tmux select-pane -t "$P_A" -T "A  INJECT / data-flow  [$(rolemodel A)]"
tmux select-pane -t "$P_B" -T "B  AUTH / logic  [$(rolemodel B)]"
tmux select-pane -t "$P_C" -T "C  TRIAGE  [$(rolemodel C)]"
tmux select-pane -t "$P_D" -T "D  EXPLOIT  [$(rolemodel D)]"
tmux select-pane -t "$P_E" -T "E  REANALYSIS  [$(rolemodel E)]"
tmux select-pane -t "$P_DASH" -T "DASHBOARD"
tmux select-window -t "$SESS:forge"
tmux select-pane -t "$P_C"

PANES="$(tmux list-panes -t "$SESS:forge" -F '#{pane_id}' | wc -l | tr -d ' ')"
EXPECTED_PANES=6
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

echo "tmux '$SESS' ready with A/B/C/D/E + dashboard."
if [ "${TAINTFORGE_NO_ATTACH:-0}" = "1" ]; then
  exit 0
fi
echo "Attaching... Ctrl-b d to detach."
sleep 1
exec tmux attach -t "$SESS"
