#!/usr/bin/env bash
# TaintForge white-box orchestrator.
#
# One root Codex session owns four project-scoped custom subagents:
#   producer_a     - injection / data-flow
#   producer_b     - logic / access-control
#   convergence_c  - cross-validation, reproduction, disclosure, and triage
#   exploitation_d - weaponization of proven critical findings
#
# The role definitions live in .codex/agents/*.toml. The shell only seeds deterministic
# artifacts, prepares optional live-target context, and supervises the root orchestrator.
#
# Usage:
#   ./audit.sh targets/<app>
#   ./audit.sh -u http://localhost:8080 targets/<app>
#   ./audit.sh --url http://host --accounts creds.json targets/<app>
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

URL=""
ACCOUNTS="accounts.json"
TARGET=""

usage() {
  cat <<'EOF'
usage: ./audit.sh [-u URL] [--accounts FILE] targets/<app>

One supervised root Codex orchestrator manages the producer_a, producer_b,
convergence_c, and exploitation_d project custom subagents.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    -u|--url) URL="${2:?missing URL}"; shift 2 ;;
    --accounts) ACCOUNTS="${2:?missing accounts path}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    -*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    *) TARGET="$1"; shift ;;
  esac
done

[ -n "$TARGET" ] || {
  usage >&2
  exit 2
}
TARGET_REAL="$(realpath -e -- "$TARGET" 2>/dev/null)" || {
  echo "error: target does not exist: $TARGET" >&2
  exit 2
}
case "$TARGET_REAL" in
  "$ROOT"/targets/*) ;;
  *) echo "error: target must be under targets/: $TARGET" >&2; exit 2 ;;
esac
TARGET="$(realpath --relative-to="$ROOT" "$TARGET_REAL")"

S=".agents/skills"
CODEX_CMD="${CODEX_CMD:-codex exec --sandbox workspace-write}"
MAX_HOURS="${MAX_HOURS:-12}"
SPAWN_ONLY="${SPAWN_ONLY:-0}"
[[ "$MAX_HOURS" =~ ^[1-9][0-9]*$ ]] || {
  echo "error: MAX_HOURS must be a positive integer" >&2
  exit 2
}

required_agent_files=(
  .codex/config.toml
  .codex/agents/producer_a.toml
  .codex/agents/producer_b.toml
  .codex/agents/convergence_c.toml
  .codex/agents/exploitation_d.toml
)
for agent_file in "${required_agent_files[@]}"; do
  [ -f "$agent_file" ] || { echo "error: missing custom-agent config: $agent_file" >&2; exit 2; }
done

mkdir -p workspace/findings workspace/hints workspace/report workspace/cm

echo "== seed (no LLM): structural model + module split + domain hypotheses =="
[ -f .env ] && set -a && . ./.env && set +a
"$S/source-model/scripts/build_code_model.sh" "$TARGET" || true
python3 "$S/source-model/scripts/coverage.py" --init "$TARGET" || true

CAT="$S/hypothesize/scripts/catalog.json"
if [ -n "${CWE_XML:-}" ] && [ -f "$CWE_XML" ]; then
  if ! grep -q "\"source_file\": \"$(basename "$CWE_XML")\"" "$CAT" 2>/dev/null; then
    echo "== merging CWE hypotheses from $CWE_XML (one-time) =="
    python3 "$S/hypothesize/scripts/cwe_to_hypotheses.py" "$CWE_XML" --catalog "$CAT" || true
  fi
fi
python3 "$S/hypothesize/scripts/gen_hypotheses.py" --target "$TARGET" || true

PCAN=""
DYNAMIC_CONTEXT="No live instance was provided. Perform static analysis only. When a finding
needs dynamic proof, record that limitation honestly instead of guessing."
if [ -n "$URL" ]; then
  if [ -f "$ACCOUNTS" ]; then
    cp "$ACCOUNTS" workspace/_accounts.json
    ACCOUNT_COUNT="$(python3 -c "import json; print(len(json.load(open('workspace/_accounts.json'))))" 2>/dev/null || echo '?')"
    ACCOUNT_CONTEXT="Test accounts ($ACCOUNT_COUNT) are in workspace/_accounts.json. Derive the
login route, CSRF flow, and session format from the target code. Use separate sessions for
different identities when reproducing access-control findings."
  else
    ACCOUNT_CONTEXT="No accounts file was found at $ACCOUNTS. Test only unauthenticated surfaces
and record where authenticated reproduction remains unavailable."
  fi

  CANARY_PORT="${SSRF_PORT:-${CANARY_PORT:-9111}}"
  CANARY_HOST="${SSRF_HOST:-${CANARY_HOST:-127.0.0.1}}"
  python3 "$S/convergence/scripts/canary.py" serve --port "$CANARY_PORT" \
    --log workspace/_canary.log > workspace/_log_canary.txt 2>&1 &
  PCAN=$!
  DYNAMIC_CONTEXT="The only authorized live target is $URL.
$ACCOUNT_CONTEXT
An out-of-band canary is available at http://$CANARY_HOST:$CANARY_PORT. Use probe.py,
browser_probe.py, and canary.py as directed by the role skills. Never send traffic to any
other host."
  echo "== live target: $URL | accounts: $ACCOUNT_CONTEXT | canary: $CANARY_HOST:$CANARY_PORT =="
else
  echo "== no --url: static-only mode =="
fi

ORCHESTRATOR_PROMPT="You are the root orchestrator for an authorized TaintForge white-box
assessment. Do not perform producer, convergence, or exploitation analysis yourself.

Immediately spawn exactly these four project custom agents in parallel, selecting each agent by
its exact configured name and using the matching task name:
1. producer_a
2. producer_b
3. convergence_c
4. exploitation_d

Give every child this runtime context:
- Repository root: $ROOT
- Read-only assessment target: $TARGET
- Shared persistent queue and notebook: $ROOT/workspace
- Stop flag: $ROOT/workspace/_stop
- $DYNAMIC_CONTEXT

The custom agent's developer instructions define its role. Do not replace a named custom agent
with a generic worker. Do not let children delegate further work. All four must run concurrently
and coordinate through workspace/findings plus the leads notebook.

Continuously supervise the four child threads. Wait for updates and relay useful cross-role
evidence when needed. If a child finishes before workspace/_stop exists, send a follow-up task to
that same child to continue from workspace state; do not create duplicate workers. producer_a and
producer_b should revisit needs_reanalysis feedback and continue exhaustive coverage.
convergence_c and exploitation_d must keep polling for newly eligible findings. Never interpret a
temporarily empty queue as completion. Remain active until the shell terminates this session or
workspace/_stop appears."

echo "== launching one Codex orchestrator with four custom subagents =="
DEADLINE=$(( $(date +%s) + MAX_HOURS * 3600 ))
STOP="workspace/_stop"
LOG="workspace/_log_orchestrator.txt"
rm -f "$STOP"

supervise_orchestrator() {
  (
    child=""
    stop_child() {
      if [ -n "$child" ]; then
        kill "$child" 2>/dev/null || true
        wait "$child" 2>/dev/null || true
      fi
      exit 0
    }
    trap stop_child INT TERM

    run=0
    while [ ! -f "$STOP" ] && [ "$(date +%s)" -lt "$DEADLINE" ]; do
      run=$((run + 1))
      echo "===== [$(date +%FT%T%z)] orchestrator session #$run =====" >> "$LOG"
      # CODEX_CMD intentionally remains a shell-style override for compatibility.
      # shellcheck disable=SC2086
      $CODEX_CMD "$ORCHESTRATOR_PROMPT" >> "$LOG" 2>&1 </dev/null &
      child=$!
      wait "$child" || true
      child=""
      python3 "$S/_shared/budget_guard.py" --check >> "$LOG" 2>&1 || true
      [ -f "$STOP" ] || sleep 5
    done
    echo "===== [$(date +%FT%T%z)] orchestrator supervisor stopped =====" >> "$LOG"
  ) </dev/null >/dev/null 2>&1 &
  echo "$!"
}

PORCH="$(supervise_orchestrator)"
printf '%s%s\n' "$PORCH" "${PCAN:+ $PCAN}" > workspace/_pids
echo "  orchestrator=$PORCH (custom agents: producer_a, producer_b, convergence_c, exploitation_d)"

stop_all() {
  touch "$STOP"
  kill "$PORCH" ${PCAN:+"$PCAN"} 2>/dev/null || true
  wait "$PORCH" ${PCAN:+"$PCAN"} 2>/dev/null || true
}

if [ "$SPAWN_ONLY" = "1" ]; then
  echo "  spawned; stop with: touch workspace/_stop; kill \$(cat workspace/_pids)"
  exit 0
fi

echo "  python3 $S/convergence/scripts/queue.py --counts"
trap 'echo; echo "stopping..."; stop_all' INT TERM
wait "$PORCH"
if [ -n "$PCAN" ]; then
  kill "$PCAN" 2>/dev/null || true
  wait "$PCAN" 2>/dev/null || true
fi
python3 "$S/convergence/scripts/emit_poc.py" || true
python3 "$S/convergence/scripts/triage.py" || true
echo "== run ended (deadline/stop): workspace/report/report.md =="
