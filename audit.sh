#!/usr/bin/env bash
# TaintForge white-box parallel role runner.
#
# Five Codex sessions share the locked findings queue:
#   A - injection / data-flow producer
#   B - logic / access-control producer
#   C - cross-validation, reproduction, disclosure, and triage
#   D - exploitation and RCE chaining
#   E - needs_reanalysis diagnosis and retriage
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

# Preserve explicit caller overrides when the project .env is loaded below.
# This lets an assessment pin its canary to a local, authorized endpoint even
# when .env contains defaults intended for a different runtime environment.
CALLER_SSRF_HOST_SET="${SSRF_HOST+x}"
CALLER_SSRF_HOST="${SSRF_HOST-}"
CALLER_SSRF_PORT_SET="${SSRF_PORT+x}"
CALLER_SSRF_PORT="${SSRF_PORT-}"

usage() {
  cat <<'EOF'
usage: ./audit.sh [-u URL] [--accounts FILE] targets/<app>

Five independent Codex sessions run A/B/C/D/E concurrently and share workspace/.
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
MAX_HOURS="${MAX_HOURS:-12}"
SPAWN_ONLY="${SPAWN_ONLY:-0}"
[[ "$MAX_HOURS" =~ ^[1-9][0-9]*$ ]] || {
  echo "error: MAX_HOURS must be a positive integer" >&2
  exit 2
}

mkdir -p workspace/findings workspace/hints workspace/report workspace/cm

[ -f .env ] && set -a && . ./.env && set +a
if [ -n "$CALLER_SSRF_HOST_SET" ]; then
  SSRF_HOST="$CALLER_SSRF_HOST"
fi
if [ -n "$CALLER_SSRF_PORT_SET" ]; then
  SSRF_PORT="$CALLER_SSRF_PORT"
fi

# Model backend. TF_BACKEND=codex (default) or claude. Setting it only supplies
# defaults; an explicit CODEX_CMD / CODEX_CMD_<ROLE> still wins, so per-role
# overrides keep working unchanged.
if [ "${TF_BACKEND:-codex}" = "claude" ]; then
  _tf_claude="claude -p --output-format stream-json --verbose --dangerously-skip-permissions --model ${TF_MODEL:-claude-opus-5}"
  CODEX_CMD="${CODEX_CMD:-$_tf_claude}"
  CODEX_CMD_C="${CODEX_CMD_C:-$_tf_claude}"
  CODEX_CMD_D="${CODEX_CMD_D:-$_tf_claude}"
  CODEX_CMD_E="${CODEX_CMD_E:-$_tf_claude}"
fi

CODEX_CMD="${CODEX_CMD:-codex exec --sandbox workspace-write --config sandbox_workspace_write.network_access=true --config web_search=live --model gpt-6-sol --config model_reasoning_effort=xhigh}"
CODEX_CMD_C="${CODEX_CMD_C:-codex exec --sandbox workspace-write --config sandbox_workspace_write.network_access=true --config web_search=live --model gpt-6-sol --config model_reasoning_effort=xhigh}"
CODEX_CMD_D="${CODEX_CMD_D:-codex exec --sandbox workspace-write --config sandbox_workspace_write.network_access=true --config web_search=live --model gpt-6-sol --config model_reasoning_effort=xhigh}"
CODEX_CMD_E="${CODEX_CMD_E:-codex exec --sandbox workspace-write --config sandbox_workspace_write.network_access=true --config web_search=live --model gpt-6-sol --config model_reasoning_effort=xhigh}"

if [ "${TF_REUSE_SEED:-0}" = "1" ]; then
  echo "== seed: validating and reusing existing Code Model, coverage, and hypotheses =="
  TARGET="$TARGET" python3 - <<'PY'
import json
import os
from pathlib import Path

target = os.environ["TARGET"]
required = [
    Path("workspace/CODE_MODEL.json"),
    Path("workspace/coverage.json"),
    Path("workspace/HYPOTHESES.json"),
]
missing = [str(path) for path in required if not path.is_file()]
if missing:
    raise SystemExit(f"TF_REUSE_SEED=1 but seed artifacts are missing: {', '.join(missing)}")

with required[0].open() as handle:
    model = json.load(handle)
model_target = model.get("target", {}).get("root")
if model_target != target:
    raise SystemExit(
        f"TF_REUSE_SEED=1 target mismatch: CODE_MODEL has {model_target!r}, requested {target!r}"
    )

with required[2].open() as handle:
    hypotheses = json.load(handle)
hypothesis_target = hypotheses.get("target")
if hypothesis_target != target:
    raise SystemExit(
        f"TF_REUSE_SEED=1 target mismatch: HYPOTHESES has {hypothesis_target!r}, requested {target!r}"
    )
print(f"reusing seed for {target}")
PY
else
  echo "== seed (no LLM): structural model + module split + domain hypotheses =="
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
fi

PCAN=""
CANARY_PORT="${SSRF_PORT:-${CANARY_PORT:-9111}}"
CANARY_HOST="${SSRF_HOST:-${CANARY_HOST:-127.0.0.1}}"
CANARY_NOTE="An out-of-band canary is available at http://$CANARY_HOST:$CANARY_PORT. Use probe.py,
browser_probe.py, and canary.py as directed by the role skills."

# Idempotent: a canary another session already left listening is reused rather than fought over.
start_canary() {
  if (exec 3<>/dev/tcp/"$CANARY_HOST"/"$CANARY_PORT") 2>/dev/null; then
    echo "== canary already listening on $CANARY_HOST:$CANARY_PORT =="
    return
  fi
  python3 "$S/convergence/scripts/canary.py" serve --port "$CANARY_PORT" \
    --log workspace/_canary.log > workspace/_log_canary.txt 2>&1 &
  PCAN=$!
}

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

  start_canary
  DYNAMIC_CONTEXT="The only authorized live target is $URL.
$ACCOUNT_CONTEXT
$CANARY_NOTE Never send traffic to any other host."
  echo "== live target: $URL | accounts: $ACCOUNT_CONTEXT | canary: $CANARY_HOST:$CANARY_PORT =="
elif [ "${TF_CANARY:-0}" = "1" ]; then
  # Desktop/CLI targets have no URL but still need an out-of-band oracle (an SSRF or callback
  # reached from a locally built copy of the target). Without this a campaign script has to
  # hand-roll the listener, which is how it drifts from the one audit.sh tears down.
  start_canary
  DYNAMIC_CONTEXT="No live service was provided; dynamic work happens only against a locally
built copy of the target in the authorized lab. $CANARY_NOTE Never send traffic to any other
host."
  echo "== no --url: local-lab mode | canary: $CANARY_HOST:$CANARY_PORT =="
else
  echo "== no --url: static-only mode =="
fi

if [ -n "${TAINTFORGE_DYNAMIC_CONTEXT:-}" ]; then
  DYNAMIC_CONTEXT="$TAINTFORGE_DYNAMIC_CONTEXT"
  echo "== custom dynamic target context enabled =="
fi

COMMON_CONTEXT="You are one independent persistent role in an authorized TaintForge white-box
assessment. Do not delegate to subagents. Read AGENTS.md completely, then
.agents/skills/_shared/METHODOLOGY.md completely, then the skill named by your role, before
acting. The methodology binds every role: decide each defect's shape (flow vs missing control)
before routing it, treat identity state, stored values, post-free and bailout-orphaned state,
cross-scope state and ordering as attacker sources, and run the mandatory passes your role owns
rather than stopping at the first source-to-sink hit.

Repository root: $ROOT
Read-only assessment target: $TARGET
Shared queue and persistent notebook: $ROOT/workspace
Stop flag: $ROOT/workspace/_stop
$DYNAMIC_CONTEXT
${TAINTFORGE_EXTRA_CONTEXT:-}

The assessment's primary objective is a demonstrable pre-authentication RCE or, secondarily, an
authenticated RCE. Prioritize chains that end in code execution: unsafe deserialization, command
or code injection, template execution, dynamic loading, file-write or upload to execution,
path-traversal to execution, and authentication or authorization bypass into an RCE-capable
administrative primitive. Do not spend the main budget on standalone low-impact issues unless
they are a necessary link in a credible RCE chain.

Analyze only code under the supplied target and never modify targets/. Use workspace as durable
memory. Author or update findings only through .agents/skills/_shared/write_finding.py. Coordinate
through workspace/findings and leads.py. Never contact any host except the authorized live target
and local canary. Continue until workspace/_stop appears; an empty queue is never completion."

MISSION_A="$COMMON_CONTEXT

You are A, the injection and data-flow producer. Read the vuln-track-a skill completely. Work
sink-first from code-execution-capable sinks and trace backward across files to unauthenticated
inputs first, then authenticated inputs. Focus on command/code injection, dangerous
deserialization, SSTI, dynamic import or plugin loading, attacker-controlled file writes and
uploads, path traversal into executable locations, and SSRF only where it can credibly chain to
RCE. Record partial capabilities in leads.py and concrete findings as track A candidates. E alone
owns findings already marked needs_reanalysis; do not duplicate E's feedback work."

MISSION_B="$COMMON_CONTEXT

You are B, the authentication, authorization, and business-logic producer. Read the vuln-track-b
skill completely. Trace exposed entries through every authn, role, tenant, ownership, and state
gate. Prioritize pre-auth authentication bypass and low-privilege paths into administrative
features that can execute code, install or load plugins, alter model/provider endpoints, write
files, run tools, invoke callbacks, or otherwise complete an RCE chain. Record partial
capabilities in leads.py and concrete findings as track B candidates. E alone owns findings
already marked needs_reanalysis; do not duplicate E's feedback work."

MISSION_C="$COMMON_CONTEXT

You are C, the convergence and triage consumer. Read the convergence skill completely. Continuously
consume candidate, cross_validated, and reproduced-awaiting-official-review findings while A and B produce them. Independently validate
the exact source-to-sink or entry-to-resource path, reproduce it against only the authorized live
target, and deduplicate it. Reproduction proves behavior only. Before confirmation, compare the
exact behavior, version, supported/default configuration, documented security boundary, and sink
ownership with primary official/vendor documentation, API contracts, security guidance, default
templates/samples, versioned source/tests, advisories, release notes, patches, and vendor-owned
issues. Record official_review with at least one public primary official/vendor documentation,
advisory, release, patch, issue, or discussion URL; local source/test paths and GitHub blob/tree/raw
source links alone do not satisfy the gate. Only product_vulnerability or known_vulnerability may
become confirmed; documented hazards, expected behavior, application misconfiguration, and unsupported
scenarios become not_product_vulnerability; inconclusive reviews remain reproduced. Determine
disclosure status only after that gate passes. Before \`novel\`, derive exact source anchors, run
git-history/path searches, compare the tested tag with upstream main and supported release branches,
search open/closed vendor issues and open/merged PRs, follow backports, and check advisories/CVEs and
release/servicing notes. A matching public source fix is known even without a CVE or security label.
Record every category in disclosure.public_history; missing evidence means inconclusive and must not
receive a potential-0-day label. Emit a PoC/report and regenerate report/report.md only after these
gates.
Rank pre-auth RCE first and authenticated RCE second. Treat
lower-impact findings mainly as possible links toward code execution. When proof is inconclusive,
set needs_reanalysis with a precise, actionable reason; E owns that state and will return only
newly supported items for retriage."

MISSION_D="$COMMON_CONTEXT

You are D, the exploitation and RCE-chain agent. Read the convergence skill completely. Work only
from confirmed findings whose official_review verdict is product_vulnerability or
known_vulnerability, plus linked primitives that can credibly end in code
execution. Push pre-auth RCE first, then authenticated RCE, verifying every escalation step on the
authorized lab target. Defeat actual parser, sanitizer, quoting, protocol, and state constraints;
do not overstate bounded impact. Write the exploit object only through write_finding.py and emit a
standalone exploit.py with exact constraints and evidence."

MISSION_E="$COMMON_CONTEXT

You are E, the dedicated needs_reanalysis investigator and retriage agent. Read the convergence
skill completely, plus vuln-track-a or vuln-track-b when the finding's track requires it. Poll only
findings whose status is needs_reanalysis. For each one, read C's exact observation and retry
history, identify the missing premise or failed reproduction step, revisit the relevant code path,
and perform the smallest authorized live test needed to resolve it. Look specifically for omitted
alternate entry points, auth-state assumptions, parser differences, environment prerequisites,
and chain links that could convert the issue into pre-auth or authenticated RCE. With genuinely
new evidence, return it to candidate or cross_validated for C, or mark it reproduced when you have
decisive live proof. Mark it false_positive when disproved or when the retry cap is exhausted
without new evidence. Never bounce a finding unchanged. Record every update only through
write_finding.py, then continue polling."

echo "== launching 5 independent Codex sessions (A/B/C/D/E) =="
DEADLINE=$(( $(date +%s) + MAX_HOURS * 3600 ))
STOP="workspace/_stop"
rm -f "$STOP"

supervise() {
  local tag="$1"
  local logfile="$2"
  local mission="$3"
  local rolecmd
  eval "rolecmd=\${CODEX_CMD_${tag}:-\$CODEX_CMD}"

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
      echo "===== [$(date +%FT%T%z)] role $tag session #$run ($rolecmd) =====" >> "$logfile"
      # Role commands intentionally remain shell-style overrides for compatibility.
      # shellcheck disable=SC2086
      $rolecmd "$mission" >> "$logfile" 2>&1 </dev/null &
      child=$!
      wait "$child" || true
      child=""
      python3 "$S/_shared/budget_guard.py" --check >> "$logfile" 2>&1 || true
      [ -f "$STOP" ] || sleep 5
    done
    echo "===== [$(date +%FT%T%z)] role $tag supervisor stopped =====" >> "$logfile"
  ) </dev/null >/dev/null 2>&1 &
  SUPERVISOR_PID="$!"
}

SUPERVISOR_PID=""
supervise A workspace/_log_A.txt "$MISSION_A"; P_A="$SUPERVISOR_PID"
supervise B workspace/_log_B.txt "$MISSION_B"; P_B="$SUPERVISOR_PID"
supervise C workspace/_log_C.txt "$MISSION_C"; P_C="$SUPERVISOR_PID"
supervise D workspace/_log_D.txt "$MISSION_D"; P_D="$SUPERVISOR_PID"
supervise E workspace/_log_E.txt "$MISSION_E"; P_E="$SUPERVISOR_PID"
ROLE_PIDS=("$P_A" "$P_B" "$P_C" "$P_D" "$P_E")
ALL_PIDS=("${ROLE_PIDS[@]}")
[ -z "$PCAN" ] || ALL_PIDS+=("$PCAN")
printf '%s\n' "${ALL_PIDS[*]}" > workspace/_pids
echo "  A=$P_A B=$P_B C=$P_C D=$P_D E=$P_E (${MAX_HOURS}h supervisors)"

stop_all() {
  touch "$STOP"
  kill "${ALL_PIDS[@]}" 2>/dev/null || true
  wait "${ALL_PIDS[@]}" 2>/dev/null || true
}

if [ "$SPAWN_ONLY" = "1" ]; then
  echo "  spawned; stop with: touch workspace/_stop; kill \$(cat workspace/_pids)"
  exit 0
fi

echo "  python3 $S/convergence/scripts/queue.py --counts"
trap 'echo; echo "stopping..."; stop_all' INT TERM
wait "${ROLE_PIDS[@]}"
if [ -n "$PCAN" ]; then
  kill "$PCAN" 2>/dev/null || true
  wait "$PCAN" 2>/dev/null || true
fi
python3 "$S/convergence/scripts/emit_poc.py" || true
python3 "$S/convergence/scripts/triage.py" || true
echo "== run ended (deadline/stop): workspace/report/report.md =="
