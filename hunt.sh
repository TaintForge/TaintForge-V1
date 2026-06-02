#!/usr/bin/env bash
# Streaming producer-consumer: three parallel autonomous Codex sessions sharing the
# findings queue (workspace/findings/).
#   A (producer) - injection / data-flow
#   B (producer) - logic / access-control (IDOR, authz, ...)
#   C (consumer) - cross-validate + reproduce + triage, continuously
# Each is ONE long self-looping session (no shell re-invoking Codex per module).
# write_finding.py is file-locked so the three never corrupt the same finding.
#
# Usage:
#   ./audit.sh targets/<app>                         # static only (no live server)
#   ./audit.sh -u http://localhost:8080 targets/<app>  # + dynamic reproduction/analysis
#   ./audit.sh --url http://host --accounts creds.json targets/<app>
#
# When --url is given, accounts.json (array of {username,password}) is passed to the
# sessions so they can authenticate (Codex figures out the login flow itself) and
# reproduce auth/IDOR issues by replaying as different users. Default accounts file:
# ./accounts.json in the repo root.
set -uo pipefail

URL=""; ACCOUNTS="accounts.json"; TARGET=""
while [ $# -gt 0 ]; do
  case "$1" in
    -u|--url)      URL="$2"; shift 2;;
    --accounts)    ACCOUNTS="$2"; shift 2;;
    -h|--help)     grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
    -*)            echo "unknown option: $1" >&2; exit 2;;
    *)             TARGET="$1"; shift;;
  esac
done
[ -n "$TARGET" ] || { echo "usage: ./audit.sh [-u URL] [--accounts FILE] targets/<app>"; exit 2; }

S=".agents/skills"
CODEX_CMD="${CODEX_CMD:-codex exec --sandbox workspace-write}"
mkdir -p workspace/findings workspace/hints workspace/report

echo "== seed (no LLM): structural model + module split =="
"$S/source-model/scripts/build_code_model.sh" "$TARGET" || true
python3 "$S/source-model/scripts/coverage.py" --init "$TARGET" || true

# ---- live-target / accounts context (only if --url given) ----
DYN=""; ACCT_NOTE=""
if [ -n "$URL" ]; then
  if [ -f "$ACCOUNTS" ]; then
    # stash accounts where the sessions can read them; tell them the path, not the secrets inline
    cp "$ACCOUNTS" workspace/_accounts.json
    N=$(python3 -c "import json;print(len(json.load(open('workspace/_accounts.json'))))" 2>/dev/null || echo "?")
    ACCT_NOTE="Test accounts ($N) are in workspace/_accounts.json as a JSON array of
{username, password}. Log in via the running app to get a session/cookie/token - YOU work
out the auth flow from the code (login route, CSRF token, cookie name). For access-control
tests, authenticate as two different accounts and replay one's request with the other's
session to prove (or disprove) IDOR/authz bugs."
  else
    ACCT_NOTE="No accounts file found at $ACCOUNTS - reproduce only what is reachable
unauthenticated, and note where authenticated testing is needed."
  fi
  DYN="A LIVE INSTANCE of the target is running at: $URL
Use it for dynamic reproduction and to confirm reachability/behavior. Send requests with
.agents/skills/convergence/scripts/probe.py (e.g. probe.py -X GET \"$URL/<path>\" -H ...).
$ACCT_NOTE
Only ever send requests to $URL - never any other host."
  echo "== live target: $URL  | accounts: $([ -f "$ACCOUNTS" ] && echo "$ACCOUNTS ($N)" || echo none) =="
else
  DYN="No live instance was provided (no --url). Do static analysis only; when a finding
needs dynamic proof, set status needs_reanalysis with a note that it requires a running
server, instead of guessing."
  echo "== no --url: static-only mode (dynamic reproduction disabled) =="
fi

COMMON="targets/ is READ-ONLY; never modify it. Your persistent memory is workspace/ -
use it as a notebook so you go DEEPER across iterations instead of repeating. Findings are
authored ONLY by you via .agents/skills/_shared/write_finding.py (file-locked,
safe for parallel writers). Read workspace/findings/ before writing so you don't duplicate.
Walk EVERY module in workspace/coverage.json; for each, either record a finding or justify
why it's safe. You don't get tired - keep going until repeated passes find nothing new.
For ConcreteCMS the real code is concrete/ and concrete/src, not the near-empty application/.
$DYN"

MISSION_A="You are PRODUCER A of a white-box security assessment. Focus ONLY on
INJECTION / DATA-FLOW vulnerabilities: SQL injection, command/code injection, XSS, SSRF,
path traversal, file inclusion, deserialization, XXE, SSTI, NoSQL, open redirect. Read
real code, enumerate sinks, trace backward to attacker-controlled sources, judge
sanitizers/exploitability. Use the vuln-track-a skill. Optionally pull leads with
.agents/skills/vuln-track-a/scripts/run_semgrep.sh $TARGET (hints only). When a live URL is
available, confirm reachability/exploitability against it. Record findings with track=\"A\".
$COMMON"

MISSION_B="You are PRODUCER B of a white-box security assessment. Focus ONLY on LOGIC /
ACCESS-CONTROL vulnerabilities that data-flow tools miss: IDOR/BOLA, missing authorization,
privilege escalation, authentication/session bypass, and business-logic flaws
(step-skipping, price/quantity tampering, mass assignment, race conditions). For EVERY
route/action ask: who can reach this, is there an authz check, is object ownership
verified. Use the vuln-track-b skill and workspace/_authz_matrix.json as a seed (build it
with .agents/skills/vuln-track-b/scripts/build_authz_matrix.py). When a live URL and
accounts are available, prove access-control bugs by replaying requests across two
accounts. Record findings with track=\"B\"; if neither code nor a live test can confirm,
set status needs_reanalysis with reasoning. $COMMON"

MISSION_C="You are the CONSUMER (convergence). Producers A and B run in PARALLEL and stream
findings into workspace/findings/. Do NOT wait for them. Loop continuously: pick
candidate/cross_validated findings (highest severity first), then
1) cross-validate: .agents/skills/convergence/scripts/cross_validate.sh $TARGET (PHP falls
   back to OpenGrep; correlate bumps matches to cross_validated),
2) reproduce dynamically (only if a live URL is provided) with
   .agents/skills/convergence/scripts/probe.py - Track A: fire the payload; Track B:
   authenticate as two accounts from workspace/_accounts.json and replay one user's request
   with the other's session. Update status reproduced/false_positive/needs_reanalysis via
   write_finding.py --update <id>,
3) regenerate workspace/report/report.md with .agents/skills/convergence/scripts/triage.py.
If the queue is momentarily empty, wait briefly and recheck - producers are still working.
Keep going until producers stop and the queue is drained. Use the convergence skill.
$DYN"

echo "== launching 3 parallel Codex sessions (A inject | B logic | C converge) =="
$CODEX_CMD "$MISSION_A" > workspace/_log_A.txt 2>&1 &  PA=$!
$CODEX_CMD "$MISSION_B" > workspace/_log_B.txt 2>&1 &  PB=$!
$CODEX_CMD "$MISSION_C" > workspace/_log_C.txt 2>&1 &  PC=$!
echo "  A=$PA (workspace/_log_A.txt)  B=$PB (workspace/_log_B.txt)  C=$PC (workspace/_log_C.txt)"
echo "  python3 $S/convergence/scripts/queue.py --counts   # watch the queue"
trap 'echo; echo "stopping..."; kill $PA $PB $PC 2>/dev/null' INT TERM
wait
echo "== all sessions ended -> workspace/report/report.md =="