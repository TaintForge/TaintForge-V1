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
  # out-of-band canary for SSRF/blind confirmation.
  # .env can set SSRF_HOST/SSRF_PORT so callbacks use an externally-reachable address the
  # target (often in its own container/network) can actually reach - 127.0.0.1 usually can't.
  [ -f .env ] && set -a && . ./.env && set +a
  CANARY_PORT="${SSRF_PORT:-${CANARY_PORT:-9111}}"
  CANARY_HOST="${SSRF_HOST:-${CANARY_HOST:-127.0.0.1}}"
  python3 "$S/convergence/scripts/canary.py" serve --port "$CANARY_PORT" \
      --log workspace/_canary.log > workspace/_log_canary.txt 2>&1 &  PCAN=$!
  DYN="A LIVE INSTANCE of the target is running at: $URL
Use it for dynamic reproduction. Send requests with
.agents/skills/convergence/scripts/probe.py (it keeps sessions via --jar FILE; e.g.
probe.py -X GET \"$URL/<path>\" --jar a.jar). $ACCT_NOTE
An OUT-OF-BAND CANARY is running on port $CANARY_PORT and is reachable from the target at
http://$CANARY_HOST:$CANARY_PORT (externally-routable). For SSRF/blind bugs make the target
fetch http://$CANARY_HOST:$CANARY_PORT/<uniqueToken> via the vulnerable param (get the URL
with .agents/skills/convergence/scripts/canary.py url <uniqueToken>), then run
.agents/skills/convergence/scripts/canary.py check <uniqueToken> - a HIT proves SSRF
out-of-band. For internal/blind SSRF without a callback, compare responses to
http://127.0.0.1:<internalport> or http://169.254.169.254/ instead.
Only send requests to $URL and the canary - never any other host."
  echo "== live target: $URL  | accounts: $([ -f "$ACCOUNTS" ] && echo "$ACCOUNTS ($N)" || echo none)  | canary: $CANARY_HOST:$CANARY_PORT =="
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
coverage.py models the codebase as a TREE (directory -> module -> entry point). Drive your
sweep with .agents/skills/source-model/scripts/coverage.py: --next gives the next pending
module ATTACK-SURFACE FIRST (modules exposing routes/handlers before leaf libraries); --tree
shows each module's entry points (the routes an attacker can actually reach). Analyze every
module, but start from those with entry points and trace inward from each route. For each
module either record a finding or justify why it's safe, then coverage.py --done <module>.
You don't get tired - keep going until repeated passes find nothing new.
$DYN"

MISSION_A="You are PRODUCER A of a white-box security assessment. Focus ONLY on
INJECTION / DATA-FLOW vulnerabilities: SQL injection, command/code injection, XSS, SSRF,
path traversal, file inclusion, deserialization, XXE, SSTI, NoSQL, open redirect.

VULNERABILITIES LIVE ON FLOWS ACROSS FILES, not in one line. Work sink-first and trace
backward across function/file/module boundaries - a call that looks safe in one file is
often fed tainted input three calls away. Use the call graph in
workspace/CODE_MODEL.json (structural.call_graph) via the helper:
  python3 .agents/skills/source-model/scripts/callgraph.py --stats
  python3 .agents/skills/source-model/scripts/callgraph.py --callers <sinkOrFunc>   # who calls it
  python3 .agents/skills/source-model/scripts/callgraph.py --trace   <sinkOrFunc>   # backward paths
For each dangerous sink (query/exec/system/unserialize/include/eval/file_get_contents/...)
list its callers, follow the chain back until you reach attacker-controlled input
(\$_GET/\$_POST/headers/route vars), and judge sanitizers along the WHOLE path. Do NOT mark
a sink safe by looking at its file alone - check the callers.

The call graph is coarse and cannot see language-construct sinks used directly on input
(e.g. include \$_GET['p'], echo \$input, eval of a request value). Find those by READING the
code too; the graph is a starting map, not the whole territory.

Use the vuln-track-a skill. Optionally pull leads with
.agents/skills/vuln-track-a/scripts/run_semgrep.sh $TARGET (hints only). When a live URL is
available, confirm reachability/exploitability against it. Record findings with track=\"A\".
$COMMON"

MISSION_B="You are PRODUCER B of a white-box security assessment. Focus ONLY on LOGIC /
ACCESS-CONTROL vulnerabilities that data-flow tools miss: IDOR/BOLA, missing authorization,
privilege escalation, authentication/session bypass, and business-logic flaws
(step-skipping, price/quantity tampering, mass assignment, race conditions).

ACCESS-CONTROL BUGS LIVE ON THE PATH FROM AN ENTRY POINT TO A RESOURCE ACCESS. Trace that
path and check whether an authorization GATE exists ANYWHERE on it. Use the call graph in
workspace/CODE_MODEL.json via:
  python3 .agents/skills/source-model/scripts/callgraph.py --callees <handlerFile>  # what a route handler calls
  python3 .agents/skills/source-model/scripts/callgraph.py --callers <loaderOrFindFn>  # who reaches a resource load
For each route/action in workspace/_authz_matrix.json and CODE_MODEL comprehension.route_map:
follow handler -> service -> repository/object-load, and ask along the WHOLE chain: is there
an authn check, a role/permission check, and an OWNERSHIP/tenant check on the requested
object id? If a findById/load/getByID is reachable from a route with NO ownership check on
the path, that is IDOR. Missing role check on a state-changing action is broken authz.
Don't judge from the handler file alone - follow the calls.

Use the vuln-track-b skill and workspace/_authz_matrix.json as a seed (build it with
.agents/skills/vuln-track-b/scripts/build_authz_matrix.py). When a live URL and accounts are
available, PROVE access-control bugs by replaying one account's request with another
account's session. Record findings with track=\"B\"; if neither code nor a live test can
confirm, set status needs_reanalysis with reasoning. $COMMON"

MISSION_C="You are the CONSUMER (convergence). Producers A and B run in PARALLEL and stream
findings into workspace/findings/. Do NOT wait for them. Loop continuously: pick
candidate/cross_validated findings (highest severity first), then
1) cross-validate: .agents/skills/convergence/scripts/cross_validate.sh $TARGET (PHP falls
   back to OpenGrep; correlate bumps matches to cross_validated),
2) reproduce dynamically (only if a live URL is provided) with
   .agents/skills/convergence/scripts/probe.py. It keeps a SESSION via --jar FILE: log in
   each account from workspace/_accounts.json into its own jar (find the login route/body
   from the code yourself), then reuse that jar to hit protected resources. Track A: fire
   the payload and look for the sink triggering. For XSS specifically, reflection is NOT
   proof - confirm EXECUTION with .agents/skills/convergence/scripts/browser_probe.py (headless
   browser; --jar for stored/authed XSS); only executed:true counts as reproduced. Track B (IDOR/authz): with account A's jar,
   request account B's object/action - if A gets B's data it is confirmed; for priv-esc hit
   an admin action with a low-priv jar. Update status reproduced/false_positive/
   needs_reanalysis via write_finding.py --update <id>. ALWAYS attach a PoC: record the
   exact reproducing command(s) in repro.poc (full probe.py/curl line with payload, headers,
   --jar - copy-pasteable) and the decisive response in repro.response; for IDOR include
   both identities' requests. If the live test is inconclusive,
   set needs_reanalysis (not stuck candidate),
3) for any finding you just moved to reproduced/confirmed, WEB-SEARCH whether it is already
   public: query the target product+version+vuln specifics against CVE/NVD, vendor and
   GitHub security advisories, changelogs. Set disclosure{status: novel|known|inconclusive,
   references:[...], rationale} via write_finding.py --update <id>. novel = no public report
   (potential 0-day). Only search reproduced/confirmed findings, not raw candidates.
4) for each reproduced/confirmed finding, WRITE a poc.py that reproduces THAT specific vuln
   using the requests library, and store its full source in repro.poc_script via
   write_finding.py --update <id>. Make it fit the actual vuln: if it is pre-auth, no login
   step; otherwise authenticate as needed; use as many requests as the exploit takes; print
   a clear PASS/FAIL signal. Do NOT assume a fixed login->exploit shape. Then run
   .agents/skills/convergence/scripts/emit_poc.py to materialize workspace/report/<id>/
   (poc.py + finding.md), one folder per vulnerability - never merged.
5) regenerate the rolling index workspace/report/report.md with .agents/skills/convergence/scripts/triage.py.
DO NOT EVER STOP ON YOUR OWN. Do not check whether producer processes are alive. Do not
treat an empty queue as completion. If workspace/findings/ has nothing new, sleep ~30s and
check again - the producers stream findings continuously and new ones arrive over time.
Never declare the convergence complete and never exit - run as an infinite loop until a
human kills you. Each cycle: process any candidate/cross_validated findings, then sleep
and recheck.
Use the convergence skill. $DYN"

MISSION_D="You are the EXPLOITATION agent. You do NOT find new bugs and you do NOT triage the
queue. You take findings that the consumer already proved (status reproduced or confirmed)
and ONLY the genuinely critical classes - rce, command-injection, sql-injection, auth-bypass,
deserialization, ssrf-to-internal, path-traversal-to-rce, file-upload-to-rce - and turn a
proof-of-concept into a fully understood, weaponized exploit. Loop continuously:
1) select: read workspace/findings/*.json; pick status in {reproduced,confirmed} whose
   vuln_class is one of the critical classes above and whose exploit.depth is missing or
   'shallow' (skip everything else - low/medium and unproven findings are not your job).
   Highest severity first.
2) deepen: starting from the existing repro, push the exploit as far as it really goes, and
   VERIFY each step against the live target ($DYN) or, when no live target, against the code
   plus a local shell/interpreter model of the sink. Concretely:
   - chain & escalate: from the proven primitive, reach the highest real impact (e.g. blind
     SQLi -> data exfic via boolean/time; command-injection limited to one token -> stage a
     payload file and invoke it by path; SSRF -> hit cloud metadata/internal services with
     canary.py; auth-bypass -> reach an admin-only action).
   - defeat mitigations: when a sanitizer/escape/quoting/WAF blocks the obvious payload,
     analyze EXACTLY what it permits (which bytes/metacharacters survive) and find a working
     bypass; prove the bypass actually executes, do not hand-wave it.
   - confirm execution out-of-band where relevant with
     .agents/skills/convergence/scripts/canary.py (SSRF/blind RCE) or browser_probe.py (XSS->
     account takeover chains).
3) record honestly: write the result back with write_finding.py --update <id> into an
   exploit object: {depth: shallow|chained|weaponized, primitive, max_impact, steps:[...],
   mitigations_bypassed:[...], constraints:[...], working_poc, oob_evidence}. Do NOT overstate
   - if the impact is bounded (e.g. only argument-less single-token commands run), say so
   precisely and record the exact constraint. A correct 'bounded' result is worth more than
   an exaggerated one.
4) materialize: write a standalone weaponized exploit as workspace/report/<id>/exploit.py
   (requests/raw sockets as needed, copy-pasteable, prints PASS plus the captured evidence),
   separate from C's poc.py, and store its full source in exploit.working_poc.
NEVER attack a host you were not pointed at; the only live target is the one in $DYN. Treat
the target as your own lab. DO NOT EVER STOP ON YOUR OWN: if nothing currently qualifies,
sleep ~45s and re-scan - the consumer keeps promoting findings to reproduced over time. Run
as an infinite loop until a human kills you. Use the convergence skill. $DYN"

echo "== launching 4 parallel Codex sessions (auto-respawn until deadline / stop) =="
MAX_HOURS="${MAX_HOURS:-12}"
DEADLINE=$(( $(date +%s) + MAX_HOURS*3600 ))
rm -f workspace/_stop

# A codex exec session is NOT infinite - it exits when the agent decides it's done or hits
# a turn/token limit. For a streaming consumer/producer that's fatal (C "completes" and
# dies while findings are still coming). So each role runs under a supervisor that RESPAWNS
# it whenever it exits, until MAX_HOURS or workspace/_stop. Logs are appended across restarts.
supervise(){ # $1=tag $2=logfile $3=mission  -> echoes supervisor pid
  ( n=0
    while [ ! -f workspace/_stop ] && [ "$(date +%s)" -lt "$DEADLINE" ]; do
        n=$((n+1))
        echo "===== [$(date +%H:%M:%S)] session $1 start #$n =====" >> "$2"
        $CODEX_CMD "$3" >> "$2" 2>&1 </dev/null
        echo "===== [$(date +%H:%M:%S)] session $1 exited (#$n); respawn in 5s =====" >> "$2"
        sleep 5
    done
    echo "===== [$(date +%H:%M:%S)] session $1 supervisor stopped =====" >> "$2"
  ) </dev/null >/dev/null 2>&1 & echo $!
}
PA=$(supervise A workspace/_log_A.txt "$MISSION_A")
PB=$(supervise B workspace/_log_B.txt "$MISSION_B")
PC=$(supervise C workspace/_log_C.txt "$MISSION_C")
PD=$(supervise D workspace/_log_D.txt "$MISSION_D")
echo "$PA $PB $PC $PD ${PCAN:-}" > workspace/_pids
echo "  A=$PA  B=$PB  C=$PC  D=$PD  (supervisors; auto-respawn, ${MAX_HOURS}h budget)"

stop_all(){ touch workspace/_stop; kill $PA $PB $PC $PD ${PCAN:-} 2>/dev/null; pkill -f "codex exec" 2>/dev/null; }

# SPAWN_ONLY=1 -> return immediately (start.sh's tmux wrapper drives the display).
if [ "${SPAWN_ONLY:-0}" = "1" ]; then
  echo "  (spawned; pids in workspace/_pids)  stop with: touch workspace/_stop; kill \$(cat workspace/_pids); pkill -f 'codex exec'"
  exit 0
fi

echo "  python3 $S/convergence/scripts/queue.py --counts   # watch the queue"
trap 'echo; echo "stopping..."; stop_all' INT TERM
wait $PA $PB $PC
echo "== run ended (deadline/stop) -> workspace/report/report.md =="