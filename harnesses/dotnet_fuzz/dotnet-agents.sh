#!/usr/bin/env bash
# Microsoft .NET bounty source/fuzzing agents with one visible pane per role.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SELF="$ROOT/harnesses/dotnet_fuzz/dotnet-agents.sh"
STATE="$ROOT/workspace/dotnet-bounty/agents"
STOP="$STATE/_stop"
PIDS="$STATE/_pids"
SESSION="${TF_DOTNET_AGENT_SESSION:-taintforge-dotnet-agents}"
MAX_HOURS="${MAX_HOURS:-12}"

timestamp() {
  date '+%Y-%m-%dT%H:%M:%S%z'
}

common_prompt() {
  cat <<EOF
This is an authorized Microsoft-only .NET bounty assessment. Do not delegate to subagents. Read
$ROOT/AGENTS.md completely and then read every role skill named below before acting.
The imported RTK.md file is absent from this checkout; note that once and continue immediately
with AGENTS.md and the named role skills instead of repeatedly searching for it.

Repository root: $ROOT
Read-only targets:
- $ROOT/targets/dotnet-aspnetcore-10.0.12 (official v10.0.12)
- $ROOT/targets/dotnet-runtime-10.0.12 (official v10.0.12)
Build-only copies: $ROOT/.labs/dotnet/source
Persistent state: $ROOT/workspace/dotnet-bounty
Shared finding queue: $ROOT/workspace/findings
Role stop flag: $STOP

Never modify targets/. Dynamic traffic is authorized only to loopback; the source-built Kestrel
sample, when active, is 127.0.0.1:5001. Author findings only through
.agents/skills/_shared/write_finding.py and record partial capabilities through leads.py. A tool
hit or crash is only a lead. The primary objective is demonstrable pre-authentication RCE, then
authenticated RCE. Keep lower-impact parser behavior only when it supplies a credible chain link.

Available isolated Code Models:
- workspace/dotnet-bounty/aspnetcore-kestrel-core/CODE_MODEL.json
- workspace/dotnet-bounty/runtime-coreclr-vm/CODE_MODEL.json
- workspace/dotnet-bounty/runtime-coreclr-jit/CODE_MODEL.json
- workspace/dotnet-bounty/runtime-library-fuzzing/CODE_MODEL.json

The active Kestrel AFL++ lane is controlled by
harnesses/dotnet_fuzz/kestrel_http1/campaign.sh and writes beneath
workspace/dotnet-bounty/kestrel-http1. Preserve every prior afl* directory. Continue until the
role stop flag exists; a quiet queue or one clean pass is not completion.

The official patch-variant lane is controlled by
harnesses/dotnet_fuzz/patch_variants/campaign.sh. Its normalized advisory set, exact release
diffs, claims and review results live under workspace/dotnet-bounty/patch-variants. Public CVEs
in that queue are known negative controls. Only a distinct root cause or incomplete fix that
reproduces on the stock 10.0.12 target can become a candidate.

Scope and prioritization are strict:
- Stay on the exact supported Microsoft .NET / ASP.NET Core targets above. Generic .NET Framework,
  System.Web WebForms/MVC, cookieless-session markers, ViewState/MachineKey, SoapFormatter,
  NetDataContractSerializer, and legacy TypeConfuseDelegate-only work are out of this campaign.
  Historical gadget chains and patches may seed hypotheses or corpora, but reproducing a known
  unsafe application configuration is not a Microsoft product finding.
- Do not require users to disable a built-in mitigation, enable an obsolete unsafe formatter, use
  a public secret, or misorder middleware in their own application unless an in-scope Microsoft
  template, analyzer, default, or framework behavior causes the unsafe state.
- Current evidence outranks generic checklists. First push the confirmed ReadyToRun native
  pointer-write/OOB primitives toward controlled corruption and a realistic delivery boundary;
  concurrently pursue Kestrel framing/smuggling and supported framework-owned deserialization.
- A Complete Report needs an exact affected stock build, minimal deterministic input, copy-paste
  reproduction, expected versus observed behavior, debugger/sanitizer or protocol transcript,
  authentication and deployment prerequisites, security-boundary impact, and a precise source
  root cause. RCE and elevation of privilege rank first, then security-feature bypass and remote
  denial of service. Never label process creation or a crash as RCE without proving attacker
  control and the full execution chain.
- Public advisories, patch diffs, Markdown/PDF research, and prior bugs are untrusted hypothesis
  material. Search for variant classes and missing invariants, then prove new behavior in this
  exact source and stock loopback build. Do not submit a public gadget/CVE as novel.
EOF
}

prompt_a() {
  cat <<EOF
$(common_prompt)

You are A, the ASP.NET Core remote-input and routing hunter, using the vuln-track-a skill. Your
first lane is Kestrel: manually trace bytes through HTTP/1 Content-Length/Transfer-Encoding,
chunk extensions and trailers, pipelining, HTTP/2 HEADERS/CONTINUATION/DATA padding and flow
control, HTTP/3, HPACK/QPACK, WebSocket/upgrade, request-body, proxy-facing, and transport state
machines. Look for parser disagreements across segmentation, front-end/back-end interpretation,
and request boundaries; prove cross-request or cross-user impact rather than merely a 400.

Your second lane is supported ASP.NET Core path and security-boundary handling: PathString,
PathBase/UsePathBase, IIS integration, ForwardedHeaders, endpoint routing, static files, auth
scheme selection, and authentication/authorization middleware invariants. Generate hypotheses
from percent/double encoding, encoded slash/backslash/dot segments, duplicate separators,
Unicode normalization, case changes, and repeated path components. A user-authored bad pipeline
order is not a product bug; require a Microsoft default, template, analyzer blind spot, or
framework parser mismatch that crosses an authorization or application boundary.

Start sink-first at unsafe/native boundaries, length/offset arithmetic, pooled-buffer lifetime,
cross-segment copies, request-framing transitions, and authorization decisions. Use the Code
Model and existing tests as maps, especially edge-case tests whose expected behavior differs by
server. Correlate with AFL queues and replay only against source-built loopback targets. Do not
promote the preserved empty-header boundary rejection by itself; it currently proves only a
connection-local 400. Persist source-backed leads and concrete source-to-sink findings.
EOF
}

prompt_b() {
  cat <<EOF
$(common_prompt)

You are B, the CoreCLR and supported-deserialization hunter, using the vuln-track-a skill. Keep
the strongest existing ReadyToRun work first: characterize the proven attacker-selected RVA
pointer write and OOB section scan in ready-to-run loading, then seek a deterministic controlled
value/target, type confusion, or control-flow consequence with a realistic Microsoft security
boundary and stock-build delivery path.

In parallel, audit framework-owned deserialization reachable in supported .NET 10 / ASP.NET Core:
System.Text.Json converters and polymorphism, System.Formats.Nrbf and any BinaryFormatter
compatibility parsing that remains in supported code, DataContractSerializer/XmlSerializer and
ASP.NET Core XML input formatters, Blazor component/circuit parameter deserialization,
DataProtection descriptor parsing, output-cache binary formatting, resource/metadata/PE/PDB
readers, and reflection/dynamic-loading boundaries. Apply a YSoNet-style methodology only to
discover new graph construction, callback, binder, converter, or type-confusion behavior owned by
the supported product. Do not spend campaign time building generic .NET Framework gadget chains
or reporting an application that explicitly selected an obsolete unsafe formatter.

Also inspect diagnostics/profiler IPC, marshalling, regex/globalization native code, JIT
importer/optimizer assumptions, GC/lifetime edges, and official library fuzz targets. Prioritize
attacker bytes that reach memory-unsafe C/C++ or framework-triggered code execution before
authentication. Distinguish hostile application IL/content from a runtime security boundary.
Use Code Models, patch diffs, official tests, and historical bug families to choose deep paths;
prove source reachability, type resolution, mitigations, and attacker control before promotion.
EOF
}

prompt_c() {
  cat <<EOF
$(common_prompt)

You are C, the convergence and triage consumer, using the convergence skill. Continuously inspect
workspace/findings, open leads, exploitability dossiers under workspace/dotnet-bounty/exploitability,
and newly saved AFL crashes. Independently validate exact source
paths; minimize and replay fuzz artifacts; test stock behavior only on loopback; determine remote
reachability, authentication level, attacker control, and security impact. Deduplicate root
causes. Move ambiguous candidates to needs_reanalysis with one precise testable premise. Only
after reproduction, check Microsoft/GitHub/CVE disclosures and emit exact PoCs and rolling
triage. Do not convert ordinary parser rejection or harness-only differential behavior into a
finding. Rank pre-auth RCE and memory-corruption primitives first.

Before cross-validation, enforce the scope gate in the common prompt. Reject generic legacy
formatter gadget execution, public MachineKeys, System.Web cookieless/ViewState behavior,
user-created middleware-order mistakes, and harness-only behavior unless the producer identifies
an exact in-scope Microsoft-owned default or invariant. For each reproduced/confirmed issue,
require a Complete Report bundle: minimal input, exact commands and build identifiers, decisive
stdout/stderr/response/debugger evidence, clean controls, affected boundary, prerequisites,
impact and reliability, source root cause, and a standalone PoC. Missing items go to
needs_reanalysis with one testable request rather than being papered over.
EOF
}

prompt_d() {
  cat <<EOF
$(common_prompt)

You are D, the proactive exploitability researcher, using the convergence and vuln-track-a skills.
Do not wait only for reproduced findings: continuously select the strongest source-backed open
lead, candidate, minimized crash, or producer hypothesis and determine whether it can become a
controlled security primitive. Work in parallel with A/B/C, but do not claim a vulnerability
until their evidence threshold is met.

At the start of every session run leads.py open and rank native memory-safety/control-flow leads
above availability-only behavior. In the current campaign, investigate the confirmed ReadyToRun
attacker-selected RVA pointer-write primitive first. Next rank Kestrel cross-request framing and
HTTP/2 flow-control candidates, supported framework-owned deserialization chains, and only then
HTTP/3/WebTransport availability leads. The known Kestrel one-character empty-header segmentation
family has already been reduced to connection-local 400-and-close; do not replay its historical
AFL files unless a new independent framing, authorization, or memory-safety composition appears.

For every selected lead, test several realistic exploit scenarios where applicable: malformed
PE/ReadyToRun/metadata through Assembly.Load(byte[]), reflection, single-file/bundle or native
image loading; Kestrel HTTP/1/2/3 and WebTransport state corruption; pooled-buffer lifetime and
cross-request reuse; supported JSON/XML/NRBF/DataProtection/Blazor deserialization callbacks and
type resolution; managed/native marshalling; and JIT wrong-code leading to bounds-check removal
or type confusion. Historical YSoNet-style graphs are mutation templates only: a successful
known gadget under an obsolete opt-in formatter is a control, not a product vulnerability.
Characterize controlled bytes, offset/size, read versus write,
lifetime, allocator and GC influence, repeatability, stock Release behavior, authentication and
remote-delivery prerequisites, plus ASLR/CFG/W^X and runtime mitigations. Use debugger and
sanitizer builds only under .labs and traffic only on loopback.

Write an evidence dossier for each investigated lead under
workspace/dotnet-bounty/exploitability/<lead-or-slug>.json with: source lead IDs, entry path,
tested scenarios, observed primitive, attacker control, mitigations, blockers, evidence paths,
and next experiment. Mark primitive_confirmed true only after deterministic proof. Record useful
capabilities with leads.py. Do not update a finding's exploit object until C has reproduced or
confirmed it; G owns final weaponization. Never relabel an exception, assert, parser rejection,
or process DoS as code execution.
EOF
}

prompt_g() {
  cat <<EOF
$(common_prompt)

You are G, the final weaponization and RCE-chain agent, using the convergence skill. Continuously
consume reproduced or confirmed findings plus D dossiers whose primitive_confirmed field is true.
Do not spend time on speculative source patterns. Re-verify the primitive on the exact stock
10.0.12 build, then push it through multiple plausible chains to demonstrable pre-auth RCE first
and authenticated RCE second.

For memory corruption, establish controlled read/write or control-flow influence, heap/GC shaping,
reliability, and mitigation constraints before attempting code execution. For parser/state bugs,
test only evidence-backed compositions into authentication bypass, internal endpoint reachability,
cross-request corruption, file write, dynamic assembly/plugin loading, or another code-execution
primitive. Keep every step local and reproducible. Update findings only through write_finding.py
with honest exploit depth and constraints, and materialize a standalone exploit.py beneath the
finding's report directory. If a dossier lacks a controlled primitive, return a precise blocker
to D rather than overstating impact.

The final exploit and report must run on the exact unmodified supported stock build and include a
benign, unmistakable execution/privilege oracle plus negative controls. State whether the result
is pre-auth, low-privilege, or requires application opt-in. Do not weaponize generic legacy
formatter gadgets, public MachineKeys, or user pipeline misconfiguration. If the chain depends on
those, mark it out of campaign scope instead of calling it RCE or elevation of privilege.
EOF
}

prompt_e() {
  cat <<EOF
$(common_prompt)

You are E, the dedicated reanalysis agent, using the convergence skill and the producer skill
matching each finding. Poll only needs_reanalysis findings. Diagnose the exact failed premise:
stock reachability, packet/Pipe segmentation, parser mode, authentication state, native boundary,
serializer/type-resolution configuration, path canonicalization layer, middleware/template
ownership, scope eligibility, sanitizer evidence, reproducibility, or missing chain link. Perform
the smallest loopback test that resolves it and include a clean negative control. Return an item
to C only with genuinely new evidence; otherwise close it as a false positive with the precise
reason. Never bounce an unchanged finding.
EOF
}

prompt_f() {
  cat <<EOF
$(common_prompt)

You are F, the adaptive harness engineer and memory-safety producer, using the vuln-track-a and
convergence skills. Inspect live AFL statistics, queue quality, crash families, source coverage,
and existing official fuzz targets. In each session make at most one evidence-driven improvement:
repair a harness invariant, improve structured seeds/dictionaries, add a regression replay, or
add the next highest-value Microsoft lane. Work this backlog in evidence order:
1. Extend Kestrel transcript generation for conflicting/repeated Content-Length and
   Transfer-Encoding, malformed chunk sizes/extensions/terminators/trailers, segmented bodies,
   pipelined requests, and paired victim requests. Add semantic repair so mutations reach deep
   states, and add response-stream/cross-request oracles instead of treating every rejection as a
   crash.
2. Add HTTP/2 structured generation for HEADERS/CONTINUATION/DATA boundaries, padding, stream
   lifecycle, and flow-control accounting; keep HTTP/3 behind stronger current evidence.
3. Add a supported-deserialization differential lane covering System.Text.Json polymorphism and
   converters, System.Formats.Nrbf/remaining BinaryFormatter compatibility parsing,
   DataContractSerializer/XmlSerializer input formatters, Blazor parameter records,
   DataProtection descriptors, and output-cache formatting. Generate bounded object graphs,
   duplicate/type metadata, malformed lengths/references, and version-skewed inputs. Oracles must
   distinguish expected parse exceptions from process signal, native sanitizer finding, callback
   outside the allowed type model, unexpected file/network/process side effect, or persistent
   state corruption.
4. Add a supported ASP.NET Core path differential lane for PathBase/UsePathBase, IIS integration,
   endpoint routing, static files, forwarded headers and auth decisions using percent/double
   encoding, slash/backslash/dot variants, duplicate separators, Unicode/case normalization and
   repeated components. Compare routing, selected endpoint, auth result and effective path.
5. Audit current official templates/analyzers for authentication/authorization ordering only
   after the runtime and protocol lanes; a deliberately misordered user application is a control.

Do not add generic .NET Framework, System.Web cookieless/ViewState/MachineKey, SoapFormatter,
NetDataContractSerializer, or TypeConfuseDelegate gadget lanes. Build and instrument only .labs
copies. Never erase or reset queues or stop a healthy campaign. Verify each change with a stock
replay and a clean control. Record crashes and side effects as leads until sanitizer/debugger
evidence, source root cause, attacker reachability, and a security boundary are established.
EOF
}

prompt_h() {
  cat <<EOF
$(common_prompt)

You are H, the dedicated Microsoft patch-variant archaeologist, using the vuln-track-a skill.
At the start of each session run:

  harnesses/dotnet_fuzz/patch_variants/campaign.sh refresh
  harnesses/dotnet_fuzz/patch_variants/campaign.sh claim --owner H

Work exactly one claimed task deeply before claiming another. Read the entire public fix hunk,
the surrounding vulnerable and fixed logic represented by the release comparison, every added
regression test, and the corresponding current 10.0.12 source. State the precise invariant the
known patch restored. Then search the current stock targets for siblings, overloads, alternate
protocol versions, alternate serializers/providers, managed/native mirrors, vectorized/scalar
implementations, error paths, and call sites that enforce the same invariant differently or not
at all. Patch keywords are navigation leads, never proof.

For parser and memory-safety patches, derive structured inputs from the regression test and vary
nested count/offset/length arithmetic, signedness, truncation, segmentation, pooling, abort and
dispose timing. For auth/crypto patches, compare every provider and compatibility path with
malformed, replayed, partial and version-skewed payloads using an authorization/signature oracle.
For protocol patches, include a paired victim request or cross-stream oracle. Prefer old fixes
whose repaired helper still has multiple current callers, and recent servicing deltas that touch
unsafe/native, framing, auth, crypto, deserialization or state-machine code.

Do not report the known CVE, a backport omission on an unsupported version, or behavior requiring
an obsolete unsafe opt-in. A valid candidate must be behaviorally distinct, attacker reachable,
reproduce on the exact unmodified supported 10.0.12 target, and cross a Microsoft-owned security
boundary. Record intermediate capabilities with leads.py. Use write_finding.py only after that
threshold. Finish every task with:

  harnesses/dotnet_fuzz/patch_variants/campaign.sh complete --id TASK_ID --owner H \
    --result RESULT --note 'evidence-backed result and next experiment'

where RESULT is one of reviewed, lead, candidate, or blocked.

If a test needs a new harness, make the smallest implementation outside targets/, verify it with
the public fixed behavior as a negative control, and hand it to F through a lead/note. Do not
erase corpora, caches, prior claims or results.
EOF
}

# Model backend. TF_BACKEND=claude (default) or codex.
#   TF_MODEL        overrides the main model for either backend
#   TF_MODEL_REASON overrides the reasoning-heavy model used by C and E (codex only;
#                   `claude -p` exposes no reasoning-effort switch, so every role
#                   gets the same model there)
# Both backends write to the same role log. stream_fmt.py renders Claude's
# stream-json and passes Codex's plain text through unchanged, so one pane
# command works for either.
run_model() {
  local role="$1"
  local prompt="$2"
  case "${TF_BACKEND:-claude}" in
    codex)
      case "$role" in
        C|E)
          codex exec --sandbox workspace-write \
            --config sandbox_workspace_write.network_access=true \
            --config web_search=live \
            --model "${TF_MODEL_REASON:-gpt-6-sol}" \
            --config model_reasoning_effort=xhigh "$prompt" < /dev/null
          ;;
        *)
          codex exec --sandbox workspace-write \
            --config sandbox_workspace_write.network_access=true \
            --config web_search=live \
            --model "${TF_MODEL:-gpt-daybreak-blue-latest}" \
            --config model_reasoning_effort=max "$prompt" < /dev/null
          ;;
      esac
      ;;
    claude|*)
      claude -p \
        --output-format stream-json --verbose \
        --dangerously-skip-permissions \
        --model "${TF_MODEL:-claude-opus-5}" \
        "$prompt" < /dev/null
      ;;
  esac
}

supervise() {
  local role="$1"
  local logfile="$STATE/$role.log"
  local prompt child="" start elapsed backoff=10
  trap '[ -z "$child" ] || kill "$child" 2>/dev/null || true; exit 0' INT TERM
  while [ ! -e "$STOP" ]; do
    prompt="$("prompt_${role,,}")"
    printf '[%s] role %s session starting\n' "$(timestamp)" "$role" >> "$logfile"
    start=$(date +%s)
    run_model "$role" "$prompt" >> "$logfile" 2>&1 &
    child=$!
    if wait "$child"; then
      printf '[%s] role %s session returned; respawning\n' "$(timestamp)" "$role" >> "$logfile"
    else
      printf '[%s] role %s session failed; respawning\n' "$(timestamp)" "$role" >> "$logfile"
    fi
    child=""
    elapsed=$(( $(date +%s) - start ))
    # A session that dies in under a minute is almost always the account rate
    # limit, not real work. Hammering it every 10s burns nothing but wall clock
    # and fills the log, so back off geometrically up to 30 minutes. A session
    # that actually ran resets the backoff.
    if [ "$elapsed" -lt 60 ]; then
      backoff=$(( backoff * 3 ))
      [ "$backoff" -gt 1800 ] && backoff=1800
      printf '[%s] role %s died after %ss; backing off %ss\n' "$(timestamp)" "$role" "$elapsed" "$backoff" >> "$logfile"
    else
      backoff=10
    fi
    for _ in $(seq 1 "$backoff"); do
      [ -e "$STOP" ] && break
      sleep 1
    done
  done
}

run_supervisors() {
  mkdir -p "$STATE" "$ROOT/workspace/findings" "$ROOT/workspace/dotnet-bounty/exploitability"
  rm -f "$STOP"
  local deadline=$(( $(date +%s) + MAX_HOURS * 3600 ))
  local role pid all_pids=()
  for role in ${TF_ROLES:-A B C D E F G H}; do
    supervise "$role" &
    pid=$!
    all_pids+=("$pid")
  done
  printf '%s\n' "${all_pids[*]}" > "$PIDS"
  trap 'touch "$STOP"; kill "${all_pids[@]}" 2>/dev/null || true; wait 2>/dev/null || true; exit 0' INT TERM
  while [ ! -e "$STOP" ] && [ "$(date +%s)" -lt "$deadline" ]; do
    sleep 5
  done
  touch "$STOP"
  kill "${all_pids[@]}" 2>/dev/null || true
  wait 2>/dev/null || true
}

status_brief() {
  printf 'session=%s\n' "$SESSION"
  harnesses/dotnet_fuzz/kestrel_http1/campaign.sh status | tail -n +2
  printf 'findings='; find workspace/findings -maxdepth 1 -name '*.json' -type f 2>/dev/null | wc -l
  printf 'open_leads='; python3 - <<'PY'
import json
try:
    data = json.load(open('workspace/leads.json'))
    print(sum(item.get('status', 'open') == 'open' for item in data.get('leads', [])))
except Exception:
    print(0)
PY
  harnesses/dotnet_fuzz/patch_variants/campaign.sh status 2>/dev/null | head -n 2 || true
  for role in ${TF_ROLES:-A B C D E F G H}; do
    printf '%s=' "$role"
    pgrep -f "role $role session starting|You are $role," >/dev/null && echo active || echo supervisor
  done
}

start_session() {
  if tmux has-session -t "$SESSION" 2>/dev/null; then
    echo "already running: tmux attach -t $SESSION"
    return
  fi
  mkdir -p "$STATE" "$ROOT/workspace/findings" "$ROOT/workspace/dotnet-bounty/exploitability"
  rm -f "$STOP" "$PIDS"
  for role in ${TF_ROLES:-A B C D E F G H}; do
    : >> "$STATE/$role.log"
  done

  local command runtime pane_a pane_b pane_c pane_d pane_e pane_f pane_g pane_h pane_status pane_vuln
  # tmux keeps a long-lived server whose environment comes from whichever client
  # created it, so campaign-scoped settings must be passed explicitly or the
  # supervisors silently fall back to their defaults.
  local -a runner_env=()
  for name in TF_BACKEND TF_ROLES TF_MODEL TF_MODEL_REASON MAX_HOURS; do
    [ -n "${!name-}" ] && runner_env+=("$name=${!name}")
  done
  printf -v command '%q ' env "${runner_env[@]}" "$SELF" run
  runtime="$(tmux new-session -d -s "$SESSION" -n runtime -x 260 -y 72 -c "$ROOT" -P -F '#{pane_id}' "$command")"
  tmux select-pane -t "$runtime" -T "SUPERVISORS"

  pane_a="$(tmux new-window -d -t "$SESSION:" -n agents -c "$ROOT" -P -F '#{pane_id}' "tail -n 80 -F workspace/dotnet-bounty/agents/A.log | python3 -u .agents/stream_fmt.py")"
  pane_b="$(tmux split-window -h -t "$pane_a" -c "$ROOT" -P -F '#{pane_id}' "tail -n 80 -F workspace/dotnet-bounty/agents/B.log | python3 -u .agents/stream_fmt.py")"
  pane_c="$(tmux split-window -v -t "$pane_a" -c "$ROOT" -P -F '#{pane_id}' "tail -n 80 -F workspace/dotnet-bounty/agents/C.log | python3 -u .agents/stream_fmt.py")"
  pane_d="$(tmux split-window -v -t "$pane_b" -c "$ROOT" -P -F '#{pane_id}' "tail -n 80 -F workspace/dotnet-bounty/agents/D.log | python3 -u .agents/stream_fmt.py")"
  pane_e="$(tmux split-window -v -t "$pane_c" -c "$ROOT" -P -F '#{pane_id}' "tail -n 80 -F workspace/dotnet-bounty/agents/E.log | python3 -u .agents/stream_fmt.py")"
  pane_f="$(tmux split-window -v -t "$pane_d" -c "$ROOT" -P -F '#{pane_id}' "tail -n 80 -F workspace/dotnet-bounty/agents/F.log | python3 -u .agents/stream_fmt.py")"
  pane_g="$(tmux split-window -v -t "$pane_f" -c "$ROOT" -P -F '#{pane_id}' "tail -n 80 -F workspace/dotnet-bounty/agents/G.log | python3 -u .agents/stream_fmt.py")"
  pane_h="$(tmux split-window -v -t "$pane_g" -c "$ROOT" -P -F '#{pane_id}' "tail -n 80 -F workspace/dotnet-bounty/agents/H.log | python3 -u .agents/stream_fmt.py")"
  command="watch -n 2 $(printf '%q' "$SELF") status-brief"
  pane_status="$(tmux split-window -v -t "$pane_e" -c "$ROOT" -P -F '#{pane_id}' "$command")"
  command="python3 .agents/skills/convergence/scripts/dashboard.py"
  pane_vuln="$(tmux new-window -d -t "$SESSION:" -n dashboard -c "$ROOT" -P -F '#{pane_id}' "$command")"
  tmux select-layout -t "$SESSION:agents" tiled

  tmux select-pane -t "$pane_a" -T "A HTTP+ROUTING / Opus 5"
  tmux select-pane -t "$pane_b" -T "B RUNTIME+SERDE / Opus 5"
  tmux select-pane -t "$pane_c" -T "C TRIAGE / Opus 5"
  tmux select-pane -t "$pane_d" -T "D EXPLOITABILITY / Opus 5"
  tmux select-pane -t "$pane_e" -T "E REANALYSIS / Opus 5"
  tmux select-pane -t "$pane_f" -T "F HARNESS / Opus 5"
  tmux select-pane -t "$pane_g" -T "G WEAPONIZE / Opus 5"
  tmux select-pane -t "$pane_h" -T "H PATCH VARIANTS / Opus 5"
  tmux select-pane -t "$pane_status" -T "MICROSOFT DASHBOARD"
  tmux select-pane -t "$pane_vuln" -T "VULNERABILITY DASHBOARD"
  tmux set -t "$SESSION" mouse on
  tmux set -t "$SESSION" default-terminal tmux-256color
  tmux setw -t "$SESSION:agents" remain-on-exit on
  tmux setw -t "$SESSION:dashboard" remain-on-exit on
  tmux select-window -t "$SESSION:dashboard"
  tmux select-pane -t "$pane_vuln"

  for _ in {1..50}; do
    [ -s "$PIDS" ] && break
    sleep .1
  done
  [ -s "$PIDS" ] || {
    echo "agent supervisors failed to start; inspect $SESSION:runtime" >&2
    return 1
  }
  echo "started: tmux attach -t $SESSION"
}

stop_session() {
  mkdir -p "$STATE"
  : > "$STOP"
  if [ -s "$PIDS" ]; then
    while read -r pid; do
      [[ "$pid" =~ ^[0-9]+$ ]] && kill "$pid" 2>/dev/null || true
    done < <(tr ' ' '\n' < "$PIDS")
  fi
  tmux kill-session -t "$SESSION" 2>/dev/null || true
  echo "stopped $SESSION; logs and findings preserved"
}

case "${1:-status}" in
  start) start_session ;;
  stop) stop_session ;;
  run) run_supervisors ;;
  status|status-brief) status_brief ;;
  attach) exec tmux attach -t "$SESSION" ;;
  *) echo "usage: $0 start|stop|status|attach" >&2; exit 2 ;;
esac
