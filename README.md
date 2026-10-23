# TaintForge

**An AI-agent white-box security assessment pipeline.** TaintForge points specialized Codex
subagents at a codebase and lets them hunt vulnerabilities the way a human auditor
would — reading code, reasoning about data flow and access control, then proving findings
against a live instance.

The model (Codex) is the analyst. Tools are its hands. Deterministic work — parsing, SAST
hints, ranking — is done by scripts; judgment — application understanding, taint reasoning,
sanitizer calls, logic/IDOR bugs, PoC crafting — is done by the agent. One contract glues
them together: the *finding* schema. For a deep, feature-by-feature and
workflow-by-workflow walkthrough, see **[DOCS.md](DOCS.md)**.

```
        ┌────────────────────────────────────────────────────────────┐
        │  targets/<app>          (read-only source)                   │
        └───────────────────────────┬──────────────────────────────────┘
                                    │
        ┌───────────────────────────▼──────────────────────────────────┐
        │ SEED (no LLM)   ast+regex structural model + module split   │
        │                 → workspace/CODE_MODEL.json, coverage.json     │
        └───────────────┬───────────────────────────┬──────────────────┘
                        │                            │      (shared findings queue)
        ┌───────────────▼──────────┐   ┌─────────────▼──────────────┐        │
        │ A  PRODUCER (Codex)       │   │ B  PRODUCER (Codex)         │        │
        │ injection / data-flow     │   │ logic / access-control      │        │
        │ sinks → sources, taint    │   │ IDOR, authz, auth bypass,   │        │
        │ sanitizer judgment        │   │ business logic              │        │
        └───────────────┬──────────┘   └─────────────┬──────────────┘        │
                        │  write_finding.py (file-locked, append-only)        │
                        └───────────────┬─────────────────────────────────────┘
                                        ▼
        ┌───────────────────────────────────────────────────────────────┐
        │ C  CONSUMER (Codex)   runs continuously while A & B produce      │
        │   cross-validate (CodeQL/OpenGrep) → reproduce live (probe.py     │
        │   sessions + SSRF canary) → web-search disclosure → PoC → triage  │
        └───────────────┬───────────────────────────────┬───────────────┘
                        │ repro fails → needs_reanalysis │ reproduced/confirmed
                        │   → back to A/B (feedback)      │ + critical class
                        │                                 ▼
                        │              ┌──────────────────────────────────┐
                        │              │ D  EXPLOITATION (Codex)            │
                        │              │ weaponize C's proven criticals:    │
                        │              │ chain & escalate, defeat sanitizers│
                        │              │ → exploit obj + report/<id>/exploit.py
                        │              └──────────────────┬───────────────┘
                        ▼                                 ▼
       workspace/report/report.md   +   report/<id>/{poc.py, finding.md, exploit.py}
```

## How it works

TaintForge runs one supervised **root Codex orchestrator** which owns four project-scoped
custom subagents. The subagents share `workspace/findings/` as a streaming producer-consumer
queue (watch the combined orchestration stream and queue state in the `start.sh` dashboard):

- **A — producer (injection / data-flow):** SQLi, command/code injection, XSS, SSRF, path
  traversal, file inclusion, deserialization, XXE, SSTI, NoSQL, open redirect. Enumerates
  sinks, traces backward to attacker-controlled sources, judges sanitizers.
- **B — producer (logic / access-control):** IDOR/BOLA, missing authorization, privilege
  escalation, auth/session bypass, business-logic flaws. The bugs SAST tools can't see.
- **C — consumer (convergence):** cross-validates statically, reproduces dynamically
  against a live instance (session-aware `probe.py`, out-of-band SSRF `canary.py`, and
  headless-browser XSS *execution* proof `browser_probe.py`), web-searches whether each
  reproduced bug is a known CVE or **novel (potential 0-day)**, writes a runnable `poc.py`
  per vuln, then triages/ranks — looping while A and B work.
- **D — exploitation:** takes only the genuinely critical findings C already proved
  (RCE, SQLi, command injection, auth bypass, deserialization, SSRF-to-internal) and pushes
  the PoC into a fully understood, weaponized exploit — chaining, escalating impact, and
  defeating sanitizers/quoting — recording the result (and an honest statement of any
  bounds) in the finding's `exploit` object plus a standalone `exploit.py`.

The stable role definitions live in `.codex/agents/*.toml`; `.codex/config.toml` enables four
concurrent child threads. The root orchestrator spawns A/B/C/D together, waits for them, and
continues a role with a follow-up task if it returns early. Because the root `codex exec` is
still finite, one shell supervisor respawns only the root until `MAX_HOURS` (default 12h) or
`workspace/_stop`. Durable state in `workspace/` lets rebuilt threads continue without losing
coverage, leads, or findings. `write_finding.py` remains file-locked, so concurrent subagents do
not corrupt the queue.

Status lifecycle of a finding:
```
candidate ──> cross_validated ──> reproduced ──> confirmed
                          │
               repro fails│── false_positive      (discarded)
                          └── needs_reanalysis     (feedback → producers)
```

**Depth over breadth — chaining, not just scanning.** Most real bugs in mature code aren't a
single obvious sink; they're a *chain* of individually-harmless steps (a raw reference here, a
missing check there, a reachable dangerous construct at the end) that only become a vulnerability
when combined — the kind of bug a human researcher finds by reading one parser/deserializer/
dispatcher line by line and asking, at each step, "if the attacker controls this, what does it
let me do next?". To make the agents work this way rather than one-pass scanning, there's a
deep-analysis notebook (`.agents/skills/_shared/leads.py`):

- a **lead** is an interesting-but-not-yet-a-bug observation (recorded with what it *enables*);
- a **primitive** is a confirmed capability built from leads;
- a **note** is the running state of a dig on one target (so a respawn continues, not restarts);
- linked leads form a **candidate chain** that C (convergence) and D (exploitation) try to
  realize into one chained vulnerability.

Coverage prioritizes deep-dive-worthy modules (parsers, deserializers, dispatchers, template/
reflection code) where such chains hide. A lead is never a finding by itself — but it's kept,
not discarded, because it may be the missing piece another session needs.

## The method every role is bound by

`.agents/skills/_shared/METHODOLOGY.md` is the class- and language-agnostic contract each role
reads after `AGENTS.md`. Four things it fixes that a sink-first scanner alone gets wrong:

- **Two shapes, not one.** A defect is either a *dangerous flow* (`defect_shape: "flow"`) or a
  *missing control* (`defect_shape: "missing_control"`). Tracks A and B are named after the
  shapes, not the classes — so a crypto, DoS, info-leak, misconfiguration, supply-chain,
  memory-safety, or TOCTOU bug always has an owner instead of falling between the two tracks.
- **Sources are more than request input.** Identity/authorization state, stored second-order
  values, post-free un-reset state, bailout-orphaned state, cross-request/worker state,
  uninitialized reuse, and ordering are all attacker influence — and the last five are
  invisible to every taint engine and to the call graph.
- **Seven mandatory passes.** Entry × privilege map, guard audit, invariant sweep, long-lived
  lifetime sweep, taint into *all seven* sink groups, error/exception-path diff, and
  cross-scope/concurrency topology. The last three have no tool support on purpose: they are
  read-the-code passes, and that is where the bugs the scanners left behind live.
- **Honest bounds, enforced.** `write_finding.py` refuses to mark a finding `confirmed` without
  its shape, its reachability (entry point + minimum privilege + pre-auth, proven by a call
  chain), its preconditions (default vs named non-default settings), and a proven escalation
  ceiling — and an observation made only under a sanitizer or patched build stays a lead until
  `repro.stock_replay` records a run on the stock build.

## Layout

```
taintforge/                         ← repo root (run from here)
  start.sh                          ← tmux launcher: orchestrator stream + dashboard
  audit.sh                          ← seed + supervised root orchestrator
  .codex/config.toml                ← enables/caps project subagent concurrency
  .codex/agents/*.toml              ← A/B/C/D custom-agent role definitions
  accounts.json[.example]           ← test accounts for dynamic auth/IDOR testing
  fix_skills.py                     ← repairs SKILL.md YAML frontmatter if Codex can't load
  AGENTS.md                         ← operating contract Codex reads first
  schemas/
    code_model.schema.json          ← contract: the Code Model
    finding.schema.json             ← contract: one finding (drives convergence)
  .agents/skills/                   ← Codex discovers skills here
    _shared/        METHODOLOGY.md (the method every role is bound by), write_finding.py (file-locked finding writer), budget_guard.py (token cap), leads.py (deep-analysis notebook: leads/primitives/chains)
    source-model/   build the Code Model (structural + comprehension); coverage.py, callgraph.py, proof_ledger.py
    hypothesize/    gen_hypotheses.py, catalog.json, cwe_to_hypotheses.py (business-logic hypotheses)
    vuln-track-a/   injection/data-flow finder; run_semgrep.sh leads, rules/
    vuln-track-b/   logic/access-control finder; build_authz_matrix.py
    convergence/    cross_validate.sh, correlate.py, probe.py (session/--jar),
                    canary.py (SSRF OOB), browser_probe.py, triage.py, emit_poc.py, queue.py, dashboard.py
  targets/                          ← code under assessment (read-only)
  workspace/
    CODE_MODEL.json                 ← structural + comprehension (graph-only on huge repos)
    HYPOTHESES.json                 ← business-logic hypotheses bound to entry points
    coverage.json                   ← module / contract list + analysis progress
    leads.json                      ← deep-analysis: leads, primitives, candidate chains
    _analysis_notes.json            ← per-target running dig notes (survive respawns)
    cm/<module>.json                ← per-module full Code Model (whitebox, huge-repo path work)
    hints/                          ← optional tool leads (not findings)
    findings/<id>.json              ← the queue; every finding authored by Codex
    report/report.md                ← rolling ranked index (incl. ⚠️ potential 0-day, 💥 weaponized)
    report/<id>/poc.py              ← per-vuln runnable PoC (reproduced/confirmed only)
    report/<id>/exploit.py          ← per-vuln weaponized exploit (agent D, critical only)
    report/<id>/finding.md          ← per-vuln individual report
    _accounts.json                  ← copied test accounts (live auth/IDOR)
    _canary.log                     ← SSRF out-of-band callback hits
    _pids                           ← root-supervisor/canary pids (stop handle)
    _stop                           ← touch this to stop root and all child threads
    _log_orchestrator.txt           ← combined root/subagent orchestration stream
```

## The Code Model

`source-model` builds `workspace/CODE_MODEL.json` once, reused by everything:
- **`structural`** (tool, ast + regex extractors): files, entry points, and a
  **call graph** (`caller -> callee` edges, including call sites of dangerous built-ins like
  `query`/`exec`/`system`/`unserialize`/`include`/`require`/`eval`/`file_get_contents`
  tagged `<builtin-sink>`). This is what lets the agents follow flows ACROSS files.
- **`comprehension`** (Codex): `service_identity`, `route_map`, `feature_flows`,
  `permission_model`, `user_journeys`, `trust_boundaries` — the understanding that logic-bug
  hunting (Track B) depends on.

`coverage.py` models a large codebase as a **hierarchical tree (directory → module → entry
point)** rather than a flat list (vendor/tests excluded; big dirs split via
`TF_SPLIT_THRESHOLD`/`TF_MAX_DEPTH`). Each module is annotated with the **entry points**
(routes/handlers) it exposes, pulled from the Code Model — so coverage tracks *reachable
attack surface*, not just files on disk. `--next` hands out pending modules **attack-surface
first** (those exposing routes before leaf libraries), `--tree` prints the tree with per-node
status, and `--summary` separately reports how much of the entry-point surface is analyzed.
This makes "100% coverage" mean "every reachable route was traced inward," not "every file
was skimmed."

Vulnerabilities live on **flows across files**, not single lines. The call graph is the map
both vuln tracks use to follow them, queried with `callgraph.py`:
```bash
python3 .agents/skills/source-model/scripts/callgraph.py --stats            # edge/sink counts
python3 .agents/skills/source-model/scripts/callgraph.py --callers <sink>   # who calls query/unserialize/include/...
python3 .agents/skills/source-model/scripts/callgraph.py --callees <file>   # what a handler calls
python3 .agents/skills/source-model/scripts/callgraph.py --trace   <sink>   # backward paths into a sink
```
- **Track A** anchors on a sink and traces **backward** to attacker-controlled input.
- **Track B** traces **entry point -> resource access** and checks whether an authz/ownership
  gate exists anywhere on the path (a resource load reachable with no ownership check = IDOR).
The graph is coarse: construct sinks used directly on input (`include $_GET[...]`, `eval`
of a request value) aren't edges, so the agents also read code. `call_edges` should be in
the thousands for a large app — `0` means the structural build failed.

## Deep analysis (chaining multi-step bugs)

Shallow scanning finds shallow bugs. The high-impact vulnerabilities in mature code are usually
a *chain*: several individually-safe behaviors that compose into an exploit (think of how
researchers chain a parser quirk → a missing `hasOwnProperty` → a reachable constructor into
RCE). No single line is "the sink", so a one-pass "find sink → judge" sweep can't see them.

TaintForge addresses this with three pieces:

1. **A deep-dive instruction** (in every producer's brief): on code that parses, deserializes,
   dispatches on a name, reflects, or walks user-controlled property paths, read it line by line
   and, at each step, ask "if the attacker controls this value, what does it enable next?" —
   then carry that capability forward instead of stopping at the first sink check.
2. **The leads notebook** (`.agents/skills/_shared/leads.py`): file-locked like `write_finding.py`.
   - `leads.py add` (kind `lead`) — an interesting observation that isn't a bug yet, with what
     it `enables`.
   - `leads.py add` (kind `primitive`) — a confirmed capability.
   - `leads.py note <target> --set "..."` — running state of a dig (understood / hold / next),
     so a respawned session continues digging instead of restarting.
   - `leads.py link <id> <id> ...` — record that several leads combine into a candidate chain.
   - `leads.py open` / `list` — what's still combinable.
3. **Deep-dive-first coverage**: `coverage.py --next` bumps modules whose names hint at parsing/
   deserialization/dispatch/templating/reflection, since that's where chains hide.

C (convergence) and D (exploitation) read the candidate chains and try to realize them end to
end into one chained finding. A lead is **never** a finding on its own and is **never** discarded
just for not being a bug yet — it may be the piece another session needs.

## Tooling (hints & cross-check only — never the author of a finding)

- **ast + regex extractors** — language-agnostic symbol/call-graph extraction for the Code Model (ast for python, regex for others; no required deps).
- **Semgrep / OpenGrep** — Track A leads + Track A-style cross-validation. OpenGrep is
  preferred: free for private code, restored cross-file taint, and a more stable core
  (Semgrep OSS can segfault on very large repos).
- **CodeQL** — deep cross-validation in convergence. Supports C/C++/C#/Go/Java/JS/TS/
  Python/Ruby/Swift/Rust — **not PHP**, so PHP targets auto-fall back to OpenGrep. Free only
  for OSI open-source / research; private code needs GitHub Advanced Security.

## Setup

```bash
cd <repo>
python3 -m venv .venv && . .venv/bin/activate
pip install jsonschema pyyaml
# OpenGrep (preferred SAST engine):
curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash
export PATH="$HOME/.opengrep/cli/latest:$PATH"
# vendor community rules (once, online):
.agents/skills/vuln-track-a/scripts/fetch_rules.sh
chmod +x audit.sh fix_skills.py .agents/skills/*/scripts/*.{sh,py}
```

If Codex logs `failed to load skill ... YAML frontmatter`, run `python3 fix_skills.py`.

## Run

```bash
./start.sh -u http://localhost:8080 targets/<app>     # tmux dashboard (recommended)
./start.sh targets/<app>                              # static only, with dashboard
```

`start.sh` opens a **tmux live view** with the combined A/B/C/D orchestration stream and a
dashboard pane (coverage bar, findings by status/class, novel + 💥 exploit counters, latest
hits, elapsed time). Detach with `Ctrl-b` then `d`; re-attach with
`tmux attach -t taintforge`. Stop everything with
`touch workspace/_stop; kill $(cat workspace/_pids); tmux kill-session -t taintforge`.
If tmux isn't installed, `start.sh` falls back to a plain headless run.

Headless / no-tmux (logs go to `workspace/_log_orchestrator.txt`):
```bash
./audit.sh -u http://localhost:8080 targets/<app>
./audit.sh --url http://host --accounts creds.json targets/<app>
```

Pass `-u/--url` when the target is **running** somewhere — the C subagent (and producers)
then send real requests to confirm findings dynamically. Test accounts go in
`accounts.json` at the repo root (or `--accounts <file>`): a JSON array of
`{username, password}` (see `accounts.json.example`). Codex works out the login/session
flow from the code itself and, for IDOR/authz, replays one user's request with another's
session. Without `--url`, findings that need a live server are marked `needs_reanalysis`
rather than guessed. Accounts are copied to `workspace/_accounts.json`; requests only ever
go to the URL you pass.

Runs with `--sandbox workspace-write` (writes `workspace/`, `targets/` stays read-only).
Four child threads plus the lightweight root orchestrator consume more tokens than a single
agent. Network and live web search are enabled only in the C/D agent TOMLs; A/B remain scoped to
repository and workspace analysis.

The root orchestrator auto-respawns until `MAX_HOURS` (default 12) or `workspace/_stop`; it
continues returned role threads while alive. To run longer, raise `MAX_HOURS=24`. State in
`workspace/` persists across runs, so replacement threads resume instead of starting over.

### Watch progress

With `start.sh` the dashboard pane shows this live. Headless? In a separate shell:

```bash
tail -f workspace/_log_orchestrator.txt                        # root + child activity
python3 .agents/skills/convergence/scripts/queue.py --counts   # queue by status
python3 .agents/skills/source-model/scripts/coverage.py --summary
ls workspace/findings | wc -l
```

## Dynamic reproduction (live target)

When you pass `-u/--url`, the convergence session proves findings against the running app:

- **`probe.py`** is **session-aware**: `--jar FILE` persists cookies across calls, so the
  agent can log in (it works out the login route/CSRF/cookie from the code itself) and then
  hit protected resources with that session. `--no-redirect` exposes `Location`; the JSON
  result surfaces `status`, `set_cookie`, `cookies`, timing, and a body snippet.
- **IDOR/authz** is proven by replaying **two identities**: log alice and bob into separate
  jars, then request bob's object with alice's jar — a `200` with bob's data confirms it.
  This needs ≥2 normal accounts in `accounts.json` (admin alone can't prove cross-user access).
- **XSS** is proven by **execution**, not reflection: `browser_probe.py` opens the payload
  URL in headless Chromium (Playwright) and reports `executed:true` only when a dialog fires
  or an injected marker runs (`--jar` injects a session for stored/authed XSS).
- **SSRF / blind** uses **`canary.py`**, an out-of-band HTTP listener auto-started on `--url`
  (`127.0.0.1:9111`). The agent makes the target fetch `http://<canary>/<token>`, then
  `canary.py check <token>` — a HIT proves SSRF. Internal/blind SSRF without a callback is
  judged by response/timing differences against internal hosts.

## Disclosure: known CVE vs novel 0-day

Once a finding is **reproduced/confirmed**, C web-searches the product+version+vuln against
CVE/NVD, vendor and GitHub advisories, and changelogs, then sets `disclosure.status`:
`known` (with CVE/refs), `novel` (no public report — **potential 0-day**), or `inconclusive`.
Novel reproduced findings are surfaced in a **⚠️ Potential 0-day** section at the top of the
report and counted on the dashboard. (Requires `--config web_search=live`.)

## Per-vulnerability PoC + report

For every reproduced/confirmed finding, the agent writes a `poc.py` tailored to that bug
(using `requests`; pre-auth bugs have no login step, multi-step flows have as many requests
as needed, with a clear PASS/FAIL). `emit_poc.py` then materializes one folder per vuln:
```
workspace/report/<id>/poc.py        # standalone, re-run with: python3 poc.py
workspace/report/<id>/finding.md    # that vuln's individual report
```
Per-vuln reports are kept separate (never merged); `report.md` stays as the ranked index.
The dashboard regenerates `report.md` and the per-vuln folders every few seconds, so they're
never stale.

## Weaponized exploitation (agent D)

For the genuinely critical reproduced findings (RCE, SQLi, command injection, auth bypass,
deserialization, SSRF-to-internal), agent **D** goes beyond a proof-of-concept: starting from
the proven primitive it chains and escalates to the highest real impact, and where a
sanitizer/escape/quoting blocks the obvious payload it analyzes exactly what survives and
finds a working bypass — verifying each step against the live target (or, with no live
target, against the code plus a local shell model of the sink). The result is recorded in the
finding's **`exploit`** object — `{depth: shallow|chained|weaponized, primitive, max_impact,
steps, mitigations_bypassed, constraints, oob_evidence}` — and materialized as a standalone
`workspace/report/<id>/exploit.py`, separate from C's `poc.py`. D records **honest bounds**:
if the impact is limited (e.g. only argument-less single-token commands run), it says so
precisely rather than overstating. D and its outputs are for assets you own or are authorized
to test — it never targets a host it wasn't pointed at.



- **The agent finds; tools assist.** Every finding is authored by Codex via
  `write_finding.py`. Semgrep/OpenGrep/CodeQL only hand it leads or cross-checks — a SAST
  hit is a place to look, not a finding.
- **Separate the model from the hunt.** `source-model` builds reusable facts once; the
  vuln tracks apply judgment on top.
- **Sink-first, flow-aware.** Anchor on the finite sink set and reason backward across
  files using the call graph — a sink safe in its own file is often fed tainted input
  several calls away. Track B mirrors this for entry-point -> resource access paths.
- **Streaming, parallel, self-driving.** A and B produce concurrently; C consumes live; the
  root orchestrator keeps all four specialized subagent threads moving.
- **Exhaustive.** Every module, every sink/route: find a bug or justify why it's safe.
- **Reproduction is the strongest evidence.** A finding becomes `confirmed` only when fired
  against a live instance; failures feed back for re-analysis.
- **Append-only, file-locked findings** with stable ids and `history` — safe for four
  concurrent role threads and fully auditable.
