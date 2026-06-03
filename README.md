# TaintForge

**An AI-agent white-box security assessment pipeline.** TaintForge points autonomous
Codex sessions at a codebase and lets them hunt vulnerabilities the way a human auditor
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
        │ SEED (no LLM)   tree-sitter structural model + module split   │
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
        └───────────────┬───────────────────────────────────────────────┘
                        │ repro fails → needs_reanalysis → back to A/B (feedback)
                        ▼
       workspace/report/report.md   +   report/<id>/{poc.py, finding.md}
```

## How it works

TaintForge runs as **three parallel autonomous Codex sessions** that share the findings
queue (`workspace/findings/`) — a streaming producer-consumer (watch them live in the
`start.sh` tmux dashboard):

- **A — producer (injection / data-flow):** SQLi, command/code injection, XSS, SSRF, path
  traversal, file inclusion, deserialization, XXE, SSTI, NoSQL, open redirect. Enumerates
  sinks, traces backward to attacker-controlled sources, judges sanitizers.
- **B — producer (logic / access-control):** IDOR/BOLA, missing authorization, privilege
  escalation, auth/session bypass, business-logic flaws. The bugs SAST tools can't see.
- **C — consumer (convergence):** cross-validates statically, reproduces dynamically
  against a live instance (session-aware `probe.py` + out-of-band SSRF `canary.py`),
  web-searches whether each reproduced bug is a known CVE or **novel (potential 0-day)**,
  writes a runnable `poc.py` per vuln, then triages/ranks — looping while A and B work.

Each session is **one long, self-driving session** — it reads code, finds, records, and
digs deeper on its own. The shell never re-invokes an agent per module (which would reset
its memory). But a `codex exec` session is finite — it ends when the agent decides it's
done or hits a token limit — so each role runs under a **shell supervisor that respawns it**
on exit until a deadline (`MAX_HOURS`, default 12h) or a `workspace/_stop` flag. That's what
keeps C alive to consume findings that arrive late. `write_finding.py` is file-locked, so
the three sessions never corrupt the same finding. A and B produce concurrently; C consumes
as findings appear; failed reproductions route back as `needs_reanalysis` (feedback loop).

Status lifecycle of a finding:
```
candidate ──> cross_validated ──> reproduced ──> confirmed
                          │
               repro fails│── false_positive      (discarded)
                          └── needs_reanalysis     (feedback → producers)
```

## Layout

```
taintforge/                         ← repo root (run from here)
  start.sh                          ← tmux launcher: 4-pane live dashboard (A | B | C | stats)
  audit.sh                          ← engine: seeds + spawns the 3 parallel sessions
  accounts.json[.example]           ← test accounts for dynamic auth/IDOR testing
  fix_skills.py                     ← repairs SKILL.md YAML frontmatter if Codex can't load
  AGENTS.md                         ← operating contract Codex reads first
  schemas/
    code_model.schema.json          ← contract: the Code Model
    finding.schema.json             ← contract: one finding (drives convergence)
  .agents/skills/                   ← Codex discovers skills here
    _shared/        write_finding.py (file-locked finding writer, used by A, B and C)
    source-model/   build the Code Model (structural + comprehension); coverage.py, callgraph.py
    vuln-track-a/   injection/data-flow finder; run_semgrep.sh leads, rules/
    vuln-track-b/   logic/access-control finder; build_authz_matrix.py
    convergence/    cross_validate.sh, correlate.py, probe.py (session/--jar),
                    canary.py (SSRF OOB), triage.py, emit_poc.py, queue.py, dashboard.py
  targets/                          ← code under assessment (read-only)
  workspace/
    CODE_MODEL.json                 ← structural + comprehension
    coverage.json                   ← module list / analysis progress
    hints/                          ← optional tool leads (not findings)
    findings/<id>.json              ← the queue; every finding authored by Codex
    report/report.md                ← rolling ranked index (incl. ⚠️ potential 0-day section)
    report/<id>/poc.py              ← per-vuln runnable PoC (reproduced/confirmed only)
    report/<id>/finding.md          ← per-vuln individual report
    _accounts.json                  ← copied test accounts (live auth/IDOR)
    _canary.log                     ← SSRF out-of-band callback hits
    _pids                           ← supervisor pids (stop handle)
    _stop                           ← touch this to stop all supervisors
    _log_{A,B,C}.txt                ← per-session reasoning logs (appended across respawns)
```

## The Code Model

`source-model` builds `workspace/CODE_MODEL.json` once, reused by everything:
- **`structural`** (tool, tree-sitter + regex backstop): files, entry points, and a
  **call graph** (`caller -> callee` edges, including call sites of dangerous built-ins like
  `query`/`exec`/`system`/`unserialize`/`include`/`require`/`eval`/`file_get_contents`
  tagged `<builtin-sink>`). This is what lets the agents follow flows ACROSS files.
- **`comprehension`** (Codex): `service_identity`, `route_map`, `feature_flows`,
  `permission_model`, `user_journeys`, `trust_boundaries` — the understanding that logic-bug
  hunting (Track B) depends on.

`coverage.py` splits a large codebase into **modules** (vendor/tests excluded; big dirs
split) so the agents cover everything in bounded chunks rather than skimming once.

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

## Tooling (hints & cross-check only — never the author of a finding)

- **tree-sitter** — language-agnostic AST / call graph for the Code Model.
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
pip install jsonschema tree-sitter-language-pack pyyaml
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

`start.sh` opens a **tmux 4-pane live view** — 🅐 inject | 🅑 logic | 🅒 converge and a
dashboard pane (coverage bar, findings by status/class, latest hits, elapsed time). Detach
with `Ctrl-b` then `d` (sessions keep running); re-attach with `tmux attach -t taintforge`.
Stop everything (the `_stop` flag must come first, or supervisors respawn):
`touch workspace/_stop; kill $(cat workspace/_pids); pkill -f 'codex exec'; tmux kill-session -t taintforge`.
If tmux isn't installed, `start.sh` falls back to a plain headless run.

Headless / no-tmux (logs go to `workspace/_log_{A,B,C}.txt`):
```bash
./audit.sh -u http://localhost:8080 targets/<app>
./audit.sh --url http://host --accounts creds.json targets/<app>
```

Pass `-u/--url` when the target is **running** somewhere — the C session (and producers)
then send real requests to confirm findings dynamically. Test accounts go in
`accounts.json` at the repo root (or `--accounts <file>`): a JSON array of
`{username, password}` (see `accounts.json.example`). Codex works out the login/session
flow from the code itself and, for IDOR/authz, replays one user's request with another's
session. Without `--url`, findings that need a live server are marked `needs_reanalysis`
rather than guessed. Accounts are copied to `workspace/_accounts.json`; requests only ever
go to the URL you pass.

Runs with `--sandbox workspace-write` (writes `workspace/`, `targets/` stays read-only).
Three concurrent sessions ≈ 3× tokens. Dynamic reproduction and disclosure search need the
sandbox's **network** and **web search** enabled, so use a `CODEX_CMD` like:
```bash
CODEX_CMD="codex exec --sandbox workspace-write \
  --config sandbox_workspace_write.network_access=true \
  --config web_search=live" \
  ./start.sh -u http://localhost:8080 targets/<app>
```
Without `network_access` the live probes fail with `Operation not permitted`; without
`web_search` the known-vs-novel (0-day) classification can't run.

Sessions auto-respawn until `MAX_HOURS` (default 12) or `workspace/_stop`. To run longer,
raise `MAX_HOURS=24`. State in `workspace/` persists across runs, so agents dig deeper.

### Watch progress

With `start.sh` the dashboard pane shows this live. Headless? In a separate shell:

```bash
tail -f workspace/_log_B.txt                                   # a session's reasoning
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

## Design principles

- **The agent finds; tools assist.** Every finding is authored by Codex via
  `write_finding.py`. Semgrep/OpenGrep/CodeQL only hand it leads or cross-checks — a SAST
  hit is a place to look, not a finding.
- **Separate the model from the hunt.** `source-model` builds reusable facts once; the
  vuln tracks apply judgment on top.
- **Sink-first, flow-aware.** Anchor on the finite sink set and reason backward across
  files using the call graph — a sink safe in its own file is often fed tainted input
  several calls away. Track B mirrors this for entry-point -> resource access paths.
- **Streaming, parallel, self-driving.** A and B produce concurrently; C consumes live;
  each is one long autonomous session, not a shell loop re-spawning a memory-less agent.
- **Exhaustive.** Every module, every sink/route: find a bug or justify why it's safe.
- **Reproduction is the strongest evidence.** A finding becomes `confirmed` only when fired
  against a live instance; failures feed back for re-analysis.
- **Append-only, file-locked findings** with stable ids and `history` — safe for the three
  concurrent sessions and fully auditable.