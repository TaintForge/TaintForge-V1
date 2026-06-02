# TaintForge

**An AI-agent white-box security assessment pipeline.** TaintForge points autonomous
Codex sessions at a codebase and lets them hunt vulnerabilities the way a human auditor
would — reading code, reasoning about data flow and access control, then proving findings
against a live instance.

The model (Codex) is the analyst. Tools are its hands. Deterministic work — parsing, SAST
hints, ranking — is done by scripts; judgment — application understanding, taint reasoning,
sanitizer calls, logic/IDOR bugs, PoC crafting — is done by the agent. One contract glues
them together: the *finding* schema.

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
        │   cross-validate (CodeQL/OpenGrep) → reproduce (live) → triage   │
        └───────────────┬───────────────────────────────────────────────┘
                        │ repro fails → needs_reanalysis → back to A/B (feedback)
                        ▼
              workspace/report/report.md
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
  against a live instance, triages and ranks into a report — looping while A and B work.

Each session is **one long, self-driving session** — it reads code, finds, records, and
digs deeper on its own. The shell never re-invokes an agent per module (which would reset
its memory). `write_finding.py` is file-locked, so the three sessions never corrupt the
same finding. A and B produce concurrently; C consumes as findings appear; failed
reproductions route back as `needs_reanalysis` (the feedback loop).

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
    convergence/    cross_validate.sh, correlate.py, probe.py, triage.py, queue.py, dashboard.py
  targets/                          ← code under assessment (read-only)
  workspace/
    CODE_MODEL.json                 ← structural + comprehension
    coverage.json                   ← module list / analysis progress
    hints/                          ← optional tool leads (not findings)
    findings/<id>.json              ← the queue; every finding authored by Codex
    report/report.md                ← the deliverable
    _log_{A,B,C}.txt                ← per-session reasoning logs
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
  (Semgrep OSS segfaults on large repos like ConcreteCMS).
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
Stop everything: `kill $(cat workspace/_pids); tmux kill-session -t taintforge`. If tmux
isn't installed, `start.sh` falls back to a plain headless run.

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
Three concurrent sessions ≈ 3× tokens. Override the agent command with `CODEX_CMD`:
```bash
CODEX_CMD="codex exec --sandbox workspace-write --model gpt-5.5" ./audit.sh -u http://localhost:8080 targets/<app>
```

To run longer or continue, re-run `./audit.sh` — state in `workspace/` persists, so the
agents pick up and dig deeper. Ctrl-C stops all three sessions.

### Watch progress

With `start.sh` the dashboard pane shows this live. Headless? In a separate shell:

```bash
tail -f workspace/_log_B.txt                                   # a session's reasoning
python3 .agents/skills/convergence/scripts/queue.py --counts   # queue by status
python3 .agents/skills/source-model/scripts/coverage.py --summary
ls workspace/findings | wc -l
```

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