# TaintForge — Detailed Documentation

This document explains every component and every workflow in depth. For a quick start, see
[README.md](README.md). Terms used throughout:

- **Agent / session** — one autonomous `codex exec` process (the LLM doing the hunting).
- **Producer** — a session that *creates* findings (Track A, Track B).
- **Consumer** — the convergence session (C) that *validates/reproduces/reports*.
- **Finding** — one candidate vulnerability, stored as `workspace/findings/<id>.json`,
  conforming to `schemas/finding.schema.json`. This JSON contract is the spine of the system.
- **Seed** — deterministic, no-LLM preprocessing that produces the Code Model and coverage map.

---

## 1. Architecture in one paragraph

TaintForge seeds a structural model of the target (tree-sitter call graph + module split),
then runs **three Codex sessions in parallel**. Two are producers — **A** hunts injection /
data-flow bugs, **B** hunts logic / access-control bugs — and they stream findings into a
shared, file-locked queue (`workspace/findings/`). The third session, **C** (convergence),
continuously consumes that queue: it cross-validates each finding with an independent engine,
reproduces it against a live instance, web-searches whether it is a known CVE or a novel
0-day, writes a runnable PoC, and ranks everything into a report. Each session is supervised
at the shell level so it **auto-respawns** if it exits, keeping the pipeline alive for hours.
The agent is always the analyst that authors findings; tools only provide leads and
cross-checks.

---

## 2. The finding contract (`schemas/finding.schema.json`)

Everything flows through this one object. Key fields:

| field | who writes | meaning |
|---|---|---|
| `id` | producer | stable unique id |
| `track` | producer | `A` or `B` |
| `vuln_class`, `cwe` | producer | e.g. `sql-injection`, `CWE-89` |
| `severity_estimate` | producer | critical/high/medium/low/info |
| `source`, `sink` | producer | `{file,line}` of attacker input and dangerous operation |
| `evidence` | producer | why the agent believes it's vulnerable (taint path, missing gate) |
| `status` | producer→C | lifecycle (below) |
| `correlation_id` | C | groups duplicates across tracks/engines |
| `repro` | C | `{attempted, success, poc, response, observation, env, poc_script}` |
| `disclosure` | C | `{checked, status: known\|novel\|inconclusive, references[], rationale}` |
| `history` | all | append-only audit trail |

**Status lifecycle**

```
candidate ──> cross_validated ──> reproduced ──> confirmed
                          │
               repro fails│── false_positive      (discarded from ranking)
                          └── needs_reanalysis     (handed back to producers)
```

- `candidate` — a producer recorded it; not yet checked by C.
- `cross_validated` — an independent engine (CodeQL/OpenGrep) agrees the pattern exists.
- `reproduced` — fired successfully against the live target (the strongest evidence).
- `confirmed` — reproduced **and** fully triaged (final).
- `false_positive` — disproven; excluded from the report ranking.
- `needs_reanalysis` — couldn't confirm; routed back as feedback so producers dig again.

---

## 3. The Code Model (`source-model` skill)

Built **once** by the seed stage, reused by every session: `workspace/CODE_MODEL.json`.

### 3.1 `build_code_model.py` / `build_code_model.sh` (structural, tool)
Uses **tree-sitter** (with a regex backstop) to extract:
- `files`, `entry_points`
- a **call graph**: `caller -> callee` edges. PHP node types
  (`function_call_expression`, `member_call_expression`, `scoped_call_expression`) and
  definitions are handled, plus **built-in sink edges** — calls to dangerous primitives
  (`query`, `exec`, `system`, `unserialize`, `include`, `require`, `eval`,
  `file_get_contents`, `curl_exec`, …) are tagged with `to: "<builtin-sink>"`.

Output lives under `structural.call_graph`. On a large app `call_edges` is in the thousands
(ConcreteCMS ≈ 73k, Craft ≈ 22k). **`call_edges: 0` means the structural build failed** —
check tree-sitter install. The graph is *coarse*: a sink used directly on input
(`include $_GET['x']`) is not an edge, so agents always read code too.

### 3.2 `callgraph.py` (query the graph)
```bash
callgraph.py --stats                 # edge + builtin-sink counts (sanity check)
callgraph.py --callers <symbol>      # who calls query/unserialize/include/...  (Track A entry)
callgraph.py --callees <file>        # what a route handler calls               (Track B entry)
callgraph.py --trace   <symbol>      # backward paths into a sink
callgraph.py --depth N               # bound trace/callees depth
callgraph.py --model PATH            # use a non-default CODE_MODEL.json
```
- **Track A** uses `--callers <sink>` then `--trace` to walk **backward** to a source.
- **Track B** uses `--callees <handler>` to follow **entry → resource access** and look for
  a missing authz/ownership gate.

### 3.3 `comprehension` (Codex-authored)
The agent fills application understanding into the Code Model: `service_identity`,
`route_map`, `feature_flows`, `permission_model`, `user_journeys`, `trust_boundaries`.
Track B depends heavily on this (you can't reason about "missing authorization" without
knowing the permission model and routes).

### 3.4 `coverage.py` (exhaustiveness)
Splits the codebase into **modules** so agents cover everything in bounded chunks instead of
skimming once. Vendor/tests excluded; oversized dirs split.
```bash
coverage.py --init <target>   # build the module list -> workspace/coverage.json
coverage.py --next            # claim the next unanalyzed module
coverage.py --done <module>   # mark a module analyzed
coverage.py --list            # list modules + status
coverage.py --summary         # progress (the dashboard's coverage bar)
```

---

## 4. Producer A — injection / data-flow (`vuln-track-a` skill)

**Goal:** SQLi, command/code injection, XSS, SSRF, path traversal, file inclusion,
deserialization, XXE, SSTI, NoSQL, open redirect.

**Method (sink-first, flow-aware):**
1. Enumerate the finite set of dangerous sinks via `callgraph.py --callers` and the
   `<builtin-sink>` edges.
2. For each sink, trace **backward** across files (`--trace`) to see whether
   attacker-controlled input reaches it.
3. Judge sanitization/escaping along the path — a sink that's safe in its own file is often
   fed tainted data several calls away.
4. Record a finding via `write_finding.py` (track A) or justify why the sink is safe.

**Tool leads (not findings):** `run_semgrep.sh` runs OpenGrep (preferred) or Semgrep over the
target and writes **LEADS** to `workspace/hints/` via `semgrep_to_hints.py`. A SAST hit is a
*place to look*, never a finding — the agent decides. Rules live in `vuln-track-a/rules/`
(`injection.yaml`, `web.yaml`); `fetch_rules.sh` vendors community rules once (online).

`run_semgrep.sh` runs with `--jobs 1 --max-target-bytes 500000 --timeout 20` and excludes
`vendor`/minified JS to avoid the Semgrep-OSS segfault on large repos.

---

## 5. Producer B — logic / access-control (`vuln-track-b` skill)

**Goal:** the bugs SAST can't see — IDOR/BOLA, missing authorization, privilege escalation,
auth/session bypass, business-logic flaws (step-skipping, price/quantity tampering, mass
assignment, race conditions).

**Method (path from entry point to resource):**
1. `build_authz_matrix.py` produces a deterministic **seed**: routes/actions vs. the authz
   checks visible on them → `workspace/_authz_matrix.json`.
2. For each route/action, follow `handler → service → repository/object-load` with
   `callgraph.py --callees`, asking along the **whole chain**: is there an authn check, a
   role/permission check, and an **ownership/tenant** check on the requested object id?
3. A `findById/load/getByID` reachable from a route with **no ownership check** on the path
   is IDOR. A missing role check on a state-changing action is broken authz.
4. Record (track B) or set `needs_reanalysis` with reasoning if neither code nor a live test
   can confirm.

---

## 6. Consumer C — convergence (`convergence` skill)

C runs continuously while A/B produce. Its loop:

### 6.1 Cross-validate (`cross_validate.sh`, `correlate.py`)
Runs an **independent** engine to see if a finding's pattern is corroborated:
- **CodeQL** for supported languages (C/C++, C#, Go, Java, JS/TS, Python, Ruby, Swift, Rust).
- **CodeQL does not support PHP**, so PHP targets (Craft, Concrete) **auto-fall back to
  OpenGrep**. `correlate.py` matches engine output to findings and bumps agreeing ones to
  `cross_validated`.

### 6.2 Reproduce dynamically (`probe.py`, `canary.py`) — only with `-u/--url`
`probe.py` is the request tool. It is **session-aware**:
```bash
probe.py -X GET  "$URL/path" --jar a.jar            # GET with saved session
probe.py -X POST "$URL/login" -d 'u=..&p=..' --jar a.jar   # login, cookies saved to a.jar
probe.py -X POST "$URL/api" --json '{"k":1}' --jar a.jar    # JSON body
probe.py -X GET  "$URL/path" --jar a.jar --no-redirect      # don't follow 3xx; see Location
```
Flags: `-X/--method`, `-H/--header` (repeatable), `-d/--data`, `--json`, `--jar FILE`
(cookie jar = session memory), `--no-redirect`, `--timeout`. The JSON result exposes
`status`, `ms`, `final_url`, `location`, `set_cookie`, `cookies` (jar contents), and a body
`snippet`.

- **Track A reproduction:** fire the crafted payload; confirm the sink triggers (error,
  reflected payload, time delay, OOB hit).
- **Track B / IDOR reproduction:** log two accounts into separate jars, then request one
  user's object with the **other's** jar. A `200` with the victim's data = confirmed. This
  is why `accounts.json` needs **≥2 normal users** — admin alone can't prove cross-user
  access.

`canary.py` is the **out-of-band server** for SSRF/blind bugs, auto-started on `--url`
(default `127.0.0.1:9111`, logging to `workspace/_canary.log`):
```bash
canary.py serve --port 9111 --log workspace/_canary.log   # listener (audit.sh starts this)
canary.py url   <token> --host H --port N                 # the URL to embed in a payload
canary.py check <token>                                   # HIT = SSRF confirmed out-of-band
```
The agent makes the target fetch `http://<canary>/<token>` through the vulnerable parameter,
then `canary.py check <token>`; a HIT proves SSRF. Blind/internal SSRF without a callback is
judged by response/timing differences against internal hosts (127.0.0.1:<port>,
169.254.169.254).

### 6.3 Disclosure — known vs novel (`web_search`)
For findings that reach **reproduced/confirmed only**, C web-searches product+version+vuln
against CVE/NVD, vendor and GitHub advisories, and changelogs, and sets `disclosure`:
- `known` → matches a published CVE/advisory (ids/URLs go in `references`)
- `novel` → no public report for this exact issue → **potential 0-day**
- `inconclusive` → can't tell

Requires `--config web_search=live`. Candidates are **not** searched (no wasted queries).

### 6.4 PoC + per-vuln report (`emit_poc.py`)
For each reproduced/confirmed finding the agent authors a `poc.py` using `requests`, tailored
to the bug (pre-auth → no login; multi-step → as many requests as needed; prints PASS/FAIL),
and stores its full source in `repro.poc_script`. `emit_poc.py` then writes, per vuln:
```
workspace/report/<id>/poc.py        # saved verbatim; re-run with: python3 poc.py
workspace/report/<id>/finding.md    # that vuln's individual report
```
It does **not** invent or parse PoC steps — the agent's script is saved as-is. If a finding
lacks `poc_script`, a stub `poc.py` is written so the folder is never empty.

### 6.5 Triage + report (`triage.py`, `queue.py`)
`triage.py` reads all findings, de-dups by `correlation_id`, ranks by
severity × confidence(status), maps CWE → OWASP Top 10, and writes
`workspace/report/report.md`:
- a **⚠️ Potential 0-day** section at the top (reproduced findings with `disclosure=novel`),
- a ranked table with a `disclosure` column,
- per-finding details including the PoC commands and response evidence.
It surfaces unreadable finding files instead of silently dropping them.

`queue.py` is the machine-readable queue view:
```bash
queue.py --counts       # findings by status
queue.py --pending      # count still needing convergence work
queue.py --reanalysis   # ones routed back to producers
queue.py --findings DIR # non-default findings dir
```

### 6.6 Live dashboard (`dashboard.py`)
The 4th tmux pane. Every ~3s it: regenerates `report.md` (via `triage.py`) and the per-vuln
folders (via `emit_poc.py`) so they're never stale, then renders coverage bar, findings by
status/class, a **novel/0-day counter**, latest hits, and elapsed time.

---

## 7. The shared writer (`_shared/write_finding.py`)

The single way findings are created/updated, used by A, B, and C. It is **file-locked**
(`fcntl`) and **append-only**, so three concurrent sessions never corrupt the same file.
```bash
write_finding.py --file f.json                 # create from a finding JSON
write_finding.py --update <id> --file patch.json   # merge an update (status, repro, disclosure...)
write_finding.py --out DIR --schema schemas/finding.schema.json
```
Updates merge into `history` for a full audit trail. It validates against the finding schema.

---

## 8. Orchestration (`audit.sh`, `start.sh`)

### 8.1 `audit.sh` — the engine
```bash
./audit.sh [-u|--url URL] [--accounts FILE] targets/<app>
```
Steps it performs:
1. **Seed** (no LLM): `build_code_model.sh` → `CODE_MODEL.json`; `coverage.py --init` →
   `coverage.json`.
2. If `--url`: copy accounts to `workspace/_accounts.json`, start `canary.py serve` in the
   background, and build the live-target instructions (`DYN`).
3. Build the three mission strings (A/B/C) and launch each under a **supervisor**:
   ```
   supervise(){ ( while no _stop and now < DEADLINE; do
                    $CODEX_CMD "$MISSION"; sleep 5;   # respawn on exit
                 done ) </dev/null >/dev/null 2>&1 & echo $!; }
   ```
   The fds are detached so backgrounded supervisors don't hold the parent shell open.
4. Write supervisor pids to `workspace/_pids`.
5. `SPAWN_ONLY=1` → return immediately (used by `start.sh`); otherwise `wait` on the
   supervisors.

Env knobs: `CODEX_CMD` (default `codex exec --sandbox workspace-write`), `MAX_HOURS`
(default 12), `CANARY_HOST`/`CANARY_PORT` (default `127.0.0.1:9111`), `SPAWN_ONLY`.

**Why supervisors?** A `codex exec` session is finite — it ends when the agent thinks it's
done or hits a token limit. For a streaming consumer that's fatal (C "completes" and dies
while findings still arrive). The supervisor respawns it until the deadline or `_stop`.

### 8.2 `start.sh` — the tmux wrapper
Calls `SPAWN_ONLY=1 audit.sh` (fds detached so it returns immediately), then builds a tmux
window with **four panes whose labels are bound to pane ids** (so the `tiled` layout can't
scramble them). The detached session is created large (`-x 250 -y 60`) so the 4th pane isn't
dropped by minimum-size limits.
```
🅐 INJECT (A)   |  🅑 LOGIC (B)
🅒 CONVERGE (C) |  📊 DASHBOARD
```
Detach: `Ctrl-b` then `d` (sessions keep running). Re-attach: `tmux attach -t taintforge`.

---

## 9. End-to-end workflow

```
1. SEED        build_code_model.sh + coverage.py --init      (deterministic, ~seconds–minutes)
2. SPAWN       audit.sh launches A, B, C under supervisors; canary.py if --url
3. PRODUCE     A (sink→source taint) and B (entry→resource authz) stream findings
                 → write_finding.py → workspace/findings/<id>.json  [status: candidate]
4. CONVERGE    C loops:
                 a. cross_validate.sh + correlate.py     → cross_validated
                 b. probe.py (--jar sessions) / canary.py → reproduced  (live PoC)
                 c. web_search disclosure                 → known | novel(0-day)
                 d. agent writes poc.py → repro.poc_script
                 e. emit_poc.py  → report/<id>/{poc.py, finding.md}
                 f. triage.py    → report/report.md (ranked, 0-day section)
5. FEEDBACK    repro fails → needs_reanalysis → producers revisit
6. RESPAWN     any session exits → supervisor restarts it (until MAX_HOURS / _stop)
7. STOP        touch workspace/_stop; kill $(cat workspace/_pids); pkill -f 'codex exec'
```

### Example: IDOR confirmed end-to-end
1. **B** follows `AssetsController::actionGetAsset → Asset::find(id)` and sees no ownership
   check on the path → records candidate (track B, CWE-639).
2. **C** cross-validates, then reproduces: logs alice and bob into `alice.jar`/`bob.jar`,
   requests bob's `assetId` with `alice.jar`, gets `200` + bob's filename → `reproduced`,
   `repro.success=true`.
3. **C** web-searches "Craft CMS \<version\> asset IDOR CVE"; finds nothing for this exact
   endpoint → `disclosure=novel`.
4. **C** writes a `requests`-based `poc.py` (login alice → GET bob's asset → assert leak),
   stored in `repro.poc_script`.
5. `emit_poc.py` writes `report/<id>/poc.py` + `finding.md`; `triage.py` lists it under
   **⚠️ Potential 0-day**.

---

## 10. Running it

### Setup
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install jsonschema tree-sitter-language-pack pyyaml requests
curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash
export PATH="$HOME/.opengrep/cli/latest:$PATH"
.agents/skills/vuln-track-a/scripts/fetch_rules.sh        # once, online
chmod +x audit.sh start.sh fix_skills.py .agents/skills/*/scripts/*.{sh,py}
```

### Accounts (`accounts.json`)
A JSON array of `{username, password}`. For IDOR/authz reproduction include **at least two
normal users plus an admin**, e.g.:
```json
[
  {"username":"admin","password":"..."},
  {"username":"alice","password":"..."},
  {"username":"bob","password":"..."}
]
```

### Full run (live target, network + web search on)
```bash
CODEX_CMD="codex exec --sandbox workspace-write \
  --config sandbox_workspace_write.network_access=true \
  --config web_search=live" \
  ./start.sh -u http://127.0.0.1:32778 targets/craftcms
```
- `network_access=true` — without it live probes fail with `Operation not permitted`.
- `web_search=live` — without it the known-vs-novel (0-day) step can't run.
- `MAX_HOURS=24 ...` — run longer.

### Watch / stop
```bash
# dashboard pane shows it live; headless:
tail -f workspace/_log_C.txt
python3 .agents/skills/convergence/scripts/queue.py --counts
cat workspace/report/report.md
ls workspace/report/*/        # per-vuln poc.py + finding.md

# stop EVERYTHING (flag first or supervisors respawn):
touch workspace/_stop
kill $(cat workspace/_pids) 2>/dev/null
pkill -f "codex exec"; pkill -f "canary.py"; pkill -f "dashboard.py"
tmux kill-session -t taintforge 2>/dev/null
```

---

## 11. Troubleshooting

| symptom | cause | fix |
|---|---|---|
| `call_edges: 0` | tree-sitter build failed | install `tree-sitter-language-pack`; re-seed |
| probe: `Operation not permitted` | sandbox network off | add `--config sandbox_workspace_write.network_access=true` |
| disclosure never set | web search off | add `--config web_search=live` |
| IDOR stuck at candidate | only 1 account (no victim to compare) | add ≥2 normal users to `accounts.json` |
| C "completes" and stops | a `codex exec` session is finite | supervisors respawn it; ensure latest `audit.sh` |
| stuck at `launching...`, no tmux | backgrounded supervisors held the shell's fds | latest `audit.sh`/`start.sh` detach fds (`</dev/null >…`) |
| tmux shows 3 panes, no C | detached session too small | latest `start.sh` creates it `-x 250 -y 60` |
| pane labels don't match contents | `tiled` renumbered panes | latest `start.sh` binds labels to pane ids |
| report shows 0 while findings exist | stale `report.md` | dashboard regenerates it each cycle; or run `triage.py` |
| killed codex keeps coming back | `_stop` not set | `touch workspace/_stop` **before** killing |
| `failed to load skill … YAML frontmatter` | bad SKILL.md frontmatter | `python3 fix_skills.py` |
| Semgrep segfault on large repo | Semgrep OSS core | use OpenGrep (preferred) |
| CodeQL ignores PHP | CodeQL has no PHP support | automatic OpenGrep fallback |

---

## 12. Design principles (why it's built this way)

- **The agent finds; tools assist.** Every finding is authored by Codex via
  `write_finding.py`. SAST/CodeQL only hand it leads or cross-checks.
- **Separate the model from the hunt.** `source-model` builds reusable facts once; the vuln
  tracks apply judgment on top.
- **Sink-first, flow-aware.** Anchor on the finite sink set, reason backward across files via
  the call graph. Track B mirrors this for entry→resource paths.
- **Streaming, parallel, self-driving, supervised.** A and B produce concurrently; C consumes
  live; each is one long autonomous session, respawned by a shell supervisor so the pipeline
  survives finite sessions.
- **Exhaustive.** Every module, every sink/route: find a bug or justify why it's safe.
- **Reproduction is the strongest evidence.** A finding becomes `confirmed` only when fired
  against a live instance; failures feed back as `needs_reanalysis`.
- **Novelty matters.** Reproduced bugs are checked against public CVEs so true 0-days surface.
- **Append-only, file-locked findings** with stable ids and `history` — safe for concurrent
  sessions and fully auditable.