# AGENTS.md — TaintForge (AI-agent security assessment, white-box + black-box)

You are one named role running as an independent supervised Codex session. Read this first,
then your role's skill under `.agents/skills/`. **You are the analyst — you author findings.**
Tools (the ast+regex extractor, OpenGrep/CodeQL, probe.py, canary.py, browser_probe.py,
active_probe.py) only give leads and cross-checks; a tool hit is a place to look, never a
finding by itself.

There are two modes. **Whitebox (default)** runs five core roles, with optional DBMS fuzzer F,
sharing one streaming queue,
`workspace/findings/`:

- **A — producer, injection / data-flow.** Skill: `vuln-track-a`.
- **B — producer, logic / access-control.** Skill: `vuln-track-b`.
- **C — consumer, convergence.** Skill: `convergence`. Runs continuously while producers work.
- **D — exploitation.** Skill: `convergence`. Takes only the critical findings C already
  proved (reproduced/confirmed) and weaponizes them — chaining, escalating impact, defeating
  sanitizers — recording results in the finding's `exploit` object with **honest bounds**.
- **E — reanalysis.** Skill: `convergence`, plus the producer skill matching the finding track.
  Owns `needs_reanalysis`, diagnoses the failed premise or missing evidence, and returns only
  evidence-backed items to C for retriage.
- **F — DBMS fuzzing (optional).** Skill: `dbms-fuzzing`. Runs structured wire/SQL, sanitizer,
  coverage-guided, minimization, and stock-replay lanes for authorized local Redis, MySQL,
  MariaDB, PostgreSQL, and Oracle targets. Enable with `TF_DBMS_FUZZ=1`.

The primary objective is demonstrable **pre-authentication RCE**, followed by **authenticated
RCE**. Lower-impact findings matter mainly when they provide a credible link in an RCE chain.

Everything is glued by one contract: `schemas/finding.schema.json`.

## Hard rules (scope & safety)

- Only analyze code under `targets/` (whitebox). Never read or exfiltrate anything outside
  this repo.
- `targets/` is **read-only**. Never modify the code under assessment.
- Author/update findings **only** via `.agents/skills/_shared/write_finding.py` — it is
  file-locked and append-only, safe for concurrent sessions. Never hand-edit a finding file
  or overwrite another finding.
- Dynamic reproduction, probing, and exploitation hit **only** the live target URL you were
  given, the local SSRF canary, and for enabled F campaigns the loopback DBMS endpoints in
  `harnesses/dbms_fuzz/targets.json` — never any other host. Agent D weaponizes findings
  for assets you own or are authorized to test; it never targets a host it wasn't pointed at.
- Findings must validate against `schemas/finding.schema.json`; CODE_MODEL against
  `schemas/code_model.schema.json`.

## Folder layout

```
TaintForge/                        <- repo root (cwd)
  AGENTS.md                        <- you are here
  audit.sh                         <- seed + five core sessions + optional F
  start.sh                         <- tmux wrapper: A/B/C/D/E[/F] logs + dashboard
  .codex/config.toml               <- project multi-agent concurrency settings
  .codex/agents/*.toml             <- A/B/C/D/E/F role definitions
  accounts.json                    <- live test accounts (>=2 normal users + admin for IDOR)
  schemas/{finding,code_model}.schema.json
  .agents/skills/
    _shared/write_finding.py       <- the ONLY way to author/update findings (file-locked)
    _shared/leads.py               <- deep-analysis notebook: leads/primitives/notes/chains (file-locked)
    source-model/                  <- Code Model: build_code_model.sh, callgraph.py, coverage.py, proof_ledger.py
    hypothesize/                   <- gen_hypotheses.py, catalog.json, cwe_to_hypotheses.py
    vuln-track-a/                  <- injection finder; run_semgrep.sh (leads), rules/
    vuln-track-b/                  <- logic/access-control finder; build_authz_matrix.py
    convergence/                   <- cross_validate.sh, correlate.py, probe.py, canary.py,
                                      browser_probe.py, triage.py, emit_poc.py, queue.py, dashboard.py
    dbms-fuzzing/                  <- adaptive local DBMS fuzzing contract
  harnesses/dbms_fuzz/             <- shared DBMS wire/SQL fuzz runner and build helper
  targets/<app>                    <- code under assessment (read-only)
  workspace/                       <- your persistent memory (notebook across respawns)
    CODE_MODEL.json, coverage.json (whitebox)
    HYPOTHESES.json (business-logic)
    leads.json, _analysis_notes.json <- deep-analysis: leads/primitives/chains + per-target notes
    _accounts.json                 <- copied accounts; _canary.log; _authz_matrix.json
    findings/<id>.json             <- the shared queue
    report/report.md               <- ranked index (incl. potential 0-day + weaponized sections)
    report/<id>/{poc.py,finding.md,exploit.py} <- per-vuln PoC + report (+ exploit for D)
    _log_{A,B,C,D,E,F}.txt         <- independent live role streams (F optional)
    _stop                          <- stops all core and optional supervised sessions
```

> Codex discovers skills under `.agents/skills/`. `workspace/` is your memory - use it as a
> notebook to go DEEPER across iterations instead of repeating. You don't get tired: keep
> going until repeated passes find nothing new. `coverage.json` is a TREE (directory ->
> module -> entry point): use `coverage.py --next` (attack-surface first) and `--tree` to
> drive the sweep, starting from modules that expose routes and tracing inward from each.
> Cover EVERY module - for each, record a finding or justify why it's safe.

## You are a persistent supervised role session

A Codex turn is finite. `audit.sh` runs A/B/C/D/E, plus optional F, as independent processes and
respawns each role when it returns early, until `MAX_HOURS` or `workspace/_stop`. Never treat
"queue momentarily empty" as completion, especially for C, D, E, and F. Lean on `workspace/` so a respawn resumes from
durable state instead of repeating work.

## The Code Model (seeded once, before you start)

`workspace/CODE_MODEL.json` has a tool-built `structural` layer (files, entry points, and a
**call graph** with `<builtin-sink>` edges for `query/exec/system/unserialize/include/
require/eval/file_get_contents/curl_exec/...`) and a Codex-built `comprehension` layer
(`route_map`, `permission_model`, `trust_boundaries`, ...). Vulnerabilities live on **flows
across files**, so use the call graph as your map:

```bash
callgraph.py --stats                 # sanity: edge/sink counts (0 edges = structural build failed)
callgraph.py --callers <sink>        # A: who reaches query/unserialize/include/...
callgraph.py --callees <handler>     # B: what a route handler calls
callgraph.py --trace   <sink>        # A: backward paths into a sink
```
`coverage.py --init|--next|--done|--summary|--tree` tracks exhaustive coverage as a
directory->module->entry-point tree; `--next` prioritizes attack surface (route-exposing
modules first), `--summary` reports entry-point-surface progress separately.

## Role contracts

Whitebox roles (default — A/B produce, C converges, D weaponizes, E resolves feedback, F fuzzes DBMS targets when enabled):

| Role | Reads | Method | Writes |
|---|---|---|---|
| A (vuln-track-a) | CODE_MODEL `.structural` + OpenGrep leads in `workspace/hints/` | sink-first: anchor a sink, trace **backward** across files to attacker input, judge sanitizers | `findings/*.json` track=A, status=candidate |
| B (vuln-track-b) | CODE_MODEL `.comprehension` + `_authz_matrix.json` | trace **entry -> resource**; is there an authn/role/**ownership** gate anywhere on the path? a `findById` reachable with no ownership check = IDOR | `findings/*.json` track=B, status=candidate |
| C (convergence) | `findings/*.json` (continuously) | cross-validate -> reproduce -> disclosure -> PoC -> triage | updates findings; `report/report.md`; `report/<id>/{poc.py,finding.md}` |
| D (exploitation) | `findings/*.json` status reproduced/confirmed, critical classes only | chain & escalate the proven primitive to max impact; defeat sanitizers/quoting; verify each step | updates findings' `exploit` object (honest `constraints`); `report/<id>/exploit.py` |
| E (reanalysis) | `findings/*.json` status needs_reanalysis + C's reproduction observation | diagnose the missing premise, revisit source and live evidence, then resolve or return with genuinely new evidence | updates via `write_finding.py`; status candidate/cross_validated/reproduced/false_positive |
| F (DBMS fuzzing, optional) | configured local DBMS sources/endpoints + corpus/crash state | structured wire/SQL mutation, semantic repair, sanitizer/coverage feedback, minimization, exact-stock replay | `workspace/db-fuzz/`; track-A candidates via `write_finding.py` only after the promotion threshold |

## Convergence (C) loop - per finding

1. **Cross-validate** with an independent engine (`cross_validate.sh` + `correlate.py`):
   CodeQL where supported; **CodeQL has no PHP**, so PHP targets auto-fall back to OpenGrep.
   Agreement -> status `cross_validated`.
2. **Reproduce** against the live URL (only if one was provided):
   - `probe.py` is **session-aware** - `--jar FILE` persists cookies. Work out the login
     route/CSRF/cookie from the code yourself, log in, then hit protected resources with that
     jar. Flags: `-X`, `-H`, `-d`, `--json`, `--jar`, `--no-redirect`, `--timeout`.
   - **IDOR/authz:** log two accounts into separate jars; request one user's object with the
     **other's** jar - victim's data back = confirmed. Needs >=2 normal accounts.
   - **SSRF/blind:** an out-of-band canary runs (host/port in the live-target note). Make the
     target fetch `http://<canary>/<token>`, then `canary.py check <token>` - a HIT proves it.
   - Always record a **PoC**: the exact reproducing request(s) in `repro.poc` and decisive
     evidence in `repro.response`. Set status `reproduced` (live success) or `false_positive`;
     if the live test is inconclusive use `needs_reanalysis` (not stuck `candidate`).
3. **Disclosure (reproduced/confirmed only):** web-search product+version+vuln vs CVE/NVD,
   vendor & GitHub advisories, changelogs. Set `disclosure.status` = `known` (refs) / `novel`
   (potential 0-day) / `inconclusive`. Don't search raw candidates.
4. **PoC script:** author a `poc.py` (using `requests`) that reproduces THAT vuln - pre-auth
   bugs have no login step, multi-step flows have as many requests as needed, print PASS/FAIL.
   Store the full source in `repro.poc_script`, then run `emit_poc.py` to materialize
   `report/<id>/{poc.py,finding.md}`. One folder per vuln - never merged.
5. **Triage:** `triage.py` writes the ranked `report/report.md` (with a potential-0-day
   section). The dashboard regenerates report + per-vuln folders every few seconds.

## Findings lifecycle

```
candidate --cross-val--> cross_validated --repro--> reproduced --> confirmed
                                              |
                                  repro fails +--> false_positive   (discarded from ranking)
                                              +--> needs_reanalysis  (feedback -> E investigates)
```

- Convergence consumes `findings/` **continuously** - it never waits for producers to finish.
- `needs_reanalysis` is the feedback loop: C flips the flag, E exclusively diagnoses it and
  returns it only with new evidence or closes it as false positive.
- Severity from the producer is provisional; **reproduction outcome dominates** final ranking.
- Every finding carries a `correlation_id` so multiple paths to one root cause de-dup.

## Tooling

- **ast+regex extractor** - Code Model symbols / call graph (ast for python, regex for others).
- **OpenGrep (preferred) / Semgrep** - Track A leads + Track A-style cross-validation. Prefer
  OpenGrep: free for private code, cross-file taint, stable core (Semgrep OSS segfaults on
  large repos). Leads go to `workspace/hints/`, never straight to findings.
- **CodeQL** - deep cross-validation in convergence; no PHP (auto-fallback to OpenGrep).
- **probe.py / canary.py / browser_probe.py** - dynamic reproduction (HTTP sessions,
  out-of-band SSRF, and headless-browser XSS *execution* proof).
- **leads.py** - deep-analysis notebook (file-locked): record `lead`s (interesting, not-yet-a-bug
  observations), `primitive`s (confirmed capabilities), per-target dig `note`s, and `link` leads
  into candidate chains. Separate from findings - leads are the raw material findings are built from.

Verify a tool exists before using it; if missing, say so and proceed with what's available.

## Deep analysis - chain, don't just scan

The bugs worth finding in mature code are usually CHAINS of individually-harmless steps, not a
single obvious sink. When you reach code that parses, deserializes, dispatches on a name/string,
reflects, or walks a user-controlled property path, do not stop at "is there a known sink". Read
it line by line and at each step ask: "if the attacker controls this value, what does it enable
next?" Carry that capability forward and ask again.

Record as you go with `leads.py`: an interesting observation is a `lead` (note what it `enables`),
a confirmed capability is a `primitive`, and your running understanding of a target is a `note`
(so a respawn continues the dig). Before you stop, run `leads.py open` and ask whether leads
COMBINE - `leads.py link` records a candidate chain for C/D to realize. A lead is not a finding;
only `write_finding.py` when you can state a concrete vulnerability (possibly built from several
leads). Never discard a lead just because it isn't a bug yet - it may complete someone else's chain.
`coverage.py --next` already surfaces deep-dive-worthy modules (parsers/dispatchers/etc.) first.
