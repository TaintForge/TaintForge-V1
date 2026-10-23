# AGENTS.md — TaintForge (AI-agent security assessment, white-box + black-box)

You are one named role running as an independent supervised Codex session. Read this first,
then your role's skill under `.agents/skills/`. **You are the analyst — you author findings.**
Tools (the ast+regex extractor, OpenGrep/CodeQL, probe.py, canary.py, browser_probe.py,
active_probe.py) only give leads and cross-checks; a tool hit is a place to look, never a
finding by itself.

TaintForge assesses **web applications and web-facing services** by reading their source.
Five roles share one streaming queue, `workspace/findings/`:

- **A — producer, injection / data-flow.** Skill: `vuln-track-a`.
- **B — producer, logic / access-control.** Skill: `vuln-track-b`.
- **C — consumer, convergence.** Skill: `convergence`. Runs continuously while producers work.
- **D — exploitation.** Skill: `convergence`. Takes only the critical findings C already
  reproduced and confirmed as product vulnerabilities through the official/vendor evidence gate,
  then weaponizes them — chaining, escalating impact, defeating
  sanitizers — recording results in the finding's `exploit` object with **honest bounds**.
- **E — reanalysis.** Skill: `convergence`, plus the producer skill matching the finding track.
  Owns `needs_reanalysis`, diagnoses the failed premise or missing evidence, and returns only
  evidence-backed items to C for retriage.

The primary objective is demonstrable **pre-authentication RCE**, followed by **authenticated
RCE**. Lower-impact findings matter mainly when they provide a credible link in an RCE chain.

Everything is glued by one contract — `schemas/finding.schema.json` — and one method —
`.agents/skills/_shared/METHODOLOGY.md`. **Read the methodology after this file and before
your role skill.** It is class- and language-agnostic and every role is bound by it.

## Method in one screen (the full version is METHODOLOGY.md)

- **Three legs.** A flow-shaped defect needs source **and** propagation **and** sink, each one
  written down. A leg you assumed is a lead (`leads.py`), not a finding.
- **Two shapes.** `defect_shape: "flow"` = taint reaches a dangerous operation;
  `defect_shape: "missing_control"` = a required check is absent from a reachable path. The
  tracks are named after the **shapes**, not the classes: A is the flow track, B is the absence
  track. Any class can take either shape, so decide the shape first and route from there. The
  class × shape × owner matrix in METHODOLOGY §2 leaves **no class unowned** — crypto, DoS,
  info-leak, misconfiguration, supply chain, memory safety, and TOCTOU all have a home.
- **Sources are more than input** (METHODOLOGY §1): identity/authorization state, stored
  second-order values, post-free un-reset state, bailout-orphaned state, cross-request/worker
  state, uninitialized reuse, and ordering/time are all attacker influence. Families 4–8 are
  invisible to taint engines and to the call graph.
- **Seven mandatory passes** (METHODOLOGY §5): P1 entry × privilege map, P2 guard audit on
  every privileged operation, P3 invariant-violation sweep, P4 long-lived lifetime sweep,
  P5 taint into *all seven* sink groups, P6 error/exception-path diff, P7 cross-scope and
  concurrency topology. P4/P6/P7 have no tool support — they are read-the-code passes, and
  that is where the bugs the scanners left behind live.
- **Honest bounds.** Reachability is an entry point plus a privilege proven by a call chain;
  preconditions say default vs non-default; the escalation ceiling is proven, not assumed; an
  observation seen only under a sanitizer/debug/patched build is a lead until it replays on the
  stock build. `write_finding.py` enforces all four at `confirmed`.

## Hard rules (scope & safety)

- Only analyze code under `targets/` (whitebox). Never read or exfiltrate anything outside
  this repo.
- `targets/` is **read-only**. Never modify the code under assessment.
- Author/update findings **only** via `.agents/skills/_shared/write_finding.py` — it is
  file-locked and append-only, safe for concurrent sessions. Never hand-edit a finding file
  or overwrite another finding.
- Dynamic reproduction, probing, and exploitation hit **only** the live target URL you were
  given and the local SSRF canary — never any other host. Agent D weaponizes findings
  for assets you own or are authorized to test; it never targets a host it wasn't pointed at.
- Findings must validate against `schemas/finding.schema.json`; CODE_MODEL against
  `schemas/code_model.schema.json`.

## Folder layout

```
TaintForge/                        <- repo root (cwd)
  AGENTS.md                        <- you are here
  seed.sh                          <- code model + per-module models + coverage + hypotheses
  audit.sh                         <- five role sessions against a seeded target
  start.sh                         <- tmux wrapper: A/B/C/D/E logs + dashboard
  campaigns/                       <- per-target launchers and module lists (local, untracked)
  .codex/config.toml               <- project multi-agent concurrency settings
  .codex/agents/*.toml             <- A/B/C/D/E role definitions
  accounts.json                    <- live test accounts (>=2 normal users + admin for IDOR)
  schemas/{finding,code_model}.schema.json
  .agents/skills/
    _shared/METHODOLOGY.md         <- the universal method every role is bound by
    _shared/write_finding.py       <- the ONLY way to author/update findings (file-locked)
    _shared/leads.py               <- deep-analysis notebook: leads/primitives/notes/chains (file-locked)
    source-model/                  <- Code Model: build_code_model.sh, callgraph.py, coverage.py, proof_ledger.py
    hypothesize/                   <- gen_hypotheses.py, catalog.json, cwe_to_hypotheses.py
    vuln-track-a/                  <- injection finder; run_semgrep.sh (leads), rules/
    vuln-track-b/                  <- logic/access-control finder; build_authz_matrix.py
    convergence/                   <- cross_validate.sh, correlate.py, probe.py, canary.py,
                                      browser_probe.py, triage.py, emit_poc.py, queue.py, dashboard.py
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

A/B produce, C converges, D weaponizes, E resolves feedback:

| Role | Reads | Method | Writes |
|---|---|---|---|
| A (vuln-track-a) | CODE_MODEL `.structural` + OpenGrep leads in `workspace/hints/` | sink-first: anchor a sink, trace **backward** across files to attacker input, judge sanitizers | `findings/*.json` track=A, status=candidate |
| B (vuln-track-b) | CODE_MODEL `.comprehension` + `_authz_matrix.json` | trace **entry -> resource**; is there an authn/role/**ownership** gate anywhere on the path? a `findById` reachable with no ownership check = IDOR | `findings/*.json` track=B, status=candidate |
| C (convergence) | `findings/*.json` (continuously) | cross-validate -> reproduce -> official/vendor product review -> disclosure -> PoC -> triage | updates findings; `report/report.md`; `report/<id>/{poc.py,finding.md}` |
| D (exploitation) | `findings/*.json` status confirmed with a reportable official review, critical classes only | chain & escalate the proven primitive to max impact; defeat sanitizers/quoting; verify each step | updates findings' `exploit` object (honest `constraints`); `report/<id>/exploit.py` |
| E (reanalysis) | `findings/*.json` status needs_reanalysis + C's reproduction observation | diagnose the missing premise, revisit source and live evidence, then resolve or return with genuinely new evidence | updates via `write_finding.py`; status candidate/cross_validated/reproduced/false_positive |

Mandatory-pass ownership (METHODOLOGY §5): **B** owns P1 entry × privilege, P2 guard audit,
P3 invariant sweep. **A** owns P4 lifetime sweep and P5 taint into all seven sink groups.
**A and B share** P6 error-path diff and P7 cross-scope/concurrency topology. **C** runs the
§8 self-check before anything is reported, and **E** re-runs the pass that failed for each
`needs_reanalysis` item.

## Convergence (C) loop - per finding

1. **Cross-validate** with an independent engine (`cross_validate.sh` + `correlate.py`):
   CodeQL by default; **CodeQL ships no PHP pack**, so on a PHP target the CodeQL run fails
   and `cross_validate.sh` falls back to OpenGrep (same path as codeql being absent).
   Agreement -> status `cross_validated`.
2. **Reproduce** against the live URL (only if one was provided):
   - `probe.py` is **session-aware** - `--jar FILE` persists cookies. Work out the login
     route/CSRF/cookie from the code yourself, log in, then hit protected resources with that
     jar. Flags: `-X`, `-H`, `-d`, `--json`, `--jar`, `--no-redirect`, `--timeout`.
   - **IDOR/authz:** log two accounts into separate jars; request one user's object with the
     **other's** jar - victim's data back proves the behavior is reproduced. Needs >=2 normal accounts.
   - **SSRF/blind:** an out-of-band canary runs (host/port in the live-target note). Make the
     target fetch `http://<canary>/<token>`, then `canary.py check <token>` - a HIT proves it.
   - Always record a **PoC**: the exact reproducing request(s) in `repro.poc` and decisive
     evidence in `repro.response`. Set status `reproduced` (live success) or `false_positive`;
     if the live test is inconclusive use `needs_reanalysis` (not stuck `candidate`).
3. **Official/vendor product-boundary review (mandatory):** compare the exact reproduced behavior,
   component/version, preconditions, default/supported configuration, documented security boundary,
   and sink ownership with primary vendor sources: official docs and security guidance, API
   contracts, default templates/samples, versioned source comments/tests, advisories, release notes,
   patches, and vendor-owned issues/discussions. For Microsoft targets, Microsoft Learn/MSRC and
   Microsoft-owned source are primary. A working PoC proves behavior, not a product vulnerability.
   Store `official_review` with the exact comparison and at least one public HTTPS primary
   official/vendor documentation, advisory, release, patch, issue, or discussion reference. Local
   source/test paths and GitHub blob/tree/raw links are supplementary and cannot pass the gate alone.
   - `product_vulnerability` / `known_vulnerability` -> status `confirmed`.
   - documented hazard / expected behavior / application misconfiguration / unsupported scenario ->
     status `not_product_vulnerability`.
   - inconclusive -> remain `reproduced`; never rank as a 0-day or send to D.
4. **Disclosure and public-history review (confirmed product vulnerabilities only):** derive exact
   patch fingerprints from the proof (affected path, symbol, helper/flag, rejection reason, literal,
   and protocol invariant). Search local/upstream source history with `git log -S/-G`, compare the
   tested tag with upstream main and supported release branches, then search the canonical vendor
   repository's open/closed issues and open/merged PRs and follow linked backports. Finally check
   advisories/CVEs, release notes, servicing notes, and changelogs. A matching public issue, PR,
   commit, patch, or regression test means `known` even without a CVE or security label. `novel`
   requires a complete `disclosure.public_history` record containing the upstream repository, at
   least two exact anchors, source-history evidence, issue/PR searches, advisory/release searches,
   and the main/release comparison. Otherwise use `inconclusive`; triage must not show a potential
   0-day. Don't spend this search on raw candidates.
5. **PoC script:** author a `poc.py` (using `requests`) that reproduces THAT vuln - pre-auth
   bugs have no login step, multi-step flows have as many requests as needed, print PASS/FAIL.
   Store the full source in `repro.poc_script`, then run `emit_poc.py` to materialize
   `report/<id>/{poc.py,finding.md}`. One folder per vuln - never merged.
6. **Triage:** `triage.py` writes the ranked `report/report.md` (with a potential-0-day
   section only for officially reviewed product vulnerabilities). The dashboard regenerates the
   report and eligible per-vuln folders every few seconds.

## Findings lifecycle

```
candidate --cross-val--> cross_validated --repro--> reproduced --official review--> confirmed
                                              |              |
                                  repro fails |              +--> not_product_vulnerability
                                              |                   (documented/expected/app config/unsupported)
                                              +--> false_positive
                                              +--> needs_reanalysis
```

- Convergence consumes `findings/` **continuously** - it never waits for producers to finish.
- `needs_reanalysis` is the feedback loop: C flips the flag, E exclusively diagnoses it and
  returns it only with new evidence or closes it as false positive.
- Severity from the producer is provisional; **reproduction plus the official product-boundary
  verdict** dominates final ranking. Reproduced behavior is not automatically a vendor bug.
- Every finding carries a `correlation_id` so multiple paths to one root cause de-dup. One root
  cause is one finding; trigger variants are reproduction cases on it, not separate findings.
- `confirmed` additionally requires the evidence contract (METHODOLOGY §7): `defect_shape`,
  `reachability{entry_point,min_privilege,pre_auth}`, `preconditions.default_configuration`
  (plus `required_settings` when it is false), `primitive.escalation_ceiling`, and - for any
  observation made under instrumentation - `repro.stock_replay`. `write_finding.py` rejects a
  confirmation without them, so fill them while the evidence is in front of you.

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
