---
name: convergence
description: "Consume candidate findings and confirm them - cross-validate statically, reproduce dynamically, then compare the behavior with primary official/vendor documentation before confirming and reporting it. Runs continuously alongside the vuln tracks (streaming), not after they finish. Drives the finding status lifecycle and the reproduction feedback loop. Triggers - triage, reproduce, PoC, confirm finding, cross-validate, deduplicate, report, rank vulnerabilities."
---

# convergence (consumer / streaming)

Consumes `workspace/findings/*.json` and pushes each through cross-validation ->
reproduction -> official/vendor product review -> disclosure -> triage, updating its `status`. Runs **continuously** while the producer
tracks stream findings - don't wait for them to finish. Process highest-severity
candidates first.

Status lifecycle (see schemas/finding.schema.json):
```
candidate --2a--> cross_validated --2b--> reproduced --official review--> confirmed
                                     |              |
                          repro fails|              +--> not_product_vulnerability
                                     |                   (documented/expected/app config/unsupported)
                                     +--> false_positive
                                     +--> needs_reanalysis
```

## 2a - Cross-validation (deep static, Track A)

```bash
.agents/skills/convergence/scripts/cross_validate.sh targets/<app> [language]
```
Always uses CodeQL (deepest interprocedural/cross-file taint). Falls back to OpenGrep
only if CodeQL is missing or fails, so cross-validation never silently skips. Override
with `ENGINE=opengrep`. It then runs `correlate.py`, which bumps any candidate whose sink
the engine also flags to `status: cross_validated` (history entry added) - automatic, no
manual matching. NOTE: CodeQL is free only for OSI open-source / research; private code
needs GitHub Advanced Security. (Track B logic findings skip 2a; reproduction proves behavior,
and the official/vendor gate decides whether it is a product vulnerability.)

## 2b - Reproduction (dynamic - the strongest evidence)

Use the **warm target env** (start it once per session; never an external host). For each
candidate craft a PoC and fire it with the probe:

probe.py keeps a SESSION via a cookie jar (--jar FILE), so you can log in and then hit a
protected/owned resource with that identity. YOU find the login route/body from the code;
probe just remembers cookies.
```bash
# log in as each account into its own jar (find the real login route/fields yourself)
probe.py -X POST "$URL/<login>" -d '<login body, csrf if needed>' --jar alice.jar
probe.py -X POST "$URL/<login>" -d '<...>'                        --jar bob.jar
```
- **Track A (injection):** fire the crafted payload; confirm the sink triggers (error,
  reflected payload, time delay, out-of-band). Use --no-redirect to inspect Location.
- **Track B (logic/IDOR/authz):** with alice's jar, request BOB's object/action:
  `probe.py -X GET "$URL/<bobs-object>" --jar alice.jar`. If alice gets bob's data (200 +
  owned content) -> IDOR confirmed. For priv-esc, hit an admin-only action with a
  low-priv jar. Two identities, real sessions - that is the proof.

- **XSS:** reflecting a payload in the HTTP body is NOT proof - prove EXECUTION in a real
  browser with `.agents/skills/convergence/scripts/browser_probe.py --url "<url-with-payload>"`
  (add `--jar a.jar` for stored/authenticated XSS; cookies from the jar are injected). It
  reports `executed:true` when a dialog fires or an injected marker (`window.__tf_xss`) ran.
  Use a payload that signals execution, e.g. `<script>alert(1)</script>` or
  `<img src=x onerror=window.__tf_xss=1>`. Only `executed:true` counts as reproduced.
- **SSRF / blind (OOB):** an out-of-band canary runs (see the live-target note for host/port).
  Make the target fetch `http://<canary>/<uniqueToken>` through the vulnerable parameter,
  then `.agents/skills/convergence/scripts/canary.py check <uniqueToken>` - a HIT proves it.
  For internal/blind SSRF without callback, compare responses to internal hosts
  (127.0.0.1:<port>, 169.254.169.254). Don't leave SSRF as untried - either fire the canary
  or, if no callback is possible, mark needs_reanalysis with the reason.

ALWAYS attach a PoC: put the EXACT reproducing command(s) into repro.poc (the full
probe.py/curl line with method, URL, headers, --jar, and payload - copy-pasteable), and the
decisive response evidence into repro.response. For IDOR include BOTH identities' requests
(victim's session hitting the other user's object). No PoC = not reproduced.

Record outcome in the finding's `repro` field and update status:
```bash
echo '<updated finding json with repro{} and status>' \
  | .agents/skills/_shared/write_finding.py --update <id>
```
- triggered -> `reproduced`. Reproduction proves the behavior only; **never** jump directly
  to `confirmed` before the official/vendor product-boundary review below passes.
- safe -> `false_positive` with reasoning.
- ambiguous / PoC likely wrong -> `needs_reanalysis` (FEEDBACK LOOP): the producing track
  re-picks it up. Append a `history` entry saying why.

## 2b-product - Official/vendor product-boundary review (mandatory)

Every `reproduced` finding must be compared with primary official/vendor material before it
can be called a product vulnerability. For Microsoft/.NET targets, search Microsoft Learn,
MSRC advisories, the exact version's API contracts, default templates and samples, versioned
source comments/tests, release notes and patches, and Microsoft-owned repository issues or
discussions. For other products use the equivalent vendor-owned sources. Third-party research
may lead the search but cannot replace primary evidence.

Compare the **exact behavior and preconditions**, not just keywords:

- exact product/component/version and whether it is supported;
- default/vendor-generated configuration versus an application-authored unsafe configuration;
- the documented security boundary, API contract, middleware ordering, and stated caller duties;
- whether the decisive security sink belongs to the product or was added only by the PoC app;
- versioned source tests, patches, release notes, and advisories that show intended behavior.

Before calling the behavior new, derive patch fingerprints from the proof: affected file path,
class/method, helper or validation flag, rejection reason/error string, distinctive literal, and the
protocol invariant being violated. Search those anchors independently; vulnerability-title searches
alone are insufficient. For a Git target, inspect local history with both `git log -S'<literal>' --
<path>` and `git log -G'<semantic-regex>' -- <path>`. If the checkout is shallow, use the canonical
vendor repository's commit history/API for the same path. Compare the tested tag against current
upstream main and every applicable supported release branch. A hardening diff is a disclosure lead
even when its commit message never says security, vulnerability, CVE, bypass, or smuggling.

A successful request, auth bypass observation, crash, or process spawn does not by itself prove a
vendor product vulnerability. For example, if official documentation explicitly warns that the
exact middleware ordering is unsafe and gives the required secure order, classify the result as
`documented_hazard`; do not call the configured sample a novel framework vulnerability. Likewise,
an app-defined command sink does not turn documented framework behavior into framework RCE.
Conversely, absence of documentation alone is not proof: identify the supported security invariant
that the reproduced behavior violates.

Write `official_review{checked,verdict,sources,rationale,product_version,default_configuration}`
through `write_finding.py`. `sources` must contain at least one public HTTPS URL to primary
official/vendor documentation, security guidance/advisory, release/patch material, or a
vendor-owned repository issue/discussion. Local/versioned vendor source paths may supplement that
URL but cannot satisfy the gate alone. A GitHub `blob`, `tree`, or raw source-file URL is also
only source evidence and cannot satisfy this documentation gate by itself. `rationale` must compare the official material directly
with the PoC and state what security invariant is violated or why the behavior is not a product bug.
Map the result exactly:

- `product_vulnerability` or `known_vulnerability` -> set status `confirmed`;
- `documented_hazard`, `expected_behavior`, `application_misconfiguration`, or
  `unsupported_scenario` -> set status `not_product_vulnerability`;
- `inconclusive` -> remain `reproduced`, record what evidence is missing, and keep the item in
  the official-review queue. It is not reportable, rankable as a 0-day, or eligible for D.

The writer rejects `confirmed` and `not_product_vulnerability` updates without successful dynamic
reproduction and exact PoC/response evidence, or whose official review is missing or inconsistent
with the status.

## 2b-evidence - The evidence contract (enforced at `confirmed`)

Reproduction and the official review say the behavior is real and is the vendor's. The
evidence contract (METHODOLOGY §7) says what the behavior actually *is* for a reader. Fill it
in the same `--update` that sets `confirmed`; `write_finding.py` rejects the update otherwise:

- `defect_shape` - `flow` (all three legs written) or `missing_control` (plus
  `missing_control{control,expected_at,unguarded_path,actor}`). A producer that left it unset
  is telling you it never decided the shape - check the finding's story holds up.
- `reachability{entry_point,min_privilege,pre_auth,call_chain}` - who triggers it, at what
  privilege, proven by a chain. If the producer claimed pre-auth, verify it with an
  unauthenticated request; downgrade `min_privilege` to what you actually reproduced.
- `preconditions{default_configuration,required_settings}` - true only if you reproduced it on
  a default/vendor-shipped configuration. If you had to enable a plugin, flag, or non-default
  setting, say so and list it; this is the same judgement as
  `official_review.default_configuration` and the two must agree.
- `primitive{kinds,escalation_ceiling,ruled_out}` - the capability you proved and its honest
  bound. Escalations you *tried and failed* go in `ruled_out` with the reason; escalations you
  never tried are not rule-outs and are not claimed. D raises the ceiling later with evidence.
- `repro{reliability,instrumentation_only,stock_replay}` - how repeatable (mandatory for races
  and heap-state bugs), and whether the observation ever existed only under a sanitizer, debug
  assertion, patched build, or diagnostic probe. Such an observation is a **lead** until
  `stock_replay` records a run on the exact stock build - the writer enforces this.

Over-packaging is a reporting defect, and an unbounded claim is the easiest way for a vendor
to close a real bug. "Read-only, self-owned objects only" is a better finding than a vague
"may allow privilege escalation".

## 2b-dedup - Is it already public? (confirmed product vulnerabilities only)

Only after the official review passes and the finding is `confirmed`, decide whether it is already
known or a NEW discovery. Run the complete exact-match public-history ladder:

1. Search source history for the affected path and exact patch fingerprints (`git log -S/-G`,
   vendor commit history/API, blame/history).
2. Compare the tested version with upstream main and supported release branches. Inspect any
   matching diff and follow linked issues, PRs, cherry-picks, servicing PRs, and backports.
3. Search the canonical vendor repository's **open and closed issues** plus **open and merged PRs**
   using exact symbols, filenames, validation flags, error strings, protocol terms, and semantic
   paraphrases. Do not search only a proposed vulnerability title.
4. Search vendor advisories, security advisories, CVEs, release notes, servicing notes, and
   changelogs. This is the last category, not the whole disclosure review.

Store the evidence in `disclosure.public_history`: canonical `upstream_repository`, at least two
`exact_anchors`, `source_history`, `vendor_issues_prs`, `advisories_releases`, and an exact
`head_or_release_comparison`. Then set the finding's `disclosure`:

  - `known` -> any public vendor issue, PR, commit, patch, test, advisory, CVE, release note, or
    changelog matches the same root cause. A public source fix is known even without a security label.
  - `novel` -> the entire ladder found no exact match and the structured evidence is complete.
  - `inconclusive` -> can't tell

The writer rejects `novel` without this evidence. Triage and the dashboard suppress the potential
0-day label when the public-history gate is incomplete, including for legacy findings that merely
say `disclosure.status=novel`.
Record via write_finding.py --update <id> with disclosure{checked,status,references,rationale}.
Do not treat this disclosure search as the product-boundary review: one establishes that the
behavior is a vendor vulnerability; the other establishes whether that vulnerability is public.

## 2b-emit - Per-vuln PoC + report (confirmed product vulnerabilities only)

For each `confirmed` finding whose official review verdict is `product_vulnerability` or
`known_vulnerability`, AUTHOR a poc.py (use the requests library) that
reproduces that specific vulnerability and store its full source in repro.poc_script. Fit
it to the bug: pre-auth -> no login; otherwise log in; use however many requests the exploit
needs; print a clear PASS/FAIL. Never assume a fixed login->exploit template. Then run
`.agents/skills/convergence/scripts/emit_poc.py` to write `workspace/report/<id>/poc.py`
(your script, verbatim) + `finding.md`. One folder per vuln - never merged.

## 2c - Triage + report (rolling, then final)

```bash
.agents/skills/convergence/scripts/triage.py
```
Prints the live queue (counts by status) and writes `workspace/report/report.md`: ranked
by severity x confidence(status), de-duplicated by `correlation_id`, CWE -> OWASP Top 10
mapped, false positives and non-product behavior excluded from ranking. Reproduced findings
awaiting official review appear in a separate pending section and can never appear as potential
0-days. Run it repeatedly for the rolling view; run once more at
the end (after the producer signals done and the queue drains) for the final global report.

## 2d - Pre-report self-check (METHODOLOGY §8)

Before a finding goes into the ranked report, and before the final triage pass, answer these.
Any "no" is a `needs_reanalysis` back to the producer, not a caveat in the report:

- [ ] Was the threat model built first - entry points, trust boundaries, assets, invariants?
- [ ] Were **both** shapes hunted on this surface? (Did P2, the guard audit, actually run, or
      did only source→sink run?)
- [ ] For a flow-shaped finding: are all three legs written and none assumed?
- [ ] Were sibling instances of the same signature swept? Defects cluster - one unscoped
      `findById`, one unreset global, one missing capability check is rarely alone.
- [ ] Was information disclosure traced to a real output sink (header/cookie/log/timing)?
      Were SSRF sinks checked?
- [ ] Were error/exception paths diffed against the success path (P6)?
- [ ] Was cross-request / cross-worker / concurrent reuse considered (P7)?
- [ ] Is this a real reproduction on a stock build, not an instrumentation artifact? Are the
      preconditions default?
- [ ] Is reachability stated as "who, with what privilege", and the escalation ceiling pinned
      down without over-packaging?
- [ ] One root cause, one finding - are trigger variants folded in as reproduction cases via
      `correlation_id` rather than filed separately?

## Streaming / feedback notes
- The finding files ARE the queue. Pick `candidate` and `cross_validated` findings, plus
  `reproduced` findings awaiting official review, highest severity first. Leave only consistently
  gated `confirmed`, `not_product_vulnerability`, and `false_positive` findings alone.
- De-dup before reproducing: set a shared `correlation_id` on findings with the same root
  cause so you reproduce once, not N times.
- Reproduction env stays warm for the whole session (shared by all PoCs).
- Never modify `targets/`; reproduction only sends requests to the running instance.
