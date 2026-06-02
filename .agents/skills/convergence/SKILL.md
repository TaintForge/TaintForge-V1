---
name: convergence
description: "Consume candidate findings and confirm them - cross-validate statically, reproduce dynamically against a running target, then triage and rank into a report. Runs continuously alongside the vuln tracks (streaming), not after they finish. Drives the finding status lifecycle and the reproduction feedback loop. Triggers - triage, reproduce, PoC, confirm finding, cross-validate, deduplicate, report, rank vulnerabilities."
---

# convergence (consumer / streaming)

Consumes `workspace/findings/*.json` and pushes each through cross-validation ->
reproduction -> triage, updating its `status`. Runs **continuously** while the producer
tracks stream findings - don't wait for them to finish. Process highest-severity
candidates first.

Status lifecycle (see schemas/finding.schema.json):
```
candidate --2a--> cross_validated --2b--> reproduced --> confirmed
                                     |
                          repro fails| --> false_positive          (discard)
                                     | --> needs_reanalysis         (feedback -> producer)
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
needs GitHub Advanced Security. (Track B logic findings skip 2a - confirmed by reproduction.)

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
- triggered -> `reproduced` (then `confirmed` once you're sure).
- safe -> `false_positive` with reasoning.
- ambiguous / PoC likely wrong -> `needs_reanalysis` (FEEDBACK LOOP): the producing track
  re-picks it up. Append a `history` entry saying why.

## 2b-dedup - Is it already public? (only for reproduced/confirmed)

Once a finding is `reproduced` (or `confirmed`), web-search to decide if it is already
known or a NEW discovery. Search the target product + version + vulnerability specifics:
e.g. "Craft CMS <version> <vuln_class> <endpoint/param> CVE", check the vendor advisories,
GitHub security advisories, NVD/CVE, and changelogs. Then set the finding's `disclosure`:
  - `known`  -> matches a published CVE/advisory (add the CVE ids / URLs to references)
  - `novel`  -> no public report found for this exact issue (potential 0-day - flag it)
  - `inconclusive` -> can't tell
Record via write_finding.py --update <id> with disclosure{checked,status,references,rationale}.
Only do this for reproduced/confirmed findings - don't waste searches on unproven candidates.

## 2b-emit - Per-vuln PoC + report (reproduced/confirmed only)

For each reproduced/confirmed finding, AUTHOR a poc.py (use the requests library) that
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
mapped, false positives excluded. Run it repeatedly for the rolling view; run once more at
the end (after the producer signals done and the queue drains) for the final global report.

## Streaming / feedback notes
- The finding files ARE the queue. Pick `candidate` (and `cross_validated`) findings,
  highest severity first; leave `confirmed`/`false_positive` alone.
- De-dup before reproducing: set a shared `correlation_id` on findings with the same root
  cause so you reproduce once, not N times.
- Reproduction env stays warm for the whole session (shared by all PoCs).
- Never modify `targets/`; reproduction only sends requests to the running instance.