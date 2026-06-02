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

```bash
.agents/skills/convergence/scripts/probe.py -X GET "http://localhost:<port>/<path>" -H "..."
```
- **Track A (injection):** send the crafted payload, confirm the sink triggers (error,
  reflected payload, time delay, out-of-band).
- **Track B (logic/IDOR):** replay a request as role/user A against user B's object/action.
  Two requests, two identities - if A sees B's data, it's confirmed.

Record outcome in the finding's `repro` field and update status:
```bash
echo '<updated finding json with repro{} and status>' \
  | .agents/skills/vuln-track-b/scripts/write_finding.py --update <id>
```
- triggered -> `reproduced` (then `confirmed` once you're sure).
- safe -> `false_positive` with reasoning.
- ambiguous / PoC likely wrong -> `needs_reanalysis` (FEEDBACK LOOP): the producing track
  re-picks it up. Append a `history` entry saying why.

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