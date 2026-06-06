---
name: hypothesize
description: "Generate top-down business-logic vulnerability hypotheses for the target, based on what the service actually DOES (its domain and its user/admin logic flows). Use at the START of an assessment, right after the Code Model, before/alongside vulnerability hunting. Complements the bottom-up sink-first and entry-first scans by asking 'given this is a [finance|vcs|community|...] service, what business-logic flaws are likely?' and seeding those as hypotheses for the producers to verify. Produces workspace/HYPOTHESES.json. Triggers - hypotheses, business logic, threat model, domain flaws, what could go wrong, attacker goals."
---

# hypothesize

Bottom-up scanning (A: sinks, B: authz gates) finds *patterns*. It misses bugs that only make
sense once you know **what the service is for** — double-spend in a wallet, protected-branch
bypass in a VCS, block-evasion in a forum. This step is the **top-down** half: model the
domain and its logic flows, then state concrete hypotheses the producers will verify.

A hypothesis is a claim of the form *"because this is an X that does Y, action Z on endpoint E
may violate rule R."* It is NOT a finding. Producers confirm or refute it against the code.

## Step 1 — Determine the domain

```bash
.agents/skills/hypothesize/scripts/gen_hypotheses.py --target targets/<app>
```
Domain is chosen as: explicit `--domain` > `SERVICE_DOMAIN` env > inferred from the Code
Model's entry points + target name. The script seeds `workspace/HYPOTHESES.json` with the
matching domain's catalog hypotheses **plus** the generic set.

If the inferred domain is wrong, re-run with `--domain finance|vcs|community|generic`. If the
service is a domain not in the catalog, use `generic` and rely more on Step 3.

## Step 2 — Reconstruct the logic flows (you, from the code)

Read the Code Model and the actual handlers to map, in your own words:
- **User flow:** signup → auth → the core actions (transfer / push / post / …) → state changes.
- **Admin flow:** who can grant roles, change settings, moderate, export, impersonate.
- **The rules that must hold:** "balance never goes negative", "only reviewers approve",
  "a blocked user cannot DM", "only the owner edits". These invariants are what hypotheses
  attack.

## Step 3 — Add service-specific hypotheses (the valuable part)

The catalog is generic to the domain. Now add hypotheses unique to THIS service's flows,
with `"source":"llm"`. For each: the invariant it breaks, the concrete `target_endpoints`
(real routes from the Code Model), `why`, and `check_how`. Fill `target_endpoints` on the
catalog hypotheses too, mapping them to this app's actual routes.

Update `workspace/HYPOTHESES.json` (same shape) via your normal file write. Keep every field;
add `target_endpoints` and any new hypotheses.

## Step 4 — Hand off

Producers A/B read `HYPOTHESES.json` and, for each open hypothesis, verify it against the code:
- confirmed → write a finding via `write_finding.py` and set the finding's `hypothesis_id`;
  mark the hypothesis `verified`.
- disproved → mark the hypothesis `refuted` with a one-line reason.
C prioritizes reproducing findings that validate a hypothesis; D weaponizes the critical ones.

Hypotheses are a checklist of *intent-level* attacks, ensuring the assessment covers "what an
attacker wants to achieve here", not only "what risky code exists".