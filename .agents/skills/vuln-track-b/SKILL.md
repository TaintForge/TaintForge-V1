---
name: vuln-track-b
description: "Find logic and access-control vulnerabilities that data-flow tools cannot - IDOR, broken access control, missing authorization, privilege escalation, authentication bypass, and business-logic flaws (step-skipping, state manipulation, race conditions). Use after the Code Model comprehension layer is filled. Consumes CODE_MODEL.comprehension. Emits candidate findings to workspace/findings/. Triggers - IDOR, access control, authorization, privilege escalation, auth bypass, business logic, BOLA."
---

# vuln-track-b (logic / access-control)

Track B finds bugs where the data flow is fine but the *rules* are wrong: a user can
reach a resource or action they shouldn't. Tools can't do this alone - they don't know
what SHOULD be allowed. So a script gives you structural SEEDS and YOU do the reasoning.

Input: `workspace/CODE_MODEL.json` (`comprehension` - route_map, permission_model,
user_journeys, trust_boundaries). Output: `workspace/findings/*.json` (track `B`, candidate).

> If `comprehension` is thin, `build_authz_matrix.py` falls back to
> `structural.entry_points`, but auth/role fields will be `unknown`. Treat unknown as
> work to prove by reading the route-to-resource path, not as safe.

## B1 - Permission matrix

```bash
.agents/skills/vuln-track-b/scripts/build_authz_matrix.py
```
Produces `workspace/_authz_matrix.json`: a role x route matrix with `expected_access` set to
`?`, plus deterministic red flags and candidate lists. Now YOU fill `expected_access` per
role from the service's intent: for each route, who *should* be allowed?

## B2 - Compare expected vs actual (read the handlers)

For every route - especially flagged ones - open the handler and find the ACTUAL check:
- **IDOR / BOLA (CWE-639):** route takes an object id, handler loads it without an
  ownership/tenant check.
- **Missing authorization (CWE-862):** sensitive/state-changing route with no authz check.
- **Privilege escalation (CWE-269):** lower role reaches an admin-only action.
- **Auth bypass (CWE-287):** the check can be skipped.
Each real mismatch is a finding.

## B3 - User-journey / state analysis (business logic)

Walk `comprehension.user_journeys`:
- **Step-skipping (CWE-841):** can a later step be called directly?
- **State manipulation:** client-controlled state (price, status) trusted by the server (CWE-915).
- **Race conditions (CWE-362):** double-spend, coupon reuse, TOCTOU.

## B4 - Emit findings

```bash
echo '{"track":"B","vuln_class":"idor","cwe":"CWE-639",
"title":"...","severity_estimate":"high",
"source":{"file":"...","line":0,"description":"attacker-controlled key"},
"sink":{"file":"...","line":0,"description":"object load without ownership check"},
"evidence":"why a different user can access it",
"_action":"confirmed via handler read (B2)"}' \
| .agents/skills/_shared/write_finding.py
```

## Trace entry -> resource across files

```bash
python3 .agents/skills/source-model/scripts/callgraph.py --entries
python3 .agents/skills/source-model/scripts/callgraph.py --forward '<handler_symbol>' -d 8
python3 .agents/skills/source-model/scripts/callgraph.py --callers <load/findById/findOne>
python3 .agents/skills/source-model/scripts/proof_ledger.py --next route
```
Walk handler -> service -> repository/object-load and check the WHOLE chain for authn, authz,
and object ownership/tenant scoping. A resource load reachable from a route with no ownership
check = IDOR/BOLA. Don't judge from the handler file alone.

## Hypotheses

Also read `workspace/HYPOTHESES.json`. For each open hypothesis bound to a real endpoint,
verify it against the code; if confirmed write a finding and set its `hypothesis_id`, then
mark the hypothesis verified; if disproved mark it refuted with a one-line reason. These are
intent-level business-logic attacks to check alongside the structural matrix.

## Exhaustiveness

Account for EVERY route/handler in the module against the matrix; for each, a finding OR a
route proof unit marked safe with concrete authn/authz/ownership evidence. Walk every logic
class. Only stop when every route+action is accounted for.

## Rules
- `targets/` is read-only.
- A Track B finding needs a concrete "who can do what they shouldn't, and where in code".
- Don't duplicate Track A: injection/data-flow is Track A's job.
- Leave `status: candidate`; convergence reproduces across roles/ids.