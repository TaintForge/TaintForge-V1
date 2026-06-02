---
name: vuln-track-b
description: "Find logic and access-control vulnerabilities that data-flow tools cannot - IDOR, broken access control, missing authorization, privilege escalation, authentication bypass, and business-logic flaws (step-skipping, state manipulation, race conditions). Use after the Code Model comprehension layer is filled. Consumes CODE_MODEL.comprehension. Emits candidate findings to workspace/findings/. Triggers - IDOR, access control, authorization, privilege escalation, auth bypass, business logic, BOLA."
---

# vuln-track-b (logic / access-control)

Track B finds bugs where the data flow is fine but the *rules* are wrong: a user can
reach a resource or action they shouldn't. Tools can't do this alone - they don't know
what SHOULD be allowed. So a script gives you structural SEEDS and YOU do the reasoning.

Input: `workspace/CODE_MODEL.json` (`comprehension` layer - route_map, permission_model,
user_journeys, trust_boundaries). Output: `workspace/findings/*.json` (track `B`,
status `candidate`), validating against `schemas/finding.schema.json`.

> If `comprehension` is empty, run the `source-model` skill first. Track B has nothing
> to reason on without the route map and permission model.

## B1 - Permission matrix (build the "expected", then seed red flags)

```bash
.agents/skills/vuln-track-b/scripts/build_authz_matrix.py
```
Produces `workspace/_authz_matrix.json`: a role x route matrix with `expected_access`
set to `?`, plus deterministic red flags (`id-param-IDOR-candidate`,
`state-change-without-auth`, `admin-route-without-role`, `no-explicit-authz-check`) and
candidate lists. Now YOU fill `expected_access` per role from the service's intent
(`comprehension.service_identity`): for each route, who *should* be allowed?

## B2 - Compare expected vs actual (read the handlers)

For every route - especially the flagged ones - open the handler and find the ACTUAL
check. Compare against your `expected_access`:
- **IDOR / BOLA (CWE-639):** route takes an object id and the handler loads it without an
  ownership/tenant check (`WHERE id = :id` but not `AND owner = current_user`).
- **Missing authorization (CWE-862):** state-changing or sensitive route with no authz
  check on the path to the action.
- **Privilege escalation (CWE-269):** lower role reaches an admin-only action; role check
  missing or wrong.
- **Auth bypass (CWE-287):** the check can be skipped (wrong order, default-allow,
  unauthenticated branch).
Each real mismatch is a finding.

## B3 - User-journey / state analysis (business logic)

Walk `comprehension.user_journeys`. Look for:
- **Step-skipping / improper workflow (CWE-841):** can a later step be called directly,
  skipping payment/verification?
- **State manipulation:** client-controlled state (price, quantity, status) trusted by the
  server (mass assignment, CWE-915).
- **Race conditions (CWE-362):** double-spend, coupon reuse, TOCTOU on a shared resource.

## B4 - Emit findings

For each confirmed mismatch, pipe a partial finding to the writer (it fills id, history,
timestamps, validates, append-only):

```bash
echo '{"track":"B","vuln_class":"idor","cwe":"CWE-639",
"title":"...","severity_estimate":"high",
"source":{"file":"...","line":0,"description":"attacker-controlled key"},
"sink":{"file":"...","line":0,"description":"object load without ownership check"},
"evidence":"why a different user can access it",
"_action":"confirmed via handler read (B2)"}' \
| .agents/skills/_shared/write_finding.py
```

## Trace entry -> resource across files (use the call graph)

Access-control bugs are about a MISSING GATE somewhere on the path from a route to a
resource access, not a single line. For each route/action:
```bash
python3 .agents/skills/source-model/scripts/callgraph.py --callees <handlerFile>   # what the handler calls
python3 .agents/skills/source-model/scripts/callgraph.py --callers <load/findById/getByID>  # who can reach a resource load
```
Walk handler -> service -> repository/object-load and check the WHOLE chain for:
- authentication (is the user logged in?),
- authorization (role/permission check for this action?),
- object ownership / tenant scoping (does the loaded id belong to the caller?).
A resource load reachable from a route with no ownership check on the path = IDOR/BOLA.
A state-changing action with no role check = broken access control. Don't judge from the
handler file alone - follow the calls.

## Exhaustiveness - do NOT stop after a shallow pass

You may be invoked on ONE module. Cover it FULLY:
- Account for EVERY route/handler in this module against the permission matrix. For each,
  either record a finding OR state why the access check is adequate. Enumerate, don't sample.
- Check every red-flagged candidate AND routes the tool didn't flag.
- Walk every logic class: IDOR/BOLA, missing authz, privilege escalation, auth bypass,
  workflow/step-skipping, mass assignment, race conditions.
- Only stop when every route+action in the module is accounted for.

## Rules
- `targets/` is read-only.
- A Track B finding needs a concrete "who can do what they shouldn't, and where in code".
  No abstract "could be insecure" - point at the missing/!wrong check.
- Don't duplicate Track A: injection/data-flow is Track A's job. Track B is authorization
  and workflow logic.
- Leave `status: candidate`; convergence reproduces by replaying requests across roles/ids.