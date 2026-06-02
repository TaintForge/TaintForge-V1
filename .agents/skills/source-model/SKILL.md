---
name: source-model
description: "Build the reusable Code Model for a target under targets/. Use at the START of any assessment, before vulnerability analysis. Extracts structural facts (files, entry points, call graph) with a script, then reasons about the application (service identity, routes, feature flows, permission model, user journeys, trust boundaries) to fill the comprehension layer. Produces workspace/CODE_MODEL.json. Triggers - code model, source analysis, map the codebase, understand the app, build CODE_MODEL."
---

# source-model

Build `workspace/CODE_MODEL.json` for a target. It has two layers and you build them with
two different methods. **Structural = facts (script). Comprehension = meaning (you).**
The schema is `schemas/code_model.schema.json` — the output MUST validate against it.

## Step 1 — Structural layer (run the script, don't hand-write it)

```bash
.agents/skills/source-model/scripts/build_code_model.sh targets/<app>
```

This walks the tree and fills `structural`: `files`, `entry_points` (route heuristics),
`call_graph`. tree-sitter gives precise functions + call edges; without it the script
falls back to regex (no call graph). Do not edit these facts by hand — re-run the script
if the target changes.

## Step 2 — Comprehension layer (this is your job, read the code)

Read the entry points and the code they reach, then fill `comprehension`:

1. **service_identity** — what is this service? domain (fintech/ecommerce/saas...), purpose,
   and the `sensitive_data` it handles. This drives later threat prioritization.
2. **route_map** — for each entry point: method, path, handler, `auth_required`, `role_required`.
   Start from `structural.entry_points`, then confirm auth by reading the handler/middleware.
3. **feature_flows** — for key features, the call chain (controller -> service -> repo -> db).
   Use `structural.call_graph` as the skeleton.
4. **permission_model** — `roles`, `auth_mechanism` (session/jwt/oauth), and `authz_locations`
   (where access checks actually live in code). Track B compares expected vs these.
5. **user_journeys** — multi-step scenarios (signup -> login -> checkout) and the `state` that
   persists across steps. This is where logic bugs hide.
6. **trust_boundaries** — where attacker-controlled input actually enters; list
   `attacker_controlled_inputs` per boundary. This separates real sources from internal data.

## Step 3 — Validate and write

```bash
python3 - <<'PY'
import json, jsonschema
s=json.load(open("schemas/code_model.schema.json"))
m=json.load(open("workspace/CODE_MODEL.json"))
jsonschema.validate(m,s); print("CODE_MODEL valid")
PY
```

Write the final merged model to `workspace/CODE_MODEL.json`. It is now the input for
`vuln-track-a` (uses `structural`) and `vuln-track-b` (uses `comprehension`).

## Rules

- `targets/` is read-only — never modify the code under assessment.
- Structural facts come from the script only. Comprehension is your reasoning, grounded in
  what you actually read — do not invent routes or roles that aren't in the code.
- If a field is genuinely undeterminable, leave it empty rather than guessing.