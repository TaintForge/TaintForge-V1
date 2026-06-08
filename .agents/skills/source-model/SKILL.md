---
name: source-model
description: "Build the reusable Code Model for a target under targets/. Use at the START of any assessment, before vulnerability analysis. Extracts structural facts (files, entry points, call graph) with a script, then reasons about the application (service identity, routes, feature flows, permission model, user journeys, trust boundaries) to fill the comprehension layer. Produces workspace/CODE_MODEL.json. Triggers - code model, source analysis, map the codebase, understand the app, build CODE_MODEL."
---

# source-model

Build `workspace/CODE_MODEL.json` for a target. Two layers, two methods.
**Structural = facts (script). Comprehension = meaning (you).**
The schema is `schemas/code_model.schema.json` - the output MUST validate against it.

## Step 1 - Structural layer (run the script, don't hand-write it)

```bash
.agents/skills/source-model/scripts/build_code_model.sh targets/<app>
```

This walks the tree (ast for python, regex extractors for other languages) and fills
`structural`: `files`, `entry_points`, and a **function/method-level call graph**. It also
writes out-of-band artifacts:

- `workspace/symbols.json` - module/class/function/method symbols with spans.
- `workspace/callsites.json` - every callsite with its containing caller symbol.
- `workspace/dataflow.json` - structural source/sink/guard/path skeletons.
- `workspace/proof_ledger.json` - route/sink analysis units for context-safe coverage.

Do not edit these structural facts by hand - re-run the script if the target changes.

## Step 2 - Comprehension layer (this is your job, read the code)

Read the entry points and the code they reach, then fill `comprehension`:

1. **service_identity** - what is this service? domain, purpose, `sensitive_data`.
2. **route_map** - per entry point: method, path, handler, `auth_required`, `role_required`.
   Start from `structural.entry_points`, confirm auth by reading the handler/middleware.
3. **feature_flows** - call chains (controller -> service -> repo -> db). Use
   `structural.call_graph`, `workspace/dataflow.json`, `callgraph.py --forward <handler_symbol>`.
4. **permission_model** - `roles`, `auth_mechanism`, `authz_locations`.
5. **user_journeys** - multi-step scenarios and the `state` that persists across steps.
6. **trust_boundaries** - where attacker input actually enters; `attacker_controlled_inputs`.

## Step 3 - Validate and write

```bash
python3 - <<'PY'
import json, jsonschema
s=json.load(open("schemas/code_model.schema.json"))
m=json.load(open("workspace/CODE_MODEL.json"))
jsonschema.validate(m,s); print("CODE_MODEL valid")
PY
```

Useful queries:

```bash
python3 .agents/skills/source-model/scripts/callgraph.py --stats
python3 .agents/skills/source-model/scripts/callgraph.py --entries
python3 .agents/skills/source-model/scripts/callgraph.py --sinks
python3 .agents/skills/source-model/scripts/callgraph.py --trace query -d 8
python3 .agents/skills/source-model/scripts/callgraph.py --forward '<handler_symbol>' -d 8
python3 .agents/skills/source-model/scripts/proof_ledger.py --summary
python3 .agents/skills/source-model/scripts/proof_ledger.py --next route
```

## Rules

- `targets/` is read-only - never modify the code under assessment.
- Structural facts come from the script only. Comprehension is your reasoning, grounded in
  what you actually read - do not invent routes or roles that aren't in the code.
- Mark proof units done only after recording a finding id or a concrete safe reason via
  `proof_ledger.py --done ...`; module-level coverage alone is not proof coverage.
- If a field is genuinely undeterminable, leave it empty rather than guessing.
- The sink set defaults to high-signal categories (sql/command/code-eval/deserialization/
  file-path/ssrf-net/redirect). Set TF_NOISY_SINKS=1 to also treat resource-load (find/where/
  first/...) and xss-output (render/send/...) as sinks - useful on small apps, but it can
  explode the sink set / proof ledger on large ORM-heavy codebases, so it is OFF by default.