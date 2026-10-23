# campaigns/

A **campaign** is one target under assessment: which checkout, which live URL, which accounts,
which modules get a full code model, and what the roles need to know about *that* codebase.
None of that is harness — it is configuration — so only this README and the `example.*` pair
are tracked. Your own campaigns stay local (`.gitignore` keeps `campaigns/*` out of git).

A campaign is two files:

| File | What it holds |
|---|---|
| `<name>.modules` | `name:path` per line — the security-relevant areas that each get a full model under `workspace/cm/<name>.json`. `#` comments and blank lines ignored. |
| `<name>.sh` | env (target, URL, accounts, backend, model, canary) + `TAINTFORGE_EXTRA_CONTEXT`, then `exec ./start.sh ...`. |

```bash
./seed.sh targets/<app> campaigns/<name>.modules   # once per checkout
./campaigns/<name>.sh                              # run the roles
```

## Why the modules file exists

`build_code_model.sh` degrades to a **graph-only** extract above ~4000 analyzable files, and a
graph-only model has no dataflow, no sink set and no proof ledger — most of what A and B
actually query. So each area listed in `<name>.modules` gets its own full model, and the roles
query those directly:

```bash
callgraph.py    --model  workspace/cm/<name>.json --sinks
proof_ledger.py --ledger workspace/cm/<name>.proof_ledger.json --next route
```

Pick the areas that carry the target's security boundaries (routing, auth, admin, API surface,
parsers, template/render, upload, plugin/extension loading) rather than the whole tree. A path
missing from this version of the target is skipped, so one modules file survives upgrades.

## What belongs in `TAINTFORGE_EXTRA_CONTEXT`

Target-specific facts the roles cannot derive cheaply, and nothing else:

- the exact tag/commit under analysis, and that findings must be pinned to it;
- the live instance's shape: login route, nonce/CSRF mechanism, which accounts exist and
  what each one can do;
- **honest limits of the extractor on this stack** — e.g. on PHP the call graph misses hook
  dispatch (`add_action`/`apply_filters`), variable functions and `call_user_func`, so a graph
  edge is a hint to verify by reading, never a path to report;
- where the disclosure ladder actually lives for this vendor (issue tracker, release notes,
  advisory feed), since it is rarely just GitHub;
- for a desktop/CLI target with no URL: `export TF_CANARY=1` so `audit.sh` starts and tears
  down the out-of-band canary itself, plus the lab containment rules for the built copy.

Keep the role contract itself in `AGENTS.md` and `.agents/skills/` — a campaign that starts
re-explaining methodology has stopped being configuration.
