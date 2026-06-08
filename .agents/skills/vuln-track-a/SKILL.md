---
name: vuln-track-a
description: "Find injection and data-flow vulnerabilities (SQL injection, command injection, code injection, XSS, SSRF, path traversal, deserialization, XXE, SSTI, NoSQL, open redirect) by reading the code yourself. YOU (the model) are the finder; Semgrep/OpenGrep only provide optional leads. Use after the Code Model exists, for any source-to-sink vulnerability. Consumes CODE_MODEL.structural. Emits findings to workspace/findings/ via write_finding.py. Triggers - injection, taint, data flow, SQLi, command injection, XSS, SSRF, source to sink."
---

# vuln-track-a (injection / data-flow family)

**You are the vulnerability finder.** You read the code and decide what is vulnerable.
Tools (Semgrep/OpenGrep) only hand you LEADS to look at faster - they create nothing.
Every finding here is authored by YOU via `write_finding.py`. If the tool finds nothing,
you still hunt by reading the code.

Track A = anything where untrusted input flows into a dangerous sink (SQLi, command/code
injection, XSS, SSRF, path traversal, deserialization, XXE, SSTI, NoSQL, open redirect).
Authorization/logic bugs are Track B.

Input: `workspace/CODE_MODEL.json` (`structural`). Output: `workspace/findings/*.json`.

## 1. (optional) Pull tool leads

```bash
.agents/skills/vuln-track-a/scripts/run_semgrep.sh targets/<app>
```
Writes leads to `workspace/hints/track-a-semgrep.md` (NOT findings). Read it if present.
**Do not stop at the leads. Do not turn leads into findings blindly.**

## 2. Hunt (this is the real work - you do it)

Using `CODE_MODEL.structural` (entry points, call graph) and `comprehension`
(trust boundaries, routes), and reading the actual source:
- Enumerate dangerous sinks for each class.
- For each sink, trace BACKWARD to a source (request params, body, headers, route vars).
  Follow value transformations across functions/files (the tool can't; you can).
- Cover sinks/sources the tool never flagged - that's where the tool's blind spots are.

## 2b. Trace the flow across files (use the call graph)

```bash
python3 .agents/skills/source-model/scripts/callgraph.py --sinks
python3 .agents/skills/source-model/scripts/callgraph.py --callers <sink>
python3 .agents/skills/source-model/scripts/callgraph.py --trace   <sink> -d 8
python3 .agents/skills/source-model/scripts/proof_ledger.py --next sink
```
The graph is function/method-level and includes callsite lines, but it is still a structural
skeleton, not a taint proof. Read the code on each path, prove attacker-controlled source
reachability and sanitizer absence/presence, then mark the sink unit `safe`, `finding`, or
`needs_reanalysis`. Never judge a sink safe from its own file alone.

> Note: the default sink set is high-signal only. If you need to hunt resource-load or
> output sinks (XSS via render/send), re-run the build with TF_NOISY_SINKS=1, or trace those
> calls manually with --callers - they are excluded by default to keep the proof ledger
> tractable on big codebases.

## 3. Judge each candidate

- Is there a real path from attacker-controlled input to the sink? If not, drop it.
- Is it sanitized/escaped/parameterized on the way? If genuinely safe, drop it. Note what you saw.
- Decide exploitability and severity. Custom/uncommon sanitizers are YOUR judgment.

## 4. Record real findings

```bash
echo '{"track":"A","vuln_class":"sql-injection","cwe":"CWE-89",
"title":"...","severity_estimate":"high",
"source":{"file":"...","line":0,"description":"attacker-controlled input"},
"sink":{"file":"...","line":0,"description":"dangerous call"},
"flow":[{"file":"...","line":0,"note":"how taint reaches the sink"}],
"sanitizers_seen":[],"evidence":"why this is exploitable",
"_action":"found by reading code"}' \
| .agents/skills/_shared/write_finding.py
```

## Exhaustiveness - do NOT stop after a shallow pass

You may be invoked on ONE module. Cover it FULLY: account for EVERY entry point / sink, walk
EVERY injection class, follow flows that leave the module, and only stop when you can't find
another untested source->sink path.

## Rules
- `targets/` is read-only.
- Findings are YOURS, grounded in code you actually read - never auto-promote a tool lead.
- A finding needs a concrete source->sink path you can point to.
- Leave `status: candidate`; convergence cross-validates + reproduces.