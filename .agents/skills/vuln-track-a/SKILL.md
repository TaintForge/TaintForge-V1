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
Treat it as "spots worth checking first" - many are false positives, and it misses a lot.
**Do not stop at the leads. Do not turn leads into findings blindly.**

## 2. Hunt (this is the real work - you do it)

Using `CODE_MODEL.structural` (entry points, call graph) and `comprehension`
(trust boundaries, routes), and reading the actual source:
- Enumerate dangerous sinks for each class (e.g. PHP: `mysqli_query`, `$pdo->query`,
  `exec`, `system`, `shell_exec`, `eval`, `unserialize`, `include`/`require` with vars,
  `echo`/`print` of request data; JS: `db.query`, `child_process.exec`, `eval`, `res.send`).
- For each sink, trace BACKWARD to a source (request params, body, headers, route vars).
  Follow value transformations across functions/files (the tool can't; you can).
- Cover sinks/sources the tool never flagged - that's where the tool's blind spots are.

## 2b. Trace the flow across files (use the call graph)

Vulns live on flows, not single lines. For each sink, find its callers and walk back to a
source across file/module boundaries:
```bash
python3 .agents/skills/source-model/scripts/callgraph.py --callers <sink>   # query, unserialize, include, system, eval, mysqli_query, ...
python3 .agents/skills/source-model/scripts/callgraph.py --trace   <sink>
```
The graph is coarse and misses construct sinks on raw input (include $_GET[...], eval of a
request value) - catch those by reading code. Never judge a sink safe from its own file alone.

## 3. Judge each candidate (A3 + A4)

- Is there a real path from attacker-controlled input to the sink? If not, drop it.
- Is it sanitized/escaped/parameterized on the way (prepared statements, allowlists,
  encoders, framework escaping)? If genuinely safe, drop it. Note what you saw.
- Decide exploitability and severity. Custom/uncommon sanitizers are YOUR judgment.

## 4. Record real findings (you author them)

For each confirmed vuln, write it (the helper fills id/history/timestamps, validates,
append-only):

```bash
echo '{"track":"A","vuln_class":"sql-injection","cwe":"CWE-89",
"title":"...","severity_estimate":"high",
"source":{"file":"...","line":0,"description":"attacker-controlled input"},
"sink":{"file":"...","line":0,"description":"dangerous call"},
"flow":[{"file":"...","line":0,"note":"how taint reaches the sink"}],
"sanitizers_seen":[],"evidence":"why this is exploitable",
"_action":"found by reading code (A2-A4)"}' \
| .agents/skills/_shared/write_finding.py
```

## Exhaustiveness - do NOT stop after a shallow pass

You may be invoked on ONE module (a subdirectory). Cover it FULLY before finishing:
- Account for EVERY entry point / sink in this module. For each, either record a finding
  OR state in your reasoning why its inputs are safe. "I found 2" is not done;
  "I checked all N sinks, these are unsafe, the rest are safe because X" is done.
- Walk EVERY injection class in the list above - don't stop at the first type you find.
- Follow flows that leave this module into others; note them so they're checked there too.
- Only stop on this module when you can't find another untested source->sink path.

## Rules
- `targets/` is read-only.
- Findings are YOURS, grounded in code you actually read - never auto-promote a tool lead.
- A finding needs a concrete source->sink path you can point to.
- Leave `status: candidate`; convergence cross-validates + reproduces.