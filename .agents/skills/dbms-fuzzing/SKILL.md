---
name: dbms-fuzzing
description: "Build, run, and adapt authorized local DBMS fuzzing campaigns for PostgreSQL, Redis, MySQL, MariaDB, and Oracle, prioritizing pre-auth or low-privilege memory-corruption paths to RCE. Use for protocol, SQL executor, sanitizer, AFL++, corpus, crash-triage, and harness self-repair work."
---

# DBMS fuzzing

Own the fuzzing loop for authorized database targets. The objective is a reproducible
attacker-controlled memory primitive that can credibly reach RCE, not a large count of syntax
errors or ordinary server disconnects.

## Boundaries

- Read target source only under `targets/`; never modify it. Copy source into `.labs/db-fuzz/`
  before instrumented builds or harness patching.
- Send traffic only to loopback addresses and explicitly configured local containers.
- Put generated corpus, state, logs, and artifacts under `workspace/db-fuzz/`; reusable harness
  source belongs under `harnesses/dbms_fuzz/`.
- Do not store credentials in corpus, findings, logs, command lines, or tracked files. Read DSNs
  from a mode-0600 file named by `DBFUZZ_DSN_FILE` when authenticated SQL coverage is authorized.
- A sanitizer hit or crash is a lead. Promote only after deterministic replay, source root-cause
  analysis, and validation on the exact stock target. Record that honestly on the finding:
  `repro.instrumentation_only` while it exists only under instrumentation,
  `repro.stock_replay` with the stock build id once it replays there, and `repro.reliability`
  (e.g. `3/50 runs`) for anything heap-state- or race-dependent. `write_finding.py` refuses to
  confirm an instrumentation-only observation.
- State the bound, not the hope: `primitive{kinds,escalation_ceiling,ruled_out}`. "DoS only: no
  control over the freed chunk contents" is a complete finding; "potential RCE" is not.
- Author candidate findings only through `.agents/skills/_shared/write_finding.py`, using track A.

## Choose lanes

Run complementary lanes rather than forcing every target through one fuzzer:

1. `wire-preauth`: structured startup/authentication transcripts against a local daemon.
2. `sql-executor`: low-privilege, schema-aware queries that reach planner, executor, built-in
   types/functions, tuple modification, prepared statements, and binary/text bind paths.
3. `coverage`: AFL++/libFuzzer against copied, instrumented source when the parser or server reset
   boundary is sound. Do not use blind byte mutation when syntax or semantic rejection dominates.
4. `stock-replay`: replay minimized candidates against the exact uninstrumented image.

PostgreSQL, MySQL/MariaDB, and Redis support source-instrumented lanes when source is present.
Oracle normally uses wire and SQL black-box lanes unless an authorized instrumentable build is
available; never pretend client-driver coverage is server coverage.

## Persistent loop

1. Run `python3 harnesses/dbms_fuzz/dbfuzz.py doctor --engine <authorized-engine>` and inspect
   `harnesses/dbms_fuzz/targets.json`.
2. Select only engines whose loopback service/source prerequisites are available.
3. Seed from regression tests, fixed security-bug families, protocol grammars, and previously
   interesting cases. Preserve valid semantic prefixes.
4. Execute bounded batches. Retain new protocol/SQL states, new coverage, sanitizer reports,
   abnormal process or backend exits, debug/stock divergence, and auth-state invariant failures.
5. Repair promising rejected inputs: rule-based framing/schema/cast repair first; reasoning-driven
   repair only when a new path or state justifies it. Record the failed premise and the change.
6. Minimize while preserving the same sanitizer stack or process-state signature. Stateful bugs
   require statement/transcript prefix minimization and a clean snapshot replay.
7. Reproduce on the exact stock image. Record authentication level, required objects/plugins,
   allocator/build assumptions, controllable offset/size/bytes, and mitigations.
8. Send proven primitives to C for convergence and D for RCE chaining. Send failed or ambiguous
   candidates to E with exact replay evidence; do not bounce unchanged cases.

## Harness commands

```bash
python3 harnesses/dbms_fuzz/dbfuzz.py doctor --engine postgresql
python3 harnesses/dbms_fuzz/dbfuzz.py wire --engine postgresql --port 55432 --iterations 1000
DBFUZZ_DSN_FILE=workspace/db-fuzz/postgresql.dsn \
python3 harnesses/dbms_fuzz/dbfuzz.py sql --engine postgresql --iterations 500
python3 harnesses/dbms_fuzz/dbfuzz.py replay --case workspace/db-fuzz/.../case.json
python3 harnesses/dbms_fuzz/dbfuzz.py minimize --case workspace/db-fuzz/.../case.json
```

Use `harnesses/dbms_fuzz/build-instrumented.sh` only after checking its plan with `--dry-run`.
It must copy source out of `targets/` before configuring or compiling.

## Engine focus

- PostgreSQL: startup/SSL/GSS/SASL, extended query protocol, type receive functions, encoding,
  regexp, text search, arrays, portal lifecycle, planner estimators, executor and tuple paths.
- MySQL/MariaDB: handshake capabilities, SSL/auth-plugin transitions, packet and length-encoded
  fields, charset conversion, prepared/binary protocol, JSON/regexp/GIS, optimizer and storage
  engine boundaries. Keep product-specific behavior separate after the shared wire prefix.
- Redis: RESP framing, auth/HELLO state, query-buffer growth, argv ownership, Lua and serialized
  object parsers after an authorized auth lane, blocked-client and command-rewrite lifetimes.
- Oracle: TNS connect/auth negotiation and low-privilege SQL type/charset/JSON/XML/regexp paths.
  Treat ORA errors and session loss as weak signals unless the local server process/log confirms
  a fault.

## Promotion threshold

Record a finding only when the exact attacker input and reachable path are known and one of these
is independently reproduced: sanitizer-backed memory corruption, deterministic abnormal server
process/backend termination rooted in unsafe memory behavior, authentication-state bypass, or a
controlled read/write/free primitive. Resource exhaustion and valid-query DoS remain notes unless
they are a necessary, demonstrated RCE-chain step.
