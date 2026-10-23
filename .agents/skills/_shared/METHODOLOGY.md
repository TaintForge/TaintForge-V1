# METHODOLOGY — the universal defect-hunting contract

Read this after `AGENTS.md` and before your role skill. It is language-, target-, and
class-agnostic: memory safety is one domain among many here, not the point of it.

Two premises drive everything below.

**Premise 1 — three legs.** Most analysts and every tool miss bugs by being *source-biased*,
*sink-biased*, or by skipping *propagation*. A flow-shaped defect only exists when all three
legs are written down explicitly. A leg you assumed is a lead, not a finding.

**Premise 2 — two shapes.** Defects arrive in two shapes:

- **(A) dangerous flow** — taint reaches a dangerous operation;
- **(B) missing control** — a check that must exist on a reachable path does not.

Access control, authentication, and most logic bugs are shape (B). Hunting only shape (A)
loses shape (B) wholesale. **The tracks are named after the shapes, not after the classes:**
Track A is the flow track, Track B is the absence track. Any class can take either shape, so
decide the shape *first* and route from there — see §2.

Record the decision in the finding as `defect_shape: "flow" | "missing_control"`.

---

## 0. Threat model first — skip this and you have no direction

Before hunting, write these four down. They already have homes in the workspace:

| What | Where it lives | Built by |
|---|---|---|
| Entry points | `CODE_MODEL.structural.entry_points`, `proof_ledger.json` | `build_code_model.sh` |
| Actors & trust boundaries | `CODE_MODEL.comprehension.{route_map,permission_model,trust_boundaries}` | source-model (you) |
| Assets | `CODE_MODEL.comprehension.service_identity.sensitive_data` | source-model (you) |
| Invariants | `HYPOTHESES.json` (`invariant` + `attacker_goal`) | hypothesize (you) |

- **Entry points:** routes, handlers, RPC, queue consumers, CLI, webhooks, cron, file
  parsers, deserialization entries, IPC, protocol wire readers.
- **Actors / trust boundaries:** unauthenticated / authenticated / per-role / per-tenant /
  internal-service. For **every** entry point state *who reaches this code* — the lowest
  privilege that reaches it, proven by a call chain, not assumed from the route name.
- **Assets:** secrets, credentials, PII, funds, permission state, integrity-critical data,
  availability.
- **Invariants:** what the code silently assumes is true — ownership, `balance >= 0`,
  state-machine order, "authenticated by this point", "this pointer is live", "this length
  matches this buffer". **The invariant list is the candidate-bug list.**

A threat model that doesn't produce an entry-point × minimum-privilege table has not been
done. That table is what `reachability` in every finding is derived from.

---

## 1. SOURCE catalog — "attacker influence", not just "input"

Eight families. Families 4–8 are invisible to taint engines *and* to the structural call
graph; they are found only by reading lifetime and error paths.

1. **Direct input** — request params/headers/cookies/body, uploads, env, IPC, deserialized
   bytes, files, protocol frames.
2. **Identity & authorization state** — session, token, role, tenant id, owner id: anything
   the attacker can *choose, forge, or confuse*. This is a source. Treating identity as
   trusted context instead of attacker influence is the single most common shape-(B) miss.
3. **Second-order / stored** — values written to DB, cache, config, or logs and later read
   back as trusted (stored XSS, second-order injection, log-to-template).
4. **Post-free un-reset state** — a pointer, handle, fd, or object freed/closed but still
   referenced by a global, a struct field, or a registry; reused later. The root of UAF.
5. **Bailout-orphaned state** — state left behind because an exception, `longjmp`, panic,
   early return, OOM, or timeout skipped cleanup. The normal path is clean; the error path
   is not.
6. **Cross-scope persistent state** — carried between requests (worker/process reuse),
   between threads, between workers (shared memory), or through a cache.
7. **Uninitialized reuse / metadata mismatch** — pool/arena residue; a length, type,
   ownership, or refcount field that disagrees with the object it describes.
8. **Time & ordering** — concurrent interleaving, reentrancy, replay of a nonce/token/
   one-time action. This is the source leg of every TOCTOU and race.

---

## 2. Class × shape matrix — run it exhaustively, and route by shape

For each class, both shapes exist. The **owner** column says which track files it so that no
class falls between A and B.

| Class | (A) dangerous flow | (B) missing control | Owner |
|---|---|---|---|
| Access control / authz | object id from input → load/mutate with no ownership check | is there an authz check on *every* path to each privileged op? horizontal/vertical escalation, tenant isolation | B |
| Authentication | token/session value trusted unverified | auth bypass, weak/fixated session, MFA-skipping path | B |
| Injection | input → SQL/NoSQL/cmd/code/LDAP/template/XSS/CRLF | no parameterization, no context-correct encoding | A |
| SSRF / request forgery | input URL → server-side fetch (http/dns/socket) | no destination allowlist, no metadata-IP block; no CSRF token | A (SSRF) / B (CSRF) |
| Path & file | input → path (traversal/LFI/RFI), upload name/type | no normalization, no root confinement, no type check | A |
| Deserialization / object injection | untrusted bytes → `unserialize`/`pickle`/gadget | no type allowlist, no signature | A |
| Memory safety | input or post-free state → `memcpy`/index/deref/function pointer | no length, NULL, or lifetime guard (UAF/OOB/type confusion) | A |
| Concurrency / TOCTOU | shared state mutated between check and use | no lock, no atomicity, no idempotency | B (logic/state), A (memory/lifetime races) |
| Crypto | secret/input → weak algorithm, fixed IV, non-constant-time compare | no verification, predictable randomness, plaintext storage | B |
| Resource / DoS | input size/count → unbounded alloc, loop, recursion | fd/lock/memory never released, no rate limit or quota | A (flow) / B (absence) |
| Information disclosure | internal state/secret → response, error, log, timing, cookie | no masking, no minimization, debug surface enabled | A |
| Business logic | input → invariant violation (negative qty/price, out-of-order, replay) | no state machine, no limit, no idempotency, no server-side validation | B |
| Config / supply chain | — (almost always absence) | default credentials, excess privilege, unsafe default, poisoned dependency | B |

Rules:

- **No class is unowned.** If neither track obviously owns what you found, the role that
  found it files it, with `defect_shape` set and a one-line note of why it sits there.
- Track A must not drop a finding because it looks like "logic"; Track B must not drop one
  because it looks like "injection". File it, set `correlation_id`, and let C de-duplicate.
- E re-opens either track's findings; F feeds track A candidates from native fuzz lanes.

---

## 3. SINK / dangerous-operation taxonomy (shape A)

Hunt every group. Looking at one group finds only that group.

1. **Execution** — `system`/`exec`/`eval`/`popen`, `include`/`require`, deserialization,
   template render, dynamic import/plugin load.
2. **Query & storage** — SQL/NoSQL/ORM raw, file write, outbound API call.
3. **Network** — server-side fetch (http/socket/dns) → SSRF.
4. **Disclosure outputs** — response headers, cookies, body, error messages, logs, URL
   rewrites, **timing**.
5. **Memory** — `memcpy`/`memmove`/`strcpy` (length/offset), array index, pointer
   arithmetic, dereference, function pointer.
6. **Privilege & control** — writes to role/ownership/flags, vtable/handler/dispatch table,
   redirect destination.
7. **Resource** — unbounded alloc/loop/recursion, lock/fd acquisition.

> **Known blind spot — read this.** The structural sink set built by `build_code_model.sh`
> is high-signal only (sql / command / code-eval / deserialization / file-path / ssrf-net /
> redirect). Groups 4, 5, 6, and 7 are **not** in the default ledger. Either re-run the build
> with `TF_NOISY_SINKS=1`, or enumerate them by hand with
> `callgraph.py --callers <symbol>`. "The ledger had no sink" is not evidence of safety for
> those four groups.

---

## 4. Propagation & reachability — the edges that are not data flow

Taint is one edge type. Trace all six:

1. **Trust-boundary transition** — unauthenticated → authenticated resource, tenant A →
   tenant B, low-trust store → high-trust consumer.
2. **Control-flow skip** — an exception, bailout, `longjmp`, early return, or retry that
   jumps over a check or a cleanup. *A check on the happy path may not exist on the error
   path.* Trace the error path separately (§5 P6).
3. **Lifetime edge** — alloc → free → same address reallocated. Where UAF lives; classic
   taint analysis cannot see it.
4. **Scope transition** — request A taints state that request B, worker B, or a later job
   consumes (persistent state, SHM, cache, DB round trip).
5. **Concurrency interleaving** — another thread/request writes between check and act.
6. **Bidirectional call graph** — forward from each source (*where does it land?*) **and**
   backward from each dangerous operation (*what reaches it?*). Doing only one direction is
   exactly the source/sink bias of Premise 1.

```bash
callgraph.py --forward '<source_or_handler_symbol>' -d 8   # source → ?
callgraph.py --callers <dangerous_symbol>                  # ? → sink
callgraph.py --trace   <dangerous_symbol> -d 8             # backward paths
```

Edges 2–5 are not in the graph. They come from reading the code.

---

## 5. MANDATORY passes — skip one and you will miss that whole family

One finding is never the end. Run every pass to exhaustion, driven by
`proof_ledger.py --next` / `coverage.py --next`, not by feel.

| # | Pass | What "done" means | Owner |
|---|---|---|---|
| P1 | **Entry × privilege map** — every entry point gets the lowest privilege that reaches it, and the sensitive operations that privilege can touch. Pre-auth reachability is proven with a call chain. | every ledger route unit has a privilege | B |
| P2 | **Guard audit on privileged operations** (shape B) — for every operation needing ownership, role, state, or payment: does an authz/ownership/state check actually sit on *that* path, on *every* caller? | every privileged op has finding / safe+evidence / needs_reanalysis | B |
| P3 | **Invariant-violation sweep** — for each invariant from §0: is there an input, ordering, or concurrency that breaks it? | every invariant in `HYPOTHESES.json` is verified or refuted | B |
| P4 | **Long-lived lifetime sweep** — for every global or long-lived field holding a pointer, handle, fd, or lock: (a) where is it released, (b) where is it reset, (c) can a bailout happen in between? All three true = candidate. | every such field triaged | A |
| P5 | **Taint → every sink family** — forward every source from §1 into **all seven** groups of §3, especially the disclosure sinks (headers/cookies/logs/timing) and SSRF. | every enumerated sink unit has a disposition | A |
| P6 | **Error/exception path diff** — diff the set of checks and cleanups that run on the success path against the failure path. A skipped check is a bypass; a skipped release is a leak or a dangling reference. | every guarded operation with a failure path diffed | A + B |
| P7 | **Cross-scope & concurrency topology** — re-judge reachability assuming request reuse, worker reuse, and concurrent execution. | every stateful operation judged under reuse | A + B |

P4, P6, and P7 have no tool support in this repo. They are read-the-code passes, and they
are where the bugs that survived the scanners live.

---

## 6. Guardrails — the methodology traps

- **Run both shapes.** Chasing only source→sink drops access control, authentication, and
  logic entirely.
- **No source-only verdicts.** An information leak or a UAF read is not a defect until it
  reaches an observation point (§3 group 4) or a dangerous operation. Without that leg it is
  a `lead` (`leads.py`), not a finding. Say which it is.
- **Don't stop at the first hit.** Defects cluster. Sweep every other instance of the same
  signature before moving on.
- **Instrumentation ≠ defect.** A crash that only happens under a sanitizer, a debug
  assertion, a diagnostic probe, or a patched build is a lead. Replay on the exact stock
  build before it is a finding, and record which build each observation came from
  (`repro.instrumentation_only`, `repro.stock_replay`).
- **Separate preconditions from the bug.** State whether the precondition holds in the
  default/vendor-shipped configuration; if not, name the exact non-default setting
  (`preconditions`).
- **Prove the escalation ceiling; don't assume it.** read → write, crash → control,
  self → other user: each step is proven or it is not claimed. If it does not escalate, nail
  it down as "DoS only", "read-only", "self-only" (`primitive.escalation_ceiling`,
  `primitive.ruled_out`). Over-packaging is a reporting defect.
- **Reachability means entry point *and* privilege.** "Who can trigger this" is answered
  with a call chain plus a role, never with a guess (`reachability`).
- **One root cause, one finding.** Trigger variants are reproduction cases on the same
  finding. If one patch fixes both, it is one finding — share a `correlation_id`.

---

## 7. Output contract — the schema *is* the report format

Do not write prose findings. Every element below is a field in
`schemas/finding.schema.json`, written through `write_finding.py`:

| Element | Field |
|---|---|
| class tag + CWE | `vuln_class`, `cwe` |
| which shape | `defect_shape` |
| mechanism | `evidence` |
| SOURCE → SINK | `source`, `sink`, `flow[]` (shape A) |
| missing control, and the path it is missing from | `missing_control{control,expected_at[],unguarded_path,actor}` (shape B) |
| reachability (entry point, privilege, pre-auth, call chain) | `reachability{entry_point,min_privilege,pre_auth,call_chain[]}` |
| preconditions (default vs non-default) | `preconditions{default_configuration,required_settings[],notes}` |
| primitive and escalation ceiling | `primitive{kinds[],escalation_ceiling,ruled_out[]}` |
| affected assets | `assets_affected[]` |
| reproduction & reliability | `repro{poc,response,reliability,instrumentation_only,stock_replay}` |
| guards you ruled out | `sanitizers_seen[]` |

Class tags for `vuln_class` (kebab-case): `broken-access-control`, `auth-bypass`, `idor`,
`sql-injection`, `nosql-injection`, `command-injection`, `code-injection`, `ssti`, `xss`,
`ssrf`, `csrf`, `path-traversal`, `deserialization`, `xxe`, `open-redirect`, `use-after-free`,
`oob-read`, `oob-write`, `type-confusion`, `null-deref`, `toctou-race`, `crypto-misuse`,
`info-leak`, `dos`, `business-logic`, `misconfiguration`, `supply-chain`.

`write_finding.py` enforces the contract at `confirmed`: a finding cannot reach a terminal
reportable state without `reachability`, `preconditions`, and a stated escalation ceiling.

---

## 8. Pre-report self-check

- [ ] Threat model done first — entry points, trust boundaries, assets, invariants?
- [ ] Both shapes run? (Was the §5 P2 guard audit actually performed?)
- [ ] For every shape-A finding: all three legs written, none assumed?
- [ ] Swept the other instances of the same signature? (globals, invariants, privileged ops)
- [ ] Information disclosure traced to an output sink (header/cookie/log/timing)? SSRF sinks
      checked?
- [ ] Error/exception paths diffed for skipped checks and skipped cleanup?
- [ ] Cross-request / cross-worker / concurrent reuse considered?
- [ ] Real reproduction on a stock build, not an instrumentation artifact? Preconditions
      default?
- [ ] Reachability proven as "who, with what privilege"? Escalation ceiling pinned down with
      no over-packaging?
