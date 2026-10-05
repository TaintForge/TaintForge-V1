# Redis pre-auth RCE research plan

## Eligibility boundary

The target is Redis 8.10.2 on TCP 6379 with `requirepass` enabled. No password or authenticated
connection may be used in the candidate path. The provided password is only for health checks.

Before authentication, useful reachable code is expected to concentrate in:

- TCP/TLS-independent stream handling and request accumulation;
- inline and RESP request framing, numeric length parsing, bulk allocation, and argv construction;
- command lookup/arity and the authentication gate;
- `AUTH` and `HELLO ... AUTH ...` parsing/state changes;
- connection close/reset/error paths and pipelined requests around authentication failure.

Most data-structure, Lua, module, persistence, and serialized-value parsers sit after the command
authorization gate. They are chain primitives, not initial entry points.

Protocol reference: [Redis serialization protocol specification](https://redis.io/docs/latest/develop/reference/protocol-spec/).

## Disclosure-derived regression seeds

| Case | Primitive | Auth status | How to use it |
|---|---|---|---|
| [CVE-2023-41056 / GHSA-xr47-pcmx-fq2m](https://github.com/redis/redis/security/advisories/GHSA-xr47-pcmx-fq2m) | Incorrect buffer-resize accounting, heap overflow, potential RCE | `PR:N` in the vendor CVSS; affected 7.0.9 and 7.2.x | Highest-value direct pre-auth memory-accounting pattern; recover the fixed path after source import and make it a regression corpus family |
| [CVE-2025-49844 / GHSA-4789-qfc9-5f9q](https://github.com/redis/redis/security/advisories/GHSA-4789-qfc9-5f9q) | Lua GC use-after-free, potential RCE | Authenticated (`PR:L`) | Exploitation-pattern corpus only; useful after a pre-auth auth-state bypass |
| [GHSA-rp2m-q4j6-gr43](https://github.com/redis/redis/security/advisories/GHSA-rp2m-q4j6-gr43) | HyperLogLog integer overflow leading to OOB write | Authenticated | Arithmetic/write primitive class, not an eligible standalone route |
| [GHSA-jhjx-x4cf-4vm8](https://github.com/redis/redis/security/advisories/GHSA-jhjx-x4cf-4vm8) | `XACKDEL` count mismatch leading to stack overflow | Authenticated | Count/vector mismatch pattern for parser and command metadata audit |
| [GHSA-c8h9-259x-jff4](https://github.com/redis/redis/security/advisories/GHSA-c8h9-259x-jff4) | Malformed `RESTORE` serialized value, unsafe memory access, potential RCE | Authenticated | Serialized-object parser primitive; chain-only |
| [GHSA-93m2-935m-8rj3](https://github.com/redis/redis/security/advisories/GHSA-93m2-935m-8rj3) | Blocked-client eviction/re-execution use-after-free | Authenticated | Lifetime/state-transition pattern; chain-only |

The key research question is not “can these authenticated bugs be replayed?” It is whether an
unauthenticated transcript can either reach an equivalent unsafe parser or desynchronize the
authentication state enough to unlock one.

## Harness tracks

### R1 — raw request parser

Feed the request buffer processor with a fake unauthenticated client and reset all client/global
state after each case. Seed with:

- valid inline command and valid RESP2 multibulk command;
- RESP2/RESP3 `HELLO`, `AUTH`, and malformed combinations;
- zero, negative, oversized, and digit-overflow array/bulk lengths;
- bulk payload one byte shorter/equal/longer than declared;
- CR/LF split across reads;
- very large argc with tiny elements and tiny argc with huge elements;
- valid command followed by an incomplete second command;
- alternating inline and multibulk frames in one query buffer.

Use ASan+UBSan, comparison tracing, allocator perturbation, and both jemalloc and libc allocator
builds where supported.

### R2 — auth-gate state invariant

Instrument the state immediately before command dispatch. Assert that no command outside the
explicit pre-auth allowlist reaches its implementation while the connection is unauthenticated.
Mutate:

- `AUTH` arity and ACL username/password forms;
- `HELLO` protocol version plus repeated/missing `AUTH` option values;
- pipelined `HELLO`, `AUTH`, disallowed commands, `RESET`, and `QUIT`;
- failed authentication followed by protocol switch or parser error;
- duplicate options, case changes, embedded NUL/high-bit bytes, and huge argument counts.

The strongest logic result is not an unusual error message; it is a forbidden command-dispatch
edge or authenticated flag without successful secret verification.

### R3 — real daemon transcript fuzzing

Replay minimized R1/R2 inputs over loopback against:

1. sanitizer build matching 8.10.2;
2. stock `redis:latest` pinned to the captured amd64 digest.

Mutate fragmentation and pipelining independently from payload bytes. A server process death,
sanitizer report, or auth invariant violation is retained. Ordinary `NOAUTH` and protocol errors
are expected and discarded unless they create a new state/coverage edge.

## Source-audit focus after checkout

- Query-buffer growth, `size_t`/signed conversions, multibulk and bulk-length arithmetic.
- Ownership of argv objects across parse errors, command rewrite, blocked clients, and reset.
- Authentication check ordering relative to command lookup, arity checks, subcommand parsing, and
  module hooks.
- `HELLO` option parsing and partial state updates when later options fail.
- Error paths that leave protocol version, ACL user, parser mode, or pending command state changed.
- Recent fixes involving resize bookkeeping, UAF, and count/vector disagreement for variant bugs.

## Exit criteria

- Every pre-auth parser/state transition is represented in corpus coverage.
- No stock-image effect is classified above crash without a byte-exact unauthenticated transcript.
- Any route into Lua, RESTORE, HLL, streams, modules, or persistence must prove how the password
  gate was bypassed before it is treated as a competition candidate.

