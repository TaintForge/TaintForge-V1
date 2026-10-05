# ZeroDay Cloud 2026: database pre-auth RCE harness plan

Captured on 2026-09-26 (Asia/Seoul).

## Success condition

The campaign is successful only when an exact competition image can be made to execute
`/flag.sh <target>` without a password, credential, or authenticated session.

Priority:

1. Direct pre-auth remote code execution.
2. Pre-auth authentication/state bypass chained into a post-auth RCE primitive.
3. Authenticated RCE is research material only and is not an eligible result by itself.

Crashes, sanitizer reports, authentication bypasses, and file-write primitives are useful
milestones, but none is reported as RCE until the command-execution boundary is reproduced on
the unmodified competition image.

The three official target READMEs say exactly this:

- [Redis competition target](../../targets/zeroday-cloud-2026/redis/README.md)
- [MariaDB competition target](../../targets/zeroday-cloud-2026/mariadb/README.md)
- [PostgreSQL competition target](../../targets/zeroday-cloud-2026/postgresql/README.md)

## Target snapshot

The competition compose files use floating `latest` tags. The snapshot below therefore records
both the visible version and immutable amd64 digest. Re-capture this table at the beginning and
end of every fuzzing campaign.

| Target | TCP | Observed `latest` | OCI index digest | linux/amd64 manifest |
|---|---:|---|---|---|
| Redis | 6379 | 8.10.2 | `sha256:718f745deb7dfefeac6eed7041fc7ec9476b50e61b247932682457c41adafa0e` | `sha256:7ef5b5cec96495a04ca7feff88a9492efeab8053fb284d24bdd73344c9245a48` |
| MariaDB | 3306 | 13.0.2-resolute | `sha256:d4fdec0510ad498e4f3127da30a99df3745bd6d5e611ae6ac5f76403d9284a8d` | `sha256:6fbfe8d506c67660f81ec9859e45080ec6df6bd5ecdc761b82a33906179147cd` |
| PostgreSQL | 5432 | 18.6 | `sha256:5a5a84b19854a9ffaa54082c166ff4ec27473a361e496e5ea167f298f2da9722` | `sha256:0377e72c5289ed2f98cf61b1a9c2db9eb9d300317fe14244492fbc94343b3d04` |

See [target-matrix.yaml](target-matrix.yaml) for the machine-readable copy.

## What the recent disclosures actually imply

Recent high-impact database bugs are useful as bug-class seeds, but most advertised “remote
RCEs” are not unauthenticated. We must keep three buckets separate:

| Bucket | Meaning | Competition use |
|---|---|---|
| Direct pre-auth | Reachable over the target TCP port before any successful authentication | Eligible primitive |
| Conditional pre-auth | Parsed before auth succeeds, but requires a named account, configured plugin, TLS/GSS mode, or another deployment condition | Eligible only if the stock target satisfies the condition without a secret |
| Post-auth | Requires an authenticated command, SQL expression, stored object, or privileged configuration | Chain material only |

This distinction prevents us from spending the campaign rediscovering a strong memory primitive
that the password gate makes unreachable.

## Common harness architecture

Use two complementary harnesses. Neither replaces the other.

### 1. In-process, coverage-guided parser harness

- Build an exact source tag with Clang and ASan+UBSan first; add MSan and a 32-bit build where
  dependencies permit it.
- Link a wrapper outside `targets/` to the smallest pre-auth parser/state transition entry point.
- Keep `targets/` immutable. Build products and generated source copies belong under `.labs/`.
- Feed one compact transcript per fuzz case, not merely one packet.
- Use protocol dictionaries, comparison tracing/value profiles, and a minimized seed corpus.
- Reset all connection/global state between iterations. If that cannot be guaranteed, use a
  fork-per-case harness instead of persistent mode.

libFuzzer is in-process and coverage-guided, and its own documentation recommends combining it
with ASan/UBSan and structured seed corpora. AFL++ recommends replacing the real network with
stdin/shared memory for throughput, while retaining a separate real-network replay stage:

- [LLVM libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html)
- [AFL++ network-service guidance](https://aflplus.plus/docs/best_practices/)
- [AFL++ persistent mode](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.persistent_mode.md)
- [OSS-Fuzz integration guide](https://github.com/google/oss-fuzz/blob/master/docs/getting-started/new_project_guide.md)

### 2. Stateful wire harness against the real daemon

Run only against the local challenge container or the local sanitizer build. A testcase is an
action transcript:

```text
CONNECT
RECV(server greeting or one-byte negotiation result)
SEND(fragment plan, bytes)
OPTIONAL START_TLS | HALF_CLOSE | RECONNECT
SEND(...)
EXPECT(response class, not exact nondeterministic bytes)
```

Mutate both content and transport behavior:

- declared length versus actual length;
- boundary lengths around 0, 1, signed limits, allocation thresholds, and maximum packet sizes;
- truncation at every field boundary;
- coalesced packets, byte-wise fragmentation, duplicate messages, and pipelining;
- state-transition reordering, repeated negotiation, reconnect, half-close, and timeout;
- capability flags that disagree with the fields actually present;
- embedded NUL, CRLF, invalid UTF-8, high-bit bytes, and unusually long identifiers;
- valid prefixes followed by malformed trailing data.

AFLNet and StateAFL are useful references for state feedback and replayable transcripts, but the
first implementation should remain small and target-specific:

- [AFLNet](https://github.com/aflnet/aflnet)
- [StateAFL](https://github.com/stateafl/stateafl)

## Oracles

Every run records the exact digest, build flags, seed hash, transcript, response classes, daemon
logs, and exit status. Interesting outcomes are:

1. ASan/MSan/UBSan finding, abort, signal, child-process crash, or reproducible hang.
2. Allocation-size or index arithmetic divergence between 64-bit and 32-bit builds.
3. Different state/result between debug and release, TLS and plaintext, or instrumented and stock
   builds for the same legal transcript.
4. Any transition into an authenticated/ready state without the secret.
5. Any command/SQL execution, file effect, module/library load, or child process before auth.

PostgreSQL commonly loses only a per-connection backend, so “main container still healthy” is not
a clean result. Watch child exits and server logs. Redis is normally a single server process, so
global state cleanup and restart speed matter. MariaDB may keep worker threads alive after a
connection failure, so sanitizer output and per-connection state are primary oracles.

## Crash-to-RCE triage

For each minimized crash, answer in order:

1. Did every attacker-controlled byte arrive before successful authentication?
2. Is the effect read, write, free/use-after-free, stack exhaustion, or pure resource exhaustion?
3. For a write, are destination, offset, size, and byte values controllable?
4. Is the primitive deterministic with allocator perturbation and multiple ASLR runs?
5. Does it reproduce on the exact digest without sanitizer instrumentation?
6. Can it reach code execution under the container's actual mitigations and service UID?
7. Can the final stock-image PoC execute the target's `/flag.sh` command?

Only steps 1-5 promote a crash to an exploitation candidate. Step 7 is the final proof.

## Initial campaign order

| Priority | Target/track | Reason |
|---|---|---|
| P0 | MariaDB handshake/auth-plugin state machine | Largest conditional grammar; capability-controlled layouts and multi-round plugins have recent pre-auth parser failures |
| P0 | PostgreSQL startup + SSL/GSS + SASL/SCRAM | Small, enumerable state space; recent unauthenticated negotiation recursion makes transition fuzzing high-value |
| P1 | Redis RESP parser + pre-auth command gate | Extremely fast parser harness, but password protection blocks most command-specific parsers |
| P1 | Cross-target auth-state invariant harness | Detects “ready/authenticated without proof” logic failures that unlock known post-auth RCE primitives |
| P2 | 32-bit and allocator-diversity matrix | Targets integer wraparound, truncation, and allocator-sensitive UAF/overflow behavior |

The detailed plans are in [mariadb.md](mariadb.md), [postgresql.md](postgresql.md), and
[redis.md](redis.md).

## Next implementation checkpoint

1. Re-snapshot the images and pin source tags under `targets/`.
2. Build a TaintForge Code Model for each source tree before manual source analysis.
3. Implement the shared transcript/replay/minimization library under `.labs/preauth-rce/`.
4. Bring up exact stock images and separate ASan/UBSan builds.
5. Land P0 MariaDB and PostgreSQL wire harnesses, then target-specific in-process harnesses.
6. Run all three campaigns concurrently while the existing LiteLLM five-agent audit continues.

