# PostgreSQL pre-auth RCE research plan

## Eligibility boundary

The target is PostgreSQL 18.6 on TCP 5432 with password authentication enabled. The `demo` and
`postgres` passwords are for administration only and cannot appear in an eligible trace.

Before `ReadyForQuery`, the reachable protocol includes:

- initial length-prefixed StartupMessage;
- SSLRequest and GSSENCRequest negotiation;
- CancelRequest on a fresh connection;
- protocol version/options negotiation;
- startup parameter key/value parsing;
- the authentication exchange selected by `pg_hba.conf`, normally SASL/SCRAM for the stock image;
- TLS/GSS handshakes when enabled by the exact build/configuration.

Official references:

- [Frontend/backend message flow](https://www.postgresql.org/docs/current/protocol-flow.html)
- [Frontend/backend message formats](https://www.postgresql.org/docs/current/protocol-message-formats.html)

SQL parsing begins after authentication and is not an initial attack surface for this target.

## Disclosure-derived regression seeds

| Case | Primitive | Auth status | How to use it |
|---|---|---|---|
| [CVE-2026-6479](https://www.postgresql.org/support/security/CVE-2026-6479/) | Uncontrolled recursion in SSL/GSS negotiation | `PR:N`; TCP-reachable when both SSL and GSS are disabled, otherwise described for AF_UNIX | Highest-value state-transition regression: repeated and alternating negotiation messages |
| [CVE-2026-14679](https://www.postgresql.org/support/security/CVE-2026-14679/) | Stack buffer overflow in argument-name matching, writes only `0x00`/`0x01` | Vendor CVSS says `PR:N`, but description requires an object creator and OUT-parameter conditions | Memory-write pattern, not evidence of direct unauthenticated socket reachability |
| [CVE-2026-6473](https://www.postgresql.org/support/security/CVE-2026-6473/) | Integer wraparound, undersized allocation, OOB write, potential arbitrary code execution | Unprivileged authenticated database user (`PR:L`) | Arithmetic and 32-bit regression family; chain-only |
| [CVE-2013-1899](https://www.postgresql.org/support/security/CVE-2013-1899/) | Startup database name beginning with `-` reached backend command-line/config behavior | Unauthenticated file damage was possible; RCE additionally required a valid login and filesystem write | Canonical startup-parameter-to-runtime-configuration logic-chain seed |

The 2013 security FAQ gives the preconditions for the historical code-execution chain and is worth
keeping beside the corpus: [PostgreSQL 2013-04-04 security FAQ](https://www.postgresql.org/support/security/faq/2013-04-04/).

## Harness tracks

### P1 — initial packet/state machine

Use a compact action grammar that emits:

- StartupMessage with protocol major/minor and NUL-terminated key/value pairs;
- SSLRequest, GSSENCRequest, CancelRequest, and invalid request codes;
- TLS bytes or plaintext after an `S`/`N` negotiation result;
- repeated/alternating special requests on one socket and across reconnects.

Mutate:

- 32-bit declared length around 0, header size, maximum startup packet, and signed boundaries;
- protocol major/minor, request-code collisions, and endianness;
- missing final NUL, odd key/value count, duplicate keys, empty names/values, and trailing bytes;
- very long `user`, `database`, `options`, `application_name`, and `_pq_.*` names;
- leading `-`, embedded `=`, backslash, whitespace, high-bit bytes, and invalid encodings;
- repeated SSL/GSS requests, `SSL -> GSS -> startup`, `GSS -> SSL -> startup`, and negotiation loops;
- packet fragmentation at every 4-byte integer and NUL boundary.

### P2 — authentication exchange

Derive the actual method from the server response and mutate only messages legal before
AuthenticationOk:

- PasswordMessage type/length framing;
- SASL mechanism name, initial-response length, SCRAM attributes, nonce, channel binding, proof,
  extensions, and repeated continuation messages;
- GSS/SSPI response framing where compiled/configured;
- unexpected frontend message types during each auth state;
- disconnect/reconnect and partial messages between challenge and response.

Primary invariant: no AuthenticationOk, post-auth parameter application, or ReadyForQuery without
valid proof. Secondary oracle: no child backend sanitizer failure or abnormal exit.

### P3 — process-aware real daemon fuzzing

PostgreSQL isolates connections in child backends. Monitor all of:

- postmaster/container health;
- per-connection backend PID exit status;
- server log signatures and sanitizer output;
- restart loops, leaked shared state, and effects visible to a fresh control connection.

A clean postmaster with a dead child is still a crash. Conversely, an ordinary FATAL protocol
error and child exit is expected and must not be treated as a finding.

Use a fork-per-test or snapshot-at-postmaster-ready design initially. Only adopt in-process parsing
after source analysis identifies a safe reset boundary.

## Source-audit focus after checkout

- Startup packet length calculation, allocation, and NUL scanning.
- Dispatch among StartupMessage, SSLRequest, GSSENCRequest, and CancelRequest.
- Negotiation recursion/re-entry and counters fixed for CVE-2026-6479; search adjacent variants.
- Startup `options` and parameter application before/after authentication.
- Username/database canonicalization, truncation, and command-line/config translation.
- SASL/SCRAM message parsing, size conversions, channel binding, and error cleanup.
- Backend startup child lifecycle and state inherited from the postmaster.
- 32-bit-only allocation arithmetic related to the CVE-2026-6473 class.

## Exit criteria

- All initial request codes and legal/illegal transitions have state coverage.
- Corpus distinguishes expected FATAL child termination from memory corruption.
- SQL-level or object-creator bugs remain post-auth unless a separate pre-auth bypass is proven.
- A final candidate replays byte-for-byte against the exact PostgreSQL image digest without any
  successful password exchange.

