# MariaDB pre-auth RCE research plan

## Eligibility boundary

The target is MariaDB 13.0.2 on TCP 3306 with authentication enabled and `LOCAL INFILE` disabled.
The `demo` and `root` passwords cannot appear in an eligible path. A username field is ordinary
pre-auth protocol input, but a finding that requires a successful login is post-auth and invalid.

The server first sends a greeting. The client then sends either an SSLRequest followed by a TLS
handshake and Handshake Response, or a plaintext Handshake Response. Capability bits control the
layout of authentication data, database name, plugin name, and connection attributes. An auth
plugin can then conduct multiple additional rounds.

Official protocol reference: [MariaDB connecting protocol](https://mariadb.com/docs/server/reference/clientserver-protocol/1-connecting/connection).

## Why this is P0

This is the richest pre-auth grammar of the three targets:

- 3-byte packet lengths plus sequence IDs;
- client/server capability intersections;
- SSL mode switch in the middle of the connection;
- NUL-terminated, fixed-length, and length-encoded fields selected by flags;
- account lookup and server-selected authentication plugin dispatch;
- optional database, plugin name, and arbitrary key/value connection attributes;
- multi-round plugin-specific messages and authentication switches.

Every disagreement between a capability bit, packet boundary, and inner length is a candidate for
truncation, stale pointer, integer-wrap, and parser-desynchronization bugs.

## Disclosure-derived regression seeds

| Case | Primitive | Auth status | How to use it |
|---|---|---|---|
| [MDEV-38365 / CVE-2026-35549](https://jira.mariadb.org/browse/MDEV-38365) | Large `caching_sha2_password` auth packet flows into `sha256_crypt_r()`/`alloca()`, exhausting stack | Authentication not yet successful, but an account configured for that plugin is required; CVSS records `PR:L` | Direct auth-message length regression seed; first verify whether the exact target exposes this plugin/account path |
| [CVE-2026-32710 / GHSA-4rj5-2227-9wgc](https://github.com/MariaDB/server/security/advisories/GHSA-4rj5-2227-9wgc) | `JSON_SCHEMA_VALID()` heap overflow, possible RCE | Authenticated (`PR:L`) | Heap-corruption pattern and exploitation primitive only; not a starting point |
| [CVE-2016-6662 vendor note](https://mariadb.com/resources/blog/is-your-mariadb-version-affected-by-the-remote-root-code-execution-vulnerability-cve-2016-6662/) | Configuration injection leading toward server-context code execution | Requires capabilities beyond an unauthenticated socket | Logic-chain reference only |
| CVE-2012-2122 | Authentication result misinterpretation could probabilistically accept a wrong password on affected historical builds | Pre-auth authentication bypass | Historical must-have regression pattern: compare result width/sign, boolean conversion, and partial-success state |

Recent wsrep/SST command and parameter injection advisories do not match the stock single-node
compose configuration and are lower priority unless source analysis finds the same unsafe helper
reachable during an ordinary connection.

MariaDB's maintained CVE index is [here](https://mariadb.com/docs/server/security/cve/community-server).

## Harness tracks

### M1 — packet and capability grammar

Represent a connection as server greeting metadata plus a sequence of client packets. Start from
valid Handshake Responses and mutate:

- outer 24-bit payload length around actual length and maximum-packet boundaries;
- sequence ID 0, expected ID, wraparound, duplicate, skip, and restart;
- capability bits individually and in contradictory combinations;
- SSLRequest-sized prefixes with trailing plaintext, truncated TLS, or a second Handshake Response;
- missing/late NUL in username, database, and plugin name;
- all three auth-response encodings: length-encoded, one-byte length, and NUL-terminated;
- length-encoded integer marker boundaries and non-canonical forms;
- connection-attribute total size versus key/value lengths and remaining packet bytes;
- packet fragmentation, aggregation, zero-length packets, and exact 16 MiB boundary behavior.

### M2 — authentication plugin state machine

Use the stock target's actual account/plugin map as the ground truth. Seeds should include existing
usernames with deliberately invalid proofs and nonexistent usernames. No successful password is
needed or allowed in candidate traces.

Track:

- server-selected versus client-advertised plugin disagreement;
- authentication switch loops and repeated plugin data;
- empty, one-byte, maximum-length, and fragmented plugin responses;
- plugin return-code/error paths that may leave security context partially initialized;
- TLS-required plugin behavior before and after an invalid SSL transition;
- lifetime of auth buffers across plugin switch, account lookup failure, and disconnect;
- compare return values, signedness, truncation, and “error treated as success” branches.

For discovery only, an instrumented lab build may create accounts for each compiled plugin to gain
coverage. Any candidate must then replay against the unmodified stock competition image; a custom
account or plugin configuration cannot be part of the final result.

### M3 — real daemon and differential oracle

Run each minimized transcript against:

- debug ASan+UBSan build;
- release ASan build;
- exact stock amd64 digest;
- TLS enabled/disabled discovery variants, while retaining only stock-reproducible candidates.

Compare response class, connection state, worker/thread survival, sanitizer logs, and whether an
OK/authenticated session appears without a valid proof. A normal access-denied response is not an
interesting result unless the same transcript first caused a sanitizer or state divergence.

## Source-audit focus after checkout

- VIO packet read/reassembly and 24-bit length arithmetic.
- Handshake Response parsing under capability-controlled optional fields.
- Length-encoded integer/string helpers and end-pointer discipline.
- Authentication plugin registry, account lookup, plugin switch, and multi-round callbacks.
- Security-context initialization/rollback and success/error return conventions.
- TLS upgrade ownership and buffered plaintext surviving the mode switch.
- Connection attributes: aggregate length, repeated keys, nested allocation, charset conversion.
- New 13.x protocol/authentication code and fixes adjacent to MDEV-38365.

## Exit criteria

- Corpus covers every field-layout selected by capability flags and every stock auth plugin path.
- Conditional plugin crashes are labeled with their exact account/configuration prerequisite.
- A promoted candidate proves either memory corruption before auth or an auth-state transition
  without a valid proof; authenticated SQL-only crashes remain chain material.

