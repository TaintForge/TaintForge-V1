# ldap_dn_oracle — negative-control oracle for patch-variant task `cc3e210b99471a78`

Covers CVE-2026-47300 (`LdapAdapter`, aspnetcore v8.0.28 → v8.0.29), whose fix is **fully
forward-ported** into stock `10.0.12`.

Replicates **verbatim** from
`targets/dotnet-aspnetcore-10.0.12/src/Security/Authentication/Negotiate/src/Internal/LdapAdapter.cs`:

| stock lines | replicated as |
|---|---|
| 17-18 | `DistinguishedNameSeparatorRegex` |
| 94 / 158 | `GroupCnFromDn` |
| 69 | `BuildUserFilter` |
| 177-206 | `EscapeLdapFilterValue` |

`targets/` is read-only and is never referenced at build time — the logic is copied in.

## Run

    dotnet run

## Sections

- **A** DN → role-claim CN parsing. The four shipped `LdapAdapterTests.cs` vectors are the
  negative control and must print `MATCH`; the `\\\,` vectors print `DIVERGE`.
- **B** first-RDN assumptions of `Substring("CN=".Length)`.
- **C** CN-only role claims colliding across containers.
- **D** filter-escaping bypass matrix — every vector must print `SAFE`.

## Known deviation

Only the **net8** SDK is installed here. Stock 10.0.12 declares the regex as a
`[GeneratedRegex]` *property* (C# 13 / net9+); this harness uses the equivalent *method*
form. The pattern string and regex-engine semantics are identical.

## Result (2026-10-03, owner H)

Section D is entirely `SAFE` — the escaping invariant is airtight. Section A's divergence is
fail-safe: the truncated CN keeps its trailing backslashes, so it cannot collide with a real
role name. No promotable candidate. See `leads.py note aspnetcore/Negotiate/LdapAdapter`.
