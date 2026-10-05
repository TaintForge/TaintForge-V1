# .NET bounty fuzzing harnesses

All targets are authorized local copies of the supported Microsoft .NET 10.0.12 release. The
read-only source under `targets/` is never modified. Build and instrumentation happen only under
`.labs/dotnet`, and generated corpora/findings live under `workspace/dotnet-bounty`.

## Kestrel HTTP/1 parser differential lane

`kestrel_http1` directly invokes the source-built `HttpParser<T>`. Every input is parsed as a
contiguous `ReadOnlySequence<byte>`, a patterned multi-segment sequence, and (for small inputs) a
byte-per-segment sequence. Unexpected exceptions and any difference in completion, consumption,
status, request-line metadata, or headers are AFL++ crashes. The active lane enables Kestrel's
strict CRLF switch so the already-isolated bare-LF short-header differential does not monopolize
the crash queue. The equivalent empty-value-header differential is narrowly suppressed after an
accepted parse records such a header. Original AFL states remain under the sibling `afl*`
directories in `workspace/dotnet-bounty/kestrel-http1/`.

```bash
harnesses/dotnet_fuzz/kestrel_http1/campaign.sh start
tmux attach -t taintforge-dotnet-fuzz
```

Publicly documented parser rejection is expected and is not a finding. A promoted candidate must
reproduce against an unmodified supported Kestrel build and demonstrate a security boundary or
memory-safety impact.

## Kestrel HTTP/1 body/framing lane

`kestrel_http1_body` starts the source-built, SharpFuzz-instrumented Kestrel Core assembly on an
ephemeral loopback port inside the AFL target process. Each test case is a complete raw HTTP/1
transcript; the application drains every request body so `Content-Length`, transfer-coding,
chunk-extension, trailer, and pipelined-request state is executed rather than merely parsing the
header text. The lane has its own tmux session and append-only AFL state, so it does not interrupt
the parser differential campaign.

```bash
harnesses/dotnet_fuzz/kestrel_http1_body/campaign.sh start
tmux attach -t taintforge-dotnet-kestrel-body
```

The confirmed bare-LF transport-boundary primitive can be replayed against the source-built
`PlaintextApp` listening on loopback port 5001:

```bash
python3 harnesses/dotnet_fuzz/kestrel_http1/repro_lf_boundary.py
```

## Microsoft-only analysis agents

Eight supervised roles run concurrently in visible tmux panes: Kestrel and CoreCLR hunters,
triage, proactive exploitability research, reanalysis, adaptive harness engineering, final
weaponization, and a dedicated official-patch variant hunter. Producer/exploitation roles use
Daybreak Blue at max effort; triage/reanalysis use GPT-6 Sol at xhigh effort. D begins with strong
leads and writes evidence dossiers; G accepts only confirmed primitives for final RCE chaining;
H mines Microsoft advisories and release diffs, then looks for distinct omissions and sibling
implementations in the current stock target.

The campaign is scoped to the supported Microsoft .NET 10.0.12 and ASP.NET Core 10.0.12 source
copies in this repository. Work is ordered by concrete evidence: the existing ReadyToRun native
pointer-write/OOB primitives, Kestrel cross-request framing and HTTP/2 accounting, supported
framework-owned deserialization, then ASP.NET Core path/routing/authentication invariants and
current templates/analyzers. The deserialization lane covers supported surfaces such as
System.Text.Json, System.Formats.Nrbf compatibility parsing, DataContractSerializer/XmlSerializer
input formatters, Blazor records, DataProtection descriptors, and output-cache formatting.

Generic .NET Framework gadget chains, System.Web cookieless markers, WebForms ViewState and public
MachineKeys, SoapFormatter, NetDataContractSerializer, TypeConfuseDelegate-only chains, and
deliberately misordered user middleware are excluded. Historical research in those areas may be
used only to derive mutation strategies or missing-invariant hypotheses for an in-scope supported
component; reproducing a known unsafe opt-in is not a finding.

The harness backlog is: richer HTTP/1 malformed framing plus paired-request oracles, structured
HTTP/2 stream/flow-control generation, supported serializer differential fuzzing, and PathBase /
IIS integration / endpoint-routing canonicalization differentials. A candidate is promoted only
with stock-build reproduction, clean controls, exact source root cause, security-boundary impact,
and a standalone PoC suitable for a complete MSRC report.

```bash
harnesses/dotnet_fuzz/dotnet-agents.sh start
tmux attach -t taintforge-dotnet-agents
```

## Official patch-variant lane

`patch_variants` periodically downloads the public GitHub security advisories for
`dotnet/runtime` and `dotnet/aspnetcore`, derives vulnerable-to-fixed release tag comparisons,
extracts risky source and regression-test hunks, and maps them onto the local 10.0.12 snapshots.
The resulting queue is claimable and preserves review results across refreshes.

```bash
harnesses/dotnet_fuzz/patch_variants/campaign.sh start
tmux attach -t taintforge-dotnet-patch-variants
```

A public fix is always a known control. It is promoted only if a distinct variant reproduces on
unmodified 10.0.12 with attacker reachability and a deterministic security-boundary oracle.

## Model backend

The runner drives either Claude Code or Codex. Pick with `TF_BACKEND`; everything
else (prompts, roles, logs, panes, the findings queue) is identical.

```bash
# Claude Code (default)
MAX_HOURS=12 TF_BACKEND=claude TF_MODEL=claude-opus-5 \
  ./harnesses/dotnet_fuzz/dotnet-agents.sh start

# Codex
MAX_HOURS=12 TF_BACKEND=codex \
  ./harnesses/dotnet_fuzz/dotnet-agents.sh start
```

| variable | default | applies to |
| --- | --- | --- |
| `TF_BACKEND` | `claude` | `claude` or `codex` |
| `TF_MODEL` | `claude-opus-5` / `gpt-daybreak-blue-latest` | main model |
| `TF_MODEL_REASON` | `gpt-6-sol` | reasoning-heavy roles C and E, **codex only** |
| `TF_ROLES` | `A B C D E F G H` | which roles to supervise |
| `MAX_HOURS` | `12` | campaign deadline |

`claude -p` exposes no reasoning-effort switch, so under the Claude backend every
role runs the same model and `TF_MODEL_REASON` is ignored.

### Panes

Each role gets a tmux pane running
`tail -F <role>.log | python3 -u .agents/stream_fmt.py`. The formatter renders
Claude's `stream-json` events as readable lines and passes Codex's plain text
through unchanged, so the same pane command works for both backends.

### Rate limiting

A session that dies in under 60 seconds is treated as an account rate limit rather
than real work, and the supervisor backs off geometrically (10s to 30 minutes)
instead of respawning every 10 seconds. A session that actually runs resets the
backoff. Watch for `died after Ns; backing off` in the role log.

Lower `TF_ROLES` to reduce burn: `TF_ROLES="A B C H"` runs the two producers,
triage, and the patch-variant lane, which is roughly half the consumption of the
full set.
