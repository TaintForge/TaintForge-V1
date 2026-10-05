# Supported NRBF compatibility differential lane

This lane exercises the .NET 10.0.12 `System.Formats.Nrbf` decoder and the supported
`System.Resources.Extensions` compatibility materializer together. It extracts only the official
`netcoreapp20` compatibility payloads from the exact target source. The clean replay tree contains
the exact source-built Release assemblies; SharpFuzz instrumentation is confined to a separate AFL
publish tree. Generation `v1` preserves the initial whole-pipeline instrumentation negative control,
whose framework callback and lazy-load paths produced variable coverage. Generation `v2` instruments
only the deterministic NRBF parser and keeps compatibility materialization stock as the behavior,
crash, and side-effect oracle.

Each candidate is bounded to 1 MiB and runs between clean `System.Int32` controls. Successful
materialization is consumed through a bounded graph probe, including decimal arithmetic,
`WeakReference.Target`, collection enumeration, and a bounded unmanaged-stream read. Unexpected
types, managed invariant faults, process signals, persistent file changes, newly loaded assemblies,
or a changed post-input control become signals. Expected malformed-input exceptions remain normal
outcomes. All executions use a fresh network namespace, so the target cannot send non-loopback or
external traffic. The `trace` command brackets the candidate with markers under `strace` for exact
file, network, and process-side-effect review.

The pre-existing invalid-decimal payload is a regression control, not a novel finding. Any AFL
crash remains a lead until it reproduces in the clean tree and has sanitizer/debugger evidence,
attacker reachability, a source root cause, and a Microsoft security boundary.
