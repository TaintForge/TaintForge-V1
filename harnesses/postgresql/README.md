# PostgreSQL pre-auth wire harness

This loopback-only harness exercises the unauthenticated startup state machine without using the
competition's health-check credentials. It covers StartupMessage, SSLRequest, GSSENCRequest,
CancelRequest, framing/length edge cases, deterministic byte mutations, premature authenticated
states, and backend crash signals.

```bash
python3 harnesses/postgresql/pgwire_harness.py --port 55432
python3 harnesses/postgresql/pgwire_harness.py --port 55432 --iterations 1000 --seed 5907523
```

Only suspicious cases are persisted under `workspace/harness-artifacts/postgresql/`. A harness
signal is a lead, not a finding; reproduce it independently and trace it to source before using
`write_finding.py`.
