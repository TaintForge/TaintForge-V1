# DBMS memory-corruption fuzzing

This local-only harness supports structured pre-auth wire fuzzing for Redis, MySQL, MariaDB,
PostgreSQL, and Oracle, plus low-privilege SQL executor fuzzing for the SQL engines. It records
new response/error states as corpus material and promotes only container/process changes or
sanitizer signatures as suspicious crash artifacts.

```bash
python3 harnesses/dbms_fuzz/dbfuzz.py doctor --engine postgresql
python3 harnesses/dbms_fuzz/dbfuzz.py wire --engine postgresql --iterations 1000
python3 harnesses/dbms_fuzz/dbfuzz.py wire --engine mariadb --iterations 1000
python3 harnesses/dbms_fuzz/dbfuzz.py minimize --case workspace/db-fuzz/wire/postgresql/<case>/case.json
```

Authenticated SQL mode reads its DSN from a mode-0600 file so credentials do not enter process
arguments or logs:

```bash
install -m 600 /dev/null workspace/db-fuzz/postgresql.dsn
# Edit the file locally: postgresql://lowpriv:...@127.0.0.1:55432/demo
DBFUZZ_DSN_FILE=workspace/db-fuzz/postgresql.dsn \
  python3 harnesses/dbms_fuzz/dbfuzz.py sql --engine postgresql --iterations 500
```

PostgreSQL's authenticated extended-query lane keeps Parse/Bind framing valid while mutating
binary parameter payloads for built-in type receive functions. It reads the same mode-0600 DSN
file and never places credentials in process arguments or artifacts:

```bash
DBFUZZ_DSN_FILE=.labs/db-fuzz/runtime/postgresql-asan/demo.dsn \
  python3 harnesses/dbms_fuzz/dbfuzz.py postgresql-binary \
  --container '' --sanitizer-log-glob '.labs/db-fuzz/runtime/postgresql-asan/sanitizer.*' \
  --iterations 500
```

`targets.json` contains only loopback endpoints and source locations. Adjust ports/container names
to match local labs. Oracle defaults to black-box TNS/SQL operation because normal Oracle builds
do not provide instrumentable server source. MySQL source must be supplied separately; MariaDB is
not treated as a byte-identical substitute after the shared handshake prefix.

Repeat `--engine` to inspect several engines. Omitting it checks every manifest entry, so scoped
campaigns should always pass their explicit engine list.

For an instrumented source build, inspect the command first:

```bash
harnesses/dbms_fuzz/build-instrumented.sh \
  --engine postgresql --source targets/zdc-2026-postgresql-18.6 --mode asan --dry-run
```

The script copies source to `.labs/db-fuzz/source/` before building. `--mode afl` requires AFL++
compiler wrappers. AFL++ is useful only when server coverage reaches the shared map or an
in-process parser/executor target exists; fuzzing an uninstrumented remote daemon through an AFL
client measures the client and is not considered coverage-guided server fuzzing.

For PostgreSQL memory-safety work, start the copied ASan+UBSan build on the dedicated loopback
port after compilation and a local staged install:

```bash
make -C .labs/db-fuzz/source/postgresql-zdc-2026-postgresql-18.6-asan install \
  DESTDIR="$PWD/.labs/db-fuzz/install/postgresql-asan"
harnesses/dbms_fuzz/postgresql-instrumented.sh start
python3 harnesses/dbms_fuzz/dbfuzz.py wire \
  --engine postgresql --host 127.0.0.1 --port 55434 --container '' \
  --sanitizer-log-glob '.labs/db-fuzz/runtime/postgresql-asan/sanitizer.*' \
  --iterations 1000
```

The runtime creates a passwordless local-trust `demo` role only inside the diagnostic cluster and
writes its mode-0600 DSN to `.labs/db-fuzz/runtime/postgresql-asan/demo.dsn`. Any candidate must
still be minimized and replayed on the exact stock target before promotion.

The PostgreSQL campaign first derives rollback-wrapped seeds from upstream regression, contrib,
and isolation tests. It validates every statement against the loopback ASan server, splits the
result into independently executable `fast` seeds and multi-statement `stateful` seeds, and uses
a PostgreSQL-aware AFL++ Python mutator instead of blind byte havoc:

```bash
python3 harnesses/dbms_fuzz/postgresql-corpus.py
```

The focused AFL++ lane instruments the PostgreSQL backend itself, so the shared map is server
coverage rather than coverage of a network client:

```bash
harnesses/dbms_fuzz/postgresql-afl-campaign.sh init
harnesses/dbms_fuzz/postgresql-afl-campaign.sh start
tmux attach -t taintforge-pg-afl
```

The tmux session has eight windows:

- `fast-main` and `fast-s1`: read-only parser/planner/type-function exploration.
- `state-main`: rollback-scoped DDL/DML/executor sequences.
- `state-jit`: the stateful lane with JIT and parallel workers enabled.
- `preauth`: bounded startup, SSL, GSS, SASL/SCRAM, length, and truncation mutations against the
  loopback ASan daemon.
- `binary`: authenticated low-privilege Parse/Bind execution with valid outer framing and bounded
  mutations of binary array, range, numeric, JSON, text-search, network, and scalar values.
- `triage`: automatic ASan+UBSan replay of AFL crash artifacts.
- `dashboard`: corpus, worker, coverage, crash, and wire-campaign status.

Each AFL worker has a private cluster under `workspace/db-fuzz/postgresql-afl/workers-v2/`.
Generated corpora live under `corpus-v2/`; when `corpus-v2-min-next/READY` exists, the campaign
selects its edge-minimized subset automatically. New AFL output is kept separate under
`output-v2-fast/` and `output-v2-stateful/`, preserving earlier runs. Triage classifications are
stored under `workspace/db-fuzz/postgresql-afl/triage/`. Sanitizer or abnormal replays remain
leads until minimized and reproduced against the exact stock server.

The optional agent session keeps the evidence-gated roles separate. C consumes only
sanitizer/abnormal replay artifacts, E consumes only `needs_reanalysis` findings, D consumes only
reproduced/confirmed findings, and F periodically reviews live coverage/rejection/stability data
to make one evidence-backed harness or corpus self-repair at a time. C and E use GPT-6 Sol xhigh;
D and F use Daybreak Blue max:

```bash
harnesses/dbms_fuzz/postgresql-afl-agents.sh start
tmux attach -t taintforge-pg-agents
```
