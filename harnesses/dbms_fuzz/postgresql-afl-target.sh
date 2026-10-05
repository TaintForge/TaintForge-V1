#!/usr/bin/env bash
# AFL target boundary: one instrumented PostgreSQL single-user backend per SQL input.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
POSTGRES="$ROOT/.labs/db-fuzz/install/postgresql-afl-stable/usr/local/pgsql/bin/postgres"
PGDATA="${DBFUZZ_PGDATA:?DBFUZZ_PGDATA must name a private AFL worker data directory}"
INPUT="${1:?usage: postgresql-afl-target.sh INPUT.sql}"

case "$(realpath -m -- "$PGDATA")" in
  "$ROOT"/workspace/db-fuzz/postgresql-afl/workers/*) ;;
  *) echo "refusing non-campaign PGDATA: $PGDATA" >&2; exit 2 ;;
esac

[ -x "$POSTGRES" ] || { echo "missing instrumented postgres: $POSTGRES" >&2; exit 3; }
[ -s "$PGDATA/PG_VERSION" ] || { echo "invalid worker PGDATA: $PGDATA" >&2; exit 3; }
[ -f "$INPUT" ] || { echo "missing AFL input: $INPUT" >&2; exit 3; }

# A killed standalone backend can leave only this exact worker-local lock file.
rm -f -- "$PGDATA/postmaster.pid"

exec "$POSTGRES" --single -j -D "$PGDATA" -F \
  -c exit_on_error=on \
  -c default_transaction_read_only=on \
  -c jit=off \
  -c max_parallel_workers=0 \
  postgres < "$INPUT"
