#!/usr/bin/env bash
# Manage the local-only PostgreSQL ASan+UBSan runtime used for memory-safety fuzzing.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BUILD="${DBFUZZ_PG_BUILD:-$ROOT/.labs/db-fuzz/source/postgresql-zdc-2026-postgresql-18.6-asan}"
INSTALL="${DBFUZZ_PG_INSTALL:-$ROOT/.labs/db-fuzz/install/postgresql-asan/usr/local/pgsql}"
RUNTIME="${DBFUZZ_PG_RUNTIME:-$ROOT/.labs/db-fuzz/runtime/postgresql-asan}"
DATA="$RUNTIME/data"
LOG="$RUNTIME/server.log"
DSN="$RUNTIME/demo.dsn"
PASSWORD_FILE="$RUNTIME/demo.password"
PORT="${DBFUZZ_PG_PORT:-55434}"

POSTGRES="$INSTALL/bin/postgres"
INITDB="$INSTALL/bin/initdb"
PG_CTL="$INSTALL/bin/pg_ctl"
PSQL="$INSTALL/bin/psql"

export ASAN_OPTIONS="abort_on_error=1:disable_coredump=0:detect_leaks=0:log_path=$RUNTIME/sanitizer"
export UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1:log_path=$RUNTIME/sanitizer"

require_build() {
  for binary in "$POSTGRES" "$INITDB" "$PG_CTL" "$PSQL"; do
    [ -x "$binary" ] || { echo "instrumented build is incomplete: $binary" >&2; exit 3; }
  done
}

init_runtime() {
  require_build
  mkdir -p "$RUNTIME"
  if [ ! -s "$DATA/PG_VERSION" ]; then
    "$INITDB" -D "$DATA" -U tf_fuzz_admin --auth-local=trust --auth-host=trust --no-instructions
  fi
  if [ ! -s "$PASSWORD_FILE" ]; then
    umask 077
    openssl rand -hex 24 > "$PASSWORD_FILE"
  fi
  chmod 0600 "$PASSWORD_FILE"
  install -m 0600 /dev/null "$DSN"
  printf 'postgresql://demo:%s@127.0.0.1:%s/postgres\n' "$(<"$PASSWORD_FILE")" "$PORT" > "$DSN"
}

start_runtime() {
  init_runtime
  if "$PG_CTL" -D "$DATA" status >/dev/null 2>&1; then
    echo "already running on 127.0.0.1:$PORT"
  else
    "$PG_CTL" -D "$DATA" -l "$LOG" \
      -o "-h 127.0.0.1 -p $PORT -F -c max_connections=32 -c shared_buffers=64MB -c logging_collector=off" \
      -w start
  fi
  SETUP_SQL="$RUNTIME/setup-role.sql"
  install -m 0600 /dev/null "$SETUP_SQL"
  printf '%s\n%s\n' \
    "DO \$\$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='demo') THEN CREATE ROLE demo LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION; END IF; END \$\$;" \
    "ALTER ROLE demo PASSWORD '$(<"$PASSWORD_FILE")';" > "$SETUP_SQL"
  "$PSQL" -X -v ON_ERROR_STOP=1 -h /tmp -p "$PORT" -U tf_fuzz_admin -d postgres \
    -f "$SETUP_SQL" >/dev/null
  rm -f "$SETUP_SQL"
  sed -i -E '/^host[[:space:]]+all[[:space:]]+all[[:space:]]+(127\.0\.0\.1\/32|::1\/128)[[:space:]]+trust([[:space:]]|$)/ s/trust/scram-sha-256/' "$DATA/pg_hba.conf"
  "$PG_CTL" -D "$DATA" reload >/dev/null
  echo "instrumented PostgreSQL ready: 127.0.0.1:$PORT"
  echo "dsn_file=$DSN"
  echo "sanitizer_glob=$RUNTIME/sanitizer.*"
}

case "${1:-status}" in
  init) init_runtime ;;
  start) start_runtime ;;
  stop)
    require_build
    "$PG_CTL" -D "$DATA" -m fast -w stop
    ;;
  restart)
    "$0" stop || true
    "$0" start
    ;;
  status)
    require_build
    "$PG_CTL" -D "$DATA" status
    ;;
  paths)
    printf 'build=%s\ninstall=%s\nruntime=%s\ndsn=%s\nsanitizer_glob=%s\n' \
      "$BUILD" "$INSTALL" "$RUNTIME" "$DSN" "$RUNTIME/sanitizer.*"
    ;;
  *)
    echo "usage: $0 init|start|stop|restart|status|paths" >&2
    exit 2
    ;;
esac
