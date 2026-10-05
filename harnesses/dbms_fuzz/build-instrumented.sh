#!/usr/bin/env bash
# Copy an authorized DBMS source tree out of targets/ and print or run an instrumented build.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ENGINE=""
SOURCE=""
MODE="asan"
DRY_RUN=0

usage() {
  echo "usage: $0 --engine redis|postgresql|mysql|mariadb --source targets/<dir> [--mode asan|afl|afl-stable] [--dry-run]"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --engine) ENGINE="${2:?missing engine}"; shift 2 ;;
    --source) SOURCE="${2:?missing source}"; shift 2 ;;
    --mode) MODE="${2:?missing mode}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[ -n "$ENGINE" ] && [ -n "$SOURCE" ] || { usage >&2; exit 2; }
SOURCE_REAL="$(realpath -e -- "$SOURCE")"
case "$SOURCE_REAL" in
  "$ROOT"/targets/*) ;;
  *) echo "source must be under $ROOT/targets" >&2; exit 2 ;;
esac
case "$ENGINE" in redis|postgresql|mysql|mariadb) ;; *) echo "unsupported engine: $ENGINE" >&2; exit 2 ;; esac
case "$MODE" in asan|afl|afl-stable) ;; *) echo "unsupported mode: $MODE" >&2; exit 2 ;; esac

DEST="$ROOT/.labs/db-fuzz/source/$ENGINE-$(basename "$SOURCE_REAL")-$MODE"
BUILD_ENV=()
if [ "$MODE" = "afl-stable" ]; then
  AFL_BIN="$ROOT/.tools/afl++/usr/bin"
  LLVM_ROOT="$ROOT/.tools/llvm17/root/usr"
  CC_BIN="$AFL_BIN/afl-clang-lto"
  CXX_BIN="$AFL_BIN/afl-clang-lto++"
  CLANG_BIN="$LLVM_ROOT/bin/clang-17"
  CLANGXX_BIN="$LLVM_ROOT/bin/clang++-17"
  LLD_BIN="$LLVM_ROOT/bin/ld.lld-17"
  for tool in "$CC_BIN" "$CXX_BIN" "$CLANG_BIN" "$CLANGXX_BIN" "$LLD_BIN"; do
    [ -x "$tool" ] || { echo "missing local LLVM AFL tool: $tool" >&2; exit 3; }
  done
  CFLAGS_VALUE="-O1 -g -fno-omit-frame-pointer"
  BUILD_ENV=(
    "AFL_CC=$CLANG_BIN"
    "AFL_CXX=$CLANGXX_BIN"
    "AFL_REAL_LD=$LLD_BIN"
  )
elif [ "$MODE" = "afl" ]; then
  CC_BIN="$(command -v afl-clang-lto || command -v afl-clang-fast || command -v afl-gcc || command -v afl-gcc-fast || true)"
  CXX_BIN="$(command -v afl-clang-lto++ || command -v afl-clang-fast++ || command -v afl-g++ || command -v afl-g++-fast || true)"
  if [ -z "$CC_BIN" ] || [ -z "$CXX_BIN" ]; then
    if [ "$DRY_RUN" = "1" ]; then
      CC_BIN="afl-clang-lto"
      CXX_BIN="afl-clang-lto++"
      echo "warning: AFL++ compiler wrappers are not installed" >&2
    else
      echo "AFL++ compiler wrappers are not installed" >&2
      exit 3
    fi
  fi
  CFLAGS_VALUE="-O1 -g -fno-omit-frame-pointer"
else
  CC_BIN="$(command -v clang || command -v gcc || true)"
  CXX_BIN="$(command -v clang++ || command -v g++ || true)"
  [ -n "$CC_BIN" ] && [ -n "$CXX_BIN" ] || { echo "clang/gcc C and C++ compilers are required" >&2; exit 3; }
  CFLAGS_VALUE="-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined"
fi

case "$ENGINE" in
  postgresql)
    if [[ "$MODE" = afl* ]]; then
      # Building all of PostgreSQL also builds libpq. AFL's compiler runtime
      # intentionally references _exit, which trips libpq's exported-library
      # safety check even though the server backend is validly instrumented.
      if [ "$MODE" = "afl-stable" ]; then
        # Assertions remain enabled in the ASan replay build.  Disabling them
        # only in the coverage producer removes PostgreSQL's deliberate
        # USE_ASSERT_CHECKING random catcache invalidation, which otherwise
        # marks nearly every AFL testcase variable and grows a noise corpus.
        # PostgreSQL's backend clean rules can remove generated files while
        # leaving the corresponding stamps under src/include.  Invalidate
        # those exact stamps so make cannot mistake dangling symlinks for a
        # complete generated-header pass.
        BUILD=(env "${BUILD_ENV[@]}" bash -lc "./configure --enable-debug --disable-cassert CC='$CC_BIN' CFLAGS='$CFLAGS_VALUE' && find src/include/utils/header-stamp src/include/nodes/header-stamp src/include/catalog/bki-stamp -maxdepth 0 -type f -delete && make -C src/backend generated-headers && make -C src/backend postgres -j8")
      else
        BUILD=(bash -lc "./configure --enable-debug --enable-cassert CC='$CC_BIN' CFLAGS='$CFLAGS_VALUE' && make -C src/backend postgres -j\$(nproc)")
      fi
    else
      BUILD=(bash -lc "./configure --enable-debug --enable-cassert CC='$CC_BIN' CFLAGS='$CFLAGS_VALUE' && make -j\$(nproc)")
    fi ;;
  redis)
    BUILD=(bash -lc "make -j\$(nproc) CC='$CC_BIN' CFLAGS='$CFLAGS_VALUE' MALLOC=libc") ;;
  mysql|mariadb)
    BUILD=(bash -lc "cmake -S . -B build-fuzz -DCMAKE_C_COMPILER='$CC_BIN' -DCMAKE_CXX_COMPILER='$CXX_BIN' -DCMAKE_C_FLAGS='$CFLAGS_VALUE' -DCMAKE_CXX_FLAGS='$CFLAGS_VALUE' -DWITH_UNIT_TESTS=OFF && cmake --build build-fuzz -j\$(nproc)") ;;
esac

echo "engine=$ENGINE mode=$MODE"
echo "source=$SOURCE_REAL"
echo "copy=$DEST"
printf 'build='
printf '%q ' "${BUILD[@]}"
echo
[ "$DRY_RUN" = "1" ] && exit 0

mkdir -p "$(dirname "$DEST")"
[ ! -e "$DEST" ] || { echo "destination already exists: $DEST" >&2; exit 4; }
cp -a --reflink=auto "$SOURCE_REAL" "$DEST"
cd "$DEST"
exec "${BUILD[@]}"
