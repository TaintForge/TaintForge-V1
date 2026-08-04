#!/usr/bin/env bash
# Decode an authorized APK under targets/ and build workspace/android/ANDROID_MODEL.json.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../../../.." && pwd)"
TARGETS_ROOT="$(readlink -f "$REPO/targets")"

usage() {
  echo "usage: $0 targets/<app.apk>"
}

[ "$#" -eq 1 ] || { usage >&2; exit 2; }
APK="$(readlink -f "$1")"
case "$APK" in
  "$TARGETS_ROOT"/*.apk) ;;
  *) echo "error: APK must be a .apk file directly under or below $TARGETS_ROOT" >&2; exit 2 ;;
esac
[ -f "$APK" ] || { echo "error: APK not found: $APK" >&2; exit 2; }

python3 - "$APK" <<'PY'
import pathlib, sys, zipfile
p = sys.argv[1]
MAX_ENTRIES = 200_000
MAX_MEMBER = 1024 * 1024 * 1024
MAX_TOTAL = 8 * 1024 * 1024 * 1024
try:
    with zipfile.ZipFile(p) as z:
        entries = z.infolist()
        if len(entries) > MAX_ENTRIES:
            raise SystemExit("error: APK entry count exceeds safety limit")
        total = 0
        for item in entries:
            parts = pathlib.PurePosixPath(item.filename).parts
            if pathlib.PurePosixPath(item.filename).is_absolute() or ".." in parts or "\x00" in item.filename:
                raise SystemExit(f"error: unsafe APK member: {item.filename}")
            if item.file_size > MAX_MEMBER:
                raise SystemExit(f"error: APK member exceeds 1 GiB: {item.filename}")
            total += item.file_size
            if total > MAX_TOTAL:
                raise SystemExit("error: APK uncompressed size exceeds 8 GiB safety limit")
except zipfile.BadZipFile:
    raise SystemExit("error: target is not a valid APK/ZIP")
PY

SHA="$(sha256sum "$APK" | awk '{print substr($1,1,12)}')"
BASE="$(basename "$APK" .apk)"
RUN="$REPO/workspace/android/${BASE}-${SHA}"
mkdir -p "$RUN"

MANIFEST=""
SOURCE_ROOTS=()

if command -v apkanalyzer >/dev/null 2>&1; then
  if apkanalyzer manifest print "$APK" > "$RUN/AndroidManifest.xml"; then
    MANIFEST="$RUN/AndroidManifest.xml"
  fi
fi

if command -v apktool >/dev/null 2>&1; then
  mkdir -p "$RUN/apktool"
  if apktool d -f -o "$RUN/apktool" "$APK"; then
    [ -f "$RUN/apktool/AndroidManifest.xml" ] && MANIFEST="$RUN/apktool/AndroidManifest.xml"
    SOURCE_ROOTS+=("$RUN/apktool")
  fi
fi

if command -v jadx >/dev/null 2>&1; then
  mkdir -p "$RUN/jadx"
  if jadx --show-bad-code --deobf -d "$RUN/jadx" "$APK"; then
    [ -z "$MANIFEST" ] && [ -f "$RUN/jadx/resources/AndroidManifest.xml" ] \
      && MANIFEST="$RUN/jadx/resources/AndroidManifest.xml"
    [ -d "$RUN/jadx/sources" ] && SOURCE_ROOTS+=("$RUN/jadx/sources")
    [ -d "$RUN/jadx/resources" ] && SOURCE_ROOTS+=("$RUN/jadx/resources")
  fi
fi

if command -v apksigner >/dev/null 2>&1; then
  apksigner verify --verbose --print-certs "$APK" > "$RUN/signature.txt" 2>&1 || true
else
  echo "apksigner unavailable; signature verification not performed" > "$RUN/signature.txt"
fi

python3 "$HERE/inventory_native.py" \
  --apk "$APK" \
  --extract-dir "$RUN/native" \
  --out "$RUN/native_inventory.json"

ARGS=(--apk "$APK" --native-inventory "$RUN/native_inventory.json" --out "$RUN/ANDROID_MODEL.json")
[ -n "$MANIFEST" ] && ARGS+=(--manifest "$MANIFEST")
for root in "${SOURCE_ROOTS[@]}"; do
  ARGS+=(--source-root "$root")
done
python3 "$HERE/build_android_model.py" "${ARGS[@]}"
cp "$RUN/ANDROID_MODEL.json" "$REPO/workspace/android/ANDROID_MODEL.json"

if [ -z "$MANIFEST" ]; then
  echo "warning: no decoded manifest; install apktool, jadx, or apkanalyzer for component mapping" >&2
fi
if [ "${#SOURCE_ROOTS[@]}" -eq 0 ]; then
  echo "warning: no decompiled source; install jadx or apktool for code-flow hints" >&2
fi

echo "[apk-seed] immutable input: $APK"
echo "[apk-seed] artifacts: $RUN"
echo "[apk-seed] canonical model: $REPO/workspace/android/ANDROID_MODEL.json"
