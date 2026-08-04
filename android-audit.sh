#!/usr/bin/env bash
# Android APK assessment orchestrator: M/L/K/W/N producers + C convergence.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
S="$ROOT/.agents/skills"
APK=""
SERIAL=""
SEED_ONLY=0
SPAWN_ONLY="${SPAWN_ONLY:-0}"
MAX_HOURS="${MAX_HOURS:-12}"
CODEX_CMD="${CODEX_CMD:-codex exec --sandbox workspace-write}"

usage() {
  cat <<'EOF'
usage: ./android-audit.sh [options] targets/<app.apk>

options:
  --serial emulator-PORT   enable dynamic reproduction on an emulator
  --seed-only              build the Android model and probe plan, then exit
  --spawn-only             start supervisors and return immediately
  --max-hours N            supervisor deadline (default: 12)
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --serial) SERIAL="${2:?missing serial}"; shift 2 ;;
    --seed-only) SEED_ONLY=1; shift ;;
    --spawn-only) SPAWN_ONLY=1; shift ;;
    --max-hours) MAX_HOURS="${2:?missing hour count}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    -*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    *) APK="$1"; shift ;;
  esac
done

[ -n "$APK" ] || { usage >&2; exit 2; }
[[ "$MAX_HOURS" =~ ^[1-9][0-9]*$ ]] || { echo "error: --max-hours must be a positive integer" >&2; exit 2; }

cd "$ROOT"
mkdir -p workspace/android workspace/findings workspace/report

echo "== Android seed: immutable APK -> Manifest/permissions/source/native model =="
"$S/android-source-model/scripts/apk_seed.sh" "$APK"
python3 "$S/android-convergence/scripts/build_probe_plan.py"

if [ "$SEED_ONLY" = "1" ]; then
  echo "== seed-only complete: workspace/android/ANDROID_MODEL.json =="
  exit 0
fi

python3 - workspace/android/ANDROID_MODEL.json <<'PY'
import json, sys
model = json.load(open(sys.argv[1], encoding="utf-8"))
manifest = model.get("manifest") or {}
if not manifest.get("package") or not manifest.get("components"):
    raise SystemExit(
        "error: full analysis requires a decoded AndroidManifest.xml; "
        "install apktool, jadx, or apkanalyzer and rerun"
    )
if int((model.get("code_scan") or {}).get("files_scanned", 0)) == 0:
    raise SystemExit(
        "error: full analysis requires decompiled Java/Kotlin or smali; "
        "install jadx or apktool and rerun"
    )
PY

DYNAMIC_NOTE="No emulator was supplied. Perform static cross-validation only; preserve candidates that need runtime proof."
if [ -n "$SERIAL" ]; then
  [[ "$SERIAL" =~ ^emulator-[0-9]+$ ]] || { echo "error: --serial must be emulator-<port>" >&2; exit 2; }
  QEMU="$(adb -s "$SERIAL" shell getprop ro.kernel.qemu 2>/dev/null | tr -d '\r')"
  [ "$QEMU" = "1" ] || { echo "error: $SERIAL did not attest as an Android emulator" >&2; exit 2; }
  DYNAMIC_NOTE="Authorized emulator: $SERIAL. Use only android_probe.py with this serial, fake data, and local canaries."
fi

COMMON="You are part of an authorized Android APK assessment. Read AGENTS.md and your named
Android skill completely before acting. The original APK under targets/ is READ-ONLY.
Use workspace/android/ANDROID_MODEL.json and the content-addressed artifact directory it names.
Never treat a scanner/API/string hit as a finding. Trace a concrete external source through all
component and file boundaries to a security-relevant sink, and judge every permission, caller,
ownership, state, and user-interaction gate. Author or update findings ONLY through
.agents/skills/_shared/write_finding.py. Do not hand-edit workspace/findings/*.json.
Use .agents/skills/_shared/leads.py for observations and candidate chains. Do not access live
accounts, external services, hardware devices, credentials, persistence, or shell payloads.
$DYNAMIC_NOTE
Keep a role-specific notebook under workspace/android/notes/ so respawns continue rather than
repeat. Cover the complete surface assigned to your role; when idle, re-check new findings and
linked leads until workspace/_android_stop exists."

MISSION_M="You are Android producer M: Manifest and permissions. Use the android-source-model
skill. Review every Activity, alias, Service, Receiver, Provider, intent filter, deep link,
effective exported state, requested/declared permission, URI-grant setting, SDK-dependent
behavior, and application security flag. Build the permission and privilege picture. Exported
alone is not a bug: follow enough code to prove an untrusted caller reaches privileged behavior.
Record concrete findings with track M. $COMMON"

MISSION_L="You are Android producer L: component-type analysis. Use android-track-components.
Systematically analyze every Activity/alias, Service, Receiver, Provider, Binder/AIDL interface,
PendingIntent, and activity-result path by lifecycle method. Trace inputs, gates, and sensitive
operations; cover all modeled components and their alternate entries. Record findings track L.
$COMMON"

MISSION_K="You are Android producer K: cross-component source-to-sink chains. Use
android-track-intent. Starting at deep links, nested Intents, Bundles, ClipData, implicit results,
Binder, push/notification inputs and URI grants, follow values across dispatchers and private
components to providers, file writes, privileged APIs, dynamic loaders, WebView or native-parser
sinks. Validate selector/flags/data/package/component separately. Record findings track K.
$COMMON"

MISSION_W="You are Android producer W: WebView and hybrid UI. Use android-track-webview. Inventory
every WebView/Lynx-like instance, settings, client callback, URL allowlist, redirect, cookie/auth
header, JavaScript bridge, message port, file/content access and Intent URL dispatch. Prove
attacker-origin control plus a sensitive bridge/data/native sink. Record findings track W.
$COMMON"

MISSION_N="You are Android producer N: embedded binaries and zero-click. Use
android-track-zero-click. Map Java/smali automatic delivery paths into JNI and each relevant .so,
then inspect native imports, strings, disassembly/decompilation and parser selection. A parser
string, risky libc symbol or crash is only a lead. Classify delivery, interaction, execution
boundary, sink, evidence grade and zero-click confidence honestly. Record findings track N.
$COMMON"

MISSION_C="You are Android convergence C. Use android-convergence. Continuously consume Android
track M/L/K/W/N findings, independently cross-check manifest + smali/decompiled code, deduplicate
shared root causes, and when an emulator is supplied reproduce only with android_probe.py,
inert markers, local canaries, and fresh fake data. Record exact commands and decisive evidence.
Write a self-contained Python poc.py invoking the wrapper for each reproduced issue, store it in
repro.poc_script, run emit_poc.py and triage.py, and keep honest interaction/execution bounds.
Never turn a candidate native parser string into zero-click or RCE without the complete passive
delivery-to-sink chain. $COMMON"

DEADLINE=$(( $(date +%s) + MAX_HOURS * 3600 ))
STOP="$ROOT/workspace/_android_stop"
rm -f "$STOP"
mkdir -p workspace/android/notes

supervise() {
  local tag="$1"
  local log="$2"
  local mission="$3"
  local role_var="CODEX_CMD_${tag}"
  local role_cmd="${!role_var:-$CODEX_CMD}"
  (
    child=""
    stop_child() {
      if [ -n "$child" ]; then
        kill "$child" 2>/dev/null || true
        wait "$child" 2>/dev/null || true
      fi
      exit 0
    }
    trap stop_child INT TERM
    n=0
    while [ ! -f "$STOP" ] && [ "$(date +%s)" -lt "$DEADLINE" ]; do
      n=$((n + 1))
      echo "===== [$(date +%FT%T%z)] Android $tag session #$n =====" >> "$log"
      # role_cmd intentionally supports the same CODEX_CMD override format as audit.sh.
      # shellcheck disable=SC2086
      $role_cmd "$mission" >> "$log" 2>&1 </dev/null &
      child=$!
      wait "$child" || true
      child=""
      python3 "$S/_shared/budget_guard.py" --check \
        --log-glob 'workspace/android/_log_*.txt' \
        --stop "$STOP" >> "$log" 2>&1 || true
      [ -f "$STOP" ] || sleep 5
    done
    echo "===== [$(date +%FT%T%z)] Android $tag supervisor stopped =====" >> "$log"
  ) </dev/null >/dev/null 2>&1 &
  echo "$!"
}

echo "== launching Android M/L/K/W/N producers + C convergence =="
PM="$(supervise M workspace/android/_log_M.txt "$MISSION_M")"
PL="$(supervise L workspace/android/_log_L.txt "$MISSION_L")"
PK="$(supervise K workspace/android/_log_K.txt "$MISSION_K")"
PW="$(supervise W workspace/android/_log_W.txt "$MISSION_W")"
PN="$(supervise N workspace/android/_log_N.txt "$MISSION_N")"
PC="$(supervise C workspace/android/_log_C.txt "$MISSION_C")"
PIDS=("$PM" "$PL" "$PK" "$PW" "$PN" "$PC")
printf '%s\n' "${PIDS[*]}" > workspace/android/_pids
echo "  M=$PM L=$PL K=$PK W=$PW N=$PN C=$PC"

stop_all() {
  touch "$STOP"
  kill "${PIDS[@]}" 2>/dev/null || true
  wait "${PIDS[@]}" 2>/dev/null || true
}

if [ "$SPAWN_ONLY" = "1" ]; then
  echo "  spawned; stop with: touch workspace/_android_stop; kill \$(cat workspace/android/_pids)"
  exit 0
fi

trap 'echo "stopping Android supervisors..."; stop_all' INT TERM
wait "${PIDS[@]}"
python3 "$S/convergence/scripts/emit_poc.py"
python3 "$S/convergence/scripts/triage.py"
echo "== Android assessment ended: workspace/report/report.md =="
