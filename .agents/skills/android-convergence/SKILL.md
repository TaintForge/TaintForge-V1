---
name: android-convergence
description: Cross-validate and safely reproduce Android APK findings on an authorized Android emulator, correlating manifest, component, WebView, cross-component, and native evidence into exact adb PoCs and ranked reports. Use after Android producer tracks emit candidates.
---

# Android convergence

Consume Android findings continuously. Use only an emulator serial and the provided wrapper;
hardware devices and third-party services are out of scope.

## Prepare conservative probes

```bash
python3 .agents/skills/android-convergence/scripts/build_probe_plan.py
python3 .agents/skills/android-convergence/scripts/android_probe.py \
  --serial emulator-5554 --dry-run uri --package com.example \
  --uri 'example://host/path?tf_probe=1'
```

Install only an APK under `targets/`. `android_probe.py` verifies `ro.kernel.qemu=1`. Activity,
URI, and broadcast probes use inert markers. Service and provider probes require
`--confirm-state-change` after reviewing their semantics.

When Frida and a matching emulator server are available, record sink telemetry without changing
the app:

```bash
python3 .agents/skills/android-convergence/scripts/frida_trace.py \
  --serial emulator-5554 --package com.example --seconds 60
```

The tracer records Intent launches, WebView loads/bridges, DEX loads, and Java/native library
loads under `workspace/android/telemetry/`. Treat instrumentation as supporting evidence and
record whether the APK was original, test-signed, or instrumented.

## Reproduction lifecycle

1. Cross-check the claimed component and source/sink lines against decoded manifest, smali, and
   decompiled source.
2. State the interaction prerequisite: none, click, open file, local app install, or next launch.
3. Reproduce on the relevant API/ABI image using a fresh snapshot and fake data only.
4. Capture the exact wrapper command, `am` result, pid-scoped logcat, crash/tombstone, and any
   instrumentation event that shows attacker-controlled data reaching the sink.
5. Mark `reproduced` only for decisive reachability/impact. Use `false_positive` for disproved
   paths and `needs_reanalysis` for a concrete missing environment or evidence.
6. Write a self-contained Python `poc.py` that invokes `android_probe.py`; store it in
   `repro.poc_script`, then run the existing emitter and triage scripts.

Original and test-signed/instrumented APK results must be separated. A patched-only result does
not prove production exploitability. An AOSP emulator result does not prove an OEM system-app
boundary.

## Safety

Allow only local canaries/mock backends. Never use live accounts, contacts, SIM data,
credentials, persistence, or shell payloads. A marker Activity, sentinel provider row, local
canary hit, or controlled crash is sufficient.
