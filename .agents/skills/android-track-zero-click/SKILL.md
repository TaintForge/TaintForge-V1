---
name: android-track-zero-click
description: Analyze embedded Android APK binaries, JNI/native parsers, DEX or dynamic modules, and passive delivery paths for credible zero-click vulnerability chains. Use when an app automatically processes push, notification, SMS/MMS, media, document, share, link-preview, or sync content, especially when native .so libraries or dynamic loaders are involved.
---

# Android native and zero-click track

Read `workspace/android/ANDROID_MODEL.json`, especially `native.libraries`, then read
`references/zero-click-evidence.md`.

## Required chain

Do not report a library name, format string, crash, or unsafe C function by itself. Establish:

`remote/passive delivery -> no required user action -> automatic parser selection -> attacker bytes
reach native/unsafe parser -> concrete memory-safety or code-loading flaw -> execution boundary`

Trace Java/Kotlin/smali into JNI registrations and the native function. Use `readelf`, `nm`,
`objdump`, `strings`, and Ghidra headless when available. Decompiler output is a lead; verify
critical control/data facts in disassembly or runtime instrumentation.

## Evidence taxonomy

Record these fields in the finding's structured `android` object and explain the proof in
`evidence`:

- delivery: App Link, custom scheme, nested Intent, broadcast, Binder, push, SMS/MMS, media sync;
- interaction: none, click, open-file, install-local-app, next-app-launch;
- execution boundary: Web account, JS bridge, app sandbox, privileged/system app, baseband/kernel;
- sink: parser corruption, arbitrary write, dynamic `.so`/DEX load, privileged API;
- evidence grade: string lead, static path, controlled crash, sanitizer trace, researcher PoC,
  full exploit, or in-the-wild;
- zero-click claim: candidate, probable, or confirmed.

Use `confirmed` only when passive delivery and sink reachability are reproduced without user
interaction. Native payloads, persistence, credential access, and shell execution are out of
bounds; use a controlled crash, marker file, or local canary as the oracle.

Create track `N` findings through the shared writer.
