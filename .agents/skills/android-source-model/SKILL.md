---
name: android-source-model
description: Build and review an Android APK model from AndroidManifest.xml, permissions, exported Activities/aliases/Services/Receivers/Providers, intent filters, deep links, DEX/source hints, and embedded native libraries. Use at the start of an authorized APK assessment, before component, WebView, cross-component, or zero-click analysis.
---

# Android source model

Build the shared Android model once. Treat the APK as hostile parser input and the original
under `targets/` as immutable.

## Seed

Run:

```bash
.agents/skills/android-source-model/scripts/apk_seed.sh targets/<app.apk>
```

The seed writes a content-addressed job directory and the canonical
`workspace/android/ANDROID_MODEL.json`. It uses `apkanalyzer`, `apktool`, `jadx`, and
`apksigner` when present, and reports every missing layer instead of inventing data.
`component_code_index` ties each manifest component to the source and sink hits found in its
implementation file; use it as a route map, then verify the full cross-file path manually.

For a decoded manifest fixture or source tree, run the builder directly:

```bash
python3 .agents/skills/android-source-model/scripts/build_android_model.py \
  --manifest AndroidManifest.xml --source-root decompiled/sources \
  --out workspace/android/ANDROID_MODEL.json
```

## Manifest and permission review

Review every component by type and record:

- fully qualified class, explicit and effective `exported`, enabled state, process, alias target;
- filters: action, category, scheme, host, port, path, MIME type, priority, `autoVerify`;
- component/app `permission`, provider read/write permissions, URI grants and authorities;
- min/target SDK because implicit export and link resolution differ by Android version;
- requested and declared permissions, especially custom permissions and protection levels;
- shared UID, uses-feature constraints, and app flags such as debuggable, backup, cleartext
  traffic, and network security config.

Do not call an exported component a vulnerability by itself. Prove that an untrusted caller
can reach a privileged operation without a permission, caller, state, or ownership gate.

## Permission semantics

Distinguish:

- platform `normal`, `dangerous`, `signature`, privileged/OEM permissions;
- custom permissions with missing or weak protection levels;
- install-time declaration from runtime grant state;
- app UID permissions from component-specific gates;
- explicit export from legacy implicit export caused by an intent filter;
- an AOSP emulator result from OEM/system-app privilege behavior.

Create track `M` findings only for concrete manifest/permission vulnerabilities. Fill the
finding's `android` context (package, component/type, SDK, delivery, interaction, boundary,
original SHA-256, and zero-click classification where relevant). Write only through
`.agents/skills/_shared/write_finding.py`.

## Native inventory

`inventory_native.py` extracts only `lib/**/*.so` into the workspace, hashes each library,
collects ELF/JNI/dependency facts, and emits parser-string leads. A parser string is a routing
hint, never proof of memory corruption or zero-click reachability.
