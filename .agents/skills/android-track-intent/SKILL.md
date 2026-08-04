---
name: android-track-intent
description: Trace Android cross-component source-to-sink chains from deep links, Intents, Bundles, ClipData, URI grants, activity results, Binder messages, and implicit intents into protected components, providers, file writes, dynamic loaders, or native parsers. Use after the APK model and component review exist.
---

# Android cross-component sink track

Work path-first, not API-hit-first:

`external entry -> parsed field -> proxy/dispatcher -> component boundary -> privileged sink`

Read `references/public-chain-patterns.md` before judging nested Intent, URI grants, or dynamic
loading.

## Sources

Anchor on exported/BROWSABLE components, custom schemes/App Links, implicit intent results,
notification/push/SMS receivers, Binder/AIDL, provider operations, and WebView navigation.
Track `Intent`, `Bundle`, `Uri`, `ClipData`, selector, flags, MIME type, component/package,
categories, and URI grants separately; validation of one does not validate the others.

## Sinks

Prioritize:

- `startActivity`, `startService`, `bindService`, broadcast sends, and `PendingIntent.send`;
- provider/file read or write and grant propagation;
- `System.load`, `DexClassLoader`, Play Core/dynamic feature paths, reflection, and command APIs;
- WebView and native-parser handoff;
- privileged account, payment, device-management, or install APIs.

## Guard analysis

Verify component/package allowlists, selector removal, flags/ClipData stripping, canonical URI
host checks, permissions, caller UID/signature, ownership, authentication state, and required
user confirmation. Re-check after every decode, reparse, forwarding Bundle, or new Intent.

Create track `K` findings only when the complete path is concrete. Cite every cross-file and
cross-component hop and fill `android.intent`, delivery, interaction, and execution boundary.
Write findings only with the shared writer.
