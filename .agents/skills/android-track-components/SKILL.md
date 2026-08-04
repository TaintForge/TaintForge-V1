---
name: android-track-components
description: Audit authorized Android APK code by component type, including Activities and aliases, Services, BroadcastReceivers, ContentProviders, Binder/AIDL, PendingIntent, and result-return flows. Use after android-source-model when tracing exported or indirectly reachable components to privileged behavior.
---

# Android component track

Read `workspace/android/ANDROID_MODEL.json`, start from `component_code_index`, then inspect the
decompiled Java/Kotlin and smali for every modeled component. Use
`references/component-checklist.md` while reviewing.

## Per-component workflow

For each component:

1. Resolve the lifecycle entry methods and all callers/callees.
2. List untrusted fields from Intent data, extras, ClipData, Bundle, Binder Parcel, provider
   URI/selection/values, or activity results.
3. Trace each field to state changes, sensitive reads, URI grants, file operations, WebView,
   dynamic loading, native parsing, or component-launch sinks.
4. Locate permission, calling UID/package/signature, ownership, state, and user-confirmation
   gates on the full path.
5. Check alternate entry methods and indirect reachability through an exported proxy.
6. Record a safe reason or author a concrete finding.

Reaching a private Activity or spoofing a receiver proves a capability, not necessarily security
impact. If the target behavior is absent or only opens an inert screen, keep it as a lead until a
privileged action, sensitive disclosure, grant, file operation, or meaningful state bypass is
shown.

## Type-specific questions

- Activity/alias: deep-link parsing, task/launch mode, auth-state skipping, nested Intent,
  `setResult`, and untrusted `onActivityResult`.
- Service: exported start/bind paths, AIDL methods, caller UID validation, arbitrary download
  or file destinations, and privileged long-running actions.
- Receiver: spoofable actions, ordered-broadcast results, sticky data, notification/push
  routing, and passive delivery.
- Provider: read/write/call/openFile gates, path canonicalization, projection/selection
  injection, URI grants, FileProvider path breadth, and row ownership.
- Binder/PendingIntent: mutability, fill-in fields, creator identity, one-shot/cancel behavior,
  delegated grants, and `clearCallingIdentity`.

Create track `L` findings through the shared writer and fill the structured `android` context.
A tool hit or exported declaration alone is only a lead.
