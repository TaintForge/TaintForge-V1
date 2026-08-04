---
name: android-track-webview
description: Audit Android WebView security in authorized APKs, tracing deep-link and IPC inputs into URL loading, JavaScript execution, native bridges, file/content access, intent URL handling, cookies, headers, downloads, and renderer callbacks. Use when WebView, Custom Tabs, Lynx-like hybrid views, or JavaScript bridge APIs appear.
---

# Android WebView track

Read `references/webview-checklist.md`. Map every WebView-like instance, its settings, clients,
bridges, URL sources, and authenticated context.

## Trace the complete flow

Start from deep-link data, extras, redirects, QR/push content, provider content, or server
responses. Follow through URL normalization and allowlists into:

- `loadUrl`, `postUrl`, `loadData`, `loadDataWithBaseURL`, and `evaluateJavascript`;
- `shouldOverrideUrlLoading`, `Intent.parseUri`, external scheme dispatch, and downloads;
- `addJavascriptInterface`, annotated bridge methods, message ports, and hybrid SDK bridges;
- file/content access, universal file-origin access, cookies, auth headers, and geolocation;
- renderer crashes and native parsers reached by WebView content.

## Judge exploitability

Parse scheme, host, port, user-info, Unicode/IDNA, and path with one canonical parser. Reject
`contains`, raw `startsWith`, suffix-only, regex, double-decode, backslash, and redirect
mismatches unless the exact logic is proven safe. Determine whether attacker content receives
cookies, headers, bridge access, local file access, or an app-privileged native action.

JavaScript enabled alone is not a finding. A bridge alone is not a finding. Show attacker origin
control plus a reachable sensitive method or data boundary.

Create track `W` findings through the shared writer. Fill the structured `android` context,
including the delivery mechanism, required interaction, and JavaScript/app execution boundary.
