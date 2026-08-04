# WebView review checklist

- URL entry: deep link, Intent extra, redirect, QR/push, remote config, provider/file.
- Validation: exact scheme + canonical host + expected port/path; repeat after redirects.
- Content authority: attacker page, stale/takeover domain, mixed content, file/content origin.
- Settings: JavaScript, file access, content access, universal file-origin access, mixed content,
  safe browsing, debugging.
- Bridges: object name, exposed annotations, argument validation, origin checks, privilege of
  every callable method.
- Sinks: `loadUrl`, `evaluateJavascript`, `Intent.parseUri`, component launch, file/provider,
  account or install APIs.
- Secrets: cookies, auth headers, WebView storage, query parameters, callback tokens.

Primary references:

- https://oversecured.com/blog/android-security-checklist-webview
- https://developer.android.com/privacy-and-security/risks/unsafe-use-of-deeplinks
- https://www.microsoft.com/en-us/security/blog/2022/08/31/vulnerability-in-tiktok-android-app-could-lead-to-one-click-account-hijacking/
