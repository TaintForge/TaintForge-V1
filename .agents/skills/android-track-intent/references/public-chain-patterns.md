# Public Android chain patterns

- Full Intent redirection: an exported proxy forwards a nested Intent and can expose a private
  component or provider grant. Check selector, ClipData, flags, data, categories, and target.
  Sources: https://oversecured.com/blog/android-access-to-app-protected-components and
  https://developer.android.com/privacy-and-security/risks/intent-redirection
- Limited WebView redirection: attacker-influenced navigation is parsed with `Intent.parseUri`
  and launched. `setComponent(null)` alone may leave a selector.
- Implicit intent interception/result poisoning: a malicious handler observes outgoing data or
  returns an attacker URI. Source:
  https://oversecured.com/blog/interception-of-android-implicit-intents
- URI grant escalation: redirection plus a broad provider/FileProvider can cross private
  component boundaries. Source:
  https://oversecured.com/blog/gaining-access-to-arbitrary-content-providers
- Persistent app-sandbox code execution: arbitrary private-file write plus a writable,
  predictable `System.load`/dynamic-module path. The published TikTok and Google cases required
  a local malicious app; do not relabel them remote or zero-click.
  Sources:
  https://oversecured.com/blog/oversecured-detects-dangerous-vulnerabilities-in-the-tiktok-android-app
  and
  https://oversecured.com/blog/why-dynamic-code-loading-could-be-dangerous-for-your-apps-a-google-example
