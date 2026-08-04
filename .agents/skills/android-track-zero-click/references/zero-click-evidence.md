# Zero-click evidence and public boundaries

## Classification

- Candidate: an automatic receiver/parser and risky native code exist, but the byte path or bug
  is unproved.
- Probable: attacker bytes automatically reach the parser and a memory-safety defect is strongly
  supported, but the delivery chain or execution impact remains incomplete.
- Confirmed: no user action is required and a controlled end-to-end oracle proves the sink.

## Public cases

- Samsung Qmage, CVE-2020-8899: genuine MMS auto-decode zero-click RCE in Samsung Messages, but
  app-process execution rather than instant kernel/root. The public exploit used repeated MMS
  requests and an ASLR oracle.
  https://projectzero.google/2020/07/mms-exploit-part-1-introduction-to-qmage.html
  https://projectzero.google/2020/08/mms-exploit-part-5-defeating-aslr-getting-rce.html
- Exynos modem CVE-2023-24033 family: genuine Internet-to-baseband zero-click, but outside APK
  application analysis. Keep modem/baseband work in a separate scope.
  https://projectzero.google/2023/03/multiple-internet-to-baseband-remote-rce.html
- LANDFALL/CVE-2025-21042: in-the-wild Samsung image-codec RCE. Public delivery evidence points
  to WhatsApp, while official scoring and public research do not fully prove every zero-click
  delivery step; classify interaction separately.
  https://unit42.paloaltonetworks.com/landfall-is-new-commercial-grade-android-spyware/
- TikTok persistent native code execution from Oversecured required a malicious local app and
  subsequent app loading. It is not remote zero-click.
  https://oversecured.com/blog/oversecured-detects-dangerous-vulnerabilities-in-the-tiktok-android-app
