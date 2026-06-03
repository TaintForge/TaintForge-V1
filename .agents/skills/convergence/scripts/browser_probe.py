#!/usr/bin/env python3
"""
browser_probe.py - confirm XSS by actually EXECUTING the page in a headless browser.

Reflecting a payload in the HTTP body only proves reflection, not execution. This opens the
URL in headless Chromium (Playwright) and reports whether injected JavaScript actually RAN -
detected two independent ways:
  1. a JS dialog fired (alert/confirm/prompt)  -> payload like alert(1) executed
  2. an injected marker ran: if your payload sets window.__tf_xss (e.g.
     "<script>window.__tf_xss=1</script>" or "<img src=x onerror=window.__tf_xss=1>"),
     we read it back after load. Catches no-dialog payloads.
Console messages / page errors are captured too (useful to see CSP blocks).

Sessions: pass --jar FILE (the same MozillaCookieJar probe.py writes) to test stored/auth'd
XSS - its cookies are injected into the browser context before navigating.

Usage:
  browser_probe.py --url "http://host/search?q=<payload>"
  browser_probe.py --url "http://host/profile" --jar alice.jar          # authed/stored
  browser_probe.py --url "http://host/p" --wait 1500 --timeout 15000
Output: JSON {executed, signals[], dialogs[], console[], errors[], final_url}.
Exit code 0 if executed, 1 otherwise (so shells can branch).

Marker convention for PoCs: make the payload set  window.__tf_xss = 1
Install once:  pip install playwright && python3 -m playwright install chromium
"""
import argparse, json, sys, http.cookiejar
from urllib.parse import urlparse

def load_cookies(jar_path, url):
    """Read a MozillaCookieJar and return Playwright cookie dicts scoped to url's host."""
    cj = http.cookiejar.MozillaCookieJar()
    try: cj.load(jar_path, ignore_discard=True, ignore_expires=True)
    except Exception: return []
    host = urlparse(url).hostname or ""
    out = []
    for c in cj:
        out.append({
            "name": c.name, "value": c.value,
            "domain": c.domain or host, "path": c.path or "/",
            "secure": bool(c.secure),
        })
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--jar")
    ap.add_argument("--wait", type=int, default=1200, help="ms to wait after load for async exec")
    ap.add_argument("--timeout", type=int, default=15000, help="navigation timeout ms")
    ap.add_argument("--marker", default="__tf_xss", help="window.<marker> set by the payload")
    a = ap.parse_args()

    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        print(json.dumps({"executed": None,
            "error": "playwright not installed: pip install playwright && python3 -m playwright install chromium"}))
        sys.exit(2)

    dialogs, console, errors, signals = [], [], [], []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
        ctx = browser.new_context(ignore_https_errors=True)
        if a.jar:
            cookies = load_cookies(a.jar, a.url)
            if cookies:
                try: ctx.add_cookies(cookies)
                except Exception as e: errors.append(f"cookie inject: {e}")
        page = ctx.new_page()

        def on_dialog(d):
            dialogs.append({"type": d.type, "message": d.message})
            signals.append(f"dialog:{d.type}:{d.message[:60]}")
            try: d.dismiss()
            except Exception: pass
        page.on("dialog", on_dialog)
        page.on("console", lambda m: console.append(f"{m.type}:{m.text[:120]}"))
        page.on("pageerror", lambda e: errors.append(str(e)[:160]))

        final_url = a.url
        try:
            page.goto(a.url, timeout=a.timeout, wait_until="load")
            final_url = page.url
            page.wait_for_timeout(a.wait)
            try:
                if page.evaluate(f"window['{a.marker}'] ? 1 : 0") == 1:
                    signals.append(f"marker:window.{a.marker}")
            except Exception:
                pass
        except Exception as e:
            errors.append(f"nav: {str(e)[:160]}")
        finally:
            browser.close()

    executed = len(signals) > 0
    print(json.dumps({
        "executed": executed, "signals": signals,
        "dialogs": dialogs, "console": console[-20:], "errors": errors,
        "final_url": final_url,
    }, indent=2))
    sys.exit(0 if executed else 1)

if __name__ == "__main__":
    main()