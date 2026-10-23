#!/usr/bin/env python3
"""
probe.py - HTTP probe for reproduction (2b). Sends one request to the WARM TARGET ENV and
reports status/length/timing/snippet as JSON. The LLM crafts the payload, calls this, and folds
the result into the finding's `repro` field. Stdlib only; never hits external hosts beyond the
target you pass.

Sessions: --jar FILE keeps cookies in a MozillaCookieJar, loaded before the request and saved
after it, so you can log in once and then act as that identity. This is what makes the
access-control proof possible - two identities, two jars, one requesting the other's object.
browser_probe.py reads the same file.

Usage:
  probe.py -X GET  "http://localhost:3000/api/orders/2" -H "Authorization: Bearer <jwtA>"
  probe.py -X POST "http://localhost:3000/login" -d 'user=alice&pass=x'   --jar alice.jar
  probe.py -X POST "http://localhost:3000/login" -d '{"u":"a"}' --json    --jar alice.jar
  probe.py -X GET  "http://localhost:3000/orders/7"                       --jar alice.jar
  probe.py -X GET  "http://localhost:3000/go?to=//evil" --no-redirect     # inspect Location
"""
import argparse, http.cookiejar, json, os, time, urllib.error, urllib.request


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Surface the 3xx itself instead of following it, so Location can be inspected."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def build_opener(jar_path, follow_redirects):
    jar = None
    handlers = []
    if jar_path:
        jar = http.cookiejar.MozillaCookieJar(jar_path)
        if os.path.exists(jar_path):
            try:
                jar.load(ignore_discard=True, ignore_expires=True)
            except Exception:
                # A truncated or foreign jar must not abort the probe - start a fresh one and
                # let the response repopulate it.
                jar = http.cookiejar.MozillaCookieJar(jar_path)
        handlers.append(urllib.request.HTTPCookieProcessor(jar))
    if not follow_redirects:
        handlers.append(_NoRedirect())
    return urllib.request.build_opener(*handlers), jar


def describe(response, elapsed_ms, read_bytes):
    """Shared shape for both a normal response and an HTTPError - both carry status/headers."""
    text = response.read(read_bytes).decode("utf8", "replace")
    headers = response.headers
    out = {
        "status": getattr(response, "status", None) or getattr(response, "code", None),
        "ms": elapsed_ms,
        "len": len(text),
        "snippet": text[:500],
    }
    location = headers.get("Location")
    if location:
        out["location"] = location
    set_cookie = headers.get_all("Set-Cookie") if hasattr(headers, "get_all") else None
    if set_cookie:
        out["set_cookie"] = set_cookie
    final_url = getattr(response, "url", None)
    if final_url:
        out["final_url"] = final_url
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("-X", "--method", default="GET")
    ap.add_argument("-H", "--header", action="append", default=[])
    ap.add_argument("-d", "--data", default=None)
    ap.add_argument("--json", action="store_true",
                    help="send -d as JSON (adds Content-Type: application/json)")
    ap.add_argument("--jar", help="MozillaCookieJar file: load before, save after (session)")
    ap.add_argument("--no-redirect", action="store_true",
                    help="do not follow 3xx; report the Location header instead")
    ap.add_argument("--timeout", type=float, default=10)
    a = ap.parse_args()

    headers = dict(h.split(":", 1) for h in (x for x in a.header if ":" in x))
    headers = {k.strip(): v.strip() for k, v in headers.items()}
    if a.json and not any(k.lower() == "content-type" for k in headers):
        headers["Content-Type"] = "application/json"

    body = a.data.encode() if a.data else None
    opener, jar = build_opener(a.jar, follow_redirects=not a.no_redirect)
    req = urllib.request.Request(a.url, data=body, headers=headers, method=a.method.upper())

    t0 = time.time()
    try:
        with opener.open(req, timeout=a.timeout) as r:
            out = describe(r, round((time.time() - t0) * 1000), 4096)
    except urllib.error.HTTPError as e:
        # A 3xx under --no-redirect, and every 4xx/5xx, arrive here. Both are evidence.
        out = describe(e, round((time.time() - t0) * 1000), 2048)
    except Exception as e:
        out = {"status": None, "error": str(e)}

    if jar is not None:
        try:
            # ignore_discard: a login cookie is usually a session cookie, and dropping it would
            # make the jar useless for the very thing it exists for.
            jar.save(ignore_discard=True, ignore_expires=True)
            out["jar"] = {"path": a.jar, "cookies": sorted(c.name for c in jar)}
        except Exception as e:
            out["jar_error"] = str(e)

    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
