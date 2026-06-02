#!/usr/bin/env python3
"""
probe.py - minimal HTTP probe for reproduction (2b). Sends one request to the WARM
TARGET ENV and reports status/length/timing/snippet as JSON. The LLM crafts the
payload, calls this, and folds the result into the finding's `repro` field. Stdlib
only; never hits external hosts beyond the target you pass.

Usage:
  probe.py -X GET  "http://localhost:3000/api/orders/2" -H "Authorization: Bearer <jwtA>"
  probe.py -X POST "http://localhost:3000/login" -d '{"u":"a"}' -H "Content-Type: application/json"
"""
import argparse, json, time, urllib.request, urllib.error

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("url")
    ap.add_argument("-X","--method",default="GET")
    ap.add_argument("-H","--header",action="append",default=[])
    ap.add_argument("-d","--data",default=None)
    ap.add_argument("--timeout",type=float,default=10)
    a=ap.parse_args()

    headers=dict(h.split(":",1) for h in (x for x in a.header if ":" in x))
    headers={k.strip():v.strip() for k,v in headers.items()}
    body=a.data.encode() if a.data else None
    req=urllib.request.Request(a.url,data=body,headers=headers,method=a.method.upper())
    t0=time.time()
    try:
        with urllib.request.urlopen(req,timeout=a.timeout) as r:
            text=r.read(4096).decode("utf8","replace")
            out={"status":r.status,"ms":round((time.time()-t0)*1000),
                 "len":len(text),"snippet":text[:500]}
    except urllib.error.HTTPError as e:
        text=e.read(2048).decode("utf8","replace")
        out={"status":e.code,"ms":round((time.time()-t0)*1000),"len":len(text),"snippet":text[:500]}
    except Exception as e:
        out={"status":None,"error":str(e)}
    print(json.dumps(out,indent=2))

if __name__=="__main__":
    main()