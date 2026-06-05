#!/usr/bin/env python3
"""
canary.py - out-of-band callback server for confirming SSRF/blind injection/XXE.

SSRF can't be proven by the response alone - you need to see the TARGET make a request to
a server you control. canary.py is that server.

Flow (the convergence session does this):
  1. start it once (background):   python3 canary.py serve --port 9111 &
  2. make the target fetch a unique URL pointing at the canary, e.g. send a payload
     url=http://<CANARY_HOST>:9111/<token>  via probe.py (token = any unique string)
  3. check whether the target called back:   python3 canary.py check <token>
     -> "HIT" with request details = SSRF confirmed (out-of-band). "no hit" = inconclusive.

Also works for blind XXE / RCE-with-curl / webhook callbacks. Hits are logged to
workspace/_canary.log (path, query, headers, client). Stdlib only.

  serve  --port N --log FILE        run the listener (blocking; background it)
  check  <token> --log FILE         did anything call back with <token> in the path/query?
  url    <token> --host H --port N  print the callback URL to embed in a payload
"""
import argparse, http.server, json, os, sys, datetime

def load_env():
    """Read SSRF_HOST / SSRF_PORT from .env (repo root or CWD) if present.
    Lets the operator point OOB callbacks at an externally-reachable host:port that a target
    inside its own container/network can actually call back to (127.0.0.1 often can't be
    reached from the target). Env vars already set take precedence over the file."""
    for path in (".env", os.path.join(os.path.dirname(__file__), "../../../../.env")):
        path=os.path.abspath(path)
        if not os.path.isfile(path): continue
        try:
            for line in open(path):
                line=line.strip()
                if not line or line.startswith("#") or "=" not in line: continue
                k,v=line.split("=",1); k=k.strip(); v=v.strip().strip('"').strip("'")
                if k in ("SSRF_HOST","SSRF_PORT") and k not in os.environ:
                    os.environ[k]=v
        except Exception: pass
        break

def env_host(): return os.environ.get("SSRF_HOST","127.0.0.1")
def env_port(): return int(os.environ.get("SSRF_PORT","9111"))

def serve(port, log):
    os.makedirs(os.path.dirname(log) or ".", exist_ok=True)
    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self,*a): pass
        def _hit(self):
            rec={"ts":datetime.datetime.now(datetime.timezone.utc).isoformat(),
                 "method":self.command,"path":self.path,
                 "client":self.client_address[0],
                 "headers":{k:v for k,v in self.headers.items()}}
            with open(log,"a") as f: f.write(json.dumps(rec)+"\n")
            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
        do_GET=do_POST=do_PUT=do_HEAD=_hit
    print(f"[canary] listening on 0.0.0.0:{port}, logging -> {log}")
    http.server.HTTPServer(("0.0.0.0",port),H).serve_forever()

def check(token, log):
    if not os.path.exists(log): print("no hit (no log yet)"); return 1
    hits=[]
    for line in open(log):
        try: r=json.loads(line)
        except Exception: continue
        if token in r.get("path","") or any(token in v for v in r.get("headers",{}).values()):
            hits.append(r)
    if hits:
        print(f"HIT x{len(hits)} for token {token} - SSRF/OOB CONFIRMED")
        for h in hits[:5]:
            print(f"  {h['ts']}  {h['method']} {h['path']}  from {h['client']}")
        return 0
    print(f"no hit for token {token} (inconclusive - target did not call back)"); return 1

def main():
    load_env()
    ap=argparse.ArgumentParser()
    sub=ap.add_subparsers(dest="cmd",required=True)
    s=sub.add_parser("serve"); s.add_argument("--port",type=int,default=env_port()); s.add_argument("--log",default="workspace/_canary.log")
    c=sub.add_parser("check"); c.add_argument("token"); c.add_argument("--log",default="workspace/_canary.log")
    u=sub.add_parser("url"); u.add_argument("token"); u.add_argument("--host",default=env_host()); u.add_argument("--port",type=int,default=env_port())
    a=ap.parse_args()
    if a.cmd=="serve": serve(a.port,a.log)
    elif a.cmd=="check": sys.exit(check(a.token,a.log))
    elif a.cmd=="url": print(f"http://{a.host}:{a.port}/{a.token}")

if __name__=="__main__":
    main()