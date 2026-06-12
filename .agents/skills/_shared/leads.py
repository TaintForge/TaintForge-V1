#!/usr/bin/env python3
"""
leads.py - the deep-analysis notebook. Where write_finding.py records VULNERABILITIES,
leads.py records the raw material that vulnerabilities are BUILT from:

  - lead      : an interesting-but-not-yet-a-bug observation ("this parser doesn't check
                hasOwnProperty", "this function returns a raw reference", "this dispatcher
                resolves a method name from user input"). On its own it's nothing; combined
                with others it can become an exploit chain.
  - primitive : a CAPABILITY the analysis has established ("attacker controls path into
                value[]", "can reach Function constructor", "can set arbitrary prototype
                member"). Primitives are leads that have been confirmed as usable.
  - note      : the running state of a deep-dive on ONE target (function/file/endpoint):
                what's understood so far, what capability is held, what to try next. Survives
                respawns so a later session continues digging instead of restarting.

This is what lets the agents go "trace → remember → trace deeper → combine" the way a human
researcher does, instead of the one-pass "find sink → judge → move on" loop. Findings answer
"is this exploitable"; leads answer "what could I build from here".

File-locked like write_finding.py so parallel sessions can append safely.

Usage:
  # add a lead/primitive (reads JSON on stdin or via flags)
  echo '{"kind":"lead","where":{"file":"x.js","line":42,"symbol":"getOutlinedModel"},
         "observation":"indexes value[path[i]] from user-split string, no hasOwnProperty",
         "why_interesting":"attacker-controlled property walk → possible prototype access",
         "enables":["arbitrary-member-read"]}' | leads.py add
  leads.py list                      # all leads/primitives (compact)
  leads.py list --kind primitive     # only primitives
  leads.py open                      # leads not yet marked combined/dead
  leads.py note <target> --set "understood X; hold capability Y; next try Z"
  leads.py note <target>             # read the running note for a target
  leads.py link <id> <id> ...        # record that these leads combine (a chain candidate)
  leads.py update <id> --status combined|dead|promoted --reason "..."
"""
from __future__ import annotations
import argparse, json, os, sys, time, hashlib

LEADS="workspace/leads.json"
NOTES="workspace/_analysis_notes.json"

def _now(): return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def _load(path, default):
    try: return json.load(open(path))
    except Exception: return default

def _locked_update(path, fn, default):
    import fcntl
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    lock=open(path+".lock","w")
    fcntl.flock(lock, fcntl.LOCK_EX)
    try:
        data=_load(path, default)
        data=fn(data)
        tmp=path+".tmp"
        json.dump(data, open(tmp,"w"), indent=2)
        os.replace(tmp, path)
        return data
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN); lock.close()

def _lead_id(d):
    w=d.get("where",{}) or {}
    basis=f"{d.get('kind','lead')}|{w.get('file','')}|{w.get('symbol','')}|{d.get('observation','')[:80]}"
    return hashlib.sha1(basis.encode()).hexdigest()[:12]

def add(args):
    try: payload=json.load(sys.stdin)
    except Exception as e: sys.exit(f"[leads] add expects JSON on stdin: {e}")
    payload.setdefault("kind","lead")
    if payload["kind"] not in ("lead","primitive"):
        sys.exit("[leads] kind must be 'lead' or 'primitive'")
    payload.setdefault("status","open")
    payload.setdefault("enables",[])
    payload.setdefault("created_at",_now())
    lid=payload.get("id") or _lead_id(payload); payload["id"]=lid
    def upd(data):
        items=data.setdefault("leads",[])
        for it in items:
            if it["id"]==lid:  # merge: keep first, extend enables, refresh
                it["enables"]=sorted(set(it.get("enables",[]))|set(payload.get("enables",[])))
                it["last_seen"]=_now()
                return data
        items.append(payload); return data
    _locked_update(LEADS, upd, {"schema_version":1,"leads":[]})
    print(f"[leads] {payload['kind']} {lid}: {payload.get('observation','')[:70]}")

def link(args):
    ids=args.ids
    if len(ids)<2: sys.exit("[leads] link needs >=2 ids")
    def upd(data):
        chains=data.setdefault("chains",[])
        chains.append({"id":hashlib.sha1(("".join(sorted(ids))).encode()).hexdigest()[:12],
            "members":ids,"created_at":_now(),"status":"candidate-chain"})
        return data
    _locked_update(LEADS, upd, {"schema_version":1,"leads":[]})
    print(f"[leads] linked chain: {' + '.join(ids)}")

def update(args):
    def upd(data):
        for it in data.get("leads",[]):
            if it["id"]==args.id:
                it["status"]=args.status
                if args.reason: it["status_reason"]=args.reason
                it["updated_at"]=_now()
        return data
    _locked_update(LEADS, upd, {"schema_version":1,"leads":[]})
    print(f"[leads] {args.id} -> {args.status}")

def _print_lead(it):
    w=it.get("where",{}) or {}
    loc=f"{w.get('file','')}:{w.get('line','')}" if w else ""
    en=("→ "+",".join(it.get("enables",[]))) if it.get("enables") else ""
    print(f"  [{it.get('kind','lead')[:4]}] {it['id']} {it.get('status','open'):9s} {loc}  {it.get('observation','')[:60]}  {en}")

def listing(args):
    data=_load(LEADS, {"leads":[]})
    items=data.get("leads",[])
    if args.kind: items=[i for i in items if i.get("kind")==args.kind]
    if not items: print("[leads] none yet"); return
    for it in items: _print_lead(it)
    chains=data.get("chains",[])
    if chains:
        print("\n[leads] candidate chains:")
        for c in chains: print(f"  chain {c['id']} ({c.get('status','')}): {' + '.join(c['members'])}")

def open_leads(args):
    data=_load(LEADS, {"leads":[]})
    items=[i for i in data.get("leads",[]) if i.get("status","open")=="open"]
    if not items: print("[leads] no open leads"); return
    print(f"[leads] {len(items)} open (not yet combined/dead/promoted):")
    for it in items: _print_lead(it)

def note(args):
    if args.set is None:
        notes=_load(NOTES, {})
        n=notes.get(args.target)
        if not n: print(f"[note] no note for {args.target}"); return
        print(f"[note] {args.target} (updated {n.get('updated_at','')}):\n{n.get('text','')}")
        return
    def upd(data):
        data[args.target]={"text":args.set,"updated_at":_now()}
        return data
    _locked_update(NOTES, upd, {})
    print(f"[note] saved for {args.target}")

def main():
    ap=argparse.ArgumentParser()
    sub=ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("add")
    pl=sub.add_parser("list"); pl.add_argument("--kind", choices=["lead","primitive"])
    sub.add_parser("open")
    pn=sub.add_parser("note"); pn.add_argument("target"); pn.add_argument("--set", default=None)
    plk=sub.add_parser("link"); plk.add_argument("ids", nargs="+")
    pu=sub.add_parser("update"); pu.add_argument("id"); pu.add_argument("--status", required=True,
        choices=["open","combined","dead","promoted"]); pu.add_argument("--reason", default="")
    args=ap.parse_args()
    {"add":add,"list":listing,"open":open_leads,"note":note,"link":link,"update":update}[args.cmd](args)

if __name__=="__main__":
    main()