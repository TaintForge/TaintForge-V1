#!/usr/bin/env python3
"""proof_ledger.py - structured context memory for long-running vuln analysis."""
from __future__ import annotations
import argparse, datetime as _dt, json, os, sys
from typing import Any, Dict, List, Optional
DEFAULT_LEDGER="workspace/proof_ledger.json"
def load(path):
    if not os.path.exists(path): sys.exit(f"[proof_ledger] missing {path}. Run build_code_model.sh first.")
    return json.load(open(path,encoding="utf-8"))
def save(path,data): json.dump(data,open(path,"w",encoding="utf-8"),indent=2,ensure_ascii=False)
def all_units(data): return list(data.get("route_units",[]))+list(data.get("sink_units",[]))
def find_unit(data,uid):
    for u in all_units(data):
        if u.get("unit_id")==uid: return u
    return None
def unit_score(u):
    if u.get("status")!="pending": return (-10,0,u.get("unit_id",""))
    risk=0
    for h in u.get("risk_hints",[]):
        if "id-param" in h or "admin" in h or "state-changing" in h: risk+=4
        elif h.startswith("reaches-"): risk+=2
        else: risk+=1
    if u.get("type")=="sink":
        cat=u.get("category","")
        risk+={"sql":5,"command":5,"code-eval":5,"deserialization":4,"ssrf-net":4,"file-path":4,"resource-load":3}.get(cat,1)
    return (risk,-len(u.get("evidence",[])),u.get("unit_id",""))
def summarize(data):
    for key,label in (("route_units","routes"),("sink_units","sinks")):
        units=data.get(key,[])
        done=sum(1 for u in units if u.get("status")=="done")
        pending=sum(1 for u in units if u.get("status")=="pending")
        needs=sum(1 for u in units if u.get("status")=="needs_reanalysis")
        findings=sum(1 for u in units if u.get("verdict")=="finding")
        safe=sum(1 for u in units if u.get("verdict")=="safe")
        print(f"[proof_ledger] {label}: total={len(units)} pending={pending} done={done} needs_reanalysis={needs} findings={findings} safe={safe}")
    print(f"[proof_ledger] open_edges={len(data.get('open_edges',[]))} safe_summaries={len(data.get('safe_summaries',[]))}")
def print_unit(u,as_json=False):
    if as_json: print(json.dumps(u,indent=2,ensure_ascii=False)); return
    print(f"{u.get('unit_id')}  type={u.get('type')}  status={u.get('status')}  verdict={u.get('verdict')}")
    if u.get("type")=="route":
        print(f"  {u.get('method','')} {u.get('path','')}  {u.get('file','')}:{u.get('line',0)}")
        print(f"  handler: {u.get('handler') or u.get('handler_symbol') or '<unresolved>'}")
        if u.get("risk_hints"): print("  risk_hints: "+", ".join(u.get("risk_hints",[])))
        if u.get("reachable_sinks"):
            print("  reachable_sinks:")
            for s in u.get("reachable_sinks",[])[:12]: print(f"    - {s.get('category','')} {s.get('callee','')} {s.get('file','')}:{s.get('line',0)}")
    else:
        print(f"  {u.get('category','')} {u.get('callee','')}  {u.get('file','')}:{u.get('line',0)}")
        print(f"  caller: {u.get('caller_symbol','')}")
    for k,v in u.get("commands",{}).items():
        if v: print(f"  cmd[{k}]: {v}")
    if u.get("evidence"):
        print("  evidence:")
        for ev in u.get("evidence",[])[-5:]: print(f"    - {ev}")
    if u.get("notes"):
        print("  notes:")
        for n in u.get("notes",[])[-5:]: print(f"    - {n}")
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--ledger",default=DEFAULT_LEDGER); ap.add_argument("--summary",action="store_true")
    ap.add_argument("--list",choices=["route","sink","all"]); ap.add_argument("--next",choices=["route","sink","all"])
    ap.add_argument("--show"); ap.add_argument("--json",action="store_true"); ap.add_argument("--done")
    ap.add_argument("--verdict",choices=["safe","finding","needs_reanalysis","unknown"],default="unknown")
    ap.add_argument("--finding",default=""); ap.add_argument("--evidence",default=""); ap.add_argument("--note",default="")
    args=ap.parse_args(); data=load(args.ledger)
    if args.summary: summarize(data); return
    if args.list:
        units=all_units(data)
        if args.list!="all": units=[u for u in units if u.get("type")==args.list]
        for u in units: print_unit(u,as_json=args.json)
        return
    if args.next:
        units=[u for u in all_units(data) if u.get("status")=="pending"]
        if args.next!="all": units=[u for u in units if u.get("type")==args.next]
        if not units: return
        units.sort(key=unit_score,reverse=True); print_unit(units[0],as_json=args.json); return
    if args.show:
        u=find_unit(data,args.show)
        if not u: sys.exit(f"[proof_ledger] unit not found: {args.show}")
        print_unit(u,as_json=args.json); return
    if args.done:
        u=find_unit(data,args.done)
        if not u: sys.exit(f"[proof_ledger] unit not found: {args.done}")
        now=_dt.datetime.now(_dt.timezone.utc).isoformat()
        u["status"]="needs_reanalysis" if args.verdict=="needs_reanalysis" else "done"
        u["verdict"]=args.verdict; u["updated_at"]=now
        if args.finding:
            u.setdefault("finding_ids",[])
            if args.finding not in u["finding_ids"]: u["finding_ids"].append(args.finding)
        if args.evidence: u.setdefault("evidence",[]).append(f"{now} {args.evidence}")
        if args.note: u.setdefault("notes",[]).append(f"{now} {args.note}")
        data.setdefault("history",[]).append({"at":now,"unit_id":args.done,"verdict":args.verdict,"finding":args.finding,"evidence":args.evidence,"note":args.note})
        save(args.ledger,data); print(f"[proof_ledger] updated {args.done}: status={u['status']} verdict={u['verdict']}"); return
    ap.print_help()
if __name__=="__main__": main()