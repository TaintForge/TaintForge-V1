#!/usr/bin/env python3
"""coverage.py - exhaustive coverage as a HIERARCHICAL TREE (directory -> module -> entry point)."""
import argparse, json, os, sys
NOISE={".git","vendor","node_modules","dist","build","__pycache__",".venv","venv",
    "target",".next","coverage","tests","test","spec","__tests__","fixtures","stubs"}
SRC_EXT={".php",".js",".ts",".jsx",".tsx",".py",".rb",".go",".java",".cs",".c",".cpp",".rs",".kt"}
COV="workspace/coverage.json"; CODE_MODEL="workspace/CODE_MODEL.json"; PROOF_LEDGER="workspace/proof_ledger.json"
SPLIT_THRESHOLD=int(os.environ.get("TF_SPLIT_THRESHOLD","120"))
MAX_DEPTH=int(os.environ.get("TF_MAX_DEPTH","4"))
def count_src(d):
    n=0
    for root,dirs,files in os.walk(d):
        dirs[:]=[x for x in dirs if x not in NOISE]
        n+=sum(1 for f in files if os.path.splitext(f)[1] in SRC_EXT)
    return n
def modules_for(target):
    mods=[]
    def consider(d,depth):
        n=count_src(d)
        if n==0: return
        if n>SPLIT_THRESHOLD and depth<MAX_DEPTH:
            kids=[os.path.join(d,x) for x in sorted(os.listdir(d)) if os.path.isdir(os.path.join(d,x)) and x not in NOISE]
            if kids:
                for k in kids: consider(k,depth+1)
                return
        mods.append((os.path.relpath(d,target),n))
    top=[os.path.join(target,x) for x in sorted(os.listdir(target)) if os.path.isdir(os.path.join(target,x)) and x not in NOISE]
    if not top: top=[target]
    for d in top: consider(d,1)
    if any(os.path.splitext(f)[1] in SRC_EXT for f in os.listdir(target) if os.path.isfile(os.path.join(target,f))):
        mods.append((".",0))
    dedup={}
    for p,n in mods: dedup[p]=max(n,dedup.get(p,0))
    return sorted(dedup.items())
def load_proof_units():
    try: data=json.load(open(PROOF_LEDGER))
    except Exception: return {}
    by_file={}
    for kind in ("route_units","sink_units"):
        for u in data.get(kind,[]) or []:
            f=u.get("file","")
            if f: by_file.setdefault(f,[]).append({"unit_id":u.get("unit_id",""),"type":u.get("type",""),
                "status":u.get("status",""),"verdict":u.get("verdict",""),"category":u.get("category",""),
                "method":u.get("method",""),"path":u.get("path",""),"callee":u.get("callee",""),"line":u.get("line",0)})
    return by_file
def units_for_module(mod_path,unit_by_file):
    out=[]
    for f,lst in unit_by_file.items():
        if f==mod_path or f.startswith(mod_path.rstrip(".")+"/") or (mod_path=="."):
            if mod_path=="." and "/" in f: continue
            out.extend(lst)
    return out
def load_entry_points():
    try: cm=json.load(open(CODE_MODEL))
    except Exception: return {}
    eps=(cm.get("structural") or cm).get("entry_points") or cm.get("entry_points") or []
    by_file={}
    for e in eps: by_file.setdefault(e.get("file",""),[]).append(e)
    return by_file
def eps_for_module(mod_path,target,ep_by_file):
    out=[]
    for f,lst in ep_by_file.items():
        if f==mod_path or f.startswith(mod_path.rstrip(".")+"/") or (mod_path=="."):
            if mod_path=="." and "/" in f: continue
            out.extend(lst)
    return out
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--init"); ap.add_argument("--next",action="store_true"); ap.add_argument("--done")
    ap.add_argument("--summary",action="store_true"); ap.add_argument("--list",action="store_true"); ap.add_argument("--tree",action="store_true")
    a=ap.parse_args()
    if a.init:
        target=os.path.abspath(a.init); mods=modules_for(target)
        ep_by_file=load_entry_points(); unit_by_file=load_proof_units(); module_objs=[]
        for p,n in mods:
            eps=eps_for_module(p,target,ep_by_file) if ep_by_file else []
            units=units_for_module(p,unit_by_file) if unit_by_file else []
            module_objs.append({"path":p,"files":n,"status":"pending","depth":p.count("/")+(0 if p=="." else 1),
                "entry_points":[{"method":e.get("method",""),"route":e.get("path",""),"kind":e.get("kind",""),
                    "file":e.get("file",""),"line":e.get("line",0),"handler_symbol":e.get("handler_symbol","")} for e in eps],
                "entry_count":len(eps),"proof_units":units,"proof_unit_count":len(units),
                "pending_proof_units":sum(1 for u in units if u.get("status")=="pending")})
        data={"target":a.init,"modules":module_objs,"has_entry_data":bool(ep_by_file),"has_proof_ledger":bool(unit_by_file)}
        os.makedirs(os.path.dirname(COV),exist_ok=True); json.dump(data,open(COV,"w"),indent=2)
        withep=sum(1 for m in module_objs if m["entry_count"]); withunits=sum(1 for m in module_objs if m.get("proof_unit_count"))
        print(f"[coverage] {len(module_objs)} modules ({withep} with entry points, {withunits} with proof units) -> {COV}")
        return
    if not os.path.exists(COV): sys.exit("[coverage] not initialized (run --init <target>)")
    data=json.load(open(COV)); mods=data["modules"]
    if a.list:
        for m in mods: print(m["path"])
        return
    if a.tree:
        for m in sorted(mods,key=lambda x:x["path"]):
            mark="\u2713" if m["status"]=="analyzed" else "\u00b7"
            ind="  "*max(0,m.get("depth",1)-1); ec=m.get("entry_count",0)
            pc=m.get("proof_unit_count",0); pend=m.get("pending_proof_units",0)
            tag=(f"  [{ec} entry]" if ec else "")+(f"  [{pend}/{pc} proof pending]" if pc else "")
            print(f"{ind}{mark} {m['path']}  ({m['files']} files){tag}")
            for e in m.get("entry_points",[])[:12]:
                hs=("  "+e.get("handler_symbol","")[:90]) if e.get("handler_symbol") else ""
                print(f"{ind}    \u2192 {e.get('method','')} {e.get('route','')}  {e.get('file','')}:{e.get('line','')}{hs}")
            for u in m.get("proof_units",[])[:8]:
                label=(u.get("method","")+" "+u.get("path","")) if u.get("type")=="route" else (u.get("category","")+" "+u.get("callee",""))
                print(f"{ind}      [{u.get('status','')}] {u.get('unit_id','')} {label} {u.get('line','')}")
        return
    if a.next:
        pend=[m for m in mods if m["status"]=="pending"]
        if not pend: return
        # Deep-dive worthiness: modules whose path hints at parsing/deserialization/dispatch/
        # reflection/templating/serialization are where multi-step chains hide (input is
        # transformed through several steps). Bump them so they're seen sooner - after raw
        # attack surface (entry points) but with weight, since one deep parser bug can outweigh
        # many shallow handlers.
        import re as _re
        DEEP=_re.compile(r"(pars|deserial|serial|unmarshal|decode|reviv|reflect|dispatch|"
            r"router|resolver|template|render|eval|interpret|marshal|flight|rpc|gadget|"
            r"middleware|hydrat|transform|codec|protocol)", _re.I)
        def deep_bonus(m): return 1 if DEEP.search(m.get("path","")) else 0
        pend.sort(key=lambda m:(-m.get("entry_count",0),-deep_bonus(m),
            -m.get("pending_proof_units",0),m["path"]))
        print(pend[0]["path"]); return
    if a.done:
        for m in mods:
            if m["path"]==a.done: m["status"]="analyzed"
        json.dump(data,open(COV,"w"),indent=2); print(f"[coverage] marked analyzed: {a.done}"); return
    if a.summary:
        done=sum(1 for m in mods if m["status"]=="analyzed")
        withep=[m for m in mods if m.get("entry_count")]; ep_done=sum(1 for m in withep if m["status"]=="analyzed")
        print(f"[coverage] {done}/{len(mods)} modules analyzed, {len(mods)-done} pending")
        if withep: print(f"[coverage] attack surface: {ep_done}/{len(withep)} entry-point modules analyzed")
        units=[u for m in mods for u in m.get("proof_units",[])]
        if units:
            pending=sum(1 for u in units if u.get("status")=="pending"); udone=sum(1 for u in units if u.get("status")=="done")
            print(f"[coverage] proof units: {udone}/{len(units)} done, {pending} pending")
if __name__=="__main__": main()