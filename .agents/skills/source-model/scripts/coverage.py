#!/usr/bin/env python3
"""
coverage.py - track exhaustive analysis coverage over a big codebase as a HIERARCHICAL TREE
(directory -> module -> entry point), so Codex analyzes the real attack surface in bounded
chunks instead of one shallow pass.

  --init <target>     build workspace/coverage.json (tree of modules; pulls entry points from
                      workspace/CODE_MODEL.json if present, so each module lists the routes/
                      handlers it exposes - the things an attacker can actually reach)
  --next              print the next PENDING module path (highest attack-surface first:
                      modules WITH entry points before leaf libs) -> drives the loop
  --done <module>     mark a module analyzed
  --summary           analyzed/total + remaining
  --list              list module paths
  --tree              print the directory->module->entrypoint tree with per-node status

A module is a directory chunk; large dirs are split into children (TF_SPLIT_THRESHOLD,
TF_MAX_DEPTH) so each chunk is small enough to read deeply. Entry points are attached per
module from CODE_MODEL so coverage reflects *reachable* surface, not just files on disk.
"""
import argparse, json, os, sys

NOISE={".git","vendor","node_modules","dist","build","__pycache__",".venv","venv",
       "target",".next","coverage","tests","test","spec","__tests__","fixtures","stubs"}
SRC_EXT={".php",".js",".ts",".jsx",".tsx",".py",".rb",".go",".java",".cs",".c",".cpp",".rs",".kt"}
COV="workspace/coverage.json"
CODE_MODEL="workspace/CODE_MODEL.json"
SPLIT_THRESHOLD=int(os.environ.get("TF_SPLIT_THRESHOLD","120"))   # dir with more source files than this -> use children
MAX_DEPTH=int(os.environ.get("TF_MAX_DEPTH","4"))                  # how deep to descend when splitting

def count_src(d):
    n=0
    for root,dirs,files in os.walk(d):
        dirs[:]=[x for x in dirs if x not in NOISE]
        n+=sum(1 for f in files if os.path.splitext(f)[1] in SRC_EXT)
    return n

def modules_for(target):
    mods=[]
    def consider(d, depth):
        n=count_src(d)
        if n==0: return
        if n>SPLIT_THRESHOLD and depth<MAX_DEPTH:
            kids=[os.path.join(d,x) for x in sorted(os.listdir(d))
                  if os.path.isdir(os.path.join(d,x)) and x not in NOISE]
            if kids:
                for k in kids: consider(k, depth+1)
                return
        mods.append((os.path.relpath(d,target), n))
    top=[os.path.join(target,x) for x in sorted(os.listdir(target))
         if os.path.isdir(os.path.join(target,x)) and x not in NOISE]
    if not top: top=[target]
    for d in top: consider(d,1)
    # if target root itself has loose source files, include "."
    if any(os.path.splitext(f)[1] in SRC_EXT for f in os.listdir(target)
           if os.path.isfile(os.path.join(target,f))):
        mods.append((".", 0))
    return mods

def load_entry_points():
    """Pull entry points from CODE_MODEL.json (if built) and group by the file they live in."""
    try:
        cm=json.load(open(CODE_MODEL))
    except Exception:
        return {}
    eps=(cm.get("structural") or cm).get("entry_points") or cm.get("entry_points") or []
    by_file={}
    for e in eps:
        f=e.get("file","")
        by_file.setdefault(f,[]).append(e)
    return by_file

def eps_for_module(mod_path, target, ep_by_file):
    """All entry points whose file falls under this module's directory."""
    out=[]
    for f,lst in ep_by_file.items():
        # entry file paths in CODE_MODEL are relative to target root
        if f==mod_path or f.startswith(mod_path.rstrip(".")+"/") or (mod_path=="." ):
            if mod_path=="." and "/" in f:  # "." only owns root-level loose files
                continue
            out.extend(lst)
    return out

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--init"); ap.add_argument("--next",action="store_true")
    ap.add_argument("--done"); ap.add_argument("--summary",action="store_true")
    ap.add_argument("--list",action="store_true")
    ap.add_argument("--tree",action="store_true")
    a=ap.parse_args()
    if a.init:
        target=os.path.abspath(a.init)
        mods=modules_for(target)
        ep_by_file=load_entry_points()
        module_objs=[]
        for p,n in mods:
            eps=eps_for_module(p, target, ep_by_file) if ep_by_file else []
            module_objs.append({
                "path":p, "files":n, "status":"pending",
                "depth":p.count("/")+ (0 if p=="." else 1),   # tree level
                "entry_points":[{"method":e.get("method",""),"route":e.get("path",""),
                                 "kind":e.get("kind",""),"file":e.get("file",""),
                                 "line":e.get("line",0)} for e in eps],
                "entry_count":len(eps),
            })
        data={"target":a.init,"modules":module_objs,
              "has_entry_data":bool(ep_by_file)}
        os.makedirs(os.path.dirname(COV),exist_ok=True)
        json.dump(data,open(COV,"w"),indent=2)
        withep=sum(1 for m in module_objs if m["entry_count"])
        print(f"[coverage] {len(module_objs)} modules ({withep} with entry points) -> {COV}")
        return
    if not os.path.exists(COV): sys.exit("[coverage] not initialized (run --init <target>)")
    data=json.load(open(COV))
    mods=data["modules"]
    if a.list:
        for m in mods: print(m["path"])
        return
    if a.tree:
        # directory -> module -> entry point, with status marks
        for m in sorted(mods,key=lambda x:x["path"]):
            mark="\u2713" if m["status"]=="analyzed" else "\u00b7"
            ind="  "*max(0,m.get("depth",1)-1)
            ec=m.get("entry_count",0)
            tag=f"  [{ec} entry]" if ec else ""
            print(f"{ind}{mark} {m['path']}  ({m['files']} files){tag}")
            for e in m.get("entry_points",[])[:12]:
                print(f"{ind}    \u2192 {e.get('method','')} {e.get('route','')}  {e.get('file','')}:{e.get('line','')}")
        return
    if a.next:
        # attack surface first: pending modules WITH entry points (most reachable) before
        # pending leaf modules; among those, more entry points first.
        pend=[m for m in mods if m["status"]=="pending"]
        if not pend: return
        pend.sort(key=lambda m:(-m.get("entry_count",0), m["path"]))
        print(pend[0]["path"]); return
    if a.done:
        for m in mods:
            if m["path"]==a.done: m["status"]="analyzed"
        json.dump(data,open(COV,"w"),indent=2); print(f"[coverage] marked analyzed: {a.done}")
        return
    if a.summary:
        done=sum(1 for m in mods if m["status"]=="analyzed")
        withep=[m for m in mods if m.get("entry_count")]
        ep_done=sum(1 for m in withep if m["status"]=="analyzed")
        print(f"[coverage] {done}/{len(mods)} modules analyzed, {len(mods)-done} pending")
        if withep:
            print(f"[coverage] attack surface: {ep_done}/{len(withep)} entry-point modules analyzed")

if __name__=="__main__":
    main()