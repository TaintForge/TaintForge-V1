#!/usr/bin/env python3
"""
coverage.py - track exhaustive analysis coverage over a big codebase by splitting it
into MODULES (so Codex analyzes everything in bounded chunks, not one shallow pass).

  --init <target>     build workspace/coverage.json = modules to analyze (status pending)
  --next              print the next PENDING module path (empty if none) -> drives the loop
  --done <module>     mark a module analyzed
  --summary           analyzed/total + remaining
A module is a directory chunk; large dirs are split into children so each chunk is
small enough for Codex to read deeply.
"""
import argparse, json, os, sys

NOISE={".git","vendor","node_modules","dist","build","__pycache__",".venv","venv",
       "target",".next","coverage","tests","test","spec","__tests__","fixtures","stubs"}
SRC_EXT={".php",".js",".ts",".jsx",".tsx",".py",".rb",".go",".java",".cs",".c",".cpp",".rs",".kt"}
COV="workspace/coverage.json"
SPLIT_THRESHOLD=400   # if a dir has more source files than this, use its children instead

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
        if n>SPLIT_THRESHOLD and depth<2:
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

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--init"); ap.add_argument("--next",action="store_true")
    ap.add_argument("--done"); ap.add_argument("--summary",action="store_true")
    ap.add_argument("--list",action="store_true")
    a=ap.parse_args()
    if a.init:
        mods=modules_for(os.path.abspath(a.init))
        data={"target":a.init,"modules":[{"path":p,"files":n,"status":"pending"} for p,n in mods]}
        os.makedirs(os.path.dirname(COV),exist_ok=True)
        json.dump(data,open(COV,"w"),indent=2)
        print(f"[coverage] {len(mods)} modules to analyze -> {COV}")
        return
    if not os.path.exists(COV): sys.exit("[coverage] not initialized (run --init <target>)")
    data=json.load(open(COV))
    if a.list:
        for m in data["modules"]: print(m["path"])
        return
    if a.next:
        for m in data["modules"]:
            if m["status"]=="pending": print(m["path"]); return
        return  # nothing pending -> empty
    if a.done:
        for m in data["modules"]:
            if m["path"]==a.done: m["status"]="analyzed"
        json.dump(data,open(COV,"w"),indent=2); print(f"[coverage] marked analyzed: {a.done}")
        return
    if a.summary:
        done=sum(1 for m in data["modules"] if m["status"]=="analyzed")
        print(f"[coverage] {done}/{len(data['modules'])} modules analyzed, "
              f"{len(data['modules'])-done} pending")

if __name__=="__main__":
    main()
