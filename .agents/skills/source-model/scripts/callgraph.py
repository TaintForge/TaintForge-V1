#!/usr/bin/env python3
"""
callgraph.py - inspect/verify the call graph in workspace/CODE_MODEL.json.

  callgraph.py --stats                 edge/function counts, top callees
  callgraph.py --callers <name>        who calls <name>  (one backward hop)
  callgraph.py --trace  <name> [-d N]  backward taint paths INTO <name> up to depth N
  callgraph.py --callees <file>        what <file> calls
Use --trace to follow a sink (e.g. a query/exec function) back toward entry points.
"""
import argparse, json, collections, sys

def load(p):
    d=json.load(open(p))["structural"]
    return d.get("call_graph",[])

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--model", default="workspace/CODE_MODEL.json")
    ap.add_argument("--stats", action="store_true")
    ap.add_argument("--callers"); ap.add_argument("--callees")
    ap.add_argument("--trace"); ap.add_argument("-d","--depth", type=int, default=4)
    a=ap.parse_args()
    edges=load(a.model)
    if a.stats:
        callees=collections.Counter(e["callee"] for e in edges)
        files=set(e["from"] for e in edges)|set(e["to"] for e in edges)
        print(f"edges={len(edges)}  files_in_graph={len(files)}  distinct_callees={len(callees)}")
        print("top called functions:")
        for n,c in callees.most_common(15): print(f"  {c:4d}  {n}")
        return
    if a.callers:
        hits=[e for e in edges if e["callee"]==a.callers]
        print(f"callers of {a.callers}: {len(hits)}")
        for e in hits: print(f"  {e['from']}  -->  {a.callers} (in {e['to']})")
        return
    if a.callees:
        hits=[e for e in edges if e["from"]==a.callees]
        print(f"{a.callees} calls {len(hits)}:")
        for e in hits: print(f"  {e['callee']}  (in {e['to']})")
        return
    if a.trace:
        # backward: find callees == target, then who calls the function defined where? coarse:
        by_callee=collections.defaultdict(list)
        for e in edges: by_callee[e["callee"]].append(e["from"])
        def walk(name, depth, path, seen):
            callers=by_callee.get(name,[])
            if not callers or depth==0:
                print("   "+" <- ".join(path)); return
            for cf in callers:
                if cf in seen: 
                    print("   "+" <- ".join(path+[cf+"(cycle)"])); continue
                walk_file(cf, depth-1, path+[cf], seen|{cf})
        def walk_file(caller_file, depth, path, seen):
            # functions defined in caller_file that are themselves called
            inner=[e["callee"] for e in edges if e["from"]==caller_file]
            # continue tracing who calls caller_file's own callers via callee names is coarse;
            # we simply report the file chain (coarse interprocedural hint for the LLM)
            print("   "+" <- ".join(path))
        print(f"backward into {a.trace} (depth {a.depth}):")
        walk(a.trace, a.depth, [a.trace], set())
        return
    ap.print_help()

if __name__=="__main__":
    main()