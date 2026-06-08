#!/usr/bin/env python3
"""callgraph.py - query the function/method-level graph in workspace/CODE_MODEL.json."""
from __future__ import annotations
import argparse, collections, json, os, sys
from typing import Any, Dict, Iterable, List, Sequence, Tuple

def load_model(path):
    try: return json.load(open(path,encoding="utf-8"))
    except FileNotFoundError: sys.exit(f"[callgraph] missing model: {path}. Run build_code_model.sh first.")
def structural(model): return model.get("structural",model)
def edges(model): return structural(model).get("call_graph",[]) or []
def entry_points(model): return structural(model).get("entry_points",[]) or []
def load_symbols(model):
    st=structural(model); ref=st.get("symbols_ref"); syms=[]
    if ref and os.path.exists(ref):
        try:
            data=json.load(open(ref,encoding="utf-8"))
            syms=data.get("symbols",[]) if isinstance(data,dict) else data
        except Exception: syms=[]
    if not syms:
        tmp={}
        for e in edges(model):
            tmp.setdefault(e.get("from",""),{"id":e.get("from",""),"qualified_name":e.get("caller_name",e.get("from","")),
                "file":e.get("caller_file",""),"start_line":e.get("caller_line",0)})
            if e.get("callee_symbol"):
                tmp.setdefault(e.get("to",""),{"id":e.get("to",""),"qualified_name":e.get("callee_name",e.get("to","")),
                    "file":e.get("callee_file",""),"start_line":e.get("callee_line",0)})
        return {k:v for k,v in tmp.items() if k}
    return {s["id"]:s for s in syms if s.get("id")}
def fmt_symbol(sid,syms):
    if sid in syms:
        s=syms[sid]; loc=f"{s.get('file','')}:{s.get('start_line',0)}"
        return f"{s.get('qualified_name') or s.get('name') or sid} [{loc}]"
    return sid
def edge_label(e):
    loc=f"{e.get('callsite_file','')}:{e.get('callsite_line',0)}"
    callee=e.get("receiver","")+("." if e.get("receiver") else "")+e.get("callee","")
    sink=f" sink={e.get('sink_category')}" if e.get("sink_category") else ""
    conf=f" {e.get('resolution','')}/{e.get('confidence','')}".strip()
    return f"--{callee}@{loc} [{conf}{sink}]-->"
def node_matches(node,query,syms):
    if node==query: return True
    s=syms.get(node,{}); vals=[s.get("name",""),s.get("qualified_name",""),s.get("file","")]
    return any(v==query or v.endswith("."+query) or query in v for v in vals if v)
def edge_matches_callee(e,query,syms):
    if e.get("callee")==query or e.get("to")==query or e.get("callee_symbol")==query: return True
    if e.get("receiver") and f"{e.get('receiver')}.{e.get('callee')}"==query: return True
    return node_matches(e.get("to",""),query,syms)
def build_indexes(es):
    adj=collections.defaultdict(list); rev=collections.defaultdict(list)
    for e in es:
        if not e.get("from") or not e.get("to"): continue
        adj[e["from"]].append(e); rev[e["to"]].append(e)
    return adj,rev
def print_path(path,syms,reverse=False):
    if not path: return
    parts=[fmt_symbol(path[0]["from"],syms)]
    for e in path: parts.append(edge_label(e)); parts.append(fmt_symbol(e["to"],syms))
    print("   "+" ".join(parts))
def backward_paths(start_nodes,rev,entry_nodes,depth,limit):
    out=[]; q=collections.deque()
    for s in start_nodes: q.append((s,[],{s}))
    while q and len(out)<limit:
        node,path,seen=q.popleft()
        if len(path)>=depth:
            if path: out.append(list(reversed(path)))
            continue
        callers=rev.get(node,[])
        if not callers:
            if path: out.append(list(reversed(path)))
            continue
        for e in callers:
            prev=e["from"]; new_path=path+[e]
            if prev in entry_nodes:
                out.append(list(reversed(new_path)))
                if len(out)>=limit: break
            elif prev not in seen: q.append((prev,new_path,seen|{prev}))
    return out
def forward_paths(start,adj,depth,limit,stop_at_sink):
    out=[]; q=collections.deque([(start,[],{start})])
    while q and len(out)<limit:
        node,path,seen=q.popleft()
        if len(path)>=depth:
            if path: out.append(path)
            continue
        nxt_edges=adj.get(node,[])
        if not nxt_edges:
            if path: out.append(path)
            continue
        for e in nxt_edges:
            nxt=e["to"]; new_path=path+[e]
            if stop_at_sink and (e.get("sink_category") or nxt.startswith("builtin:sink:")):
                out.append(new_path)
                if len(out)>=limit: break
                continue
            if nxt.startswith("external:") or nxt.startswith("builtin:") or nxt in seen:
                out.append(new_path)
                if len(out)>=limit: break
                continue
            q.append((nxt,new_path,seen|{nxt}))
    return out
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--model",default="workspace/CODE_MODEL.json")
    ap.add_argument("--stats",action="store_true"); ap.add_argument("--entries",action="store_true")
    ap.add_argument("--sinks",action="store_true"); ap.add_argument("--callers")
    ap.add_argument("--callees"); ap.add_argument("--trace"); ap.add_argument("--forward")
    ap.add_argument("-d","--depth",type=int,default=6); ap.add_argument("--limit",type=int,default=80)
    args=ap.parse_args()
    # --stats: prefer the tiny sidecar so we never json.load a GB-scale model just for counts.
    if args.stats:
        sidecar=os.path.join(os.path.dirname(args.model) or ".","_model_stats.json")
        if os.path.exists(sidecar):
            try:
                sc=json.load(open(sidecar,encoding="utf-8")); st=sc.get("stats",sc)
                print(f"target={sc.get('target','')} mode={st.get('mode','')}")
                for k in ("files","symbols","functions_or_methods","entry_points","callsites",
                          "call_edges","resolved_edges","sink_edges","sources","guards",
                          "entry_to_sink_paths","open_edges"):
                    if k in st: print(f"  {k}={st[k]}")
                print("(from _model_stats.json sidecar; omit --stats for graph queries)")
                return
            except Exception: pass
    model=load_model(args.model); es=edges(model); syms=load_symbols(model); eps=entry_points(model)
    # graph-only models carry no inline edges (they were split to call_graph_ref to stay loadable
    # on huge repos). Graph queries that need edges would silently return nothing - warn instead.
    st=structural(model)
    if not es and st.get("mode")=="graph-only" and (args.callers or args.callees or args.trace or args.forward or args.sinks):
        ref=st.get("call_graph_ref","")
        print("[callgraph] this is a GRAPH-ONLY global index: edges are not inline "
              f"({'in '+ref if ref else 'split out'}). Whole-repo edge queries OOM on a repo this "
              "size by design. Build the specific MODULE you care about and query that:")
        print("  python3 .agents/skills/source-model/scripts/build_code_model.py <module_dir> -o workspace/cm/<m>.json")
        print("  python3 .agents/skills/source-model/scripts/callgraph.py --model workspace/cm/<m>.json --sinks|--trace|--forward")
        return
    adj,rev=build_indexes(es); entry_nodes={e.get("handler_symbol") for e in eps if e.get("handler_symbol")}
    if args.stats:
        callees=collections.Counter(e.get("callee","") for e in es)
        resolutions=collections.Counter(e.get("resolution","") for e in es)
        sinks=collections.Counter(e.get("sink_category","") for e in es if e.get("sink_category"))
        print(f"edges={len(es)} symbols={len(syms)} entries={len(eps)} entry_symbols={len(entry_nodes)}")
        print(f"resolved_edges={sum(1 for e in es if e.get('callee_symbol'))} builtin_or_sink_edges={sum(1 for e in es if e.get('sink_category') or str(e.get('to','')).startswith('builtin:sink:'))}")
        print("top callees:")
        for n,c in callees.most_common(15): print(f"  {c:4d}  {n}")
        print("resolutions:")
        for n,c in resolutions.most_common(): print(f"  {c:4d}  {n or '<none>'}")
        if sinks:
            print("sink categories:")
            for n,c in sinks.most_common(): print(f"  {c:4d}  {n}")
        return
    if args.entries:
        print(f"entry points: {len(eps)}")
        for e in eps:
            h=e.get("handler_symbol") or e.get("handler") or "<unresolved>"
            print(f"  {e.get('method',''):6s} {e.get('path','') or '<controller-action>'}  {e.get('file','')}:{e.get('line',0)}  -> {h}")
        return
    if args.sinks:
        hits=[e for e in es if e.get("sink_category") or str(e.get("to","")).startswith("builtin:sink:")]
        print(f"sinks: {len(hits)}")
        for e in hits[:args.limit]:
            print(f"  {e.get('sink_category',''):16s} {e.get('callee',''):24s} {e.get('callsite_file','')}:{e.get('callsite_line',0)}  caller={fmt_symbol(e.get('from',''),syms)}")
        if len(hits)>args.limit: print(f"  ... {len(hits)-args.limit} more")
        return
    if args.callers:
        hits=[e for e in es if edge_matches_callee(e,args.callers,syms)]
        print(f"callers of {args.callers}: {len(hits)}")
        for e in hits[:args.limit]: print(f"  {fmt_symbol(e.get('from',''),syms)} {edge_label(e)} {fmt_symbol(e.get('to',''),syms)}")
        if len(hits)>args.limit: print(f"  ... {len(hits)-args.limit} more")
        return
    if args.callees:
        q=args.callees
        if any(e.get("caller_file")==q or e.get("callsite_file")==q for e in es):
            hits=[e for e in es if e.get("caller_file")==q or e.get("callsite_file")==q]
        else:
            start_nodes=[sid for sid in syms if node_matches(sid,q,syms)] or [q]
            hits=[e for e in es if e.get("from") in start_nodes]
        print(f"callees from {q}: {len(hits)}")
        for e in hits[:args.limit]: print(f"  {fmt_symbol(e.get('from',''),syms)} {edge_label(e)} {fmt_symbol(e.get('to',''),syms)}")
        if len(hits)>args.limit: print(f"  ... {len(hits)-args.limit} more")
        return
    if args.trace:
        starts={e["to"] for e in es if edge_matches_callee(e,args.trace,syms)}
        if not starts and args.trace in syms: starts={args.trace}
        print(f"backward paths into {args.trace} (depth {args.depth}, starts={len(starts)}):")
        paths=backward_paths(starts,rev,entry_nodes,args.depth,args.limit)
        for p in paths: print_path(p,syms)
        if not paths: print("   <no graph path found; inspect direct callers with --callers>")
        return
    if args.forward:
        starts=[sid for sid in syms if node_matches(sid,args.forward,syms)] or [args.forward]
        print(f"forward paths from {args.forward} (depth {args.depth}, starts={len(starts)}):")
        shown=0
        for st in starts:
            for p in forward_paths(st,adj,args.depth,args.limit-shown,stop_at_sink=True):
                print_path(p,syms); shown+=1
                if shown>=args.limit: break
            if shown>=args.limit: break
        if shown==0: print("   <no graph path found>")
        return
    ap.print_help()
if __name__=="__main__": main()