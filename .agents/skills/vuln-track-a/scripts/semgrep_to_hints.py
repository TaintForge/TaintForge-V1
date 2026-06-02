#!/usr/bin/env python3
"""
semgrep_to_hints.py - turn Semgrep/OpenGrep output into LEADS for Codex, NOT findings.
The tool never creates findings; it only points Codex at suspicious spots. Codex reads
the code around each lead (plus anything the tool missed) and decides what is a real
finding, writing those with write_finding.py.

Writes workspace/hints/track-a-semgrep.md (LLM-readable) + .json (structured).
Usage: semgrep_to_hints.py <semgrep_or_opengrep.json> [--root DIR] [--out workspace/hints]
"""
import argparse, json, os, re, sys

def cwe_of(meta):
    c=meta.get("cwe")
    if isinstance(c,str) and c.upper().startswith("CWE-"): return c.split(":")[0].upper()
    for t in (c if isinstance(c,list) else []) + meta.get("tags",[]):
        m=re.match(r"(CWE-\d+)", str(t))
        if m: return m.group(1)
    return ""

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("results"); ap.add_argument("--root",default="")
    ap.add_argument("--out",default="workspace/hints")
    a=ap.parse_args()
    if not os.path.exists(a.results):
        print(f"[hints] no tool output ({a.results}) - Codex proceeds from code alone"); sys.exit(0)
    d=json.load(open(a.results))
    leads=[]
    for r in d.get("results",[]):
        meta=r.get("extra",{}).get("metadata",{}) or {}
        p=r.get("path","")
        if a.root:
            try: p=os.path.relpath(p,a.root)
            except Exception: pass
        leads.append({
            "file":p, "line":r.get("start",{}).get("line"),
            "rule":r.get("check_id","").rsplit(".",1)[-1],
            "cwe":cwe_of(meta), "vuln_class_guess":meta.get("vuln_class",""),
            "message":(r.get("extra",{}).get("message","") or "")[:160],
        })
    os.makedirs(a.out,exist_ok=True)
    json.dump(leads, open(os.path.join(a.out,"track-a-semgrep.json"),"w"), indent=2)
    L=["# Track A - tool LEADS (NOT findings)\n",
       "These are suspicious spots from Semgrep/OpenGrep. They are leads only - many are",
       "false positives, and the tool misses plenty. Read the code around each, confirm or",
       "reject, and ALSO hunt for what the tool didn't flag. Record real ones with write_finding.py.\n",
       f"_{len(leads)} leads_\n",
       "| file:line | guess | CWE | rule | note |","|---|---|---|---|---|"]
    for x in leads:
        L.append(f"| {x['file']}:{x['line']} | {x['vuln_class_guess'] or '?'} | {x['cwe'] or '-'} | {x['rule']} | {x['message'][:80]} |")
    open(os.path.join(a.out,"track-a-semgrep.md"),"w").write("\n".join(L))
    print(f"[hints] {len(leads)} leads -> {a.out}/track-a-semgrep.md (leads only, not findings)")

if __name__=="__main__":
    main()