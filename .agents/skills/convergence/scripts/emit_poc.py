#!/usr/bin/env python3
"""
emit_poc.py - materialize a per-vuln folder for every reproduced/confirmed finding:
  workspace/report/<id>/poc.py     <- the agent-authored repro.poc_script, saved VERBATIM
  workspace/report/<id>/finding.md <- the individual report for that one vulnerability

This script does NOT invent or parse PoC steps. The convergence agent writes a poc.py that
fits the actual vulnerability (pre-auth = no login; whatever number of requests it takes,
using requests) and stores the full source in finding.repro.poc_script. We just persist it.
If poc_script is missing we still write a finding.md and a small stub poc.py noting it's
absent, so the folder is never empty - but a reproduced finding SHOULD carry poc_script.

Usage: emit_poc.py [--findings workspace/findings] [--out workspace/report]
"""
import argparse, glob, json, os, datetime

EMIT_STATUSES = {"reproduced", "confirmed"}

STUB = '''#!/usr/bin/env python3
# No poc_script was recorded for finding {id} ({vuln_class}).
# The convergence agent should author a requests-based poc.py for this vuln and store it
# in finding.repro.poc_script. See finding.md for the recorded reproduction notes.
print("no PoC script recorded for finding {id}")
'''

def finding_md(f):
    r = f.get("repro", {}) or {}
    d = f.get("disclosure", {}) or {}
    src, sink = f.get("source", {}) or {}, f.get("sink", {}) or {}
    L = [f"# {f.get('title','(untitled)')}", "",
         f"- **id**: `{f.get('id')}`  ",
         f"- **class**: {f.get('vuln_class','?')} ({f.get('cwe','-')})  ",
         f"- **severity**: {f.get('severity_estimate','?')}  ",
         f"- **status**: {f.get('status','?')}  "]
    if d.get("checked"):
        refs = ", ".join(d.get("references", []) or [])
        L.append(f"- **disclosure**: {d.get('status','?')}{(' ['+refs+']') if refs else ''} - {d.get('rationale','')}  ")
    L += ["", f"**Data flow**: `{src.get('file','?')}:{src.get('line','?')}` -> `{sink.get('file','?')}:{sink.get('line','?')}`", ""]
    if f.get("evidence"):
        L += ["## Evidence", "", str(f["evidence"]), ""]
    L += ["## Reproduction", "",
          f"- attempted: {r.get('attempted')} | success: {r.get('success')}"]
    if r.get("observation"): L.append(f"- observation: {r['observation']}")
    if r.get("response"): L.append(f"- response evidence: {r['response']}")
    if r.get("poc"):
        L += ["", "Recorded request(s):", "```http", str(r["poc"]).strip(), "```"]
    ex = f.get("exploit", {}) or {}
    if ex.get("depth"):
        L += ["", "## Exploitation", "",
              f"- **depth**: {ex.get('depth')}  ",
              f"- **primitive**: {ex.get('primitive','?')}  ",
              f"- **max impact**: {ex.get('max_impact','?')}  "]
        if ex.get("steps"): L += ["- steps:"] + [f"  {i+1}. {s}" for i,s in enumerate(ex["steps"])]
        if ex.get("mitigations_bypassed"): L.append("- mitigations bypassed: " + "; ".join(ex["mitigations_bypassed"]))
        if ex.get("constraints"): L.append("- constraints (honest bounds): " + "; ".join(ex["constraints"]))
        if ex.get("oob_evidence"): L.append(f"- OOB evidence: {ex['oob_evidence']}")
        if ex.get("working_poc","").strip():
            L += ["", "Run the weaponized exploit:", "```bash", "python3 exploit.py", "```"]
    L += ["", "## Run the PoC", "```bash", "pip install requests   # if needed", "python3 poc.py", "```",
          "", f"_generated {datetime.datetime.now(datetime.timezone.utc).isoformat()}_"]
    return "\n".join(L)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--findings", default="workspace/findings")
    ap.add_argument("--out", default="workspace/report")
    a = ap.parse_args()
    n = 0
    for p in glob.glob(os.path.join(a.findings, "*.json")):
        try: f = json.load(open(p))
        except Exception: continue
        if f.get("status") not in EMIT_STATUSES: continue
        fid = str(f.get("id", os.path.basename(p)[:-5]))
        d = os.path.join(a.out, fid); os.makedirs(d, exist_ok=True)
        script = (f.get("repro", {}) or {}).get("poc_script")
        if script and script.strip():
            open(os.path.join(d, "poc.py"), "w").write(script)
        else:
            open(os.path.join(d, "poc.py"), "w").write(
                STUB.format(id=fid, vuln_class=f.get("vuln_class","?")))
        open(os.path.join(d, "finding.md"), "w").write(finding_md(f))
        ex = (f.get("exploit", {}) or {}).get("working_poc")
        if ex and ex.strip():
            open(os.path.join(d, "exploit.py"), "w").write(ex)
        n += 1
    print(f"[emit_poc] wrote {n} per-vuln folder(s) under {a.out}/<id>/ (poc.py + finding.md)")

if __name__ == "__main__":
    main()