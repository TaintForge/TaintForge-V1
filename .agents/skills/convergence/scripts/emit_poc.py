#!/usr/bin/env python3
"""
emit_poc.py - materialize a per-vuln folder for every confirmed product vulnerability:
  workspace/report/<id>/poc.py     <- the agent-authored repro.poc_script, saved VERBATIM
  workspace/report/<id>/finding.md <- the individual report for that one vulnerability

This script does NOT invent or parse PoC steps. The convergence agent writes a poc.py that
fits the actual vulnerability (web PoCs typically use requests
emulator-only wrapper) and stores the full source in finding.repro.poc_script. We persist it.
If poc_script is missing we still write a finding.md and a small stub poc.py noting it's
absent, so the folder is never empty - but an eligible confirmed finding SHOULD carry poc_script.

Usage: emit_poc.py [--findings workspace/findings] [--out workspace/report]
"""
import argparse, glob, json, os, datetime
from official_review import confirmation_gate_passes

STUB = '''#!/usr/bin/env python3
# No poc_script was recorded for finding {id} ({vuln_class}).
# The convergence agent should author a target-specific poc.py and store it in
# finding.repro.poc_script. See finding.md for the recorded reproduction notes.
print("no PoC script recorded for finding {id}")
'''

def finding_md(f):
    r = f.get("repro", {}) or {}
    d = f.get("disclosure", {}) or {}
    official = f.get("official_review", {}) or {}
    src, sink = f.get("source", {}) or {}, f.get("sink", {}) or {}
    L = [f"# {f.get('title','(untitled)')}", "",
         f"- **id**: `{f.get('id')}`  ",
         f"- **class**: {f.get('vuln_class','?')} ({f.get('cwe','-')})  ",
         f"- **severity**: {f.get('severity_estimate','?')}  ",
         f"- **status**: {f.get('status','?')}  "]
    if d.get("checked"):
        refs = ", ".join(d.get("references", []) or [])
        L.append(f"- **disclosure**: {d.get('status','?')}{(' ['+refs+']') if refs else ''} - {d.get('rationale','')}  ")
    if official.get("checked"):
        sources = ", ".join(official.get("sources", []) or [])
        L += ["", "## Official product-boundary review", "",
              f"- **verdict**: {official.get('verdict','?')}  ",
              f"- **product version**: {official.get('product_version','?')}  ",
              f"- **default configuration**: {official.get('default_configuration','unknown')}  ",
              f"- **official sources**: {sources or '?'}  ",
              f"- **rationale**: {official.get('rationale','')}  "]
    if f.get("defect_shape") == "missing_control":
        mc = f.get("missing_control", {}) or {}
        L += ["", "## Missing control", "",
              f"- **control**: {mc.get('control','?')}  ",
              f"- **expected at**: {', '.join(mc.get('expected_at', []) or []) or '?'}  ",
              f"- **unguarded path**: `{mc.get('unguarded_path','?')}`  ",
              f"- **actor**: {mc.get('actor','?')}  "]
        if mc.get("evidence"):
            L.append(f"- **evidence**: {mc['evidence']}  ")
        L.append("")
        L += [f"**Privileged operation**: `{sink.get('file','?')}:{sink.get('line','?')}`"
              f" (key enters at `{src.get('file','?')}:{src.get('line','?')}`)", ""]
    else:
        L += ["", f"**Data flow**: `{src.get('file','?')}:{src.get('line','?')}` -> `{sink.get('file','?')}:{sink.get('line','?')}`", ""]
    reach = f.get("reachability", {}) or {}
    if reach:
        pre = {True: "yes", False: "no"}.get(reach.get("pre_auth"), "unknown")
        L += ["## Reachability", "",
              f"- **entry point**: {reach.get('entry_point','?')}  ",
              f"- **minimum privilege**: {reach.get('min_privilege','?')}  ",
              f"- **pre-auth**: {pre}  "]
        if reach.get("call_chain"):
            L.append("- **call chain**: " + " -> ".join(f"`{h}`" for h in reach["call_chain"]) + "  ")
        if reach.get("notes"):
            L.append(f"- **notes**: {reach['notes']}  ")
        L.append("")
    pre_c = f.get("preconditions", {}) or {}
    if pre_c:
        L += ["## Preconditions", "",
              "- **default configuration**: "
              + {True: "yes", False: "no", None: "unknown"}.get(pre_c.get("default_configuration"), "unknown")
              + "  "]
        if pre_c.get("required_settings"):
            L.append("- **required non-default settings**: " + ", ".join(pre_c["required_settings"]) + "  ")
        if pre_c.get("notes"):
            L.append(f"- **notes**: {pre_c['notes']}  ")
        L.append("")
    prim = f.get("primitive", {}) or {}
    if prim:
        L += ["## Primitive and proven ceiling", "",
              f"- **primitive**: {', '.join(prim.get('kinds', []) or []) or '?'}  ",
              f"- **escalation ceiling (proven bound)**: {prim.get('escalation_ceiling','?')}  "]
        if prim.get("ruled_out"):
            L.append("- **ruled out**: " + "; ".join(prim["ruled_out"]) + "  ")
        L.append("")
    if f.get("assets_affected"):
        L += ["## Assets affected", "", "- " + "\n- ".join(f["assets_affected"]), ""]
    if f.get("evidence"):
        L += ["## Evidence", "", str(f["evidence"]), ""]
    L += ["## Reproduction", "",
          f"- attempted: {r.get('attempted')} | success: {r.get('success')}"]
    if r.get("observation"): L.append(f"- observation: {r['observation']}")
    if r.get("response"): L.append(f"- response evidence: {r['response']}")
    local_runtime = "microsoft.netcore.app" in str(r.get("env", "")).lower()
    if r.get("poc"):
        L += ["", "Recorded reproduction command(s):", "```bash" if local_runtime else "```http",
              str(r["poc"]).strip(), "```"]
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
    run_lines = ["python3 poc.py"] if local_runtime else ["pip install requests   # if needed", "python3 poc.py"]
    L += ["", "## Run the PoC", "```bash", *run_lines, "```",
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
        if not confirmation_gate_passes(f): continue
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
