#!/usr/bin/env python3
"""
triage.py - rolling triage + report for the convergence stage.

Reads all of workspace/findings/, shows queue state (counts by status = the live
streaming view), ranks findings by severity x confidence(status), de-dups by
correlation_id, maps CWE -> OWASP Top 10, and writes workspace/report/report.md.

Run it repeatedly while producers stream findings (rolling), and once more at the
end for the final global report. false_positive findings are excluded from ranking.

Usage: triage.py [--findings workspace/findings] [--out workspace/report/report.md]
"""
import argparse, glob, json, os, collections

SEV_W = {"critical":5,"high":4,"medium":3,"low":2,"info":1}
CONF = {"confirmed":1.0,"reproduced":1.0,"cross_validated":0.7,
        "candidate":0.4,"needs_reanalysis":0.3,"false_positive":0.0}
OWASP = {
    "CWE-639":"A01 Broken Access Control","CWE-862":"A01 Broken Access Control",
    "CWE-269":"A01 Broken Access Control","CWE-352":"A01 Broken Access Control",
    "CWE-22":"A01 Broken Access Control","CWE-200":"A01 Broken Access Control",
    "CWE-915":"A01 Broken Access Control","CWE-601":"A01 Broken Access Control",
    "CWE-327":"A02 Cryptographic Failures",
    "CWE-89":"A03 Injection","CWE-78":"A03 Injection","CWE-77":"A03 Injection",
    "CWE-94":"A03 Injection","CWE-79":"A03 Injection","CWE-90":"A03 Injection",
    "CWE-91":"A03 Injection","CWE-943":"A03 Injection","CWE-1336":"A03 Injection",
    "CWE-841":"A04 Insecure Design","CWE-362":"A04 Insecure Design",
    "CWE-611":"A05 Security Misconfiguration",
    "CWE-287":"A07 Auth Failures","CWE-798":"A07 Auth Failures",
    "CWE-502":"A08 Integrity Failures",
    "CWE-918":"A10 SSRF",
}

def score(f):
    return SEV_W.get(f.get("severity_estimate","medium"),3) * CONF.get(f.get("status","candidate"),0.4)

def load(findings_dir):
    out=[]; bad=[]
    for p in glob.glob(os.path.join(findings_dir,"*.json")):
        if p.endswith(".lock"): continue
        try: out.append(json.load(open(p)))
        except Exception as e: bad.append((os.path.basename(p),str(e)))
    if bad:
        print(f"[triage] WARNING: {len(bad)} unreadable finding file(s) skipped:")
        for n,e in bad[:10]: print(f"    {n}: {e}")
    return out

def dedup(findings):
    groups=collections.OrderedDict()
    for f in findings:
        key=f.get("correlation_id") or f["id"]
        groups.setdefault(key,[]).append(f)
    reps=[]
    for key,g in groups.items():
        g.sort(key=score,reverse=True)
        rep=dict(g[0]); rep["_dup_count"]=len(g)
        reps.append(rep)
    return reps

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--findings",default="workspace/findings")
    ap.add_argument("--out",default="workspace/report/report.md")
    args=ap.parse_args()

    findings=load(args.findings)
    by_status=collections.Counter(f.get("status","candidate") for f in findings)
    by_class=collections.Counter(f.get("vuln_class","other") for f in findings)

    # queue / rolling view to stdout
    print("=== convergence queue (rolling) ===")
    for s in ["candidate","cross_validated","reproduced","confirmed","needs_reanalysis","false_positive"]:
        if by_status.get(s): print(f"  {s:18} {by_status[s]}")
    print(f"  total {len(findings)}")

    ranked=[f for f in dedup(findings) if f.get("status")!="false_positive"]
    ranked.sort(key=score,reverse=True)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)),exist_ok=True)
    L=[]
    L.append("# Security Assessment - Findings Report\n")
    L.append(f"_Total findings: {len(findings)} | ranked (excl. false positives): {len(ranked)}_\n")
    L.append("## Summary by status\n")
    for s in ["confirmed","reproduced","cross_validated","candidate","needs_reanalysis","false_positive"]:
        if by_status.get(s): L.append(f"- **{s}**: {by_status[s]}")
    L.append("\n## Summary by class\n")
    for c,n in by_class.most_common(): L.append(f"- {c}: {n}")
    novel=[f for f in ranked if (f.get("disclosure") or {}).get("status")=="novel"
           and f.get("status") in ("reproduced","confirmed")]
    if novel:
        L.append("\n## \u26a0\ufe0f Potential 0-day (reproduced + no public report)\n")
        for f in novel:
            sk=f.get("sink",{})
            L.append(f"- **{f.get('severity_estimate','?')}** {f.get('vuln_class','?')} "
                     f"at {sk.get('file','?')}:{sk.get('line','?')} - "
                     f"{(f.get('disclosure') or {}).get('rationale','')}")
    L.append("\n## Ranked findings\n")
    L.append("| # | sev | status | disclosure | class | CWE | OWASP | location | dups |")
    L.append("|---|-----|--------|-----------|-------|-----|-------|----------|------|")
    for i,f in enumerate(ranked,1):
        sink=f.get("sink",{})
        loc=f"{sink.get('file','?')}:{sink.get('line','?')}"
        owasp=OWASP.get((f.get('cwe') or '').upper(),"-")
        disc=(f.get('disclosure') or {}).get('status','-')
        L.append(f"| {i} | {f.get('severity_estimate','?')} | {f.get('status','?')} | {disc} | "
                 f"{f.get('vuln_class','?')} | {f.get('cwe','-')} | {owasp} | {loc} | "
                 f"{f.get('_dup_count',1)} |")
    L.append("\n## Details\n")
    for i,f in enumerate(ranked,1):
        L.append(f"### {i}. {f.get('title','(untitled)')}  `[{f.get('status')}]`")
        L.append(f"- class: {f.get('vuln_class')} ({f.get('cwe','-')}) | severity: {f.get('severity_estimate')}")
        src=f.get('source',{}); sink=f.get('sink',{})
        L.append(f"- source: {src.get('file','?')}:{src.get('line','?')} -> sink: {sink.get('file','?')}:{sink.get('line','?')}")
        if f.get('evidence'): L.append(f"- evidence: {f['evidence']}")
        rep=f.get('repro',{})
        if rep.get('attempted'):
            L.append(f"- repro: success={rep.get('success')} | {rep.get('observation','')}")
        d=f.get('disclosure') or {}
        if d.get('checked'):
            refs=", ".join(d.get('references',[]) or [])
            L.append(f"- disclosure: {d.get('status','?')}{(' ['+refs+']') if refs else ''} - {d.get('rationale','')}")
        L.append("")
    open(args.out,"w").write("\n".join(L))
    print(f"\n[triage] ranked {len(ranked)} -> {args.out}")

if __name__=="__main__":
    main()