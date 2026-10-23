#!/usr/bin/env python3
"""
triage.py - rolling triage + report for the convergence stage.

Reads all of workspace/findings/, shows queue state (counts by status = the live
streaming view), ranks findings by severity x confidence(status), de-dups by
correlation_id, maps CWE -> OWASP Top 10, and writes workspace/report/report.md.

Run it repeatedly while producers stream findings (rolling), and once more at the
end for the final global report. False positives and reproduced behavior classified by
official/vendor evidence as non-product vulnerabilities are excluded from ranking.

Usage: triage.py [--findings workspace/findings] [--out workspace/report/report.md]
"""
import argparse, glob, json, os, collections
from official_review import (
    confirmation_gate_passes,
    disclosure_state,
    needs_public_history_work,
    novelty_gate_passes,
    official_review,
    review_state,
)

SEV_W = {"critical":5,"high":4,"medium":3,"low":2,"info":1}
CONF = {"confirmed":1.0,"reproduced":0.85,"cross_validated":0.7,
        "candidate":0.4,"needs_reanalysis":0.3,"not_product_vulnerability":0.0,
        "false_positive":0.0}
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
    "CWE-367":"A04 Insecure Design",
    "CWE-611":"A05 Security Misconfiguration",
    "CWE-287":"A07 Auth Failures","CWE-798":"A07 Auth Failures",
    "CWE-502":"A08 Integrity Failures",
    "CWE-918":"A10 SSRF",
}

def yesno(value):
    """Tri-state renderer: unknown is a distinct answer from no, and must read that way."""
    return {True: "yes", False: "no"}.get(value, "unknown")

def score(f):
    state = review_state(f)
    if state == "non_product":
        return 0
    confidence = CONF.get(f.get("status","candidate"),0.4)
    # Legacy findings may already say confirmed without having passed the new gate. Treat
    # those as reproduced behavior until official/vendor evidence is attached.
    if f.get("status") == "confirmed" and state != "reportable":
        confidence = CONF["reproduced"]
    return SEV_W.get(f.get("severity_estimate","medium"),3) * confidence

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
    for s in ["candidate","cross_validated","reproduced","confirmed","needs_reanalysis",
              "not_product_vulnerability","false_positive"]:
        if by_status.get(s): print(f"  {s:18} {by_status[s]}")
    review_pending=sum(1 for f in findings if f.get("status") in ("reproduced","confirmed")
                       and not confirmation_gate_passes(f))
    reportable_confirmed=sum(1 for f in findings if confirmation_gate_passes(f))
    public_history_pending=sum(1 for f in findings if needs_public_history_work(f))
    if review_pending: print(f"  {'official_review_pending':18} {review_pending}")
    if reportable_confirmed: print(f"  {'reportable_confirmed':18} {reportable_confirmed}")
    if public_history_pending: print(f"  {'public_history_pending':18} {public_history_pending}")
    print(f"  total {len(findings)}")

    representatives=dedup(findings)
    non_product=[f for f in representatives if f.get("status")=="not_product_vulnerability"
                 or review_state(f)=="non_product"]
    active=[f for f in representatives if f.get("status")!="false_positive"
            and f not in non_product]
    reportable=[f for f in active if confirmation_gate_passes(f)]
    provisional=[f for f in active if not confirmation_gate_passes(f)]
    reportable.sort(key=score,reverse=True)
    provisional.sort(key=score,reverse=True)
    ranked=reportable
    official_pending=[f for f in provisional if f.get("status") in ("reproduced","confirmed")
                      and not confirmation_gate_passes(f)]
    history_pending=[f for f in reportable if needs_public_history_work(f)]

    os.makedirs(os.path.dirname(os.path.abspath(args.out)),exist_ok=True)
    L=[]
    L.append("# Security Assessment - Findings Report\n")
    L.append(f"_Total findings: {len(findings)} | officially reportable unique roots: {len(reportable)} | "
             f"provisional: {len(provisional)} | non-product: {len(non_product)}_\n")
    L.append("## Summary by status\n")
    for s in ["confirmed","reproduced","cross_validated","candidate","needs_reanalysis",
              "not_product_vulnerability","false_positive"]:
        if by_status.get(s): L.append(f"- **{s}**: {by_status[s]}")
    L.append(f"- **officially reportable confirmed (raw)**: {reportable_confirmed}")
    L.append(f"- **officially reportable unique root causes**: {len(reportable)}")
    L.append(f"- **official review pending (raw)**: {review_pending}")
    L.append(f"- **official review pending unique root causes**: {len(official_pending)}")
    L.append(f"- **public-history/disclosure review pending (raw)**: {public_history_pending}")
    L.append(f"- **public-history/disclosure review pending unique root causes**: {len(history_pending)}")
    L.append("\n## Summary by class\n")
    for c,n in by_class.most_common(): L.append(f"- {c}: {n}")
    if official_pending:
        L.append("\n## Official/vendor review pending\n")
        L.append("These items reproduce behavior but are not yet confirmed product vulnerabilities.")
        for f in official_pending:
            review=official_review(f)
            L.append(f"- `{f.get('id','?')}` **{f.get('title','(untitled)')}** - "
                     f"verdict: `{review.get('verdict','not reviewed')}`")
    if history_pending:
        L.append("\n## Public-history/disclosure review pending\n")
        L.append("These confirmed product bugs cannot be called novel until exact source history, "
                 "upstream main/release code, vendor issues/PRs, and advisories/releases are checked.")
        for f in history_pending:
            raw=(f.get("disclosure") or {}).get("status", "not reviewed")
            L.append(f"- `{f.get('id','?')}` **{f.get('title','(untitled)')}** - "
                     f"claimed: `{raw}`; effective disclosure state: `{disclosure_state(f)}`")
    novel=[f for f in reportable if novelty_gate_passes(f)]
    if novel:
        L.append("\n## \u26a0\ufe0f Potential 0-day (officially reviewed product vulnerabilities)\n")
        for f in novel:
            sk=f.get("sink",{})
            L.append(f"- **{f.get('severity_estimate','?')}** {f.get('vuln_class','?')} "
                     f"at {sk.get('file','?')}:{sk.get('line','?')} - "
                     f"{(f.get('disclosure') or {}).get('rationale','')}")
    exploited=[f for f in reportable if f.get("exploit")
               and (f.get("exploit") or {}).get("depth") in ("chained","weaponized")]
    if exploited:
        L.append("\n## \U0001f4a5 Weaponized / chained exploits\n")
        for f in exploited:
            ex=f.get("exploit") or {}; sk=f.get("sink",{})
            L.append(f"- **{f.get('severity_estimate','?')}** {f.get('vuln_class','?')} "
                     f"at {sk.get('file','?')}:{sk.get('line','?')} - "
                     f"depth **{ex.get('depth','?')}**; primitive: {ex.get('primitive','?')}; "
                     f"max impact: {ex.get('max_impact','?')}")
            cons=ex.get('constraints') or []
            if cons: L.append(f"  - constraints (honest bounds): {'; '.join(cons)}")
            byp=ex.get('mitigations_bypassed') or []
            if byp: L.append(f"  - mitigations bypassed: {'; '.join(byp)}")
    if non_product:
        L.append("\n## Reproduced but not a product vulnerability\n")
        for f in non_product:
            review=official_review(f)
            L.append(f"- `{f.get('id','?')}` **{f.get('title','(untitled)')}** - "
                     f"`{review.get('verdict','unclassified')}`: {review.get('rationale','')}")
    if provisional:
        L.append("\n## Provisional findings (not reportable)\n")
        L.append("These findings remain analysis work items and are not confirmed vendor vulnerabilities.")
        L.append("| sev | status | official review | class | location |")
        L.append("|-----|--------|-----------------|-------|----------|")
        for f in provisional:
            sink=f.get("sink",{})
            loc=f"{sink.get('file','?')}:{sink.get('line','?')}"
            official=official_review(f).get('verdict','pending')
            L.append(f"| {f.get('severity_estimate','?')} | {f.get('status','?')} | {official} | "
                     f"{f.get('vuln_class','?')} | {loc} |")
    L.append("\n## Ranked confirmed product vulnerabilities\n")
    L.append("| # | sev | status | official review | disclosure | class | CWE | OWASP | location | dups |")
    L.append("|---|-----|--------|-----------------|------------|-------|-----|-------|----------|------|")
    for i,f in enumerate(ranked,1):
        sink=f.get("sink",{})
        loc=f"{sink.get('file','?')}:{sink.get('line','?')}"
        owasp=OWASP.get((f.get('cwe') or '').upper(),"-")
        raw_disc=(f.get('disclosure') or {}).get('status','-')
        effective_disc=disclosure_state(f)
        disc=raw_disc if raw_disc == effective_disc else f"{raw_disc} (gate: {effective_disc})"
        official=official_review(f).get('verdict','pending')
        L.append(f"| {i} | {f.get('severity_estimate','?')} | {f.get('status','?')} | {official} | {disc} | "
                 f"{f.get('vuln_class','?')} | {f.get('cwe','-')} | {owasp} | {loc} | "
                 f"{f.get('_dup_count',1)} |")
    if not ranked:
        L.append("\n_No finding has passed the official/vendor product-boundary gate._\n")
    L.append("\n## Confirmed product vulnerability details\n")
    for i,f in enumerate(ranked,1):
        L.append(f"### {i}. {f.get('title','(untitled)')}  `[{f.get('status')}]`")
        L.append(f"- class: {f.get('vuln_class')} ({f.get('cwe','-')}) | severity: {f.get('severity_estimate')}")
        src=f.get('source',{}); sink=f.get('sink',{})
        L.append(f"- source: {src.get('file','?')}:{src.get('line','?')} -> sink: {sink.get('file','?')}:{sink.get('line','?')}")
        mc=f.get('missing_control') or {}
        if mc:
            L.append(f"- missing control: {mc.get('control','?')} | unguarded path: "
                     f"{mc.get('unguarded_path','?')} | actor: {mc.get('actor','?')}")
        reach=f.get('reachability') or {}
        if reach:
            pre=reach.get('pre_auth')
            L.append(f"- reachability: {reach.get('entry_point','?')} | min privilege: "
                     f"{reach.get('min_privilege','?')} | pre-auth: {yesno(pre)}")
            if reach.get('call_chain'):
                L.append("  - call chain: " + " -> ".join(str(h) for h in reach['call_chain']))
        pre_c=f.get('preconditions') or {}
        if pre_c:
            line=f"- preconditions: default config={yesno(pre_c.get('default_configuration'))}"
            if pre_c.get('required_settings'):
                line += " | requires: " + ", ".join(pre_c['required_settings'])
            L.append(line)
        prim=f.get('primitive') or {}
        if prim:
            L.append(f"- primitive: {', '.join(prim.get('kinds') or []) or '?'} | ceiling: "
                     f"{prim.get('escalation_ceiling','?')}")
            if prim.get('ruled_out'):
                L.append("  - ruled out: " + "; ".join(prim['ruled_out']))
        if f.get('assets_affected'):
            L.append("- assets: " + ", ".join(f['assets_affected']))
        if f.get('evidence'): L.append(f"- evidence: {f['evidence']}")
        rep=f.get('repro',{})
        local_runtime="microsoft.netcore.app" in str(rep.get('env','')).lower()
        if rep.get('attempted'):
            L.append(f"- repro: success={rep.get('success')} | {rep.get('observation','')}")
            if rep.get('poc'):
                L.append("- PoC:")
                L.append("```bash" if local_runtime else "```http")
                L.append(str(rep['poc']).strip())
                L.append("```")
            if rep.get('response'):
                L.append(f"- response evidence: {rep['response']}")
            if rep.get('reliability'):
                L.append(f"- reliability: {rep['reliability']}")
            if rep.get('instrumentation_only') is not None or rep.get('stock_replay'):
                L.append(f"- instrumentation only: {yesno(rep.get('instrumentation_only'))}"
                         + (f" | stock replay: {rep['stock_replay']}" if rep.get('stock_replay') else ""))
        d=f.get('disclosure') or {}
        official=official_review(f)
        if official:
            refs=", ".join(official.get('sources',[]) or [])
            L.append(f"- official review: {official.get('verdict','?')} "
                     f"(version={official.get('product_version','?')}, "
                     f"default={official.get('default_configuration','unknown')})")
            if refs: L.append(f"  - official sources: {refs}")
            if official.get('rationale'): L.append(f"  - rationale: {official['rationale']}")
        elif f.get('status') in ('reproduced','confirmed'):
            L.append("- official review: **pending; not yet a confirmed product vulnerability**")
        if d.get('checked'):
            refs=", ".join(d.get('references',[]) or [])
            L.append(f"- disclosure: {d.get('status','?')}{(' ['+refs+']') if refs else ''} - {d.get('rationale','')}")
        ex=f.get('exploit') or {}
        if ex.get('depth'):
            L.append(f"- exploit: depth={ex.get('depth')}; primitive={ex.get('primitive','?')}; max_impact={ex.get('max_impact','?')}")
            if ex.get('steps'): L.append("  - steps: " + " -> ".join(ex['steps']))
            if ex.get('constraints'): L.append("  - constraints: " + "; ".join(ex['constraints']))
            if ex.get('oob_evidence'): L.append(f"  - OOB evidence: {ex['oob_evidence']}")
        L.append("")
    open(args.out,"w").write("\n".join(L))
    print(f"\n[triage] reportable {len(ranked)}; provisional {len(provisional)} -> {args.out}")

if __name__=="__main__":
    main()
