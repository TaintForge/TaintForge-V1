#!/usr/bin/env python3
"""
gen_hypotheses.py - seed workspace/HYPOTHESES.json with domain business-logic hypotheses.

Top-down complement to A/B's bottom-up scan: instead of only "find risky patterns in code,"
this asks "given what this service IS, what business-logic flaws are likely?" - then the
producers VERIFY those against the code. Catches domain-specific bugs (double-spend,
protected-branch bypass, block-evasion) that generic authz/injection patterns miss.

Domain selection:
  --domain X         explicit (finance|vcs|community|generic|...); else
  SERVICE_DOMAIN env; else
  inferred from CODE_MODEL entry points + target name (best-effort; the LLM refines).

This only seeds the CATALOG hypotheses deterministically. The hypothesize SKILL then has the
LLM add service-specific hypotheses from the actual user/admin logic flows and rewrite the
file. Each hypothesis stays a HYPOTHESIS until a producer verifies it into a finding.

Usage:
  gen_hypotheses.py --target targets/<app> [--domain finance]
  gen_hypotheses.py --target targets/gitlab            # infers 'vcs'
"""
import argparse, json, os, sys

HERE=os.path.dirname(os.path.abspath(__file__))
CATALOG=os.path.join(HERE,"catalog.json")
CODE_MODEL="workspace/CODE_MODEL.json"
OUT="workspace/HYPOTHESES.json"

def infer_domain(target, catalog):
    """Best-effort: match target name + entry-point paths against domain aliases."""
    hay=os.path.basename(target.rstrip("/")).lower()
    try:
        cm=json.load(open(CODE_MODEL))
        eps=(cm.get("structural") or cm).get("entry_points") or cm.get("entry_points") or []
        hay+=" "+" ".join((e.get("path","")+" "+e.get("file","")).lower() for e in eps[:200])
    except Exception:
        pass
    best=("generic",0)
    for dom,spec in catalog["domains"].items():
        if dom=="generic": continue
        score=sum(1 for a in spec.get("aliases",[]) if a!="*" and a in hay)
        if score>best[1]: best=(dom,score)
    return best[0]

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--target",required=True)
    ap.add_argument("--domain")
    a=ap.parse_args()
    catalog=json.load(open(CATALOG))

    domain=a.domain or os.environ.get("SERVICE_DOMAIN") or infer_domain(a.target,catalog)
    if domain not in catalog["domains"]:
        print(f"[hypotheses] unknown domain '{domain}', falling back to generic", file=sys.stderr)
        domain="generic"

    # always include generic + the matched domain
    picked=["generic"] if domain=="generic" else [domain,"generic"]
    hyps=[]; hid=0
    for dom in picked:
        spec=catalog["domains"][dom]
        for h in spec["hypotheses"]:
            hid+=1
            hyps.append({
                "id": f"H{hid:03d}",
                "domain": dom,
                "source": "catalog",
                "class": h["class"],
                "name": h["name"],
                "why": h["why"],
                "check_how": h["check_how"],
                "target_endpoints": [],          # LLM fills from entry points
                "status": "open",                # open -> verified | refuted (by producers)
            })
    # universal patterns (OWASP BLA / API / research-derived) apply to every target
    for h in catalog.get("_universal", []):
        hid+=1
        hyps.append({"id":f"H{hid:03d}","domain":"_universal","source":"catalog",
                     "class":h["class"],"name":h["name"],"why":h["why"],
                     "check_how":h["check_how"],"target_endpoints":[],"status":"open"})
    # CWE-derived pool (hundreds), if cwe_to_hypotheses.py was run
    cwe=catalog.get("_cwe_derived",{})
    for h in cwe.get("hypotheses", []):
        hyps.append({"id":h["id"],"domain":"_cwe","source":"cwe","cwe_id":h.get("cwe_id"),
                     "class":h["class"],"name":h["name"],"why":h["why"],
                     "check_how":h["check_how"],"target_endpoints":[],"status":"open"})
    data={
        "target": a.target,
        "domain": domain,
        "domain_flows": catalog["domains"].get(domain,{}).get("flows",[]),
        "note": "Catalog seed. The hypothesize skill adds service-specific hypotheses (source=llm) from real user/admin flows. Producers verify each against the code; mark status verified/refuted and link findings via hypothesis_id.",
        "hypotheses": hyps,
    }
    os.makedirs(os.path.dirname(OUT),exist_ok=True)
    json.dump(data,open(OUT,"w"),indent=2)
    bysrc={}
    for h in hyps: bysrc[h["source"]]=bysrc.get(h["source"],0)+1
    print(f"[hypotheses] domain={domain}  total {len(hyps)} hypotheses -> {OUT}")
    print(f"[hypotheses] by source: {bysrc}")
    print("[hypotheses] now have the LLM add service-specific ones (source=llm) per the skill.")

if __name__=="__main__":
    main()