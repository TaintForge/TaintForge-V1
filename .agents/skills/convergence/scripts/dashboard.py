#!/usr/bin/env python3
"""dashboard.py - live status panel for TaintForge (refreshes in place)."""
import json, os, glob, time, collections, sys, subprocess
from official_review import (
    confirmation_gate_passes, needs_public_history_work, novelty_gate_passes, review_state
)

C = {"reset":"\033[0m","dim":"\033[2m","b":"\033[1m","cyan":"\033[36m","grn":"\033[32m",
     "yel":"\033[33m","red":"\033[31m","mag":"\033[35m","blu":"\033[34m","gry":"\033[90m"}
SEV = {"critical":C["red"],"high":C["red"],"medium":C["yel"],"low":C["blu"],"info":C["gry"]}
STT = {"candidate":C["gry"],"cross_validated":C["cyan"],"reproduced":C["grn"],
       "confirmed":C["grn"]+C["b"],"not_product_vulnerability":C["dim"],
       "false_positive":C["dim"],"needs_reanalysis":C["mag"]}
START = time.time()

def load(p):
    try: return json.load(open(p))
    except Exception: return None

def bar(done, total, w=24):
    if total<=0: return C["gry"]+"·"*w+C["reset"]
    f=int(w*done/total); return C["grn"]+"█"*f+C["gry"]+"░"*(w-f)+C["reset"]

def main():
    findings_dir="workspace/findings"; cov="workspace/coverage.json"
    while True:
        # keep report.md always current (not stale) - cheap, runs triage quietly
        try:
            subprocess.run(["python3",".agents/skills/convergence/scripts/triage.py"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
            subprocess.run(["python3",".agents/skills/convergence/scripts/emit_poc.py"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
        except Exception: pass
        fs=[load(p) for p in glob.glob(f"{findings_dir}/*.json")]; fs=[f for f in fs if f]
        st=collections.Counter(f.get("status","candidate") for f in fs)
        cl=collections.Counter(f.get("vuln_class","?") for f in fs)
        c=load(cov) or {}; mods=c.get("modules",[]); done=sum(1 for m in mods if m.get("status")=="analyzed")
        el=int(time.time()-START); hh,mm,ss=el//3600,(el%3600)//60,el%60

        out=[]
        out.append(f"{C['b']}{C['cyan']}  TaintForge — live{C['reset']}   {C['gry']}elapsed {hh:02d}:{mm:02d}:{ss:02d}{C['reset']}")
        out.append(f"{C['gry']}  ────────────────────────────────────{C['reset']}")
        out.append(f"  {C['b']}coverage{C['reset']}  {bar(done,len(mods))} {done}/{len(mods)} modules")
        out.append(f"  {C['b']}findings{C['reset']}  {len(fs)} total")
        reportable=[f for f in fs if confirmation_gate_passes(f)]
        pending_review=[f for f in fs if f.get("status") in ("reproduced","confirmed")
                        and not confirmation_gate_passes(f)]
        rejected=[f for f in fs if f.get("status")=="not_product_vulnerability"
                  or review_state(f)=="non_product"]
        history_pending=[f for f in reportable if needs_public_history_work(f)]
        novel=[f for f in reportable if novelty_gate_passes(f)]
        out.append(f"  {C['b']}official gate{C['reset']}  {len(reportable)} reportable, "
                   f"{len(pending_review)} pending, {len(rejected)} non-product")
        if history_pending:
            out.append(f"  {C['b']}{C['yel']}public history pending{C['reset']}  {len(history_pending)}")
        if novel: out.append(f"  {C['b']}{C['red']}\u26a0 potential 0-day{C['reset']}  {len(novel)} (official + source-history reviewed)")
        exps=[f for f in reportable if f.get("exploit")]
        weap=[f for f in exps if (f.get("exploit") or {}).get("depth")=="weaponized"]
        chained=[f for f in exps if (f.get("exploit") or {}).get("depth")=="chained"]
        if exps:
            out.append(f"  {C['b']}{C['red']}\U0001f4a5 exploited{C['reset']}  {len(weap)} weaponized, {len(chained)} chained")
        for s in ["confirmed","reproduced","cross_validated","candidate","needs_reanalysis",
                  "not_product_vulnerability","false_positive"]:
            if st.get(s): out.append(f"      {STT.get(s,'')}{s:<16}{C['reset']} {st[s]}")
        if cl:
            out.append(f"  {C['b']}by class{C['reset']}")
            for k,v in cl.most_common(8): out.append(f"      {k:<22} {v}")
        # newest 5 findings
        recent=sorted(fs,key=lambda f:f.get("updated_at",""),reverse=True)[:5]
        if recent:
            out.append(f"  {C['b']}latest{C['reset']}")
            for f in recent:
                sev=f.get("severity_estimate","?"); loc=(f.get('sink') or {}).get('file','')[-34:]
                out.append(f"      {SEV.get(sev,'')}{sev:<8}{C['reset']}{STT.get(f.get('status'),'')}{f.get('status','')[:12]:<13}{C['reset']}{C['dim']}{f.get('vuln_class','?'):<16}{loc}{C['reset']}")
        sys.stdout.write("\033[2J\033[H"+"\n".join(out)+"\n")
        sys.stdout.flush()
        time.sleep(3)

if __name__=="__main__":
    try: main()
    except KeyboardInterrupt: pass
