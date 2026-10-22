#!/usr/bin/env python3
"""queue.py - machine-readable finding-queue state for the orchestrator.
--pending   : print count of findings still needing convergence work
              (candidate, cross_validated, needs_reanalysis, official review work,
               or public-history/disclosure work)
--reanalysis: print "id<TAB>track" for findings flagged needs_reanalysis
--counts    : human-readable status counts
"""
import argparse, glob, json, os, collections
from official_review import needs_official_review_work, needs_public_history_work
PENDING={"candidate","cross_validated","needs_reanalysis"}
ap=argparse.ArgumentParser()
ap.add_argument("--findings",default="workspace/findings")
ap.add_argument("--pending",action="store_true")
ap.add_argument("--reanalysis",action="store_true")
ap.add_argument("--counts",action="store_true")
a=ap.parse_args()
fs=[]
for p in glob.glob(os.path.join(a.findings,"*.json")):
    try: fs.append(json.load(open(p)))
    except Exception: pass
if a.reanalysis:
    for f in fs:
        if f.get("status")=="needs_reanalysis":
            print(f"{f['id']}\t{f.get('track','A')}")
elif a.counts:
    c=collections.Counter(f.get("status","candidate") for f in fs)
    for k,v in c.items(): print(f"{k}\t{v}")
    review_pending=sum(1 for f in fs if needs_official_review_work(f))
    if review_pending: print(f"official_review_pending\t{review_pending}")
    history_pending=sum(1 for f in fs if needs_public_history_work(f))
    if history_pending: print(f"public_history_pending\t{history_pending}")
else:  # --pending (default)
    print(sum(1 for f in fs if f.get("status","candidate") in PENDING
              or needs_official_review_work(f)
              or needs_public_history_work(f)))
