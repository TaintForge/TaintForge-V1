#!/usr/bin/env python3
"""
budget_guard.py - cheap cumulative-token guard for the run.

Reasoning-heavy agents can burn tokens non-linearly (cf. the cost trap of LLM security
pipelines). The supervisor calls this each respawn; when cumulative tokens across all
session logs exceed TF_TOKEN_BUDGET, it touches workspace/_stop so every supervisor winds
down at its next loop check.

Token accounting is best-effort: it scans the session logs for common usage markers Codex
prints (e.g. "tokens used: N", "total tokens: N", "N tokens"). If it finds none, it reports
0 and never stops the run (fail-open) - a budget you can't measure shouldn't kill the work.
Set TF_TOKEN_BUDGET=0 (default) to disable the guard entirely.

Usage:
  budget_guard.py --check          # exit 0 always; touches _stop if over budget; prints usage
  budget_guard.py --report         # just print cumulative tokens, no side effects
"""
import argparse, glob, os, re, sys

DEFAULT_LOG_GLOB="workspace/_log_*.txt"
DEFAULT_STOP="workspace/_stop"
TOKEN_PATTERNS=[
    re.compile(r"total[_ ]tokens[\"']?\s*[:=]\s*([0-9,]+)", re.I),
    re.compile(r"tokens?[_ ]used[\"']?\s*[:=]\s*([0-9,]+)", re.I),
    re.compile(r"\b([0-9,]{3,})\s+tokens\b", re.I),
    re.compile(r"\"(?:input|output|total)_tokens\"\s*:\s*([0-9,]+)", re.I),
]

def cumulative_tokens(log_glob):
    total=0; hits=0
    for path in glob.glob(log_glob):
        try: txt=open(path, errors="ignore").read()
        except Exception: continue
        for pat in TOKEN_PATTERNS:
            for m in pat.finditer(txt):
                try: total+=int(m.group(1).replace(",","")); hits+=1
                except Exception: pass
    return total, hits

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--report", action="store_true")
    ap.add_argument("--log-glob", default=DEFAULT_LOG_GLOB)
    ap.add_argument("--stop", default=DEFAULT_STOP)
    a=ap.parse_args()
    budget=int(os.environ.get("TF_TOKEN_BUDGET","0"))
    total, hits = cumulative_tokens(a.log_glob)
    if a.report or not a.check:
        print(f"[budget] cumulative tokens ~= {total:,} (from {hits} log markers); "
              f"budget={'off' if budget==0 else format(budget,',')}")
        if not a.check: return
    if budget>0 and hits>0 and total>=budget:
        open(a.stop,"w").close()
        print(f"[budget] OVER BUDGET: ~{total:,} >= {budget:,} -> touched {a.stop} (winding down)")
    else:
        why="disabled" if budget==0 else ("no token markers in logs (fail-open)" if hits==0 else f"~{total:,} / {budget:,}")
        print(f"[budget] under budget ({why})")

if __name__=="__main__":
    main()
