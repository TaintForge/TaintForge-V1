#!/usr/bin/env python3
"""Render claude -p --output-format stream-json JSONL into readable live lines for a tmux pane.
Reads stdin line by line (from `tail -F logfile`), prints a compact human view per event.
Non-JSON lines (audit.sh session headers, budget output) pass through unchanged.
Run unbuffered: `... | python3 -u stream_fmt.py`."""
import sys, json

RST="\033[0m"; DIM="\033[2m"; CYAN="\033[36m"; GRN="\033[32m"; YEL="\033[33m"; RED="\033[31m"; BLU="\033[34m"; MAG="\033[35m"

def clip(s, n):
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[:n-1] + "…"

def tool_desc(name, inp):
    inp = inp or {}
    if name == "Bash":
        return clip(inp.get("command",""), 160)
    if name in ("Read","Edit","Write","NotebookEdit"):
        return clip(inp.get("file_path") or inp.get("notebook_path") or "", 120)
    if name in ("Grep","Glob"):
        p = inp.get("pattern","") + (f"  ({inp.get('path')})" if inp.get("path") else "")
        return clip(p, 120)
    if name == "Task":
        return clip(f"{inp.get('subagent_type','')}: {inp.get('description','')}", 120)
    if name == "Skill":
        return clip(inp.get("skill",""), 80)
    if name in ("WebFetch","WebSearch"):
        return clip(inp.get("url") or inp.get("query") or "", 120)
    return clip(json.dumps(inp, ensure_ascii=False), 120)

def emit(line):
    sys.stdout.write(line + "\n"); sys.stdout.flush()

for raw in sys.stdin:
    raw = raw.rstrip("\n")
    if not raw.strip():
        continue
    if not raw.lstrip().startswith("{"):
        emit(raw)  # session header / budget / plain text
        continue
    try:
        ev = json.loads(raw)
    except Exception:
        emit(raw); continue
    t = ev.get("type")
    if t == "system" and ev.get("subtype") == "init":
        emit(f"{DIM}▶ session start · model={ev.get('model','?')} · cwd={ev.get('cwd','')}{RST}")
    elif t == "assistant":
        for c in ev.get("message",{}).get("content",[]):
            k = c.get("type")
            if k == "text":
                txt = c.get("text","").strip()
                if txt:
                    for ln in txt.splitlines():
                        if ln.strip(): emit(f"{CYAN}│{RST} {ln}")
            elif k == "tool_use":
                emit(f"{YEL}🔧 {c.get('name','?')}{RST} {DIM}{tool_desc(c.get('name'), c.get('input'))}{RST}")
            elif k == "thinking":
                th = clip(c.get("thinking",""), 200)
                if th: emit(f"{MAG}🧠 {th}{RST}")
    elif t == "user":
        for c in ev.get("message",{}).get("content",[]):
            if c.get("type") == "tool_result":
                content = c.get("content","")
                if isinstance(content, list):
                    content = " ".join(x.get("text","") for x in content if isinstance(x, dict))
                err = c.get("is_error")
                first = clip(content, 160)
                emit(f"{(RED+'  ✗ ' if err else GRN+'  ↳ ')}{first}{RST}")
    elif t == "result":
        cost = ev.get("total_cost_usd"); turns = ev.get("num_turns")
        sub = ev.get("subagent_stats",{}).get("spawned")
        extra = f" · subagents={sub}" if sub else ""
        emit(f"{BLU}✓ session done · turns={turns} · ${cost}{extra}{RST}")
    elif t == "rate_limit_event":
        info = ev.get("rate_limit_info",{})
        uw = info.get("unifiedWindows",{}).get("five_hour",{})
        if info.get("status") != "allowed":
            emit(f"{RED}⚠ rate-limit: {info.get('status')} 5h-util={uw.get('utilization')}{RST}")
