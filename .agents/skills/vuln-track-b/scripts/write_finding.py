#!/usr/bin/env python3
"""
write_finding.py - safe append-only writer for LLM-authored findings (Track B, and
Track A's A3/A4 confirmations). Reads a PARTIAL finding as JSON on stdin, fills the
mechanical fields (id, timestamps, history, defaults), validates against
schemas/finding.schema.json, and writes workspace/findings/<id>.json without
clobbering an existing finding.

The LLM only needs to supply: track, vuln_class, cwe, title, severity_estimate,
source{file,line,...}, sink{file,line,...}, evidence  (flow/sanitizers optional).

Usage:  echo '<partial finding json>' | write_finding.py
        write_finding.py --file finding.json
        write_finding.py --update <id>   # rewrite an existing finding (status changes, etc.)
"""
import argparse, hashlib, json, os, sys, datetime

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stable_id(track, vuln_class, sink):
    key = f"{track}|{vuln_class}|{sink.get('file','')}|{sink.get('line','')}"
    return hashlib.sha1(key.encode()).hexdigest()[:16]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file")
    ap.add_argument("--out", default="workspace/findings")
    ap.add_argument("--schema", default="schemas/finding.schema.json")
    ap.add_argument("--update", help="existing finding id to overwrite (allows status changes)")
    args = ap.parse_args()

    raw = open(args.file).read() if args.file else sys.stdin.read()
    f = json.loads(raw)

    f.setdefault("track", "B")
    f.setdefault("detector", "llm-track-b" if f["track"] == "B" else "llm-track-a")
    f.setdefault("status", "candidate")
    f.setdefault("sanitizers_seen", [])
    f.setdefault("flow", [])
    sink = f.get("sink") or {}
    if not sink.get("file"):
        sys.exit("error: sink.file is required")

    fid = args.update or stable_id(f["track"], f.get("vuln_class","other"), sink)
    f["id"] = fid
    f.setdefault("created_at", now())
    f["updated_at"] = now()
    hist = f.get("history", [])
    stage = "track-b" if f["track"] == "B" else "track-a"
    hist.append({"stage": stage, "action": f.get("_action", "authored by LLM"), "ts": now()})
    f["history"] = hist
    f.pop("_action", None)

    try:
        import jsonschema
        jsonschema.validate(f, json.load(open(args.schema)))
    except ImportError:
        print("[warn] jsonschema not installed - skipping validation", file=sys.stderr)
    except Exception as e:
        sys.exit(f"schema validation failed: {e}")

    os.makedirs(args.out, exist_ok=True)
    dest = os.path.join(args.out, f"{fid}.json")
    if os.path.exists(dest) and not args.update:
        print(f"[track-b] exists, not clobbering: {fid} (use --update to modify)")
        return
    json.dump(f, open(dest, "w"), indent=2)
    print(f"[track-b] wrote {dest}  ({f['vuln_class']}, {f['status']})")

if __name__ == "__main__":
    main()