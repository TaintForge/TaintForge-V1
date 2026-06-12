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

DETECTOR_DEFAULTS = {
    "A": "llm-track-a",
    "B": "llm-track-b",
    "F": "llm-track-f",
    "G": "llm-track-g",
    "H": "llm-track-h",
    "I": "llm-track-i",
}

STAGE_DEFAULTS = {
    "A": "track-a",
    "B": "track-b",
    "F": "track-f",
    "G": "track-g",
    "H": "track-h",
    "I": "track-i",
}

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
    f.setdefault("detector", DETECTOR_DEFAULTS.get(f["track"], "llm-track-b"))
    f.setdefault("status", "candidate")
    f.setdefault("sanitizers_seen", [])
    f.setdefault("flow", [])
    sink = f.get("sink") or {}
    if not sink.get("file"):
        sys.exit("error: sink.file is required")

    fid = args.update or stable_id(f["track"], f.get("vuln_class", "other"), sink)
    f["id"] = fid
    f["updated_at"] = now()
    hist = f.get("history", [])
    stage = f.pop("_stage", None) or STAGE_DEFAULTS.get(f["track"], "track-b")
    hist.append({"stage": stage, "action": f.get("_action", "authored by LLM"), "ts": now()})
    f["history"] = hist
    f.pop("_action", None)

    os.makedirs(args.out, exist_ok=True)
    dest = os.path.join(args.out, f"{fid}.json")

    # File lock so parallel producers and the consumer can't corrupt the same finding.
    import fcntl
    lockpath = dest + ".lock"
    lock = open(lockpath, "w")
    fcntl.flock(lock, fcntl.LOCK_EX)
    try:
        if os.path.exists(dest):
            existing = json.load(open(dest))
            if not args.update:
                # Same bug re-seen by another pass: keep original and only append history.
                existing.setdefault("history", []).extend(f.get("history", []))
                existing["updated_at"] = now()
                json.dump(existing, open(dest, "w"), indent=2)
                print(f"[finding] track={existing.get('track')} {existing.get('vuln_class')} "
                      f"already present ({fid}) - history appended")
                return
            f.setdefault("created_at", existing.get("created_at", now()))
            if f.get("status") == "needs_reanalysis":
                f["reanalysis_count"] = int(existing.get("reanalysis_count", 0)) + 1
            merged_hist = existing.get("history", []) + [
                h for h in f.get("history", []) if h not in existing.get("history", [])
            ]
            existing.update(f)
            existing["history"] = merged_hist
            f = existing
        else:
            f.setdefault("created_at", now())
            if f.get("status") == "needs_reanalysis":
                f["reanalysis_count"] = int(f.get("reanalysis_count", 0)) + 1

        try:
            import jsonschema
            jsonschema.validate(f, json.load(open(args.schema)))
        except ImportError:
            print("[warn] jsonschema not installed - skipping validation", file=sys.stderr)
        except Exception as e:
            sys.exit(f"schema validation failed: {e}")

        json.dump(f, open(dest, "w"), indent=2)
        print(f"[finding] track={f['track']} {f['vuln_class']} {f['status']} -> {fid}.json")
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        lock.close()
        try:
            os.remove(lockpath)
        except OSError:
            pass

if __name__ == "__main__":
    main()
