#!/usr/bin/env python3
"""
write_finding.py - safe append-only writer for LLM-authored findings (Track B, and
Track A's A3/A4 confirmations). Reads a PARTIAL finding as JSON on stdin, fills the
mechanical fields (id, timestamps, history, defaults), validates against
schemas/finding.schema.json, and writes workspace/findings/<id>.json without
clobbering an existing finding.

The LLM only needs to supply: track, vuln_class, cwe, title, severity_estimate,
source{file,line,...}, sink{file,line,...}, evidence  (flow/sanitizers optional).

For a missing-control (shape B) finding `sink` is the privileged operation's own location,
and `missing_control{control,expected_at,unguarded_path,actor}` carries the evidence that a
required check is absent from a reachable path.

Terminal gates (see .agents/skills/_shared/METHODOLOGY.md):
  confirmed  -> successful reproduction + official_review  (enforce_official_review_gate)
             -> defect_shape, reachability, preconditions, escalation ceiling, and a stock
                replay for instrumentation-only observations  (enforce_evidence_contract)
  novel      -> complete disclosure.public_history            (enforce_disclosure_gate)

Usage:  echo '<partial finding json>' | write_finding.py
        write_finding.py --file finding.json
        write_finding.py --update <id>   # rewrite an existing finding (status changes, etc.)
"""
import argparse, hashlib, json, os, sys, datetime

REPORTABLE_OFFICIAL_VERDICTS = {"product_vulnerability", "known_vulnerability"}
NON_PRODUCT_OFFICIAL_VERDICTS = {
    "documented_hazard", "expected_behavior", "application_misconfiguration",
    "unsupported_scenario",
}

def is_qualifying_public_reference(source):
    if not isinstance(source, str) or not source.startswith("https://"):
        return False
    lowered = source.lower()
    if "github.com/" in lowered and any(part in lowered for part in ("/blob/", "/tree/", "/raw/")):
        return False
    return True

def nonempty_strings(value, minimum=1):
    return (
        isinstance(value, list)
        and len([item for item in value if isinstance(item, str) and item.strip()]) >= minimum
    )

def public_history_review_is_complete(f):
    disclosure = f.get("disclosure") or {}
    review = disclosure.get("public_history") or {}
    repository = review.get("upstream_repository") or ""
    comparison = review.get("head_or_release_comparison") or ""
    return (
        review.get("checked") is True
        and isinstance(repository, str)
        and repository.startswith("https://")
        and nonempty_strings(review.get("exact_anchors"), minimum=2)
        and nonempty_strings(review.get("source_history"))
        and nonempty_strings(review.get("vendor_issues_prs"))
        and nonempty_strings(review.get("advisories_releases"))
        and isinstance(comparison, str)
        and len(comparison.strip()) >= 20
    )

def enforce_disclosure_gate(f):
    disclosure = f.get("disclosure") or {}
    if not isinstance(disclosure, dict) or disclosure.get("checked") is not True:
        if (f.get("official_review") or {}).get("verdict") == "known_vulnerability":
            sys.exit("error: known_vulnerability requires disclosure.checked=true and status=known")
        return
    status = disclosure.get("status")
    rationale = str(disclosure.get("rationale") or "").strip()
    if len(rationale) < 20:
        sys.exit("error: completed disclosure review requires a concrete rationale")
    if status == "known":
        references = disclosure.get("references") or []
        if not any(is_qualifying_public_reference(ref) for ref in references):
            sys.exit("error: disclosure.status=known requires an exact public vendor reference")
    elif status == "novel":
        if (f.get("official_review") or {}).get("verdict") != "product_vulnerability":
            sys.exit("error: only an officially reviewed product_vulnerability may be novel")
        if not public_history_review_is_complete(f):
            sys.exit(
                "error: disclosure.status=novel requires public_history evidence for exact anchors, "
                "source history, upstream head/release comparison, vendor issues/PRs, and advisories/releases"
            )
    elif status != "inconclusive":
        sys.exit("error: disclosure.status must be known, novel, or inconclusive")

    if (f.get("official_review") or {}).get("verdict") == "known_vulnerability" and status != "known":
        sys.exit("error: official_review.verdict=known_vulnerability requires disclosure.status=known")

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def stable_id(track, vuln_class, sink):
    key = f"{track}|{vuln_class}|{sink.get('file','')}|{sink.get('line','')}"
    # A sink with no usable line (manifest-level items, dynamic dispatch, line unknown) would
    # otherwise collapse every such finding in the same file onto one id. Disambiguate with the
    # symbol in exactly that degenerate case, so well-formed findings keep their existing ids.
    if not sink.get("line"):
        key += f"|{sink.get('symbol','')}"
    return hashlib.sha1(key.encode()).hexdigest()[:16]


def enforce_evidence_contract(f):
    """Gate the METHODOLOGY output contract at the terminal reportable state.

    A finding may not be called `confirmed` while its reachability, preconditions, or
    escalation ceiling are unstated: those three are what stop an over-packaged report, and
    they are the deliverables of the mandatory passes (METHODOLOGY sections 5-7).
    """
    if f.get("status") != "confirmed":
        return

    shape = f.get("defect_shape")
    if shape not in {"flow", "missing_control"}:
        sys.exit(
            "error: status=confirmed requires defect_shape 'flow' (source/propagation/sink all "
            "stated) or 'missing_control' (the absent check and the path it is missing from)"
        )
    if shape == "missing_control":
        mc = f.get("missing_control") or {}
        if not (str(mc.get("control") or "").strip() and str(mc.get("unguarded_path") or "").strip()):
            sys.exit(
                "error: defect_shape=missing_control requires missing_control.control and "
                "missing_control.unguarded_path - name the check and the reachable path it is "
                "absent from (sink stays the privileged operation's location)"
            )

    reach = f.get("reachability") or {}
    if not (
        str(reach.get("entry_point") or "").strip()
        and str(reach.get("min_privilege") or "").strip()
        and "pre_auth" in reach
        and reach.get("pre_auth") in (True, False, None)
    ):
        sys.exit(
            "error: status=confirmed requires reachability{entry_point,min_privilege,pre_auth} - "
            "prove who can trigger this and at what privilege, not which route name looks public"
        )

    pre = f.get("preconditions") or {}
    if "default_configuration" not in pre or pre.get("default_configuration") not in (True, False, None):
        sys.exit(
            "error: status=confirmed requires preconditions.default_configuration (true/false/null); "
            "when false, list the exact non-default settings in preconditions.required_settings"
        )
    if pre.get("default_configuration") is False and not nonempty_strings(pre.get("required_settings")):
        sys.exit(
            "error: preconditions.default_configuration=false requires the exact non-default "
            "settings in preconditions.required_settings"
        )

    primitive = f.get("primitive") or {}
    if len(str(primitive.get("escalation_ceiling") or "").strip()) < 10:
        sys.exit(
            "error: status=confirmed requires primitive.escalation_ceiling - state the highest "
            "impact actually proven as a bound (e.g. 'read-only, self-owned objects only', "
            "'DoS only: no control over the freed chunk')"
        )

    repro = f.get("repro") or {}
    if repro.get("instrumentation_only") is True and not str(repro.get("stock_replay") or "").strip():
        sys.exit(
            "error: an observation seen only under instrumentation (sanitizer/debug/patched build) "
            "is a lead until repro.stock_replay records a replay on the exact stock build"
        )

def enforce_official_review_gate(f):
    status = f.get("status")
    if status not in {"confirmed", "not_product_vulnerability"}:
        return
    repro = f.get("repro") or {}
    if not (
        repro.get("attempted") is True
        and repro.get("success") is True
        and bool(str(repro.get("poc") or "").strip())
        and bool(str(repro.get("response") or "").strip())
    ):
        sys.exit(
            f"error: status={status} requires successful dynamic reproduction with exact "
            "repro.poc and decisive repro.response before official review can become terminal"
        )
    review = f.get("official_review") or {}
    sources = review.get("sources") or []
    rationale = review.get("rationale") or ""
    if not (
        review.get("checked") is True
        and isinstance(sources, list)
        and any(isinstance(source, str) and source.strip() for source in sources)
        and any(is_qualifying_public_reference(source) for source in sources)
        and isinstance(rationale, str)
        and len(rationale.strip()) >= 20
        and bool(str(review.get("product_version") or "").strip())
        and "default_configuration" in review
        and review.get("default_configuration") in (True, False, None)
    ):
        sys.exit(
            f"error: status={status} requires a completed official_review with checked=true, "
            "at least one public primary official/vendor documentation, advisory, release, patch, "
            "issue, or discussion URL (a GitHub blob/tree/raw source URL alone is insufficient), "
            "an exact product_version/default_configuration assessment, and a concrete rationale"
        )
    verdict = review.get("verdict")
    allowed = (REPORTABLE_OFFICIAL_VERDICTS if status == "confirmed"
               else NON_PRODUCT_OFFICIAL_VERDICTS)
    if verdict not in allowed:
        sys.exit(
            f"error: status={status} is inconsistent with official_review.verdict={verdict!r}; "
            f"allowed verdicts: {', '.join(sorted(allowed))}"
        )

def official_review_is_reportable(f):
    review = f.get("official_review") or {}
    repro = f.get("repro") or {}
    return (
        f.get("status") == "confirmed"
        and repro.get("attempted") is True
        and repro.get("success") is True
        and bool(str(repro.get("poc") or "").strip())
        and bool(str(repro.get("response") or "").strip())
        and review.get("checked") is True
        and review.get("verdict") in REPORTABLE_OFFICIAL_VERDICTS
        and bool(review.get("sources"))
        and any(is_qualifying_public_reference(source) for source in review.get("sources", []))
        and len(str(review.get("rationale") or "").strip()) >= 20
        and bool(str(review.get("product_version") or "").strip())
        and "default_configuration" in review
        and review.get("default_configuration") in (True, False, None)
    )

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
    detector_by_track = {"A": "llm-track-a", "B": "llm-track-b"}
    f.setdefault("detector", detector_by_track.get(f["track"], "llm-track-a"))
    f.setdefault("status", "candidate")
    # retry cap: count how many times this finding is bounced to needs_reanalysis, so C can
    # stop re-verifying it forever (burns reasoning tokens). Incremented on each such update.
    if f.get("status") == "needs_reanalysis":
        f["reanalysis_count"] = int(f.get("reanalysis_count", 0)) + 1
    f.setdefault("sanitizers_seen", [])
    f.setdefault("flow", [])
    sink = f.get("sink") or {}
    if not sink.get("file"):
        sys.exit("error: sink.file is required")
    if not f.get("defect_shape"):
        # Not fatal for a candidate - the shape can still be undecided while hunting - but the
        # terminal gate needs it, and deciding it early is what keeps shape-B bugs from being
        # squeezed into a source->sink story they do not have.
        print("[warn] no defect_shape set ('flow' or 'missing_control'); required before confirmed",
              file=sys.stderr)

    fid = args.update or stable_id(f["track"], f.get("vuln_class","other"), sink)
    f["id"] = fid
    f.setdefault("created_at", now())
    f["updated_at"] = now()
    hist = f.get("history", [])
    stage = f"track-{str(f['track']).lower()}"
    hist.append({"stage": stage, "action": f.get("_action", "authored by LLM"), "ts": now()})
    f["history"] = hist
    f.pop("_action", None)

    os.makedirs(args.out, exist_ok=True)
    dest = os.path.join(args.out, f"{fid}.json")

    # File lock so parallel producers (A, B) and the consumer (C) can't corrupt the
    # same finding when writing concurrently. Lock is per-finding-id.
    import fcntl
    lockpath = dest + ".lock"
    lock = open(lockpath, "w")
    fcntl.flock(lock, fcntl.LOCK_EX)
    try:
        previous_exploit = None
        if os.path.exists(dest):
            existing = json.load(open(dest))
            previous_exploit = existing.get("exploit")
            if not args.update:
                # same bug re-seen by another pass: keep original, just append history, don't clobber
                existing.setdefault("history", []).extend(f.get("history", []))
                existing["updated_at"] = now()
                json.dump(existing, open(dest, "w"), indent=2)
                print(f"[finding] track={existing.get('track')} {existing.get('vuln_class')} "
                      f"already present ({fid}) - history appended")
                return
            # --update: merge new fields onto existing, preserve full history
            merged_hist = existing.get("history", []) + [h for h in f.get("history", []) if h not in existing.get("history", [])]
            existing.update(f); existing["history"] = merged_hist
            f = existing

        # Dynamic reproduction proves behavior, not that the behavior crosses the vendor's
        # supported product security boundary. Terminal classifications require primary
        # official/vendor evidence and a consistent product-boundary verdict.
        enforce_official_review_gate(f)
        enforce_evidence_contract(f)
        enforce_disclosure_gate(f)
        if f.get("exploit") != previous_exploit and not official_review_is_reportable(f):
            sys.exit(
                "error: adding or changing exploit evidence requires status=confirmed and a "
                "reportable official_review verdict"
            )

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
        fcntl.flock(lock, fcntl.LOCK_UN); lock.close()
        try: os.remove(lockpath)
        except OSError: pass

if __name__ == "__main__":
    main()
