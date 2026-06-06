#!/usr/bin/env python3
"""
cwe_to_hypotheses.py - convert MITRE CWE XML into business-logic / access-control / logic
HYPOTHESES and merge them into the hypothesize catalog (_cwe_derived pool).

This grows the catalog to hundreds of *patterns to verify* (not exploits) from the public
CWE corpus. We keep only weaknesses in the logic/authz/workflow/race families - the bugs the
generic injection/authz scans tend to miss - and emit each as
  {class, name, why, check_how, cwe_id}
The producers treat these like any other hypothesis: verify against the code, link a finding
via hypothesis_id, mark verified/refuted.

Get the XML first (cwe.mitre.org is reachable from your machine, not the sandbox):
  curl -L -o /tmp/cwec_latest.xml.zip https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
  unzip /tmp/cwec_latest.xml.zip -d /tmp/

Usage:
  cwe_to_hypotheses.py /tmp/cwec_v4.20.xml
  cwe_to_hypotheses.py /tmp/cwec_v4.20.xml --catalog .agents/skills/hypothesize/scripts/catalog.json
  cwe_to_hypotheses.py /tmp/cwec_v4.20.xml --dry-run        # print what would be added, don't write
"""
import argparse, json, os, re, sys
import xml.etree.ElementTree as ET

# CWE roots whose whole subtree is business-logic / access-control / workflow / race / limits.
# We include these IDs and (via ChildOf relationships) everything under them.
SEED_ROOTS = {
    "840": ("business-logic", "Business Logic Errors"),
    "285": ("broken-access-control", "Improper Authorization"),
    "862": ("broken-access-control", "Missing Authorization"),
    "863": ("broken-access-control", "Incorrect Authorization"),
    "639": ("idor", "Authorization Bypass Through User-Controlled Key"),
    "284": ("broken-access-control", "Improper Access Control"),
    "282": ("broken-access-control", "Improper Ownership Management"),
    "283": ("broken-access-control", "Unverified Ownership"),
    "841": ("business-logic", "Improper Enforcement of Behavioral Workflow"),
    "840-state": ("business-logic", "state"),
    "367": ("business-logic", "TOCTOU Race Condition"),
    "362": ("business-logic", "Concurrent Execution / Race Condition"),
    "799": ("business-logic", "Improper Control of Interaction Frequency"),
    "770": ("business-logic", "Allocation of Resources Without Limits"),
    "913": ("business-logic", "Improper Control of Dynamically-Managed Code Resources"),
    "269": ("privilege-escalation", "Improper Privilege Management"),
    "266": ("privilege-escalation", "Incorrect Privilege Assignment"),
    "732": ("broken-access-control", "Incorrect Permission Assignment"),
    "915": ("privilege-escalation", "Improperly Controlled Modification of Dynamically-Determined Object Attributes (mass assignment)"),
    "472": ("business-logic", "External Control of Assumed-Immutable Web Parameter"),
    "807": ("business-logic", "Reliance on Untrusted Inputs in a Security Decision"),
    "565": ("business-logic", "Reliance on Cookies without Validation"),
    "602": ("business-logic", "Client-Side Enforcement of Server-Side Security"),
    "20":  ("business-logic", "Improper Input Validation"),   # we narrow this one below
}

# map a CWE name/desc to our vuln_class by keyword (fallback when not under a known root)
CLASS_KEYWORDS = [
    ("idor",                 r"user-controlled key|object reference|direct object|ownership"),
    ("broken-access-control",r"authoriz|access control|permission|privilege.*check|forced browsing"),
    ("privilege-escalation", r"privilege|mass assignment|object attribute|escalat"),
    ("business-logic",       r"business logic|workflow|race|toctou|frequency|state|sequence|order of|limit|quota|client-side enforcement|immutable|untrusted input"),
    ("ssrf",                 r"server-side request forgery|ssrf"),
    ("information-disclosure",r"information exposure|sensitive information|enumeration"),
]

# Keep CWEs whose name/desc clearly mean logic/authz; drop pure memory/crypto/injection noise.
INCLUDE = re.compile(r"authoriz|access control|permission|privilege|business logic|workflow|"
                     r"race|toctou|frequency|quota|limit|state|sequence|order of|ownership|"
                     r"object reference|direct object|mass assignment|object attribute|"
                     r"client-side enforcement|immutable|untrusted input.*security|"
                     r"interaction frequency|behavioral", re.I)
EXCLUDE = re.compile(r"buffer|overflow.*memory|use after free|null pointer|cryptograph|"
                     r"sql injection|xss|cross-site script|command injection|path traversal|"
                     r"deserializ|xml external|format string|integer overflow.*memory", re.I)

def strip_ns(tag): return tag.split('}',1)[1] if '}' in tag else tag

def text_of(el):
    if el is None: return ""
    return re.sub(r"\s+"," "," ".join(el.itertext())).strip()

def find(el, name):
    for c in el.iter():
        if strip_ns(c.tag)==name: return c
    return None

def classify(name, desc):
    blob=(name+" "+desc).lower()
    for cls,pat in CLASS_KEYWORDS:
        if re.search(pat, blob): return cls
    return "business-logic"

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("xml")
    ap.add_argument("--catalog", default=os.path.join(os.path.dirname(os.path.abspath(__file__)),"catalog.json"))
    ap.add_argument("--dry-run", action="store_true")
    a=ap.parse_args()

    if not os.path.isfile(a.xml): sys.exit(f"not found: {a.xml}")
    tree=ET.parse(a.xml); root=tree.getroot()

    # gather all Weakness elements regardless of namespace
    weaknesses=[el for el in root.iter() if strip_ns(el.tag)=="Weakness"]
    if not weaknesses: sys.exit("no <Weakness> elements found - check the XML")

    derived=[]; seen=set()
    for w in weaknesses:
        cid=w.attrib.get("ID","")
        name=w.attrib.get("Name","")
        if not cid or cid in seen: continue
        # description
        descel=None
        for c in w.iter():
            if strip_ns(c.tag)=="Description": descel=c; break
        desc=text_of(descel)
        blob=name+" "+desc
        # keep if explicitly a seed root, or matches INCLUDE and not EXCLUDE
        is_seed = cid in SEED_ROOTS
        if not is_seed:
            if EXCLUDE.search(blob): continue
            if not INCLUDE.search(blob): continue
        seen.add(cid)
        cls = SEED_ROOTS[cid][0] if is_seed else classify(name, desc)
        why = desc[:240] if desc else name
        # extraction/detection hint
        det=""
        for c in w.iter():
            if strip_ns(c.tag)=="Detection_Method":
                det=text_of(c)[:200]; break
        check_how = (det or f"Look for code paths matching CWE-{cid}: {name}. Verify the relevant server-side check is present and reachable.")[:240]
        derived.append({
            "id": f"CWE{cid}",
            "domain": "_cwe",
            "source": "cwe",
            "cwe_id": f"CWE-{cid}",
            "class": cls,
            "name": name,
            "why": why,
            "check_how": check_how,
            "target_endpoints": [],
            "status": "open",
        })

    derived.sort(key=lambda h: int(h["cwe_id"].split("-")[1]))
    print(f"[cwe] extracted {len(derived)} logic/authz/workflow hypotheses from {len(weaknesses)} CWEs")
    by_class={}
    for h in derived: by_class[h["class"]]=by_class.get(h["class"],0)+1
    print("[cwe] by class:", by_class)

    if a.dry_run:
        for h in derived[:25]: print(f"  {h['cwe_id']:<10} {h['class']:<22} {h['name'][:60]}")
        print("  ... (--dry-run, nothing written)")
        return

    cat=json.load(open(a.catalog))
    cat["_cwe_derived"]={
        "note": "Hypotheses auto-derived from MITRE CWE (logic/authz/workflow/race/limit families). Domain-independent pool; the hypothesize step seeds these alongside the matched domain. Patterns to verify, not exploits.",
        "source_file": os.path.basename(a.xml),
        "count": len(derived),
        "hypotheses": derived,
    }
    json.dump(cat, open(a.catalog,"w"), indent=2)
    print(f"[cwe] merged into {a.catalog} under _cwe_derived ({len(derived)} hypotheses)")

if __name__=="__main__":
    main()