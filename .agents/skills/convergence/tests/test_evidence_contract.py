#!/usr/bin/env python3
"""Gates from .agents/skills/_shared/METHODOLOGY.md sections 5-7.

A finding may not reach `confirmed` while its shape, reachability, preconditions, or
escalation ceiling are unstated, and an observation seen only under instrumentation stays a
lead until it replays on the stock build.
"""
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[4]
WRITER = ROOT / ".agents/skills/_shared/write_finding.py"
SCHEMA = ROOT / "schemas/finding.schema.json"


def confirmed_finding():
    return {
        "track": "A",
        "vuln_class": "command-injection",
        "cwe": "CWE-78",
        "title": "evidence contract fixture",
        "severity_estimate": "critical",
        "status": "confirmed",
        "defect_shape": "flow",
        "source": {"file": "targets/app/route.py", "line": 10},
        "sink": {"file": "targets/app/exec.py", "line": 42},
        "evidence": "test fixture",
        "reachability": {
            "entry_point": "POST /api/convert",
            "min_privilege": "unauthenticated",
            "pre_auth": True,
            "call_chain": ["convert_view", "run_tool"],
        },
        "preconditions": {"default_configuration": True},
        "primitive": {
            "kinds": ["code-exec"],
            "escalation_ceiling": "single-token argv injection; no shell metacharacters pass",
        },
        "repro": {
            "attempted": True,
            "success": True,
            "poc": "python3 poc.py",
            "response": "PASS: uid=33(www-data) in the response body",
        },
        "official_review": {
            "checked": True,
            "verdict": "product_vulnerability",
            "sources": ["https://vendor.example/docs/security"],
            "rationale": "The documented boundary states the parameter is escaped; it is not.",
            "product_version": "4.2.1",
            "default_configuration": True,
        },
    }


def missing_control_finding():
    f = confirmed_finding()
    f.update({
        "track": "B",
        "vuln_class": "broken-access-control",
        "cwe": "CWE-862",
        "defect_shape": "missing_control",
        "missing_control": {
            "control": "capability check current_user_can('edit_posts')",
            "expected_at": ["targets/app/ajax.py:120"],
            "unguarded_path": "POST /admin-ajax.php?action=find_posts -> find_posts() -> query",
            "actor": "any authenticated subscriber",
        },
        "primitive": {
            "kinds": ["read"],
            "escalation_ceiling": "read of other users' draft titles only; no write path found",
        },
    })
    return f


class EvidenceContractGateTest(unittest.TestCase):
    def run_writer(self, finding):
        with tempfile.TemporaryDirectory() as tmp:
            return subprocess.run(
                [sys.executable, str(WRITER), "--out", tmp, "--schema", str(SCHEMA)],
                input=json.dumps(finding), text=True, capture_output=True, cwd=ROOT,
            )

    def assert_rejected(self, finding, expected):
        result = self.run_writer(finding)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(expected, result.stderr)

    def test_accepts_complete_flow_finding(self):
        result = self.run_writer(confirmed_finding())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_accepts_complete_missing_control_finding(self):
        result = self.run_writer(missing_control_finding())
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rejects_confirmed_without_defect_shape(self):
        f = confirmed_finding()
        del f["defect_shape"]
        self.assert_rejected(f, "requires defect_shape")

    def test_rejects_missing_control_shape_without_the_absent_check(self):
        f = missing_control_finding()
        f["missing_control"] = {"control": "capability check"}
        self.assert_rejected(f, "missing_control.unguarded_path")

    def test_rejects_confirmed_without_reachability(self):
        f = confirmed_finding()
        del f["reachability"]
        self.assert_rejected(f, "requires reachability")

    def test_rejects_reachability_without_privilege(self):
        f = confirmed_finding()
        f["reachability"]["min_privilege"] = ""
        self.assert_rejected(f, "requires reachability")

    def test_rejects_confirmed_without_precondition_assessment(self):
        f = confirmed_finding()
        del f["preconditions"]
        self.assert_rejected(f, "preconditions.default_configuration")

    def test_rejects_nondefault_preconditions_without_the_settings(self):
        f = confirmed_finding()
        f["preconditions"] = {"default_configuration": False}
        self.assert_rejected(f, "required_settings")

    def test_rejects_confirmed_without_escalation_ceiling(self):
        f = confirmed_finding()
        f["primitive"] = {"kinds": ["code-exec"]}
        self.assert_rejected(f, "escalation_ceiling")

    def test_rejects_instrumentation_only_observation(self):
        f = confirmed_finding()
        f["repro"]["instrumentation_only"] = True
        self.assert_rejected(f, "stock_replay")

    def test_accepts_instrumentation_observation_replayed_on_stock(self):
        f = confirmed_finding()
        f["repro"]["instrumentation_only"] = True
        f["repro"]["stock_replay"] = "Replayed on the stock 4.2.1 release build: same crash, 10/10."
        self.assertEqual(self.run_writer(f).returncode, 0)

    def test_candidate_is_not_gated(self):
        f = confirmed_finding()
        f["status"] = "candidate"
        for field in ("defect_shape", "reachability", "preconditions", "primitive",
                      "official_review", "repro"):
            f.pop(field, None)
        self.assertEqual(self.run_writer(f).returncode, 0)


class StableIdTest(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, str(ROOT / ".agents/skills/_shared"))
        import write_finding
        self.stable_id = write_finding.stable_id

    def test_unknown_line_disambiguates_by_symbol(self):
        a = self.stable_id("B", "idor", {"file": "app/x.php", "line": 0, "symbol": "load_user"})
        b = self.stable_id("B", "idor", {"file": "app/x.php", "line": 0, "symbol": "load_order"})
        self.assertNotEqual(a, b)

    def test_known_line_keeps_the_legacy_id(self):
        import hashlib
        sink = {"file": "app/x.php", "line": 42, "symbol": "load_user"}
        legacy = hashlib.sha1(b"B|idor|app/x.php|42").hexdigest()[:16]
        self.assertEqual(self.stable_id("B", "idor", sink), legacy)


if __name__ == "__main__":
    unittest.main()
