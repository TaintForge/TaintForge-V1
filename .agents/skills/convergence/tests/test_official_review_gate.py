#!/usr/bin/env python3
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[4]
SCRIPTS = ROOT / ".agents/skills/convergence/scripts"
WRITER = ROOT / ".agents/skills/_shared/write_finding.py"
SCHEMA = ROOT / "schemas/finding.schema.json"
sys.path.insert(0, str(SCRIPTS))

from official_review import (
    confirmation_gate_passes,
    disclosure_state,
    novelty_gate_passes,
    public_history_review_is_complete,
    review_state,
)


def base_finding(status="reproduced"):
    return {
        "track": "B",
        "vuln_class": "auth-bypass",
        "cwe": "CWE-862",
        "title": "gate test",
        "severity_estimate": "high",
        "status": status,
        "defect_shape": "flow",
        "source": {"file": "targets/app/source.cs", "line": 10},
        "sink": {"file": "targets/app/sink.cs", "line": 20},
        "evidence": "test fixture",
        "reachability": {
            "entry_point": "POST /api/items",
            "min_privilege": "unauthenticated",
            "pre_auth": True,
            "call_chain": ["ItemsController.Post", "Parser.ParseContentLength"],
        },
        "preconditions": {"default_configuration": True},
        "primitive": {
            "kinds": ["authn-bypass"],
            "escalation_ceiling": "request smuggling only; no path to code execution found",
        },
        "repro": {
            "attempted": True,
            "success": True,
            "poc": "python3 poc.py",
            "response": "PASS: security boundary crossed",
        },
    }


def review(verdict):
    return {
        "checked": True,
        "verdict": verdict,
        "sources": ["https://learn.microsoft.com/example"],
        "rationale": "The exact supported product boundary was compared with the reproduced behavior.",
        "product_version": "10.0.12",
        "default_configuration": False,
    }


def public_history():
    return {
        "checked": True,
        "upstream_repository": "https://github.com/vendor/product",
        "exact_anchors": ["Parser.ParseContentLength", "InvalidContentLength"],
        "source_history": ["git log -S'InvalidContentLength' -- src/Parser.cs"],
        "vendor_issues_prs": [
            "https://github.com/vendor/product/issues?q=InvalidContentLength"
        ],
        "advisories_releases": ["https://vendor.example/security/advisories"],
        "head_or_release_comparison": (
            "Compared the tested tag with upstream main and the supported release branch; "
            "the behavior and fix were absent."
        ),
    }


class OfficialReviewHelpersTest(unittest.TestCase):
    def test_reportable_review_passes_confirmation_gate(self):
        finding = base_finding("confirmed")
        finding["official_review"] = review("product_vulnerability")
        self.assertEqual(review_state(finding), "reportable")
        self.assertTrue(confirmation_gate_passes(finding))

    def test_documented_hazard_is_non_product(self):
        finding = base_finding("not_product_vulnerability")
        finding["official_review"] = review("documented_hazard")
        self.assertEqual(review_state(finding), "non_product")
        self.assertFalse(confirmation_gate_passes(finding))

    def test_missing_review_stays_pending(self):
        self.assertEqual(review_state(base_finding("reproduced")), "pending")

    def test_novelty_requires_complete_public_history(self):
        finding = base_finding("confirmed")
        finding["official_review"] = review("product_vulnerability")
        finding["disclosure"] = {
            "checked": True,
            "status": "novel",
            "references": [],
            "rationale": "No matching public report or source change was found.",
        }
        self.assertEqual(disclosure_state(finding), "pending")
        self.assertFalse(novelty_gate_passes(finding))

        finding["disclosure"]["public_history"] = public_history()
        self.assertTrue(public_history_review_is_complete(finding))
        self.assertEqual(disclosure_state(finding), "novel")
        self.assertTrue(novelty_gate_passes(finding))


class FindingWriterGateTest(unittest.TestCase):
    def run_writer(self, finding):
        with tempfile.TemporaryDirectory() as tmp:
            return subprocess.run(
                [sys.executable, str(WRITER), "--out", tmp, "--schema", str(SCHEMA)],
                input=json.dumps(finding), text=True, capture_output=True, cwd=ROOT,
            )

    def test_rejects_confirmation_without_official_review(self):
        result = self.run_writer(base_finding("confirmed"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires a completed official_review", result.stderr)

    def test_rejects_confirmation_without_successful_reproduction(self):
        finding = base_finding("confirmed")
        finding["official_review"] = review("product_vulnerability")
        finding["repro"]["success"] = False
        result = self.run_writer(finding)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires successful dynamic reproduction", result.stderr)

    def test_rejects_non_product_verdict_as_confirmed(self):
        finding = base_finding("confirmed")
        finding["official_review"] = review("documented_hazard")
        result = self.run_writer(finding)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("inconsistent", result.stderr)

    def test_rejects_local_source_only_review(self):
        finding = base_finding("confirmed")
        finding["official_review"] = review("product_vulnerability")
        finding["official_review"]["sources"] = ["targets/runtime/source.cs:10"]
        result = self.run_writer(finding)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("public primary", result.stderr)

    def test_rejects_github_blob_as_only_public_reference(self):
        finding = base_finding("confirmed")
        finding["official_review"] = review("product_vulnerability")
        finding["official_review"]["sources"] = [
            "https://github.com/dotnet/runtime/blob/v10.0.12/src/example.cs"
        ]
        result = self.run_writer(finding)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("blob/tree/raw", result.stderr)

    def test_accepts_consistent_terminal_states(self):
        confirmed = base_finding("confirmed")
        confirmed["official_review"] = review("product_vulnerability")
        self.assertEqual(self.run_writer(confirmed).returncode, 0)

        non_product = base_finding("not_product_vulnerability")
        non_product["official_review"] = review("application_misconfiguration")
        self.assertEqual(self.run_writer(non_product).returncode, 0)

    def test_rejects_exploitation_before_product_gate(self):
        finding = base_finding("reproduced")
        finding["exploit"] = {
            "depth": "weaponized", "primitive": "test", "max_impact": "test"
        }
        result = self.run_writer(finding)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exploit evidence requires", result.stderr)

    def test_rejects_novel_without_public_history(self):
        finding = base_finding("confirmed")
        finding["official_review"] = review("product_vulnerability")
        finding["disclosure"] = {
            "checked": True,
            "status": "novel",
            "references": [],
            "rationale": "No matching public report was found in a preliminary search.",
        }
        result = self.run_writer(finding)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("requires public_history evidence", result.stderr)

    def test_accepts_novel_with_complete_public_history(self):
        finding = base_finding("confirmed")
        finding["official_review"] = review("product_vulnerability")
        finding["disclosure"] = {
            "checked": True,
            "status": "novel",
            "references": [],
            "rationale": "No matching public report or source change was found.",
            "public_history": public_history(),
        }
        self.assertEqual(self.run_writer(finding).returncode, 0)

    def test_rejects_known_verdict_claimed_as_novel(self):
        finding = base_finding("confirmed")
        finding["official_review"] = review("known_vulnerability")
        finding["disclosure"] = {
            "checked": True,
            "status": "novel",
            "references": [],
            "rationale": "The finding was incorrectly claimed as novel for this fixture.",
            "public_history": public_history(),
        }
        result = self.run_writer(finding)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("only an officially reviewed product_vulnerability may be novel", result.stderr)


class ReportingGateTest(unittest.TestCase):
    def test_triage_and_emit_only_promote_gated_confirmed_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            findings = tmp_path / "findings"
            report = tmp_path / "report"
            findings.mkdir()

            product = base_finding("confirmed")
            product.update({"id": "product", "disclosure": {
                "checked": True, "status": "novel", "references": [],
                "rationale": "No matching public advisory was found.",
                "public_history": public_history(),
            }})
            product["repro"]["poc_script"] = "print('PASS')\n"
            product["official_review"] = review("product_vulnerability")

            legacy = base_finding("confirmed")
            legacy.update({"id": "legacy", "title": "legacy confirmation"})

            claimed = base_finding("confirmed")
            claimed.update({"id": "claimed", "title": "unreviewed novelty claim",
                            "disclosure": {
                                "checked": True, "status": "novel", "references": [],
                                "rationale": "No matching public advisory was found.",
                            }})
            claimed["official_review"] = review("product_vulnerability")

            rejected = base_finding("not_product_vulnerability")
            rejected.update({"id": "rejected", "title": "documented behavior"})
            rejected["official_review"] = review("documented_hazard")

            for finding in (product, legacy, claimed, rejected):
                (findings / f"{finding['id']}.json").write_text(json.dumps(finding))

            triage = subprocess.run(
                [sys.executable, str(SCRIPTS / "triage.py"), "--findings", str(findings),
                 "--out", str(report / "report.md")],
                text=True, capture_output=True, cwd=ROOT,
            )
            self.assertEqual(triage.returncode, 0, triage.stderr)
            rendered = (report / "report.md").read_text()
            self.assertIn("officially reportable unique roots: 2", rendered)
            self.assertIn("official review pending", rendered)
            self.assertIn("Public-history/disclosure review pending", rendered)
            self.assertIn("`claimed`", rendered)
            self.assertIn("Reproduced but not a product vulnerability", rendered)
            self.assertIn("Potential 0-day", rendered)
            potential = rendered.split("Potential 0-day", 1)[1].split("##", 1)[0]
            self.assertIn("No matching public advisory was found.", potential)
            self.assertNotIn("unreviewed novelty claim", potential)

            emitted = subprocess.run(
                [sys.executable, str(SCRIPTS / "emit_poc.py"), "--findings", str(findings),
                 "--out", str(report)],
                text=True, capture_output=True, cwd=ROOT,
            )
            self.assertEqual(emitted.returncode, 0, emitted.stderr)
            self.assertTrue((report / "product/poc.py").exists())
            self.assertFalse((report / "legacy").exists())
            self.assertFalse((report / "rejected").exists())


if __name__ == "__main__":
    unittest.main()
