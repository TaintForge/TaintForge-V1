#!/usr/bin/env python3
"""Shared policy helpers for the mandatory official/vendor product review gate."""

REPORTABLE_VERDICTS = {"product_vulnerability", "known_vulnerability"}
NON_PRODUCT_VERDICTS = {
    "documented_hazard",
    "expected_behavior",
    "application_misconfiguration",
    "unsupported_scenario",
}


def is_qualifying_public_reference(source):
    if not isinstance(source, str) or not source.startswith("https://"):
        return False
    lowered = source.lower()
    # A raw/versioned source file is useful supporting evidence, but it is not the
    # documentation/advisory/release/patch/issue comparison required by this gate.
    if "github.com/" in lowered and any(part in lowered for part in ("/blob/", "/tree/", "/raw/")):
        return False
    return True


def official_review(finding):
    review = finding.get("official_review") or {}
    return review if isinstance(review, dict) else {}


def disclosure(finding):
    value = finding.get("disclosure") or {}
    return value if isinstance(value, dict) else {}


def public_history_review(finding):
    value = disclosure(finding).get("public_history") or {}
    return value if isinstance(value, dict) else {}


def _nonempty_strings(value, minimum=1):
    return (
        isinstance(value, list)
        and len([item for item in value if isinstance(item, str) and item.strip()]) >= minimum
    )


def public_history_review_is_complete(finding):
    """Whether a claimed novel finding passed the exact-match public-history search ladder."""
    review = public_history_review(finding)
    repository = review.get("upstream_repository") or ""
    comparison = review.get("head_or_release_comparison") or ""
    return (
        review.get("checked") is True
        and isinstance(repository, str)
        and repository.startswith("https://")
        and _nonempty_strings(review.get("exact_anchors"), minimum=2)
        and _nonempty_strings(review.get("source_history"))
        and _nonempty_strings(review.get("vendor_issues_prs"))
        and _nonempty_strings(review.get("advisories_releases"))
        and isinstance(comparison, str)
        and len(comparison.strip()) >= 20
    )


def disclosure_state(finding):
    """Return novel, known, inconclusive, or pending after enforcing disclosure evidence."""
    value = disclosure(finding)
    if value.get("checked") is not True or len(str(value.get("rationale") or "").strip()) < 20:
        return "pending"
    status = value.get("status")
    if status == "known":
        references = value.get("references") or []
        return "known" if any(is_qualifying_public_reference(ref) for ref in references) else "pending"
    if status == "novel":
        return "novel" if public_history_review_is_complete(finding) else "pending"
    if status == "inconclusive":
        return "inconclusive"
    return "pending"


def review_is_complete(finding):
    review = official_review(finding)
    sources = review.get("sources") or []
    rationale = review.get("rationale") or ""
    return (
        review.get("checked") is True
        and review.get("verdict") in REPORTABLE_VERDICTS | NON_PRODUCT_VERDICTS | {"inconclusive"}
        and isinstance(sources, list)
        and any(isinstance(source, str) and source.strip() for source in sources)
        and any(is_qualifying_public_reference(source) for source in sources)
        and isinstance(rationale, str)
        and len(rationale.strip()) >= 20
        and bool(str(review.get("product_version") or "").strip())
        and "default_configuration" in review
        and review.get("default_configuration") in (True, False, None)
    )


def review_state(finding):
    """Return reportable, non_product, or pending."""
    if not review_is_complete(finding):
        return "pending"
    verdict = official_review(finding).get("verdict")
    if verdict in REPORTABLE_VERDICTS:
        return "reportable"
    if verdict in NON_PRODUCT_VERDICTS:
        return "non_product"
    return "pending"


def reproduction_is_complete(finding):
    repro = finding.get("repro") or {}
    return (
        repro.get("attempted") is True
        and repro.get("success") is True
        and bool(str(repro.get("poc") or "").strip())
        and bool(str(repro.get("response") or "").strip())
    )


def confirmation_gate_passes(finding):
    return (
        finding.get("status") == "confirmed"
        and reproduction_is_complete(finding)
        and review_state(finding) == "reportable"
    )


def novelty_gate_passes(finding):
    return (
        confirmation_gate_passes(finding)
        and official_review(finding).get("verdict") == "product_vulnerability"
        and disclosure_state(finding) == "novel"
    )


def needs_public_history_work(finding):
    """Whether C still owes exact source-history / issue / PR / release disclosure review."""
    if not confirmation_gate_passes(finding):
        return False
    verdict = official_review(finding).get("verdict")
    state = disclosure_state(finding)
    if verdict == "known_vulnerability":
        return state != "known"
    return state in {"pending", "inconclusive"}


def non_product_gate_passes(finding):
    return (
        finding.get("status") == "not_product_vulnerability"
        and reproduction_is_complete(finding)
        and review_state(finding) == "non_product"
    )


def needs_official_review_work(finding):
    """Whether convergence still owes review or a status transition."""
    status = finding.get("status", "candidate")
    if status == "reproduced":
        return True
    if status == "confirmed":
        return not confirmation_gate_passes(finding)
    if status == "not_product_vulnerability":
        return not non_product_gate_passes(finding)
    return False
