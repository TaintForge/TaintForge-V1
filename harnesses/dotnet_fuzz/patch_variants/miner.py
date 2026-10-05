#!/usr/bin/env python3
"""Build and manage a Microsoft .NET patch-variant research queue.

Only official GitHub advisory and compare APIs are consumed. Public CVEs and their
fixes are hypothesis material, never findings. A queue item becomes interesting only
when an analyst proves a distinct bug on the current stock target.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
CONFIG = HERE / "config.json"
STATE = ROOT / "workspace/dotnet-bounty/patch-variants"
QUEUE = STATE / "variant-queue.json"
LOCK = STATE / ".lock"
USER_AGENT = "TaintForge-dotnet-patch-variant-miner/1.0"

RISK_TERMS: dict[str, tuple[str, ...]] = {
    "memory-safety": (
        "unsafe", "pointer", "memcpy", "memmove", "buffer", "span<", "memorymarshal",
        "stackalloc", "alloc", "free(", "overflow", "underflow", "out of bounds", "oob",
        "length", "offset", "size_t", "checked(", "unmanaged", "native", "asan",
    ),
    "http-framing": (
        "content-length", "transfer-encoding", "chunked", "request line", "header",
        "http1", "http2", "http3", "hpack", "qpack", "frame", "stream window",
        "kestrel", "quic", "websocket", "multipart", "trailer", "pipeline",
    ),
    "auth-crypto": (
        "authentication", "authorization", "cookie", "token", "dataprotection",
        "protect", "unprotect", "signature", "certificate", "identity", "negotiate",
        "ldap", "keyring", "cryptograph", "principal", "claim", "redirect",
    ),
    "parser-deserialization": (
        "deserialize", "serializer", "json", "xml", "cbor", "metadata", "peheader",
        "readytorun", "pdb", "archive", "zip", "regex", "uri", "utf", "encoding",
        "parse", "reader", "decoder", "reflection", "typeload", "marshal",
    ),
    "lifetime-concurrency": (
        "race", "interlocked", "volatile", "lock (", "dispose", "cancel", "abort",
        "reset", "lifetime", "pool", "use after", "uaf", "async", "thread", "gc ",
    ),
    "arithmetic-boundary": (
        "int.maxvalue", "uint.maxvalue", "long.maxvalue", "0x7fff", "0xffff", "maxvalue",
        "minvalue", "boundary", "negative", "truncate", "wrap", "index", "count",
    ),
}

IMPACT_WEIGHT = {
    "remote code execution": 50,
    "elevation of privilege": 42,
    "security feature bypass": 36,
    "information disclosure": 24,
    "denial of service": 12,
}

FIX_PATTERNS = (
    r"\bfix(?:es|ed|ing)?\b", r"\bharden(?:s|ed|ing)?\b", r"\breject(?:s|ed|ing)?\b",
    r"\bvalidat(?:e|es|ed|ing|ion)\b", r"\bprevent(?:s|ed|ing)?\b",
    r"\bavoid(?:s|ed|ing)?\b", r"\boverflows?\b", r"\bbounds?\b", r"\braces?\b",
    r"\bleaks?\b", r"\bcorrupt(?:s|ed|ing|ion)?\b", r"\bsecurity\b",
    r"\bsanitiz(?:e|es|ed|ing|ation)\b", r"\btruncat(?:e|es|ed|ing|ion)\b",
    r"\bcrash(?:es|ed|ing)?\b", r"\bhang(?:s|ing)?\b", r"\block(?:s|ed|ing)?\b",
)
BORING_COMMIT_TERMS = (
    "update dependencies", "bump ", "branding", "merge branch", "merge pull request",
    "quarantine", "flaky test", "source-build", "arcade", "baseline, sdk",
)

SOURCE_SUFFIXES = {
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".cs", ".fs", ".rs", ".js", ".ts"
}
TEST_MARKERS = ("/test/", "/tests/", "test.cs", "tests.cs", "fuzz")
NOISE_PREFIXES = (
    "eng/", ".azure/", ".github/", "docs/", "documentation/", "src/installer/"
)
NOISE_MARKERS = ("/snapshots/", "/external/", "/ref/", "/samples/", "/sample/")

ADVISORY_HINTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("http/3", ("http3", "http/3", "quic")),
    ("http/2", ("http2", "http/2", "hpack")),
    ("http request", ("request", "kestrel", "http")),
    ("kestrel", ("kestrel",)),
    ("websocket", ("websocket", "web socket")),
    ("data protection", ("dataprotection", "data protection", "authenticatedencryptor")),
    ("authentication cookie", ("cookie", "authentication")),
    ("cookie", ("cookie",)),
    ("negotiate", ("negotiate", "ldap", "kerberos")),
    ("certificate", ("certificate", "x509")),
    ("xml", ("xml",)),
    ("json", ("json",)),
    ("cbor", ("cbor",)),
    ("pdb", ("pdb", "diasymreader", "msfz")),
    ("readytorun", ("readytorun", "ready to run")),
    ("zip", ("zip", "archive")),
    ("regex", ("regex", "regular expression")),
)


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fp:
            json.dump(value, fp, indent=2, sort_keys=True)
            fp.write("\n")
        os.replace(tmp, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)


@contextlib.contextmanager
def locked() -> Iterable[None]:
    STATE.mkdir(parents=True, exist_ok=True)
    with LOCK.open("a+", encoding="utf-8") as fp:
        fcntl.flock(fp.fileno(), fcntl.LOCK_EX)
        yield


def api_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": USER_AGENT,
        "X-GitHub-Api-Version": "2022-11-28",
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_json(url: str, cache: Path, max_age_hours: int, force: bool) -> Any:
    if cache.exists() and not force:
        age = dt.datetime.now().timestamp() - cache.stat().st_mtime
        if age < max_age_hours * 3600:
            return read_json(cache)
    req = urllib.request.Request(url, headers=api_headers())
    try:
        with urllib.request.urlopen(req, timeout=45) as response:
            data = json.load(response)
    except (urllib.error.URLError, TimeoutError) as exc:
        if cache.exists():
            print(f"warning: {url}: {exc}; using cache", file=sys.stderr)
            return read_json(cache)
        raise
    atomic_json(cache, data)
    return data


def fetch_text(url: str, cache: Path, max_age_hours: int, force: bool) -> str:
    if cache.exists() and not force:
        age = dt.datetime.now().timestamp() - cache.stat().st_mtime
        if age < max_age_hours * 3600:
            return cache.read_text(encoding="utf-8", errors="replace")
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=45) as response:
            data = response.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError) as exc:
        if cache.exists():
            print(f"warning: {url}: {exc}; using cache", file=sys.stderr)
            return cache.read_text(encoding="utf-8", errors="replace")
        raise
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(data, encoding="utf-8")
    return data


def stable_semver(value: str) -> tuple[int, int, int] | None:
    match = re.fullmatch(r"\s*(\d+)\.(\d+)\.(\d+)\s*", value or "")
    return tuple(map(int, match.groups())) if match else None


def upper_bound(version_range: str, patched: tuple[int, int, int]) -> tuple[int, int, int]:
    candidates = []
    for text in re.findall(r"(?:<=|<)\s*(\d+\.\d+\.\d+)", version_range or ""):
        parsed = stable_semver(text)
        if parsed and parsed[:2] == patched[:2] and parsed < patched:
            candidates.append(parsed)
    if candidates:
        return max(candidates)
    return patched[0], patched[1], max(0, patched[2] - 1)


def impact_score(advisory: dict[str, Any]) -> int:
    text = f"{advisory.get('summary', '')} {advisory.get('description', '')}".lower()
    score = max((weight for term, weight in IMPACT_WEIGHT.items() if term in text), default=5)
    severity = str(advisory.get("severity", "")).lower()
    score += {"critical": 18, "high": 12, "medium": 5, "low": 0}.get(severity, 0)
    return score


def compact_advisory(repo: str, advisory: dict[str, Any]) -> dict[str, Any]:
    description = re.sub(r"\s+", " ", advisory.get("description") or "").strip()
    return {
        "repository": repo,
        "ghsa_id": advisory.get("ghsa_id"),
        "cve_id": advisory.get("cve_id"),
        "summary": advisory.get("summary"),
        "severity": advisory.get("severity"),
        "published_at": advisory.get("published_at"),
        "description": description[:4000],
        "cwes": [x.get("cwe_id") for x in advisory.get("cwes", []) if x.get("cwe_id")],
        "cvss": advisory.get("cvss", {}),
        "vulnerabilities": advisory.get("vulnerabilities", []),
        "url": advisory.get("html_url") or (
            f"https://github.com/{repo}/security/advisories/{advisory.get('ghsa_id')}"
        ),
        "impact_score": impact_score(advisory),
    }


def derive_comparisons(
    config: dict[str, Any], advisories: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    majors = set(config["supported_majors"])
    by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    for adv in advisories:
        repo = adv["repository"]
        for vuln in adv.get("vulnerabilities", []):
            patched = stable_semver(vuln.get("patched_versions", ""))
            if not patched or patched[0] not in majors or patched[2] == 0:
                continue
            base = upper_bound(vuln.get("vulnerable_version_range", ""), patched)
            key = (repo, "v" + ".".join(map(str, base)), "v" + ".".join(map(str, patched)))
            row = by_key.setdefault(key, {
                "repository": repo,
                "base": key[1],
                "head": key[2],
                "advisories": [],
                "reason": "security servicing delta",
                "priority": 0,
            })
            ref = {
                "cve_id": adv.get("cve_id"),
                "ghsa_id": adv.get("ghsa_id"),
                "summary": adv.get("summary"),
                "url": adv.get("url"),
                "description": adv.get("description", "")[:1200],
            }
            if ref not in row["advisories"]:
                row["advisories"].append(ref)
            row["priority"] = max(row["priority"], adv["impact_score"])
    for item in config.get("always_compare", []):
        key = (item["repository"], item["base"], item["head"])
        if key in by_key:
            by_key[key]["priority"] = max(by_key[key]["priority"], item.get("priority", 58))
            by_key[key]["reason"] = item["reason"]
        else:
            by_key[key] = {
                **item,
                "advisories": [],
                "priority": item.get("priority", 58),
            }
    return sorted(by_key.values(), key=lambda x: (-x["priority"], x["repository"], x["head"]))


def categories_for(text: str) -> list[str]:
    lower = text.lower()
    return [name for name, terms in RISK_TERMS.items() if any(term in lower for term in terms)]


def score_file(filename: str, patch: str, comparison: dict[str, Any]) -> tuple[int, list[str]]:
    combined = f"{filename}\n{patch}"
    categories = categories_for(combined)
    score = comparison["priority"] + 5 * len(categories)
    suffix = Path(filename).suffix.lower()
    lower = filename.lower()
    is_source = suffix in SOURCE_SUFFIXES
    is_test = any(marker in lower for marker in TEST_MARKERS)
    is_noise = lower.startswith(NOISE_PREFIXES) or any(marker in lower for marker in NOISE_MARKERS)
    if is_source and not is_test and not is_noise:
        score += 32
    elif is_source and is_test:
        score -= 6
    else:
        score -= 25
    if is_noise:
        score -= 40
    if not patch:
        score -= 8
    advisory_text = " ".join(
        f"{item.get('summary', '')} {item.get('description', '')}" for item in comparison["advisories"]
    ).lower()
    active_hints = [aliases for phrase, aliases in ADVISORY_HINTS if phrase in advisory_text]
    hint_matches = sum(1 for aliases in active_hints if any(alias in combined.lower() for alias in aliases))
    if hint_matches:
        score += min(42, hint_matches * 14)
    elif active_hints:
        score -= 24
    return score, categories


def suspicious_commit_map(
    comparison: dict[str, Any], payload: dict[str, Any], cache: Path, max_age: int, force: bool
) -> dict[str, list[dict[str, str]]]:
    """Map files to likely fix commits without consuming GitHub API requests.

    Release comparisons contain many unrelated servicing changes. Commit .patch endpoints let us
    prefer files that actually belong to a fix-like commit while retaining the complete delta as
    fallback material.
    """
    selected = []
    for item in payload.get("commits", []):
        message = ((item.get("commit") or {}).get("message") or "").splitlines()[0]
        lower = message.lower()
        if not any(re.search(pattern, lower) for pattern in FIX_PATTERNS):
            continue
        if any(term in lower for term in BORING_COMMIT_TERMS) and "security" not in lower:
            continue
        selected.append((item, message))
    selected = selected[:10]
    file_map: dict[str, list[dict[str, str]]] = defaultdict(list)
    for item, message in selected:
        sha = item.get("sha")
        html_url = item.get("html_url") or f"https://github.com/{comparison['repository']}/commit/{sha}"
        try:
            patch = fetch_text(
                html_url + ".patch",
                cache / f"commit-{comparison['repository'].replace('/', '--')}--{sha}.patch",
                max_age,
                force,
            )
        except Exception as exc:
            print(f"warning: commit patch {sha}: {exc}", file=sys.stderr)
            continue
        paths = re.findall(r"^diff --git a/(.+?) b/(.+?)$", patch, flags=re.MULTILINE)
        ref = {"sha": sha, "message": message, "url": html_url}
        for before, after in paths:
            filename = after if after != "/dev/null" else before
            if ref not in file_map[filename]:
                file_map[filename].append(ref)
    return file_map


def path_index(target: Path) -> tuple[set[str], dict[str, list[str]]]:
    exact: set[str] = set()
    names: dict[str, list[str]] = defaultdict(list)
    for path in target.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(target).as_posix()
        exact.add(rel)
        names[path.name].append(rel)
    return exact, names


def map_current_path(filename: str, target: str, indexes: dict[str, Any]) -> list[str]:
    exact, names = indexes[target]
    if filename in exact:
        return [f"{target}/{filename}"]
    matches = names.get(Path(filename).name, [])
    return [f"{target}/{item}" for item in matches[:8]]


def extract_symbols(patch: str) -> list[str]:
    found: list[str] = []
    patterns = (
        r"\b(?:public|private|internal|protected|static|virtual|override|async)\s+"
        r"(?:[\w<>,.?\[\] ]+\s+)?([A-Za-z_]\w*)\s*\(",
        r"\b(?:TEST|TEST_F|Theory|Fact)\s*\(?\s*([A-Za-z_]\w*)?",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, patch):
            value = match.group(1) if match.lastindex else None
            if value and value not in found:
                found.append(value)
    return found[:20]


def variant_plan(categories: list[str]) -> list[str]:
    plans = [
        "Read the complete vulnerable-to-fixed hunk and its regression tests; state the repaired invariant.",
        "Search the current stock target for sibling callers and parallel implementations that enforce the same invariant differently.",
        "Prove attacker-controlled reachability before fuzzing; preserve the public CVE as a known negative control only.",
    ]
    if "memory-safety" in categories or "arithmetic-boundary" in categories:
        plans.append("Mutate nested length/offset/count arithmetic at 0, 1, boundary-1, boundary, boundary+1, signed-wrap and allocation-limit values under ASan or an exact corruption oracle.")
    if "http-framing" in categories:
        plans.append("Vary segmentation, duplicate/conflicting lengths, frame padding, stream reset/half-close, auto-drain and a paired victim request; compare consumed bytes and next-request ownership.")
    if "auth-crypto" in categories:
        plans.append("Exercise malformed/partial/replayed protected payloads across every encryptor/provider path and require an authorization or signature-verification oracle, not just an exception difference.")
    if "parser-deserialization" in categories:
        plans.append("Generate structurally valid graphs/documents plus duplicate metadata, reference cycles, depth/length skew and version mismatch; monitor native boundaries and side effects.")
    if "lifetime-concurrency" in categories:
        plans.append("Schedule abort/cancel/dispose/reset at every await and ownership transfer; look for pooled cross-request reuse, double release and stale native handles.")
    return plans


def make_tasks(
    comparisons: list[dict[str, Any]],
    compare_payloads: list[tuple[dict[str, Any], dict[str, Any]]],
    repo_targets: dict[str, str],
    old_queue: dict[str, Any],
) -> list[dict[str, Any]]:
    old = {task["id"]: task for task in old_queue.get("tasks", [])}
    indexes = {target: path_index(ROOT / target) for target in set(repo_targets.values())}
    tasks = []
    for comparison, payload in compare_payloads:
        target = repo_targets[comparison["repository"]]
        commits = [
            {
                "sha": item.get("sha"),
                "message": ((item.get("commit") or {}).get("message") or "").splitlines()[0],
                "url": item.get("html_url"),
            }
            for item in payload.get("commits", [])
        ]
        for changed in payload.get("files", []):
            filename = changed.get("filename", "")
            patch = changed.get("patch", "")
            score, categories = score_file(filename, patch, comparison)
            fix_commits = payload.get("_variant_commit_map", {}).get(filename, [])
            if fix_commits:
                score += 45
                for item in fix_commits:
                    for category in categories_for(item["message"]):
                        if category not in categories:
                            categories.append(category)
            current_paths = map_current_path(filename, target, indexes)
            if not current_paths:
                score -= 28
            if score < 25 or not categories or Path(filename).suffix.lower() not in SOURCE_SUFFIXES:
                continue
            identity = "\0".join((comparison["repository"], comparison["base"], comparison["head"], filename))
            task_id = hashlib.sha256(identity.encode()).hexdigest()[:16]
            previous = old.get(task_id, {})
            tasks.append({
                "id": task_id,
                "status": previous.get("status", "queued"),
                "owner": previous.get("owner"),
                "claimed_at": previous.get("claimed_at"),
                "completed_at": previous.get("completed_at"),
                "resolution": previous.get("resolution"),
                "notes": previous.get("notes", []),
                "score": score,
                "repository": comparison["repository"],
                "base": comparison["base"],
                "head": comparison["head"],
                "known_advisories": comparison["advisories"],
                "known_public_issue": True,
                "file": filename,
                "current_paths": current_paths,
                "change": {
                    "status": changed.get("status"),
                    "additions": changed.get("additions"),
                    "deletions": changed.get("deletions"),
                    "changes": changed.get("changes"),
                    "blob_url": changed.get("blob_url"),
                    "raw_url": changed.get("raw_url"),
                },
                "categories": categories,
                "symbols": extract_symbols(patch),
                "patch": patch[:30000],
                "commits": commits,
                "fix_commits": fix_commits,
                "variant_plan": variant_plan(categories),
                "promotion_gate": [
                    "Behavior is distinct from every known advisory attached to this task.",
                    "The bug reproduces on the unmodified supported stock 10.0.12 target.",
                    "Attacker-controlled input and a Microsoft-owned security boundary are proven.",
                    "A deterministic security oracle exists; a patch pattern or crash alone is not a finding.",
                ],
            })
    # The same fix is commonly backported to 8/9/10. Review one current-source projection per
    # CVE and file instead of making H repeat an equivalent task for every servicing branch.
    ordered = sorted(
        tasks,
        key=lambda x: (x["status"] == "queued", -x["score"], x["repository"], x["file"]),
    )
    deduped = []
    seen = set()
    for task in ordered:
        cves = tuple(sorted(x.get("cve_id") or x.get("ghsa_id") for x in task["known_advisories"]))
        current = task["current_paths"][0] if task["current_paths"] else task["file"]
        key = (task["repository"], current, cves) if cves else ("task", task["id"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(task)
    return sorted(deduped, key=lambda x: (-x["score"], x["repository"], x["file"]))


def write_summary(queue: dict[str, Any], comparisons: list[dict[str, Any]]) -> None:
    counts: dict[str, int] = defaultdict(int)
    categories: dict[str, int] = defaultdict(int)
    for task in queue["tasks"]:
        counts[task["status"]] += 1
        for category in task["categories"]:
            categories[category] += 1
    lines = [
        "# .NET patch-variant queue",
        "",
        f"Generated: `{queue['generated_at']}`",
        "",
        "Public fixes are known controls, not reportable findings. Analysts must prove a distinct",
        "variant on the exact stock 10.0.12 target before using `write_finding.py`.",
        "",
        f"- Tasks: {len(queue['tasks'])}",
        f"- Status: {', '.join(f'{key}={value}' for key, value in sorted(counts.items()))}",
        f"- Categories: {', '.join(f'{key}={value}' for key, value in sorted(categories.items()))}",
        f"- Release comparisons: {len(comparisons)}",
        "",
        "## Highest-priority open tasks",
        "",
        "| Score | ID | Repository / range | Categories | Current path |",
        "| ---: | --- | --- | --- | --- |",
    ]
    for task in [x for x in queue["tasks"] if x["status"] in ("queued", "claimed")][:30]:
        path = task["current_paths"][0] if task["current_paths"] else task["file"]
        lines.append(
            f"| {task['score']} | `{task['id']}` | {task['repository']} "
            f"{task['base']}…{task['head']} | {', '.join(task['categories'])} | `{path}` |"
        )
    (STATE / "SUMMARY.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def refresh(args: argparse.Namespace) -> None:
    config = read_json(CONFIG)
    cache = STATE / "cache"
    repo_targets = {item["github"]: item["target"] for item in config["repositories"]}
    advisories: list[dict[str, Any]] = []
    for item in config["repositories"]:
        repo = item["github"]
        encoded = repo.replace("/", "--")
        url = f"https://api.github.com/repos/{repo}/security-advisories?per_page=100"
        rows = fetch_json(url, cache / f"advisories-{encoded}.json", args.max_age, args.force)
        for row in rows:
            published = row.get("published_at") or "0000"
            if int(published[:4]) < config["minimum_year"]:
                continue
            advisories.append(compact_advisory(repo, row))
    advisories.sort(key=lambda x: (-x["impact_score"], x.get("published_at") or ""), reverse=False)
    atomic_json(STATE / "advisories.json", {"generated_at": now(), "advisories": advisories})

    comparisons = derive_comparisons(config, advisories)[: args.max_comparisons]
    payloads: list[tuple[dict[str, Any], dict[str, Any]]] = []
    failures = []
    for comparison in comparisons:
        repo = comparison["repository"]
        base = urllib.parse.quote(comparison["base"], safe="")
        head = urllib.parse.quote(comparison["head"], safe="")
        url = f"https://api.github.com/repos/{repo}/compare/{base}...{head}?per_page=100"
        filename = f"compare-{repo.replace('/', '--')}--{comparison['base']}--{comparison['head']}.json"
        try:
            payload = fetch_json(url, cache / filename, args.max_age, args.force)
        except Exception as exc:  # preserve the rest of the queue if one historical tag is absent
            failures.append({"comparison": comparison, "error": str(exc)})
            continue
        if isinstance(payload, dict) and payload.get("files"):
            payload["_variant_commit_map"] = suspicious_commit_map(
                comparison, payload, cache, args.max_age, args.force
            )
            payloads.append((comparison, payload))

    with locked():
        old_queue = read_json(QUEUE, {"tasks": []})
        tasks = make_tasks(comparisons, payloads, repo_targets, old_queue)
        queue = {
            "schema_version": 1,
            "generated_at": now(),
            "known_issue_policy": "Public patches are controls only; only distinct stock-10.0.12 variants may be promoted.",
            "comparisons": comparisons,
            "failures": failures,
            "tasks": tasks,
        }
        atomic_json(QUEUE, queue)
        write_summary(queue, comparisons)
    print(f"refreshed advisories={len(advisories)} comparisons={len(payloads)} tasks={len(tasks)} failures={len(failures)}")


def status(_: argparse.Namespace) -> None:
    queue = read_json(QUEUE, {"tasks": []})
    counts: dict[str, int] = defaultdict(int)
    for task in queue["tasks"]:
        counts[task.get("status", "queued")] += 1
    print(f"generated={queue.get('generated_at', 'never')}")
    print(f"tasks={len(queue['tasks'])} " + " ".join(f"{k}={v}" for k, v in sorted(counts.items())))
    for task in [x for x in queue["tasks"] if x.get("status") in ("queued", "claimed")][:10]:
        print(
            f"{task['status']:<8} score={task['score']:<3} id={task['id']} "
            f"{task['repository']} {task['base']}..{task['head']} {task['file']}"
        )


def claim(args: argparse.Namespace) -> None:
    with locked():
        queue = read_json(QUEUE, {"tasks": []})
        current_time = dt.datetime.now(dt.timezone.utc)
        for task in queue["tasks"]:
            if task.get("status") != "claimed":
                continue
            claimed_at = task.get("claimed_at")
            try:
                claimed_time = dt.datetime.fromisoformat(claimed_at)
            except (TypeError, ValueError):
                claimed_time = current_time
            age_hours = (current_time - claimed_time).total_seconds() / 3600
            if task.get("owner") == args.owner and age_hours < args.stale_hours:
                print(json.dumps(task, indent=2))
                return
            if age_hours >= args.stale_hours:
                task.setdefault("notes", []).append({
                    "at": now(),
                    "owner": "queue",
                    "text": f"stale claim released after {age_hours:.1f} hours",
                })
                task["status"] = "queued"
                task["owner"] = None
                task["claimed_at"] = None
        selected = None
        for task in queue["tasks"]:
            if task.get("status") == "queued":
                selected = task
                break
        if selected is None:
            print("EMPTY")
            return
        selected["status"] = "claimed"
        selected["owner"] = args.owner
        selected["claimed_at"] = now()
        atomic_json(QUEUE, queue)
        write_summary(queue, queue.get("comparisons", []))
        print(json.dumps(selected, indent=2))


def complete(args: argparse.Namespace) -> None:
    allowed = {"reviewed", "lead", "candidate", "blocked", "queued"}
    if args.result not in allowed:
        raise SystemExit(f"result must be one of: {', '.join(sorted(allowed))}")
    with locked():
        queue = read_json(QUEUE, {"tasks": []})
        for task in queue["tasks"]:
            if task["id"] != args.id:
                continue
            task["status"] = args.result
            task["resolution"] = args.note
            task["completed_at"] = now() if args.result != "queued" else None
            task.setdefault("notes", []).append({"at": now(), "owner": args.owner, "text": args.note})
            if args.result == "queued":
                task["owner"] = None
                task["claimed_at"] = None
            atomic_json(QUEUE, queue)
            write_summary(queue, queue.get("comparisons", []))
            print(json.dumps(task, indent=2))
            return
    raise SystemExit(f"unknown task: {args.id}")


def show(args: argparse.Namespace) -> None:
    queue = read_json(QUEUE, {"tasks": []})
    for task in queue["tasks"]:
        if task["id"] == args.id:
            print(json.dumps(task, indent=2))
            return
    raise SystemExit(f"unknown task: {args.id}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    refresh_cmd = sub.add_parser("refresh")
    refresh_cmd.add_argument("--force", action="store_true")
    refresh_cmd.add_argument("--max-age", type=int, default=12, help="cache age in hours")
    refresh_cmd.add_argument("--max-comparisons", type=int, default=24)
    refresh_cmd.set_defaults(func=refresh)
    status_cmd = sub.add_parser("status")
    status_cmd.set_defaults(func=status)
    claim_cmd = sub.add_parser("claim")
    claim_cmd.add_argument("--owner", required=True)
    claim_cmd.add_argument("--stale-hours", type=float, default=6.0)
    claim_cmd.set_defaults(func=claim)
    complete_cmd = sub.add_parser("complete")
    complete_cmd.add_argument("--id", required=True)
    complete_cmd.add_argument("--owner", required=True)
    complete_cmd.add_argument("--result", required=True)
    complete_cmd.add_argument("--note", required=True)
    complete_cmd.set_defaults(func=complete)
    show_cmd = sub.add_parser("show")
    show_cmd.add_argument("--id", required=True)
    show_cmd.set_defaults(func=show)
    return parser.parse_args()


if __name__ == "__main__":
    namespace = parse_args()
    namespace.func(namespace)
