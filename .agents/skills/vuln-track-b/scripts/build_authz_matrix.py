#!/usr/bin/env python3
"""
build_authz_matrix.py - deterministic SEED for Track B (logic / access-control).

Track B can't be done by a tool alone (a tool doesn't know what SHOULD be allowed).
This script produces the scaffolding the LLM then reasons over: a role x route
expected-access matrix plus structural red flags (state-change without auth,
id-parameter routes = IDOR candidates, admin routes without a role, routes with no
authz check). The LLM confirms/rejects each by reading the handler (see ../SKILL.md).

Input:  workspace/CODE_MODEL.json (uses the `comprehension` layer)
Output: workspace/_authz_matrix.json

Usage: build_authz_matrix.py [code_model.json] [-o workspace/_authz_matrix.json]
"""
import argparse, json, re, sys

ID_PARAM = re.compile(r'[:{<]\s*\w*[Ii]d\w*\s*[}>]?|/:\w*[Ii]d\w*|<\w*:\w*[Ii]d\w*>')
STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}
ADMIN_HINT = re.compile(r'/(admin|internal|manage|root|superuser)\b', re.I)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("model", nargs="?", default="workspace/CODE_MODEL.json")
    ap.add_argument("-o", "--out", default="workspace/_authz_matrix.json")
    args = ap.parse_args()

    model = json.load(open(args.model))
    comp = model.get("comprehension", {}) or {}
    pm = comp.get("permission_model", {}) or {}
    routes = comp.get("route_map", []) or []
    roles = pm.get("roles", []) or []
    authz_locations = pm.get("authz_locations", []) or []
    authz_handlers = {a.get("file","")+":"+str(a.get("line","")) for a in authz_locations}

    if not routes:
        print("[track-b] WARNING: comprehension.route_map is empty - run source-model "
              "to fill the comprehension layer first, else Track B has nothing to reason on.",
              file=sys.stderr)

    all_roles = sorted(set(roles) | {"anonymous", "authenticated"})
    matrix, idor, missing_authz, priv = [], [], [], []

    for r in routes:
        method = (r.get("method") or "").upper()
        path = r.get("path") or ""
        handler = r.get("handler") or ""
        auth_required = bool(r.get("auth_required"))
        role_required = r.get("role_required") or ""
        flags = []

        if method in STATE_CHANGING and not auth_required:
            flags.append("state-change-without-auth")
        if ID_PARAM.search(path):
            flags.append("id-param-IDOR-candidate")
            idor.append({"method": method, "path": path, "handler": handler,
                         "why": "takes an object id; needs an ownership/tenant check"})
        if ADMIN_HINT.search(path) and not role_required:
            flags.append("admin-route-without-role")
            priv.append({"method": method, "path": path, "handler": handler})
        # no explicit authz check tied to this handler
        if handler and not any(handler in h for h in authz_handlers):
            flags.append("no-explicit-authz-check")
            if auth_required is False:
                missing_authz.append({"method": method, "path": path, "handler": handler})

        # expected access row (what SHOULD be allowed - LLM verifies/edits)
        expected = {role: ("?" ) for role in all_roles}
        matrix.append({
            "method": method, "path": path, "handler": handler,
            "auth_required": auth_required, "role_required": role_required,
            "expected_access": expected, "red_flags": flags,
        })

    out = {
        "roles": all_roles,
        "auth_mechanism": pm.get("auth_mechanism", ""),
        "routes": matrix,
        "idor_candidates": idor,
        "missing_authz_candidates": missing_authz,
        "privilege_candidates": priv,
        "user_journeys": comp.get("user_journeys", []),
        "note": "expected_access is '?' - LLM fills per role from service intent, then "
                "compares against the actual checks in each handler (B2).",
    }
    json.dump(out, open(args.out, "w"), indent=2)
    print(f"[track-b] routes={len(matrix)} idor_candidates={len(idor)} "
          f"missing_authz={len(missing_authz)} priv={len(priv)} -> {args.out}")

if __name__ == "__main__":
    main()