#!/usr/bin/env python3
"""build_authz_matrix.py - deterministic SEED for Track B (logic / access-control)."""
from __future__ import annotations
import argparse, json, re, sys
from typing import Any, Dict, List
ID_PARAM=re.compile(r'[:{<]\s*\w*[Ii]d\w*\s*[}>]?|/:\w*[Ii]d\w*|<\w*:\w*[Ii]d\w*>|/\{\w*[Ii]d\w*\}')
STATE_CHANGING={"POST","PUT","PATCH","DELETE"}
ADMIN_HINT=re.compile(r'/(admin|internal|manage|root|superuser)\b',re.I)
def normalize_routes(model):
    comp=model.get("comprehension",{}) or {}
    routes=comp.get("route_map",[]) or []
    if routes: return routes,"comprehension.route_map"
    eps=(model.get("structural",{}) or {}).get("entry_points",[]) or []
    out=[]
    for e in eps:
        out.append({"method":e.get("method",""),"path":e.get("path",""),"handler":e.get("handler",""),
            "handler_symbol":e.get("handler_symbol",""),"file":e.get("file",""),"line":e.get("line",0)})
    return out,"structural.entry_points fallback"
def unknown_bool(v):
    if v is True: return "true"
    if v is False: return "false"
    return "unknown"
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("model",nargs="?",default="workspace/CODE_MODEL.json")
    ap.add_argument("-o","--out",default="workspace/_authz_matrix.json")
    args=ap.parse_args()
    model=json.load(open(args.model,encoding="utf-8"))
    comp=model.get("comprehension",{}) or {}; pm=comp.get("permission_model",{}) or {}
    routes,route_source=normalize_routes(model)
    roles=pm.get("roles",[]) or []; authz_locations=pm.get("authz_locations",[]) or []
    authz_handlers={a.get("file","")+":"+str(a.get("line","")) for a in authz_locations}
    if not routes: print("[track-b] WARNING: no routes or entry points found.",file=sys.stderr)
    all_roles=sorted(set(roles)|{"anonymous","authenticated"})
    matrix=[]; idor=[]; missing_authz=[]; priv=[]; needs_comprehension=[]
    for r in routes:
        method=(r.get("method") or "").upper(); path=r.get("path") or ""
        handler=r.get("handler") or ""; handler_symbol=r.get("handler_symbol") or ""
        auth_state=unknown_bool(r.get("auth_required") if "auth_required" in r else None)
        role_required=r.get("role_required") if "role_required" in r else None
        role_state=role_required if role_required not in (None,"") else "unknown"
        flags=[]
        if auth_state=="unknown":
            flags.append("auth-status-unknown-read-handler")
            needs_comprehension.append({"method":method,"path":path,"handler":handler,"why":"auth_required is unknown"})
        if method in STATE_CHANGING and auth_state!="true": flags.append("state-change-auth-missing-or-unknown")
        if ID_PARAM.search(path):
            flags.append("id-param-IDOR-candidate")
            idor.append({"method":method,"path":path,"handler":handler,"handler_symbol":handler_symbol,
                "why":"takes an object id; needs ownership/tenant check on the route-to-resource path"})
        if ADMIN_HINT.search(path) and role_state=="unknown":
            flags.append("admin-route-role-unknown")
            priv.append({"method":method,"path":path,"handler":handler,"handler_symbol":handler_symbol})
        if handler and not any(handler in h for h in authz_handlers):
            flags.append("no-explicit-authz-location-in-comprehension")
            if auth_state!="true": missing_authz.append({"method":method,"path":path,"handler":handler,"handler_symbol":handler_symbol})
        matrix.append({"method":method,"path":path,"handler":handler,"handler_symbol":handler_symbol,
            "file":r.get("file",""),"line":r.get("line",0),"auth_required":auth_state,"role_required":role_state,
            "expected_access":{role:"?" for role in all_roles},"red_flags":flags})
    out={"schema_version":2,"route_source":route_source,"roles":all_roles,
        "auth_mechanism":pm.get("auth_mechanism",""),"routes":matrix,"idor_candidates":idor,
        "missing_authz_candidates":missing_authz,"privilege_candidates":priv,
        "needs_comprehension":needs_comprehension,"user_journeys":comp.get("user_journeys",[]),
        "note":"auth_required/role_required can be 'unknown'. Unknown is not safe; read the handler/path."}
    json.dump(out,open(args.out,"w",encoding="utf-8"),indent=2,ensure_ascii=False)
    print(f"[track-b] route_source={route_source} routes={len(matrix)} idor_candidates={len(idor)} missing_or_unknown_authz={len(missing_authz)} priv={len(priv)} needs_comprehension={len(needs_comprehension)} -> {args.out}")
if __name__=="__main__": main()