#!/usr/bin/env python3
"""Compile an Android model into conservative emulator probe cases."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from urllib.parse import urlencode


def case_id(*parts: str) -> str:
    return hashlib.sha1("|".join(parts).encode()).hexdigest()[:12]


def deeplink_uri(link: dict) -> str | None:
    scheme = link.get("scheme")
    if not scheme:
        return None
    host = link.get("host") or ""
    port = f":{link['port']}" if link.get("port") else ""
    path = link.get("path") or link.get("pathPrefix") or "/"
    if not path.startswith("/"):
        path = "/" + path
    query = urlencode({"tf_probe": "manifest-seed"})
    return f"{scheme}://{host}{port}{path}?{query}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, default=Path("workspace/android/ANDROID_MODEL.json"))
    parser.add_argument("--out", type=Path, default=Path("workspace/android/probes.json"))
    args = parser.parse_args()
    model = json.loads(args.model.read_text(encoding="utf-8"))
    manifest = model.get("manifest", {})
    package = manifest.get("package", "")
    cases = []

    for link in manifest.get("deep_links", []):
        uri = deeplink_uri(link)
        if not uri:
            continue
        cases.append(
            {
                "id": case_id("uri", link.get("component", ""), uri),
                "kind": "uri",
                "package": package,
                "component": link.get("component"),
                "uri": uri,
                "safe_default": True,
                "interaction": "adb-launch",
                "oracle": "Activity resolution, pid-scoped logcat, and instrumentation events",
            }
        )

    for component in manifest.get("components", []):
        if not component.get("effective_exported"):
            continue
        kind = component.get("type")
        base = {
            "id": case_id(kind or "", component.get("name", "")),
            "package": package,
            "component": component.get("name"),
            "permissions": [
                x for x in (
                    component.get("permission"),
                    component.get("read_permission"),
                    component.get("write_permission"),
                ) if x
            ],
        }
        if kind in {"activity", "activity-alias"}:
            cases.append(
                {
                    **base,
                    "kind": "activity",
                    "safe_default": True,
                    "interaction": "adb-launch",
                    "oracle": "Activity start result and instrumentation events",
                }
            )
        elif kind == "receiver":
            actions = sorted(
                {
                    action
                    for intent_filter in component.get("intent_filters", [])
                    for action in intent_filter.get("actions", [])
                }
            )
            for action in actions:
                cases.append(
                    {
                        **base,
                        "id": case_id("broadcast", component.get("name", ""), action),
                        "kind": "broadcast",
                        "action": action,
                        "safe_default": True,
                        "interaction": "adb-broadcast",
                        "oracle": "Broadcast result, pid-scoped logcat, and instrumentation events",
                    }
                )
        elif kind == "service":
            cases.append(
                {
                    **base,
                    "kind": "service",
                    "safe_default": False,
                    "requires_review": "Starting a service may mutate application state",
                    "interaction": "adb-service",
                    "oracle": "Service start result and instrumentation events",
                }
            )
        elif kind == "provider":
            for authority in component.get("authorities", []):
                if authority:
                    cases.append(
                        {
                            **base,
                            "id": case_id("provider", component.get("name", ""), authority),
                            "kind": "provider-query",
                            "authority": authority,
                            "uri": f"content://{authority}/",
                            "safe_default": False,
                            "requires_review": "Provider paths and row-level authorization need manual scoping",
                            "interaction": "content-query",
                            "oracle": "Read-only query result; never insert, update, or delete",
                        }
                    )

    plan = {
        "schema_version": 1,
        "package": package,
        "model": str(args.model),
        "safety": {
            "device": "emulator-only",
            "network": "local canary/mock only",
            "payload": "tf_probe markers; no credential access, persistence, or shell payloads",
        },
        "cases": cases,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
    print(f"[probe-plan] cases={len(cases)} safe={sum(c['safe_default'] for c in cases)} -> {args.out}")


if __name__ == "__main__":
    main()
